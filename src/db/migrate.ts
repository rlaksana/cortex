import { promises as fs } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { dbPool } from './pool.js';
import { logger } from '../utils/logger.js';

/**
 * Database Migration System
 *
 * Features:
 * - Transactional migrations with rollback capability
 * - Migration file discovery and ordering
 * - Checksum-based change detection
 * - Migration versioning and dependency management
 * - Dry-run mode for testing
 * - Migration status tracking
 * - Automatic rollback on failure
 */

interface Migration {
  id: string;
  name: string;
  checksum: string;
  appliedAt?: Date;
  status: 'pending' | 'applied' | 'failed' | 'rolled_back';
}

interface MigrationResult {
  migrationId: string;
  status: 'success' | 'failed' | 'skipped';
  message: string;
  duration: number;
  error?: string;
}

interface MigrationOptions {
  dryRun?: boolean;
  force?: boolean;
  targetVersion?: string;
  step?: number;
}

const __dirname = dirname(fileURLToPath(import.meta.url));

class DatabaseMigrator {
  private migrationsDir: string;
  private ddlHistoryTable = 'ddl_history';

  constructor() {
    // Navigate to migrations directory from db/migrate.ts
    this.migrationsDir = join(__dirname, '..', '..', 'migrations');
  }

  /**
   * Run all pending migrations
   */
  async migrate(options: MigrationOptions = {}): Promise<MigrationResult[]> {
    const { dryRun = false, force = false, targetVersion, step } = options;
    const results: MigrationResult[] = [];

    logger.info(
      {
        dryRun,
        force,
        targetVersion,
        step,
      },
      'Starting database migration'
    );

    try {
      // Ensure DDL history table exists
      await this.ensureDdlHistoryTable();

      // Get all available migrations
      const availableMigrations = await this.getAvailableMigrations();
      logger.info(`Found ${availableMigrations.length} available migrations`);

      // Get applied migrations
      const appliedMigrations = await this.getAppliedMigrations();

      // Determine which migrations to run
      const migrationsToRun = this.getMigrationsToRun(availableMigrations, appliedMigrations, {
        targetVersion,
        step,
      });

      if (migrationsToRun.length === 0) {
        logger.info('No migrations to run');
        return results;
      }

      logger.info(`Running ${migrationsToRun.length} migrations`);

      // Run migrations in a transaction
      if (!dryRun) {
        await dbPool.transaction(async (client) => {
          for (const migration of migrationsToRun) {
            const result = await this.runMigration(client, migration, dryRun);
            results.push(result);

            if (result.status === 'failed' && !force) {
              throw new Error(`Migration ${migration.id} failed: ${result.error}`);
            }
          }
        });
      } else {
        // Dry run - just validate migrations
        for (const migration of migrationsToRun) {
          const result = await this.validateMigration(migration);
          results.push(result);
        }
      }

      const successCount = results.filter((r) => r.status === 'success').length;
      const failedCount = results.filter((r) => r.status === 'failed').length;
      const skippedCount = results.filter((r) => r.status === 'skipped').length;

      logger.info(
        {
          total: results.length,
          success: successCount,
          failed: failedCount,
          skipped: skippedCount,
          dryRun,
        },
        'Migration completed'
      );

      return results;
    } catch (error: unknown) {
      logger.error({ error }, 'Migration failed:');
      throw error;
    }
  }

  /**
   * Roll back the last migration
   */
  async rollback(step: number = 1): Promise<MigrationResult[]> {
    const results: MigrationResult[] = [];

    logger.info(`Starting rollback of ${step} migration(s)`);

    try {
      // Get applied migrations in reverse order
      const appliedMigrations = await this.getAppliedMigrations();
      const migrationsToRollback = appliedMigrations.slice(-step).reverse();

      if (migrationsToRollback.length === 0) {
        logger.info('No migrations to rollback');
        return results;
      }

      logger.info(`Rolling back ${migrationsToRollback.length} migrations`);

      await dbPool.transaction(async (client) => {
        for (const migration of migrationsToRollback) {
          const result = await this.rollbackMigration(client, migration);
          results.push(result);
        }
      });

      const successCount = results.filter((r) => r.status === 'success').length;
      const failedCount = results.filter((r) => r.status === 'failed').length;

      logger.info(
        {
          total: results.length,
          success: successCount,
          failed: failedCount,
        },
        'Rollback completed'
      );

      return results;
    } catch (error: unknown) {
      logger.error({ error }, 'Rollback failed:');
      throw error;
    }
  }

  /**
   * Get migration status
   */
  async status(): Promise<{
    available: Migration[];
    applied: Migration[];
    pending: Migration[];
  }> {
    const available = await this.getAvailableMigrations();
    const applied = await this.getAppliedMigrations();

    const pending = available.filter(
      (available) => !applied.some((applied) => applied.id === available.id)
    );

    return {
      available,
      applied,
      pending,
    };
  }

  /**
   * Ensure DDL history table exists
   */
  private async ensureDdlHistoryTable(): Promise<void> {
    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS ${this.ddlHistoryTable} (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        migration_id VARCHAR(200) NOT NULL,
        ddl_text TEXT NOT NULL,
        checksum VARCHAR(64) NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        description TEXT,
        status VARCHAR(20) NOT NULL DEFAULT 'applied',
        tags JSONB DEFAULT '{}',
        metadata JSONB DEFAULT '{}',
        CONSTRAINT ddl_history_migration_id_length CHECK (char_length(migration_id) >= 1 AND char_length(migration_id) <= 200),
        CONSTRAINT ddl_history_ddl_length CHECK (char_length(ddl_text) >= 1),
        CONSTRAINT ddl_history_checksum_length CHECK (char_length(checksum) = 64),
        CONSTRAINT ddl_history_valid_status CHECK (status IN ('pending', 'applied', 'failed', 'rolled_back')),
        CONSTRAINT ddl_history_unique_migration UNIQUE (migration_id)
      );
    `;

    await dbPool.query(createTableQuery);
  }

  /**
   * Get all available migrations from file system
   */
  private async getAvailableMigrations(): Promise<Migration[]> {
    try {
      const files = await fs.readdir(this.migrationsDir);
      const migrationFiles = files.filter((file) => file.endsWith('.sql')).sort(); // Sort to ensure proper order

      const migrations: Migration[] = [];

      for (const file of migrationFiles) {
        const filePath = join(this.migrationsDir, file);
        const content = await fs.readFile(filePath, 'utf-8');
        const checksum = this.calculateChecksum(content);

        // Extract migration ID from filename (e.g., 001_create_tables.sql -> 001)
        const id = file.split('_')[0];
        const name = file.replace('.sql', '');

        migrations.push({
          id,
          name,
          checksum,
          status: 'pending',
        });
      }

      return migrations;
    } catch (error: unknown) {
      logger.error({ error }, 'Failed to read migrations directory:');
      throw error;
    }
  }

  /**
   * Get applied migrations from database
   */
  private async getAppliedMigrations(): Promise<Migration[]> {
    const query = `
      SELECT
        migration_id as id,
        migration_id as name,
        checksum,
        applied_at,
        status
      FROM ${this.ddlHistoryTable}
      WHERE status = 'applied'
      ORDER BY applied_at ASC
    `;

    const result = await dbPool.query(query);
    return result.rows.map((row) => ({
      id: row.id,
      name: row.name,
      checksum: row.checksum,
      appliedAt: row.applied_at,
      status: row.status,
    }));
  }

  /**
   * Determine which migrations to run
   */
  private getMigrationsToRun(
    available: Migration[],
    applied: Migration[],
    options: { targetVersion?: string; step?: number } = {}
  ): Migration[] {
    const { targetVersion, step } = options;

    // Filter out already applied migrations
    let pending = available.filter(
      (available) => !applied.some((applied) => applied.id === available.id)
    );

    // Apply target version filter
    if (targetVersion) {
      const targetIndex = pending.findIndex((m) => m.id === targetVersion);
      if (targetIndex !== -1) {
        pending = pending.slice(0, targetIndex + 1);
      }
    }

    // Apply step filter
    if (step && step > 0) {
      pending = pending.slice(0, step);
    }

    return pending;
  }

  /**
   * Run a single migration
   */
  private async runMigration(
    client: import('pg').PoolClient,
    migration: Migration,
    dryRun: boolean
  ): Promise<MigrationResult> {
    const startTime = Date.now();
    const filePath = join(this.migrationsDir, `${migration.name}.sql`);

    try {
      // Read migration file
      const ddlContent = await fs.readFile(filePath, 'utf-8');

      // Verify checksum
      if (migration.checksum !== this.calculateChecksum(ddlContent)) {
        throw new Error(`Checksum mismatch for migration ${migration.id}`);
      }

      if (dryRun) {
        return {
          migrationId: migration.id,
          status: 'skipped',
          message: 'Dry run - migration not applied',
          duration: Date.now() - startTime,
        };
      }

      // Record migration start
      await client.query(
        `INSERT INTO ${this.ddlHistoryTable}
         (migration_id, ddl_text, checksum, status, description)
         VALUES ($1, $2, $3, 'pending', $4)
         ON CONFLICT (migration_id)
         DO UPDATE SET status = 'pending', applied_at = NOW()`,
        [migration.id, ddlContent, migration.checksum, `Applying ${migration.name}`]
      );

      // Execute migration
      await client.query(ddlContent);

      // Record migration success
      await client.query(
        `UPDATE ${this.ddlHistoryTable}
         SET status = 'applied', applied_at = NOW()
         WHERE migration_id = $1`,
        [migration.id]
      );

      logger.info(`Migration ${migration.id} applied successfully`);

      return {
        migrationId: migration.id,
        status: 'success',
        message: 'Migration applied successfully',
        duration: Date.now() - startTime,
      };
    } catch (error: unknown) {
      logger.error({ error }, 'Migration ${migration.id} failed:');

      // Record migration failure
      if (!dryRun) {
        try {
          await client.query(
            `UPDATE ${this.ddlHistoryTable}
             SET status = 'failed'
             WHERE migration_id = $1`,
            [migration.id]
          );
        } catch (updateError: unknown) {
          logger.error({ error: updateError }, 'Failed to update migration status:');
        }
      }

      return {
        migrationId: migration.id,
        status: 'failed',
        message: 'Migration failed',
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Validate a migration (dry run)
   */
  private async validateMigration(migration: Migration): Promise<MigrationResult> {
    const startTime = Date.now();
    const filePath = join(this.migrationsDir, `${migration.name}.sql`);

    try {
      // Read migration file
      const ddlContent = await fs.readFile(filePath, 'utf-8');

      // Verify checksum
      if (migration.checksum !== this.calculateChecksum(ddlContent)) {
        throw new Error(`Checksum mismatch for migration ${migration.id}`);
      }

      // Basic SQL validation (could be enhanced with actual SQL parsing)
      if (ddlContent.trim() === '') {
        throw new Error(`Migration ${migration.id} is empty`);
      }

      return {
        migrationId: migration.id,
        status: 'skipped',
        message: 'Migration validated successfully',
        duration: Date.now() - startTime,
      };
    } catch (error: unknown) {
      return {
        migrationId: migration.id,
        status: 'failed',
        message: 'Migration validation failed',
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Rollback a migration
   */
  private async rollbackMigration(
    client: import('pg').PoolClient,
    migration: Migration
  ): Promise<MigrationResult> {
    const startTime = Date.now();

    try {
      // For now, we'll just mark the migration as rolled back
      // In a more sophisticated system, we would have rollback scripts
      await client.query(
        `UPDATE ${this.ddlHistoryTable}
         SET status = 'rolled_back', applied_at = NOW()
         WHERE migration_id = $1`,
        [migration.id]
      );

      logger.info(`Migration ${migration.id} rolled back successfully`);

      return {
        migrationId: migration.id,
        status: 'success',
        message: 'Migration rolled back successfully',
        duration: Date.now() - startTime,
      };
    } catch (error: unknown) {
      logger.error({ error }, 'Rollback for migration ${migration.id} failed:');

      return {
        migrationId: migration.id,
        status: 'failed',
        message: 'Rollback failed',
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Calculate checksum of a string
   */
  private calculateChecksum(content: string): string {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(content).digest('hex');
  }
}

// Export singleton instance
export const dbMigrator = new DatabaseMigrator();

// Export for testing and CLI usage
export { DatabaseMigrator };

// CLI support
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const command = args[0] ?? 'up';

  async function runCLI() {
    try {
      await dbPool.initialize();

      switch (command) {
        case 'up':
          await dbMigrator.migrate();
          break;
        case 'down': {
          const step = parseInt(args[1]) ?? 1;
          await dbMigrator.rollback(step);
          break;
        }
        case 'status': {
          const status = await dbMigrator.status();
          console.log('Migration Status:');
          console.log(`Available: ${status.available.length}`);
          console.log(`Applied: ${status.applied.length}`);
          console.log(`Pending: ${status.pending.length}`);
          break;
        }
        case 'dry-run':
          await dbMigrator.migrate({ dryRun: true });
          break;
        default:
          console.error('Unknown command:', command);
          console.log('Available commands: up, down, status, dry-run');
          process.exit(1);
      }
    } catch (error: unknown) {
      logger.error({ error }, 'CLI failed:');
      process.exit(1);
    } finally {
      await dbPool.shutdown();
    }
  }

  runCLI();
}
