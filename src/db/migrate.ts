/**
 * Cortex Memory MCP - Qdrant Migration System
 *
 * Pure Qdrant-based migration system with:
 * - Collection configuration migrations
 * - Payload schema updates
 * - Index management
 * - Version tracking
 * - Rollback capabilities
 * - Dry-run mode for testing
 */

import { promises as fs } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createHash } from 'crypto';
import { qdrantConnectionManager } from './pool.js';
import { logger } from '../utils/logger.js';

/**
 * Migration interface
 */
interface Migration {
  id: string;
  name: string;
  version: string;
  description: string;
  checksum: string;
  applied_at?: Date;
  status: 'pending' | 'applied' | 'failed' | 'rolled_back';
}

/**
 * Migration result
 */
interface MigrationResult {
  migration_id: string;
  status: 'success' | 'failed' | 'skipped';
  message: string;
  duration: number;
  error?: string;
}

/**
 * Migration options
 */
interface MigrationOptions {
  dryRun?: boolean;
  force?: boolean;
  targetVersion?: string;
  step?: number;
}

/**
 * Migration operation types
 */
type MigrationOperation =
  | 'create_collection'
  | 'delete_collection'
  | 'update_collection_config'
  | 'create_index'
  | 'delete_index'
  | 'update_payload_schema';

/**
 * Migration step definition
 */
interface MigrationStep {
  operation: MigrationOperation;
  collection: string;
  parameters: Record<string, any>;
  rollback?: Record<string, any>;
}

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Qdrant Migration Manager
 *
 * Manages Qdrant collection and schema migrations with version tracking
 * and rollback capabilities.
 */
class QdrantMigrationManager {
  private migrationsDir: string;
  private client = qdrantConnectionManager.getClient();
  private migrationCollection = 'migrations';

  constructor() {
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
      'Starting Qdrant migration'
    );

    try {
      // Ensure migrations collection exists
      await this.ensureMigrationsCollection();

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

      // Run migrations
      for (const migration of migrationsToRun) {
        const result = await this.runMigration(migration, dryRun);
        results.push(result);

        if (result.status === 'failed' && !force) {
          throw new Error(`Migration ${migration.id} failed: ${result.error}`);
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
    } catch (error) {
      logger.error({ error }, 'Migration failed');
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

      for (const migration of migrationsToRollback) {
        const result = await this.rollbackMigration(migration);
        results.push(result);
      }

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
    } catch (error) {
      logger.error({ error }, 'Rollback failed');
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
   * Ensure migrations collection exists
   */
  private async ensureMigrationsCollection(): Promise<void> {
    try {
      const collections = await this.client.getCollections();
      const exists = collections.collections.some((c) => c.name === this.migrationCollection);

      if (!exists) {
        logger.info(`Creating migrations collection: ${this.migrationCollection}`);

        await this.client.createCollection(this.migrationCollection, {
          vectors: {
            size: 1, // Minimal vector size, we don't actually use vectors for migrations
            distance: 'Cosine',
          },
          payload_schema: {
            type: 'object',
            properties: {
              migration_id: { type: 'keyword' },
              name: { type: 'keyword' },
              version: { type: 'keyword' },
              description: { type: 'text' },
              checksum: { type: 'keyword' },
              applied_at: { type: 'datetime' },
              status: { type: 'keyword' },
            },
          },
        });

        // Create indexes for performance
        await this.client.createCollectionIndex(this.migrationCollection, {
          field_name: 'migration_id',
          field_schema: 'keyword',
        });

        await this.client.createCollectionIndex(this.migrationCollection, {
          field_name: 'status',
          field_schema: 'keyword',
        });

        await this.client.createCollectionIndex(this.migrationCollection, {
          field_name: 'applied_at',
          field_schema: 'datetime',
        });

        logger.info('Migrations collection created successfully');
      }
    } catch (error) {
      logger.error({ error }, 'Failed to ensure migrations collection');
      throw error;
    }
  }

  /**
   * Get all available migrations from file system
   */
  private async getAvailableMigrations(): Promise<Migration[]> {
    try {
      const files = await fs.readdir(this.migrationsDir);
      const migrationFiles = files.filter((file) => file.endsWith('.json')).sort();

      const migrations: Migration[] = [];

      for (const file of migrationFiles) {
        const filePath = join(this.migrationsDir, file);
        const content = await fs.readFile(filePath, 'utf-8');
        const migrationData = JSON.parse(content);
        const checksum = this.calculateChecksum(content);

        // Extract migration info from filename and content
        const id = file.split('_')[0];
        const name = file.replace('.json', '');

        migrations.push({
          id,
          name,
          version: migrationData.version || '1.0.0',
          description: migrationData.description || `Migration ${id}`,
          checksum,
          status: 'pending',
        });
      }

      return migrations;
    } catch (error) {
      logger.error({ error }, 'Failed to read migrations directory');
      throw error;
    }
  }

  /**
   * Get applied migrations from Qdrant
   */
  private async getAppliedMigrations(): Promise<Migration[]> {
    try {
      const searchResult = await this.client.search(this.migrationCollection, {
        vector: [0], // Dummy vector, we filter by payload
        filter: {
          must: [{ key: 'status', match: { value: 'applied' } }],
        },
        limit: 1000,
        with_payload: true,
      });

      return searchResult.map((point) => ({
        id: point.payload?.migration_id as string,
        name: point.payload?.name as string,
        version: point.payload?.version as string,
        description: point.payload?.description as string,
        checksum: point.payload?.checksum as string,
        applied_at: point.payload?.applied_at
          ? new Date(point.payload.applied_at as string)
          : undefined,
        status: 'applied' as const,
      }));
    } catch (error) {
      logger.error({ error }, 'Failed to get applied migrations');
      return [];
    }
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
      const targetIndex = pending.findIndex((m) => m.version === targetVersion);
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
  private async runMigration(migration: Migration, dryRun: boolean): Promise<MigrationResult> {
    const startTime = Date.now();
    const filePath = join(this.migrationsDir, `${migration.name}.json`);

    try {
      // Read migration file
      const content = await fs.readFile(filePath, 'utf-8');
      const migrationData = JSON.parse(content);

      // Verify checksum
      if (migration.checksum !== this.calculateChecksum(content)) {
        throw new Error(`Checksum mismatch for migration ${migration.id}`);
      }

      if (dryRun) {
        return {
          migration_id: migration.id,
          status: 'skipped',
          message: 'Dry run - migration not applied',
          duration: Date.now() - startTime,
        };
      }

      // Execute migration steps
      if (migrationData.steps && Array.isArray(migrationData.steps)) {
        for (const step of migrationData.steps) {
          await this.executeMigrationStep(step);
        }
      }

      // Record migration success
      await this.recordMigration(migration, 'applied');

      logger.info(`Migration ${migration.id} applied successfully`);

      return {
        migration_id: migration.id,
        status: 'success',
        message: 'Migration applied successfully',
        duration: Date.now() - startTime,
      };
    } catch (error) {
      logger.error({ error }, `Migration ${migration.id} failed`);

      // Record migration failure
      if (!dryRun) {
        try {
          await this.recordMigration(migration, 'failed');
        } catch (recordError) {
          logger.error({ error: recordError }, 'Failed to record migration failure');
        }
      }

      return {
        migration_id: migration.id,
        status: 'failed',
        message: 'Migration failed',
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Execute a migration step
   */
  private async executeMigrationStep(step: MigrationStep): Promise<void> {
    switch (step.operation) {
      case 'create_collection':
        await this.client.createCollection(step.collection, step.parameters);
        break;

      case 'delete_collection':
        await this.client.deleteCollection(step.collection);
        break;

      case 'update_collection_config':
        // Note: Qdrant doesn't support updating collection config directly
        // This would typically require collection recreation
        logger.warn(`Collection config update not supported: ${step.collection}`);
        break;

      case 'create_index':
        await this.client.createCollectionIndex(step.collection, {
          field_name: step.parameters.field_name,
          field_schema: step.parameters.field_schema,
        });
        break;

      case 'delete_index':
        // Note: Qdrant doesn't support index deletion directly
        logger.warn(
          `Index deletion not supported: ${step.collection}.${step.parameters.field_name}`
        );
        break;

      case 'update_payload_schema':
        // Note: Qdrant payload schema is flexible, no explicit updates needed
        logger.debug(`Payload schema update not needed: ${step.collection}`);
        break;

      default:
        throw new Error(`Unknown migration operation: ${step.operation}`);
    }
  }

  /**
   * Record a migration in the migrations collection
   */
  private async recordMigration(migration: Migration, status: string): Promise<void> {
    const point = {
      id: migration.id,
      vector: [0], // Dummy vector
      payload: {
        migration_id: migration.id,
        name: migration.name,
        version: migration.version,
        description: migration.description,
        checksum: migration.checksum,
        applied_at: new Date().toISOString(),
        status,
      },
    };

    await this.client.upsert(this.migrationCollection, {
      points: [point],
    });
  }

  /**
   * Rollback a migration
   */
  private async rollbackMigration(migration: Migration): Promise<MigrationResult> {
    const startTime = Date.now();

    try {
      const filePath = join(this.migrationsDir, `${migration.name}.json`);
      const content = await fs.readFile(filePath, 'utf-8');
      const migrationData = JSON.parse(content);

      // Execute rollback steps if available
      if (migrationData.steps && Array.isArray(migrationData.steps)) {
        for (const step of migrationData.steps.reverse()) {
          if (step.rollback) {
            await this.executeMigrationStep({
              operation: step.operation,
              collection: step.collection,
              parameters: step.rollback,
            });
          }
        }
      }

      // Record rollback
      await this.recordMigration(migration, 'rolled_back');

      logger.info(`Migration ${migration.id} rolled back successfully`);

      return {
        migration_id: migration.id,
        status: 'success',
        message: 'Migration rolled back successfully',
        duration: Date.now() - startTime,
      };
    } catch (error) {
      logger.error({ error }, `Rollback for migration ${migration.id} failed`);

      return {
        migration_id: migration.id,
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
    return createHash('sha256').update(content).digest('hex');
  }
}

// Export singleton instance
export const qdrantMigrationManager = new QdrantMigrationManager();

// Export for testing and CLI usage
export { QdrantMigrationManager };

// Export types
export type { Migration, MigrationResult, MigrationOptions, MigrationStep, MigrationOperation };

// CLI support
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const command = args[0] ?? 'up';

  async function runCLI() {
    try {
      await qdrantConnectionManager.initialize();

      switch (command) {
        case 'up':
          await qdrantMigrationManager.migrate();
          break;
        case 'down': {
          const step = parseInt(args[1]) ?? 1;
          await qdrantMigrationManager.rollback(step);
          break;
        }
        case 'status': {
          const status = await qdrantMigrationManager.status();
          console.log('Migration Status:');
          console.log(`Available: ${status.available.length}`);
          console.log(`Applied: ${status.applied.length}`);
          console.log(`Pending: ${status.pending.length}`);
          break;
        }
        case 'dry-run':
          await qdrantMigrationManager.migrate({ dryRun: true });
          break;
        default:
          console.error('Unknown command:', command);
          console.log('Available commands: up, down, status, dry-run');
          process.exit(1);
      }
    } catch (error) {
      logger.error({ error }, 'CLI failed');
      process.exit(1);
    } finally {
      await qdrantConnectionManager.shutdown();
    }
  }

  runCLI();
}
