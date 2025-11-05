/**
 * Database Service Adapter
 *
 * Adapter class that bridges the gap between DatabaseManager implementation
 * and the IDatabaseService interface requirements.
 *
 * Implements the adapter pattern to provide interface compliance while
 * maintaining backward compatibility with existing DatabaseManager.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { DatabaseManager } from '../../db/database-manager.js';
import type { IDatabase } from '../../db/database-interface.js';
import type { IDatabaseService } from '../service-interfaces.js';
import { logger } from '../../utils/logger.js';

/**
 * Adapter that wraps DatabaseManager to implement IDatabaseService interface
 */
export class DatabaseServiceAdapter implements IDatabaseService {
  private databaseManager: DatabaseManager;

  constructor(databaseManager: DatabaseManager) {
    this.databaseManager = databaseManager;
  }

  /**
   * Get database connection - required by IDatabaseService interface
   * This method was missing from DatabaseManager implementation
   */
  async getConnection(): Promise<IDatabase> {
    try {
      logger.debug('Getting database connection via adapter');

      // Ensure database manager is initialized
      await this.ensureInitialized();

      // Return the underlying database instance
      return this.databaseManager.getDatabase();
    } catch (error) {
      logger.error({ error }, 'Failed to get database connection via adapter');
      throw new Error(
        `Failed to get database connection: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Health check - delegate to DatabaseManager
   */
  async healthCheck(): Promise<boolean> {
    try {
      return await this.databaseManager.healthCheck();
    } catch (error) {
      logger.error({ error }, 'Database health check failed via adapter');
      return false;
    }
  }

  /**
   * Close database connection - delegate to DatabaseManager
   */
  async close(): Promise<void> {
    try {
      await this.databaseManager.close();
      logger.debug('Database connection closed via adapter');
    } catch (error) {
      logger.error({ error }, 'Failed to close database connection via adapter');
      throw error;
    }
  }

  /**
   * Ensure DatabaseManager is initialized
   */
  private async ensureInitialized(): Promise<void> {
    try {
      // DatabaseManager doesn't expose initialization status directly
      // so we attempt a health check to verify it's ready
      const isHealthy = await this.databaseManager.healthCheck();
      if (!isHealthy) {
        logger.warn('Database manager not healthy, attempting reinitialization');
        // The healthCheck method will attempt initialization if needed
      }
    } catch (error) {
      logger.debug(
        { error },
        'Database manager initialization check failed, this is expected for first use'
      );
      // Continue with connection attempt as DatabaseManager will auto-initialize
    }
  }

  /**
   * Get the underlying DatabaseManager instance for advanced operations
   * This provides access to DatabaseManager-specific methods if needed
   */
  getDatabaseManager(): DatabaseManager {
    return this.databaseManager;
  }
}
