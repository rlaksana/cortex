import { Pool, PoolClient, QueryResult } from 'pg';
import { logger } from '../utils/logger.js';
import { config } from '../config/environment.js';

/**
 * PostgreSQL Connection Pool Configuration
 *
 * Features:
 * - Configurable pool size (2-10 connections)
 * - Health check functionality
 * - Connection timeout handling
 * - Graceful shutdown support
 * - Environment-based configuration
 * - Query logging and metrics
 * - Automatic retry on connection failures
 */

interface PoolConfig {
  min: number;
  max: number;
  idleTimeoutMillis: number;
  connectionTimeoutMillis: number;
  maxUses: number;
  ssl?: boolean;
}

interface HealthCheckResult {
  isHealthy: boolean;
  message: string;
  poolStats?: {
    total: number;
    idle: number;
    waiting: number;
    max: number;
  };
  databaseStats?: {
    version: string;
    currentDatabase: string;
    currentSchema: string;
  };
}

class DatabasePool {
  private pool: Pool;
  private isInitialized = false;
  private isShuttingDown = false;

  constructor() {
    const poolConfig: PoolConfig = this.getPoolConfig();

    const dbConfig = config.getDatabaseConfig();

    this.pool = new Pool({
      host: dbConfig.host,
      port: dbConfig.port,
      database: dbConfig.database,
      user: dbConfig.user,
      password: dbConfig.password,
      min: poolConfig.min,
      max: poolConfig.max,
      idleTimeoutMillis: poolConfig.idleTimeoutMillis,
      connectionTimeoutMillis: poolConfig.connectionTimeoutMillis,
      maxUses: poolConfig.maxUses,
      ssl: poolConfig.ssl ? { rejectUnauthorized: false } : false,
      // Enable query timeout
      query_timeout: parseInt(process.env.DB_QUERY_TIMEOUT || '30000'),
      // Enable statement timeout
      statement_timeout: parseInt(process.env.DB_STATEMENT_TIMEOUT || '30000'),
      // Enable application name for monitoring
      application_name: 'cortex-mcp-server',
    });

    this.setupEventListeners();
  }

  private getPoolConfig(): PoolConfig {
    return {
      min: parseInt(process.env.DB_POOL_MIN || '2'),
      max: parseInt(process.env.DB_POOL_MAX || '10'),
      idleTimeoutMillis: parseInt(process.env.DB_IDLE_TIMEOUT_MS || '30000'),
      connectionTimeoutMillis: parseInt(process.env.DB_CONNECTION_TIMEOUT_MS || '10000'),
      maxUses: parseInt(process.env.DB_MAX_USES || '7500'),
      ssl: process.env.DB_SSL === 'true',
    };
  }

  private setupEventListeners(): void {
    // Pool-level event listeners
    this.pool.on('connect', (_client: PoolClient) => {
      logger.debug('New database connection established');
    });

    this.pool.on('acquire', (_client: PoolClient) => {
      logger.debug('Connection acquired from pool');
    });

    this.pool.on('release', () => {
      logger.debug('Connection released to pool');
    });

    this.pool.on('remove', (_client: PoolClient) => {
      logger.warn('Connection removed from pool due to error or timeout');
    });

    this.pool.on('error', (err: Error) => {
      logger.error('Pool connection error:', err);
    });
  }

  /**
   * Initialize the database pool and verify connectivity
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('Database pool already initialized');
      return;
    }

    if (this.isShuttingDown) {
      throw new Error('Cannot initialize pool during shutdown');
    }

    try {
      // Test connection with a simple query
      const result = await this.query('SELECT NOW() as current_time');
      logger.info(
        `Database pool initialized successfully. Current time: ${result.rows[0].current_time}`
      );

      this.isInitialized = true;

      // Log pool configuration
      const config = this.getPoolConfig();
      logger.info('Pool configuration:', {
        min: config.min,
        max: config.max,
        idleTimeoutMillis: config.idleTimeoutMillis,
        connectionTimeoutMillis: config.connectionTimeoutMillis,
        ssl: config.ssl,
      });
    } catch (error) {
      logger.error('Failed to initialize database pool:', error);
      throw error;
    }
  }

  /**
   * Execute a query with automatic retry on connection failures
   */
  async query(text: string, params?: any[]): Promise<QueryResult> {
    if (!this.isInitialized) {
      throw new Error('Database pool not initialized. Call initialize() first.');
    }

    if (this.isShuttingDown) {
      throw new Error('Database pool is shutting down');
    }

    const startTime = Date.now();
    let attempt = 0;
    const maxRetries = 3;

    while (attempt <= maxRetries) {
      try {
        const result = await this.pool.query(text, params);
        const duration = Date.now() - startTime;

        logger.debug('Query executed successfully', {
          text: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
          duration,
          rowCount: result.rowCount,
          attempt,
        });

        return result;
      } catch (error) {
        attempt++;
        const duration = Date.now() - startTime;

        logger.error('Query failed', {
          text: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
          duration,
          attempt,
          error: error instanceof Error ? error.message : String(error),
        });

        // If this is the last attempt, throw the error
        if (attempt > maxRetries) {
          throw error;
        }

        // For connection errors, wait before retrying
        if (this.isConnectionError(error)) {
          const delay = Math.min(1000 * Math.pow(2, attempt - 1), 5000); // Exponential backoff
          logger.warn(
            `Connection error, retrying in ${delay}ms (attempt ${attempt}/${maxRetries})`
          );
          await this.sleep(delay);
        } else {
          // For non-connection errors, don't retry
          throw error;
        }
      }
    }

    throw new Error('Max retries exceeded');
  }

  /**
   * Get a client from the pool for transactions
   */
  async getClient(): Promise<PoolClient> {
    if (!this.isInitialized) {
      throw new Error('Database pool not initialized. Call initialize() first.');
    }

    if (this.isShuttingDown) {
      throw new Error('Database pool is shutting down');
    }

    return this.pool.connect();
  }

  /**
   * Execute a transaction with automatic rollback on error
   */
  async transaction<T>(callback: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.getClient();

    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Health check for the database pool
   */
  async healthCheck(): Promise<HealthCheckResult> {
    try {
      if (!this.isInitialized) {
        return {
          isHealthy: false,
          message: 'Database pool not initialized',
        };
      }

      if (this.isShuttingDown) {
        return {
          isHealthy: false,
          message: 'Database pool is shutting down',
        };
      }

      // Test basic connectivity
      await this.query('SELECT NOW() as current_time');

      // Get database version and info
      const versionResult = await this.query(
        'SELECT version() as version, current_database() as database, current_schema() as schema'
      );

      // Get pool statistics
      const poolStats = {
        total: this.pool.totalCount,
        idle: this.pool.idleCount,
        waiting: this.pool.waitingCount,
        max: this.pool.options.max,
      };

      return {
        isHealthy: true,
        message: 'Database pool is healthy',
        poolStats,
        databaseStats: {
          version: versionResult.rows[0].version,
          currentDatabase: versionResult.rows[0].database,
          currentSchema: versionResult.rows[0].schema,
        },
      };
    } catch (error) {
      logger.error('Database health check failed:', error);
      return {
        isHealthy: false,
        message: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Get pool statistics
   */
  getStats() {
    return {
      total: this.pool.totalCount,
      idle: this.pool.idleCount,
      waiting: this.pool.waitingCount,
      max: this.pool.options.max,
      min: this.pool.options.min,
    };
  }

  /**
   * Get the underlying pg Pool for compatibility
   */
  getPool(): Pool {
    return this.pool;
  }

  /**
   * Graceful shutdown of the database pool
   */
  async shutdown(): Promise<void> {
    if (this.isShuttingDown) {
      logger.warn('Database pool is already shutting down');
      return;
    }

    this.isShuttingDown = true;
    logger.info('Starting graceful shutdown of database pool');

    try {
      // End the pool with a timeout
      await Promise.race([
        this.pool.end(),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Pool shutdown timeout')), 10000)
        ),
      ]);

      logger.info('Database pool shutdown completed');
    } catch (error) {
      logger.error('Error during database pool shutdown:', error);
      throw error;
    }
  }

  /**
   * Check if an error is a connection error
   */
  private isConnectionError(error: any): boolean {
    const connectionErrorCodes = [
      'ECONNREFUSED',
      'ETIMEDOUT',
      'ECONNRESET',
      'ENOTFOUND',
      '08006', // connection failure
      '08001', // SQL client unable to establish SQL connection
      '08004', // SQL server rejected establishment of SQL connection
      '57P01', // admin shutdown
      '57P02', // crash shutdown
      '57P03', // cannot connect now
    ];

    if (error?.code && connectionErrorCodes.includes(error.code)) {
      return true;
    }

    // Check for connection-related error messages
    const connectionErrorMessages = [
      'connection refused',
      'timeout',
      'network is unreachable',
      'connection terminated',
      'connection closed',
    ];

    const errorMessage = error?.message?.toLowerCase() || '';
    return connectionErrorMessages.some((msg) => errorMessage.includes(msg));
  }

  /**
   * Sleep for a specified duration
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// Export singleton instance
export const dbPool = new DatabasePool();

// Export the underlying pg Pool for compatibility
export const getPool = () => dbPool.getPool();

// Export for testing and multiple instances
export { DatabasePool };

// Graceful shutdown handlers
if (typeof process !== 'undefined') {
  const shutdownHandler = async (signal: string) => {
    logger.info(`Received ${signal}, starting graceful shutdown...`);
    try {
      await dbPool.shutdown();
      process.exit(0);
    } catch (error) {
      logger.error('Error during graceful shutdown:', error);
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => shutdownHandler('SIGTERM'));
  process.on('SIGINT', () => shutdownHandler('SIGINT'));

  // Handle uncaught exceptions
  process.on('uncaughtException', async (error) => {
    logger.error('Uncaught exception:', error);
    try {
      await dbPool.shutdown();
    } catch (shutdownError) {
      logger.error('Error during shutdown after uncaught exception:', shutdownError);
    }
    process.exit(1);
  });

  // Handle unhandled promise rejections
  process.on('unhandledRejection', async (reason, promise) => {
    logger.error('Unhandled promise rejection at:', promise, 'reason:', reason);
    try {
      await dbPool.shutdown();
    } catch (shutdownError) {
      logger.error('Error during shutdown after unhandled rejection:', shutdownError);
    }
    process.exit(1);
  });
}
