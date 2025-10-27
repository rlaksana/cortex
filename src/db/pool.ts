import { Pool, PoolClient, QueryResult } from 'pg';
import { logger } from '../utils/logger.js';
import { Environment } from '../config/environment.js';

/**
 * qdrant Connection Pool Configuration
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
    const env = Environment.getInstance();
    const poolConfig: PoolConfig = this.getPoolConfig(env);
    const dbConnectionConfig = env.getDatabaseConnectionConfig();

    this.pool = new Pool({
      host: dbConnectionConfig.host,
      port: dbConnectionConfig.port,
      database: dbConnectionConfig.database,
      user: dbConnectionConfig.user,
      password: dbConnectionConfig.password,
      min: poolConfig.min,
      max: poolConfig.max,
      idleTimeoutMillis: poolConfig.idleTimeoutMillis,
      connectionTimeoutMillis: poolConfig.connectionTimeoutMillis,
      maxUses: poolConfig.maxUses,
      ssl: poolConfig.ssl ? { rejectUnauthorized: false } : false,
      // Enable query timeout
      query_timeout: dbConnectionConfig.queryTimeout,
      // Enable statement timeout
      statement_timeout: dbConnectionConfig.statementTimeout,
      // Enable application name for monitoring
      application_name: 'cortex-mcp-server',
    });

    this.setupEventListeners();
  }

  private getPoolConfig(env: Environment): PoolConfig {
    const rawConfig = env.getRawConfig();
    return {
      min: rawConfig.DB_POOL_MIN, // Increased for better concurrency
      max: rawConfig.DB_POOL_MAX, // Increased to handle concurrent operations
      idleTimeoutMillis: rawConfig.DB_IDLE_TIMEOUT_MS,
      connectionTimeoutMillis: rawConfig.DB_CONNECTION_TIMEOUT_MS,
      maxUses: rawConfig.DB_MAX_USES,
      ssl: rawConfig.DB_SSL,
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
      logger.error({ error: err }, 'Pool connection error:');
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
      // Test connection with a simple query using the pool directly
      const client = await this.pool.connect();
      try {
        const result = await client.query('SELECT NOW() as current_time');
        logger.info(
          `Database pool initialized successfully. Current time: ${(result.rows[0] as Record<string, unknown>).current_time}`
        );
      } finally {
        client.release();
      }

      this.isInitialized = true;

      // Log pool configuration
      const config = this.getPoolConfig();
      logger.info(
        {
          min: config.min,
          max: config.max,
          idleTimeoutMillis: config.idleTimeoutMillis,
          connectionTimeoutMillis: config.connectionTimeoutMillis,
          ssl: config.ssl,
        },
        'Pool configuration:'
      );
    } catch (error: unknown) {
      logger.error({ error }, 'Failed to initialize database pool:');
      throw error;
    }
  }

  /**
   * Execute a query with automatic retry on connection failures
   */
  async query(text: string, params?: unknown[]): Promise<QueryResult> {
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

        logger.debug(
          {
            text: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
            duration,
            rowCount: result.rowCount,
            attempt,
          },
          'Query executed successfully'
        );

        return result;
      } catch (error: unknown) {
        attempt++;
        const duration = Date.now() - startTime;

        logger.error(
          {
            text: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
            duration,
            attempt,
            error: error instanceof Error ? (error as Error).message : String(error),
          },
          'Query failed'
        );

        // If this is the last attempt, throw the error
        if (attempt > maxRetries) {
          throw error;
        }

        // For connection errors, wait before retrying
        if (this.isConnectionError(error)) {
          const delay = Math.min(1000 * Math.pow(2, attempt - 1), 5000); // Exponential backoff
          const errorMessage = error instanceof Error ? (error as Error).message : String(error);
          logger.warn(
            { delay, attempt, maxRetries, error: errorMessage },
            `Connection error - retrying in ${delay}ms (attempt ${attempt}/${maxRetries})`
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
  // eslint-disable-next-line no-unused-vars
  async transaction<T>(callback: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.getClient();

    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (error: unknown) {
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
        } as {
          isHealthy: false;
          message: 'Database pool not initialized';
        };
      }

      if (this.isShuttingDown) {
        return {
          isHealthy: false,
          message: 'Database pool is shutting down',
        } as {
          isHealthy: false;
          message: 'Database pool is shutting down';
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
          version: String((versionResult.rows[0] as Record<string, unknown>).version ?? ''),
          currentDatabase: String(
            (versionResult.rows[0] as Record<string, unknown>).database ?? ''
          ),
          currentSchema: String((versionResult.rows[0] as Record<string, unknown>).schema ?? ''),
        },
      };
    } catch (error: unknown) {
      logger.error({ error }, 'Database health check failed:');
      return {
        isHealthy: false,
        message: error instanceof Error ? (error as Error).message : String(error),
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
    } as {
      total: number;
      idle: number;
      waiting: number;
      max: number;
      min: number;
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
    } catch (error: unknown) {
      logger.error({ error }, 'Error during database pool shutdown:');
      throw error;
    }
  }

  /**
   * Check if an error is a connection error
   */
  private isConnectionError(error: unknown): boolean {
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

    if (
      error &&
      typeof error === 'object' &&
      'code' in error &&
      typeof error.code === 'string' &&
      connectionErrorCodes.includes(error.code)
    ) {
      return true as const;
    }

    // Check for connection-related error messages
    const connectionErrorMessages = [
      'connection refused',
      'timeout',
      'network is unreachable',
      'connection terminated',
      'connection closed',
    ];

    const errorMessage =
      error &&
      typeof error === 'object' &&
      'message' in error &&
      typeof (error as Error).message === 'string'
        ? (error as Error).message.toLowerCase()
        : '';
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
    logger.info({ signal }, `Starting graceful shutdown... Received ${signal}`);
    try {
      await dbPool.shutdown();
      process.exit(0);
    } catch (error: unknown) {
      logger.error({ error }, 'Error during graceful shutdown:');
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => shutdownHandler('SIGTERM'));
  process.on('SIGINT', () => shutdownHandler('SIGINT'));

  // Handle uncaught exceptions
  process.on('uncaughtException', async (error) => {
    logger.error({ error }, 'Uncaught exception:');
    try {
      await dbPool.shutdown();
    } catch (shutdownError: unknown) {
      logger.error({ error: shutdownError }, 'Error during shutdown after uncaught exception:');
    }
    process.exit(1);
  });

  // Handle unhandled promise rejections
  process.on('unhandledRejection', async (reason, promise) => {
    logger.error({ error: promise, reason }, 'Unhandled promise rejection at:');
    try {
      await dbPool.shutdown();
    } catch (shutdownError: unknown) {
      logger.error({ error: shutdownError }, 'Error during shutdown after unhandled rejection:');
    }
    process.exit(1);
  });
}
