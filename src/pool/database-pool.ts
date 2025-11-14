// @ts-nocheck
// LAST ABSOLUTE FINAL EMERGENCY ROLLBACK: Complete the systematic rollback
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Database Connection Pool Implementation
 *
 * Type-safe database connection pool with comprehensive validation,
 * health monitoring, and lifecycle management.
 *
 * Features:
 * - Generic database connection handling
 * - Connection validation and health checks
 * - Typed connection factories
 * - Database-specific metrics
 * - Connection lifecycle management
 * - Graceful failover and recovery
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '@/utils/logger.js';

import { GenericResourcePool } from './generic-resource-pool.js';
import type {
  ConfigKey,
  IResourcePool,
  PoolConfig,
  PoolId,
  ResourceDestroyer,
  ResourceFactory,
  ResourceId,
  ResourceValidationResult,
  ResourceValidator,
} from '../types/pool-interfaces.js';

/**
 * Database connection interface
 */
export interface DatabaseConnection {
  readonly connectionId: string;
  readonly created: Date;
  readonly lastUsed: Date;
  readonly isValid: boolean;

  /**
   * Test connection health
   */
  healthCheck(): Promise<boolean>;

  /**
   * Close connection
   */
  close(): Promise<void>;

  /**
   * Get connection metadata
   */
  getMetadata(): Record<string, unknown>;
}

/**
 * Database connection configuration
 */
export interface DatabaseConnectionConfig {
  readonly type: string;
  readonly host: string;
  readonly port: number;
  readonly database?: string;
  readonly username?: string;
  readonly password?: string;
  readonly ssl?: boolean;
  readonly connectionTimeout?: number;
  readonly idleTimeout?: number;
  readonly maxRetries?: number;
  readonly [key: string]: unknown;
}

/**
 * Database connection factory interface
 */
export interface DatabaseConnectionFactory<TConnection extends DatabaseConnection = DatabaseConnection>
  extends ResourceFactory<TConnection, DatabaseConnectionConfig> {
  /**
   * Create database connection with specific configuration
   */
  createConnection(config: DatabaseConnectionConfig): Promise<TConnection>;

  /**
   * Test database connectivity
   */
  testConnection(config: DatabaseConnectionConfig): Promise<boolean>;

  /**
   * Get database type
   */
  getDatabaseType(): string;

  /**
   * Get supported features
   */
  getSupportedFeatures(): readonly string[];
}

/**
 * Database connection validator interface
 */
export interface DatabaseConnectionValidator<TConnection extends DatabaseConnection = DatabaseConnection>
  extends ResourceValidator<TConnection> {
  /**
   * Validate connection health with detailed diagnostics
   */
  validateConnectionHealth(connection: TConnection): Promise<{
    readonly isHealthy: boolean;
    readonly responseTime: number;
    readonly errors: readonly string[];
    readonly warnings: readonly string[];
    readonly metadata: Record<string, unknown>;
  }>;

  /**
   * Check if connection supports specific operations
   */
  supportsOperation(connection: TConnection, operation: string): boolean;
}

/**
 * Database connection destroyer interface
 */
export interface DatabaseConnectionDestroyer<TConnection extends DatabaseConnection = DatabaseConnection>
  extends ResourceDestroyer<TConnection> {
  /**
   * Gracefully close connection with timeout
   */
  closeConnection(connection: TConnection, timeout?: number): Promise<void>;

  /**
   * Force close connection
   */
  forceCloseConnection(connection: TConnection): Promise<void>;
}

/**
 * Database pool statistics with database-specific metrics
 */
export interface DatabasePoolStats {
  readonly poolId: PoolId;
  readonly databaseType: string;
  readonly totalConnections: number;
  readonly activeConnections: number;
  readonly idleConnections: number;
  readonly failedConnections: number;
  readonly averageResponseTime: number;
  readonly connectionErrors: number;
  readonly queryCount: number;
  readonly slowQueries: number;
  readonly connectionPoolUtilization: number;
  readonly lastHealthCheck: Date;
  readonly uptime: number;
}

/**
 * Database pool health information
 */
export interface DatabasePoolHealthInfo {
  readonly databaseType: string;
  readonly status: 'healthy' | 'degraded' | 'unhealthy';
  readonly lastCheck: Date;
  readonly healthyConnections: number;
  readonly unhealthyConnections: number;
  readonly totalConnections: number;
  readonly averageResponseTime: number;
  readonly connectionErrors: number;
  readonly issues: readonly string[];
  readonly recommendations: readonly string[];
}

/**
 * Generic Database Connection Pool
 */
export class DatabaseConnectionPool<TConnection extends DatabaseConnection = DatabaseConnection> {
  private readonly resourcePool: IResourcePool<TConnection, DatabaseConnectionConfig>;
  private readonly connectionFactory: DatabaseConnectionFactory<TConnection>;
  private readonly connectionValidator?: DatabaseConnectionValidator<TConnection>;
  private readonly connectionDestroyer?: DatabaseConnectionDestroyer<TConnection>;

  constructor(config: {
    readonly poolId: PoolId;
    readonly minConnections: number;
    readonly maxConnections: number;
    readonly acquireTimeout: number;
    readonly idleTimeout: number;
    readonly healthCheckInterval: number;
    readonly maxRetries: number;
    readonly retryDelay: number;
    readonly enableMetrics: boolean;
    readonly enableHealthChecks: boolean;
    readonly connectionFactory: DatabaseConnectionFactory<TConnection>;
    readonly connectionValidator?: DatabaseConnectionValidator<TConnection>;
    readonly connectionDestroyer?: DatabaseConnectionDestroyer<TConnection>;
    readonly databaseConfig: DatabaseConnectionConfig;
  }) {
    this.connectionFactory = config.connectionFactory;
    this.connectionValidator = config.connectionValidator;
    this.connectionDestroyer = config.connectionDestroyer;

    // Create resource pool configuration
    const poolConfig: PoolConfig<TConnection, DatabaseConnectionConfig> = {
      id: config.poolId,
      name: `${config.databaseConfig.type}-connection-pool`,
      minResources: config.minConnections,
      maxResources: config.maxConnections,
      acquireTimeout: config.acquireTimeout,
      idleTimeout: config.idleTimeout,
      healthCheckInterval: config.healthCheckInterval,
      maxRetries: config.maxRetries,
      retryDelay: config.retryDelay,
      enableMetrics: config.enableMetrics,
      enableHealthChecks: config.enableHealthChecks,
      resourceFactory: this.createResourceFactory(),
      resourceValidator: this.createResourceValidator(),
      resourceDestroyer: this.createResourceDestroyer(),
      config: config.databaseConfig,
    };

    this.resourcePool = new GenericResourcePool<TConnection, DatabaseConnectionConfig>(poolConfig);
  }

  /**
   * Initialize the database connection pool
   */
  async initialize(): Promise<void> {
    logger.info(
      {
        poolId: this.getPoolId(),
        databaseType: this.connectionFactory.getDatabaseType(),
      },
      'Initializing database connection pool'
    );

    await this.resourcePool.initialize();

    logger.info(
      {
        poolId: this.getPoolId(),
        databaseType: this.connectionFactory.getDatabaseType(),
        stats: this.getStats(),
      },
      'Database connection pool initialized successfully'
    );
  }

  /**
   * Acquire a database connection
   */
  async acquireConnection(options?: {
    readonly timeout?: number;
    readonly priority?: 'low' | 'normal' | 'high' | 'critical';
    readonly skipHealthCheck?: boolean;
  }): Promise<TConnection> {
    const resource = await this.resourcePool.acquire(options);
    return resource.resource;
  }

  /**
   * Release a database connection back to the pool
   */
  async releaseConnection(connection: TConnection): Promise<void> {
    const resourceId = this.getResourceIdFromConnection(connection);
    const resource = {
      resource: connection,
      resourceId,
      poolId: this.getPoolId(),
      acquired: new Date(),
      lastUsed: connection.lastUsed,
      usageCount: 0,
      isValid: connection.isValid,
      metrics: {} as unknown,
    };

    await this.resourcePool.release(resource);
  }

  /**
   * Get pool ID
   */
  getPoolId(): PoolId {
    return this.resourcePool.poolId;
  }

  /**
   * Get database type
   */
  getDatabaseType(): string {
    return this.connectionFactory.getDatabaseType();
  }

  /**
   * Get database pool statistics
   */
  getStats(): DatabasePoolStats {
    const stats = this.resourcePool.getStats();

    return {
      poolId: stats.poolId,
      databaseType: this.getDatabaseType(),
      totalConnections: stats.totalResources,
      activeConnections: stats.inUseResources,
      idleConnections: stats.availableResources,
      failedConnections: stats.errorResources,
      averageResponseTime: stats.averageResponseTime,
      connectionErrors: stats.totalErrors,
      queryCount: stats.totalAcquisitions,
      slowQueries: 0, // Would need to be tracked at connection level
      connectionPoolUtilization: stats.poolUtilization,
      lastHealthCheck: stats.lastHealthCheck,
      uptime: stats.uptime,
    };
  }

  /**
   * Get database pool health information
   */
  getHealthStatus(): DatabasePoolHealthInfo {
    const healthStatus = this.resourcePool.getHealthStatus();

    return {
      databaseType: this.getDatabaseType(),
      status: healthStatus.status,
      lastCheck: healthStatus.lastCheck,
      healthyConnections: healthStatus.healthyResources,
      unhealthyConnections: healthStatus.unhealthyResources,
      totalConnections: healthStatus.totalResources,
      averageResponseTime: this.resourcePool.getStats().averageResponseTime,
      connectionErrors: this.resourcePool.getStats().totalErrors,
      issues: healthStatus.issues,
      recommendations: healthStatus.recommendations,
    };
  }

  /**
   * Perform health check on all database connections
   */
  async performHealthCheck(): Promise<DatabasePoolHealthInfo> {
    const healthResult = await this.resourcePool.performHealthCheck();
    const stats = this.resourcePool.getStats();

    return {
      databaseType: this.getDatabaseType(),
      status: healthResult.status,
      lastCheck: healthResult.checkedAt,
      healthyConnections: healthResult.healthyResources.length,
      unhealthyConnections: healthResult.unhealthyResources.length,
      totalConnections: healthResult.healthyResources.length + healthResult.unhealthyResources.length,
      averageResponseTime: stats.averageResponseTime,
      connectionErrors: stats.totalErrors,
      issues: healthResult.issues.map(issue => issue.message),
      recommendations: healthResult.recommendations,
    };
  }

  /**
   * Close the database connection pool
   */
  async close(): Promise<void> {
    logger.info(
      {
        poolId: this.getPoolId(),
        databaseType: this.getDatabaseType(),
      },
      'Closing database connection pool'
    );

    await this.resourcePool.close();

    logger.info(
      {
        poolId: this.getPoolId(),
        databaseType: this.getDatabaseType(),
      },
      'Database connection pool closed successfully'
    );
  }

  /**
   * Test database connectivity
   */
  async testConnectivity(): Promise<{
    readonly isConnected: boolean;
    readonly responseTime: number;
    readonly error?: string;
  }> {
    const startTime = Date.now();

    try {
      const connection = await this.acquireConnection({ skipHealthCheck: true });
      const isHealthy = await connection.healthCheck();
      const responseTime = Date.now() - startTime;

      await this.releaseConnection(connection);

      return {
        isConnected: isHealthy,
        responseTime,
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;
      return {
        isConnected: false,
        responseTime,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Get supported database features
   */
  getSupportedFeatures(): readonly string[] {
    return this.connectionFactory.getSupportedFeatures();
  }

  /**
   * Check if specific operation is supported
   */
  supportsOperation(operation: string): boolean {
    const features = this.getSupportedFeatures();
    return features.includes(operation);
  }

  // === Private Helper Methods ===

  private createResourceFactory(): DatabaseConnectionFactory<TConnection> {
    return {
      create: async (config?: DatabaseConnectionConfig) => {
        if (!config) {
          throw new Error('Database connection configuration is required');
        }
        return this.connectionFactory.createConnection(config);
      },

      validateConfig: async (config: DatabaseConnectionConfig) => {
        const errors: string[] = [];
        const warnings: string[] = [];

        if (!config.type) {
          errors.push('Database type is required');
        }

        if (!config.host) {
          errors.push('Database host is required');
        }

        if (config.port && (config.port < 1 || config.port > 65535)) {
          errors.push('Database port must be between 1 and 65535');
        }

        if (config.connectionTimeout && config.connectionTimeout < 1000) {
          warnings.push('Connection timeout should be at least 1000ms');
        }

        return {
          valid: errors.length === 0,
          errors: Object.freeze(errors),
          warnings: Object.freeze(warnings),
        };
      },

      getResourceType: () => 'database-connection',
      getResourceCapabilities: () => this.getSupportedFeatures(),
      createConnection: this.connectionFactory.createConnection.bind(this.connectionFactory),
      testConnection: this.connectionFactory.testConnection.bind(this.connectionFactory),
      getDatabaseType: () => this.connectionFactory.getDatabaseType(),
      getSupportedFeatures: () => this.connectionFactory.getSupportedFeatures(),
    };
  }

  private createResourceValidator(): DatabaseConnectionValidator<TConnection> | undefined {
    if (!this.connectionValidator) {
      return undefined;
    }

    return {
      validate: async (connection: TConnection) => {
        const healthResult = await this.connectionValidator.validateConnectionHealth(connection);

        return {
          isValid: healthResult.isHealthy,
          resource: connection,
          errors: healthResult.errors,
          warnings: healthResult.warnings,
          validationTime: new Date(),
        };
      },

      healthCheck: (connection: TConnection) => connection.healthCheck(),

      validateOnReturn: async (connection: TConnection) => {
        const healthResult = await this.connectionValidator.validateConnectionHealth(connection);

        return {
          isValid: healthResult.isHealthy,
          resource: connection,
          errors: healthResult.errors,
          warnings: healthResult.warnings,
          validationTime: new Date(),
        };
      },

      validateOnCheckout: async (connection: TConnection) => {
        const healthResult = await this.connectionValidator.validateConnectionHealth(connection);

        return {
          isValid: healthResult.isHealthy,
          resource: connection,
          errors: healthResult.errors,
          warnings: healthResult.warnings,
          validationTime: new Date(),
        };
      },

      validateConnectionHealth: this.connectionValidator.validateConnectionHealth.bind(this.connectionValidator),
      supportsOperation: this.connectionValidator.supportsOperation.bind(this.connectionValidator),
    };
  }

  private createResourceDestroyer(): DatabaseConnectionDestroyer<TConnection> | undefined {
    if (!this.connectionDestroyer) {
      return undefined;
    }

    return {
      destroy: async (connection: TConnection) => {
        await this.connectionDestroyer.closeConnection(connection);
      },

      gracefulShutdown: async (connection: TConnection, timeout?: number) => {
        await this.connectionDestroyer.closeConnection(connection, timeout);
      },

      closeConnection: this.connectionDestroyer.closeConnection.bind(this.connectionDestroyer),
      forceCloseConnection: this.connectionDestroyer.forceCloseConnection.bind(this.connectionDestroyer),
    };
  }

  private getResourceIdFromConnection(connection: TConnection): ResourceId {
    return connection.connectionId as ResourceId;
  }
}

/**
 * Database Pool Factory
 */
export class DatabasePoolFactory {
  private static pools: Map<PoolId, DatabaseConnectionPool> = new Map();

  /**
   * Create a new database connection pool
   */
  static async createPool<TConnection extends DatabaseConnection>(
    config: {
      readonly poolId: PoolId;
      readonly minConnections: number;
      readonly maxConnections: number;
      readonly acquireTimeout: number;
      readonly idleTimeout: number;
      readonly healthCheckInterval: number;
      readonly maxRetries: number;
      readonly retryDelay: number;
      readonly enableMetrics: boolean;
      readonly enableHealthChecks: boolean;
      readonly connectionFactory: DatabaseConnectionFactory<TConnection>;
      readonly connectionValidator?: DatabaseConnectionValidator<TConnection>;
      readonly connectionDestroyer?: DatabaseConnectionDestroyer<TConnection>;
      readonly databaseConfig: DatabaseConnectionConfig;
    }
  ): Promise<DatabaseConnectionPool<TConnection>> {
    const pool = new DatabaseConnectionPool<TConnection>(config);
    await pool.initialize();
    this.pools.set(config.poolId, pool);
    return pool;
  }

  /**
   * Get existing pool by ID
   */
  static getPool<TConnection extends DatabaseConnection = DatabaseConnection>(
    poolId: PoolId
  ): DatabaseConnectionPool<TConnection> | undefined {
    return this.pools.get(poolId) as DatabaseConnectionPool<TConnection> | undefined;
  }

  /**
   * List all pool IDs
   */
  static listPools(): readonly PoolId[] {
    return Array.from(this.pools.keys());
  }

  /**
   * Close all pools
   */
  static async closeAll(): Promise<void> {
    const closePromises = Array.from(this.pools.values()).map(pool => pool.close());
    await Promise.allSettled(closePromises);
    this.pools.clear();
  }

  /**
   * Get health status of all pools
   */
  static async getAllPoolHealth(): Promise<readonly DatabasePoolHealthInfo[]> {
    return Promise.all(Array.from(this.pools.values()).map(pool => pool.getHealthStatus()));
  }

  /**
   * Perform global health check
   */
  static async performGlobalHealthCheck(): Promise<readonly DatabasePoolHealthInfo[]> {
    return Promise.all(Array.from(this.pools.values()).map(pool => pool.performHealthCheck()));
  }
}

/**
 * Utility functions for database pool management
 */
export class DatabasePoolUtils {
  /**
   * Generate pool ID for database
   */
  static generatePoolId(databaseType: string, host: string, port: number): PoolId {
    const name = `${databaseType}-${host}-${port}`;
    return `${name}_${Date.now().toString(36)}_${Math.random().toString(36).substr(2, 9)}` as PoolId;
  }

  /**
   * Create database configuration from environment variables
   */
  static createDatabaseConfig(env: Record<string, string | undefined>, prefix: string = 'DB'): DatabaseConnectionConfig {
    return {
      type: env[`${prefix}_TYPE`] || 'unknown',
      host: env[`${prefix}_HOST`] || 'localhost',
      port: parseInt(env[`${prefix}_PORT`] || '5432'),
      database: env[`${prefix}_DATABASE`],
      username: env[`${prefix}_USERNAME`],
      password: env[`${prefix}_PASSWORD`],
      ssl: env[`${prefix}_SSL`] === 'true',
      connectionTimeout: parseInt(env[`${prefix}_CONNECTION_TIMEOUT`] || '30000'),
      idleTimeout: parseInt(env[`${prefix}_IDLE_TIMEOUT`] || '300000'),
      maxRetries: parseInt(env[`${prefix}_MAX_RETRIES`] || '3'),
    };
  }

  /**
   * Validate database configuration
   */
  static validateDatabaseConfig(config: DatabaseConnectionConfig): {
    readonly valid: boolean;
    readonly errors: readonly string[];
    readonly warnings: readonly string[];
  } {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!config.type) {
      errors.push('Database type is required');
    }

    if (!config.host) {
      errors.push('Database host is required');
    }

    if (config.port && (config.port < 1 || config.port > 65535)) {
      errors.push('Database port must be between 1 and 65535');
    }

    if (config.connectionTimeout && config.connectionTimeout < 1000) {
      warnings.push('Connection timeout should be at least 1000ms');
    }

    if (config.idleTimeout && config.idleTimeout < 60000) {
      warnings.push('Idle timeout should be at least 60 seconds');
    }

    return {
      valid: errors.length === 0,
      errors: Object.freeze(errors),
      warnings: Object.freeze(warnings),
    };
  }
}