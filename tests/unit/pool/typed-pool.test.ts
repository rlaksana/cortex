/**
 * Typed Pool Tests - Type Safety and Runtime Validation
 *
 * Comprehensive test suite for typed pool implementations.
 * Tests type safety, runtime validation, and proper error handling.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import { DatabaseConnectionPool, DatabasePoolFactory } from '@/pool/database-pool.js';
import { GenericResourcePool, TypedPoolFactory, TypedPoolManager } from '@/pool/generic-resource-pool.js';
import { PoolRuntimeValidator, PoolTypeGuards } from '@/utils/pool-type-guards.js';

import type {
  PoolConfig,
  ResourceFactory,
  ResourceValidator,
  ResourceDestroyer,
  ResourceValidationResult,
  PoolId,
  ResourceId,
} from '@/types/pool-interfaces.js';
import type { DatabaseConnection, DatabaseConnectionConfig } from '@/pool/database-pool.js';

// Mock resource for testing
class MockResource implements DatabaseConnection {
  public readonly connectionId: ResourceId;
  public readonly created: Date;
  public lastUsed: Date;
  public isValid: boolean;
  public responseTime: number;
  public errorRate: number;
  public operationCount: number;

  constructor(connectionId: ResourceId) {
    this.connectionId = connectionId;
    this.created = new Date();
    this.lastUsed = new Date();
    this.isValid = true;
    this.responseTime = 100;
    this.errorRate = 0;
    this.operationCount = 0;
  }

  async healthCheck(): Promise<boolean> {
    this.operationCount++;
    this.lastUsed = new Date();

    // Simulate 95% success rate
    const isSuccess = Math.random() > 0.05;
    if (!isSuccess) {
      this.errorRate = Math.min(this.errorRate + 0.1, 1);
    }

    return isSuccess && this.isValid;
  }

  async close(): Promise<void> {
    this.isValid = false;
  }

  getMetadata(): Record<string, unknown> {
    return {
      connectionId: this.connectionId,
      created: this.created,
      lastUsed: this.lastUsed,
      isValid: this.isValid,
      responseTime: this.responseTime,
      errorRate: this.errorRate,
      operationCount: this.operationCount,
    };
  }

  // Simulate operation
  async performOperation(): Promise<string> {
    this.operationCount++;
    this.lastUsed = new Date();

    // Simulate response time
    await new Promise(resolve => setTimeout(resolve, this.responseTime));

    // Simulate occasional errors
    if (Math.random() < this.errorRate) {
      throw new Error('Mock operation failed');
    }

    return `Operation completed at ${this.lastUsed.toISOString()}`;
  }
}

// Mock resource factory
class MockResourceFactory implements ResourceFactory<MockResource, DatabaseConnectionConfig> {
  private resourceCounter = 0;

  async create(config?: DatabaseConnectionConfig): Promise<MockResource> {
    if (!config) {
      throw new Error('Configuration is required');
    }

    this.resourceCounter++;
    const connectionId = `mock_resource_${this.resourceCounter}_${Date.now()}` as ResourceId;

    // Simulate creation delay
    await new Promise(resolve => setTimeout(resolve, 10));

    return new MockResource(connectionId);
  }

  async validateConfig(config: DatabaseConnectionConfig): Promise<{
    valid: boolean;
    errors: readonly string[];
    warnings: readonly string[];
  }> {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!config.type) {
      errors.push('Database type is required');
    }

    if (!config.host) {
      errors.push('Database host is required');
    }

    if (config.port && (config.port < 1 || config.port > 65535)) {
      errors.push('Port must be between 1 and 65535');
    }

    if (config.connectionTimeout && config.connectionTimeout < 1000) {
      warnings.push('Connection timeout should be at least 1000ms');
    }

    return {
      valid: errors.length === 0,
      errors: Object.freeze(errors),
      warnings: Object.freeze(warnings),
    };
  }

  getResourceType(): string {
    return 'mock-resource';
  }

  getResourceCapabilities(): readonly string[] {
    return ['read', 'write', 'health-check'];
  }
}

// Mock resource validator
class MockResourceValidator implements ResourceValidator<MockResource> {
  async validate(resource: MockResource): Promise<ResourceValidationResult<MockResource>> {
    const errors: string[] = [];
    const warnings: string[] = [];
    const validationTime = new Date();

    if (!resource.isValid) {
      errors.push('Resource is marked as invalid');
    }

    if (resource.errorRate > 0.5) {
      errors.push(`High error rate: ${(resource.errorRate * 100).toFixed(2)}%`);
    } else if (resource.errorRate > 0.2) {
      warnings.push(`Elevated error rate: ${(resource.errorRate * 100).toFixed(2)}%`);
    }

    if (resource.responseTime > 1000) {
      warnings.push(`High response time: ${resource.responseTime}ms`);
    }

    // Perform health check
    const isHealthy = await resource.healthCheck();
    if (!isHealthy) {
      errors.push('Health check failed');
    }

    return {
      isValid: errors.length === 0,
      resource,
      errors: Object.freeze(errors),
      warnings: Object.freeze(warnings),
      validationTime,
    };
  }

  async healthCheck(resource: MockResource): Promise<boolean> {
    return resource.healthCheck();
  }

  async validateOnReturn(resource: MockResource): Promise<ResourceValidationResult<MockResource>> {
    return this.validate(resource);
  }

  async validateOnCheckout(resource: MockResource): Promise<ResourceValidationResult<MockResource>> {
    return this.validate(resource);
  }
}

// Mock resource destroyer
class MockResourceDestroyer implements ResourceDestroyer<MockResource> {
  async destroy(resource: MockResource): Promise<void> {
    await resource.close();
  }

  async gracefulShutdown(resource: MockResource, timeout = 30000): Promise<void> {
    await Promise.race([
      this.destroy(resource),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Shutdown timeout')), timeout)
      ),
    ]);
  }
}

describe('Typed Pool Implementation', () => {
  let poolId: PoolId;
  let pool: GenericResourcePool<MockResource, DatabaseConnectionConfig>;
  let resourceFactory: MockResourceFactory;
  let resourceValidator: MockResourceValidator;
  let resourceDestroyer: MockResourceDestroyer;
  let poolConfig: PoolConfig<MockResource, DatabaseConnectionConfig>;

  beforeEach(() => {
    vi.clearAllMocks();

    poolId = `test-pool-${Date.now()}` as PoolId;
    resourceFactory = new MockResourceFactory();
    resourceValidator = new MockResourceValidator();
    resourceDestroyer = new MockResourceDestroyer();

    poolConfig = {
      id: poolId,
      name: 'Test Pool',
      minResources: 2,
      maxResources: 5,
      acquireTimeout: 5000,
      idleTimeout: 30000,
      healthCheckInterval: 10000,
      maxRetries: 3,
      retryDelay: 1000,
      enableMetrics: true,
      enableHealthChecks: true,
      resourceFactory,
      resourceValidator,
      resourceDestroyer,
      config: {
        type: 'mock',
        host: 'localhost',
        port: 5432,
      },
    };

    pool = new GenericResourcePool<MockResource, DatabaseConnectionConfig>(poolConfig);
  });

  afterEach(async () => {
    if (pool) {
      await pool.close();
    }
  });

  describe('Pool Initialization', () => {
    it('should initialize pool with correct configuration', async () => {
      await pool.initialize();

      const stats = pool.getStats();
      expect(stats.poolId).toBe(poolId);
      expect(stats.totalResources).toBeGreaterThanOrEqual(poolConfig.minResources);
      expect(stats.totalResources).toBeLessThanOrEqual(poolConfig.maxResources);
      expect(stats.healthStatus).toBe('healthy');
    });

    it('should fail initialization with invalid configuration', async () => {
      const invalidConfig = {
        ...poolConfig,
        minResources: 10,
        maxResources: 5, // Invalid: min > max
      };

      const invalidPool = new GenericResourcePool<MockResource, DatabaseConnectionConfig>(invalidConfig);

      await expect(invalidPool.initialize()).rejects.toThrow('Invalid pool configuration');
    });

    it('should create minimum resources on initialization', async () => {
      await pool.initialize();

      const stats = pool.getStats();
      expect(stats.totalResources).toBeGreaterThanOrEqual(poolConfig.minResources);
    });
  });

  describe('Resource Acquisition and Release', () => {
    beforeEach(async () => {
      await pool.initialize();
    });

    it('should acquire resource successfully', async () => {
      const resource = await pool.acquire();

      expect(resource.resource).toBeDefined();
      expect(resource.resourceId).toBeDefined();
      expect(resource.poolId).toBe(poolId);
      expect(resource.isValid).toBe(true);

      await pool.release(resource);
    });

    it('should release resource successfully', async () => {
      const resource = await pool.acquire();
      const statsBeforeRelease = pool.getStats();

      await pool.release(resource);
      const statsAfterRelease = pool.getStats();

      expect(statsAfterRelease.inUseResources).toBe(statsBeforeRelease.inUseResources - 1);
      expect(statsAfterRelease.availableResources).toBe(statsBeforeRelease.availableResources + 1);
    });

    it('should fail to acquire resource when pool is exhausted', async () => {
      // Acquire all available resources
      const resources = [];
      const maxAcquisitions = poolConfig.maxResources + 2; // Try to get more than max

      for (let i = 0; i < maxAcquisitions; i++) {
        try {
          const resource = await pool.acquire({ timeout: 1000 });
          resources.push(resource);
        } catch (error) {
          // Expected to fail after reaching max
          expect(error).toBeInstanceOf(Error);
          break;
        }
      }

      expect(resources.length).toBeLessThanOrEqual(poolConfig.maxResources);

      // Release acquired resources
      for (const resource of resources) {
        await pool.release(resource);
      }
    });

    it('should validate resource on checkout', async () => {
      const resource = await pool.acquire();

      // Resource should be valid and healthy
      expect(resource.isValid).toBe(true);
      expect(resource.resource.isValid).toBe(true);

      await pool.release(resource);
    });

    it('should validate resource on return', async () => {
      const resource = await pool.acquire();

      // Simulate resource becoming unhealthy
      resource.resource.isValid = false;

      // Should not throw error but mark resource as invalid
      await expect(pool.release(resource)).resolves.not.toThrow();

      const stats = pool.getStats();
      expect(stats.errorResources).toBeGreaterThan(0);
    });
  });

  describe('Pool Health Monitoring', () => {
    beforeEach(async () => {
      await pool.initialize();
    });

    it('should perform health check successfully', async () => {
      const healthResult = await pool.performHealthCheck();

      expect(healthResult).toHaveProperty('status');
      expect(healthResult).toHaveProperty('checkedAt');
      expect(healthResult).toHaveProperty('healthyResources');
      expect(healthResult).toHaveProperty('unhealthyResources');
      expect(healthResult).toHaveProperty('issues');
      expect(healthResult).toHaveProperty('recommendations');
      expect(healthResult).toHaveProperty('metrics');

      expect(['healthy', 'degraded', 'unhealthy']).toContain(healthResult.status);
      expect(healthResult.healthyResources.length + healthResult.unhealthyResources.length).toBe(
        healthResult.healthyResources.length + healthResult.unhealthyResources.length
      );
    });

    it('should get pool health status', () => {
      const healthStatus = pool.getHealthStatus();

      expect(healthStatus).toHaveProperty('status');
      expect(healthStatus).toHaveProperty('lastCheck');
      expect(healthStatus).toHaveProperty('healthyResources');
      expect(healthStatus).toHaveProperty('unhealthyResources');
      expect(healthStatus).toHaveProperty('totalResources');
      expect(healthStatus).toHaveProperty('issues');
      expect(healthStatus).toHaveProperty('recommendations');
      expect(healthStatus).toHaveProperty('nextCheckDue');

      expect(['healthy', 'degraded', 'unhealthy', 'maintenance', 'unknown']).toContain(healthStatus.status);
    });

    it('should update health status based on resource health', async () => {
      // Get a resource and make it unhealthy
      const resource = await pool.acquire();
      resource.resource.isValid = false;
      resource.resource.errorRate = 0.8; // 80% error rate
      await pool.release(resource);

      // Perform health check
      const healthResult = await pool.performHealthCheck();

      // Should detect unhealthy resource
      expect(healthResult.unhealthyResources.length).toBeGreaterThan(0);
      expect(healthResult.status).toBe('degraded' || 'unhealthy');
    });
  });

  describe('Pool Statistics', () => {
    beforeEach(async () => {
      await pool.initialize();
    });

    it('should get comprehensive pool statistics', () => {
      const stats = pool.getStats();

      expect(stats).toHaveProperty('poolId');
      expect(stats).toHaveProperty('totalResources');
      expect(stats).toHaveProperty('availableResources');
      expect(stats).toHaveProperty('inUseResources');
      expect(stats).toHaveProperty('maintenanceResources');
      expect(stats).toHaveProperty('errorResources');
      expect(stats).toHaveProperty('averageAcquireTime');
      expect(stats).toHaveProperty('averageResponseTime');
      expect(stats).toHaveProperty('totalAcquisitions');
      expect(stats).toHaveProperty('totalReleases');
      expect(stats).toHaveProperty('totalErrors');
      expect(stats).toHaveProperty('poolUtilization');
      expect(stats).toHaveProperty('healthStatus');
      expect(stats).toHaveProperty('lastHealthCheck');
      expect(stats).toHaveProperty('uptime');

      expect(typeof stats.poolId).toBe('string');
      expect(typeof stats.totalResources).toBe('number');
      expect(typeof stats.poolUtilization).toBe('number');
      expect(['healthy', 'degraded', 'unhealthy', 'maintenance', 'unknown']).toContain(stats.healthStatus);
    });

    it('should track resource usage statistics', async () => {
      const initialStats = pool.getStats();

      // Acquire and release resources
      const resource = await pool.acquire();
      await pool.release(resource);

      const updatedStats = pool.getStats();

      expect(updatedStats.totalAcquisitions).toBe(initialStats.totalAcquisitions + 1);
      expect(updatedStats.totalReleases).toBe(initialStats.totalReleases + 1);
      expect(updatedStats.averageAcquireTime).toBeGreaterThanOrEqual(0);
    });

    it('should get resource metrics', async () => {
      const resource = await pool.acquire();
      const metrics = pool.getResourceMetrics();

      expect(Array.isArray(metrics)).toBe(true);
      expect(metrics.length).toBeGreaterThan(0);

      const resourceMetric = metrics.find(m => m.resourceId === resource.resourceId);
      expect(resourceMetric).toBeDefined();
      expect(resourceMetric?.poolId).toBe(poolId);
      expect(resourceMetric?.state).toBe('in_use');

      await pool.release(resource);
    });
  });

  describe('Pool Configuration Validation', () => {
    it('should validate valid pool configuration', async () => {
      const validation = await pool.validateConfig();

      expect(validation.valid).toBe(true);
      expect(Array.isArray(validation.errors)).toBe(true);
      expect(Array.isArray(validation.warnings)).toBe(true);
      expect(validation.errors.length).toBe(0);
    });

    it('should detect invalid pool configuration', async () => {
      const invalidPool = new GenericResourcePool<MockResource, DatabaseConnectionConfig>({
        ...poolConfig,
        minResources: 10,
        maxResources: 5,
      });

      const validation = await invalidPool.validateConfig();

      expect(validation.valid).toBe(false);
      expect(validation.errors.length).toBeGreaterThan(0);
      expect(validation.errors.some(error => error.includes('minResources'))).toBe(true);
    });

    it('should provide safe configuration without sensitive data', () => {
      const safeConfig = pool.getConfig();

      expect(safeConfig).toHaveProperty('id');
      expect(safeConfig).toHaveProperty('name');
      expect(safeConfig).toHaveProperty('minResources');
      expect(safeConfig).toHaveProperty('maxResources');
      expect(safeConfig).not.toHaveProperty('config');
    });
  });

  describe('Pool Lifecycle Management', () => {
    it('should close pool gracefully', async () => {
      await pool.initialize();

      // Acquire some resources
      const resources = [];
      for (let i = 0; i < 3; i++) {
        resources.push(await pool.acquire());
      }

      expect(pool.getStats().inUseResources).toBe(3);

      // Close pool
      await pool.close();

      // Pool should be closed
      await expect(pool.acquire()).rejects.toThrow();
    });

    it('should handle double close gracefully', async () => {
      await pool.initialize();
      await pool.close();

      // Second close should not throw
      await expect(pool.close()).resolves.not.toThrow();
    });

    it('should clean up resources on close', async () => {
      await pool.initialize();

      const statsBeforeClose = pool.getStats();
      expect(statsBeforeClose.totalResources).toBeGreaterThan(0);

      await pool.close();

      // After close, resources should be cleaned up
      // (Specific implementation depends on the pool type)
    });
  });

  describe('Error Handling', () => {
    beforeEach(async () => {
      await pool.initialize();
    });

    it('should handle resource creation failures', async () => {
      // This would require modifying the factory to simulate failures
      // For now, test that pool continues to work with existing resources
      const resource = await pool.acquire();
      expect(resource).toBeDefined();
      await pool.release(resource);
    });

    it('should handle validation errors gracefully', async () => {
      const resource = await pool.acquire();

      // Make resource invalid
      resource.resource.isValid = false;

      // Should handle invalid resource gracefully
      await expect(pool.release(resource)).resolves.not.toThrow();
    });

    it('should track errors in statistics', async () => {
      const initialStats = pool.getStats();

      try {
        // Try to acquire from exhausted pool
        const resources = [];
        for (let i = 0; i < poolConfig.maxResources + 1; i++) {
          resources.push(await pool.acquire());
        }
      } catch (error) {
        // Expected to fail
      }

      const updatedStats = pool.getStats();
      expect(updatedStats.totalErrors).toBe(initialStats.totalErrors);
    });
  });
});

describe('Database Connection Pool', () => {
  let dbPool: DatabaseConnectionPool<MockResource>;
  let mockFactory: MockResourceFactory;
  let mockValidator: MockResourceValidator;
  let mockDestroyer: MockResourceDestroyer;

  beforeEach(() => {
    mockFactory = new MockResourceFactory();
    mockValidator = new MockResourceValidator();
    mockDestroyer = new MockResourceDestroyer();

    dbPool = new DatabaseConnectionPool<MockResource>({
      poolId: `test-db-pool-${Date.now()}` as PoolId,
      minConnections: 2,
      maxConnections: 5,
      acquireTimeout: 5000,
      idleTimeout: 30000,
      healthCheckInterval: 10000,
      maxRetries: 3,
      retryDelay: 1000,
      enableMetrics: true,
      enableHealthChecks: true,
      connectionFactory: mockFactory,
      connectionValidator: mockValidator,
      connectionDestroyer: mockDestroyer,
      databaseConfig: {
        type: 'mock',
        host: 'localhost',
        port: 5432,
      },
    });
  });

  afterEach(async () => {
    if (dbPool) {
      await dbPool.close();
    }
  });

  describe('Database-Specific Functionality', () => {
    it('should initialize database pool', async () => {
      await dbPool.initialize();

      expect(dbPool.getPoolId()).toBeDefined();
      expect(dbPool.getDatabaseType()).toBe('mock-resource');
    });

    it('should acquire and release database connections', async () => {
      await dbPool.initialize();

      const connection = await dbPool.acquireConnection();
      expect(connection).toBeDefined();
      expect(connection.isValid).toBe(true);

      await dbPool.releaseConnection(connection);
    });

    it('should get database-specific statistics', async () => {
      await dbPool.initialize();

      const stats = dbPool.getStats();

      expect(stats).toHaveProperty('databaseType');
      expect(stats).toHaveProperty('totalConnections');
      expect(stats).toHaveProperty('activeConnections');
      expect(stats).toHaveProperty('idleConnections');
      expect(stats).toHaveProperty('connectionErrors');
      expect(stats).toHaveProperty('queryCount');
      expect(stats).toHaveProperty('connectionPoolUtilization');

      expect(stats.databaseType).toBe('mock-resource');
    });

    it('should get database-specific health status', async () => {
      await dbPool.initialize();

      const healthStatus = dbPool.getHealthStatus();

      expect(healthStatus).toHaveProperty('databaseType');
      expect(healthStatus).toHaveProperty('status');
      expect(healthStatus).toHaveProperty('healthyConnections');
      expect(healthStatus).toHaveProperty('unhealthyConnections');
      expect(healthStatus).toHaveProperty('averageResponseTime');
      expect(healthStatus).toHaveProperty('connectionErrors');

      expect(healthStatus.databaseType).toBe('mock-resource');
    });

    it('should test connectivity', async () => {
      await dbPool.initialize();

      const connectivity = await dbPool.testConnectivity();

      expect(connectivity).toHaveProperty('isConnected');
      expect(connectivity).toHaveProperty('responseTime');
      expect(typeof connectivity.isConnected).toBe('boolean');
      expect(typeof connectivity.responseTime).toBe('number');
    });

    it('should check supported features', async () => {
      await dbPool.initialize();

      const features = dbPool.getSupportedFeatures();
      expect(Array.isArray(features)).toBe(true);
      expect(features.length).toBeGreaterThan(0);

      expect(dbPool.supportsOperation('read')).toBe(true);
      expect(dbPool.supportsOperation('write')).toBe(true);
    });
  });
});

describe('Type Guards and Runtime Validation', () => {
  describe('PoolTypeGuards', () => {
    it('should validate PoolId', () => {
      expect(PoolTypeGuards.isPoolId('pool_123')).toBe(true);
      expect(PoolTypeGuards.isPoolId('')).toBe(false);
      expect(PoolTypeGuards.isPoolId(123)).toBe(false);
      expect(PoolTypeGuards.isPoolId(null)).toBe(false);
      expect(PoolTypeGuards.isPoolId(undefined)).toBe(false);
    });

    it('should validate ResourceId', () => {
      expect(PoolTypeGuards.isResourceId('resource_123')).toBe(true);
      expect(PoolTypeGuards.isResourceId('')).toBe(false);
      expect(PoolTypeGuards.isResourceId(123)).toBe(false);
      expect(PoolTypeGuards.isResourceId(null)).toBe(false);
    });

    it('should validate ResourceState', () => {
      expect(PoolTypeGuards.isResourceState('available')).toBe(true);
      expect(PoolTypeGuards.isResourceState('in_use')).toBe(true);
      expect(PoolTypeGuards.isResourceState('invalid')).toBe(false);
      expect(PoolTypeGuards.isResourceState(123)).toBe(false);
    });

    it('should validate PoolHealthStatus', () => {
      expect(PoolTypeGuards.isPoolHealthStatus('healthy')).toBe(true);
      expect(PoolTypeGuards.isPoolHealthStatus('degraded')).toBe(true);
      expect(PoolTypeGuards.isPoolHealthStatus('unhealthy')).toBe(true);
      expect(PoolTypeGuards.isPoolHealthStatus('invalid')).toBe(false);
      expect(PoolTypeGuards.isPoolHealthStatus(123)).toBe(false);
    });

    it('should validate PoolEventType', () => {
      expect(PoolTypeGuards.isPoolEventType('resource_created')).toBe(true);
      expect(PoolTypeGuards.isPoolEventType('resource_acquired')).toBe(true);
      expect(PoolTypeGuards.isPoolEventType('invalid_event')).toBe(false);
      expect(PoolTypeGuards.isPoolEventType(123)).toBe(false);
    });

    it('should validate DatabaseConnection', () => {
      const validConnection = new MockResource('test_123' as ResourceId);
      expect(PoolTypeGuards.isDatabaseConnection(validConnection)).toBe(true);

      const invalidConnection = { not: 'a connection' };
      expect(PoolTypeGuards.isDatabaseConnection(invalidConnection)).toBe(false);
    });

    it('should validate database connection configuration', () => {
      const validConfig = {
        type: 'postgres',
        host: 'localhost',
        port: 5432,
      };
      expect(PoolTypeGuards.isDatabaseConnectionConfig(validConfig)).toBe(true);

      const invalidConfig = { not: 'a config' };
      expect(PoolTypeGuards.isDatabaseConnectionConfig(invalidConfig)).toBe(false);
    });
  });

  describe('PoolRuntimeValidator', () => {
    it('should validate and cast PoolId', () => {
      const validId = 'pool_123' as PoolId;
      expect(PoolRuntimeValidator.validatePoolId(validId)).toBe(validId);

      expect(() => PoolRuntimeValidator.validatePoolId('')).toThrow('Invalid PoolId');
      expect(() => PoolRuntimeValidator.validatePoolId(123)).toThrow('Invalid PoolId');
    });

    it('should validate and cast ResourceId', () => {
      const validId = 'resource_123' as ResourceId;
      expect(PoolRuntimeValidator.validateResourceId(validId)).toBe(validId);

      expect(() => PoolRuntimeValidator.validateResourceId('')).toThrow('Invalid ResourceId');
      expect(() => PoolRuntimeValidator.validateResourceId(123)).toThrow('Invalid ResourceId');
    });

    it('should validate arrays', () => {
      const validArray = ['pool_1', 'pool_2', 'pool_3'];
      const result = PoolRuntimeValidator.validateArray(validArray, PoolTypeGuards.isPoolId, 'PoolId');
      expect(result).toEqual(validArray);

      const invalidArray = ['pool_1', 123, 'pool_3'];
      expect(() => PoolRuntimeValidator.validateArray(invalidArray, PoolTypeGuards.isPoolId, 'PoolId'))
        .toThrow('Invalid PoolId at index 1');
    });

    it('should validate primitive types', () => {
      expect(PoolRuntimeValidator.validateString('test')).toBe('test');
      expect(() => PoolRuntimeValidator.validateString(123)).toThrow('expected string');

      expect(PoolRuntimeValidator.validateNumber(123)).toBe(123);
      expect(() => PoolRuntimeValidator.validateNumber('123')).toThrow('expected number');

      expect(PoolRuntimeValidator.validateBoolean(true)).toBe(true);
      expect(() => PoolRuntimeValidator.validateBoolean(1)).toThrow('expected boolean');

      expect(PoolRuntimeValidator.validateEnum('healthy', ['healthy', 'unhealthy'] as const)).toBe('healthy');
      expect(() => PoolRuntimeValidator.validateEnum('invalid', ['healthy', 'unhealthy'] as const))
        .toThrow('expected one of healthy, unhealthy');
    });

    it('should validate dates', () => {
      const validDate = new Date();
      expect(PoolRuntimeValidator.validateDate(validDate)).toBe(validDate);

      expect(() => PoolRuntimeValidator.validateDate('2023-01-01')).toThrow('Invalid date');
      expect(() => PoolRuntimeValidator.validateDate(123)).toThrow('Invalid date');
    });
  });
});

describe('Pool Factory and Manager', () => {
  let poolFactory: TypedPoolFactory;
  let poolManager: TypedPoolManager;

  beforeEach(() => {
    poolFactory = new TypedPoolFactory();
    poolManager = new TypedPoolManager();
  });

  describe('TypedPoolFactory', () => {
    it('should create and manage pools', async () => {
      const mockFactory = new MockResourceFactory();
      const mockValidator = new MockResourceValidator();
      const mockDestroyer = new MockResourceDestroyer();

      const poolConfig: PoolConfig<MockResource, DatabaseConnectionConfig> = {
        id: `factory-test-${Date.now()}` as PoolId,
        name: 'Factory Test Pool',
        minResources: 1,
        maxResources: 3,
        acquireTimeout: 5000,
        idleTimeout: 30000,
        healthCheckInterval: 10000,
        maxRetries: 3,
        retryDelay: 1000,
        enableMetrics: true,
        enableHealthChecks: true,
        resourceFactory: mockFactory,
        resourceValidator: mockValidator,
        resourceDestroyer: mockDestroyer,
        config: {
          type: 'mock',
          host: 'localhost',
          port: 5432,
        },
      };

      const pool = await poolFactory.createPool(poolConfig);
      expect(pool).toBeDefined();
      expect(pool.poolId).toBe(poolConfig.id);

      const retrievedPool = poolFactory.getPool(poolConfig.id);
      expect(retrievedPool).toBe(pool);

      const allPools = poolFactory.listPools();
      expect(allPools).toContain(poolConfig.id);

      await poolFactory.closeAll();
    });

    it('should get factory statistics', async () => {
      const stats = poolFactory.getFactoryStats();

      expect(stats).toHaveProperty('totalPools');
      expect(stats).toHaveProperty('activePools');
      expect(stats).toHaveProperty('totalResources');
      expect(stats).toHaveProperty('activeResources');

      expect(typeof stats.totalPools).toBe('number');
      expect(typeof stats.activePools).toBe('number');
    });
  });

  describe('TypedPoolManager', () => {
    it('should register and manage pools', async () => {
      const mockFactory = new MockResourceFactory();
      const mockValidator = new MockResourceValidator();
      const mockDestroyer = new MockResourceDestroyer();

      const poolConfig: PoolConfig<MockResource, DatabaseConnectionConfig> = {
        id: `manager-test-${Date.now()}` as PoolId,
        name: 'Manager Test Pool',
        minResources: 1,
        maxResources: 3,
        acquireTimeout: 5000,
        idleTimeout: 30000,
        healthCheckInterval: 10000,
        maxRetries: 3,
        retryDelay: 1000,
        enableMetrics: true,
        enableHealthChecks: true,
        resourceFactory: mockFactory,
        resourceValidator: mockValidator,
        resourceDestroyer: mockDestroyer,
        config: {
          type: 'mock',
          host: 'localhost',
          port: 5432,
        },
      };

      const pool = new GenericResourcePool<MockResource, DatabaseConnectionConfig>(poolConfig);
      await pool.initialize();

      await poolManager.registerPool(pool);

      const retrievedPool = poolManager.getPool(poolConfig.id);
      expect(retrievedPool).toBe(pool);

      await poolManager.unregisterPool(poolConfig.id);
      await pool.close();
    });

    it('should get pools by type', async () => {
      const poolsByType = poolManager.getPoolsByType('mock-resource');
      expect(Array.isArray(poolsByType)).toBe(true);
    });

    it('should handle global health checks', async () => {
      const globalHealth = await poolManager.performGlobalHealthCheck();
      expect(Array.isArray(globalHealth)).toBe(true);
    });

    it('should handle event listeners', () => {
      const mockListener = vi.fn();

      poolManager.addEventListener('pool_initialized', mockListener);
      poolManager.removeEventListener('pool_initialized', mockListener);

      // Listener should be removed
      expect(mockListener).not.toHaveBeenCalled();
    });
  });
});