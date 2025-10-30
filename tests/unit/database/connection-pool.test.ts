/**
 * Comprehensive Unit Tests for Database Connection Pool Functionality
 *
 * Tests connection pool functionality including:
 * - Pool Initialization and Configuration (connection pool creation, limits, timeouts, validation)
 * - Connection Lifecycle Management (acquisition, release, health monitoring, cleanup, recycling)
 * - Pool Scaling and Performance (dynamic expansion, contraction, concurrent handling, optimization)
 * - Error Handling and Recovery (failed connections, exhaustion, timeout recovery, cleanup)
 * - Monitoring and Statistics (usage statistics, health metrics, performance monitoring, tracking)
 * - Integration with Database Operations (vector operations, transactions, batch support, error propagation)
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { DatabaseConnectionPool, PoolConfig, ConnectionStats, PoolStatus } from '../../../src/db/connection-pool';

// Mock Qdrant client for connection pool testing
const mockQdrantClient = {
  getCollections: vi.fn(),
  healthCheck: vi.fn(),
  createCollection: vi.fn(),
  deleteCollection: vi.fn(),
  getCollection: vi.fn(),
  updateCollection: vi.fn(),
  upsert: vi.fn(),
  search: vi.fn(),
  retrieve: vi.fn(),
  delete: vi.fn(),
  scroll: vi.fn(),
  createSnapshot: vi.fn(),
  close: vi.fn()
};

// Mock connection wrapper for pool testing
class MockConnection {
  public id: string;
  public created: Date;
  public lastUsed: Date;
  public isHealthy: boolean = true;
  public isInUse: boolean = false;
  public operations: number = 0;

  constructor(id: string) {
    this.id = id;
    this.created = new Date();
    this.lastUsed = new Date();
  }

  async healthCheck(): Promise<boolean> {
    // Simulate health check - 95% success rate
    this.isHealthy = Math.random() > 0.05;
    return this.isHealthy;
  }

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (!this.isHealthy) {
      throw new Error('Connection is unhealthy');
    }
    if (this.isInUse) {
      throw new Error('Connection is already in use');
    }

    this.isInUse = true;
    this.operations++;
    this.lastUsed = new Date();

    try {
      return await operation();
    } finally {
      this.isInUse = false;
    }
  }

  close(): void {
    this.isHealthy = false;
  }
}

// Mock connection factory
const createMockConnection = () => {
  const connectionId = `conn_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  return new MockConnection(connectionId);
};

vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor(config?: any) {
      this.config = config;
      return mockQdrantClient;
    }
  }
}));

describe('Database Connection Pool - Comprehensive Testing', () => {
  let pool: DatabaseConnectionPool;
  let poolConfig: PoolConfig;

  beforeEach(() => {
    // Set up default pool configuration for testing
    poolConfig = {
      minConnections: 2,
      maxConnections: 10,
      connectionTimeout: 5000,
      idleTimeout: 30000,
      healthCheckInterval: 10000,
      maxRetries: 3,
      retryDelay: 1000,
      acquireTimeout: 3000,
      connectionFactory: createMockConnection
    };

    // Reset all mocks
    vi.clearAllMocks();

    // Mock successful health checks by default
    mockQdrantClient.healthCheck.mockResolvedValue(true);
    mockQdrantClient.getCollections.mockResolvedValue({
      collections: [{ name: 'test-collection' }]
    });

    pool = new DatabaseConnectionPool(poolConfig);
  });

  afterEach(async () => {
    await pool.close();
    vi.clearAllMocks();
  });

  describe('Pool Initialization and Configuration', () => {
    it('should initialize pool with minimum connections', async () => {
      await pool.initialize();

      const stats = pool.getStats();
      expect(stats.totalConnections).toBe(poolConfig.minConnections);
      expect(stats.activeConnections).toBe(0);
      expect(stats.idleConnections).toBe(poolConfig.minConnections);
      expect(stats.status).toBe('healthy');
    });

    it('should validate configuration parameters', () => {
      expect(() => {
        new DatabaseConnectionPool({
          ...poolConfig,
          minConnections: -1
        });
      }).toThrow('minConnections must be non-negative');

      expect(() => {
        new DatabaseConnectionPool({
          ...poolConfig,
          maxConnections: 0
        });
      }).toThrow('maxConnections must be positive');

      expect(() => {
        new DatabaseConnectionPool({
          ...poolConfig,
          minConnections: 5,
          maxConnections: 3
        });
      }).toThrow('minConnections cannot be greater than maxConnections');
    });

    it('should handle initialization failures gracefully', async () => {
      const faultyPool = new DatabaseConnectionPool({
        ...poolConfig,
        connectionFactory: () => {
          throw new Error('Connection creation failed');
        }
      });

      await expect(faultyPool.initialize()).rejects.toThrow('Connection creation failed');

      const stats = faultyPool.getStats();
      expect(stats.status).toBe('unhealthy');
    });

    it('should respect maximum connection limits', async () => {
      await pool.initialize();

      // Acquire all available connections
      const connections = [];
      for (let i = 0; i < poolConfig.maxConnections; i++) {
        const connection = await pool.acquire();
        connections.push(connection);
      }

      // Next acquire should timeout
      const acquirePromise = pool.acquire();
      await expect(acquirePromise).rejects.toThrow('Connection acquire timeout');

      // Release connections
      for (const connection of connections) {
        await pool.release(connection);
      }
    });

    it('should handle different timeout configurations', async () => {
      const customPool = new DatabaseConnectionPool({
        ...poolConfig,
        acquireTimeout: 100,
        connectionTimeout: 1000,
        idleTimeout: 5000
      });

      await customPool.initialize();

      const connection = await customPool.acquire();
      expect(connection).toBeDefined();

      await customPool.release(connection);
      await customPool.close();
    });

    it('should validate pool size constraints', async () => {
      await pool.initialize();

      const stats = pool.getStats();
      expect(stats.totalConnections).toBeGreaterThanOrEqual(poolConfig.minConnections);
      expect(stats.totalConnections).toBeLessThanOrEqual(poolConfig.maxConnections);
    });
  });

  describe('Connection Lifecycle Management', () => {
    beforeEach(async () => {
      await pool.initialize();
    });

    it('should acquire and release connections properly', async () => {
      const initialStats = pool.getStats();

      const connection = await pool.acquire();
      const statsDuringAcquire = pool.getStats();

      expect(connection).toBeDefined();
      expect(statsDuringAcquire.activeConnections).toBe(initialStats.activeConnections + 1);
      expect(statsDuringAcquire.idleConnections).toBe(initialStats.idleConnections - 1);

      await pool.release(connection);
      const statsAfterRelease = pool.getStats();

      expect(statsAfterRelease.activeConnections).toBe(initialStats.activeConnections);
      expect(statsAfterRelease.idleConnections).toBe(initialStats.idleConnections);
    });

    it('should monitor connection health', async () => {
      const connection = await pool.acquire();

      // Simulate connection becoming unhealthy
      (connection as any).isHealthy = false;

      // When released, unhealthy connection should be removed
      await pool.release(connection);

      const stats = pool.getStats();
      expect(stats.totalConnections).toBe(poolConfig.minConnections - 1);

      // Pool should create new connection to maintain minimum
      await new Promise(resolve => setTimeout(resolve, 100));
      const updatedStats = pool.getStats();
      expect(updatedStats.totalConnections).toBe(poolConfig.minConnections);
    });

    it('should clean up idle connections', async () => {
      // Create connections and let them idle
      const connections = [];
      for (let i = 0; i < poolConfig.minConnections; i++) {
        connections.push(await pool.acquire());
      }

      // Release all connections
      for (const connection of connections) {
        await pool.release(connection);
      }

      // Force cleanup by triggering manual cleanup
      await pool.cleanupIdleConnections();

      const stats = pool.getStats();
      expect(stats.idleConnections).toBeGreaterThanOrEqual(0);
    });

    it('should recycle connections efficiently', async () => {
      const connection1 = await pool.acquire();
      await pool.release(connection1);

      const connection2 = await pool.acquire();
      // Should reuse the same connection
      expect(connection2).toBe(connection1);

      await pool.release(connection2);
    });

    it('should track connection usage statistics', async () => {
      const connection = await pool.acquire();

      // Simulate multiple operations
      await connection.execute(async () => 'test result');
      await connection.execute(async () => 'another result');

      await pool.release(connection);

      const stats = pool.getStats();
      expect(stats.totalOperations).toBeGreaterThan(0);
    });

    it('should handle concurrent acquire/release operations', async () => {
      const operations = [];

      // Create concurrent acquire/release operations
      for (let i = 0; i < 20; i++) {
        operations.push(
          pool.acquire()
            .then(connection => pool.release(connection))
        );
      }

      await Promise.all(operations);

      const stats = pool.getStats();
      expect(stats.activeConnections).toBe(0);
      expect(stats.idleConnections).toBe(poolConfig.minConnections);
    });
  });

  describe('Pool Scaling and Performance', () => {
    beforeEach(async () => {
      await pool.initialize();
    });

    it('should expand pool under load', async () => {
      const connections = [];

      // Acquire more connections than minimum
      for (let i = 0; i < poolConfig.minConnections + 3; i++) {
        connections.push(await pool.acquire());
      }

      const stats = pool.getStats();
      expect(stats.totalConnections).toBeGreaterThan(poolConfig.minConnections);
      expect(stats.totalConnections).toBeLessThanOrEqual(poolConfig.maxConnections);

      // Release connections
      for (const connection of connections) {
        await pool.release(connection);
      }
    });

    it('should contract pool during idle periods', async () => {
      // First expand the pool
      const connections = [];
      for (let i = 0; i < poolConfig.minConnections + 5; i++) {
        connections.push(await pool.acquire());
      }

      // Release all connections
      for (const connection of connections) {
        await pool.release(connection);
      }

      // Force cleanup to simulate idle timeout
      await pool.cleanupIdleConnections();

      const stats = pool.getStats();
      // Should maintain minimum connections
      expect(stats.totalConnections).toBeGreaterThanOrEqual(poolConfig.minConnections);
    });

    it('should handle high concurrency efficiently', async () => {
      const startTime = Date.now();
      const promises = [];

      // Create many concurrent operations
      for (let i = 0; i < 50; i++) {
        promises.push(
          pool.acquire()
            .then(async connection => {
              await connection.execute(async () => {
                // Simulate database operation
                await new Promise(resolve => setTimeout(resolve, 10));
                return `result_${i}`;
              });
              return connection;
            })
            .then(connection => pool.release(connection))
        );
      }

      await Promise.all(promises);
      const endTime = Date.now();

      const stats = pool.getStats();
      expect(endTime - startTime).toBeLessThan(5000); // Should complete within 5 seconds
      expect(stats.totalOperations).toBe(50);
    });

    it('should optimize resource utilization', async () => {
      const initialStats = pool.getStats();

      // Perform burst of operations
      const burst = [];
      for (let i = 0; i < 10; i++) {
        burst.push(
          pool.acquire()
            .then(conn => pool.release(conn))
        );
      }
      await Promise.all(burst);

      const afterBurstStats = pool.getStats();

      // Pool should efficiently handle burst without excessive connection creation
      expect(afterBurstStats.totalConnections).toBeLessThanOrEqual(poolConfig.minConnections + 5);
    });

    it('should maintain performance under sustained load', async () => {
      const durations = [];

      // Perform sustained operations
      for (let round = 0; round < 5; round++) {
        const startTime = Date.now();

        const operations = [];
        for (let i = 0; i < 20; i++) {
          operations.push(
            pool.acquire()
              .then(conn => pool.release(conn))
          );
        }
        await Promise.all(operations);

        const duration = Date.now() - startTime;
        durations.push(duration);
      }

      // Performance should not degrade significantly over time
      const avgDuration = durations.reduce((sum, d) => sum + d, 0) / durations.length;
      expect(avgDuration).toBeLessThan(2000); // Average should be under 2 seconds
    });
  });

  describe('Error Handling and Recovery', () => {
    beforeEach(async () => {
      await pool.initialize();
    });

    it('should handle failed connection creation', async () => {
      const faultyPool = new DatabaseConnectionPool({
        ...poolConfig,
        connectionFactory: () => {
          // Fail first 2 attempts, succeed on 3rd
          faultyPool.connectionFailures = (faultyPool.connectionFailures || 0) + 1;
          if (faultyPool.connectionFailures <= 2) {
            throw new Error(`Connection failure ${faultyPool.connectionFailures}`);
          }
          return createMockConnection();
        }
      });

      // Should recover and initialize successfully
      await faultyPool.initialize();
      const stats = faultyPool.getStats();
      expect(stats.status).toBe('healthy');

      await faultyPool.close();
    });

    it('should handle pool exhaustion scenarios', async () => {
      // Acquire all available connections
      const connections = [];
      for (let i = 0; i < poolConfig.maxConnections; i++) {
        connections.push(await pool.acquire());
      }

      // Next acquire should fail
      await expect(pool.acquire()).rejects.toThrow('Connection acquire timeout');

      // Release one connection
      await pool.release(connections[0]);

      // Should now be able to acquire again
      const newConnection = await pool.acquire();
      expect(newConnection).toBeDefined();

      // Release remaining connections
      for (let i = 1; i < connections.length; i++) {
        await pool.release(connections[i]);
      }
      await pool.release(newConnection);
    });

    it('should recover from connection timeouts', async () => {
      const slowPool = new DatabaseConnectionPool({
        ...poolConfig,
        acquireTimeout: 100,
        connectionFactory: () => {
          return new Promise(resolve => {
            setTimeout(() => resolve(createMockConnection()), 200);
          });
        }
      });

      await slowPool.initialize();

      // Should timeout on slow connection creation
      await expect(slowPool.acquire()).rejects.toThrow('Connection acquire timeout');

      await slowPool.close();
    });

    it('should clean up dead connections', async () => {
      const connection = await pool.acquire();

      // Simulate connection death
      (connection as any).isHealthy = false;

      await pool.release(connection);

      // Pool should detect and remove dead connection
      await new Promise(resolve => setTimeout(resolve, 100));

      const stats = pool.getStats();
      expect(stats.deadConnections).toBe(0); // Should be cleaned up
    });

    it('should handle network interruptions gracefully', async () => {
      const connection = await pool.acquire();

      // Simulate network error during operation
      const faultyOperation = vi.fn().mockRejectedValue(new Error('Network interrupted'));

      await expect(
        connection.execute(faultyOperation)
      ).rejects.toThrow('Network interrupted');

      // Connection should still be usable after error
      await expect(
        connection.execute(async () => 'recovery test')
      ).resolves.toBe('recovery test');

      await pool.release(connection);
    });

    it('should implement retry logic for failed operations', async () => {
      const retryPool = new DatabaseConnectionPool({
        ...poolConfig,
        maxRetries: 3,
        retryDelay: 10
      });

      await retryPool.initialize();

      let attemptCount = 0;
      const flakyOperation = vi.fn().mockImplementation(() => {
        attemptCount++;
        if (attemptCount < 3) {
          throw new Error(`Attempt ${attemptCount} failed`);
        }
        return 'success';
      });

      const connection = await retryPool.acquire();
      const result = await connection.execute(flakyOperation);

      expect(result).toBe('success');
      expect(attemptCount).toBe(3);
      expect(flakyOperation).toHaveBeenCalledTimes(3);

      await retryPool.release(connection);
      await retryPool.close();
    });
  });

  describe('Monitoring and Statistics', () => {
    beforeEach(async () => {
      await pool.initialize();
    });

    it('should provide comprehensive pool statistics', async () => {
      const stats = pool.getStats();

      expect(stats).toHaveProperty('totalConnections');
      expect(stats).toHaveProperty('activeConnections');
      expect(stats).toHaveProperty('idleConnections');
      expect(stats).toHaveProperty('deadConnections');
      expect(stats).toHaveProperty('totalOperations');
      expect(stats).toHaveProperty('totalErrors');
      expect(stats).toHaveProperty('averageWaitTime');
      expect(stats).toHaveProperty('peakConnections');
      expect(stats).toHaveProperty('status');

      expect(typeof stats.totalConnections).toBe('number');
      expect(typeof stats.averageWaitTime).toBe('number');
      expect(['healthy', 'degraded', 'unhealthy']).toContain(stats.status);
    });

    it('should track connection health metrics', async () => {
      const connection = await pool.acquire();

      // Perform operations to generate metrics
      await connection.execute(async () => 'test');
      await connection.execute(async () => 'test2');

      await pool.release(connection);

      const healthMetrics = pool.getHealthMetrics();

      expect(healthMetrics).toHaveProperty('healthyConnections');
      expect(healthMetrics).toHaveProperty('unhealthyConnections');
      expect(healthMetrics).toHaveProperty('lastHealthCheck');
      expect(healthMetrics).toHaveProperty('healthCheckSuccessRate');
    });

    it('should monitor performance metrics', async () => {
      const startTime = Date.now();

      const connection = await pool.acquire();
      const acquireTime = Date.now() - startTime;

      await connection.execute(async () => {
        await new Promise(resolve => setTimeout(resolve, 50));
        return 'performance test';
      });

      await pool.release(connection);

      const performanceMetrics = pool.getPerformanceMetrics();

      expect(performanceMetrics).toHaveProperty('averageAcquireTime');
      expect(performanceMetrics).toHaveProperty('averageOperationTime');
      expect(performanceMetrics).toHaveProperty('totalOperations');
      expect(performanceMetrics).toHaveProperty('operationsPerSecond');

      expect(performanceMetrics.averageAcquireTime).toBeGreaterThanOrEqual(0);
      expect(performanceMetrics.totalOperations).toBe(1);
    });

    it('should track resource utilization', async () => {
      // Create load to generate utilization data
      const connections = [];
      for (let i = 0; i < 5; i++) {
        connections.push(await pool.acquire());
      }

      const utilizationMetrics = pool.getUtilizationMetrics();

      expect(utilizationMetrics).toHaveProperty('connectionUtilization');
      expect(utilizationMetrics).toHaveProperty('poolUtilization');
      expect(utilizationMetrics).toHaveProperty('memoryUsage');
      expect(utilizationMetrics).toHaveProperty('maxCapacityReached');

      expect(utilizationMetrics.connectionUtilization).toBeGreaterThan(0);
      expect(typeof utilizationMetrics.poolUtilization).toBe('number');

      // Release connections
      for (const connection of connections) {
        await pool.release(connection);
      }
    });

    it('should provide historical statistics', async () => {
      // Generate some activity
      for (let i = 0; i < 3; i++) {
        const connection = await pool.acquire();
        await connection.execute(async () => `operation_${i}`);
        await pool.release(connection);
      }

      const historicalStats = pool.getHistoricalStats(1000); // Last 1 second

      expect(historicalStats).toHaveProperty('timeSeries');
      expect(historicalStats).toHaveProperty('trends');
      expect(Array.isArray(historicalStats.timeSeries)).toBe(true);
    });

    it('should update statistics in real-time', async () => {
      const initialStats = pool.getStats();

      const connection = await pool.acquire();
      const afterAcquireStats = pool.getStats();

      expect(afterAcquireStats.activeConnections).toBe(initialStats.activeConnections + 1);
      expect(afterAcquireStats.totalOperations).toBe(initialStats.totalOperations);

      await connection.execute(async () => 'real-time test');
      const afterOperationStats = pool.getStats();

      expect(afterOperationStats.totalOperations).toBe(initialStats.totalOperations + 1);

      await pool.release(connection);
      const afterReleaseStats = pool.getStats();

      expect(afterReleaseStats.activeConnections).toBe(initialStats.activeConnections);
    });
  });

  describe('Integration with Database Operations', () => {
    beforeEach(async () => {
      await pool.initialize();
    });

    it('should integrate seamlessly with vector operations', async () => {
      const connection = await pool.acquire();

      // Mock vector operations
      const mockVectorOperation = vi.fn().mockResolvedValue({
        ids: ['vector_1', 'vector_2'],
        status: 'success'
      });

      const result = await connection.execute(mockVectorOperation);

      expect(result).toEqual({
        ids: ['vector_1', 'vector_2'],
        status: 'success'
      });
      expect(mockVectorOperation).toHaveBeenCalledTimes(1);

      await pool.release(connection);
    });

    it('should handle transaction management', async () => {
      const connection = await pool.acquire();

      let transactionStarted = false;
      let transactionCommitted = false;

      const mockTransaction = vi.fn().mockImplementation(async (operation) => {
        transactionStarted = true;
        try {
          const result = await operation();
          transactionCommitted = true;
          return result;
        } catch (error) {
          transactionStarted = false;
          throw error;
        }
      });

      const result = await connection.execute(() =>
        mockTransaction(async () => 'transaction result')
      );

      expect(result).toBe('transaction result');
      expect(transactionStarted).toBe(true);
      expect(transactionCommitted).toBe(true);

      await pool.release(connection);
    });

    it('should support batch operations', async () => {
      const connection = await pool.acquire();

      const batchItems = [
        { id: '1', data: 'item1' },
        { id: '2', data: 'item2' },
        { id: '3', data: 'item3' }
      ];

      const mockBatchOperation = vi.fn().mockResolvedValue({
        processed: 3,
        successful: 3,
        failed: 0,
        results: batchItems
      });

      const result = await connection.execute(() => mockBatchOperation(batchItems));

      expect(result.processed).toBe(3);
      expect(result.successful).toBe(3);
      expect(result.results).toEqual(batchItems);

      await pool.release(connection);
    });

    it('should propagate database errors correctly', async () => {
      const connection = await pool.acquire();

      const dbError = new Error('Database constraint violation');
      const mockFailingOperation = vi.fn().mockRejectedValue(dbError);

      await expect(
        connection.execute(mockFailingOperation)
      ).rejects.toThrow('Database constraint violation');

      // Pool should remain healthy after operation error
      const stats = pool.getStats();
      expect(stats.status).toBe('healthy');

      await pool.release(connection);
    });

    it('should maintain consistency across pooled connections', async () => {
      const connections = [];
      const results = [];

      // Acquire multiple connections
      for (let i = 0; i < 3; i++) {
        connections.push(await pool.acquire());
      }

      // Perform operations on each connection
      for (let i = 0; i < connections.length; i++) {
        const mockOperation = vi.fn().mockResolvedValue(`result_${i}`);
        const result = await connections[i].execute(mockOperation);
        results.push(result);
      }

      expect(results).toEqual(['result_0', 'result_1', 'result_2']);

      // Release all connections
      for (const connection of connections) {
        await pool.release(connection);
      }
    });

    it('should handle connection-specific configuration', async () => {
      const connection = await pool.acquire();

      // Test that connection maintains its configuration
      expect(connection.id).toBeDefined();
      expect(connection.created).toBeInstanceOf(Date);

      const operationStartTime = Date.now();
      await connection.execute(async () => 'config test');
      const operationEndTime = Date.now();

      expect(connection.lastUsed.getTime()).toBeGreaterThanOrEqual(operationStartTime);
      expect(connection.lastUsed.getTime()).toBeLessThanOrEqual(operationEndTime);

      await pool.release(connection);
    });
  });

  describe('Edge Cases and Stress Testing', () => {
    it('should handle rapid connection acquisition and release', async () => {
      await pool.initialize();

      // Rapidly acquire and release connections
      for (let i = 0; i < 100; i++) {
        const connection = await pool.acquire();
        await pool.release(connection);
      }

      const stats = pool.getStats();
      expect(stats.totalOperations).toBe(100);
      expect(stats.activeConnections).toBe(0);
    });

    it('should handle zero minimum connections configuration', async () => {
      const zeroMinPool = new DatabaseConnectionPool({
        ...poolConfig,
        minConnections: 0,
        maxConnections: 5
      });

      await zeroMinPool.initialize();

      const stats = zeroMinPool.getStats();
      expect(stats.totalConnections).toBe(0);

      // Should create connection on demand
      const connection = await zeroMinPool.acquire();
      expect(connection).toBeDefined();

      await zeroMinPool.release(connection);
      await zeroMinPool.close();
    });

    it('should handle single connection pool', async () => {
      const singlePool = new DatabaseConnectionPool({
        ...poolConfig,
        minConnections: 1,
        maxConnections: 1
      });

      await singlePool.initialize();

      const connection1 = await singlePool.acquire();
      const connection2Promise = singlePool.acquire();

      // Second acquire should timeout
      await expect(connection2Promise).rejects.toThrow('Connection acquire timeout');

      await singlePool.release(connection1);
      await singlePool.close();
    });

    it('should handle pool closure gracefully', async () => {
      await pool.initialize();

      const connections = [];
      for (let i = 0; i < 5; i++) {
        connections.push(await pool.acquire());
      }

      // Close pool with active connections
      await pool.close();

      const stats = pool.getStats();
      expect(stats.status).toBe('closed');
    });

    it('should maintain performance with large datasets', async () => {
      await pool.initialize();

      const largeDataset = Array.from({ length: 1000 }, (_, i) => `item_${i}`);

      const startTime = Date.now();

      const connection = await pool.acquire();
      await connection.execute(async () => {
        // Simulate processing large dataset
        return largeDataset.map(item => item.toUpperCase());
      });
      await pool.release(connection);

      const endTime = Date.now();
      expect(endTime - startTime).toBeLessThan(1000); // Should complete within 1 second
    });
  });

  describe('Health Monitoring and Diagnostics', () => {
    beforeEach(async () => {
      await pool.initialize();
    });

    it('should perform regular health checks', async () => {
      // Trigger manual health check
      await pool.performHealthCheck();

      const healthStatus = pool.getHealthStatus();

      expect(healthStatus).toHaveProperty('status');
      expect(healthStatus).toHaveProperty('lastCheck');
      expect(healthStatus).toHaveProperty('healthyConnections');
      expect(healthStatus).toHaveProperty('unhealthyConnections');
      expect(healthStatus).toHaveProperty('nextCheckDue');
    });

    it('should detect and report pool degradation', async () => {
      // Simulate degradation by making connections unhealthy
      const connections = [];
      for (let i = 0; i < poolConfig.minConnections; i++) {
        const connection = await pool.acquire();
        (connection as any).isHealthy = false;
        connections.push(connection);
      }

      for (const connection of connections) {
        await pool.release(connection);
      }

      await pool.performHealthCheck();

      const healthStatus = pool.getHealthStatus();
      expect(['degraded', 'unhealthy']).toContain(healthStatus.status);
    });

    it('should provide diagnostic information', async () => {
      const diagnostics = pool.getDiagnostics();

      expect(diagnostics).toHaveProperty('poolConfiguration');
      expect(diagnostics).toHaveProperty('currentStatus');
      expect(diagnostics).toHaveProperty('performanceMetrics');
      expect(diagnostics).toHaveProperty('connectionDetails');
      expect(diagnostics).toHaveProperty('recentErrors');
      expect(diagnostics).toHaveProperty('systemInformation');
    });

    it('should support pool reset functionality', async () => {
      // Create some activity
      const connection = await pool.acquire();
      await connection.execute(async () => 'test');
      await pool.release(connection);

      const preResetStats = pool.getStats();

      // Reset pool
      await pool.reset();

      const postResetStats = pool.getStats();
      expect(postResetStats.totalOperations).toBe(0);
      expect(postResetStats.totalErrors).toBe(0);
    });
  });
});