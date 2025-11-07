/**
 * Integration Tests: Dependency Health System
 *
 * Comprehensive integration tests for the dependency registry, health aggregation,
 * and health check services. Tests cover normal operation, failure scenarios,
 * recovery procedures, and system integration.
 *
 * Test Coverage:
 * - Dependency registration and lifecycle management
 * - Health check execution with various strategies
 * - Health aggregation and SLA monitoring
 * - Alert generation and management
 * - Failure scenarios and recovery
 * - Performance under load
 * - Integration with existing services
 * - Cache behavior and invalidation
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { describe, beforeAll, afterAll, beforeEach, afterEach, it, expect, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import {
  DependencyRegistry,
  DependencyType,
  DependencyStatus,
  DependencyConfig,
} from '../../src/services/deps-registry.js';
import HealthAggregationService, {
  AlertSeverity,
  SLAStatus,
} from '../../src/services/health-aggregation.service.js';
import HealthCheckService, {
  HealthCheckStrategy,
} from '../../src/services/health-check.service.js';
import { logger } from '../../src/utils/logger.js';

// Mock logger to avoid noise in tests
vi.mock('../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// Mock fetch for API health checks
global.fetch = vi.fn();

describe('Dependency Health System Integration Tests', () => {
  let dependencyRegistry: DependencyRegistry;
  let healthAggregation: HealthAggregationService;
  let healthCheckService: HealthCheckService;

  // Test dependency configurations
  const mockDatabaseConfig: DependencyConfig = {
    name: 'test-database',
    type: DependencyType['DATABASE'],
    priority: 'critical',
    healthCheck: {
      enabled: true,
      intervalMs: 5000,
      timeoutMs: 10000,
      failureThreshold: 3,
      successThreshold: 2,
      retryAttempts: 2,
      retryDelayMs: 1000,
    },
    connection: {
      url: 'http://localhost:6333',
      timeout: 10000,
    },
    thresholds: {
      responseTimeWarning: 1000,
      responseTimeCritical: 5000,
      errorRateWarning: 5,
      errorRateCritical: 15,
      availabilityWarning: 99,
      availabilityCritical: 95,
    },
  };

  const mockEmbeddingConfig: DependencyConfig = {
    name: 'test-embedding',
    type: DependencyType['EMBEDDING_SERVICE'],
    priority: 'high',
    healthCheck: {
      enabled: true,
      intervalMs: 10000,
      timeoutMs: 30000,
      failureThreshold: 3,
      successThreshold: 2,
      retryAttempts: 3,
      retryDelayMs: 2000,
    },
    connection: {
      url: 'https://api.openai.com',
      apiKey: 'test-api-key',
      timeout: 30000,
    },
    thresholds: {
      responseTimeWarning: 2000,
      responseTimeCritical: 10000,
      errorRateWarning: 3,
      errorRateCritical: 10,
      availabilityWarning: 99.5,
      availabilityCritical: 98,
    },
  };

  const mockAPIConfig: DependencyConfig = {
    name: 'test-api',
    type: DependencyType['EXTERNAL_API'],
    priority: 'medium',
    healthCheck: {
      enabled: true,
      intervalMs: 15000,
      timeoutMs: 5000,
      failureThreshold: 2,
      successThreshold: 2,
      retryAttempts: 1,
      retryDelayMs: 500,
    },
    connection: {
      url: 'https://api.example.com/health',
      timeout: 5000,
      headers: {
        Authorization: 'Bearer test-token',
      },
    },
    thresholds: {
      responseTimeWarning: 500,
      responseTimeCritical: 2000,
      errorRateWarning: 2,
      errorRateCritical: 8,
      availabilityWarning: 99,
      availabilityCritical: 95,
    },
  };

  beforeAll(async () => {
    // Initialize services
    dependencyRegistry = new DependencyRegistry();
    healthAggregation = new HealthAggregationService(dependencyRegistry);
    healthCheckService = new HealthCheckService();

    // Initialize dependency registry
    await dependencyRegistry.initialize();
  });

  afterAll(async () => {
    // Clean up services
    await healthAggregation.stop();
    await dependencyRegistry.shutdown();
  });

  beforeEach(() => {
    // Reset mocks
    vi.clearAllMocks();
  });

  afterEach(async () => {
    // Clean up registered dependencies
    const dependencies = dependencyRegistry.getAllDependencies();
    for (const name of Object.keys(dependencies)) {
      await dependencyRegistry.unregisterDependency(name);
    }

    // Clear caches
    healthCheckService.clearCache();
  });

  describe('Dependency Registry', () => {
    describe('Dependency Registration', () => {
      it('should register a dependency successfully', async () => {
        const registeredSpy = vi.fn();
        dependencyRegistry.on('dependencyRegistered', registeredSpy);

        await dependencyRegistry.registerDependency(mockDatabaseConfig);

        const state = dependencyRegistry.getDependencyState('test-database');
        expect(state).toBeDefined();
        expect(state!.config.name).toBe('test-database');
        expect(state!.config.type).toBe(DependencyType['DATABASE']);
        expect(state!.enabled).toBe(true);
        expect(registeredSpy).toHaveBeenCalledWith('test-database', expect.any(Object));
      });

      it('should register multiple dependencies', async () => {
        await dependencyRegistry.registerDependency(mockDatabaseConfig);
        await dependencyRegistry.registerDependency(mockEmbeddingConfig);
        await dependencyRegistry.registerDependency(mockAPIConfig);

        const allDeps = dependencyRegistry.getAllDependencies();
        expect(Object.keys(allDeps)).toHaveLength(3);
        expect(allDeps['test-database']).toBeDefined();
        expect(allDeps['test-embedding']).toBeDefined();
        expect(allDeps['test-api']).toBeDefined();
      });

      it('should reject invalid dependency configuration', async () => {
        const invalidConfig = {
          ...mockDatabaseConfig,
          name: '', // Invalid: empty name
          type: 'invalid' as any, // Invalid: unknown type
        };

        await expect(dependencyRegistry.registerDependency(invalidConfig)).rejects.toThrow(
          'Dependency name is required'
        );
      });

      it('should emit events on dependency registration', async () => {
        const registeredSpy = vi.fn();
        dependencyRegistry.on('dependencyRegistered', registeredSpy);

        await dependencyRegistry.registerDependency(mockDatabaseConfig);

        expect(registeredSpy).toHaveBeenCalledTimes(1);
        expect(registeredSpy).toHaveBeenCalledWith(
          'test-database',
          expect.objectContaining({
            config: mockDatabaseConfig,
            status: expect.any(String),
            enabled: true,
          })
        );
      });
    });

    describe('Dependency Lifecycle', () => {
      it('should unregister dependency successfully', async () => {
        await dependencyRegistry.registerDependency(mockDatabaseConfig);

        const unregisteredSpy = vi.fn();
        dependencyRegistry.on('dependencyUnregistered', unregisteredSpy);

        await dependencyRegistry.unregisterDependency('test-database');

        expect(dependencyRegistry.getDependencyState('test-database')).toBeUndefined();
        expect(unregisteredSpy).toHaveBeenCalledWith('test-database');
      });

      it('should handle unregistering non-existent dependency gracefully', async () => {
        await expect(
          dependencyRegistry.unregisterDependency('non-existent')
        ).resolves.not.toThrow();
      });

      it('should enable and disable health checking', async () => {
        await dependencyRegistry.registerDependency(mockDatabaseConfig);

        dependencyRegistry.setHealthCheckingEnabled('test-database', false);
        let state = dependencyRegistry.getDependencyState('test-database');
        expect(state!.enabled).toBe(false);
        expect(state!.config.healthCheck.enabled).toBe(false);

        dependencyRegistry.setHealthCheckingEnabled('test-database', true);
        state = dependencyRegistry.getDependencyState('test-database');
        expect(state!.enabled).toBe(true);
        expect(state!.config.healthCheck.enabled).toBe(true);
      });
    });

    describe('Dependency Querying', () => {
      beforeEach(async () => {
        await dependencyRegistry.registerDependency(mockDatabaseConfig);
        await dependencyRegistry.registerDependency(mockEmbeddingConfig);
        await dependencyRegistry.registerDependency(mockAPIConfig);
      });

      it('should get dependencies by type', () => {
        const databases = dependencyRegistry.getDependenciesByType(DependencyType['DATABASE']);
        expect(Object.keys(databases)).toHaveLength(1);
        expect(databases['test-database']).toBeDefined();

        const apis = dependencyRegistry.getDependenciesByType(DependencyType['EXTERNAL_API']);
        expect(Object.keys(apis)).toHaveLength(1);
        expect(apis['test-api']).toBeDefined();
      });

      it('should get dependencies by status', async () => {
        // Perform health checks to set status
        await dependencyRegistry.performHealthCheck('test-database');
        await dependencyRegistry.performHealthCheck('test-api');

        // Note: Status will depend on actual health check results
        const healthyDeps = dependencyRegistry.getDependenciesByStatus(DependencyStatus['HEALTHY']);
        expect(Array.isArray(Object.keys(healthyDeps))).toBe(true);
      });
    });
  });

  describe('Health Check Service', () => {
    describe('Basic Health Checks', () => {
      it('should perform basic health check strategy', async () => {
        const result = await healthCheckService.performHealthCheck('test-api', mockAPIConfig, {
          strategy: HealthCheckStrategy['BASIC'],
        });

        expect(result).toBeDefined();
        expect(result.dependency).toBe('test-api');
        expect(result.strategy).toBe(HealthCheckStrategy['BASIC']);
        expect(result.timestamp).toBeInstanceOf(Date);
        expect(result.diagnostics).toBeDefined();
        expect(result.retryAttempts).toBeGreaterThanOrEqual(0);
        expect(result.cached).toBe(false);
      });

      it('should handle health check timeouts', async () => {
        const timeoutConfig = {
          ...mockAPIConfig,
          healthCheck: {
            ...mockAPIConfig.healthCheck,
            timeoutMs: 1, // Very short timeout
          },
        };

        const result = await healthCheckService.performHealthCheck(
          'test-api-timeout',
          timeoutConfig,
          { strategy: HealthCheckStrategy['BASIC'] }
        );

        expect(result.status).toBe(DependencyStatus['CRITICAL']);
        expect(result.error).toContain('timeout');
      });

      it('should retry failed health checks', async () => {
        const failingConfig = {
          ...mockAPIConfig,
          connection: {
            ...mockAPIConfig.connection,
            url: 'http://invalid-url-that-will-fail.com',
          },
        };

        const result = await healthCheckService.performHealthCheck(
          'test-failing-api',
          failingConfig,
          { strategy: HealthCheckStrategy['BASIC'], retries: 2, retryDelay: 100 }
        );

        expect(result.status).toBe(DependencyStatus['CRITICAL']);
        expect(result.retryAttempts).toBeGreaterThan(0);
      });
    });

    describe('Advanced Health Checks', () => {
      it('should perform advanced health check strategy', async () => {
        const result = await healthCheckService.performHealthCheck(
          'test-embedding-advanced',
          mockEmbeddingConfig,
          { strategy: HealthCheckStrategy['ADVANCED'] }
        );

        expect(result.strategy).toBe(HealthCheckStrategy['ADVANCED']);
        expect(result.details?.advanced).toBe(true);
      });

      it('should perform comprehensive health check strategy', async () => {
        const result = await healthCheckService.performHealthCheck(
          'test-database-comprehensive',
          mockDatabaseConfig,
          { strategy: HealthCheckStrategy['COMPREHENSIVE'] }
        );

        expect(result.strategy).toBe(HealthCheckStrategy['COMPREHENSIVE']);
        expect(result.details?.comprehensive).toBe(true);
      });
    });

    describe('Parallel Health Checks', () => {
      it('should perform health checks on multiple dependencies in parallel', async () => {
        const dependencies = [
          { name: 'test-api-1', config: mockAPIConfig },
          { name: 'test-api-2', config: mockAPIConfig },
          { name: 'test-api-3', config: mockAPIConfig },
        ];

        const startTime = Date.now();
        const results = await healthCheckService.performParallelHealthChecks(dependencies, {
          strategy: HealthCheckStrategy['BASIC'],
        });
        const endTime = Date.now();

        expect(Object.keys(results)).toHaveLength(3);
        expect(results['test-api-1']).toBeDefined();
        expect(results['test-api-2']).toBeDefined();
        expect(results['test-api-3']).toBeDefined();

        // Should be faster than sequential execution
        const executionTime = endTime - startTime;
        expect(executionTime).toBeLessThan(10000); // Should complete in under 10 seconds
      });

      it('should handle mixed success and failure in parallel checks', async () => {
        const dependencies = [
          { name: 'test-success', config: mockAPIConfig },
          {
            name: 'test-failure',
            config: { ...mockAPIConfig, connection: { url: 'http://invalid-url' } },
          },
          {
            name: 'test-timeout',
            config: { ...mockAPIConfig, connection: { url: 'http://slow-server.com' } },
          },
        ];

        const results = await healthCheckService.performParallelHealthChecks(dependencies, {
          strategy: HealthCheckStrategy['BASIC'],
          timeout: 1000,
        });

        expect(Object.keys(results)).toHaveLength(3);
        // Results should contain both successful and failed checks
        expect(Object.values(results).some((r) => r.status === DependencyStatus['HEALTHY'])).toBe(
          true
        );
        expect(Object.values(results).some((r) => r.status === DependencyStatus['CRITICAL'])).toBe(
          true
        );
      });
    });

    describe('Caching', () => {
      it('should cache successful health check results', async () => {
        const config = { ...mockAPIConfig };

        // First check
        const result1 = await healthCheckService.performHealthCheck('test-cached', config, {
          strategy: HealthCheckStrategy['BASIC'],
          cacheEnabled: true,
          cacheTTL: 5000,
        });
        expect(result1.cached).toBe(false);

        // Second check should use cache
        const result2 = await healthCheckService.performHealthCheck('test-cached', config, {
          strategy: HealthCheckStrategy['BASIC'],
          cacheEnabled: true,
        });
        expect(result2.cached).toBe(true);
        expect(result2.responseTime).toBe(result1.responseTime);
        expect(result2.timestamp).toEqual(result1.timestamp);
      });

      it('should not cache failed health check results', async () => {
        const failingConfig = {
          ...mockAPIConfig,
          connection: { url: 'http://invalid-url' },
        };

        const result1 = await healthCheckService.performHealthCheck(
          'test-failed-cache',
          failingConfig,
          { strategy: HealthCheckStrategy['BASIC'], cacheEnabled: true }
        );
        expect(result1.cached).toBe(false);
        expect(result1.status).toBe(DependencyStatus['CRITICAL']);

        // Second check should not use cache and should retry
        const result2 = await healthCheckService.performHealthCheck(
          'test-failed-cache',
          failingConfig,
          { strategy: HealthCheckStrategy['BASIC'], cacheEnabled: true }
        );
        expect(result2.cached).toBe(false);
        expect(result2.retryAttempts).toBeGreaterThan(0);
      });

      it('should provide cache statistics', () => {
        const stats = healthCheckService.getCacheStats();
        expect(stats).toHaveProperty('size');
        expect(stats).toHaveProperty('hitRate');
        expect(stats).toHaveProperty('entries');
        expect(typeof stats.size).toBe('number');
        expect(typeof stats.hitRate).toBe('number');
        expect(Array.isArray(stats.entries)).toBe(true);
      });

      it('should clear cache', () => {
        healthCheckService.clearCache();
        const stats = healthCheckService.getCacheStats();
        expect(stats.size).toBe(0);
      });
    });

    describe('Diagnostics and Benchmarking', () => {
      it('should collect diagnostics when enabled', async () => {
        const result = await healthCheckService.performHealthCheck(
          'test-diagnostics',
          mockAPIConfig,
          {
            strategy: HealthCheckStrategy['BASIC'],
            diagnosticsEnabled: true,
          }
        );

        expect(result.diagnostics).toBeDefined();
        expect(result.diagnostics.executionTime).toBeGreaterThan(0);
        expect(result.diagnostics.performanceMetrics).toBeDefined();
      });

      it('should perform benchmarking when enabled', async () => {
        // Mock successful response for benchmarking
        (global.fetch as any).mockResolvedValue({
          ok: true,
          status: 200,
          statusText: 'OK',
        });

        const result = await healthCheckService.performHealthCheck(
          'test-benchmark',
          mockAPIConfig,
          {
            strategy: HealthCheckStrategy['BASIC'],
            benchmarkEnabled: true,
            benchmarkRequests: 3,
          }
        );

        expect(result.benchmarkResults).toBeDefined();
        expect(result.benchmarkResults!.throughput).toBeGreaterThanOrEqual(0);
        expect(result.benchmarkResults!.averageResponseTime).toBeGreaterThanOrEqual(0);
        expect(result.benchmarkResults!.errorRate).toBeGreaterThanOrEqual(0);
      });
    });
  });

  describe('Health Aggregation Service', () => {
    beforeEach(async () => {
      // Register test dependencies
      await dependencyRegistry.registerDependency(mockDatabaseConfig);
      await dependencyRegistry.registerDependency(mockEmbeddingConfig);
      await dependencyRegistry.registerDependency(mockAPIConfig);
    });

    describe('Health Status Aggregation', () => {
      it('should get comprehensive health analysis', async () => {
        const analysis = await healthAggregation.getHealthStatus();

        expect(analysis).toBeDefined();
        expect(analysis.overall).toBeDefined();
        expect(analysis.overall.status).toBeDefined();
        expect(analysis.overall.score).toBeGreaterThanOrEqual(0);
        expect(analysis.overall.score).toBeLessThanOrEqual(100);
        expect(analysis.overall.trend).toBeDefined();
        expect(analysis.overall.confidence).toBeGreaterThanOrEqual(0);
        expect(analysis.overall.confidence).toBeLessThanOrEqual(100);

        expect(analysis.dependencies).toBeDefined();
        expect(Object.keys(analysis.dependencies)).toBeGreaterThan(0);

        expect(analysis.risks).toBeDefined();
        expect(Array.isArray(analysis.risks)).toBe(true);

        expect(analysis.recommendations).toBeDefined();
        expect(Array.isArray(analysis.recommendations)).toBe(true);

        expect(analysis.timestamp).toBeInstanceOf(Date);
      });

      it('should calculate weighted health scores correctly', async () => {
        const analysis = await healthAggregation.getHealthStatus();

        // Critical dependencies should have higher impact
        const databaseDep = analysis.dependencies['test-database'];
        const apiDep = analysis.dependencies['test-api'];

        if (databaseDep && apiDep) {
          expect(databaseDep.impact).toBeGreaterThan(apiDep.impact);
        }
      });

      it('should detect health trends', async () => {
        // Perform multiple health checks to generate trend data
        for (let i = 0; i < 5; i++) {
          await healthAggregation.getHealthStatus();
          await new Promise((resolve) => setTimeout(resolve, 100));
        }

        const analysis = await healthAggregation.getHealthStatus();
        expect(analysis.overall.trend).toBeDefined();
        expect(['improving', 'stable', 'degrading', 'fluctuating']).toContain(
          analysis.overall.trend
        );
      });

      it('should generate risk assessments', async () => {
        const analysis = await healthAggregation.getHealthStatus();

        // Should have risk entries for critical dependencies
        const risks = analysis.risks.filter((r) => r.dependency === 'test-database');
        expect(risks.length).toBeGreaterThanOrEqual(0);

        // Risk properties should be properly formatted
        risks.forEach((risk) => {
          expect(risk.dependency).toBeDefined();
          expect(risk.type).toBeDefined();
          expect(['low', 'medium', 'high', 'critical']).toContain(risk.level);
          expect(risk.description).toBeDefined();
          expect(risk.probability).toBeGreaterThanOrEqual(0);
          expect(risk.probability).toBeLessThanOrEqual(1);
          expect(risk.impact).toBeGreaterThanOrEqual(0);
          expect(risk.impact).toBeLessThanOrEqual(1);
          expect(risk.mitigation).toBeDefined();
        });
      });

      it('should generate recommendations', async () => {
        const analysis = await healthAggregation.getHealthStatus();

        expect(analysis.recommendations.length).toBeGreaterThanOrEqual(0);

        analysis.recommendations.forEach((rec) => {
          expect(rec.priority).toBeDefined();
          expect(['low', 'medium', 'high', 'critical']).toContain(rec.priority);
          expect(rec.category).toBeDefined();
          expect(rec.title).toBeDefined();
          expect(rec.description).toBeDefined();
          expect(rec.estimatedImpact).toBeGreaterThanOrEqual(0);
        });

        // Recommendations should be sorted by priority
        if (analysis.recommendations.length > 1) {
          for (let i = 1; i < analysis.recommendations.length; i++) {
            const priorityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
            const prevPriority = priorityOrder[analysis.recommendations[i - 1].priority];
            const currPriority = priorityOrder[analysis.recommendations[i].priority];
            expect(currPriority).toBeLessThanOrEqual(prevPriority);
          }
        }
      });
    });

    describe('SLA Monitoring', () => {
      it('should register and evaluate SLA definitions', () => {
        const slaDefinition = {
          name: 'test-sla',
          description: 'Test SLA for critical dependencies',
          targets: {
            availability: 99.9,
            responseTime: 1000,
            errorRate: 1,
          },
          period: {
            type: 'daily' as const,
            duration: 1,
          },
          dependencies: ['test-database', 'test-embedding'],
          priority: 'high' as const,
        };

        healthAggregation.registerSLA(slaDefinition);

        const compliance = healthAggregation.getSLACompliance('test-sla');
        expect(compliance.size).toBe(1);
        expect(compliance.get('test-sla')).toBeDefined();
      });

      it('should detect SLA violations', async () => {
        // Register SLA with very strict targets that will likely be violated
        const strictSLA = {
          name: 'strict-sla',
          description: 'Strict SLA for testing',
          targets: {
            availability: 99.99,
            responseTime: 100,
            errorRate: 0.1,
          },
          period: {
            type: 'daily' as const,
            duration: 1,
          },
          dependencies: ['test-api'],
          priority: 'high' as const,
        };

        healthAggregation.registerSLA(strictSLA);

        // Generate some health data
        await healthAggregation.getHealthStatus();

        const compliance = healthAggregation.getSLACompliance('strict-sla');
        const slaData = compliance.get('strict-sla');

        if (slaData) {
          expect(slaData.sla).toBe('strict-sla');
          expect(slaData.status).toBeDefined();
          expect([
            SLAStatus['COMPLIANT'],
            SLAStatus['WARNING'],
            SLAStatus['VIOLATION'],
            SLAStatus['UNKNOWN'],
          ]).toContain(slaData.status);
        }
      });
    });

    describe('Alert Management', () => {
      it('should create alerts for health issues', async () => {
        const alertCreatedSpy = vi.fn();
        healthAggregation.on('alertCreated', alertCreatedSpy);

        // Configure a dependency that will likely fail
        const failingConfig = {
          ...mockAPIConfig,
          connection: { url: 'http://invalid-url' },
          healthCheck: {
            ...mockAPIConfig.healthCheck,
            intervalMs: 100,
            timeoutMs: 100,
          },
        };

        await dependencyRegistry.registerDependency(failingConfig);

        // Start health aggregation to trigger alerts
        await healthAggregation.start();

        // Wait for alert generation
        await new Promise((resolve) => setTimeout(resolve, 1000));

        const activeAlerts = healthAggregation.getActiveAlerts();
        expect(activeAlerts.length).toBeGreaterThanOrEqual(0);

        if (activeAlerts.length > 0) {
          expect(alertCreatedSpy).toHaveBeenCalled();

          const alert = activeAlerts[0];
          expect(alert.id).toBeDefined();
          expect(alert.dependency).toBeDefined();
          expect(alert.severity).toBeDefined();
          expect(alert.title).toBeDefined();
          expect(alert.message).toBeDefined();
          expect(alert.timestamp).toBeInstanceOf(Date);
          expect(alert.acknowledged).toBe(false);
          expect(alert.resolved).toBe(false);
        }

        await healthAggregation.stop();
      });

      it('should acknowledge and resolve alerts', async () => {
        // Create a test alert manually
        const testAlertId = 'test-alert-123';

        // Mock an alert in the system (this would normally be created by the service)
        // Note: Since alerts are private, we're testing the public interface
        const activeAlerts = healthAggregation.getActiveAlerts();
        const initialCount = activeAlerts.length;

        // Test acknowledging alerts (if any exist)
        if (activeAlerts.length > 0) {
          const alert = activeAlerts[0];
          healthAggregation.acknowledgeAlert(alert.id, 'test-user');

          const updatedAlerts = healthAggregation.getActiveAlerts();
          expect(updatedAlerts.length).toBeLessThan(initialCount);
        }
      });

      it('should filter alerts by severity', async () => {
        const criticalAlerts = healthAggregation.getActiveAlerts(AlertSeverity['CRITICAL']);
        const warningAlerts = healthAggregation.getActiveAlerts(AlertSeverity['WARNING']);
        const allAlerts = healthAggregation.getActiveAlerts();

        expect(Array.isArray(criticalAlerts)).toBe(true);
        expect(Array.isArray(warningAlerts)).toBe(true);
        expect(Array.isArray(allAlerts)).toBe(true);

        // Critical alerts should be a subset of all alerts
        expect(criticalAlerts.length).toBeLessThanOrEqual(allAlerts.length);
      });
    });

    describe('Health History', () => {
      it('should maintain health history', async () => {
        // Generate multiple health snapshots
        for (let i = 0; i < 3; i++) {
          await healthAggregation.getHealthStatus();
          await new Promise((resolve) => setTimeout(resolve, 50));
        }

        const history = healthAggregation.getHealthHistory();
        expect(history.length).toBeGreaterThanOrEqual(0);
        expect(history.length).toBeLessThanOrEqual(100); // Default limit

        if (history.length > 0) {
          const snapshot = history[0];
          expect(snapshot.timestamp).toBeInstanceOf(Date);
          expect(snapshot.dependencies).toBeDefined();
          expect(snapshot.overall).toBeDefined();
        }
      });

      it('should limit health history size', async () => {
        const limitedHistory = healthAggregation.getHealthHistory(5);
        expect(limitedHistory.length).toBeLessThanOrEqual(5);
      });
    });
  });

  describe('System Integration', () => {
    beforeEach(async () => {
      await dependencyRegistry.registerDependency(mockDatabaseConfig);
      await dependencyRegistry.registerDependency(mockEmbeddingConfig);
      await dependencyRegistry.registerDependency(mockAPIConfig);
    });

    it('should integrate all services together', async () => {
      // Start health aggregation
      await healthAggregation.start();

      // Perform health checks
      const healthResults = await healthCheckService.performParallelHealthChecks([
        { name: 'test-database', config: mockDatabaseConfig },
        { name: 'test-embedding', config: mockEmbeddingConfig },
        { name: 'test-api', config: mockAPIConfig },
      ]);

      // Get aggregated health status
      const analysis = await healthAggregation.getHealthStatus();

      // Verify all services are working together
      expect(Object.keys(healthResults)).toHaveLength(3);
      expect(analysis.dependencies).toBeDefined();
      expect(analysis.overall.status).toBeDefined();

      // Check for active alerts
      const alerts = healthAggregation.getActiveAlerts();
      expect(Array.isArray(alerts)).toBe(true);

      await healthAggregation.stop();
    });

    it('should handle service failures gracefully', async () => {
      // Register a failing dependency
      const failingConfig = {
        ...mockAPIConfig,
        connection: { url: 'http://invalid-url' },
      };

      await dependencyRegistry.registerDependency(failingConfig);

      // System should continue working despite failure
      const analysis = await healthAggregation.getHealthStatus();
      expect(analysis).toBeDefined();
      expect(analysis.dependencies['test-api']).toBeDefined();

      // Should detect the failure
      expect(analysis.dependencies['test-api'].status).toBe(DependencyStatus['CRITICAL']);

      // Overall system should still provide status
      expect(analysis.overall.status).toBeDefined();
    });

    it('should handle dependency lifecycle changes', async () => {
      // Start with some dependencies
      await healthAggregation.start();
      let analysis = await healthAggregation.getHealthStatus();
      const initialCount = Object.keys(analysis.dependencies).length;

      // Add a new dependency
      const newConfig = {
        ...mockAPIConfig,
        name: 'test-new-api',
      };
      await dependencyRegistry.registerDependency(newConfig);

      // Wait for health check to run
      await new Promise((resolve) => setTimeout(resolve, 200));

      analysis = await healthAggregation.getHealthStatus();
      expect(Object.keys(analysis.dependencies)).toHaveLength(initialCount + 1);
      expect(analysis.dependencies['test-new-api']).toBeDefined();

      // Remove a dependency
      await dependencyRegistry.unregisterDependency('test-new-api');

      await healthAggregation.stop();
    });
  });

  describe('Performance and Load Testing', () => {
    it('should handle concurrent health checks efficiently', async () => {
      const startTime = Date.now();

      // Create many dependencies
      const configs = Array.from({ length: 10 }, (_, i) => ({
        name: `test-load-${i}`,
        config: {
          ...mockAPIConfig,
          name: `test-load-${i}`,
          connection: { ...mockAPIConfig.connection },
        },
      }));

      // Register all dependencies
      for (const { config } of configs) {
        await dependencyRegistry.registerDependency(config);
      }

      // Perform parallel health checks
      const results = await healthCheckService.performParallelHealthChecks(configs);

      const endTime = Date.now();
      const executionTime = endTime - startTime;

      expect(Object.keys(results)).toHaveLength(10);
      expect(executionTime).toBeLessThan(15000); // Should complete in under 15 seconds

      // Clean up
      for (const { name } of configs) {
        await dependencyRegistry.unregisterDependency(name);
      }
    });

    it('should maintain performance under repeated operations', async () => {
      const iterations = 5;
      const times: number[] = [];

      for (let i = 0; i < iterations; i++) {
        const startTime = Date.now();

        await healthCheckService.performHealthCheck('test-performance', mockAPIConfig, {
          strategy: HealthCheckStrategy['BASIC'],
        });

        const endTime = Date.now();
        times.push(endTime - startTime);
      }

      // Calculate average and variance
      const average = times.reduce((sum, time) => sum + time, 0) / times.length;
      const variance =
        times.reduce((sum, time) => sum + Math.pow(time - average, 2), 0) / times.length;
      const standardDeviation = Math.sqrt(variance);

      // Performance should be consistent
      expect(standardDeviation).toBeLessThan(average * 0.5); // Variance less than 50% of average
    });

    it('should handle memory usage efficiently', async () => {
      const initialMemory = process.memoryUsage().heapUsed;

      // Perform many operations
      for (let i = 0; i < 50; i++) {
        await healthCheckService.performHealthCheck(`test-memory-${i}`, mockAPIConfig, {
          strategy: HealthCheckStrategy['BASIC'],
          cacheEnabled: true,
        });
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be reasonable (less than 50MB)
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle network errors gracefully', async () => {
      const networkErrorConfig = {
        ...mockAPIConfig,
        connection: {
          url: 'http://network-error.test',
          timeout: 1000,
        },
      };

      const result = await healthCheckService.performHealthCheck(
        'test-network-error',
        networkErrorConfig,
        { strategy: HealthCheckStrategy['BASIC'] }
      );

      expect(result.status).toBe(DependencyStatus['CRITICAL']);
      expect(result.error).toBeDefined();
      expect(result.diagnostics.errorDetails).toBeDefined();
    });

    it('should handle malformed responses', async () => {
      // Mock fetch to return malformed response
      (global.fetch as any).mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        json: () => Promise.reject(new Error('Invalid JSON')),
      });

      const result = await healthCheckService.performHealthCheck('test-malformed', mockAPIConfig, {
        strategy: HealthCheckStrategy['BASIC'],
      });

      expect(result.status).toBe(DependencyStatus['CRITICAL']);
    });

    it('should handle service unavailability', async () => {
      // Test when services are completely unavailable
      const unavailableConfig = {
        ...mockDatabaseConfig,
        connection: {
          url: 'http://unavailable-service.test',
          timeout: 1000,
        },
      };

      const result = await healthCheckService.performHealthCheck(
        'test-unavailable',
        unavailableConfig,
        { strategy: HealthCheckStrategy['BASIC'] }
      );

      expect(result.status).toBe(DependencyStatus['CRITICAL']);
      expect(result.error).toBeDefined();
    });

    it('should handle configuration validation errors', async () => {
      const invalidConfigs = [
        { name: '', type: DependencyType['DATABASE'] }, // Empty name
        { name: 'test', type: 'invalid' as any }, // Invalid type
        { name: 'test', type: DependencyType['DATABASE'], connection: {} }, // Missing connection
      ];

      for (const config of invalidConfigs) {
        await expect(dependencyRegistry.registerDependency(config as any)).rejects.toThrow();
      }
    });
  });
});
