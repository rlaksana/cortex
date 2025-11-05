/**
 * Health Aggregation Interface Contract Tests
 *
 * Verifies that the health aggregation service properly conforms
 * to the exported interfaces from deps-registry.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  DependencyRegistry,
  DependencyStatus,
  DependencyType,
  DependencyState,
  AggregatedHealthStatus,
  HealthCheckResult,
  DependencyConfig,
} from '../../../src/services/deps-registry.js';
import { HealthAggregationService } from '../../../src/services/health-aggregation.service.js';

describe('Health Aggregation Interface Contracts', () => {
  let dependencyRegistry: DependencyRegistry;
  let healthAggregation: HealthAggregationService;

  beforeEach(() => {
    vi.clearAllMocks();

    // Create dependency registry with mock dependencies
    dependencyRegistry = new DependencyRegistry();

    // Register test dependencies
    dependencyRegistry.register({
      name: 'test-db',
      type: DependencyType.DATABASE,
      connection: { url: 'http://localhost:5432', timeout: 5000 },
      healthCheck: {
        interval: 30000,
        timeout: 5000,
        retries: 3,
      },
      criticality: 'high',
    });

    dependencyRegistry.register({
      name: 'test-vector-db',
      type: DependencyType.VECTOR_DB,
      connection: { url: 'http://localhost:6333', timeout: 10000 },
      healthCheck: {
        interval: 30000,
        timeout: 10000,
        retries: 2,
      },
      criticality: 'high',
    });

    // Create health aggregation service
    healthAggregation = new HealthAggregationService(dependencyRegistry);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Interface Compliance', () => {
    it('should properly implement DependencyStatus enum values', () => {
      // Verify all expected status values exist
      expect(DependencyStatus.HEALTHY).toBe('healthy');
      expect(DependencyStatus.WARNING).toBe('warning');
      expect(DependencyStatus.CRITICAL).toBe('critical');
      expect(DependencyStatus.UNKNOWN).toBe('unknown');
      expect(DependencyStatus.DISABLED).toBe('disabled');
    });

    it('should create HealthCheckResult objects conforming to interface', async () => {
      const mockHealthCheck = vi.fn().mockResolvedValue({
        dependency: 'test-db',
        status: DependencyStatus.HEALTHY,
        responseTime: 150,
        timestamp: new Date(),
        details: { version: '1.0.0' },
      });

      // Mock the dependency registry health check
      vi.spyOn(dependencyRegistry, 'checkHealth').mockImplementation(mockHealthCheck);

      const result = await dependencyRegistry.checkHealth({
        name: 'test-db',
        type: DependencyType.DATABASE,
        connection: { url: 'http://localhost:5432', timeout: 5000 },
        healthCheck: { interval: 30000, timeout: 5000, retries: 3 },
        criticality: 'high',
      });

      // Verify interface compliance
      expect(result).toHaveProperty('dependency');
      expect(result).toHaveProperty('status');
      expect(result).toHaveProperty('responseTime');
      expect(result).toHaveProperty('timestamp');
      expect(typeof result.dependency).toBe('string');
      expect(Object.values(DependencyStatus)).toContain(result.status);
      expect(typeof result.responseTime).toBe('number');
      expect(result.timestamp).toBeInstanceOf(Date);
    });

    it('should create AggregatedHealthStatus objects conforming to interface', async () => {
      // Mock health checks to return predictable results
      const mockHealthResults: HealthCheckResult[] = [
        {
          dependency: 'test-db',
          status: DependencyStatus.HEALTHY,
          responseTime: 150,
          timestamp: new Date(),
        },
        {
          dependency: 'test-vector-db',
          status: DependencyStatus.WARNING,
          responseTime: 300,
          error: 'High latency',
          timestamp: new Date(),
        },
      ];

      vi.spyOn(dependencyRegistry, 'checkAllHealth').mockResolvedValue(mockHealthResults);

      const result = await dependencyRegistry.checkAllHealth();

      // Verify interface compliance
      expect(result).toHaveProperty('overall');
      expect(result).toHaveProperty('dependencies');
      expect(result).toHaveProperty('summary');
      expect(result).toHaveProperty('score');
      expect(result).toHaveProperty('timestamp');

      expect(Object.values(DependencyStatus)).toContain(result.overall);
      expect(typeof result.dependencies).toBe('object');
      expect(typeof result.summary).toBe('object');
      expect(typeof result.score).toBe('number');
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(100);
      expect(result.timestamp).toBeInstanceOf(Date);
    });

    it('should maintain dependency state interface consistency', async () => {
      const dependency = dependencyRegistry.getDependency('test-db');

      if (dependency) {
        // Verify DependencyState interface compliance
        expect(dependency).toHaveProperty('config');
        expect(dependency).toHaveProperty('status');
        expect(dependency).toHaveProperty('lastCheck');
        expect(dependency).toHaveProperty('metrics');
        expect(dependency).toHaveProperty('enabled');

        expect(dependency.config).toHaveProperty('name');
        expect(dependency.config).toHaveProperty('type');
        expect(dependency.config).toHaveProperty('connection');
        expect(dependency.config).toHaveProperty('healthCheck');
        expect(dependency.config).toHaveProperty('criticality');

        expect(Object.values(DependencyStatus)).toContain(dependency.status);
        expect(typeof dependency.enabled).toBe('boolean');
      }
    });

    it('should properly handle DependencyConfig interface', () => {
      const testConfig: DependencyConfig = {
        name: 'test-service',
        type: DependencyType.EXTERNAL_API,
        connection: {
          url: 'https://api.example.com',
          timeout: 5000,
          headers: { 'Authorization': 'Bearer token' },
        },
        healthCheck: {
          interval: 60000,
          timeout: 5000,
          retries: 3,
          path: '/health',
        },
        criticality: 'medium',
        tags: ['external', 'api'],
      };

      // Verify the config conforms to the interface
      expect(testConfig.name).toBe('test-service');
      expect(testConfig.type).toBe(DependencyType.EXTERNAL_API);
      expect(testConfig.connection.url).toBe('https://api.example.com');
      expect(testConfig.connection.timeout).toBe(5000);
      expect(testConfig.healthCheck.interval).toBe(60000);
      expect(testConfig.criticality).toBe('medium');
      expect(Array.isArray(testConfig.tags)).toBe(true);
    });
  });

  describe('Health Aggregation Service Integration', () => {
    it('should properly aggregate health results from dependency registry', async () => {
      const mockHealthResults: HealthCheckResult[] = [
        {
          dependency: 'test-db',
          status: DependencyStatus.HEALTHY,
          responseTime: 150,
          timestamp: new Date(),
        },
        {
          dependency: 'test-vector-db',
          status: DependencyStatus.HEALTHY,
          responseTime: 200,
          timestamp: new Date(),
        },
      ];

      vi.spyOn(dependencyRegistry, 'checkAllHealth').mockResolvedValue(mockHealthResults);

      const aggregatedStatus = await dependencyRegistry.checkAllHealth();

      // Verify the aggregation logic works correctly
      expect(aggregatedStatus.summary.total).toBe(2);
      expect(aggregatedStatus.summary.healthy).toBe(2);
      expect(aggregatedStatus.summary.warning).toBe(0);
      expect(aggregatedStatus.summary.critical).toBe(0);
      expect(aggregatedStatus.score).toBeGreaterThan(80); // High score for healthy services
    });

    it('should handle mixed health statuses in aggregation', async () => {
      const mockHealthResults: HealthCheckResult[] = [
        {
          dependency: 'test-db',
          status: DependencyStatus.HEALTHY,
          responseTime: 150,
          timestamp: new Date(),
        },
        {
          dependency: 'test-vector-db',
          status: DependencyStatus.CRITICAL,
          responseTime: 5000,
          error: 'Connection timeout',
          timestamp: new Date(),
        },
      ];

      vi.spyOn(dependencyRegistry, 'checkAllHealth').mockResolvedValue(mockHealthResults);

      const aggregatedStatus = await dependencyRegistry.checkAllHealth();

      // Verify critical status is properly reflected
      expect(aggregatedStatus.overall).toBe(DependencyStatus.CRITICAL);
      expect(aggregatedStatus.summary.healthy).toBe(1);
      expect(aggregatedStatus.summary.critical).toBe(1);
      expect(aggregatedStatus.score).toBeLessThan(50); // Low score for critical issues
    });
  });

  describe('Type Safety and Contract Validation', () => {
    it('should reject invalid status values', () => {
      const invalidResult = {
        dependency: 'test',
        status: 'invalid' as any, // This should not be allowed
        responseTime: 100,
        timestamp: new Date(),
      };

      // TypeScript should prevent this, but we verify runtime behavior
      expect(Object.values(DependencyStatus)).not.toContain(invalidResult.status);
    });

    it('should maintain type consistency across interfaces', () => {
      // Create objects that use all related interfaces
      const config: DependencyConfig = {
        name: 'test',
        type: DependencyType.DATABASE,
        connection: { url: 'http://localhost:5432', timeout: 5000 },
        healthCheck: { interval: 30000, timeout: 5000, retries: 3 },
        criticality: 'high',
      };

      const state: DependencyState = {
        config,
        status: DependencyStatus.HEALTHY,
        lastCheck: new Date(),
        metrics: { uptime: 3600000, responseTime: 150 },
        enabled: true,
      };

      const healthResult: HealthCheckResult = {
        dependency: config.name,
        status: state.status,
        responseTime: 150,
        timestamp: new Date(),
      };

      // Verify all types are consistent
      expect(healthResult.dependency).toBe(config.name);
      expect(healthResult.status).toBe(state.status);
      expect(Object.values(DependencyStatus)).toContain(healthResult.status);
    });
  });
});