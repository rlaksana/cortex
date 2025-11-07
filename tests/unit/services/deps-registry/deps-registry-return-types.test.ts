/**
 * Dependency Registry Promise Return Types Tests
 *
 * Verifies that all methods in deps-registry properly return
 * Promise<Result<T>> types instead of boolean or void returns.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  DependencyRegistry,
  DependencyType,
  DependencyStatus,
  DependencyConfig,
} from '../../../src/services/deps-registry.js';
import {
  DependencyResultFactory,
  DependencyErrorCode,
  type ConnectionResult,
  type DisconnectionResult,
  type HealthCheckResultExtended,
  type RegistrationResult,
  type UnregistrationResult,
} from '../../../src/services/deps-registry.types.js';

describe('Dependency Registry Promise Return Types', () => {
  let registry: DependencyRegistry;

  beforeEach(() => {
    vi.clearAllMocks();
    registry = new DependencyRegistry();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('registerDependency return types', () => {
    it('should return RegistrationPromiseResult on successful registration', async () => {
      const testConfig: DependencyConfig = {
        name: 'test-db',
        type: DependencyType['DATABASE'],
        priority: 'high',
        healthCheck: {
          enabled: true,
          intervalMs: 30000,
          timeoutMs: 5000,
          failureThreshold: 3,
          successThreshold: 2,
          retryAttempts: 3,
          retryDelayMs: 1000,
        },
        connection: {
          url: 'http://localhost:5432',
          timeout: 10000,
        },
        thresholds: {
          responseTimeWarning: 1000,
          responseTimeCritical: 5000,
          errorRateWarning: 0.1,
          errorRateCritical: 0.25,
          availabilityWarning: 0.95,
          availabilityCritical: 0.9,
        },
      };

      const mockConnector = vi
        .fn()
        .mockResolvedValue(DependencyResultFactory.connectionSuccess('test-db', 150, 0));

      const result = await registry.registerDependency(testConfig, {
        connector: mockConnector,
      });

      // Verify the result is properly typed
      expect(result).toHaveProperty('success');
      expect(result).toHaveProperty('data');
      expect(result).toHaveProperty('dependency');
      expect(result).toHaveProperty('type');
      expect(result).toHaveProperty('autoConnected');
      expect(result).toHaveProperty('timestamp');

      // Verify success case
      expect(result.success).toBe(true);
      expect(result.data).toBe('test-db');
      expect(result.dependency).toBe('test-db');
      expect(result.type).toBe('database');
      expect(result.autoConnected).toBe(true);
      expect(typeof result.timestamp).toBe('object'); // Date object
    });

    it('should return RegistrationPromiseResult on registration failure', async () => {
      const invalidConfig = {
        name: '', // Invalid empty name
        type: DependencyType['DATABASE'],
        priority: 'high' as const,
        healthCheck: {
          enabled: true,
          intervalMs: 30000,
          timeoutMs: 5000,
          failureThreshold: 3,
          successThreshold: 2,
          retryAttempts: 3,
          retryDelayMs: 1000,
        },
        connection: {
          url: 'http://localhost:5432',
          timeout: 10000,
        },
        thresholds: {
          responseTimeWarning: 1000,
          responseTimeCritical: 5000,
          errorRateWarning: 0.1,
          errorRateCritical: 0.25,
          availabilityWarning: 0.95,
          availabilityCritical: 0.9,
        },
      };

      const result = await registry.registerDependency(invalidConfig);

      // Verify failure case
      expect(result.success).toBe(false);
      expect(result).toHaveProperty('error');
      expect(result.error?.code).toBe(DependencyErrorCode['VALIDATION_ERROR']);
      expect(result.dependency).toBe('');
      expect(result.type).toBe('database');
      expect(typeof result.timestamp).toBe('object');
    });
  });

  describe('unregisterDependency return types', () => {
    beforeEach(async () => {
      // Register a test dependency first
      const testConfig: DependencyConfig = {
        name: 'test-unreg',
        type: DependencyType['CACHE'],
        priority: 'medium',
        healthCheck: {
          enabled: true,
          intervalMs: 30000,
          timeoutMs: 5000,
          failureThreshold: 3,
          successThreshold: 2,
          retryAttempts: 3,
          retryDelayMs: 1000,
        },
        connection: {
          url: 'http://localhost:6379',
          timeout: 5000,
        },
        thresholds: {
          responseTimeWarning: 500,
          responseTimeCritical: 2000,
          errorRateWarning: 0.05,
          errorRateCritical: 0.15,
          availabilityWarning: 0.98,
          availabilityCritical: 0.95,
        },
      };

      await registry.registerDependency(testConfig);
    });

    it('should return UnregistrationPromiseResult on successful unregistration', async () => {
      const mockDisconnector = vi
        .fn()
        .mockResolvedValue(DependencyResultFactory.disconnectionSuccess('test-unreg', true));

      // Register the disconnector
      await registry.registerDependency(
        {
          name: 'test-unreg',
          type: DependencyType['CACHE'],
          priority: 'medium',
          healthCheck: {
            enabled: true,
            intervalMs: 30000,
            timeoutMs: 5000,
            failureThreshold: 3,
            successThreshold: 2,
            retryAttempts: 3,
            retryDelayMs: 1000,
          },
          connection: {
            url: 'http://localhost:6379',
            timeout: 5000,
          },
          thresholds: {
            responseTimeWarning: 500,
            responseTimeCritical: 2000,
            errorRateWarning: 0.05,
            errorRateCritical: 0.15,
            availabilityWarning: 0.98,
            availabilityCritical: 0.95,
          },
        },
        {
          disconnector: mockDisconnector,
        }
      );

      const result = await registry.unregisterDependency('test-unreg');

      // Verify the result is properly typed
      expect(result).toHaveProperty('success');
      expect(result).toHaveProperty('data');
      expect(result).toHaveProperty('dependency');
      expect(result).toHaveProperty('wasConnected');
      expect(result).toHaveProperty('cleanedUpResources');
      expect(result).toHaveProperty('timestamp');

      // Verify success case
      expect(result.success).toBe(true);
      expect(result.data).toBe('test-unreg');
      expect(result.dependency).toBe('test-unreg');
      expect(Array.isArray(result.cleanedUpResources)).toBe(true);
      expect(typeof result.timestamp).toBe('object');
    });

    it('should return UnregistrationPromiseResult on dependency not found', async () => {
      const result = await registry.unregisterDependency('non-existent');

      // Verify failure case
      expect(result.success).toBe(false);
      expect(result).toHaveProperty('error');
      expect(result.error?.code).toBe(DependencyErrorCode['DEPENDENCY_NOT_FOUND']);
      expect(result.dependency).toBe('non-existent');
    });
  });

  describe('performHealthCheck return types', () => {
    beforeEach(async () => {
      // Register a test dependency first
      const testConfig: DependencyConfig = {
        name: 'test-health',
        type: DependencyType['EXTERNAL_API'],
        priority: 'high',
        healthCheck: {
          enabled: true,
          intervalMs: 30000,
          timeoutMs: 5000,
          failureThreshold: 3,
          successThreshold: 2,
          retryAttempts: 3,
          retryDelayMs: 1000,
        },
        connection: {
          url: 'https://api.example.com',
          timeout: 10000,
        },
        thresholds: {
          responseTimeWarning: 1000,
          responseTimeCritical: 3000,
          errorRateWarning: 0.05,
          errorRateCritical: 0.1,
          availabilityWarning: 0.99,
          availabilityCritical: 0.95,
        },
      };

      await registry.registerDependency(testConfig);
    });

    it('should return HealthCheckPromiseResult on successful health check', async () => {
      // Mock the built-in health check to return a healthy result
      const mockHealthCheck = vi.fn().mockResolvedValue({
        dependency: 'test-health',
        status: DependencyStatus['HEALTHY'],
        responseTime: 200,
        timestamp: new Date(),
        details: { statusCode: 200 },
      });

      // Access the private method using bracket notation for testing
      const registryAny = registry as any;
      registryAny.healthChecks.set('test-health', mockHealthCheck);

      const result = await registryAny.performHealthCheck('test-health');

      // Verify the result is properly typed
      expect(result).toHaveProperty('success');
      expect(result).toHaveProperty('data');
      expect(result).toHaveProperty('dependency');
      expect(result).toHaveProperty('responseTime');
      expect(result).toHaveProperty('timestamp');

      // Verify success case
      expect(result.success).toBe(true);
      expect(result.data?.status).toBe(DependencyStatus['HEALTHY']);
      expect(result.dependency).toBe('test-health');
      expect(result.responseTime).toBe(200);
      expect(typeof result.timestamp).toBe('object');
    });

    it('should return HealthCheckPromiseResult on health check failure', async () => {
      // Mock the built-in health check to throw an error
      const mockHealthCheck = vi.fn().mockRejectedValue(new Error('Connection timeout'));

      // Access the private method using bracket notation for testing
      const registryAny = registry as any;
      registryAny.healthChecks.set('test-health', mockHealthCheck);

      const result = await registryAny.performHealthCheck('test-health');

      // Verify failure case
      expect(result.success).toBe(false);
      expect(result).toHaveProperty('error');
      expect(result.error?.code).toBe(DependencyErrorCode['HEALTH_CHECK_FAILED']);
      expect(result.dependency).toBe('test-health');
      expect(typeof result.responseTime).toBe('number');
    });

    it('should return HealthCheckPromiseResult for non-existent dependency', async () => {
      const result = await registry.performHealthCheck('non-existent');

      // Verify failure case
      expect(result.success).toBe(false);
      expect(result).toHaveProperty('error');
      expect(result.error?.code).toBe(DependencyErrorCode['DEPENDENCY_NOT_FOUND']);
      expect(result.dependency).toBe('non-existent');
      expect(result.responseTime).toBe(0);
    });
  });

  describe('checkAllDependencies return types', () => {
    beforeEach(async () => {
      // Register multiple test dependencies
      const configs: DependencyConfig[] = [
        {
          name: 'test-db-all',
          type: DependencyType['DATABASE'],
          priority: 'high',
          healthCheck: {
            enabled: true,
            intervalMs: 30000,
            timeoutMs: 5000,
            failureThreshold: 3,
            successThreshold: 2,
            retryAttempts: 3,
            retryDelayMs: 1000,
          },
          connection: {
            url: 'http://localhost:5432',
            timeout: 10000,
          },
          thresholds: {
            responseTimeWarning: 1000,
            responseTimeCritical: 5000,
            errorRateWarning: 0.1,
            errorRateCritical: 0.25,
            availabilityWarning: 0.95,
            availabilityCritical: 0.9,
          },
        },
        {
          name: 'test-cache-all',
          type: DependencyType['CACHE'],
          priority: 'medium',
          healthCheck: {
            enabled: true,
            intervalMs: 30000,
            timeoutMs: 5000,
            failureThreshold: 3,
            successThreshold: 2,
            retryAttempts: 3,
            retryDelayMs: 1000,
          },
          connection: {
            url: 'http://localhost:6379',
            timeout: 5000,
          },
          thresholds: {
            responseTimeWarning: 500,
            responseTimeCritical: 2000,
            errorRateWarning: 0.05,
            errorRateCritical: 0.15,
            availabilityWarning: 0.98,
            availabilityCritical: 0.95,
          },
        },
      ];

      for (const config of configs) {
        await registry.registerDependency(config);
      }
    });

    it('should return Record<string, HealthCheckResultExtended>', async () => {
      const result = await registry.checkAllDependencies();

      // Verify the result is properly typed
      expect(typeof result).toBe('object');
      expect(result).toHaveProperty('test-db-all');
      expect(result).toHaveProperty('test-cache-all');

      // Verify each health check result has the correct structure
      for (const [name, healthResult] of Object.entries(result)) {
        expect(healthResult).toHaveProperty('success');
        expect(healthResult).toHaveProperty('dependency');
        expect(healthResult).toHaveProperty('responseTime');
        expect(healthResult).toHaveProperty('timestamp');
        expect(healthResult.dependency).toBe(name);
        expect(typeof healthResult.responseTime).toBe('number');
        expect(typeof healthResult.timestamp).toBe('object');
      }
    });
  });

  describe('type safety verification', () => {
    it('should ensure all method signatures return Promise types', async () => {
      // This test verifies that the type signatures are correct at compile time
      // It serves as documentation for the expected return types

      const testConfig: DependencyConfig = {
        name: 'type-safety-test',
        type: DependencyType['DATABASE'],
        priority: 'high',
        healthCheck: {
          enabled: true,
          intervalMs: 30000,
          timeoutMs: 5000,
          failureThreshold: 3,
          successThreshold: 2,
          retryAttempts: 3,
          retryDelayMs: 1000,
        },
        connection: {
          url: 'http://localhost:5432',
          timeout: 10000,
        },
        thresholds: {
          responseTimeWarning: 1000,
          responseTimeCritical: 5000,
          errorRateWarning: 0.1,
          errorRateCritical: 0.25,
          availabilityWarning: 0.95,
          availabilityCritical: 0.9,
        },
      };

      // All these should have proper Promise return types
      const registrationResult: Promise<RegistrationResult> =
        registry.registerDependency(testConfig);

      const unregistrationResult: Promise<UnregistrationResult> =
        registry.unregisterDependency('type-safety-test');

      const healthCheckResult: Promise<HealthCheckResultExtended> =
        registry.performHealthCheck('type-safety-test');

      const allHealthResults: Promise<Record<string, HealthCheckResultExtended>> =
        registry.checkAllDependencies();

      // Verify they are all Promises
      expect(registrationResult).toBeInstanceOf(Promise);
      expect(unregistrationResult).toBeInstanceOf(Promise);
      expect(healthCheckResult).toBeInstanceOf(Promise);
      expect(allHealthResults).toBeInstanceOf(Promise);
    });

    it('should ensure no methods return void or boolean', () => {
      // This test serves as documentation that we've moved away from
      // void or boolean return types to proper Result<T> patterns

      const registryProto = Object.getPrototypeOf(registry);
      const methodsToCheck = [
        'registerDependency',
        'unregisterDependency',
        'performHealthCheck',
        'checkAllDependencies',
      ];

      for (const methodName of methodsToCheck) {
        const method = registryProto[methodName];
        expect(typeof method).toBe('function');

        // The method should be async (return Promise)
        expect(method.constructor.name).toBe('AsyncFunction');
      }
    });
  });

  describe('Result factory consistency', () => {
    it('should create consistent result objects', () => {
      const successResult = DependencyResultFactory.success('test data');
      expect(successResult.success).toBe(true);
      expect(successResult.data).toBe('test data');
      expect(successResult.timestamp).toBeInstanceOf(Date);
      expect(successResult.error).toBeUndefined();

      const failureResult = DependencyResultFactory.failure('TEST_ERROR', 'Test error message', {
        detail: 'test',
      });
      expect(failureResult.success).toBe(false);
      expect(failureResult.error?.code).toBe('TEST_ERROR');
      expect(failureResult.error?.message).toBe('Test error message');
      expect(failureResult.error?.details).toEqual({ detail: 'test' });
      expect(failureResult.timestamp).toBeInstanceOf(Date);
    });
  });
});
