/**
 * Comprehensive Tests for Typed DI Container
 *
 * Tests all aspects of the typed DI container including:
 * - Service registration and resolution
 * - Runtime validation
 * - Circular dependency detection
 * - Scoped services
 * - Factory registration
 * - Error handling
 * - Metrics and monitoring
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { TypedDIContainer, createTypedDIContainer, ServiceLifetime } from '../typed-di-container';
import {
  RuntimeValidator,
  RuntimeTypeChecker,
  ServiceValidationError,
  TypeValidationError,
} from '../runtime-validation';
import { createServiceId } from '../../factories/factory-types';

// ============================================================================
// Test Interfaces and Implementations
// ============================================================================

interface ITestService {
  getValue(): string;
  setValue(value: string): void;
}

interface ITestServiceWithDeps {
  getDepValue(): string;
  getValue(): string;
}

class TestService implements ITestService {
  private value: string = 'default';

  getValue(): string {
    return this.value;
  }

  setValue(value: string): void {
    this.value = value;
  }
}

class TestServiceWithDeps implements ITestServiceWithDeps {
  constructor(private readonly testService: ITestService) {}

  getDepValue(): string {
    return this.testService.getValue();
  }

  getValue(): string {
    return 'with-deps';
  }
}

class DisposableService implements ITestService {
  private disposed = false;
  private value = 'disposable';

  getValue(): string {
    if (this.disposed) {
      throw new Error('Service has been disposed');
    }
    return this.value;
  }

  setValue(value: string): void {
    if (this.disposed) {
      throw new Error('Service has been disposed');
    }
    this.value = value;
  }

  async dispose(): Promise<void> {
    this.disposed = true;
  }
}

// ============================================================================
// Test Validators
// ============================================================================

const testServiceValidator: RuntimeValidator<ITestService> = {
  validate(value: unknown): value is ITestService {
    if (typeof value !== 'object' || value === null) return false;
    const service = value as ITestService;
    return typeof service.getValue === 'function' && typeof service.setValue === 'function';
  },

  getExpectedType(): string {
    return 'ITestService';
  },

  getErrorMessage(value: unknown): string {
    return `Expected ITestService, got ${typeof value}`;
  },
};

// ============================================================================
// Test Setup
// ============================================================================

describe('TypedDIContainer', () => {
  let container: TypedDIContainer;
  const TEST_SERVICE_ID = createServiceId<ITestService>('TestService');
  const TEST_SERVICE_WITH_DEPS_ID = createServiceId<ITestServiceWithDeps>('TestServiceWithDeps');
  const DISPOSABLE_SERVICE_ID = createServiceId<ITestService>('DisposableService');

  beforeEach(() => {
    container = createTypedDIContainer({
      enableAutoValidation: true,
      enableRuntimeTypeChecking: true,
      enableCircularDependencyDetection: true,
      enableMetrics: true,
      enableDebugLogging: false,
    });
  });

  afterEach(async () => {
    await container.dispose();
  });

  // ============================================================================
  // Basic Service Registration and Resolution Tests
  // ============================================================================

  describe('Service Registration and Resolution', () => {
    it('should register and resolve a simple service', () => {
      container.register(TEST_SERVICE_ID, TestService, ServiceLifetime.SINGLETON);

      const service = container.resolve(TEST_SERVICE_ID) as ITestService;

      expect(service).toBeInstanceOf(TestService);
      expect(service.getValue()).toBe('default');
    });

    it('should return the same instance for singleton services', () => {
      container.register(TEST_SERVICE_ID, TestService, ServiceLifetime.SINGLETON);

      const service1 = container.resolve(TEST_SERVICE_ID) as ITestService;
      const service2 = container.resolve(TEST_SERVICE_ID) as ITestService;

      expect(service1).toBe(service2);
    });

    it('should create new instances for transient services', () => {
      container.register(TEST_SERVICE_ID, TestService, ServiceLifetime.TRANSIENT);

      const service1 = container.resolve(TEST_SERVICE_ID) as ITestService;
      const service2 = container.resolve(TEST_SERVICE_ID) as ITestService;

      expect(service1).not.toBe(service2);
      expect(service1).toBeInstanceOf(TestService);
      expect(service2).toBeInstanceOf(TestService);
    });

    it('should resolve services with dependencies', () => {
      container.register(TEST_SERVICE_ID, TestService, ServiceLifetime.SINGLETON);
      container.register(
        TEST_SERVICE_WITH_DEPS_ID,
        TestServiceWithDeps,
        ServiceLifetime.SINGLETON,
        [TEST_SERVICE_ID]
      );

      const service = container.resolve(TEST_SERVICE_WITH_DEPS_ID) as ITestServiceWithDeps;

      expect(service).toBeInstanceOf(TestServiceWithDeps);
      expect(service.getValue()).toBe('with-deps');
      expect(service.getDepValue()).toBe('default');
    });

    it('should register and resolve instances', () => {
      const instance = new TestService();
      instance.setValue('instance-value');

      container.registerInstance(TEST_SERVICE_ID, instance, testServiceValidator);

      const resolved = container.resolve(TEST_SERVICE_ID) as ITestService;

      expect(resolved).toBe(instance);
      expect(resolved.getValue()).toBe('instance-value');
    });

    it('should register and resolve factory services', async () => {
      const factory = vi.fn().mockImplementation(() => {
        const service = new TestService();
        service.setValue('factory-value');
        return service;
      });

      container.registerFactory(TEST_SERVICE_ID, factory, ServiceLifetime.SINGLETON);

      const service = container.resolve(TEST_SERVICE_ID) as ITestService;

      expect(factory).toHaveBeenCalledWith(container);
      expect(service).toBeInstanceOf(TestService);
      expect(service.getValue()).toBe('factory-value');
    });
  });

  // ============================================================================
  // Runtime Validation Tests
  // ============================================================================

  describe('Runtime Validation', () => {
    it('should validate services during registration when validator is provided', () => {
      const invalidInstance = { invalid: 'object' } as unknown;

      expect(() => {
        container.registerInstance(TEST_SERVICE_ID, invalidInstance, testServiceValidator);
      }).toThrow(ServiceValidationError);
    });

    it('should validate services during resolution when validator is provided', () => {
      const factory = vi.fn().mockReturnValue({ invalid: 'object' });

      container.registerFactory(
        TEST_SERVICE_ID,
        factory,
        ServiceLifetime.SINGLETON,
        [],
        testServiceValidator
      );

      expect(() => {
        container.resolve(TEST_SERVICE_ID);
      }).toThrow(ServiceValidationError);
    });

    it('should skip validation when runtime type checking is disabled', () => {
      const containerNoValidation = createTypedDIContainer({
        enableRuntimeTypeChecking: false,
      });

      const invalidInstance = { invalid: 'object' } as unknown;

      expect(() => {
        containerNoValidation.registerInstance(
          TEST_SERVICE_ID,
          invalidInstance,
          testServiceValidator
        );
      }).not.toThrow();
    });
  });

  // ============================================================================
  // Circular Dependency Detection Tests
  // ============================================================================

  describe('Circular Dependency Detection', () => {
    it('should detect simple circular dependencies', () => {
      const SERVICE_A = createServiceId<unknown>('ServiceA');
      const SERVICE_B = createServiceId<unknown>('ServiceB');

      container.register(
        SERVICE_A,
        class A {
          constructor(public b: unknown) {}
        },
        ServiceLifetime.SINGLETON,
        [SERVICE_B]
      );

      container.register(
        SERVICE_B,
        class B {
          constructor(public a: unknown) {}
        },
        ServiceLifetime.SINGLETON,
        [SERVICE_A]
      );

      expect(() => {
        container.resolve(SERVICE_A);
      }).toThrow(/Circular dependency detected/);
    });

    it('should detect complex circular dependencies', () => {
      const SERVICE_A = createServiceId<unknown>('ServiceA');
      const SERVICE_B = createServiceId<unknown>('ServiceB');
      const SERVICE_C = createServiceId<unknown>('ServiceC');

      container.register(
        SERVICE_A,
        class A {
          constructor(public b: unknown) {}
        },
        ServiceLifetime.SINGLETON,
        [SERVICE_B]
      );

      container.register(
        SERVICE_B,
        class B {
          constructor(public c: unknown) {}
        },
        ServiceLifetime.SINGLETON,
        [SERVICE_C]
      );

      container.register(
        SERVICE_C,
        class C {
          constructor(public a: unknown) {}
        },
        ServiceLifetime.SINGLETON,
        [SERVICE_A]
      );

      expect(() => {
        container.resolve(SERVICE_A);
      }).toThrow(/Circular dependency detected/);
    });

    it('should validate dependency graph for circular dependencies', () => {
      const SERVICE_A = createServiceId<unknown>('ServiceA');
      const SERVICE_B = createServiceId<unknown>('ServiceB');

      container.register(
        SERVICE_A,
        class A {
          constructor(public b: unknown) {}
        },
        ServiceLifetime.SINGLETON,
        [SERVICE_B]
      );

      container.register(
        SERVICE_B,
        class B {
          constructor(public a: unknown) {}
        },
        ServiceLifetime.SINGLETON,
        [SERVICE_A]
      );

      const validation = container.validateDependencyGraph();

      expect(validation.valid).toBe(false);
      expect(validation.errors).toHaveLength(1);
      expect(validation.errors[0]).toContain('Circular dependency');
    });
  });

  // ============================================================================
  // Scoped Services Tests
  // ============================================================================

  describe('Scoped Services', () => {
    it('should create scoped containers', () => {
      const scopedContainer = container.createScope('test-scope');

      expect(scopedContainer).toHaveProperty('scopeId', 'test-scope');
    });

    it('should isolate scoped service instances', () => {
      const SCOPED_SERVICE_ID = createServiceId<ITestService>('ScopedService');

      container.register(SCOPED_SERVICE_ID, TestService, ServiceLifetime.SCOPED);

      const scope1 = container.createScope('scope-1');
      const scope2 = container.createScope('scope-2');

      const service1 = scope1.resolve(SCOPED_SERVICE_ID);
      const service2 = scope2.resolve(SCOPED_SERVICE_ID);

      expect(service1).not.toBe(service2);
      expect(service1).toBeInstanceOf(TestService);
      expect(service2).toBeInstanceOf(TestService);
    });

    it('should return the same instance within the same scope', () => {
      const SCOPED_SERVICE_ID = createServiceId<ITestService>('ScopedService');

      container.register(SCOPED_SERVICE_ID, TestService, ServiceLifetime.SCOPED);

      const scope = container.createScope('test-scope');

      const service1 = scope.resolve(SCOPED_SERVICE_ID);
      const service2 = scope.resolve(SCOPED_SERVICE_ID);

      expect(service1).toBe(service2);
    });

    it('should clear scoped instances', () => {
      const SCOPED_SERVICE_ID = createServiceId<ITestService>('ScopedService');

      container.register(SCOPED_SERVICE_ID, TestService, ServiceLifetime.SCOPED);

      const scope = container.createScope('test-scope');
      scope.resolve(SCOPED_SERVICE_ID);

      container.clearScope('test-scope');

      // Should create a new instance after clearing scope
      const newService = scope.resolve(SCOPED_SERVICE_ID);
      expect(newService).toBeInstanceOf(TestService);
    });
  });

  // ============================================================================
  // Error Handling Tests
  // ============================================================================

  describe('Error Handling', () => {
    it('should throw error when resolving unregistered service', () => {
      const UNREGISTERED_SERVICE_ID = createServiceId<ITestService>('UnregisteredService');

      expect(() => {
        container.resolve(UNREGISTERED_SERVICE_ID);
      }).toThrow(/is not registered/);
    });

    it('should throw error when registering duplicate service', () => {
      container.register(TEST_SERVICE_ID, TestService);

      expect(() => {
        container.register(TEST_SERVICE_ID, TestService);
      }).toThrow(/is already registered/);
    });

    it('should throw error when dependency is not registered', () => {
      const UNREGISTERED_DEP_ID = createServiceId<ITestService>('UnregisteredDep');

      container.register(
        TEST_SERVICE_WITH_DEPS_ID,
        TestServiceWithDeps,
        ServiceLifetime.SINGLETON,
        [UNREGISTERED_DEP_ID]
      );

      expect(() => {
        container.resolve(TEST_SERVICE_WITH_DEPS_ID);
      }).toThrow(/is not registered/);
    });

    it('should handle factory errors gracefully', () => {
      const errorFactory = vi.fn().mockImplementation(() => {
        throw new Error('Factory error');
      });

      container.registerFactory(TEST_SERVICE_ID, errorFactory, ServiceLifetime.SINGLETON);

      expect(() => {
        container.resolve(TEST_SERVICE_ID);
      }).toThrow('Factory error');
    });
  });

  // ============================================================================
  // Lifecycle Management Tests
  // ============================================================================

  describe('Lifecycle Management', () => {
    it('should dispose disposable services', async () => {
      container.registerInstance(
        DISPOSABLE_SERVICE_ID,
        new DisposableService(),
        testServiceValidator
      );

      const service = container.resolve(DISPOSABLE_SERVICE_ID) as ITestService;
      expect(service.getValue()).toBe('disposable');

      await container.dispose();

      expect(() => {
        service.getValue();
      }).toThrow('Service has been disposed');
    });

    it('should handle disposal errors gracefully', async () => {
      const faultyDisposable = new DisposableService();
      const originalDispose = faultyDisposable.dispose.bind(faultyDisposable);
      faultyDisposable.dispose = vi.fn().mockImplementation(async () => {
        await originalDispose();
        throw new Error('Disposal error');
      });

      container.registerInstance(DISPOSABLE_SERVICE_ID, faultyDisposable, testServiceValidator);

      // Should not throw during container disposal
      await expect(container.dispose()).resolves.not.toThrow();
    });

    it('should clear all instances', () => {
      container.register(TEST_SERVICE_ID, TestService, ServiceLifetime.SINGLETON);
      container.resolve(TEST_SERVICE_ID);

      container.clear();

      // Should create new instance after clearing
      const newService = container.resolve(TEST_SERVICE_ID);
      expect(newService).toBeInstanceOf(TestService);
    });
  });

  // ============================================================================
  // Metrics and Monitoring Tests
  // ============================================================================

  describe('Metrics and Monitoring', () => {
    it('should collect metrics when enabled', () => {
      container.register(TEST_SERVICE_ID, TestService, ServiceLifetime.SINGLETON);

      // Resolve service multiple times
      container.resolve(TEST_SERVICE_ID);
      container.resolve(TEST_SERVICE_ID);

      const metrics = container.getMetrics();

      expect(metrics.totalServices).toBe(1);
      expect(metrics.resolvedServices).toBe(1);
      expect(metrics.averageResolutionTime).toBeGreaterThan(0);
    });

    it('should emit lifecycle events', async () => {
      container.register(TEST_SERVICE_ID, TestService, ServiceLifetime.SINGLETON);

      let eventCount = 0;
      const expectedEvents = ['service:registered', 'service:resolving', 'service:resolved'];

      return new Promise<void>((resolve) => {
        container.on('service:registered', () => {
          eventCount++;
          checkComplete();
        });

        container.on('service:resolving', () => {
          eventCount++;
          checkComplete();
        });

        container.on('service:resolved', () => {
          eventCount++;
          checkComplete();
        });

        function checkComplete() {
          if (eventCount === expectedEvents.length) {
            resolve();
          }
        }

        container.resolve(TEST_SERVICE_ID);
      });
    });

    it('should track failed resolutions', () => {
      const INVALID_SERVICE_ID = createServiceId<ITestService>('InvalidService');

      try {
        container.resolve(INVALID_SERVICE_ID);
      } catch {
        // Expected to throw
      }

      const metrics = container.getMetrics();
      expect(metrics.failedResolutions).toBe(1);
    });
  });

  // ============================================================================
  // Service Information and Discovery Tests
  // ============================================================================

  describe('Service Information and Discovery', () => {
    it('should provide service information', () => {
      container.register(
        TEST_SERVICE_ID,
        TestService,
        ServiceLifetime.SINGLETON,
        [],
        testServiceValidator,
        ['test']
      );

      const serviceInfo = container.getServiceInfo(TEST_SERVICE_ID);

      expect(serviceInfo).toBeDefined();
      expect(serviceInfo?.token).toBe(TEST_SERVICE_ID);
      expect(serviceInfo?.lifetime).toBe(ServiceLifetime.SINGLETON);
    });

    it('should return null for unknown service info', () => {
      const UNKNOWN_SERVICE_ID = createServiceId<ITestService>('UnknownService');

      const serviceInfo = container.getServiceInfo(UNKNOWN_SERVICE_ID);

      expect(serviceInfo).toBeNull();
    });

    it('should list all registered services', () => {
      container.register(TEST_SERVICE_ID, TestService, ServiceLifetime.SINGLETON);

      const allServices = container.getAllServices();

      expect(allServices.size).toBe(1);
      expect(allServices.has(TEST_SERVICE_ID)).toBe(true);
    });

    it('should check if service is registered', () => {
      expect(container.isRegistered(TEST_SERVICE_ID)).toBe(false);

      container.register(TEST_SERVICE_ID, TestService, ServiceLifetime.SINGLETON);

      expect(container.isRegistered(TEST_SERVICE_ID)).toBe(true);
    });
  });

  // ============================================================================
  // Configuration Tests
  // ============================================================================

  describe('Configuration', () => {
    it('should use provided configuration', () => {
      const customContainer = createTypedDIContainer({
        enableAutoValidation: false,
        enableRuntimeTypeChecking: false,
        enableMetrics: false,
        maxResolutionDepth: 5,
      });

      expect(customContainer.getMetrics().totalServices).toBe(0);
    });

    it('should use default configuration when none provided', () => {
      const defaultContainer = createTypedDIContainer();

      expect(defaultContainer).toBeInstanceOf(TypedDIContainer);
    });
  });

  // ============================================================================
  // Integration Tests
  // ============================================================================

  describe('Integration Tests', () => {
    it('should handle complex dependency graphs', () => {
      const SERVICE_A = createServiceId<ITestService>('ServiceA');
      const SERVICE_B = createServiceId<ITestService>('ServiceB');
      const SERVICE_C = createServiceId<ITestService>('ServiceC');

      container.register(SERVICE_A, TestService, ServiceLifetime.SINGLETON);
      container.register(SERVICE_B, TestServiceWithDeps, ServiceLifetime.SINGLETON, [SERVICE_A]);
      container.register(SERVICE_C, TestServiceWithDeps, ServiceLifetime.SINGLETON, [
        SERVICE_B,
        SERVICE_A,
      ]);

      const serviceC = container.resolve(SERVICE_C) as ITestServiceWithDeps;

      expect(serviceC).toBeInstanceOf(TestServiceWithDeps);
      expect(serviceC.getDepValue()).toBe('with-deps');
    });

    it('should handle mixed lifetimes correctly', () => {
      const SINGLETON_SERVICE = createServiceId<ITestService>('SingletonService');
      const TRANSIENT_SERVICE = createServiceId<ITestService>('TransientService');
      const SCOPED_SERVICE = createServiceId<ITestService>('ScopedService');

      container.register(SINGLETON_SERVICE, TestService, ServiceLifetime.SINGLETON);
      container.register(TRANSIENT_SERVICE, TestService, ServiceLifetime.TRANSIENT);
      container.register(SCOPED_SERVICE, TestService, ServiceLifetime.SCOPED);

      const singleton1 = container.resolve(SINGLETON_SERVICE);
      const singleton2 = container.resolve(SINGLETON_SERVICE);
      expect(singleton1).toBe(singleton2);

      const transient1 = container.resolve(TRANSIENT_SERVICE);
      const transient2 = container.resolve(TRANSIENT_SERVICE);
      expect(transient1).not.toBe(transient2);

      const scope = container.createScope('integration-test');
      const scoped1 = scope.resolve(SCOPED_SERVICE);
      const scoped2 = scope.resolve(SCOPED_SERVICE);
      expect(scoped1).toBe(scoped2);
    });

    it('should handle factory dependencies correctly', async () => {
      const FACTORY_DEP_ID = createServiceId<ITestService>('FactoryDep');
      const FACTORY_SERVICE_ID = createServiceId<ITestService>('FactoryService');

      container.register(FACTORY_DEP_ID, TestService, ServiceLifetime.SINGLETON);

      container.registerFactory(
        FACTORY_SERVICE_ID,
        (container) => {
          const dep = container.resolve(FACTORY_DEP_ID) as ITestService;
          const service = new TestService();
          service.setValue(`factory-with-dep: ${dep.getValue()}`);
          return service;
        },
        ServiceLifetime.SINGLETON,
        [FACTORY_DEP_ID]
      );

      const service = container.resolve(FACTORY_SERVICE_ID) as ITestService;

      expect(service.getValue()).toBe('factory-with-dep: default');
    });
  });
});
