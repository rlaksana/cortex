/**
 * Service Locator Pattern Implementation
 *
 * Provides a global access point for services while maintaining
 * the benefits of dependency injection. Use sparingly and prefer
 * constructor injection where possible.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '@/utils/logger.js';

import { type DIContainer } from './di-container.js';
import type {
  IAuditService,
  IAuthService,
  ICacheService,
  ICircuitBreakerService,
  IConfigService,
  IDatabaseService,
  IDeduplicationService,
  IEmbeddingService,
  IEventService,
  IHealthCheckService,
  ILoggerService,
  IMemoryFindOrchestrator,
  IMemoryStoreOrchestrator,
  IMetricsService,
  IPerformanceMonitor,
  IValidationService,
  ServiceType,
} from './service-interfaces.js';
import { ServiceTokens } from './service-interfaces.js';

/**
 * Service Locator implementation with container management
 */
export class ServiceLocator {
  private static instance: ServiceLocator;
  private container: DIContainer | null = null;
  private initialized = false;

  private constructor() {}

  /**
   * Get singleton instance
   */
  static getInstance(): ServiceLocator {
    if (!ServiceLocator.instance) {
      ServiceLocator.instance = new ServiceLocator();
    }
    return ServiceLocator.instance;
  }

  /**
   * Initialize the service locator with a container
   */
  initialize(container: DIContainer): void {
    if (this.initialized) {
      throw new Error('ServiceLocator is already initialized');
    }

    this.container = container;
    this.initialized = true;
    logger.info('ServiceLocator initialized with DI container');
  }

  /**
   * Check if the locator is initialized
   */
  isInitialized(): boolean {
    return this.initialized && this.container !== null;
  }

  /**
   * Get service by token
   */
  get<T>(token: ServiceType): T {
    this.ensureInitialized();
    return this.container!.resolve<T>(token);
  }

  /**
   * Try to get service, return null if not found
   */
  tryGet<T>(token: ServiceType): T | null {
    if (!this.isInitialized()) {
      return null;
    }

    try {
      return this.container!.resolve<T>(token);
    } catch {
      return null;
    }
  }

  /**
   * Check if service is registered
   */
  has(token: ServiceType): boolean {
    if (!this.isInitialized()) {
      return false;
    }

    return this.container!.isRegistered(token);
  }

  /**
   * Get all registered service tokens
   */
  getRegisteredServices(): ServiceType[] {
    this.ensureInitialized();
    const services = this.container!.getAllServices();
    return Array.from(services.keys()).filter((key) =>
      Object.values(ServiceTokens).includes(key as ServiceType)
    ) as ServiceType[];
  }

  /**
   * Convenience getters for common services
   */
  get config(): IConfigService {
    return this.get<IConfigService>(ServiceTokens.CONFIG_SERVICE);
  }

  get logger(): ILoggerService {
    return this.get<ILoggerService>(ServiceTokens.LOGGER_SERVICE);
  }

  get performanceMonitor(): IPerformanceMonitor {
    return this.get<IPerformanceMonitor>(ServiceTokens.PERFORMANCE_MONITOR);
  }

  get memoryStoreOrchestrator(): IMemoryStoreOrchestrator {
    return this.get<IMemoryStoreOrchestrator>(ServiceTokens.MEMORY_STORE_ORCHESTRATOR);
  }

  get memoryFindOrchestrator(): IMemoryFindOrchestrator {
    return this.get<IMemoryFindOrchestrator>(ServiceTokens.MEMORY_FIND_ORCHESTRATOR);
  }

  get databaseService(): IDatabaseService {
    return this.get<IDatabaseService>(ServiceTokens.DATABASE_SERVICE);
  }

  get authService(): IAuthService {
    return this.get<IAuthService>(ServiceTokens.AUTH_SERVICE);
  }

  get auditService(): IAuditService {
    return this.get<IAuditService>(ServiceTokens.AUDIT_SERVICE);
  }

  get deduplicationService(): IDeduplicationService {
    return this.get<IDeduplicationService>(ServiceTokens.DEDUPLICATION_SERVICE);
  }

  get embeddingService(): IEmbeddingService {
    return this.get<IEmbeddingService>(ServiceTokens.EMBEDDING_SERVICE);
  }

  get circuitBreakerService(): ICircuitBreakerService {
    return this.get<ICircuitBreakerService>(ServiceTokens.CIRCUIT_BREAKER_SERVICE);
  }

  get metricsService(): IMetricsService {
    return this.get<IMetricsService>(ServiceTokens.METRICS_SERVICE);
  }

  get healthCheckService(): IHealthCheckService {
    return this.get<IHealthCheckService>(ServiceTokens.HEALTH_CHECK_SERVICE);
  }

  get cacheService(): ICacheService {
    return this.get<ICacheService>(ServiceTokens.CACHE_SERVICE);
  }

  get eventService(): IEventService {
    return this.get<IEventService>(ServiceTokens.EVENT_SERVICE);
  }

  get validationService(): IValidationService {
    return this.get<IValidationService>(ServiceTokens.VALIDATION_SERVICE);
  }

  /**
   * Create a scoped service locator
   */
  createScope(scopeId?: string): ScopedServiceLocator {
    this.ensureInitialized();
    const scopedContainer = this.container!.createScope(scopeId);
    return new ScopedServiceLocator(scopedContainer);
  }

  /**
   * Reset the service locator (mainly for testing)
   */
  reset(): void {
    this.container = null;
    this.initialized = false;
  }

  private ensureInitialized(): void {
    if (!this.initialized || !this.container) {
      throw new Error('ServiceLocator is not initialized. Call initialize() first.');
    }
  }
}

/**
 * Scoped service locator for specific contexts
 */
export class ScopedServiceLocator {
  private container: DIContainer;

  constructor(container: DIContainer) {
    this.container = container;
  }

  /**
   * Get service from scoped container
   */
  get<T>(token: ServiceType): T {
    return this.container.resolve<T>(token, { scope: 'scoped' });
  }

  /**
   * Clear the scope
   */
  clear(): void {
    this.container.clearScope('scoped');
  }
}

/**
 * Global service locator instance
 */
export const serviceLocator = ServiceLocator.getInstance();

/**
 * Decorator for injecting services into classes (when constructor injection isn't possible)
 */
export function InjectService(token: ServiceType) {
  return function (target: any, propertyKey: string) {
    const privateProperty = `_${propertyKey}`;

    Object.defineProperty(target, propertyKey, {
      get: function () {
        if (!this[privateProperty]) {
          this[privateProperty] = serviceLocator.get(token);
        }
        return this[privateProperty];
      },
      enumerable: true,
      configurable: true,
    });
  };
}
