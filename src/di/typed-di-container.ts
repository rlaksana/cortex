/**
 * Fully Typed Dependency Injection Container with proper type safety
 *
 * A comprehensive DI container with runtime validation, circular dependency detection,
 * and proper lifecycle management.
 */

import { EventEmitter } from 'events';

import {
  DependencyResolutionError,
  type EnhancedServiceRegistration,
  type FactoryServiceRegistration,
  type InstanceServiceRegistration,
  type ResolutionOptions,
  type ServiceId,
  ServiceLifetime,
  ServiceRegistrationError,
  type TypedDIContainer as ITypedDIContainer,
  type TypedServiceRegistration,
  type ValidationResult,
} from '../factories/factory-types';
import {
  isDIContainerConfig,
  isDisposable} from '../utils/type-safe-access.js';

// Re-export ServiceLifetime and ServiceRegistrationError for external use
export { ServiceLifetime, ServiceRegistrationError } from '../factories/factory-types';

import {
  DependencyResolutionValidator,
  type RuntimeValidator,
  type ServiceTypeDescriptor,
  ServiceValidationError,
  ValidatedServiceRegistry,
} from './runtime-validation';

// Container configuration options
export interface TypedContainerConfig {
  readonly enableAutoValidation?: boolean;
  readonly enableRuntimeTypeChecking?: boolean;
  readonly enableCircularDependencyDetection?: boolean;
  readonly enableMetrics?: boolean;
  readonly enableDebugLogging?: boolean;
  readonly maxResolutionDepth?: number;
  readonly validationCacheTimeout?: number;
  readonly enableLazyLoading?: boolean;
  readonly enableServiceProxying?: boolean;
}

// Service registration with validation support
export interface ValidatedServiceRegistration<T = unknown> {
  readonly validator?: RuntimeValidator<T>;
  readonly descriptor?: ServiceTypeDescriptor;
  readonly tags?: ReadonlyArray<string>;
  readonly priority?: number;
  readonly registration: EnhancedServiceRegistration<T>;
}

// Resolution context for tracking
export interface ResolutionContext {
  readonly requestId: string;
  readonly serviceId: string;
  readonly path: ReadonlyArray<string>;
  readonly depth: number;
  readonly scope?: string;
  readonly startTime: number;
  readonly timeout?: number;
  readonly forceNew: boolean;
}

// Enhanced typed DI container implementation
export class TypedDIContainer implements ITypedDIContainer {
  private services = new Map<string | symbol, EnhancedServiceRegistration<unknown>>();
  private instances = new Map<string | symbol, unknown>();
  private scopedInstances = new Map<string, Map<string | symbol, unknown>>();
  private serviceRegistry: ValidatedServiceRegistry;
  private dependencyValidator: DependencyResolutionValidator;
  private eventEmitter: EventEmitter;
  private metrics = new Map<string, { count: number; totalTime: number; errors: number }>();
  private config: TypedContainerConfig;

  constructor(config: TypedContainerConfig = {}) {
    this.serviceRegistry = new ValidatedServiceRegistry();
    this.dependencyValidator = new DependencyResolutionValidator(this.serviceRegistry);
    this.eventEmitter = new EventEmitter();
    this.config = {
      enableAutoValidation: config.enableAutoValidation ?? true,
      enableRuntimeTypeChecking: config.enableRuntimeTypeChecking ?? true,
      enableCircularDependencyDetection: config.enableCircularDependencyDetection ?? true,
      enableMetrics: config.enableMetrics ?? false,
      enableDebugLogging: config.enableDebugLogging ?? process.env.NODE_ENV === 'development',
      maxResolutionDepth: config.maxResolutionDepth ?? 50,
      validationCacheTimeout: config.validationCacheTimeout ?? 30000,
      enableLazyLoading: config.enableLazyLoading ?? false,
      enableServiceProxying: config.enableServiceProxying ?? false,
    };

    if (this.config.enableAutoValidation) {
      this.setupAutoValidation();
    }
  }

  // Service registration methods
  register<T>(
    token: ServiceId<T> | symbol | (new (...args: any[]) => T),
    implementation: new (...args: any[]) => T,
    lifetime: ServiceLifetime = ServiceLifetime.SINGLETON,
    dependencies?: ReadonlyArray<ServiceId | symbol | (new (...args: any[]) => unknown)>,
    validator?: RuntimeValidator<T>,
    tags?: ReadonlyArray<string>,
    priority?: number
  ): void {
    const key = this.getServiceKey(token);
    const serviceId = this.getServiceIdString(key);

    this.validateServiceRegistration(key, implementation, lifetime, dependencies);

    if (this.services.has(key)) {
      throw new ServiceRegistrationError(`Service ${serviceId} is already registered`, serviceId);
    }

    const registration: TypedServiceRegistration<T> = {
      token,
      implementation,
      lifetime,
      dependencies: dependencies || [],
    };

    this.services.set(key, registration);

    if (validator) {
      this.serviceRegistry.registerService(key, {
        name: serviceId,
        validator,
        dependencies: (dependencies || []).map((dep) =>
          this.getServiceIdString(this.getServiceKey(dep))
        ),
        optionalDependencies: [],
      });
    }

    this.emitEvent('service:registered', {
      serviceId,
      registration,
      metadata: { lifetime, dependencies, tags, priority },
    });
    this.logDebug(`Registered service: ${serviceId} with lifetime: ${lifetime}`);
  }

  registerFactory<T>(
    token: ServiceId<T> | symbol | (new (...args: any[]) => T),
    factory: (container: ITypedDIContainer) => T | Promise<T>,
    lifetime: ServiceLifetime = ServiceLifetime.SINGLETON,
    dependencies?: ReadonlyArray<ServiceId | symbol | (new (...args: any[]) => unknown)>,
    validator?: RuntimeValidator<T>,
    tags?: ReadonlyArray<string>
  ): void {
    const key = this.getServiceKey(token);
    const serviceId = this.getServiceIdString(key);

    this.validateFactoryRegistration(key, factory, lifetime, dependencies);

    if (this.services.has(key)) {
      throw new ServiceRegistrationError(`Service ${serviceId} is already registered`, serviceId);
    }

    const registration: FactoryServiceRegistration<T> = {
      token,
      factory,
      lifetime,
      dependencies: dependencies || [],
    };

    this.services.set(key, registration);

    if (validator) {
      this.serviceRegistry.registerService(key, {
        name: serviceId,
        validator,
        dependencies: (dependencies || []).map((dep) =>
          this.getServiceIdString(this.getServiceKey(dep))
        ),
        optionalDependencies: [],
      });
    }

    this.emitEvent('service:factory-registered', {
      serviceId,
      registration,
      metadata: { lifetime, dependencies, tags },
    });
    this.logDebug(`Registered factory: ${serviceId} with lifetime: ${lifetime}`);
  }

  registerInstance<T>(
    token: ServiceId<T> | symbol | (new (...args: any[]) => T),
    instance: T,
    validator?: RuntimeValidator<T>,
    tags?: ReadonlyArray<string>
  ): void {
    const key = this.getServiceKey(token);
    const serviceId = this.getServiceIdString(key);

    this.validateInstanceRegistration(key, instance);

    if (this.services.has(key)) {
      throw new ServiceRegistrationError(`Service ${serviceId} is already registered`, serviceId);
    }

    if (this.config.enableRuntimeTypeChecking && validator) {
      const validation = this.serviceRegistry.validateService(key, instance);
      if (!validation.valid) {
        throw new ServiceValidationError(
          `Instance validation failed for ${serviceId}: ${validation.errors.join(', ')}`,
          serviceId,
          validation.errors
        );
      }
    }

    const registration: InstanceServiceRegistration<T> = {
      token,
      instance,
      lifetime: ServiceLifetime.SINGLETON,
    };

    this.services.set(key, registration);
    this.instances.set(key, instance);

    if (validator) {
      this.serviceRegistry.registerService(key, {
        name: serviceId,
        validator,
        dependencies: [],
        optionalDependencies: [],
      });
    }

    this.emitEvent('service:instance-registered', { serviceId, instance, metadata: { tags } });
    this.logDebug(`Registered instance: ${serviceId}`);
  }

  // Service resolution
  resolve<T>(
    token: ServiceId<T> | symbol | (new (...args: never[]) => T),
    options: ResolutionOptions = {}
  ): T {
    const key = this.getServiceKey(token);
    const serviceId = this.getServiceIdString(key);
    const startTime = Date.now();

    const context: ResolutionContext = {
      requestId: crypto.randomUUID(),
      serviceId,
      path: [serviceId],
      depth: 0,
      scope: options?.scope,
      startTime,
      timeout: options?.timeout,
      forceNew: options?.forceNew ?? false,
    };

    try {
      this.emitEvent('service:resolving', { serviceId, context, metadata: { options } });

      const instance = this.resolveWithContext(key, context);

      if (this.config.enableMetrics) {
        this.updateMetrics(serviceId, Date.now() - startTime, true);
      }

      this.emitEvent('service:resolved', {
        serviceId,
        instance,
        context,
        metadata: { resolutionTime: Date.now() - startTime },
      });
      return instance as T;
    } catch (error) {
      if (this.config.enableMetrics) {
        this.updateMetrics(serviceId, Date.now() - startTime, false);
      }

      this.emitEvent('service:resolution-failed', {
        serviceId,
        error,
        context,
        metadata: { resolutionTime: Date.now() - startTime },
      });
      throw error;
    }
  }

  private resolveWithContext(key: string | symbol, context: ResolutionContext): unknown {
    const serviceId = this.getServiceIdString(key);
    const registration = this.services.get(key);

    if (!registration) {
      throw new ServiceRegistrationError(`Service ${serviceId} is not registered`, serviceId);
    }

    if (context.depth > this.config.maxResolutionDepth!) {
      throw new DependencyResolutionError(
        `Maximum resolution depth exceeded: ${context.depth} > ${this.config.maxResolutionDepth}`,
        serviceId,
        context.path[context.path.length - 2]
      );
    }

    if (context.path.includes(serviceId)) {
      const cycleStart = context.path.indexOf(serviceId);
      const cycle = context.path.slice(cycleStart).concat([serviceId]);
      throw new DependencyResolutionError(
        `Circular dependency detected: ${cycle.join(' -> ')}`,
        serviceId,
        context.path[context.path.length - 2]
      );
    }

    if (
      registration.lifetime === ServiceLifetime.SINGLETON &&
      this.instances.has(key) &&
      !context.forceNew
    ) {
      const instance = this.instances.get(key);
      this.validateResolvedInstance(key, instance);
      return instance;
    }

    if (registration.lifetime === ServiceLifetime.SCOPED && context.scope) {
      const scope = this.scopedInstances.get(context.scope);
      if (scope && scope.has(key) && !context.forceNew) {
        const instance = scope.get(key);
        this.validateResolvedInstance(key, instance);
        return instance;
      }
    }

    const instance = this.createInstance(registration, {
      ...context,
      path: [...context.path, serviceId],
      depth: context.depth + 1,
    });

    if (registration.lifetime === ServiceLifetime.SINGLETON) {
      this.instances.set(key, instance);
    } else if (registration.lifetime === ServiceLifetime.SCOPED && context.scope) {
      if (!this.scopedInstances.has(context.scope)) {
        this.scopedInstances.set(context.scope, new Map());
      }
      this.scopedInstances.get(context.scope)!.set(key, instance);
    }

    this.validateResolvedInstance(key, instance);
    return instance;
  }

  private createInstance(
    registration: EnhancedServiceRegistration<unknown>,
    context: ResolutionContext
  ): unknown {
    if ('factory' in registration) {
      return registration.factory(this);
    }

    if ('instance' in registration) {
      return registration.instance;
    }

    if ('implementation' in registration) {
      const dependencies = this.resolveDependencies(registration.dependencies || [], context);
      const ImplementationClass = registration.implementation as new (...args: unknown[]) => unknown;

      return new ImplementationClass(...dependencies);
    }

    throw new ServiceRegistrationError(
      `Invalid service registration for ${context.serviceId}: no factory, instance, or implementation`,
      context.serviceId
    );
  }

  private resolveDependencies(
    dependencies: ReadonlyArray<ServiceId | symbol | (new (...args: never[]) => unknown)>,
    context: ResolutionContext
  ): unknown[] {
    return dependencies.map((dep) => {
      const depKey = this.getServiceKey(dep);
      const depId = this.getServiceIdString(depKey);

      const depRegistration = this.services.get(depKey);
      if (!depRegistration) {
        throw new DependencyResolutionError(
          `Dependency ${depId} is not registered`,
          depId,
          context.serviceId
        );
      }

      return this.resolveWithContext(depKey, {
        ...context,
        serviceId: depId,
        path: [...context.path, depId],
      });
    });
  }

  // Container lifecycle and management
  isRegistered<T>(token: ServiceId<T> | symbol | (new (...args: never[]) => T)): boolean {
    const key = this.getServiceKey(token);
    return this.services.has(key);
  }

  createScope(scopeId?: string): ITypedDIContainer & { readonly scopeId: string } {
    const scope = scopeId || crypto.randomUUID();
    const scopedContainer = new TypedDIContainer(this.config);

    for (const [key, registration] of this.services) {
      // Re-register services in the scoped container
      if ('implementation' in registration) {
        scopedContainer.register(key as any, registration.implementation, registration.lifetime, registration.dependencies);
      } else if ('factory' in registration) {
        scopedContainer.registerFactory(key as any, registration.factory, registration.lifetime, registration.dependencies);
      } else if ('instance' in registration) {
        scopedContainer.registerInstance(key as any, registration.instance);
      }
    }

    // Add scope-specific instance tracking
    if (!scopedContainer.scopedInstances) {
      (scopedContainer as any).scopedInstances = new Map();
    }
    (scopedContainer as any).scopedInstances.set(scope, new Map());

    return Object.assign(scopedContainer, { scopeId: scope });
  }

  clearScope(scopeId: string): void {
    this.scopedInstances.delete(scopeId);
    this.emitEvent('scope:cleared', { scopeId });
  }

  clear(): void {
    this.instances.clear();
    this.scopedInstances.clear();
    this.metrics.clear();
    this.emitEvent('container:cleared', {});
  }

  async dispose(): Promise<void> {
    const disposePromises: Promise<void>[] = [];

    for (const [key, instance] of this.instances) {
      if (isDisposable(instance)) {
        disposePromises.push(
          Promise.resolve(instance.dispose()).catch((error) => {
            this.logError(`Error disposing service ${this.getServiceIdString(key)}:`, error);
          })
        );
      } else if (this.isDisposable(instance)) {
        // Fall back to existing check for backwards compatibility
        disposePromises.push(
          Promise.resolve((instance as any).dispose()).catch((error) => {
            this.logError(`Error disposing service ${this.getServiceIdString(key)}:`, error);
          })
        );
      }
    }

    await Promise.all(disposePromises);

    this.instances.clear();
    this.scopedInstances.clear();
    this.services.clear();
    this.metrics.clear();
    this.serviceRegistry = {} as ValidatedServiceRegistry;

    this.emitEvent('container:disposed', {});
    this.eventEmitter.removeAllListeners();
  }

  // Validation and diagnostics
  validateDependencyGraph(): ValidationResult {
    const config = this.config as unknown;
    if (!isDIContainerConfig(config) || !config.enableCircularDependencyDetection) {
      return { valid: true, errors: [] };
    }

    return this.dependencyValidator.validateDependencyGraph?.() ?? { valid: true, errors: [], warnings: [] };
  }

  validateAllServices(): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    for (const [key, registration] of this.services) {
      const serviceId = this.getServiceIdString(key);

      try {
        const reg = registration as TypedServiceRegistration<unknown> |
                   FactoryServiceRegistration<unknown> |
                   InstanceServiceRegistration<unknown>;

        if ('implementation' in reg) {
          const implReg = reg as TypedServiceRegistration<unknown>;
          this.validateServiceRegistration(
            key,
            implReg.implementation as new (...args: any[]) => unknown,
            implReg.lifetime,
            implReg.dependencies
          );
        } else if ('factory' in reg) {
          const factoryReg = reg as FactoryServiceRegistration<unknown>;
          this.validateFactoryRegistration(
            key,
            factoryReg.factory,
            factoryReg.lifetime,
            factoryReg.dependencies
          );
        } else if ('instance' in reg) {
          const instanceReg = reg as InstanceServiceRegistration<unknown>;
          this.validateInstanceRegistration(key, instanceReg.instance);
        }
      } catch (error) {
        errors.push(`${serviceId}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  // Utility methods
  getServiceInfo<T>(
    token: ServiceId<T> | symbol | (new (...args: any[]) => T)
  ): TypedServiceRegistration<T> | FactoryServiceRegistration<T> | InstanceServiceRegistration<T> | null {
    const key = this.getServiceKey(token);
    const registration = this.services.get(key);

    if (!registration) {
      return null;
    }

    // Type guard to properly narrow the registration type
    if ('implementation' in registration) {
      return registration as TypedServiceRegistration<T>;
    } else if ('factory' in registration) {
      return registration as FactoryServiceRegistration<T>;
    } else if ('instance' in registration) {
      return registration as InstanceServiceRegistration<T>;
    }

    return null;
  }

  getAllServices(): ReadonlyMap<string | symbol, EnhancedServiceRegistration<unknown>> {
    return new Map(this.services);
  }

  // Event handling
  on(event: string, listener: (...args: unknown[]) => void): void {
    this.eventEmitter.on(event, listener);
  }

  // Private helper methods
  private getServiceKey(
    token: ServiceId | symbol | (new (...args: never[]) => unknown)
  ): string | symbol {
    if (typeof token === 'string' || typeof token === 'symbol') {
      return token;
    }
    const tokenObj = token as unknown;
    return isDIContainerConfig(tokenObj) && tokenObj.name ? tokenObj.name : String(token);
  }

  private getServiceIdString(key: string | symbol): string {
    return typeof key === 'string' ? key : key.toString();
  }

  private validateServiceRegistration<T>(
    key: string | symbol,
    implementation: new (...args: never[]) => T,
    lifetime: ServiceLifetime,
    dependencies?: ReadonlyArray<ServiceId | symbol | (new (...args: never[]) => unknown)>
  ): void {
    const errors: string[] = [];

    if (typeof implementation !== 'function') {
      errors.push('Implementation must be a constructor function');
    }

    if (!Object.values(ServiceLifetime).includes(lifetime)) {
      errors.push(`Invalid service lifetime: ${lifetime}`);
    }

    if (dependencies && dependencies.length > 0) {
      for (const dep of dependencies) {
        const depKey = this.getServiceKey(dep);
        if (!this.services.has(depKey)) {
          this.logDebug(
            `Dependency ${this.getServiceIdString(depKey)} is not registered during registration of ${this.getServiceIdString(key)}`
          );
        }
      }
    }

    if (errors.length > 0) {
      throw new ServiceRegistrationError(
        `Invalid service registration for ${this.getServiceIdString(key)}: ${errors.join(', ')}`,
        this.getServiceIdString(key)
      );
    }
  }

  private validateFactoryRegistration<T>(
    key: string | symbol,
    factory: (container: ITypedDIContainer) => T | Promise<T>,
    lifetime: ServiceLifetime,
    dependencies?: ReadonlyArray<ServiceId | symbol | (new (...args: never[]) => unknown)>
  ): void {
    const errors: string[] = [];

    if (typeof factory !== 'function') {
      errors.push('Factory must be a function');
    }

    if (!Object.values(ServiceLifetime).includes(lifetime)) {
      errors.push(`Invalid service lifetime: ${lifetime}`);
    }

    if (errors.length > 0) {
      throw new ServiceRegistrationError(
        `Invalid factory registration for ${this.getServiceIdString(key)}: ${errors.join(', ')}`,
        this.getServiceIdString(key)
      );
    }
  }

  private validateInstanceRegistration<T>(key: string | symbol, instance: T): void {
    if (instance === null || instance === undefined) {
      throw new ServiceRegistrationError(
        `Instance cannot be null or undefined for ${this.getServiceIdString(key)}`,
        this.getServiceIdString(key)
      );
    }
  }

  private validateResolvedInstance(key: string | symbol, instance: unknown): void {
    if (!this.config.enableRuntimeTypeChecking) return;

    const registration = this.services.get(key);
    if (!registration) return;

    // Add runtime validation logic here if needed
  }

  private isDisposable(instance: unknown): boolean {
    return (
      instance !== null &&
      instance !== undefined &&
      typeof instance === 'object' &&
      'dispose' in instance &&
      typeof (instance as any).dispose === 'function'
    );
  }

  private updateMetrics(serviceId: string, resolutionTime: number, success: boolean): void {
    const existing = this.metrics.get(serviceId) || { count: 0, totalTime: 0, errors: 0 };

    this.metrics.set(serviceId, {
      count: existing.count + 1,
      totalTime: existing.totalTime + resolutionTime,
      errors: success ? existing.errors : existing.errors + 1,
    });
  }

  private emitEvent(event: string, data: unknown): void {
    try {
      this.eventEmitter.emit(event, data);
    } catch (error) {
      this.logError(`Error emitting event ${event}:`, error);
    }
  }

  private setupAutoValidation(): void {
    this.on('service:registered', () => {
      const validation = this.validateDependencyGraph();
      if (!validation.valid) {
        this.logError('Dependency graph validation failed:', validation.errors);
      }
    });
  }

  private logDebug(message: string, ...args: unknown[]): void {
    if (this.config.enableDebugLogging) {
      console.debug(`[Typed DI Container] ${message}`, ...args);
    }
  }

  private logError(message: string, ...args: unknown[]): void {
    console.error(`[Typed DI Container] ${message}`, ...args);
  }

  public getMetrics(): {
    totalServices: number;
    resolvedServices: number;
    failedResolutions: number;
    averageResolutionTime: number;
    serviceMetrics: ReadonlyMap<string, { count: number; totalTime: number; errors: number }>;
  } {
    let totalCount = 0;
    let resolvedCount = 0;
    let failedCount = 0;
    let totalTime = 0;

    for (const [, service] of this.metrics) {
      totalCount += service.count;
      resolvedCount += service.count - service.errors;
      failedCount += service.errors;
      totalTime += service.totalTime;
    }

    return {
      totalServices: this.services.size,
      resolvedServices: resolvedCount,
      failedResolutions: failedCount,
      averageResolutionTime: resolvedCount > 0 ? totalTime / resolvedCount : 0,
      serviceMetrics: new Map(this.metrics),
    };
  }
}

// Factory function for creating containers with sensible defaults
export function createTypedDIContainer(config?: TypedContainerConfig): TypedDIContainer {
  return new TypedDIContainer(config);
}

// Default container instance
export const defaultTypedContainer = createTypedDIContainer({
  enableAutoValidation: true,
  enableRuntimeTypeChecking: true,
  enableCircularDependencyDetection: true,
  enableMetrics: process.env.NODE_ENV === 'development',
  enableDebugLogging: process.env.NODE_ENV === 'development',
});
