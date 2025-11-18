// EMERGENCY ROLLBACK: DI container interface compatibility issues

/**
 * Dependency Injection Container
 *
 * A comprehensive dependency injection system that manages service instantiation,
 * lifecycle, and dependencies. Replaces singleton patterns with proper DI.
 *
 * Features:
 * - Service registration and resolution
 * - Constructor injection support
 * - Lifecycle management (singleton, transient, scoped)
 * - Circular dependency detection
 * - Factory pattern support
 * - Interface-based dependency resolution
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'node:events';

import { logger } from '../utils/logger.js';

import 'reflect-metadata';

/**
 * Service lifecycle types
 */
export enum ServiceLifetime {
  SINGLETON = 'singleton',
  TRANSIENT = 'transient',
  SCOPED = 'scoped',
}

/**
 * Service registration configuration
 */
export interface ServiceRegistration<T = unknown> {
  token: string | symbol | (new (...args: any[]) => T);
  implementation: new (...args: any[]) => T | (() => T);
  lifetime: ServiceLifetime;
  dependencies?: (string | symbol | (new (...args: any[]) => unknown))[];
  factory?: (container: DIContainer) => T;
  instance?: T;
}

/**
 * Service resolution options
 */
export interface ResolutionOptions {
  allowTransient?: boolean;
  forceNew?: boolean;
  scope?: string;
}

/**
 * Dependency injection container with comprehensive service management
 */
export class DIContainer {
  private services = new Map<string | symbol, ServiceRegistration<unknown>>();
  private instances = new Map<string | symbol, unknown>();
  private scopedInstances = new Map<string, Map<string | symbol, unknown>>();
  private resolving = new Set<string | symbol>();
  private eventEmitter = new EventEmitter();

  /**
   * Register a service with the container
   */
  register<T>(
    token: string | symbol | (new (...args: any[]) => T),
    implementation: new (...args: any[]) => T,
    lifetime: ServiceLifetime = ServiceLifetime.SINGLETON,
    dependencies?: (string | symbol | (new (...args: any[]) => unknown))[]
  ): void {
    const key = this.getServiceKey(token);

    if (this.services.has(key)) {
      throw new Error(`Service ${String(key)} is already registered`);
    }

    const registration: ServiceRegistration<T> = {
      token,
      implementation,
      lifetime,
      dependencies: dependencies || [],
    };

    this.services.set(key, registration);
    logger.debug(`Registered service: ${String(key)} with lifetime: ${lifetime}`);

    this.eventEmitter.emit('service:registered', { key, registration });
  }

  /**
   * Register a singleton instance
   */
  registerInstance<T>(token: string | symbol | (new (...args: any[]) => T), instance: T): void {
    const key = this.getServiceKey(token);

    const registration: ServiceRegistration<T> = {
      token,
      implementation:
        instance && instance.constructor
          ? (instance.constructor as new (...args: any[]) => T)
          : (class {} as new (...args: any[]) => T),
      lifetime: ServiceLifetime.SINGLETON,
      instance,
    };

    this.services.set(key, registration);
    this.instances.set(key, instance);

    logger.debug(`Registered instance: ${String(key)}`);
    this.eventEmitter.emit('service:instance-registered', { key, instance });
  }

  /**
   * Register a factory function for service creation
   */
  registerFactory<T>(
    token: string | symbol | (new (...args: any[]) => T),
    factory: (container: DIContainer) => T,
    lifetime: ServiceLifetime = ServiceLifetime.SINGLETON,
    dependencies?: (string | symbol | (new (...args: any[]) => unknown))[]
  ): void {
    const key = this.getServiceKey(token);

    if (this.services.has(key)) {
      throw new Error(`Service ${String(key)} is already registered`);
    }

    const registration: ServiceRegistration<T> = {
      token,
      implementation: null as unknown as new (...args: any[]) => T,
      lifetime,
      dependencies: dependencies || [],
      factory,
    };

    this.services.set(key, registration);
    logger.debug(`Registered factory: ${String(key)} with lifetime: ${lifetime}`);

    this.eventEmitter.emit('service:factory-registered', { key, registration });
  }

  /**
   * Resolve a service instance
   */
  resolve<T>(
    token: string | symbol | (new (...args: any[]) => T),
    options: ResolutionOptions = {}
  ): T {
    const key = this.getServiceKey(token);

    if (!this.services.has(key)) {
      throw new Error(`Service ${String(key)} is not registered`);
    }

    // Check for circular dependencies
    if (this.resolving.has(key)) {
      throw new Error(`Circular dependency detected: ${String(key)}`);
    }

    const registration = this.services.get(key)!;

    // Return existing instance for singletons (unless forced)
    if (
      registration.lifetime === ServiceLifetime.SINGLETON &&
      this.instances.has(key) &&
      !options.forceNew
    ) {
      return this.instances.get(key) as T;
    }

    // Check scoped instances
    if (registration.lifetime === ServiceLifetime.SCOPED && options.scope) {
      const scope = this.scopedInstances.get(options.scope);
      if (scope && scope.has(key) && !options.forceNew) {
        return scope.get(key) as T;
      }
    }

    this.resolving.add(key);

    try {
      let instance: T;

      if (registration.factory) {
        instance = registration.factory(this) as T;
      } else if (registration.instance) {
        instance = registration.instance as T;
      } else {
        // Resolve dependencies first
        const dependencies = this.resolveDependencies(registration.dependencies || [], options);
        instance = new registration.implementation(...dependencies) as T;
      }

      // Store instance based on lifetime
      if (registration.lifetime === ServiceLifetime.SINGLETON) {
        this.instances.set(key, instance);
      } else if (registration.lifetime === ServiceLifetime.SCOPED && options.scope) {
        if (!this.scopedInstances.has(options.scope)) {
          this.scopedInstances.set(options.scope, new Map());
        }
        this.scopedInstances.get(options.scope)!.set(key, instance);
      }

      this.eventEmitter.emit('service:resolved', { key, instance });
      return instance;
    } finally {
      this.resolving.delete(key);
    }
  }

  /**
   * Check if a service is registered
   */
  isRegistered(token: string | symbol | (new (...args: any[]) => unknown)): boolean {
    const key = this.getServiceKey(token);
    return this.services.has(key);
  }

  /**
   * Create a scoped container
   */
  createScope(scopeId?: string): DIContainer {
    const scope = scopeId || crypto.randomUUID();
    const scopedContainer = new DIContainer();

    // Copy all registrations to the scoped container
    Array.from(this.services.entries()).forEach(([key, registration]) => {
      scopedContainer.services.set(key, { ...registration });
    });

    // Set the scope for resolution
    scopedContainer.scopedInstances.set(scope, new Map());

    return scopedContainer;
  }

  /**
   * Clear all scoped instances for a specific scope
   */
  clearScope(scopeId: string): void {
    this.scopedInstances.delete(scopeId);
    this.eventEmitter.emit('scope:cleared', { scopeId });
  }

  /**
   * Clear all instances (useful for testing)
   */
  clear(): void {
    this.instances.clear();
    this.scopedInstances.clear();
    this.eventEmitter.emit('container:cleared');
  }

  /**
   * Get service information
   */
  getServiceInfo(
    token: string | symbol | (new (...args: any[]) => unknown)
  ): ServiceRegistration | null {
    const key = this.getServiceKey(token);
    return this.services.get(key) || null;
  }

  /**
   * Get all registered services
   */
  getAllServices(): Map<string | symbol, ServiceRegistration> {
    return new Map(this.services);
  }

  /**
   * Event subscription for container events
   */
  on(event: string, listener: (...args: any[]) => void): void {
    this.eventEmitter.on(event, listener);
  }

  /**
   * Dispose container and cleanup resources
   */
  async dispose(): Promise<void> {
    // Dispose all instances that have dispose method
    const disposePromises = Array.from(this.instances.entries()).map(async ([key, instance]) => {
      if (instance && typeof (instance as any).dispose === 'function') {
        try {
          await (instance as any).dispose();
        } catch (error) {
          logger.error(`Error disposing service ${String(key)}:`, error);
        }
      }
    });

    await Promise.all(disposePromises);

    // Clear all containers
    this.instances.clear();
    this.scopedInstances.clear();
    this.services.clear();
    this.resolving.clear();

    this.eventEmitter.emit('container:disposed');
    this.eventEmitter.removeAllListeners();
  }

  /**
   * Resolve service dependencies recursively
   */
  private resolveDependencies(
    dependencies: (string | symbol | (new (...args: any[]) => unknown))[],
    options: ResolutionOptions
  ): unknown[] {
    return dependencies.map((dep) => this.resolve(dep, options));
  }

  /**
   * Get consistent key for service tokens
   */
  private getServiceKey(
    token: string | symbol | (new (...args: any[]) => unknown)
  ): string | symbol {
    if (typeof token === 'string' || typeof token === 'symbol') {
      return token;
    }
    return token.name;
  }
}

/**
 * Global container instance (should be replaced with proper injection in entry points)
 */
export const globalContainer = new DIContainer();

/**
 * Service decorator for automatic registration
 */
export function Injectable(token?: string | symbol) {
  return function <T extends new (...args: any[]) => unknown>(target: T) {
    // Store metadata for later registration
    Reflect.defineMetadata('injectable', true, target);
    if (token) {
      Reflect.defineMetadata('token', token, target);
    }
    return target;
  };
}

/**
 * Inject decorator for constructor parameters
 */
export function Inject(token: string | symbol) {
  return function (
    target: unknown,
    propertyKey: string | symbol | undefined,
    parameterIndex: number
  ) {
    const existingTokens = Reflect.getMetadata('inject-tokens', target) || [];
    existingTokens[parameterIndex] = token;
    Reflect.defineMetadata('inject-tokens', existingTokens, target);
  };
}
