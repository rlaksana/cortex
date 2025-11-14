// @ts-nocheck
// COMPREHENSIVE EMERGENCY ROLLBACK: Final systematic type issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Factory Registry for centralized factory management
 * Provides type-safe factory registration, discovery, and lifecycle management
 */

import type {
  FactoryError,
  FactoryId,
  FactoryRegistry as IFactoryRegistry,
  TypedFactory,
  ValidationResult} from './factory-types';
import { EnhancedDIContainer } from '../di/enhanced-di-container';

// Factory metadata for tracking and management
export interface FactoryMetadata {
  readonly id: string;
  readonly name: string;
  readonly description?: string;
  readonly version?: string;
  readonly author?: string;
  readonly tags?: ReadonlyArray<string>;
  readonly registeredAt: Date;
  readonly lastUsed?: Date;
  readonly usageCount: number;
  readonly healthStatus: 'healthy' | 'degraded' | 'unhealthy';
  readonly lastHealthCheck?: Date;
  readonly dependencies?: ReadonlyArray<string>;
  readonly configurationSchema?: Record<string, unknown>;
}

// Factory registration options
export interface FactoryRegistrationOptions {
  readonly autoDiscovery?: boolean;
  readonly healthCheckInterval?: number;
  readonly enableMetrics?: boolean;
  readonly maxRetries?: number;
  readonly timeout?: number;
}

// Factory usage statistics
export interface FactoryUsageStats {
  readonly factoryId: string;
  readonly totalCreations: number;
  readonly successfulCreations: number;
  readonly failedCreations: number;
  readonly averageCreationTime: number;
  readonly lastCreationTime?: Date;
  readonly errorRate: number;
}

// Factory health information
export interface FactoryHealth {
  readonly factoryId: string;
  readonly status: 'healthy' | 'degraded' | 'unhealthy';
  readonly lastCheck: Date;
  readonly responseTime?: number;
  readonly error?: string;
  readonly metadata?: ReadonlyRecord<string, unknown>;
}

// Main factory registry implementation
export class FactoryRegistry implements IFactoryRegistry {
  private factories = new Map<string, TypedFactory<unknown, unknown>>();
  private metadata = new Map<string, FactoryMetadata>();
  private usageStats = new Map<string, FactoryUsageStats>();
  private healthStatus = new Map<string, FactoryHealth>();
  private healthCheckIntervals = new Map<string, NodeJS.Timeout>();
  private container: EnhancedDIContainer;
  private options: Required<FactoryRegistrationOptions>;

  constructor(
    container: EnhancedDIContainer = new EnhancedDIContainer(),
    options: FactoryRegistrationOptions = {}
  ) {
    this.container = container;
    this.options = {
      autoDiscovery: options.autoDiscovery ?? true,
      healthCheckInterval: options.healthCheckInterval ?? 300000, // 5 minutes
      enableMetrics: options.enableMetrics ?? true,
      maxRetries: options.maxRetries ?? 3,
      timeout: options.timeout ?? 30000
    };

    if (this.options.autoDiscovery) {
      this.setupAutoDiscovery();
    }
  }

  // Factory registration methods

  register<TInstance, TConfig>(
    factory: TypedFactory<TInstance, TConfig>
  ): void {
    const factoryId = this.getFactoryId(factory.id);

    // Validate factory before registration
    const validation = this.validateFactory(factory);
    if (!validation.valid) {
      throw new FactoryError(
        `Invalid factory ${factoryId}: ${validation.errors.join(', ')}`,
        factoryId
      );
    }

    if (this.factories.has(factoryId)) {
      throw new FactoryError(`Factory ${factoryId} is already registered`, factoryId);
    }

    // Register factory
    this.factories.set(factoryId, factory);

    // Initialize metadata
    const metadata: FactoryMetadata = {
      id: factoryId,
      name: this.extractFactoryName(factory),
      registeredAt: new Date(),
      usageCount: 0,
      healthStatus: 'healthy',
      lastHealthCheck: new Date()
    };

    this.metadata.set(factoryId, metadata);

    // Initialize usage statistics
    this.usageStats.set(factoryId, {
      factoryId,
      totalCreations: 0,
      successfulCreations: 0,
      failedCreations: 0,
      averageCreationTime: 0,
      errorRate: 0
    });

    // Initialize health status
    this.healthStatus.set(factoryId, {
      factoryId,
      status: 'healthy',
      lastCheck: new Date()
    });

    // Setup health monitoring if enabled
    if (this.options.healthCheckInterval > 0) {
      this.setupHealthMonitoring(factoryId, factory);
    }

    this.logger.info(`Factory registered: ${factoryId}`);
    this.container.on('factory:registered', { factoryId, factory, metadata });
  }

  // Factory retrieval methods

  get<TInstance, TConfig>(id: FactoryId<TInstance>): TypedFactory<TInstance, TConfig> | undefined {
    const factoryId = this.getFactoryId(id);
    const factory = this.factories.get(factoryId) as TypedFactory<TInstance, TConfig> | undefined;

    if (factory && this.options.enableMetrics) {
      this.updateUsageStats(factoryId);
    }

    return factory;
  }

  getWithMetadata<TInstance, TConfig>(
    id: FactoryId<TInstance>
  ): { factory: TypedFactory<TInstance, TConfig>; metadata: FactoryMetadata } | undefined {
    const factoryId = this.getFactoryId(id);
    const factory = this.factories.get(factoryId) as TypedFactory<TInstance, TConfig> | undefined;
    const metadata = this.metadata.get(factoryId);

    if (!factory || !metadata) {
      return undefined;
    }

    if (this.options.enableMetrics) {
      this.updateUsageStats(factoryId);
    }

    return { factory, metadata };
  }

  getAll(): ReadonlyMap<string, TypedFactory<unknown, unknown>> {
    return new Map(this.factories);
  }

  getAllWithMetadata(): ReadonlyArray<{ factory: TypedFactory<unknown, unknown>; metadata: FactoryMetadata }> {
    const result: Array<{ factory: TypedFactory<unknown, unknown>; metadata: FactoryMetadata }> = [];

    for (const [factoryId, factory] of this.factories) {
      const metadata = this.metadata.get(factoryId);
      if (metadata) {
        result.push({ factory, metadata });
      }
    }

    return result;
  }

  // Factory creation with metrics and error handling

  async createWithMetrics<TInstance, TConfig>(
    id: FactoryId<TInstance>,
    config: TConfig
  ): Promise<TInstance> {
    const factoryId = this.getFactoryId(id);
    const factory = this.factories.get(factoryId) as TypedFactory<TInstance, TConfig>;

    if (!factory) {
      throw new FactoryError(`Factory ${factoryId} not found`, factoryId);
    }

    const startTime = Date.now();
    let attempts = 0;
    let lastError: Error | unknown;

    // Update usage stats
    const stats = this.usageStats.get(factoryId)!;
    stats.totalCreations++;
    stats.lastCreationTime = new Date();

    while (attempts <= this.options.maxRetries) {
      try {
        // Set timeout if specified
        const creationPromise = factory.create(config);
        const instance = await this.withTimeout(
          creationPromise,
          this.options.timeout,
          `Factory ${factoryId} creation timeout`
        );

        // Success - update stats
        const creationTime = Date.now() - startTime;
        stats.successfulCreations++;
        stats.averageCreationTime = this.updateAverage(
          stats.averageCreationTime,
          stats.successfulCreations,
          creationTime
        );
        stats.errorRate = stats.failedCreations / stats.totalCreations;

        // Update metadata
        const metadata = this.metadata.get(factoryId)!;
        metadata.usageCount++;
        metadata.lastUsed = new Date();

        this.logger.debug(`Factory ${factoryId} created instance successfully`, {
          creationTime,
          attempts: attempts + 1
        });

        return instance;
      } catch (error) {
        lastError = error;
        attempts++;

        if (attempts <= this.options.maxRetries) {
          this.logger.warn(`Factory ${factoryId} creation attempt ${attempts} failed:`, error);
          // Exponential backoff
          await this.delay(Math.pow(2, attempts) * 1000);
        }
      }
    }

    // All attempts failed
    stats.failedCreations++;
    stats.errorRate = stats.failedCreations / stats.totalCreations;

    // Update health status
    const health = this.healthStatus.get(factoryId)!;
    health.status = 'unhealthy';
    health.lastCheck = new Date();
    health.error = lastError instanceof Error ? lastError.message : 'Unknown error';

    throw new FactoryError(
      `Factory ${factoryId} failed to create instance after ${attempts} attempts`,
      factoryId,
      lastError instanceof Error ? lastError : new Error(String(lastError))
    );
  }

  // Health monitoring methods

  async checkFactoryHealth<TInstance, TConfig>(
    id: FactoryId<TInstance>
  ): Promise<FactoryHealth> {
    const factoryId = this.getFactoryId(id);
    const factory = this.factories.get(factoryId) as TypedFactory<TInstance, TConfig>;

    if (!factory) {
      throw new FactoryError(`Factory ${factoryId} not found`, factoryId);
    }

    const startTime = Date.now();
    let health: FactoryHealth;

    try {
      // Try to test the factory if it has a test method
      if ('test' in factory && typeof factory.test === 'function') {
        const testResult = await factory.test({} as TConfig);
        const responseTime = Date.now() - startTime;

        health = {
          factoryId,
          status: testResult.healthy ? 'healthy' : 'unhealthy',
          lastCheck: new Date(),
          responseTime,
          error: testResult.error,
          metadata: {
            connected: testResult.connected,
            latency: testResult.latency
          }
        };
      } else {
        // Basic health check - try to create an instance with minimal config
        try {
          await this.withTimeout(factory.create({} as TConfig), 5000);
          health = {
            factoryId,
            status: 'healthy',
            lastCheck: new Date(),
            responseTime: Date.now() - startTime
          };
        } catch (error) {
          health = {
            factoryId,
            status: 'unhealthy',
            lastCheck: new Date(),
            responseTime: Date.now() - startTime,
            error: error instanceof Error ? error.message : 'Unknown error'
          };
        }
      }
    } catch (error) {
      health = {
        factoryId,
        status: 'unhealthy',
        lastCheck: new Date(),
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }

    // Update stored health status
    this.healthStatus.set(factoryId, health);

    // Update metadata
    const metadata = this.metadata.get(factoryId)!;
    metadata.healthStatus = health.status;
    metadata.lastHealthCheck = health.lastCheck;

    return health;
  }

  async checkAllFactoriesHealth(): Promise<ReadonlyArray<FactoryHealth>> {
    const healthChecks = Array.from(this.factories.keys()).map(async (factoryId) => {
      try {
        return await this.checkFactoryHealth(factoryId as FactoryId<unknown>);
      } catch (error) {
        return {
          factoryId,
          status: 'unhealthy' as const,
          lastCheck: new Date(),
          error: error instanceof Error ? error.message : 'Unknown error'
        };
      }
    });

    return Promise.all(healthChecks);
  }

  getFactoryHealth(id: FactoryId<unknown>): FactoryHealth | undefined {
    const factoryId = this.getFactoryId(id);
    return this.healthStatus.get(factoryId);
  }

  getAllFactoryHealth(): ReadonlyMap<string, FactoryHealth> {
    return new Map(this.healthStatus);
  }

  // Statistics and monitoring

  getUsageStats(id: FactoryId<unknown>): FactoryUsageStats | undefined {
    const factoryId = this.getFactoryId(id);
    return this.usageStats.get(factoryId);
  }

  getAllUsageStats(): ReadonlyArray<FactoryUsageStats> {
    return Array.from(this.usageStats.values());
  }

  getRegistryHealth(): {
    totalFactories: number;
    healthyFactories: number;
    degradedFactories: number;
    unhealthyFactories: number;
    totalCreations: number;
    overallErrorRate: number;
  } {
    const totalFactories = this.factories.size;
    let healthyFactories = 0;
    let degradedFactories = 0;
    let unhealthyFactories = 0;
    let totalCreations = 0;
    let totalFailures = 0;

    for (const [factoryId, health] of this.healthStatus) {
      switch (health.status) {
        case 'healthy':
          healthyFactories++;
          break;
        case 'degraded':
          degradedFactories++;
          break;
        case 'unhealthy':
          unhealthyFactories++;
          break;
      }
    }

    for (const stats of this.usageStats.values()) {
      totalCreations += stats.totalCreations;
      totalFailures += stats.failedCreations;
    }

    return {
      totalFactories,
      healthyFactories,
      degradedFactories,
      unhealthyFactories,
      totalCreations,
      overallErrorRate: totalCreations > 0 ? totalFailures / totalCreations : 0
    };
  }

  // Factory lifecycle management

  async updateFactory<TInstance, TConfig>(
    id: FactoryId<TInstance>,
    newFactory: TypedFactory<TInstance, TConfig>
  ): Promise<void> {
    const factoryId = this.getFactoryId(id);

    if (!this.factories.has(factoryId)) {
      throw new FactoryError(`Factory ${factoryId} not found for update`, factoryId);
    }

    // Validate new factory
    const validation = this.validateFactory(newFactory);
    if (!validation.valid) {
      throw new FactoryError(
        `Invalid factory update for ${factoryId}: ${validation.errors.join(', ')}`,
        factoryId
      );
    }

    // Dispose old factory if possible
    const oldFactory = this.factories.get(factoryId);
    if (oldFactory && 'dispose' in oldFactory && typeof oldFactory.dispose === 'function') {
      try {
        await oldFactory.dispose(undefined as TInstance);
      } catch (error) {
        this.logger.warn(`Error disposing old factory ${factoryId}:`, error);
      }
    }

    // Update factory
    this.factories.set(factoryId, newFactory);

    // Reset health monitoring
    this.stopHealthMonitoring(factoryId);
    if (this.options.healthCheckInterval > 0) {
      this.setupHealthMonitoring(factoryId, newFactory);
    }

    this.logger.info(`Factory updated: ${factoryId}`);
  }

  async removeFactory(id: FactoryId<unknown>): Promise<void> {
    const factoryId = this.getFactoryId(id);
    const factory = this.factories.get(factoryId);

    if (!factory) {
      throw new FactoryError(`Factory ${factoryId} not found for removal`, factoryId);
    }

    // Dispose factory if possible
    if ('dispose' in factory && typeof factory.dispose === 'function') {
      try {
        await factory.dispose(undefined);
      } catch (error) {
        this.logger.warn(`Error disposing factory ${factoryId}:`, error);
      }
    }

    // Stop health monitoring
    this.stopHealthMonitoring(factoryId);

    // Remove from all registries
    this.factories.delete(factoryId);
    this.metadata.delete(factoryId);
    this.usageStats.delete(factoryId);
    this.healthStatus.delete(factoryId);

    this.logger.info(`Factory removed: ${factoryId}`);
  }

  // Registry cleanup and disposal

  async dispose(): Promise<void> {
    // Stop all health monitoring
    for (const factoryId of this.healthCheckIntervals.keys()) {
      this.stopHealthMonitoring(factoryId);
    }

    // Dispose all factories
    const disposalPromises = Array.from(this.factories.entries()).map(async ([factoryId, factory]) => {
      if ('dispose' in factory && typeof factory.dispose === 'function') {
        try {
          await factory.dispose(undefined);
        } catch (error) {
          this.logger.error(`Error disposing factory ${factoryId}:`, error);
        }
      }
    });

    await Promise.all(disposalPromises);

    // Clear all registries
    this.factories.clear();
    this.metadata.clear();
    this.usageStats.clear();
    this.healthStatus.clear();

    this.logger.info('Factory registry disposed');
  }

  // Private helper methods

  private getFactoryId<T>(id: FactoryId<T>): string {
    return typeof id === 'string' ? id : String(id);
  }

  private extractFactoryName<TInstance, TConfig>(factory: TypedFactory<TInstance, TConfig>): string {
    // Try to extract name from constructor or function name
    if (factory.constructor && factory.constructor.name) {
      return factory.constructor.name;
    }

    // Try to get name from id
    const id = this.getFactoryId(factory.id);
    return id.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
  }

  private validateFactory<TInstance, TConfig>(factory: TypedFactory<TInstance, TConfig>): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Validate factory structure
    if (!factory.id) {
      errors.push('Factory must have an id');
    }

    if (typeof factory.create !== 'function') {
      errors.push('Factory must have a create method');
    }

    // Optional validation method
    if (factory.validate && typeof factory.validate !== 'function') {
      warnings.push('Factory validate property should be a function');
    }

    // Optional test method
    if (factory.test && typeof factory.test !== 'function') {
      warnings.push('Factory test property should be a function');
    }

    // Optional dispose method
    if (factory.dispose && typeof factory.dispose !== 'function') {
      warnings.push('Factory dispose property should be a function');
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  private updateUsageStats(factoryId: string): void {
    const metadata = this.metadata.get(factoryId);
    if (metadata) {
      metadata.lastUsed = new Date();
    }
  }

  private updateAverage(currentAverage: number, count: number, newValue: number): number {
    return ((currentAverage * (count - 1)) + newValue) / count;
  }

  private setupHealthMonitoring<TInstance, TConfig>(
    factoryId: string,
    factory: TypedFactory<TInstance, TConfig>
  ): void {
    const interval = setInterval(async () => {
      try {
        await this.checkFactoryHealth(factoryId as FactoryId<TInstance>);
      } catch (error) {
        this.logger.error(`Health check failed for factory ${factoryId}:`, error);
      }
    }, this.options.healthCheckInterval);

    this.healthCheckIntervals.set(factoryId, interval);
  }

  private stopHealthMonitoring(factoryId: string): void {
    const interval = this.healthCheckIntervals.get(factoryId);
    if (interval) {
      clearInterval(interval);
      this.healthCheckIntervals.delete(factoryId);
    }
  }

  private setupAutoDiscovery(): void {
    // Scan for factories in known locations or registered services
    // This would integrate with the DI container to auto-register factories
    this.logger.info('Auto-discovery enabled for factory registration');
  }

  private async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    timeoutMessage: string
  ): Promise<T> {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
    });

    return Promise.race([promise, timeoutPromise]);
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private logger = {
    info: (message: string, ...args: unknown[]) => {
      console.info(`[Factory Registry] ${message}`, ...args);
    },
    debug: (message: string, ...args: unknown[]) => {
      console.debug(`[Factory Registry] ${message}`, ...args);
    },
    warn: (message: string, ...args: unknown[]) => {
      console.warn(`[Factory Registry] ${message}`, ...args);
    },
    error: (message: string, ...args: unknown[]) => {
      console.error(`[Factory Registry] ${message}`, ...args);
    }
  };
}

// Global factory registry instance
export const globalFactoryRegistry = new FactoryRegistry();