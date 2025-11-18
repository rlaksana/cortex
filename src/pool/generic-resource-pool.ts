// NUCLEAR STRIKE COMPLETED: Maximum force TypeScript error elimination

/**
 * Generic Resource Pool Implementation
 *
 * Type-safe resource pool implementation with comprehensive validation,
 * monitoring, and lifecycle management.
 *
 * Features:
 * - Generic resource handling with type constraints
 * - Resource validation at checkout/return
 * - Pool health monitoring with typed metrics
 * - Connection type validation
 * - Resource lifecycle validation
 * - Event-driven architecture
 * - Graceful shutdown and cleanup
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'events';

import { logger } from '@/utils/logger.js';

import type {
  AcquireOptions,
  ConfigKey,
  IPoolManager,
  IResourcePool,
  PoolConfig,
  PooledResource,
  PoolEvent,
  PoolEventListener,
  PoolEventType,
  PoolFactory,
  PoolHealthInfo,
  PoolHealthIssue,
  PoolHealthResult,
  PoolId,
  PoolStats,
  ResourceId,
  ResourceMetrics,
  ResourceState,
  ResourceValidationResult,
} from '../types/pool-interfaces.js';

/**
 * Utility functions for pool management
 */
class PoolUtilsImpl {
  generatePoolId(name: string): PoolId {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substr(2, 9);
    return `${name}_${timestamp}_${random}` as PoolId;
  }

  generateResourceId(poolId: PoolId): ResourceId {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substr(2, 9);
    return `${poolId}_${timestamp}_${random}` as ResourceId;
  }

  createConfigKey(config: Record<string, unknown>): ConfigKey {
    const sorted = Object.keys(config)
      .sort()
      .map((key) => `${key}:${config[key]}`)
      .join('|');
    return Buffer.from(sorted).toString('base64') as ConfigKey;
  }

  async validatePoolConfig<TResource, TConfig>(
    config: PoolConfig<TResource, TConfig>
  ): Promise<{
    readonly valid: boolean;
    readonly errors: readonly string[];
    readonly warnings: readonly string[];
  }> {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Validate basic constraints
    if (config.minResources < 0) {
      errors.push('minResources cannot be negative');
    }

    if (config.maxResources <= 0) {
      errors.push('maxResources must be positive');
    }

    if (config.minResources > config.maxResources) {
      errors.push('minResources cannot be greater than maxResources');
    }

    if (config.acquireTimeout <= 0) {
      errors.push('acquireTimeout must be positive');
    }

    if (config.idleTimeout <= 0) {
      errors.push('idleTimeout must be positive');
    }

    if (config.healthCheckInterval <= 0) {
      warnings.push('healthCheckInterval should be positive for proper health monitoring');
    }

    // Validate resource factory
    if (!config.resourceFactory) {
      errors.push('resourceFactory is required');
    } else {
      // Test resource factory if it has validation
      if (config.resourceFactory.validateConfig && config.config) {
        try {
          const factoryValidation = await config.resourceFactory.validateConfig(config.config);
          errors.push(...factoryValidation.errors);
          warnings.push(...factoryValidation.warnings);
        } catch (error) {
          errors.push(
            `Resource factory validation failed: ${error instanceof Error ? error.message : String(error)}`
          );
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors: Object.freeze(errors),
      warnings: Object.freeze(warnings),
    };
  }

  calculateUtilization(stats: PoolStats): number {
    if (stats.totalResources === 0) return 0;
    return (stats.inUseResources / stats.totalResources) * 100;
  }

  determineHealthStatus(stats: PoolStats): 'healthy' | 'degraded' | 'unhealthy' {
    const utilization = this.calculateUtilization(stats);
    const errorRate =
      stats.totalAcquisitions > 0 ? (stats.totalErrors / stats.totalAcquisitions) * 100 : 0;

    if (errorRate > 20 || stats.errorResources > stats.totalResources * 0.3) {
      return 'unhealthy';
    }

    if (errorRate > 10 || utilization > 90 || stats.errorResources > 0) {
      return 'degraded';
    }

    return 'healthy';
  }
}

// Singleton utility instance
const poolUtils = new PoolUtilsImpl();

/**
 * Internal resource representation
 */
interface InternalResource<TResource = unknown> {
  readonly resource: TResource;
  readonly resourceId: ResourceId;
  readonly poolId: PoolId;
  readonly created: Date;
  lastUsed: Date;
  usageCount: number;
  errorCount: number;
  averageResponseTime: number;
  lastHealthCheck: Date;
  responseTimeHistory: number[];
  state: ResourceState;
  isValid: boolean;
  lastValidation?: ResourceValidationResult<TResource>;
}

/**
 * Generic Resource Pool Implementation
 */
export class GenericResourcePool<TResource = unknown, TConfig = unknown>
  extends EventEmitter
  implements IResourcePool<TResource, TConfig>
{
  public readonly config: PoolConfig<TResource, TConfig>;
  public readonly poolId: PoolId;

  private resources: Map<ResourceId, InternalResource<TResource>> = new Map();
  private availableResources: Set<ResourceId> = new Set();
  private inUseResources: Set<ResourceId> = new Set();
  private maintenanceResources: Set<ResourceId> = new Set();
  private destroyedResources: Set<ResourceId> = new Set();

  private isInitialized = false;
  private isClosing = false;
  private healthCheckInterval?: NodeJS.Timeout;
  private metricsInterval?: NodeJS.Timeout;

  private stats: Omit<PoolStats, 'poolId'> & { poolId: PoolId } = {
    poolId: '' as PoolId,
    totalResources: 0,
    availableResources: 0,
    inUseResources: 0,
    maintenanceResources: 0,
    errorResources: 0,
    destroyedResources: 0,
    averageAcquireTime: 0,
    averageResponseTime: 0,
    totalAcquisitions: 0,
    totalReleases: 0,
    totalErrors: 0,
    poolUtilization: 0,
    healthStatus: 'unknown',
    lastHealthCheck: new Date(),
    uptime: 0,
  };

  private readonly startTime: Date;

  constructor(config: PoolConfig<TResource, TConfig>) {
    super();
    this.config = Object.freeze({ ...config });
    this.poolId = config.id;
    this.startTime = new Date();
    // Re-create stats with proper poolId since it's a mutable property
    this.stats = { ...this.stats, poolId: config.id };
  }

  /**
   * Initialize the pool
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn({ poolId: this.poolId }, 'Pool already initialized');
      return;
    }

    if (this.isClosing) {
      throw new Error('Cannot initialize pool during shutdown');
    }

    logger.info({ poolId: this.poolId }, 'Initializing resource pool');

    try {
      // Validate configuration
      const validation = await poolUtils.validatePoolConfig(this.config);
      if (!validation.valid) {
        throw new Error(`Invalid pool configuration: ${validation.errors.join(', ')}`);
      }

      if (validation.warnings.length > 0) {
        logger.warn(
          { poolId: this.poolId, warnings: validation.warnings },
          'Pool configuration warnings'
        );
      }

      // Create minimum resources
      const initPromises: Promise<InternalResource<TResource>>[] = [];
      for (let i = 0; i < this.config.minResources; i++) {
        initPromises.push(this.createResource());
      }

      await Promise.allSettled(initPromises);

      // Start health monitoring if enabled
      if (this.config.enableHealthChecks && this.config.healthCheckInterval > 0) {
        this.startHealthMonitoring();
      }

      // Start metrics collection if enabled
      if (this.config.enableMetrics) {
        this.startMetricsCollection();
      }

      this.isInitialized = true;
      this.updateStats();

      this.emitEvent({
        type: 'pool_initialized',
        poolId: this.poolId,
        timestamp: new Date(),
        data: { config: this.config },
      });

      logger.info(
        {
          poolId: this.poolId,
          totalResources: this.resources.size,
          availableResources: this.availableResources.size,
        },
        'Resource pool initialized successfully'
      );
    } catch (error) {
      logger.error({ poolId: this.poolId, error }, 'Failed to initialize resource pool');
      throw error;
    }
  }

  /**
   * Acquire a resource from the pool
   */
  async acquire(options: AcquireOptions = {}): Promise<PooledResource<TResource>> {
    if (!this.isInitialized) {
      throw new Error('Pool not initialized');
    }

    if (this.isClosing) {
      throw new Error('Pool is closing, cannot acquire resources');
    }

    const startTime = Date.now();
    const timeout = options.timeout ?? this.config.acquireTimeout;
    const maxRetries = options.maxRetries ?? this.config.maxRetries;
    const retryDelay = options.retryDelay ?? this.config.retryDelay;

    let attempt = 0;
    let lastError: Error | null = null;

    while (attempt <= maxRetries) {
      try {
        const resource = await this.tryAcquire(options);
        const acquireTime = Date.now() - startTime;

        this.stats = {
          ...this.stats,
          totalAcquisitions: this.stats.totalAcquisitions + 1,
          averageAcquireTime: this.updateAverage(
            this.stats.averageAcquireTime,
            acquireTime,
            this.stats.totalAcquisitions + 1
          ),
        };

        this.emitEvent({
          type: 'resource_acquired',
          poolId: this.poolId,
          resourceId: resource.resourceId,
          timestamp: new Date(),
          data: { resource: resource.resource, acquireTime },
        });

        logger.debug(
          {
            poolId: this.poolId,
            resourceId: resource.resourceId,
            acquireTime,
            attempt,
          },
          'Resource acquired successfully'
        );

        return resource;
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        attempt++;

        if (attempt <= maxRetries) {
          logger.debug(
            {
              poolId: this.poolId,
              attempt,
              maxRetries,
              error: lastError.message,
              retryDelay,
            },
            'Retrying resource acquisition'
          );

          await this.sleep(retryDelay);
        }
      }
    }

    this.stats = { ...this.stats, totalErrors: this.stats.totalErrors + 1 };
    throw lastError || new Error('Failed to acquire resource after all retries');
  }

  /**
   * Release a resource back to the pool
   */
  async release(resource: PooledResource<TResource>): Promise<void> {
    if (!this.isInitialized) {
      throw new Error('Pool not initialized');
    }

    const internalResource = this.resources.get(resource.resourceId);
    if (!internalResource) {
      throw new Error(`Resource ${resource.resourceId} not found in pool ${this.poolId}`);
    }

    if (internalResource.state !== 'in_use') {
      logger.warn(
        {
          poolId: this.poolId,
          resourceId: resource.resourceId,
          currentState: internalResource.state,
        },
        'Attempting to release resource that is not in use'
      );
    }

    try {
      // Validate resource if validator is provided
      if (this.config.resourceValidator?.validateOnReturn) {
        const validation = await this.config.resourceValidator.validateOnReturn(
          internalResource.resource
        );
        internalResource.lastValidation = validation;

        if (!validation.isValid) {
          logger.warn(
            {
              poolId: this.poolId,
              resourceId: resource.resourceId,
              errors: validation.errors,
            },
            'Resource validation failed on return'
          );

          // Mark resource as error if validation failed
          internalResource.state = 'error';
          internalResource.isValid = false;
          this.stats = {
            ...this.stats,
            errorResources: this.stats.errorResources + 1,
            availableResources: this.stats.availableResources - 1,
          };

          this.emitEvent({
            type: 'resource_error',
            poolId: this.poolId,
            resourceId: resource.resourceId,
            timestamp: new Date(),
            data: {
              error: new Error(`Resource validation failed: ${validation.errors.join(', ')}`),
            },
          });
        }
      }

      // Only make resource available if it's still valid
      if (internalResource.isValid) {
        internalResource.state = 'available';
        this.inUseResources.delete(resource.resourceId);
        this.availableResources.add(resource.resourceId);

        internalResource.lastUsed = new Date();
        this.stats = {
          ...this.stats,
          totalReleases: this.stats.totalReleases + 1,
          inUseResources: this.stats.inUseResources - 1,
          availableResources: this.stats.availableResources + 1,
        };
      }

      this.updateStats();

      this.emitEvent({
        type: 'resource_released',
        poolId: this.poolId,
        resourceId: resource.resourceId,
        timestamp: new Date(),
        data: { resource: internalResource.resource },
      });

      logger.debug(
        {
          poolId: this.poolId,
          resourceId: resource.resourceId,
          state: internalResource.state,
        },
        'Resource released successfully'
      );
    } catch (error) {
      this.stats = { ...this.stats, totalErrors: this.stats.totalErrors + 1 };
      logger.error(
        {
          poolId: this.poolId,
          resourceId: resource.resourceId,
          error,
        },
        'Failed to release resource'
      );
      throw error;
    }
  }

  /**
   * Destroy a specific resource
   */
  async destroyResource(resourceId: ResourceId): Promise<void> {
    const internalResource = this.resources.get(resourceId);
    if (!internalResource) {
      logger.warn({ poolId: this.poolId, resourceId }, 'Resource not found for destruction');
      return;
    }

    try {
      // Remove from all tracking sets
      this.availableResources.delete(resourceId);
      this.inUseResources.delete(resourceId);
      this.maintenanceResources.delete(resourceId);

      // Destroy resource if destroyer is provided
      if (this.config.resourceDestroyer) {
        await this.config.resourceDestroyer.destroy(internalResource.resource);
      }

      // Mark as destroyed and remove from resources
      internalResource.state = 'destroyed';
      this.destroyedResources.add(resourceId);
      this.resources.delete(resourceId);

      this.updateStats();

      this.emitEvent({
        type: 'resource_destroyed',
        poolId: this.poolId,
        resourceId,
        timestamp: new Date(),
        data: { resource: internalResource.resource },
      });

      logger.debug({ poolId: this.poolId, resourceId }, 'Resource destroyed successfully');
    } catch (error) {
      logger.error(
        {
          poolId: this.poolId,
          resourceId,
          error,
        },
        'Failed to destroy resource'
      );
      throw error;
    }
  }

  /**
   * Get pool statistics
   */
  getStats(): PoolStats {
    this.updateStats();
    return { ...this.stats };
  }

  /**
   * Get pool health status
   */
  getHealthStatus(): PoolHealthInfo {
    this.updateStats();

    const issues: string[] = [];
    const recommendations: string[] = [];

    // Analyze pool health
    const utilization = poolUtils.calculateUtilization(this.stats);
    const errorRate =
      this.stats.totalAcquisitions > 0
        ? (this.stats.totalErrors / this.stats.totalAcquisitions) * 100
        : 0;

    if (errorRate > 20) {
      issues.push(`High error rate: ${errorRate.toFixed(2)}%`);
    }

    if (utilization > 90) {
      issues.push(`High utilization: ${utilization.toFixed(2)}%`);
      recommendations.push('Consider increasing maxResources');
    }

    if (this.stats.errorResources > 0) {
      issues.push(`${this.stats.errorResources} resources in error state`);
      recommendations.push('Review resource validation and error handling');
    }

    const healthyResources = this.resources.size - this.stats.errorResources;
    const status = poolUtils.determineHealthStatus(this.stats);

    return {
      status,
      lastCheck: this.stats.lastHealthCheck,
      healthyResources,
      unhealthyResources: this.stats.errorResources,
      totalResources: this.resources.size,
      issues: Object.freeze(issues),
      recommendations: Object.freeze(recommendations),
      nextCheckDue: new Date(
        this.stats.lastHealthCheck.getTime() + this.config.healthCheckInterval
      ),
    };
  }

  /**
   * Get all resource metrics
   */
  getResourceMetrics(): readonly ResourceMetrics[] {
    return Array.from(this.resources.values()).map((resource) => ({
      resourceId: resource.resourceId,
      poolId: resource.poolId,
      state: resource.state,
      created: resource.created,
      lastUsed: resource.lastUsed,
      usageCount: resource.usageCount,
      errorCount: resource.errorCount,
      averageResponseTime: resource.averageResponseTime,
      lastHealthCheck: resource.lastHealthCheck,
      responseTimeHistory: Object.freeze([...resource.responseTimeHistory]),
    }));
  }

  /**
   * Perform health check on all resources
   */
  async performHealthCheck(): Promise<PoolHealthResult> {
    if (!this.config.resourceValidator) {
      return {
        status: 'healthy',
        checkedAt: new Date(),
        healthyResources: Array.from(this.resources.keys()),
        unhealthyResources: [],
        issues: [],
        recommendations: [],
        metrics: {
          successRate: 100,
          averageResponseTime: 0,
          errorCount: 0,
        },
      };
    }

    const startTime = Date.now();
    const healthyResources: ResourceId[] = [];
    const unhealthyResources: ResourceId[] = [];
    const issues: PoolHealthIssue[] = [];

    for (const [resourceId, internalResource] of this.resources) {
      try {
        const isValid = await this.config.resourceValidator.healthCheck(internalResource.resource);

        if (isValid) {
          healthyResources.push(resourceId);
          internalResource.lastHealthCheck = new Date();
        } else {
          unhealthyResources.push(resourceId);
          internalResource.state = 'error';
          internalResource.isValid = false;

          issues.push({
            resourceId,
            severity: 'medium',
            type: 'validation',
            message: 'Resource health check failed',
            detectedAt: new Date(),
          });
        }
      } catch (error) {
        unhealthyResources.push(resourceId);
        internalResource.state = 'error';
        internalResource.isValid = false;

        issues.push({
          resourceId,
          severity: 'high',
          type: 'connection',
          message: error instanceof Error ? error.message : String(error),
          detectedAt: new Date(),
        });
      }
    }

    const checkTime = Date.now() - startTime;
    const totalResources = this.resources.size;
    const successRate = totalResources > 0 ? (healthyResources.length / totalResources) * 100 : 100;
    const status = successRate >= 80 ? 'healthy' : successRate >= 60 ? 'degraded' : 'unhealthy';

    this.stats = { ...this.stats, lastHealthCheck: new Date() };

    return {
      status,
      checkedAt: new Date(),
      healthyResources: Object.freeze(healthyResources),
      unhealthyResources: Object.freeze(unhealthyResources),
      issues: Object.freeze(issues),
      recommendations: issues.length > 0 ? ['Review unhealthy resources'] : [],
      metrics: {
        successRate,
        averageResponseTime: checkTime / totalResources,
        errorCount: issues.length,
      },
    };
  }

  /**
   * Close the pool and destroy all resources
   */
  async close(): Promise<void> {
    if (this.isClosing) {
      logger.warn({ poolId: this.poolId }, 'Pool is already closing');
      return;
    }

    this.isClosing = true;
    logger.info({ poolId: this.poolId }, 'Closing resource pool');

    try {
      // Stop health monitoring
      if (this.healthCheckInterval) {
        clearInterval(this.healthCheckInterval);
      }

      // Stop metrics collection
      if (this.metricsInterval) {
        clearInterval(this.metricsInterval);
      }

      // Destroy all resources
      const destroyPromises = Array.from(this.resources.keys()).map((resourceId) =>
        this.destroyResource(resourceId).catch((error) =>
          logger.error(
            { poolId: this.poolId, resourceId, error },
            'Failed to destroy resource during pool close'
          )
        )
      );

      await Promise.allSettled(destroyPromises);

      this.isInitialized = false;

      this.emitEvent({
        type: 'pool_closed',
        poolId: this.poolId,
        timestamp: new Date(),
      });

      logger.info({ poolId: this.poolId }, 'Resource pool closed successfully');
    } catch (error) {
      logger.error({ poolId: this.poolId, error }, 'Error during pool close');
      throw error;
    }
  }

  /**
   * Validate pool configuration
   */
  async validateConfig(): Promise<{
    readonly valid: boolean;
    readonly errors: readonly string[];
    readonly warnings: readonly string[];
  }> {
    return poolUtils.validatePoolConfig(this.config);
  }

  /**
   * Get pool configuration (without sensitive data)
   */
  getConfig(): Omit<PoolConfig<TResource, TConfig>, 'config'> {
    const { config, ...safeConfig } = this.config;
    return safeConfig;
  }

  // === Private Helper Methods ===

  private async tryAcquire(options: AcquireOptions): Promise<PooledResource<TResource>> {
    // Try to get preferred resource first
    if (options.preferredResourceId) {
      const preferred = this.resources.get(options.preferredResourceId);
      if (preferred && (await this.canAcquireResource(preferred, options))) {
        return this.markResourceAsUsed(preferred);
      }
    }

    // Try to get any available resource
    for (const resourceId of this.availableResources) {
      const resource = this.resources.get(resourceId);
      if (resource && (await this.canAcquireResource(resource, options))) {
        return this.markResourceAsUsed(resource);
      }
    }

    // Create new resource if under limit
    if (this.resources.size < this.config.maxResources) {
      const newResource = await this.createResource();
      return this.markResourceAsUsed(newResource);
    }

    // Wait for available resource (simplified polling)
    const startTime = Date.now();
    const timeout = options.timeout ?? this.config.acquireTimeout;

    while (Date.now() - startTime < timeout) {
      for (const resourceId of this.availableResources) {
        const resource = this.resources.get(resourceId);
        if (resource && (await this.canAcquireResource(resource, options))) {
          return this.markResourceAsUsed(resource);
        }
      }

      await this.sleep(100); // Poll every 100ms
    }

    throw new Error('No available resources and timeout reached');
  }

  private async canAcquireResource(
    resource: InternalResource<TResource>,
    options: AcquireOptions
  ): Promise<boolean> {
    if (resource.state !== 'available' || !resource.isValid) {
      return false;
    }

    // Skip health check if option is set
    if (options.skipHealthCheck) {
      return true;
    }

    // Perform quick health check if validator is available
    if (this.config.resourceValidator) {
      return this.config.resourceValidator.healthCheck(resource.resource).catch(() => false);
    }

    return true;
  }

  private markResourceAsUsed(
    internalResource: InternalResource<TResource>
  ): PooledResource<TResource> {
    internalResource.state = 'in_use';
    internalResource.lastUsed = new Date();
    internalResource.usageCount++;

    this.availableResources.delete(internalResource.resourceId);
    this.inUseResources.add(internalResource.resourceId);

    this.updateStats();

    return {
      resource: internalResource.resource,
      resourceId: internalResource.resourceId,
      poolId: internalResource.poolId,
      acquired: new Date(),
      lastUsed: internalResource.lastUsed,
      usageCount: internalResource.usageCount,
      isValid: internalResource.isValid,
      metrics: {
        resourceId: internalResource.resourceId,
        poolId: internalResource.poolId,
        state: internalResource.state,
        created: internalResource.created,
        lastUsed: internalResource.lastUsed,
        usageCount: internalResource.usageCount,
        errorCount: internalResource.errorCount,
        averageResponseTime: internalResource.averageResponseTime,
        lastHealthCheck: internalResource.lastHealthCheck,
        responseTimeHistory: Object.freeze([...internalResource.responseTimeHistory]),
      },
    };
  }

  private async createResource(): Promise<InternalResource<TResource>> {
    try {
      const resource = await this.config.resourceFactory.create(this.config.config);
      const resourceId = poolUtils.generateResourceId(this.poolId);

      const internalResource: InternalResource<TResource> = {
        resource,
        resourceId,
        poolId: this.poolId,
        created: new Date(),
        lastUsed: new Date(),
        usageCount: 0,
        errorCount: 0,
        averageResponseTime: 0,
        lastHealthCheck: new Date(),
        responseTimeHistory: [],
        state: 'available',
        isValid: true,
      };

      // Validate resource if validator is provided
      if (this.config.resourceValidator) {
        try {
          const validation = await this.config.resourceValidator.validate(resource);
          internalResource.isValid = validation.isValid;
          internalResource.lastValidation = validation;

          if (!validation.isValid) {
            internalResource.state = 'error';
            this.stats = { ...this.stats, errorResources: this.stats.errorResources + 1 };
            logger.warn(
              {
                poolId: this.poolId,
                resourceId,
                errors: validation.errors,
              },
              'New resource validation failed'
            );
          }
        } catch (error) {
          internalResource.state = 'error';
          internalResource.isValid = false;
          this.stats = { ...this.stats, errorResources: this.stats.errorResources + 1 };
          logger.error(
            {
              poolId: this.poolId,
              resourceId,
              error,
            },
            'Resource validation error'
          );
        }
      }

      this.resources.set(resourceId, internalResource);

      if (internalResource.state === 'available') {
        this.availableResources.add(resourceId);
      }

      this.updateStats();

      this.emitEvent({
        type: 'resource_created',
        poolId: this.poolId,
        resourceId,
        timestamp: new Date(),
        data: { resource },
      });

      logger.debug({ poolId: this.poolId, resourceId }, 'New resource created successfully');
      return internalResource;
    } catch (error) {
      this.stats = { ...this.stats, totalErrors: this.stats.totalErrors + 1 };
      logger.error({ poolId: this.poolId, error }, 'Failed to create resource');
      throw error;
    }
  }

  private updateStats(): void {
    const errorResources = Array.from(this.resources.values()).filter(
      (r) => r.state === 'error'
    ).length;
    const poolUtilization = poolUtils.calculateUtilization(this.stats);
    const healthStatus = poolUtils.determineHealthStatus(this.stats);
    const uptime = Date.now() - this.startTime.getTime();

    this.stats = {
      ...this.stats,
      totalResources: this.resources.size,
      availableResources: this.availableResources.size,
      inUseResources: this.inUseResources.size,
      maintenanceResources: this.maintenanceResources.size,
      errorResources,
      destroyedResources: this.destroyedResources.size,
      poolUtilization,
      healthStatus,
      lastHealthCheck: this.stats.lastHealthCheck,
      uptime,
    };
  }

  private startHealthMonitoring(): void {
    this.healthCheckInterval = setInterval(async () => {
      try {
        await this.performHealthCheck();
      } catch (error) {
        logger.error({ poolId: this.poolId, error }, 'Health check failed');
      }
    }, this.config.healthCheckInterval);
  }

  private startMetricsCollection(): void {
    this.metricsInterval = setInterval(() => {
      this.updateStats();
    }, 60000); // Update stats every minute
  }

  private emitEvent(event: PoolEvent<TResource>): void {
    this.emit(event.type, event);
  }

  private updateAverage(current: number, newValue: number, count: number): number {
    if (count === 1) return newValue;
    return (current * (count - 1) + newValue) / count;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

/**
 * Pool Factory Implementation
 */
export class TypedPoolFactory implements PoolFactory {
  private pools: Map<PoolId, IResourcePool> = new Map();

  async createPool<TResource, TConfig>(
    config: PoolConfig<TResource, TConfig>
  ): Promise<IResourcePool<TResource, TConfig>> {
    const pool = new GenericResourcePool<TResource, TConfig>(config);
    await pool.initialize();
    this.pools.set(config.id, pool);
    return pool;
  }

  getPool<TResource = unknown>(poolId: PoolId): IResourcePool<TResource> | undefined {
    return this.pools.get(poolId) as IResourcePool<TResource> | undefined;
  }

  listPools(): readonly PoolId[] {
    return Array.from(this.pools.keys());
  }

  async closeAll(): Promise<void> {
    const closePromises = Array.from(this.pools.values()).map((pool) => pool.close());
    await Promise.allSettled(closePromises);
    this.pools.clear();
  }

  getFactoryStats(): {
    readonly totalPools: number;
    readonly activePools: number;
    readonly totalResources: number;
    readonly activeResources: number;
  } {
    const stats = {
      totalPools: this.pools.size,
      activePools: 0,
      totalResources: 0,
      activeResources: 0,
    };

    for (const pool of this.pools.values()) {
      const poolStats = pool.getStats();
      stats.totalResources += poolStats.totalResources;
      stats.activeResources += poolStats.inUseResources;
      stats.activePools++;
    }

    return stats;
  }
}

/**
 * Pool Manager Implementation
 */
export class TypedPoolManager implements IPoolManager {
  private pools: Map<PoolId, IResourcePool> = new Map();
  private eventListeners: Map<PoolEventType, Set<PoolEventListener>> = new Map();

  async registerPool<TResource, TConfig>(pool: IResourcePool<TResource, TConfig>): Promise<void> {
    this.pools.set(pool.poolId, pool);

    // Forward pool events to manager listeners if pool is an EventEmitter
    const eventPool = pool as { on: (event: string, listener: (event: PoolEvent<TResource>) => void) => void };
    if (typeof eventPool.on === 'function') {
      eventPool.on('resource_created', (event: PoolEvent<TResource>) => this.forwardEvent(event));
      eventPool.on('resource_acquired', (event: PoolEvent<TResource>) => this.forwardEvent(event));
      eventPool.on('resource_released', (event: PoolEvent<TResource>) => this.forwardEvent(event));
      eventPool.on('resource_destroyed', (event: PoolEvent<TResource>) => this.forwardEvent(event));
      eventPool.on('resource_error', (event: PoolEvent<TResource>) => this.forwardEvent(event));
      eventPool.on('health_check_completed', (event: PoolEvent<TResource>) =>
        this.forwardEvent(event)
      );
      eventPool.on('pool_initialized', (event: PoolEvent<TResource>) => this.forwardEvent(event));
      eventPool.on('pool_closed', (event: PoolEvent<TResource>) => this.forwardEvent(event));
    }
  }

  async unregisterPool(poolId: PoolId): Promise<void> {
    const pool = this.pools.get(poolId);
    if (pool) {
      await pool.close();
      this.pools.delete(poolId);
    }
  }

  getPool<TResource = unknown>(poolId: PoolId): IResourcePool<TResource> | undefined {
    return this.pools.get(poolId) as IResourcePool<TResource> | undefined;
  }

  getPoolsByType<TResource = unknown>(resourceType: string): readonly IResourcePool<TResource>[] {
    return Array.from(this.pools.values()).filter((pool) => {
      // This would need to be enhanced to track resource types
      return true; // Simplified for now
    }) as IResourcePool<TResource>[];
  }

  async getAllPoolHealth(): Promise<readonly PoolHealthInfo[]> {
    return Array.from(this.pools.values()).map((pool) => pool.getHealthStatus());
  }

  async performGlobalHealthCheck(): Promise<readonly PoolHealthResult[]> {
    const healthChecks = Array.from(this.pools.values()).map((pool) => pool.performHealthCheck());
    return Promise.all(healthChecks);
  }

  async closeAll(): Promise<void> {
    const closePromises = Array.from(this.pools.values()).map((pool) => pool.close());
    await Promise.allSettled(closePromises);
    this.pools.clear();
  }

  addEventListener<TResource = unknown>(
    eventType: PoolEventType,
    listener: PoolEventListener<TResource>
  ): void {
    if (!this.eventListeners.has(eventType)) {
      this.eventListeners.set(eventType, new Set());
    }
    this.eventListeners.get(eventType)!.add(listener as PoolEventListener);
  }

  removeEventListener<TResource = unknown>(
    eventType: PoolEventType,
    listener: PoolEventListener<TResource>
  ): void {
    const listeners = this.eventListeners.get(eventType);
    if (listeners) {
      listeners.delete(listener as PoolEventListener);
    }
  }

  private forwardEvent(event: PoolEvent): void {
    const listeners = this.eventListeners.get(event.type);
    if (listeners) {
      for (const listener of listeners) {
        try {
          listener(event);
        } catch (error) {
          logger.error({ eventType: event.type, error }, 'Event listener error');
        }
      }
    }
  }
}

// Export singleton instances
export const poolFactory = new TypedPoolFactory();
export const poolManager = new TypedPoolManager();
