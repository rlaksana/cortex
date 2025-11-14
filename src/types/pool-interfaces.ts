/**
 * Typed Pool Interfaces - Generic Resource Pool Management
 *
 * Comprehensive type-safe pool interfaces with proper constraints, generic resource
 * handling, and branded types for pool identifiers.
 *
 * Features:
 * - Generic pool interfaces with proper constraints
 * - Typed resource factory patterns
 * - Type-safe pool lifecycle management
 * - Branded types for pool identifiers
 * - Resource validation at checkout/return
 * - Pool health monitoring with typed metrics
 * - Connection type validation
 * - Resource lifecycle validation
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

/**
 * Branded type for unique pool identifiers
 */
export type PoolId = string & { readonly __brand: 'PoolId' };

/**
 * Branded type for unique resource identifiers
 */
export type ResourceId = string & { readonly __brand: 'ResourceId' };

/**
 * Branded type for pool configuration keys
 */
export type ConfigKey = string & { readonly __brand: 'ConfigKey' };

/**
 * Pool resource states with type safety
 */
export type ResourceState =
  | 'available'
  | 'in_use'
  | 'maintenance'
  | 'health_check'
  | 'error'
  | 'destroyed';

/**
 * Pool health status with detailed typing
 */
export type PoolHealthStatus =
  | 'healthy'
  | 'degraded'
  | 'unhealthy'
  | 'maintenance'
  | 'unknown';

/**
 * Resource validation result with detailed typing
 */
export interface ResourceValidationResult<TResource = unknown> {
  readonly isValid: boolean;
  readonly resource: TResource;
  readonly errors: readonly string[];
  readonly warnings: readonly string[];
  readonly validationTime: Date;
}

/**
 * Resource metrics with type safety
 */
export interface ResourceMetrics {
  readonly resourceId: ResourceId;
  readonly poolId: PoolId;
  readonly state: ResourceState;
  readonly created: Date;
  readonly lastUsed: Date;
  readonly usageCount: number;
  readonly errorCount: number;
  readonly averageResponseTime: number;
  readonly lastHealthCheck: Date;
  readonly responseTimeHistory: readonly number[];
}

/**
 * Pool configuration with generic constraints
 */
export interface PoolConfig<TResource = unknown, TConfig = unknown> {
  readonly id: PoolId;
  readonly name: string;
  readonly minResources: number;
  readonly maxResources: number;
  readonly acquireTimeout: number;
  readonly idleTimeout: number;
  readonly healthCheckInterval: number;
  readonly maxRetries: number;
  readonly retryDelay: number;
  readonly enableMetrics: boolean;
  readonly enableHealthChecks: boolean;
  readonly resourceFactory: ResourceFactory<TResource, TConfig>;
  readonly resourceValidator?: ResourceValidator<TResource>;
  readonly resourceDestroyer?: ResourceDestroyer<TResource>;
  readonly config?: TConfig;
}

/**
 * Generic resource factory interface
 */
export interface ResourceFactory<TResource = unknown, TConfig = unknown> {
  /**
   * Create a new resource instance
   */
  create(config?: TConfig): Promise<TResource>;

  /**
   * Validate resource configuration
   */
  validateConfig?(config: TConfig): Promise<{
    readonly valid: boolean;
    readonly errors: readonly string[];
    readonly warnings: readonly string[];
  }>;

  /**
   * Get resource type identifier
   */
  getResourceType(): string;

  /**
   * Get resource capabilities
   */
  getResourceCapabilities(): readonly string[];
}

/**
 * Resource validator interface for runtime validation
 */
export interface ResourceValidator<TResource = unknown> {
  /**
   * Validate resource health and usability
   */
  validate(resource: TResource): Promise<ResourceValidationResult<TResource>>;

  /**
   * Quick health check (non-blocking)
   */
  healthCheck(resource: TResource): Promise<boolean>;

  /**
   * Validate resource before returning to pool
   */
  validateOnReturn?(resource: TResource): Promise<ResourceValidationResult<TResource>>;

  /**
   * Validate resource before checkout from pool
   */
  validateOnCheckout?(resource: TResource): Promise<ResourceValidationResult<TResource>>;
}

/**
 * Resource destroyer interface for cleanup
 */
export interface ResourceDestroyer<TResource = unknown> {
  /**
   * Clean up and destroy resource
   */
  destroy(resource: TResource): Promise<void>;

  /**
   * Graceful shutdown with timeout
   */
  gracefulShutdown?(resource: TResource, timeout: number): Promise<void>;
}

/**
 * Generic resource pool interface
 */
export interface IResourcePool<TResource = unknown, TConfig = unknown> {
  readonly config: PoolConfig<TResource, TConfig>;
  readonly poolId: PoolId;

  /**
   * Initialize the pool
   */
  initialize(): Promise<void>;

  /**
   * Acquire a resource from the pool
   */
  acquire(options?: AcquireOptions): Promise<PooledResource<TResource>>;

  /**
   * Release a resource back to the pool
   */
  release(resource: PooledResource<TResource>): Promise<void>;

  /**
   * Destroy a specific resource
   */
  destroyResource(resourceId: ResourceId): Promise<void>;

  /**
   * Get pool statistics
   */
  getStats(): PoolStats;

  /**
   * Get pool health status
   */
  getHealthStatus(): PoolHealthInfo;

  /**
   * Get all resource metrics
   */
  getResourceMetrics(): readonly ResourceMetrics[];

  /**
   * Perform health check on all resources
   */
  performHealthCheck(): Promise<PoolHealthResult>;

  /**
   * Close the pool and destroy all resources
   */
  close(): Promise<void>;

  /**
   * Validate pool configuration
   */
  validateConfig(): Promise<{
    readonly valid: boolean;
    readonly errors: readonly string[];
    readonly warnings: readonly string[];
  }>;

  /**
   * Get pool configuration (without sensitive data)
   */
  getConfig(): Omit<PoolConfig<TResource, TConfig>, 'config'>;
}

/**
 * Pooled resource wrapper with metadata
 */
export interface PooledResource<TResource = unknown> {
  readonly resource: TResource;
  readonly resourceId: ResourceId;
  readonly poolId: PoolId;
  readonly acquired: Date;
  readonly lastUsed: Date;
  readonly usageCount: number;
  readonly isValid: boolean;
  readonly metrics: ResourceMetrics;
}

/**
 * Resource acquisition options
 */
export interface AcquireOptions {
  readonly timeout?: number;
  readonly priority?: 'low' | 'normal' | 'high' | 'critical';
  readonly preferredResourceId?: ResourceId;
  readonly skipHealthCheck?: boolean;
  readonly maxRetries?: number;
  readonly retryDelay?: number;
}

/**
 * Pool statistics with comprehensive metrics
 */
export interface PoolStats {
  readonly poolId: PoolId;
  readonly totalResources: number;
  readonly availableResources: number;
  readonly inUseResources: number;
  readonly maintenanceResources: number;
  readonly errorResources: number;
  readonly destroyedResources: number;
  readonly averageAcquireTime: number;
  readonly averageResponseTime: number;
  readonly totalAcquisitions: number;
  readonly totalReleases: number;
  readonly totalErrors: number;
  readonly poolUtilization: number;
  readonly healthStatus: PoolHealthStatus;
  readonly lastHealthCheck: Date;
  readonly uptime: number;
}

/**
 * Pool health information
 */
export interface PoolHealthInfo {
  readonly status: PoolHealthStatus;
  readonly lastCheck: Date;
  readonly healthyResources: number;
  readonly unhealthyResources: number;
  readonly totalResources: number;
  readonly issues: readonly string[];
  readonly recommendations: readonly string[];
  readonly nextCheckDue: Date;
}

/**
 * Pool health check result
 */
export interface PoolHealthResult {
  readonly status: PoolHealthStatus;
  readonly checkedAt: Date;
  readonly healthyResources: readonly ResourceId[];
  readonly unhealthyResources: readonly ResourceId[];
  readonly issues: readonly PoolHealthIssue[];
  readonly recommendations: readonly string[];
  readonly metrics: {
    readonly successRate: number;
    readonly averageResponseTime: number;
    readonly errorCount: number;
  };
}

/**
 * Pool health issue details
 */
export interface PoolHealthIssue {
  readonly resourceId: ResourceId;
  readonly severity: 'low' | 'medium' | 'high' | 'critical';
  readonly type: 'connection' | 'performance' | 'validation' | 'timeout' | 'configuration';
  readonly message: string;
  readonly detectedAt: Date;
  readonly metrics?: {
    readonly responseTime?: number;
    readonly errorCount?: number;
    readonly lastSuccess?: Date;
  };
}

/**
 * Pool event types for monitoring
 */
export type PoolEventType =
  | 'resource_created'
  | 'resource_acquired'
  | 'resource_released'
  | 'resource_destroyed'
  | 'resource_error'
  | 'health_check_completed'
  | 'pool_initialized'
  | 'pool_closed'
  | 'configuration_updated'
  | 'maintenance_started'
  | 'maintenance_completed';

/**
 * Pool event with typed payload
 */
export interface PoolEvent<TResource = unknown> {
  readonly type: PoolEventType;
  readonly poolId: PoolId;
  readonly resourceId?: ResourceId;
  readonly timestamp: Date;
  readonly data?: {
    readonly resource?: TResource;
    readonly metrics?: ResourceMetrics;
    readonly error?: Error;
    readonly config?: PoolConfig<TResource, unknown>;
    [key: string]: unknown;
  };
}

/**
 * Pool event listener interface
 */
export interface PoolEventListener<TResource = unknown> {
  (event: PoolEvent<TResource>): void | Promise<void>;
}

/**
 * Pool factory interface for creating typed pools
 */
export interface IPoolFactory {
  /**
   * Create a new resource pool
   */
  createPool<TResource, TConfig>(
    config: PoolConfig<TResource, TConfig>
  ): Promise<IResourcePool<TResource, TConfig>>;

  /**
   * Get pool by ID
   */
  getPool<TResource = unknown>(poolId: PoolId): IResourcePool<TResource> | undefined;

  /**
   * List all pools
   */
  listPools(): readonly PoolId[];

  /**
   * Close all pools
   */
  closeAll(): Promise<void>;

  /**
   * Get factory statistics
   */
  getFactoryStats(): {
    readonly totalPools: number;
    readonly activePools: number;
    readonly totalResources: number;
    readonly activeResources: number;
  };
}

/**
 * Resource constraints for type safety
 */
export interface ResourceConstraints<TResource = unknown> {
  readonly resourceType: string;
  readonly requiredCapabilities: readonly string[];
  readonly optionalCapabilities: readonly string[];
  readonly validator?: (resource: unknown) => resource is TResource;
  readonly destroyer?: (resource: TResource) => Promise<void>;
}

/**
 * Pool manager for managing multiple pools
 */
export interface IPoolManager {
  /**
   * Register a new pool
   */
  registerPool<TResource, TConfig>(
    pool: IResourcePool<TResource, TConfig>
  ): Promise<void>;

  /**
   * Unregister a pool
   */
  unregisterPool(poolId: PoolId): Promise<void>;

  /**
   * Get pool by ID with type safety
   */
  getPool<TResource = unknown>(
    poolId: PoolId,
    resourceType?: string
  ): IResourcePool<TResource> | undefined;

  /**
   * Get all pools of a specific resource type
   */
  getPoolsByType<TResource = unknown>(
    resourceType: string
  ): readonly IResourcePool<TResource>[];

  /**
   * Get health status of all pools
   */
  getAllPoolHealth(): Promise<readonly PoolHealthInfo[]>;

  /**
   * Perform health check on all pools
   */
  performGlobalHealthCheck(): Promise<readonly PoolHealthResult[]>;

  /**
   * Close all pools gracefully
   */
  closeAll(): Promise<void>;

  /**
   * Add event listener for pool events
   */
  addEventListener<TResource = unknown>(
    eventType: PoolEventType,
    listener: PoolEventListener<TResource>
  ): void;

  /**
   * Remove event listener
   */
  removeEventListener<TResource = unknown>(
    eventType: PoolEventType,
    listener: PoolEventListener<TResource>
  ): void;
}

/**
 * Type guards for pool runtime validation
 */
export interface PoolTypeGuards {
  isPoolId(value: unknown): value is PoolId;
  isResourceId(value: unknown): value is ResourceId;
  isResourceState(value: unknown): value is ResourceState;
  isPoolHealthStatus(value: unknown): value is PoolHealthStatus;
  isPoolEventType(value: unknown): value is PoolEventType;
}

/**
 * Utility functions for pool management
 */
export interface PoolUtils {
  /**
   * Generate unique pool ID
   */
  generatePoolId(name: string): PoolId;

  /**
   * Generate unique resource ID
   */
  generateResourceId(poolId: PoolId): ResourceId;

  /**
   * Create pool configuration key
   */
  createConfigKey(config: Record<string, unknown>): ConfigKey;

  /**
   * Validate pool configuration
   */
  validatePoolConfig<TResource, TConfig>(
    config: PoolConfig<TResource, TConfig>
  ): Promise<{
    readonly valid: boolean;
    readonly errors: readonly string[];
    readonly warnings: readonly string[];
  }>;

  /**
   * Calculate pool utilization
   */
  calculateUtilization(stats: PoolStats): number;

  /**
   * Determine pool health from stats
   */
  determineHealthStatus(stats: PoolStats): PoolHealthStatus;
}