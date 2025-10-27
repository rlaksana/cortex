/**
 * Connection Pool Configuration Manager
 *
 * Advanced connection pool management for qdrant and Qdrant with
 * health monitoring, performance optimization, and dynamic scaling.
 *
 * Features:
 * - Dynamic pool sizing based on load
 * - Health monitoring and automatic recovery
 * - Performance metrics collection
 * - Connection timeout and retry logic
 * - Environment-specific optimization
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import type { PostgresConfig, QdrantConfig } from './database-config.js';

export interface PoolConfiguration {
  min: number;
  max: number;
  idleTimeout: number;
  connectionTimeout: number;
  retryAttempts: number;
  retryDelay: number;
  acquireTimeout: number;
  createTimeout: number;
  destroyTimeout: number;
  reapInterval: number;
  createRetryInterval: number;
}

export interface PoolMetrics {
  totalConnections: number;
  activeConnections: number;
  idleConnections: number;
  waitingRequests: number;
  totalAcquires: number;
  totalReleases: number;
  totalCreates: number;
  totalDestroys: number;
  averageAcquireTime: number;
  averageConnectionAge: number;
  errors: number;
  lastError?: Date;
}

export interface PoolHealthStatus {
  healthy: boolean;
  status: 'healthy' | 'degraded' | 'unhealthy';
  uptime: number;
  lastHealthCheck: Date;
  consecutiveErrors: number;
  metrics: PoolMetrics;
}

export interface PoolConfigurationPreset {
  name: string;
  description: string;
  development: PoolConfiguration;
  production: PoolConfiguration;
  test: PoolConfiguration;
}

/**
 * Pool configuration presets for different use cases
 */
export const POOL_PRESETS: PoolConfigurationPreset[] = [
  {
    name: 'default',
    description: 'Balanced configuration for general use',
    development: {
      min: 1,
      max: 3,
      idleTimeout: 30000,
      connectionTimeout: 30000,
      retryAttempts: 3,
      retryDelay: 1000,
      acquireTimeout: 5000,
      createTimeout: 10000,
      destroyTimeout: 5000,
      reapInterval: 1000,
      createRetryInterval: 2000
    },
    production: {
      min: 5,
      max: 20,
      idleTimeout: 30000,
      connectionTimeout: 30000,
      retryAttempts: 3,
      retryDelay: 1000,
      acquireTimeout: 3000,
      createTimeout: 5000,
      destroyTimeout: 2000,
      reapInterval: 500,
      createRetryInterval: 1000
    },
    test: {
      min: 1,
      max: 1,
      idleTimeout: 5000,
      connectionTimeout: 5000,
      retryAttempts: 1,
      retryDelay: 500,
      acquireTimeout: 1000,
      createTimeout: 2000,
      destroyTimeout: 1000,
      reapInterval: 500,
      createRetryInterval: 500
    }
  },
  {
    name: 'high-performance',
    description: 'Optimized for high-throughput applications',
    development: {
      min: 2,
      max: 5,
      idleTimeout: 15000,
      connectionTimeout: 20000,
      retryAttempts: 5,
      retryDelay: 500,
      acquireTimeout: 2000,
      createTimeout: 5000,
      destroyTimeout: 2000,
      reapInterval: 500,
      createRetryInterval: 1000
    },
    production: {
      min: 10,
      max: 50,
      idleTimeout: 15000,
      connectionTimeout: 20000,
      retryAttempts: 5,
      retryDelay: 500,
      acquireTimeout: 1500,
      createTimeout: 3000,
      destroyTimeout: 1500,
      reapInterval: 250,
      createRetryInterval: 500
    },
    test: {
      min: 1,
      max: 2,
      idleTimeout: 3000,
      connectionTimeout: 3000,
      retryAttempts: 2,
      retryDelay: 250,
      acquireTimeout: 500,
      createTimeout: 1000,
      destroyTimeout: 500,
      reapInterval: 250,
      createRetryInterval: 250
    }
  },
  {
    name: 'conservative',
    description: 'Minimal resource usage for low-traffic applications',
    development: {
      min: 1,
      max: 2,
      idleTimeout: 60000,
      connectionTimeout: 45000,
      retryAttempts: 2,
      retryDelay: 2000,
      acquireTimeout: 10000,
      createTimeout: 15000,
      destroyTimeout: 10000,
      reapInterval: 2000,
      createRetryInterval: 5000
    },
    production: {
      min: 2,
      max: 8,
      idleTimeout: 60000,
      connectionTimeout: 45000,
      retryAttempts: 2,
      retryDelay: 2000,
      acquireTimeout: 8000,
      createTimeout: 12000,
      destroyTimeout: 8000,
      reapInterval: 1500,
      createRetryInterval: 3000
    },
    test: {
      min: 1,
      max: 1,
      idleTimeout: 10000,
      connectionTimeout: 10000,
      retryAttempts: 1,
      retryDelay: 1000,
      acquireTimeout: 2000,
      createTimeout: 3000,
      destroyTimeout: 2000,
      reapInterval: 1000,
      createRetryInterval: 2000
    }
  }
];

/**
 * qdrant pool configuration optimizer
 */
export class qdrantPoolConfigurator {
  private baseConfig: PoolConfiguration;
  private metrics: PoolMetrics;
  private healthStatus: PoolHealthStatus;
  private environment: 'development' | 'production' | 'test';

  constructor(baseConfig: PostgresConfig, environment: 'development' | 'production' | 'test') {
    this.environment = environment;
    this.baseConfig = this.extractPoolConfig(baseConfig);
    this.metrics = this.initializeMetrics();
    this.healthStatus = this.initializeHealthStatus();
  }

  /**
   * Extract pool configuration from qdrant config
   */
  private extractPoolConfig(pgConfig: PostgresConfig): PoolConfiguration {
    const preset = POOL_PRESETS.find(p => p.name === 'default');
    const defaultEnvConfig = preset?.development;

    if (!defaultEnvConfig) {
      throw new Error('Default pool configuration not found');
    }

    const envConfig = preset?.[this.environment] || defaultEnvConfig;

    return {
      min: pgConfig.pool.min || envConfig.min,
      max: pgConfig.pool.max || envConfig.max,
      idleTimeout: pgConfig.pool.idleTimeout || envConfig.idleTimeout,
      connectionTimeout: pgConfig.pool.connectionTimeout || envConfig.connectionTimeout,
      retryAttempts: pgConfig.pool.retryAttempts || envConfig.retryAttempts,
      retryDelay: pgConfig.pool.retryDelay || envConfig.retryDelay,
      acquireTimeout: envConfig.acquireTimeout,
      createTimeout: envConfig.createTimeout,
      destroyTimeout: envConfig.destroyTimeout,
      reapInterval: envConfig.reapInterval,
      createRetryInterval: envConfig.createRetryInterval
    };
  }

  /**
   * Initialize metrics collection
   */
  private initializeMetrics(): PoolMetrics {
    return {
      totalConnections: 0,
      activeConnections: 0,
      idleConnections: 0,
      waitingRequests: 0,
      totalAcquires: 0,
      totalReleases: 0,
      totalCreates: 0,
      totalDestroys: 0,
      averageAcquireTime: 0,
      averageConnectionAge: 0,
      errors: 0
    };
  }

  /**
   * Initialize health status
   */
  private initializeHealthStatus(): PoolHealthStatus {
    return {
      healthy: true,
      status: 'healthy',
      uptime: 0,
      lastHealthCheck: new Date(),
      consecutiveErrors: 0,
      metrics: this.metrics
    };
  }

  /**
   * Get optimized pool configuration
   */
  getPoolConfiguration(): PoolConfiguration {
    return { ...this.baseConfig };
  }

  /**
   * Apply performance optimizations based on metrics
   */
  optimizeConfiguration(): PoolConfiguration {
    const optimized = { ...this.baseConfig };

    // Optimize based on current metrics
    if (this.metrics.averageAcquireTime > 1000) {
      // Slow acquires - increase pool size or decrease timeout
      optimized.max = Math.min(optimized.max * 1.5, 100);
      optimized.acquireTimeout = Math.max(optimized.acquireTimeout * 0.8, 1000);
    }

    if (this.metrics.errors > 10) {
      // High error rate - increase retry attempts
      optimized.retryAttempts = Math.min(optimized.retryAttempts + 1, 10);
      optimized.retryDelay = Math.min(optimized.retryDelay * 1.5, 10000);
    }

    if (this.metrics.idleConnections > this.metrics.activeConnections * 2) {
      // Too many idle connections - reduce pool size
      optimized.min = Math.max(optimized.min - 1, 1);
      optimized.idleTimeout = Math.min(optimized.idleTimeout * 0.8, 5000);
    }

    return optimized;
  }

  /**
   * Apply environment-specific preset
   */
  applyPreset(presetName: string): PoolConfiguration {
    const preset = POOL_PRESETS.find(p => p.name === presetName);
    if (!preset) {
      throw new Error(`Unknown pool preset: ${presetName}`);
    }

    const envConfig = preset[this.environment];
    return { ...this.baseConfig, ...envConfig };
  }

  /**
   * Get pool configuration for pg library
   */
  getPgPoolConfig() {
    return {
      min: this.baseConfig.min,
      max: this.baseConfig.max,
      idleTimeoutMillis: this.baseConfig.idleTimeout,
      connectionTimeoutMillis: this.baseConfig.connectionTimeout,
      acquireTimeoutMillis: this.baseConfig.acquireTimeout,
      createTimeoutMillis: this.baseConfig.createTimeout,
      destroyTimeoutMillis: this.baseConfig.destroyTimeout,
      reapIntervalMillis: this.baseConfig.reapInterval,
      createRetryIntervalMillis: this.baseConfig.createRetryInterval
    };
  }

  /**
   * Update metrics
   */
  updateMetrics(newMetrics: Partial<PoolMetrics>): void {
    this.metrics = { ...this.metrics, ...newMetrics };
    this.healthStatus.metrics = this.metrics;
    this.healthStatus.lastHealthCheck = new Date();

    // Update health status based on metrics
    this.updateHealthStatus();
  }

  /**
   * Update health status based on metrics
   */
  private updateHealthStatus(): void {
    const errorRate = this.metrics.errors / Math.max(this.metrics.totalAcquires, 1);
    const utilizationRate = this.metrics.activeConnections / Math.max(this.metrics.totalConnections, 1);

    if (errorRate > 0.1 || utilizationRate > 0.9) {
      this.healthStatus.status = 'unhealthy';
      this.healthStatus.healthy = false;
      this.healthStatus.consecutiveErrors++;
    } else if (errorRate > 0.05 || utilizationRate > 0.7) {
      this.healthStatus.status = 'degraded';
      this.healthStatus.healthy = true;
      this.healthStatus.consecutiveErrors = 0;
    } else {
      this.healthStatus.status = 'healthy';
      this.healthStatus.healthy = true;
      this.healthStatus.consecutiveErrors = 0;
    }
  }

  /**
   * Get current health status
   */
  getHealthStatus(): PoolHealthStatus {
    return { ...this.healthStatus };
  }

  /**
   * Get current metrics
   */
  getMetrics(): PoolMetrics {
    return { ...this.metrics };
  }
}

/**
 * Qdrant HTTP connection pool configurator
 */
export class QdrantPoolConfigurator {
  private config: QdrantConfig;
  private maxConcurrentRequests!: number;
  private requestTimeout!: number;
  private retryAttempts!: number;
  private retryDelay!: number;
  private environment: 'development' | 'production' | 'test';

  constructor(config: QdrantConfig, environment: 'development' | 'production' | 'test') {
    this.config = config;
    this.environment = environment;
    this.applyEnvironmentDefaults();
  }

  /**
   * Apply environment-specific defaults
   */
  private applyEnvironmentDefaults(): void {
    switch (this.environment) {
      case 'development':
        this.maxConcurrentRequests = 5;
        this.requestTimeout = 30000;
        this.retryAttempts = 3;
        this.retryDelay = 1000;
        break;
      case 'production':
        this.maxConcurrentRequests = 20;
        this.requestTimeout = 30000;
        this.retryAttempts = 5;
        this.retryDelay = 500;
        break;
      case 'test':
        this.maxConcurrentRequests = 2;
        this.requestTimeout = 5000;
        this.retryAttempts = 1;
        this.retryDelay = 250;
        break;
    }
  }

  /**
   * Get HTTP client configuration
   */
  getHttpClientConfig() {
    return {
      maxConcurrentRequests: this.maxConcurrentRequests,
      timeout: this.requestTimeout,
      retryAttempts: this.retryAttempts,
      retryDelay: this.retryDelay,
      baseUrl: this.config.url,
      defaultHeaders: {
        'Content-Type': 'application/json',
        ...(this.config.apiKey && { 'api-key': this.config.apiKey })
      }
    };
  }

  /**
   * Get fetch configuration for requests
   */
  getFetchConfig(additionalHeaders: Record<string, string> = {}) {
    return {
      headers: {
        'Content-Type': 'application/json',
        ...(this.config.apiKey && { 'api-key': this.config.apiKey }),
        ...additionalHeaders
      },
      signal: AbortSignal.timeout(this.requestTimeout)
    };
  }

  /**
   * Update configuration
   */
  updateConfig(updates: {
    maxConcurrentRequests?: number;
    requestTimeout?: number;
    retryAttempts?: number;
    retryDelay?: number;
  }): void {
    if (updates.maxConcurrentRequests) {
      this.maxConcurrentRequests = updates.maxConcurrentRequests;
    }
    if (updates.requestTimeout) {
      this.requestTimeout = updates.requestTimeout;
    }
    if (updates.retryAttempts) {
      this.retryAttempts = updates.retryAttempts;
    }
    if (updates.retryDelay) {
      this.retryDelay = updates.retryDelay;
    }
  }

  /**
   * Apply performance optimizations
   */
  optimizeForHighThroughput(): void {
    this.maxConcurrentRequests = Math.min(this.maxConcurrentRequests * 2, 100);
    this.requestTimeout = Math.max(this.requestTimeout * 0.7, 5000);
    this.retryDelay = Math.max(this.retryDelay * 0.5, 100);
  }

  /**
   * Apply conservative settings for reliability
   */
  optimizeForReliability(): void {
    this.maxConcurrentRequests = Math.max(this.maxConcurrentRequests * 0.7, 2);
    this.requestTimeout = Math.min(this.requestTimeout * 1.3, 60000);
    this.retryAttempts = Math.min(this.retryAttempts + 2, 10);
    this.retryDelay = Math.min(this.retryDelay * 1.5, 5000);
  }
}

/**
 * Pool configuration factory
 */
export class PoolConfigFactory {
  /**
   * Create qdrant pool configurator
   */
  static createPostgresConfigurator(
    pgConfig: PostgresConfig,
    environment: 'development' | 'production' | 'test' = 'production'
  ): qdrantPoolConfigurator {
    return new qdrantPoolConfigurator(pgConfig, environment);
  }

  /**
   * Create Qdrant pool configurator
   */
  static createQdrantConfigurator(
    qdrantConfig: QdrantConfig,
    environment: 'development' | 'production' | 'test' = 'production'
  ): QdrantPoolConfigurator {
    return new QdrantPoolConfigurator(qdrantConfig, environment);
  }

  /**
   * Get available presets
   */
  static getAvailablePresets(): string[] {
    return POOL_PRESETS.map(p => p.name);
  }

  /**
   * Get preset details
   */
  static getPresetDetails(name: string): PoolConfigurationPreset | undefined {
    return POOL_PRESETS.find(p => p.name === name);
  }

  /**
   * Create configuration from preset
   */
  static createFromPreset(
    presetName: string,
    environment: 'development' | 'production' | 'test'
  ): PoolConfiguration {
    const preset = POOL_PRESETS.find(p => p.name === presetName);
    if (!preset) {
      throw new Error(`Unknown pool preset: ${presetName}`);
    }

    return preset[environment];
  }
}

// Export utility functions
export function createPostgresPoolConfig(
  pgConfig: PostgresConfig,
  environment: 'development' | 'production' | 'test' = 'production'
): qdrantPoolConfigurator {
  return PoolConfigFactory.createPostgresConfigurator(pgConfig, environment);
}

export function createQdrantPoolConfig(
  qdrantConfig: QdrantConfig,
  environment: 'development' | 'production' | 'test' = 'production'
): QdrantPoolConfigurator {
  return PoolConfigFactory.createQdrantConfigurator(qdrantConfig, environment);
}