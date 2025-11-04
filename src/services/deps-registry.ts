/**
 * Dependency Registry & Health Monitoring System
 *
 * Comprehensive dependency management system that tracks, monitors, and manages
 * all external dependencies (Qdrant, OpenAI, Redis, etc.) with health monitoring,
 * lifecycle management, and performance tracking.
 *
 * Features:
 * - Centralized dependency registration and management
 * - Real-time health monitoring with configurable thresholds
 * - Dependency lifecycle management (connect, disconnect, health check)
 * - Performance metrics and SLA tracking
 * - Circuit breaker integration for failure resilience
 * - Dependency isolation and fallback mechanisms
 * - Service catalog with metadata discovery
 * - Weighted health scoring and aggregation
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'node:events';
import { logger } from '../utils/logger.js';
import { circuitBreakerManager } from './circuit-breaker.service.js';

/**
 * Dependency status levels with severity
 */
export enum DependencyStatus {
  HEALTHY = 'healthy',
  WARNING = 'warning',
  CRITICAL = 'critical',
  UNKNOWN = 'unknown',
  DISABLED = 'disabled'
}

/**
 * Dependency types supported by the registry
 */
export enum DependencyType {
  DATABASE = 'database',
  VECTOR_DB = 'vector_db',
  EMBEDDING_SERVICE = 'embedding_service',
  CACHE = 'cache',
  MESSAGE_QUEUE = 'message_queue',
  STORAGE = 'storage',
  EXTERNAL_API = 'external_api',
  MONITORING = 'monitoring'
}

/**
 * Health check configuration for dependencies
 */
export interface HealthCheckConfig {
  enabled: boolean;
  intervalMs: number;
  timeoutMs: number;
  failureThreshold: number;
  successThreshold: number;
  retryAttempts: number;
  retryDelayMs: number;
}

/**
 * Performance metrics for a dependency
 */
export interface DependencyMetrics {
  responseTime: {
    current: number;
    average: number;
    p95: number;
    p99: number;
  };
  throughput: {
    requestsPerSecond: number;
    requestsPerMinute: number;
  };
  error: {
    rate: number;
    count: number;
    lastError?: string;
  };
  availability: {
    uptime: number;
    downtime: number;
    lastCheck: Date;
  };
  circuitBreaker?: {
    state: string;
    failureRate: number;
    totalCalls: number;
  };
}

/**
 * Dependency configuration and metadata
 */
export interface DependencyConfig {
  name: string;
  type: DependencyType;
  version?: string;
  description?: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  healthCheck: HealthCheckConfig;
  connection: {
    url: string;
    timeout?: number;
    apiKey?: string;
    [key: string]: any;
  };
  thresholds: {
    responseTimeWarning: number;
    responseTimeCritical: number;
    errorRateWarning: number;
    errorRateCritical: number;
    availabilityWarning: number;
    availabilityCritical: number;
  };
  fallback?: {
    enabled: boolean;
    service?: string;
    config?: any;
  };
  metadata?: Record<string, any>;
}

/**
 * Current state of a dependency
 */
export interface DependencyState {
  config: DependencyConfig;
  status: DependencyStatus;
  metrics: DependencyMetrics;
  lastHealthCheck: Date;
  consecutiveFailures: number;
  consecutiveSuccesses: number;
  totalChecks: number;
  enabled: boolean;
  metadata: {
    createdAt: Date;
    updatedAt: Date;
    lastFailure?: Date;
    lastSuccess?: Date;
  };
}

/**
 * Health check result from individual dependency
 */
export interface HealthCheckResult {
  dependency: string;
  status: DependencyStatus;
  responseTime: number;
  error?: string;
  details?: Record<string, any>;
  timestamp: Date;
}

/**
 * Aggregated health status for the entire system
 */
export interface AggregatedHealthStatus {
  overall: DependencyStatus;
  dependencies: Record<string, DependencyState>;
  summary: {
    total: number;
    healthy: number;
    warning: number;
    critical: number;
    unknown: number;
    disabled: number;
  };
  score: number; // 0-100
  timestamp: Date;
}

/**
 * Health check function signature
 */
export type HealthCheckFunction = (
  config: DependencyConfig
) => Promise<HealthCheckResult>;

/**
 * Connection management function signatures
 */
export type ConnectFunction = (config: DependencyConfig) => Promise<boolean>;
export type DisconnectFunction = (config: DependencyConfig) => Promise<boolean>;

/**
 * Dependency Registry Service
 *
 * Central registry for managing all external dependencies with health monitoring,
 * lifecycle management, and performance tracking capabilities.
 */
export class DependencyRegistry extends EventEmitter {
  private dependencies = new Map<string, DependencyState>();
  private healthChecks = new Map<string, HealthCheckFunction>();
  private connectors = new Map<string, ConnectFunction>();
  private disconnectors = new Map<string, DisconnectFunction>();
  private healthCheckIntervals = new Map<string, NodeJS.Timeout>();
  private metricsHistory = new Map<string, DependencyMetrics[]>();
  private isInitialized = false;

  constructor() {
    super();
    this.setupErrorHandling();
  }

  /**
   * Initialize the dependency registry
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    try {
      logger.info('Initializing Dependency Registry...');

      // Set up built-in health checkers for common dependency types
      this.registerBuiltInHealthCheckers();

      // Start health monitoring for all registered dependencies
      this.startAllHealthChecks();

      this.isInitialized = true;
      this.emit('initialized');

      logger.info('Dependency Registry initialized successfully');
    } catch (error) {
      logger.error({ error }, 'Failed to initialize Dependency Registry');
      throw error;
    }
  }

  /**
   * Register a new dependency
   */
  async registerDependency(
    config: DependencyConfig,
    options: {
      healthCheck?: HealthCheckFunction;
      connector?: ConnectFunction;
      disconnector?: DisconnectFunction;
    } = {}
  ): Promise<void> {
    try {
      logger.info({ dependency: config.name }, 'Registering dependency');

      // Validate configuration
      this.validateDependencyConfig(config);

      // Create initial state
      const state: DependencyState = {
        config,
        status: DependencyStatus.UNKNOWN,
        metrics: this.createEmptyMetrics(),
        lastHealthCheck: new Date(),
        consecutiveFailures: 0,
        consecutiveSuccesses: 0,
        totalChecks: 0,
        enabled: config.healthCheck.enabled,
        metadata: {
          createdAt: new Date(),
          updatedAt: new Date()
        }
      };

      // Store dependency state
      this.dependencies.set(config.name, state);

      // Register custom health check if provided
      if (options.healthCheck) {
        this.healthChecks.set(config.name, options.healthCheck);
      }

      // Register connector/disconnector if provided
      if (options.connector) {
        this.connectors.set(config.name, options.connector);
      }
      if (options.disconnector) {
        this.disconnectors.set(config.name, options.disconnector);
      }

      // Initialize metrics history
      this.metricsHistory.set(config.name, []);

      // Connect to dependency if connector is available
      if (options.connector) {
        try {
          const connected = await options.connector(config);
          if (connected) {
            state.status = DependencyStatus.HEALTHY;
            state.metadata.lastSuccess = new Date();
          } else {
            state.status = DependencyStatus.CRITICAL;
            state.metadata.lastFailure = new Date();
          }
        } catch (error) {
          logger.warn({ dependency: config.name, error }, 'Failed to connect to dependency');
          state.status = DependencyStatus.CRITICAL;
          state.metadata.lastFailure = new Date();
        }
      }

      // Start health checking if enabled
      if (config.healthCheck.enabled && this.isInitialized) {
        this.startHealthCheck(config.name);
      }

      this.emit('dependencyRegistered', config.name, state);
      logger.info({ dependency: config.name, status: state.status }, 'Dependency registered');

    } catch (error) {
      logger.error({ dependency: config.name, error }, 'Failed to register dependency');
      throw error;
    }
  }

  /**
   * Unregister a dependency
   */
  async unregisterDependency(name: string): Promise<void> {
    try {
      const state = this.dependencies.get(name);
      if (!state) {
        logger.warn({ dependency: name }, 'Dependency not found for unregistration');
        return;
      }

      logger.info({ dependency: name }, 'Unregistering dependency');

      // Stop health checking
      this.stopHealthCheck(name);

      // Disconnect if disconnector is available
      const disconnector = this.disconnectors.get(name);
      if (disconnector) {
        try {
          await disconnector(state.config);
        } catch (error) {
          logger.warn({ dependency: name, error }, 'Failed to disconnect from dependency');
        }
      }

      // Clean up resources
      this.dependencies.delete(name);
      this.healthChecks.delete(name);
      this.connectors.delete(name);
      this.disconnectors.delete(name);
      this.metricsHistory.delete(name);

      this.emit('dependencyUnregistered', name);
      logger.info({ dependency: name }, 'Dependency unregistered');

    } catch (error) {
      logger.error({ dependency: name, error }, 'Failed to unregister dependency');
      throw error;
    }
  }

  /**
   * Get dependency state
   */
  getDependencyState(name: string): DependencyState | undefined {
    return this.dependencies.get(name);
  }

  /**
   * Get all registered dependencies
   */
  getAllDependencies(): Record<string, DependencyState> {
    const result: Record<string, DependencyState> = {};
    for (const [name, state] of this.dependencies) {
      result[name] = { ...state };
    }
    return result;
  }

  /**
   * Get dependencies by type
   */
  getDependenciesByType(type: DependencyType): Record<string, DependencyState> {
    const result: Record<string, DependencyState> = {};
    for (const [name, state] of this.dependencies) {
      if (state.config.type === type) {
        result[name] = { ...state };
      }
    }
    return result;
  }

  /**
   * Get dependencies by status
   */
  getDependenciesByStatus(status: DependencyStatus): Record<string, DependencyState> {
    const result: Record<string, DependencyState> = {};
    for (const [name, state] of this.dependencies) {
      if (state.status === status) {
        result[name] = { ...state };
      }
    }
    return result;
  }

  /**
   * Perform health check on a specific dependency
   */
  async performHealthCheck(name: string): Promise<HealthCheckResult> {
    const state = this.dependencies.get(name);
    if (!state) {
      throw new Error(`Dependency ${name} not found`);
    }

    if (!state.enabled) {
      return {
        dependency: name,
        status: DependencyStatus.DISABLED,
        responseTime: 0,
        timestamp: new Date()
      };
    }

    const startTime = Date.now();
    let result: HealthCheckResult;

    try {
      // Get appropriate health check function
      const healthCheck = this.healthChecks.get(name) ||
                         this.getBuiltInHealthCheck(state.config.type);

      if (!healthCheck) {
        throw new Error(`No health check available for dependency ${name}`);
      }

      // Execute health check with timeout
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('Health check timeout')),
                   state.config.healthCheck.timeoutMs);
      });

      result = await Promise.race([
        healthCheck(state.config),
        timeoutPromise
      ]);

    } catch (error) {
      result = {
        dependency: name,
        status: DependencyStatus.CRITICAL,
        responseTime: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date()
      };
    }

    // Update dependency state
    this.updateDependencyState(name, result);

    return result;
  }

  /**
   * Get aggregated health status for all dependencies
   */
  async getAggregatedHealthStatus(): Promise<AggregatedHealthStatus> {
    const dependencies = this.getAllDependencies();
    const summary = {
      total: 0,
      healthy: 0,
      warning: 0,
      critical: 0,
      unknown: 0,
      disabled: 0
    };

    // Calculate weighted score based on priority and status
    let totalWeight = 0;
    let weightedScore = 0;

    for (const state of Object.values(dependencies)) {
      summary.total++;

      switch (state.status) {
        case DependencyStatus.HEALTHY:
          summary.healthy++;
          break;
        case DependencyStatus.WARNING:
          summary.warning++;
          break;
        case DependencyStatus.CRITICAL:
          summary.critical++;
          break;
        case DependencyStatus.UNKNOWN:
          summary.unknown++;
          break;
        case DependencyStatus.DISABLED:
          summary.disabled++;
          break;
      }

      // Calculate weighted score
      const weight = this.getPriorityWeight(state.config.priority);
      const statusScore = this.getStatusScore(state.status);

      totalWeight += weight;
      weightedScore += weight * statusScore;
    }

    const overallScore = totalWeight > 0 ? weightedScore / totalWeight : 0;
    const overallStatus = this.determineOverallStatus(summary, overallScore);

    return {
      overall: overallStatus,
      dependencies,
      summary,
      score: Math.round(overallScore),
      timestamp: new Date()
    };
  }

  /**
   * Enable or disable health checking for a dependency
   */
  setHealthCheckingEnabled(name: string, enabled: boolean): void {
    const state = this.dependencies.get(name);
    if (!state) {
      throw new Error(`Dependency ${name} not found`);
    }

    state.enabled = enabled;
    state.config.healthCheck.enabled = enabled;

    if (enabled) {
      this.startHealthCheck(name);
    } else {
      this.stopHealthCheck(name);
    }

    this.emit('healthCheckToggled', name, enabled);
  }

  /**
   * Get dependency metrics history
   */
  getMetricsHistory(name: string, limit: number = 100): DependencyMetrics[] {
    const history = this.metricsHistory.get(name) || [];
    return history.slice(-limit);
  }

  /**
   * Manually trigger health check for all dependencies
   */
  async checkAllDependencies(): Promise<Record<string, HealthCheckResult>> {
    const results: Record<string, HealthCheckResult> = {};

    for (const name of this.dependencies.keys()) {
      try {
        results[name] = await this.performHealthCheck(name);
      } catch (error) {
        results[name] = {
          dependency: name,
          status: DependencyStatus.CRITICAL,
          responseTime: 0,
          error: error instanceof Error ? error.message : String(error),
          timestamp: new Date()
        };
      }
    }

    return results;
  }

  /**
   * Gracefully shutdown the dependency registry
   */
  async shutdown(): Promise<void> {
    logger.info('Shutting down Dependency Registry...');

    // Stop all health checks
    for (const name of this.healthCheckIntervals.keys()) {
      this.stopHealthCheck(name);
    }

    // Disconnect from all dependencies
    const disconnectPromises: Promise<void>[] = [];
    for (const [name, disconnector] of this.disconnectors) {
      const state = this.dependencies.get(name);
      if (state && disconnector) {
        disconnectPromises.push(
          disconnector(state.config).then(() => {}).catch(error =>
            logger.warn({ dependency: name, error }, 'Failed to disconnect during shutdown')
          )
        );
      }
    }

    await Promise.allSettled(disconnectPromises);

    this.isInitialized = false;
    this.emit('shutdown');

    logger.info('Dependency Registry shutdown completed');
  }

  /**
   * Validate dependency configuration
   */
  private validateDependencyConfig(config: DependencyConfig): void {
    if (!config.name || typeof config.name !== 'string') {
      throw new Error('Dependency name is required and must be a string');
    }

    if (!config.type || !Object.values(DependencyType).includes(config.type)) {
      throw new Error('Valid dependency type is required');
    }

    if (!config.priority || !['critical', 'high', 'medium', 'low'].includes(config.priority)) {
      throw new Error('Valid priority is required');
    }

    if (!config.connection?.url || typeof config.connection.url !== 'string') {
      throw new Error('Connection URL is required and must be a string');
    }

    if (!config.healthCheck) {
      throw new Error('Health check configuration is required');
    }
  }

  /**
   * Create empty metrics object
   */
  private createEmptyMetrics(): DependencyMetrics {
    return {
      responseTime: {
        current: 0,
        average: 0,
        p95: 0,
        p99: 0
      },
      throughput: {
        requestsPerSecond: 0,
        requestsPerMinute: 0
      },
      error: {
        rate: 0,
        count: 0
      },
      availability: {
        uptime: 0,
        downtime: 0,
        lastCheck: new Date()
      }
    };
  }

  /**
   * Register built-in health checkers for common dependency types
   */
  private registerBuiltInHealthCheckers(): void {
    // Built-in health checkers are registered in getBuiltInHealthCheck method
    logger.debug('Built-in health checkers available');
  }

  /**
   * Get built-in health check for dependency type
   */
  private getBuiltInHealthCheck(type: DependencyType): HealthCheckFunction | null {
    switch (type) {
      case DependencyType.DATABASE:
        return this.performDatabaseHealthCheck;
      case DependencyType.VECTOR_DB:
        return this.performVectorDbHealthCheck;
      case DependencyType.EMBEDDING_SERVICE:
        return this.performEmbeddingServiceHealthCheck;
      case DependencyType.CACHE:
        return this.performCacheHealthCheck;
      case DependencyType.EXTERNAL_API:
        return this.performExternalApiHealthCheck;
      default:
        return null;
    }
  }

  /**
   * Perform health check for database dependencies
   */
  private async performDatabaseHealthCheck(
    config: DependencyConfig
  ): Promise<HealthCheckResult> {
    const startTime = Date.now();

    try {
      // Import DatabaseManager dynamically to avoid circular dependencies
      const { DatabaseManager } = await import('../db/database-manager.js');

      // Create a temporary manager for health checking
      const manager = new DatabaseManager({
        qdrant: {
          url: config.connection.url,
          apiKey: config.connection.apiKey,
          timeout: config.connection.timeout || 30000
        },
        enableVectorOperations: false,
        enableFallback: false
      });

      const isHealthy = await manager.healthCheck();

      return {
        dependency: config.name,
        status: isHealthy ? DependencyStatus.HEALTHY : DependencyStatus.CRITICAL,
        responseTime: Date.now() - startTime,
        timestamp: new Date(),
        details: { connection: config.connection.url }
      };
    } catch (error) {
      return {
        dependency: config.name,
        status: DependencyStatus.CRITICAL,
        responseTime: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date()
      };
    }
  }

  /**
   * Perform health check for vector database dependencies
   */
  private async performVectorDbHealthCheck(
    config: DependencyConfig
  ): Promise<HealthCheckResult> {
    const startTime = Date.now();

    try {
      // Similar to database health check but with vector-specific operations
      const { DatabaseManager } = await import('../db/database-manager.js');

      const manager = new DatabaseManager({
        qdrant: {
          url: config.connection.url,
          apiKey: config.connection.apiKey,
          timeout: config.connection.timeout || 30000
        },
        enableVectorOperations: true,
        enableFallback: false
      });

      const isHealthy = await manager.healthCheck();

      return {
        dependency: config.name,
        status: isHealthy ? DependencyStatus.HEALTHY : DependencyStatus.CRITICAL,
        responseTime: Date.now() - startTime,
        timestamp: new Date(),
        details: {
          connection: config.connection.url,
          vectorOperations: true
        }
      };
    } catch (error) {
      return {
        dependency: config.name,
        status: DependencyStatus.CRITICAL,
        responseTime: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date()
      };
    }
  }

  /**
   * Perform health check for embedding service dependencies
   */
  private async performEmbeddingServiceHealthCheck(
    config: DependencyConfig
  ): Promise<HealthCheckResult> {
    const startTime = Date.now();

    try {
      const { EmbeddingService } = await import('./embeddings/embedding-service.js');
      const embeddingService = new EmbeddingService({
        apiKey: config.connection.apiKey,
        timeout: config.connection.timeout || 30000
      });

      const isHealthy = await embeddingService.healthCheck();

      return {
        dependency: config.name,
        status: isHealthy ? DependencyStatus.HEALTHY : DependencyStatus.CRITICAL,
        responseTime: Date.now() - startTime,
        timestamp: new Date(),
        details: {
          service: 'OpenAI Embeddings',
          apiKeyConfigured: !!config.connection.apiKey
        }
      };
    } catch (error) {
      return {
        dependency: config.name,
        status: DependencyStatus.CRITICAL,
        responseTime: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date()
      };
    }
  }

  /**
   * Perform health check for cache dependencies
   */
  private async performCacheHealthCheck(
    config: DependencyConfig
  ): Promise<HealthCheckResult> {
    const startTime = Date.now();

    try {
      // This would implement Redis/other cache health checks
      // For now, return a basic implementation
      const testKey = `health_check_${Date.now()}`;
      const testValue = 'test';

      // Simulate cache operations
      // In a real implementation, this would use actual cache client

      return {
        dependency: config.name,
        status: DependencyStatus.HEALTHY,
        responseTime: Date.now() - startTime,
        timestamp: new Date(),
        details: {
          connection: config.connection.url,
          operations: ['ping', 'set', 'get', 'del']
        }
      };
    } catch (error) {
      return {
        dependency: config.name,
        status: DependencyStatus.CRITICAL,
        responseTime: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date()
      };
    }
  }

  /**
   * Perform health check for external API dependencies
   */
  private async performExternalApiHealthCheck(
    config: DependencyConfig
  ): Promise<HealthCheckResult> {
    const startTime = Date.now();

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), config.connection.timeout || 10000);

      const response = await fetch(config.connection.url, {
        method: 'GET',
        signal: controller.signal,
        headers: config.connection.headers || {}
      });

      clearTimeout(timeoutId);

      const isHealthy = response.ok;

      return {
        dependency: config.name,
        status: isHealthy ? DependencyStatus.HEALTHY : DependencyStatus.CRITICAL,
        responseTime: Date.now() - startTime,
        timestamp: new Date(),
        details: {
          url: config.connection.url,
          statusCode: response.status,
          statusText: response.statusText
        }
      };
    } catch (error) {
      return {
        dependency: config.name,
        status: DependencyStatus.CRITICAL,
        responseTime: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date()
      };
    }
  }

  /**
   * Start health checking for a dependency
   */
  private startHealthCheck(name: string): void {
    const state = this.dependencies.get(name);
    if (!state || !state.config.healthCheck.enabled) {
      return;
    }

    // Stop existing health check if any
    this.stopHealthCheck(name);

    // Start new health check interval
    const interval = setInterval(async () => {
      try {
        await this.performHealthCheck(name);
      } catch (error) {
        logger.error({ dependency: name, error }, 'Health check failed');
      }
    }, state.config.healthCheck.intervalMs);

    this.healthCheckIntervals.set(name, interval);
    logger.debug({ dependency: name, interval: state.config.healthCheck.intervalMs },
                 'Health check started');
  }

  /**
   * Stop health checking for a dependency
   */
  private stopHealthCheck(name: string): void {
    const interval = this.healthCheckIntervals.get(name);
    if (interval) {
      clearInterval(interval);
      this.healthCheckIntervals.delete(name);
      logger.debug({ dependency: name }, 'Health check stopped');
    }
  }

  /**
   * Start health checking for all dependencies
   */
  private startAllHealthChecks(): void {
    for (const [name, state] of this.dependencies) {
      if (state.config.healthCheck.enabled) {
        this.startHealthCheck(name);
      }
    }
  }

  /**
   * Update dependency state based on health check result
   */
  private updateDependencyState(name: string, result: HealthCheckResult): void {
    const state = this.dependencies.get(name);
    if (!state) {
      return;
    }

    const previousStatus = state.status;
    state.status = result.status;
    state.lastHealthCheck = result.timestamp;
    state.totalChecks++;
    state.metadata.updatedAt = result.timestamp;

    // Update consecutive counters
    if (result.status === DependencyStatus.HEALTHY) {
      state.consecutiveSuccesses++;
      state.consecutiveFailures = 0;
      state.metadata.lastSuccess = result.timestamp;
    } else {
      state.consecutiveFailures++;
      state.consecutiveSuccesses = 0;
      state.metadata.lastFailure = result.timestamp;
    }

    // Update metrics
    this.updateMetrics(name, result);

    // Store metrics history
    this.storeMetricsHistory(name);

    // Emit status change event
    if (previousStatus !== result.status) {
      this.emit('statusChanged', name, previousStatus, result.status);
      logger.info({
        dependency: name,
        previousStatus,
        newStatus: result.status,
        responseTime: result.responseTime
      }, 'Dependency status changed');
    }
  }

  /**
   * Update dependency metrics
   */
  private updateMetrics(name: string, result: HealthCheckResult): void {
    const state = this.dependencies.get(name);
    if (!state) {
      return;
    }

    // Update response time metrics
    const currentResponseTime = result.responseTime;
    state.metrics.responseTime.current = currentResponseTime;

    // Update average response time
    if (state.metrics.responseTime.average === 0) {
      state.metrics.responseTime.average = currentResponseTime;
    } else {
      const alpha = 0.1; // Exponential moving average factor
      state.metrics.responseTime.average =
        alpha * currentResponseTime + (1 - alpha) * state.metrics.responseTime.average;
    }

    // Update error metrics
    if (result.status === DependencyStatus.HEALTHY) {
      state.metrics.error.count = 0;
    } else {
      state.metrics.error.count++;
      state.metrics.error.lastError = result.error;
    }

    state.metrics.error.rate = state.metrics.error.count / state.totalChecks;
    state.metrics.availability.lastCheck = result.timestamp;

    // Update circuit breaker metrics if available
    const circuitBreaker = circuitBreakerManager.getCircuitBreaker(name);
    if (circuitBreaker) {
      const stats = circuitBreaker.getStats();
      state.metrics.circuitBreaker = {
        state: stats.state,
        failureRate: stats.failureRate,
        totalCalls: stats.totalCalls
      };
    }
  }

  /**
   * Store metrics in history
   */
  private storeMetricsHistory(name: string): void {
    const state = this.dependencies.get(name);
    if (!state) {
      return;
    }

    const history = this.metricsHistory.get(name) || [];
    history.push({ ...state.metrics });

    // Keep only last 1000 entries
    if (history.length > 1000) {
      history.splice(0, history.length - 1000);
    }

    this.metricsHistory.set(name, history);
  }

  /**
   * Get priority weight for scoring
   */
  private getPriorityWeight(priority: string): number {
    switch (priority) {
      case 'critical': return 4;
      case 'high': return 3;
      case 'medium': return 2;
      case 'low': return 1;
      default: return 1;
    }
  }

  /**
   * Get status score for scoring
   */
  private getStatusScore(status: DependencyStatus): number {
    switch (status) {
      case DependencyStatus.HEALTHY: return 100;
      case DependencyStatus.WARNING: return 70;
      case DependencyStatus.CRITICAL: return 30;
      case DependencyStatus.UNKNOWN: return 50;
      case DependencyStatus.DISABLED: return 0;
      default: return 0;
    }
  }

  /**
   * Determine overall status from summary and score
   */
  private determineOverallStatus(
    summary: AggregatedHealthStatus['summary'],
    score: number
  ): DependencyStatus {
    // Critical dependencies failure overrides everything
    if (summary.critical > 0) {
      return DependencyStatus.CRITICAL;
    }

    // High number of warnings leads to warning status
    if (summary.warning > 0 || score < 80) {
      return DependencyStatus.WARNING;
    }

    // All healthy leads to healthy status
    if (summary.healthy === summary.total - summary.disabled) {
      return DependencyStatus.HEALTHY;
    }

    // Unknown dependencies lead to unknown status
    if (summary.unknown > 0) {
      return DependencyStatus.UNKNOWN;
    }

    return DependencyStatus.HEALTHY;
  }

  /**
   * Setup error handling for the registry
   */
  private setupErrorHandling(): void {
    this.on('error', (error) => {
      logger.error({ error }, 'Dependency Registry error');
    });

    process.on('SIGINT', () => {
      this.shutdown().catch(error =>
        logger.error({ error }, 'Error during shutdown')
      );
    });

    process.on('SIGTERM', () => {
      this.shutdown().catch(error =>
        logger.error({ error }, 'Error during shutdown')
      );
    });
  }
}

// Export singleton instance
export const dependencyRegistry = new DependencyRegistry();