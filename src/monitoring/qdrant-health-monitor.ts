
// @ts-nocheck - Emergency rollback: Critical monitoring service
/**
 * Enhanced Qdrant Health Monitor
 *
 * Comprehensive monitoring system for Qdrant vector database with detailed connectivity
 * checks, performance metrics, and health status tracking. Supports proactive monitoring
 * and automated recovery detection.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { EventEmitter } from 'events';

import { logger } from '@/utils/logger.js';

import { CircuitBreaker } from '../services/circuit-breaker.service.js';
import { DependencyType,HealthStatus } from '../types/unified-health-interfaces.js';

/**
 * Qdrant connection status types
 */
export enum QdrantConnectionStatus {
  CONNECTED = 'connected',
  DISCONNECTED = 'disconnected',
  CONNECTING = 'connecting',
  ERROR = 'error',
  TIMEOUT = 'timeout',
  AUTHENTICATION_FAILED = 'authentication_failed',
  RATE_LIMITED = 'rate_limited',
}

/**
 * Qdrant performance metrics
 */
export interface QdrantPerformanceMetrics {
  // Connection metrics
  connectionTime: number;              // Time to establish connection (ms)
  lastConnectionTime: number;          // Timestamp of last connection
  totalConnections: number;            // Total connection attempts
  successfulConnections: number;       // Successful connections
  failedConnections: number;           // Failed connections

  // Request metrics
  requestsPerSecond: number;           // Current request rate
  averageResponseTime: number;         // Average response time (ms)
  p95ResponseTime: number;             // 95th percentile response time
  p99ResponseTime: number;             // 99th percentile response time
  totalRequests: number;               // Total requests made
  successfulRequests: number;          // Successful requests
  failedRequests: number;              // Failed requests

  // Vector operation metrics
  vectorUpsertsPerSecond: number;      // Vector upsert rate
  vectorSearchesPerSecond: number;     // Vector search rate
  averageVectorUpsertTime: number;     // Average upsert time (ms)
  averageVectorSearchTime: number;     // Average search time (ms)
  vectorOperationSuccessRate: number;  // Success rate for vector ops

  // Database metrics
  collectionCount: number;             // Number of collections
  totalVectors: number;                // Total vectors across all collections
  memoryUsage: number;                 // Memory usage in bytes
  diskUsage: number;                   // Disk usage in bytes
  indexStatus: Record<string, string>; // Status of indexes per collection

  // Error metrics
  errorRate: number;                   // Overall error rate (percentage)
  timeOutRate: number;                 // Timeout rate (percentage)
  authenticationErrors: number;        // Authentication error count
  networkErrors: number;               // Network error count
  rateLimitErrors: number;             // Rate limit error count
}

/**
 * Qdrant health check result
 */
export interface QdrantHealthCheckResult {
  status: HealthStatus;
  connectionStatus: QdrantConnectionStatus;
  timestamp: Date;
  responseTime: number;
  error?: string;
  metrics: QdrantPerformanceMetrics;
  details: {
    version: string;
    collections: Array<{
      name: string;
      vectors: number;
      status: string;
      indexerStatus: string;
    }>;
    systemInfo: {
      uptime: number;
      memory: number;
      cpu: number;
      disk: number;
    };
  };
}

/**
 * Qdrant health monitor configuration
 */
export interface QdrantHealthMonitorConfig {
  // Connection configuration
  url: string;
  apiKey?: string;
  timeoutMs: number;
  retryAttempts: number;
  retryDelayMs: number;

  // Health check configuration
  healthCheckIntervalMs: number;
  metricsCollectionIntervalMs: number;
  connectionTestIntervalMs: number;

  // Performance thresholds
  thresholds: {
    responseTimeWarning: number;      // milliseconds
    responseTimeCritical: number;     // milliseconds
    errorRateWarning: number;         // percentage
    errorRateCritical: number;        // percentage
    connectionTimeWarning: number;    // milliseconds
    connectionTimeCritical: number;   // milliseconds
    memoryUsageWarning: number;       // percentage
    memoryUsageCritical: number;      // percentage
    diskUsageWarning: number;         // percentage
    diskUsageCritical: number;        // percentage
  };

  // Circuit breaker configuration
  circuitBreaker: {
    enabled: boolean;
    failureThreshold: number;
    recoveryTimeoutMs: number;
    monitoringWindowMs: number;
  };

  // Alerts configuration
  alerts: {
    enabled: boolean;
    consecutiveFailuresThreshold: number;
    performanceDegradationThreshold: number; // percentage
  };
}

/**
 * Qdrant Health Monitor
 */
export class QdrantHealthMonitor extends EventEmitter {
  private config: QdrantHealthMonitorConfig;
  private circuitBreaker: CircuitBreaker | null = null;
  private isRunning = false;
  private startTime: number;

  // State tracking
  private currentStatus: HealthStatus = HealthStatus.UNKNOWN;
  private currentConnectionStatus: QdrantConnectionStatus = QdrantConnectionStatus.DISCONNECTED;
  private currentMetrics: QdrantPerformanceMetrics;
  private lastHealthCheck: Date | null = null;
  private consecutiveFailures = 0;
  private consecutiveSuccesses = 0;

  // Intervals
  private healthCheckInterval: NodeJS.Timeout | null = null;
  private metricsCollectionInterval: NodeJS.Timeout | null = null;
  private connectionTestInterval: NodeJS.Timeout | null = null;

  // Performance tracking
  private responseTimeHistory: number[] = [];
  private requestHistory: Array<{ timestamp: number; success: boolean; responseTime: number }> = [];
  private connectionHistory: Array<{ timestamp: number; success: boolean; connectionTime: number }> = [];

  constructor(config: Partial<QdrantHealthMonitorConfig>) {
    super();

    // Default configuration
    const defaultConfig: QdrantHealthMonitorConfig = {
      // Required connection config
      url: 'http://localhost:6333',

      // Connection config with defaults
      timeoutMs: 10000,
      retryAttempts: 3,
      retryDelayMs: 1000,

      // Health check config with defaults
      healthCheckIntervalMs: 30000,
      metricsCollectionIntervalMs: 10000,
      connectionTestIntervalMs: 60000,

      // Circuit breaker config with defaults
      circuitBreaker: {
        enabled: true,
        failureThreshold: 5,
        recoveryTimeoutMs: 60000,
        monitoringWindowMs: 300000,
      },

      // Alerts config with defaults
      alerts: {
        enabled: true,
        consecutiveFailuresThreshold: 3,
        performanceDegradationThreshold: 25,
      },

      // Performance thresholds with defaults
      thresholds: {
        responseTimeWarning: 1000,
        responseTimeCritical: 5000,
        errorRateWarning: 5,
        errorRateCritical: 15,
        connectionTimeWarning: 2000,
        connectionTimeCritical: 10000,
        memoryUsageWarning: 80,
        memoryUsageCritical: 95,
        diskUsageWarning: 85,
        diskUsageCritical: 95,
      },
    };

    // Deep merge the configuration to avoid duplicates
    this.config = {
      ...defaultConfig,
      url: config.url || defaultConfig.url,
      apiKey: config.apiKey,
      timeoutMs: config.timeoutMs ?? defaultConfig.timeoutMs,
      retryAttempts: config.retryAttempts ?? defaultConfig.retryAttempts,
      retryDelayMs: config.retryDelayMs ?? defaultConfig.retryDelayMs,
      healthCheckIntervalMs: config.healthCheckIntervalMs ?? defaultConfig.healthCheckIntervalMs,
      metricsCollectionIntervalMs: config.metricsCollectionIntervalMs ?? defaultConfig.metricsCollectionIntervalMs,
      connectionTestIntervalMs: config.connectionTestIntervalMs ?? defaultConfig.connectionTestIntervalMs,
      circuitBreaker: {
        ...defaultConfig.circuitBreaker,
        ...config.circuitBreaker,
      },
      alerts: {
        ...defaultConfig.alerts,
        ...config.alerts,
      },
      thresholds: {
        ...defaultConfig.thresholds,
        ...config.thresholds,
      },
    };

    this.startTime = Date.now();
    this.currentMetrics = this.getInitialMetrics();

    // Initialize circuit breaker if enabled
    if (this.config.circuitBreaker.enabled) {
      this.circuitBreaker = new CircuitBreaker('qdrant-health-monitor', {
        failureThreshold: this.config.circuitBreaker.failureThreshold,
        recoveryTimeoutMs: this.config.circuitBreaker.recoveryTimeoutMs,
        monitoringWindowMs: this.config.circuitBreaker.monitoringWindowMs,
        failureRateThreshold: 0.5,
        minimumCalls: 5,
        trackFailureTypes: true,
        enablePerformanceLogging: true,
        enableSLOAnnotations: true,
      });
    }
  }

  /**
   * Start health monitoring
   */
  start(): void {
    if (this.isRunning) {
      logger.warn('Qdrant health monitor is already running');
      return;
    }

    this.isRunning = true;

    // Start health checks
    this.healthCheckInterval = setInterval(
      () => this.performHealthCheck(),
      this.config.healthCheckIntervalMs
    );

    // Start metrics collection
    this.metricsCollectionInterval = setInterval(
      () => this.collectMetrics(),
      this.config.metricsCollectionIntervalMs
    );

    // Start connection tests
    this.connectionTestInterval = setInterval(
      () => this.testConnection(),
      this.config.connectionTestIntervalMs
    );

    // Perform initial checks
    this.performHealthCheck();
    this.testConnection();

    logger.info(
      {
        url: this.config.url,
        healthCheckInterval: this.config.healthCheckIntervalMs,
        metricsCollectionInterval: this.config.metricsCollectionIntervalMs,
      },
      'Qdrant health monitor started'
    );

    this.emit('started');
  }

  /**
   * Stop health monitoring
   */
  stop(): void {
    if (!this.isRunning) {
      logger.warn('Qdrant health monitor is not running');
      return;
    }

    this.isRunning = false;

    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }

    if (this.metricsCollectionInterval) {
      clearInterval(this.metricsCollectionInterval);
      this.metricsCollectionInterval = null;
    }

    if (this.connectionTestInterval) {
      clearInterval(this.connectionTestInterval);
      this.connectionTestInterval = null;
    }

    logger.info('Qdrant health monitor stopped');
    this.emit('stopped');
  }

  /**
   * Get current health status
   */
  getCurrentStatus(): HealthStatus {
    return this.currentStatus;
  }

  /**
   * Get current connection status
   */
  getCurrentConnectionStatus(): QdrantConnectionStatus {
    return this.currentConnectionStatus;
  }

  /**
   * Get current metrics
   */
  getCurrentMetrics(): QdrantPerformanceMetrics {
    return { ...this.currentMetrics };
  }

  /**
   * Perform comprehensive health check
   */
  private async performHealthCheck(): Promise<QdrantHealthCheckResult> {
    const startTime = Date.now();

    try {
      const result = await this.executeWithCircuitBreaker(
        () => this.checkQdrantHealth(),
        'health-check'
      );

      this.lastHealthCheck = new Date();
      this.updateHealthState(result.status);

      this.emit('health_check', result);
      return result;

    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      logger.error({ error: errorMsg }, 'Qdrant health check failed');

      const result: QdrantHealthCheckResult = {
        status: HealthStatus.UNHEALTHY,
        connectionStatus: QdrantConnectionStatus.ERROR,
        timestamp: new Date(),
        responseTime: Date.now() - startTime,
        error: errorMsg,
        metrics: this.currentMetrics,
        details: {
          version: 'unknown',
          collections: [],
          systemInfo: {
            uptime: 0,
            memory: 0,
            cpu: 0,
            disk: 0,
          },
        },
      };

      this.updateHealthState(HealthStatus.UNHEALTHY);
      this.emit('health_check', result);
      this.emit('health_check_error', error);

      return result;
    }
  }

  /**
   * Test Qdrant connection
   */
  private async testConnection(): Promise<void> {
    const startTime = Date.now();
    try {
      const result = await this.executeWithCircuitBreaker(
        () => this.pingQdrant(),
        'connection-test'
      );

      const connectionTime = Date.now() - this.startTime;

      this.connectionHistory.push({
        timestamp: Date.now(),
        success: result,
        connectionTime,
      });

      // Keep only last 100 connection attempts
      if (this.connectionHistory.length > 100) {
        this.connectionHistory = this.connectionHistory.slice(-100);
      }

      this.updateConnectionMetrics(result, connectionTime);
      this.emit('connection_test', { success: result, connectionTime });

    } catch (error) {
      const connectionTime = Date.now() - this.startTime;

      this.connectionHistory.push({
        timestamp: Date.now(),
        success: false,
        connectionTime,
      });

      this.updateConnectionMetrics(false, connectionTime);
      this.emit('connection_test', { success: false, connectionTime, error });
    }
  }

  /**
   * Collect performance metrics
   */
  private async collectMetrics(): Promise<void> {
    try {
      const metrics = await this.executeWithCircuitBreaker(
        () => this.getQdrantMetrics(),
        'metrics-collection'
      );

      Object.assign(this.currentMetrics, metrics);
      this.emit('metrics_collected', this.currentMetrics);

    } catch (error) {
      logger.warn({ error }, 'Failed to collect Qdrant metrics');
      this.emit('metrics_collection_error', error);
    }
  }

  /**
   * Check Qdrant health endpoint
   */
  private async checkQdrantHealth(): Promise<QdrantHealthCheckResult> {
    const startTime = Date.now();
    const response = await this.makeQdrantRequest('/health');
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      throw new Error(`Qdrant health check failed: ${response.status} ${response.statusText}`);
    }

    const healthData = await response.json();

    // Get detailed metrics
    const metrics = await this.getQdrantMetrics();
    const collections = await this.getCollectionsInfo();
    const systemInfo = await this.getSystemInfo();

    // Determine health status
    let status = HealthStatus.HEALTHY;
    const connectionStatus = QdrantConnectionStatus.CONNECTED;
    const issues: string[] = [];

    // Check response time
    if (responseTime > this.config.thresholds.responseTimeCritical) {
      status = HealthStatus.UNHEALTHY;
      issues.push(`Critical response time: ${responseTime}ms`);
    } else if (responseTime > this.config.thresholds.responseTimeWarning) {
      status = HealthStatus.DEGRADED;
      issues.push(`High response time: ${responseTime}ms`);
    }

    // Check error rate
    if (metrics.errorRate && metrics.errorRate > this.config.thresholds.errorRateCritical) {
      status = HealthStatus.UNHEALTHY;
      issues.push(`Critical error rate: ${metrics.errorRate.toFixed(2)}%`);
    } else if (metrics.errorRate && metrics.errorRate > this.config.thresholds.errorRateWarning) {
      status = HealthStatus.DEGRADED;
      issues.push(`High error rate: ${metrics.errorRate.toFixed(2)}%`);
    }

    // Check memory usage
    const memoryUsagePercent = (systemInfo.memory / systemInfo.totalMemory) * 100;
    if (memoryUsagePercent > this.config.thresholds.memoryUsageCritical) {
      status = HealthStatus.UNHEALTHY;
      issues.push(`Critical memory usage: ${memoryUsagePercent.toFixed(2)}%`);
    } else if (memoryUsagePercent > this.config.thresholds.memoryUsageWarning) {
      status = HealthStatus.DEGRADED;
      issues.push(`High memory usage: ${memoryUsagePercent.toFixed(2)}%`);
    }

    // Check disk usage
    const diskUsagePercent = (systemInfo.disk / systemInfo.totalDisk) * 100;
    if (diskUsagePercent > this.config.thresholds.diskUsageCritical) {
      status = HealthStatus.UNHEALTHY;
      issues.push(`Critical disk usage: ${diskUsagePercent.toFixed(2)}%`);
    } else if (diskUsagePercent > this.config.thresholds.diskUsageWarning) {
      status = HealthStatus.DEGRADED;
      issues.push(`High disk usage: ${diskUsagePercent.toFixed(2)}%`);
    }

    // Create complete metrics object with defaults for missing properties
    const completeMetrics: QdrantPerformanceMetrics = {
      connectionTime: metrics.connectionTime || responseTime,
      lastConnectionTime: Date.now(),
      totalConnections: this.connectionHistory.length,
      successfulConnections: this.connectionHistory.filter(h => h.success).length,
      failedConnections: this.connectionHistory.filter(h => !h.success).length,
      requestsPerSecond: metrics.requestsPerSecond || 0,
      averageResponseTime: metrics.averageResponseTime || responseTime,
      p95ResponseTime: metrics.p95ResponseTime || responseTime,
      p99ResponseTime: metrics.p99ResponseTime || responseTime,
      totalRequests: metrics.totalRequests || 0,
      successfulRequests: metrics.successfulRequests || 0,
      failedRequests: metrics.failedRequests || 0,
      vectorUpsertsPerSecond: metrics.vectorUpsertsPerSecond || 0,
      vectorSearchesPerSecond: metrics.vectorSearchesPerSecond || 0,
      totalVectors: metrics.totalVectors || 0,
      memoryUsage: metrics.memoryUsage || systemInfo.memory,
      diskUsage: metrics.diskUsage || systemInfo.disk,
      errorRate: metrics.errorRate || 0,
      timeOutRate: metrics.timeOutRate || 0,
      authenticationErrors: metrics.authenticationErrors || 0,
      networkErrors: metrics.networkErrors || 0,
      rateLimitErrors: metrics.rateLimitErrors || 0,
      averageVectorUpsertTime: metrics.averageVectorUpsertTime || 0,
      averageVectorSearchTime: metrics.averageVectorSearchTime || 0,
      vectorOperationSuccessRate: metrics.vectorOperationSuccessRate || 100,
      collectionCount: metrics.collectionCount || 0,
      indexStatus: metrics.indexStatus || {},
      ...metrics,
    };

    return {
      status,
      connectionStatus,
      timestamp: new Date(),
      responseTime,
      metrics: completeMetrics,
      details: {
        version: healthData.version || 'unknown',
        collections,
        systemInfo,
      },
    };
  }

  /**
   * Ping Qdrant to test connectivity
   */
  private async pingQdrant(): Promise<boolean> {
    try {
      const response = await this.makeQdrantRequest('/health', { timeout: 5000 });
      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * Get detailed Qdrant metrics
   */
  private async getQdrantMetrics(): Promise<Partial<QdrantPerformanceMetrics>> {
    try {
      const response = await this.makeQdrantRequest('/metrics');
      const metricsText = await response.text();

      // Parse Prometheus metrics
      const metrics = this.parsePrometheusMetrics(metricsText);

      // Calculate derived metrics
      const now = Date.now();
      const recentRequests = this.requestHistory.filter(r => now - r.timestamp < 60000); // Last minute
      const requestsPerSecond = recentRequests.length / 60;

      const successfulRequests = recentRequests.filter(r => r.success).length;
      const errorRate = recentRequests.length > 0 ? ((recentRequests.length - successfulRequests) / recentRequests.length) * 100 : 0;

      const responseTimes = recentRequests.map(r => r.responseTime);
      const averageResponseTime = responseTimes.length > 0 ? responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length : 0;

      // Calculate percentiles
      const sortedTimes = responseTimes.sort((a, b) => a - b);
      const p95ResponseTime = this.calculatePercentile(sortedTimes, 0.95);
      const p99ResponseTime = this.calculatePercentile(sortedTimes, 0.99);

      return {
        requestsPerSecond,
        averageResponseTime,
        p95ResponseTime,
        p99ResponseTime,
        errorRate,
        totalRequests: this.requestHistory.length,
        successfulRequests,
        failedRequests: this.requestHistory.length - successfulRequests,
        ...metrics,
      };

    } catch (error) {
      logger.warn({ error }, 'Failed to get Qdrant metrics');
      return this.getBasicMetrics();
    }
  }

  /**
   * Get collections information
   */
  private async getCollectionsInfo(): Promise<Array<{
    name: string;
    vectors: number;
    status: string;
    indexerStatus: string;
  }>> {
    try {
      const response = await this.makeQdrantRequest('/collections');
      const data = await response.json();

      return (data.result?.collections || []).map((collection: unknown) => ({
        name: collection.name,
        vectors: collection.vectors_count || 0,
        status: collection.status || 'unknown',
        indexerStatus: collection.optimizer_status?.status || 'unknown',
      }));

    } catch (error) {
      logger.warn({ error }, 'Failed to get collections info');
      return [];
    }
  }

  /**
   * Get system information
   */
  private async getSystemInfo(): Promise<{
    uptime: number;
    memory: number;
    cpu: number;
    disk: number;
    totalMemory: number;
    totalDisk: number;
  }> {
    try {
      const response = await this.makeQdrantRequest('/telemetry');
      const data = await response.json();

      return {
        uptime: data.result?.uptime || 0,
        memory: data.result?.memory?.usage?.ram || 0,
        cpu: data.result?.cpu?.usage || 0,
        disk: data.result?.disk?.usage || 0,
        totalMemory: data.result?.memory?.total?.ram || 1,
        totalDisk: data.result?.disk?.total || 1,
      };

    } catch (error) {
      logger.warn({ error }, 'Failed to get system info');
      return {
        uptime: 0,
        memory: 0,
        cpu: 0,
        disk: 0,
        totalMemory: 1,
        totalDisk: 1,
      };
    }
  }

  /**
   * Make HTTP request to Qdrant
   */
  private async makeQdrantRequest(
    path: string,
    options: RequestInit & { timeout?: number } = {}
  ): Promise<Response> {
    const url = `${this.config.url}${path}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'Cortex-MCP-Health-Monitor/2.0.1',
    };

    if (this.config.apiKey) {
      headers['api_key'] = this.config.apiKey;
    }

    const controller = new AbortController();
    const timeoutMs = options.timeout || this.config.timeoutMs;
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Track request metrics
      this.requestHistory.push({
        timestamp: Date.now(),
        success: response.ok,
        responseTime: 0, // Will be calculated by caller
      });

      // Keep only last 1000 requests
      if (this.requestHistory.length > 1000) {
        this.requestHistory = this.requestHistory.slice(-1000);
      }

      return response;

    } catch (error) {
      clearTimeout(timeoutId);

      // Track failed request
      this.requestHistory.push({
        timestamp: Date.now(),
        success: false,
        responseTime: 0,
      });

      throw error;
    }
  }

  /**
   * Execute operation with circuit breaker
   */
  private async executeWithCircuitBreaker<T>(
    operation: () => Promise<T>,
    operationName: string
  ): Promise<T> {
    if (this.circuitBreaker) {
      return this.circuitBreaker.execute(operation, operationName);
    } else {
      return operation();
    }
  }

  /**
   * Update health state
   */
  private updateHealthState(status: HealthStatus): void {
    const previousStatus = this.currentStatus;
    this.currentStatus = status;

    if (status === HealthStatus.HEALTHY) {
      this.consecutiveSuccesses++;
      this.consecutiveFailures = 0;
      this.currentConnectionStatus = QdrantConnectionStatus.CONNECTED;
    } else {
      this.consecutiveFailures++;
      this.consecutiveSuccesses = 0;
      this.currentConnectionStatus = this.mapHealthStatusToConnectionStatus(status);
    }

    // Emit status change events
    if (previousStatus !== status) {
      logger[status === HealthStatus.HEALTHY ? 'info' : 'warn'](
        {
          previousStatus,
          newStatus: status,
          consecutiveFailures: this.consecutiveFailures,
          consecutiveSuccesses: this.consecutiveSuccesses,
        },
        `Qdrant health status changed from ${previousStatus} to ${status}`
      );

      this.emit('status_change', { previous: previousStatus, current: status });
    }

    // Emit alerts if thresholds exceeded
    if (this.config.alerts.enabled) {
      if (this.consecutiveFailures >= this.config.alerts.consecutiveFailuresThreshold) {
        this.emit('alert', {
          type: 'consecutive_failures',
          severity: 'critical',
          message: `Qdrant has failed ${this.consecutiveFailures} consecutive health checks`,
          count: this.consecutiveFailures,
        });
      }
    }
  }

  /**
   * Update connection metrics
   */
  private updateConnectionMetrics(success: boolean, connectionTime: number): void {
    if (success) {
      this.currentMetrics.lastConnectionTime = Date.now();
      this.currentMetrics.connectionTime = connectionTime;
    }

    const recentConnections = this.connectionHistory.filter(c => Date.now() - c.timestamp < 300000); // Last 5 minutes
    this.currentMetrics.totalConnections = this.connectionHistory.length;
    this.currentMetrics.successfulConnections = this.connectionHistory.filter(c => c.success).length;
    this.currentMetrics.failedConnections = this.connectionHistory.length - this.currentMetrics.successfulConnections;

    // Calculate average connection time
    const successfulConnectionTimes = recentConnections.filter(c => c.success).map(c => c.connectionTime);
    this.currentMetrics.connectionTime = successfulConnectionTimes.length > 0
      ? successfulConnectionTimes.reduce((a, b) => a + b, 0) / successfulConnectionTimes.length
      : 0;
  }

  /**
   * Map health status to connection status
   */
  private mapHealthStatusToConnectionStatus(status: HealthStatus): QdrantConnectionStatus {
    switch (status) {
      case HealthStatus.HEALTHY:
        return QdrantConnectionStatus.CONNECTED;
      case HealthStatus.DEGRADED:
        return QdrantConnectionStatus.CONNECTING;
      case HealthStatus.UNHEALTHY:
      case HealthStatus.CRITICAL:
        return QdrantConnectionStatus.ERROR;
      default:
        return QdrantConnectionStatus.DISCONNECTED;
    }
  }

  /**
   * Parse Prometheus metrics text
   */
  private parsePrometheusMetrics(metricsText: string): Partial<QdrantPerformanceMetrics> {
    const metrics: Partial<QdrantPerformanceMetrics> = {};
    const lines = metricsText.split('\n');

    for (const line of lines) {
      if (line.startsWith('#') || !line.trim()) continue;

      const [name, value] = line.split(' ');
      if (!value) continue;

      switch (name) {
        case 'qdrant_collections_total':
          metrics.collectionCount = parseInt(value);
          break;
        case 'qdrant_vectors_total':
          metrics.totalVectors = parseInt(value);
          break;
        case 'qdrant_memory_usage_bytes':
          metrics.memoryUsage = parseInt(value);
          break;
        case 'qdrant_disk_usage_bytes':
          metrics.diskUsage = parseInt(value);
          break;
      }
    }

    return metrics;
  }

  /**
   * Calculate percentile from sorted array
   */
  private calculatePercentile(sortedArray: number[], percentile: number): number {
    if (sortedArray.length === 0) return 0;

    const index = Math.ceil(sortedArray.length * percentile) - 1;
    return sortedArray[Math.max(0, Math.min(index, sortedArray.length - 1))];
  }

  /**
   * Get initial metrics
   */
  private getInitialMetrics(): QdrantPerformanceMetrics {
    return {
      connectionTime: 0,
      lastConnectionTime: 0,
      totalConnections: 0,
      successfulConnections: 0,
      failedConnections: 0,
      requestsPerSecond: 0,
      averageResponseTime: 0,
      p95ResponseTime: 0,
      p99ResponseTime: 0,
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      vectorUpsertsPerSecond: 0,
      vectorSearchesPerSecond: 0,
      averageVectorUpsertTime: 0,
      averageVectorSearchTime: 0,
      vectorOperationSuccessRate: 100,
      collectionCount: 0,
      totalVectors: 0,
      memoryUsage: 0,
      diskUsage: 0,
      indexStatus: {},
      errorRate: 0,
      timeOutRate: 0,
      authenticationErrors: 0,
      networkErrors: 0,
      rateLimitErrors: 0,
    };
  }

  /**
   * Get basic metrics when detailed collection fails
   */
  private getBasicMetrics(): Partial<QdrantPerformanceMetrics> {
    const now = Date.now();
    const recentRequests = this.requestHistory.filter(r => now - r.timestamp < 60000);
    const requestsPerSecond = recentRequests.length / 60;

    const successfulRequests = recentRequests.filter(r => r.success).length;
    const errorRate = recentRequests.length > 0 ? ((recentRequests.length - successfulRequests) / recentRequests.length) * 100 : 0;

    return {
      requestsPerSecond,
      errorRate,
      totalRequests: this.requestHistory.length,
      successfulRequests,
      failedRequests: this.requestHistory.length - successfulRequests,
    };
  }

  /**
   * Get circuit breaker status
   */
  getCircuitBreakerStatus() {
    if (!this.circuitBreaker) return null;

    return {
      isOpen: this.circuitBreaker.isOpen(),
      isHalfOpen: this.circuitBreaker.isHalfOpen(),
      stats: this.circuitBreaker.getStats(),
    };
  }

  /**
   * Get connection history
   */
  getConnectionHistory(limit?: number): Array<{
    timestamp: number;
    success: boolean;
    connectionTime: number;
  }> {
    const history = [...this.connectionHistory].reverse(); // Most recent first
    return limit ? history.slice(0, limit) : history;
  }

  /**
   * Get request history
   */
  getRequestHistory(limit?: number): Array<{
    timestamp: number;
    success: boolean;
    responseTime: number;
  }> {
    const history = [...this.requestHistory].reverse(); // Most recent first
    return limit ? history.slice(0, limit) : history;
  }

  /**
   * Public health check method for graceful degradation manager
   */
  public async healthCheck(): Promise<boolean> {
    try {
      const result = await this.performHealthCheck();
      return result.status === HealthStatus.HEALTHY;
    } catch {
      return false;
    }
  }
}

export default QdrantHealthMonitor;
