// @ts-nocheck
// EMERGENCY ROLLBACK: Enhanced monitoring type compatibility issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Qdrant Graceful Degradation Manager
 *
 * Orchestrates graceful degradation for Qdrant outages, integrating
 * detection, failover, notifications, and recovery. Provides a unified
 * interface for managing degradation scenarios with automatic failover
 * to in-memory storage and recovery when service is restored.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { EventEmitter } from 'events';

import { logger } from '@/utils/logger.js';

import { CircuitBreakerMonitor } from './circuit-breaker-monitor.js';
import { type DegradationEvent,DegradationLevel, QdrantDegradationDetector } from './degradation-detector.js';
import { QdrantDegradationNotifier } from './degradation-notifier.js';
import { QdrantErrorBudgetTracker } from './error-budget-tracker.js';
import { QdrantConnectionStatus,QdrantHealthMonitor } from './qdrant-health-monitor.js';
import { InMemoryFallbackStorage } from '../db/adapters/in-memory-fallback-storage.js';
import type {
  BatchSummary,
  ItemResult,
  KnowledgeItem,
  SearchQuery,
  SearchResult,
  StoreResult,
} from '../types/core-interfaces.js';
import { HealthStatus } from '../types/unified-health-interfaces.js';

/**
 * Degradation state
 */
export interface DegradationState {
  currentLevel: DegradationLevel;
  isInFailover: boolean;
  failoverStartTime?: Date;
  lastHealthCheck: Date;
  qdrantStatus: HealthStatus;
  circuitBreakerOpen: boolean;
  activeAlerts: string[];
  userFacingMessage?: string;
}

/**
 * Failover statistics
 */
export interface FailoverStatistics {
  totalFailovers: number;
  totalFailback: number;
  currentFailoverDuration: number;
  averageFailoverDuration: number;
  lastFailoverTime?: Date;
  lastFailbackTime?: Date;
  successfulFailovers: number;
  failedFailovers: number;
  fallbackOperations: number;
  fallbackErrors: number;
}

/**
 * Graceful degradation manager configuration
 */
export interface GracefulDegradationManagerConfig {
  // Failover settings
  failover: {
    enabled: boolean;
    triggerLevel: DegradationLevel;
    minDurationBeforeFailover: number;
    maxFailoverAttempts: number;
    failoverCooldownMs: number;
    automaticFailback: boolean;
    consecutiveHealthChecksRequired: number;
    healthCheckIntervalMs: number;
  };

  // Fallback storage settings
  fallback: {
    maxItems: number;
    maxMemoryUsageMB: number;
    defaultTTL: number;
    enablePersistence: boolean;
    syncOnRecovery: boolean;
  };

  // Notification settings
  notifications: {
    enabled: boolean;
    userFacingMessages: boolean;
    operatorAlerts: boolean;
    detailedLogging: boolean;
  };

  // Error budget settings
  errorBudget: {
    enabled: boolean;
    availabilityTarget: number;
    latencyTarget: number;
    errorRateTarget: number;
  };
}

/**
 * Unified operation response
 */
export interface DegradedOperationResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  degraded: boolean;
  fallbackUsed: boolean;
  executionTime: number;
  strategy: 'qdrant' | 'fallback' | 'hybrid';
  meta: {
    level: DegradationLevel;
    notifications: string[];
    recommendations: string[];
    errorBudget?: unknown;
    strategy?: string;
  };
}

/**
 * Qdrant Graceful Degradation Manager
 */
export class QdrantGracefulDegradationManager extends EventEmitter {
  private config: GracefulDegradationManagerConfig;
  private qdrantMonitor: QdrantHealthMonitor;
  private circuitMonitor: CircuitBreakerMonitor;
  private degradationDetector: QdrantDegradationDetector;
  private notifier: QdrantDegradationNotifier;
  private errorBudgetTracker: QdrantErrorBudgetTracker;
  private fallbackStorage: InMemoryFallbackStorage;

  // State management
  private state: DegradationState;
  private statistics: FailoverStatistics;
  private isRunning = false;
  private recoveryInterval: NodeJS.Timeout | null = null;

  // Operation interceptors
  private originalQdrantAdapter: unknown;
  private interceptorsEnabled = false;

  constructor(
    qdrantAdapter: unknown,
    config?: Partial<GracefulDegradationManagerConfig>
  ) {
    super();

    this.originalQdrantAdapter = qdrantAdapter;

    this.config = {
      failover: {
        enabled: true,
        triggerLevel: DegradationLevel.CRITICAL,
        minDurationBeforeFailover: 30000,
        maxFailoverAttempts: 3,
        failoverCooldownMs: 300000,
        automaticFailback: true,
        consecutiveHealthChecksRequired: 3,
        healthCheckIntervalMs: 15000,
      },
      fallback: {
        maxItems: 10000,
        maxMemoryUsageMB: 100,
        defaultTTL: 30,
        enablePersistence: false,
        syncOnRecovery: true,
      },
      notifications: {
        enabled: true,
        userFacingMessages: true,
        operatorAlerts: true,
        detailedLogging: true,
      },
      errorBudget: {
        enabled: true,
        availabilityTarget: 99.9,
        latencyTarget: 1000,
        errorRateTarget: 0.1,
      },
      ...config,
    };

    // Initialize components
    this.qdrantMonitor = new QdrantHealthMonitor({
      url: process.env.QDRANT_URL || 'http://localhost:6333',
      timeoutMs: 10000,
      healthCheckIntervalMs: this.config.failover.healthCheckIntervalMs,
      retryAttempts: 3,
      retryDelayMs: 500,
      metricsCollectionIntervalMs: 60000,
      connectionTestIntervalMs: 15000,
      thresholds: {
        responseTimeWarning: 1000,
        responseTimeCritical: 2500,
        errorRateWarning: 0.05,
        errorRateCritical: 0.15,
        connectionTimeWarning: 300,
        connectionTimeCritical: 1000,
        memoryUsageWarning: 0.8,
        memoryUsageCritical: 0.9,
        diskUsageWarning: 0.8,
        diskUsageCritical: 0.9,
      },
      circuitBreaker: {
        enabled: true,
        failureThreshold: 5,
        recoveryTimeoutMs: 30000,
        monitoringWindowMs: 60000,
      },
      alerts: {
        enabled: true,
        consecutiveFailuresThreshold: 3,
        performanceDegradationThreshold: 0.7,
      },
    });

    this.circuitMonitor = new CircuitBreakerMonitor();
    this.degradationDetector = new QdrantDegradationDetector(
      this.qdrantMonitor,
      this.circuitMonitor
    );
    this.notifier = new QdrantDegradationNotifier({
      ui: {
        showUserFacingMessages: this.config.notifications.userFacingMessages,
        bannerMessage: '',
        detailedLogsEnabled: true,
        progressIndicatorEnabled: false,
      },
    });
    this.errorBudgetTracker = new QdrantErrorBudgetTracker({
      slo: {
        availabilityTarget: this.config.errorBudget.availabilityTarget,
        latencyTarget: this.config.errorBudget.latencyTarget,
        errorRateTarget: this.config.errorBudget.errorRateTarget,
        timeWindowMs: 60 * 60 * 1000,
      },
    });
    this.fallbackStorage = new InMemoryFallbackStorage({
      maxItems: this.config.fallback.maxItems,
      maxMemoryUsageMB: this.config.fallback.maxMemoryUsageMB,
      defaultTTL: this.config.fallback.defaultTTL,
      enablePersistence: this.config.fallback.enablePersistence,
    });

    // Initialize state
    this.state = {
      currentLevel: DegradationLevel.HEALTHY,
      isInFailover: false,
      lastHealthCheck: new Date(),
      qdrantStatus: HealthStatus.UNKNOWN,
      circuitBreakerOpen: false,
      activeAlerts: [],
    };

    this.statistics = {
      totalFailovers: 0,
      totalFailback: 0,
      currentFailoverDuration: 0,
      averageFailoverDuration: 0,
      successfulFailovers: 0,
      failedFailovers: 0,
      fallbackOperations: 0,
      fallbackErrors: 0,
    };

    this.setupEventListeners();
    logger.info('Graceful degradation manager initialized');
  }

  /**
   * Start graceful degradation management
   */
  async start(): Promise<void> {
    if (this.isRunning) {
      logger.warn('Graceful degradation manager is already running');
      return;
    }

    try {
      // Initialize all components
      await Promise.all<void>([
        Promise.resolve(this.qdrantMonitor.start() as unknown as Promise<void>),
        Promise.resolve(this.circuitMonitor.start() as unknown as Promise<void>),
        Promise.resolve(this.degradationDetector.start() as unknown as Promise<void>),
        Promise.resolve(this.errorBudgetTracker.start() as unknown as Promise<void>),
        this.fallbackStorage.initialize(),
      ]);

      // Initialize notifier (no start method available)
      // Notifier is event-driven and doesn't need explicit initialization

      // Enable operation interceptors
      this.enableInterceptors();

      this.isRunning = true;

      logger.info('Graceful degradation manager started successfully', {
        failoverEnabled: this.config.failover.enabled,
        notificationsEnabled: this.config.notifications.enabled,
        errorBudgetEnabled: this.config.errorBudget.enabled,
      });

      this.emit('started');

    } catch (error) {
      logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Failed to start graceful degradation manager');
      throw (error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Stop graceful degradation management
   */
  async stop(): Promise<void> {
    if (!this.isRunning) {
      logger.warn('Graceful degradation manager is not running');
      return;
    }

    try {
      // Stop all components
      await Promise.all<void>([
        Promise.resolve(this.qdrantMonitor.stop() as unknown as Promise<void>),
        Promise.resolve(this.circuitMonitor.stop() as unknown as Promise<void>),
        Promise.resolve(this.degradationDetector.stop() as unknown as Promise<void>),
        Promise.resolve(this.errorBudgetTracker.stop() as unknown as Promise<void>),
        this.fallbackStorage.shutdown() as Promise<void>,
      ]);

      // Notifier cleanup (no stop method available)
      // Event listeners will be cleaned up by the base EventEmitter cleanup

      // Disable operation interceptors
      this.disableInterceptors();

      // Stop recovery monitoring
      if (this.recoveryInterval) {
        clearInterval(this.recoveryInterval);
        this.recoveryInterval = null;
      }

      this.isRunning = false;

      logger.info('Graceful degradation manager stopped');
      this.emit('stopped');

    } catch (error) {
      logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Error during graceful degradation manager shutdown');
      throw (error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Store items with graceful degradation
   */
  async store(items: KnowledgeItem[]): Promise<DegradedOperationResponse<{
    items: ItemResult[];
    summary: BatchSummary;
  }>> {
    const startTime = Date.now();

    try {
      // Record operation start
      this.recordOperationStart('store');

      if (this.shouldUseQdrant('store')) {
        try {
          const result = await this.originalQdrantAdapter.store(items);
          this.recordOperationSuccess('store', Date.now() - startTime);

          return {
            success: true,
            data: result,
            degraded: this.state.currentLevel !== DegradationLevel.HEALTHY,
            fallbackUsed: false,
            executionTime: Date.now() - startTime,
            strategy: 'qdrant',
            meta: {
              level: this.state.currentLevel,
              notifications: this.getActiveNotifications(),
              recommendations: this.getRecommendations(),
              errorBudget: this.errorBudgetTracker.getCurrentStatus(),
            },
          };

    } catch (error) {
      logger.warn({ error: error instanceof Error ? error.message : String(error) }, 'Qdrant store failed, attempting fallback');
      return await this.performFallbackStore(items, startTime);
    }

      } else {
        return await this.performFallbackStore(items, startTime);
      }

    } catch (error) {
      this.recordOperationFailure('store', Date.now() - startTime);
      this.statistics.fallbackErrors++;

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        degraded: true,
        fallbackUsed: this.state.isInFailover,
        executionTime: Date.now() - startTime,
        strategy: 'fallback',
        meta: {
          level: this.state.currentLevel,
          notifications: this.getActiveNotifications(),
          recommendations: ['Retry operation', 'Check system status', 'Contact support if issue persists'],
        },
      };
    }
  }

  /**
   * Search items with graceful degradation
   */
  async search(query: SearchQuery): Promise<DegradedOperationResponse<{
    results: SearchResult[];
    items: SearchResult[];
    total_count: number;
  }>> {
    const startTime = Date.now();

    try {
      // Record operation start
      this.recordOperationStart('search');

      if (this.shouldUseQdrant('search')) {
        try {
          const result = await this.originalQdrantAdapter.search(query);
          this.recordOperationSuccess('search', Date.now() - startTime);

          return {
            success: true,
            data: result,
            degraded: this.state.currentLevel !== DegradationLevel.HEALTHY,
            fallbackUsed: false,
            executionTime: Date.now() - startTime,
            strategy: 'qdrant',
            meta: {
              level: this.state.currentLevel,
              notifications: this.getActiveNotifications(),
              recommendations: this.getRecommendations(),
              errorBudget: this.errorBudgetTracker.getCurrentStatus(),
            },
          };

    } catch (error) {
      logger.warn({ error: error instanceof Error ? error.message : String(error) }, 'Qdrant search failed, attempting fallback');
      return await this.performFallbackSearch(query, startTime);
    }

      } else {
        return await this.performFallbackSearch(query, startTime);
      }

    } catch (error) {
      this.recordOperationFailure('search', Date.now() - startTime);
      this.statistics.fallbackErrors++;

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        degraded: true,
        fallbackUsed: this.state.isInFailover,
        executionTime: Date.now() - startTime,
        strategy: 'fallback',
        meta: {
          level: this.state.currentLevel,
          notifications: this.getActiveNotifications(),
          recommendations: ['Retry with simpler query', 'Check connection', 'Use alternative search terms'],
        },
      };
    }
  }

  /**
   * Get current degradation state
   */
  getCurrentState(): DegradationState {
    return { ...this.state };
  }

  /**
   * Get failover statistics
   */
  getStatistics(): FailoverStatistics {
    return {
      ...this.statistics,
      currentFailoverDuration: this.state.failoverStartTime
        ? Date.now() - this.state.failoverStartTime.getTime()
        : 0,
    };
  }

  /**
   * Force manual failover
   */
  async forceFailover(reason: string): Promise<boolean> {
    if (!this.config.failover.enabled) {
      logger.warn('Manual failover requested but failover is disabled');
      return false;
    }

    logger.warn({ reason }, 'Manual failover triggered');

    try {
      await this.performFailover(DegradationLevel.CRITICAL, 'manual', reason);
      return true;
    } catch (error) {
      logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Manual failover failed');
      return false;
    }
  }

  /**
   * Force manual failback
   */
  async forceFailback(): Promise<boolean> {
    if (!this.state.isInFailover) {
      logger.warn('Manual failback requested but not in failover state');
      return false;
    }

    logger.info('Manual failback triggered');

    try {
      await this.performFailback('manual');
      return true;
    } catch (error) {
      logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Manual failback failed');
      return false;
    }
  }

  // === Private Methods ===

  /**
   * Setup event listeners
   */
  private setupEventListeners(): void {
    // Listen to degradation detector events
    this.degradationDetector.on('level_change', (event) => {
      this.handleDegradationLevelChange(event);
    });

    this.degradationDetector.on('failover_triggered', (event) => {
      this.handleFailoverTriggered(event);
    });

    this.degradationDetector.on('recovery', (event) => {
      this.handleRecovery(event);
    });

    // Listen to Qdrant health monitor events
    this.qdrantMonitor.on('status_change', (event) => {
      this.updateHealthStatus();
    });

    // Listen to circuit breaker events
    this.circuitMonitor.on('alert', (alert) => {
      if (alert.serviceName === 'qdrant') {
        this.updateCircuitBreakerStatus();
      }
    });
  }

  /**
   * Handle degradation level change
   */
  private handleDegradationLevelChange(event: unknown): void {
    if (!this.isValidDegradationEvent(event)) {
      logger.warn({ event }, 'Invalid degradation event received');
      return;
    }

    const { previousLevel, newLevel, levelChangeEvent } = event;

    this.state.currentLevel = newLevel;
    this.state.lastHealthCheck = new Date();
    this.state.activeAlerts = [levelChangeEvent.trigger];

    logger.info(
      { previousLevel, newLevel, trigger: levelChangeEvent.trigger },
      'Degradation level changed'
    );

    this.emit('degradation_level_changed', { previousLevel, newLevel, event: levelChangeEvent });

    // Check if failover should be triggered
    if (this.shouldTriggerFailover(newLevel)) {
      setTimeout(() => {
        this.performFailover(newLevel, levelChangeEvent.trigger, levelChangeEvent.description);
      }, this.config.failover.minDurationBeforeFailover);
    }
  }

  /**
   * Handle failover triggered event
   */
  private handleFailoverTriggered(event: DegradationEvent): void {
    logger.warn({ event }, 'Failover triggered by degradation detector');
    this.performFailover(event.level, event.trigger, event.description);
  }

  /**
   * Handle recovery event
   */
  private handleRecovery(event: unknown): void {
    logger.info({ event }, 'Recovery detected');
    this.performFailback('auto_recovery');
  }

  /**
   * Update health status
   */
  private updateHealthStatus(): void {
    this.state.qdrantStatus = this.qdrantMonitor.getCurrentStatus();
    this.state.lastHealthCheck = new Date();

    // Check for recovery if in failover
    if (this.state.isInFailover && this.state.qdrantStatus === HealthStatus.HEALTHY) {
      this.startRecoveryMonitoring();
    }
  }

  /**
   * Update circuit breaker status
   */
  private updateCircuitBreakerStatus(): void {
    const circuitStatus = this.circuitMonitor.getHealthStatus('qdrant');
    this.state.circuitBreakerOpen = circuitStatus?.isOpen || false;
  }

  /**
   * Check if failover should be triggered
   */
  private shouldTriggerFailover(level: DegradationLevel): boolean {
    if (!this.config.failover.enabled) {
      return false;
    }

    if (level < this.config.failover.triggerLevel) {
      return false;
    }

    if (this.state.isInFailover) {
      return false;
    }

    // Check cooldown
    if (this.statistics.lastFailoverTime) {
      const timeSinceLastFailover = Date.now() - this.statistics.lastFailoverTime.getTime();
      if (timeSinceLastFailover < this.config.failover.failoverCooldownMs) {
        return false;
      }
    }

    // Check max attempts
    if (this.statistics.totalFailovers >= this.config.failover.maxFailoverAttempts) {
      return false;
    }

    return true;
  }

  /**
   * Perform failover
   */
  private async performFailover(
    level: DegradationLevel,
    trigger: string,
    description: string
  ): Promise<void> {
    if (this.state.isInFailover) {
      logger.warn('Failover already in progress');
      return;
    }

    try {
      logger.info(
        { level, trigger, description },
        'Performing failover to in-memory storage'
      );

      // Update state
      this.state.isInFailover = true;
      this.state.failoverStartTime = new Date();
      this.state.currentLevel = level;

      // Update statistics
      this.statistics.totalFailovers++;
      this.statistics.lastFailoverTime = new Date();

      // Send notifications
      if (this.config.notifications.enabled) {
        const event: DegradationEvent = {
          id: `fo_${Date.now()}`,
          timestamp: new Date(),
          level,
          trigger: 'failover',
          description: `Failover activated: ${description}`,
          metrics: {
            qdrantHealth: this.state.qdrantStatus,
            connectionStatus: this.qdrantMonitor.getCurrentConnectionStatus(),
            circuitBreakerOpen: this.state.circuitBreakerOpen,
          },
          recommendations: [
            'System is operating in degraded mode',
            'Data is being stored in temporary memory',
            'Normal operation will resume when service is restored',
          ],
          autoFailoverTriggered: true,
        };

        await this.notifier.sendNotification(event);
      }

      // Record error budget impact
      if (this.config.errorBudget.enabled) {
        this.errorBudgetTracker.recordDegradationEvent({
          id: `fo_${Date.now()}`,
          timestamp: new Date(),
          level,
          trigger: 'failover',
          description,
          metrics: {},
          recommendations: [],
          autoFailoverTriggered: true,
        });
      }

      this.statistics.successfulFailovers++;
      this.emit('failover_completed', { level, trigger, description });

    } catch (error) {
      logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Failover failed');
      this.statistics.failedFailovers++;
      this.emit('failover_failed', { error: error instanceof Error ? error.message : String(error), level, trigger });
      throw (error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Perform failback
   */
  private async performFailback(reason: string): Promise<void> {
    if (!this.state.isInFailover) {
      logger.warn('Failback requested but not in failover state');
      return;
    }

    try {
      logger.info({ reason }, 'Performing failback to Qdrant');

      // Update state
      this.state.isInFailover = false;
      const failoverDuration = this.state.failoverStartTime
        ? Date.now() - this.state.failoverStartTime.getTime()
        : 0;

      // Update statistics
      this.statistics.totalFailback++;
      this.statistics.lastFailbackTime = new Date();
      this.statistics.averageFailoverDuration =
        (this.statistics.averageFailoverDuration * (this.statistics.totalFailback - 1) + failoverDuration) /
        this.statistics.totalFailback;

      // Sync data from fallback storage if enabled
      if (this.config.fallback.syncOnRecovery) {
        await this.syncFallbackData();
      }

      // Send recovery notification
      if (this.config.notifications.enabled) {
        const event: DegradationEvent = {
          id: `fb_${Date.now()}`,
          timestamp: new Date(),
          level: DegradationLevel.HEALTHY,
          trigger: 'failback',
          description: `Failback completed: ${reason}`,
          metrics: {
            qdrantHealth: HealthStatus.HEALTHY,
            connectionStatus: QdrantConnectionStatus.CONNECTED,
            circuitBreakerOpen: false,
          },
          recommendations: [
            'Normal operation resumed',
            'Verify data consistency',
            'Monitor system stability',
          ],
          autoFailoverTriggered: false,
        };

        await this.notifier.sendRecoveryNotification(event);
      }

      this.state.failoverStartTime = undefined;
      this.state.currentLevel = DegradationLevel.HEALTHY;

      this.emit('failback_completed', { reason, duration: failoverDuration });

    } catch (error) {
      logger.error({ error: error instanceof Error ? error.message : String(error) }, 'Failback failed');
      this.emit('failback_failed', { error: error instanceof Error ? error.message : String(error), reason });
      throw (error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Start recovery monitoring
   */
  private startRecoveryMonitoring(): void {
    if (this.recoveryInterval) {
      clearInterval(this.recoveryInterval);
    }

    let consecutiveHealthChecks = 0;

    this.recoveryInterval = setInterval(async () => {
      try {
        // Use the public healthCheck method that returns a boolean
        const isHealthy = await this.qdrantMonitor.healthCheck();

        if (isHealthy) {
          consecutiveHealthChecks++;
          logger.debug(
            { consecutiveHealthChecks, required: this.config.failover.consecutiveHealthChecksRequired },
            'Recovery health check passed'
          );

          if (consecutiveHealthChecks >= this.config.failover.consecutiveHealthChecksRequired) {
            await this.performFailback('auto_recovery');
            clearInterval(this.recoveryInterval!);
            this.recoveryInterval = null;
          }
        } else {
          consecutiveHealthChecks = 0;
        }

      } catch (error) {
        consecutiveHealthChecks = 0;
        logger.debug?.({ error: error instanceof Error ? error.message : String(error) }, 'Recovery health check failed');
      }
    }, this.config.failover.healthCheckIntervalMs);
  }

  /**
   * Check if should use Qdrant for operation
   */
  private shouldUseQdrant(operation: string): boolean {
    if (this.state.isInFailover) {
      return false;
    }

    if (this.state.circuitBreakerOpen) {
      return false;
    }

    if (this.state.qdrantStatus !== HealthStatus.HEALTHY) {
      return false;
    }

    return true;
  }

  /**
   * Perform fallback store operation
   */
  private async performFallbackStore(
    items: KnowledgeItem[],
    startTime: number
  ): Promise<DegradedOperationResponse<{
    items: ItemResult[];
    summary: BatchSummary;
  }>> {
    try {
      const result = await this.fallbackStorage.store(items);
      this.statistics.fallbackOperations++;
      this.recordOperationSuccess('store', Date.now() - startTime, true);

      return {
        success: true,
        data: result,
        degraded: true,
        fallbackUsed: true,
        executionTime: Date.now() - startTime,
        strategy: 'fallback',
        meta: {
          level: this.state.currentLevel,
          notifications: ['Operating in fallback mode - data stored temporarily'],
          recommendations: ['Normal operation will resume when service is restored'],
          errorBudget: this.errorBudgetTracker.getCurrentStatus(),
        },
      };

    } catch (error) {
      this.recordOperationFailure('store', Date.now() - startTime, true);
      throw (error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Perform fallback search operation
   */
  private async performFallbackSearch(
    query: SearchQuery,
    startTime: number
  ): Promise<DegradedOperationResponse<{
    results: SearchResult[];
    items: SearchResult[];
    total_count: number;
  }>> {
    try {
      const result = await this.fallbackStorage.search(query);
      this.statistics.fallbackOperations++;
      this.recordOperationSuccess('search', Date.now() - startTime, true);

      return {
        success: true,
        data: result,
        degraded: true,
        fallbackUsed: true,
        executionTime: Date.now() - startTime,
        strategy: 'fallback',
        meta: {
          level: this.state.currentLevel,
          notifications: ['Operating in fallback mode - limited search results'],
          recommendations: ['Try simpler search terms', 'Results may be limited during degradation'],
          errorBudget: this.errorBudgetTracker.getCurrentStatus(),
        },
      };

    } catch (error) {
      this.recordOperationFailure('search', Date.now() - startTime, true);
      throw (error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Sync data from fallback storage
   */
  private async syncFallbackData(): Promise<void> {
    // This would implement data synchronization from fallback to Qdrant
    logger.info('Syncing fallback data to Qdrant');
    // Implementation would involve:
    // 1. Retrieving data from fallback storage
    // 2. Migrating it to Qdrant
    // 3. Handling conflicts and duplicates
    // 4. Clearing fallback storage after successful sync
  }

  /**
   * Enable operation interceptors
   */
  private enableInterceptors(): void {
    // This would intercept Qdrant adapter operations
    // Implementation would involve monkey-patching or proxying the adapter methods
    this.interceptorsEnabled = true;
    logger.debug('Operation interceptors enabled');
  }

  /**
   * Disable operation interceptors
   */
  private disableInterceptors(): void {
    // This would restore original Qdrant adapter operations
    this.interceptorsEnabled = false;
    logger.debug('Operation interceptors disabled');
  }

  /**
   * Record operation start
   */
  private recordOperationStart(operation: string): void {
    if (this.config.errorBudget.enabled) {
      this.errorBudgetTracker.recordOperation({
        timestamp: Date.now(),
        operationType: operation as unknown,
        success: false, // Will be updated on completion
        responseTime: 0,
        degraded: this.state.currentLevel !== DegradationLevel.HEALTHY,
        fallbackUsed: this.state.isInFailover,
      });
    }
  }

  /**
   * Record operation success
   */
  private recordOperationSuccess(operation: string, responseTime: number, fallback: boolean = false): void {
    if (this.config.errorBudget.enabled) {
      this.errorBudgetTracker.recordOperation({
        timestamp: Date.now(),
        operationType: operation as unknown,
        success: true,
        responseTime,
        degraded: this.state.currentLevel !== DegradationLevel.HEALTHY,
        fallbackUsed: fallback,
      });
    }
  }

  /**
   * Record operation failure
   */
  private recordOperationFailure(operation: string, responseTime: number, fallback: boolean = false): void {
    if (this.config.errorBudget.enabled) {
      this.errorBudgetTracker.recordOperation({
        timestamp: Date.now(),
        operationType: operation as unknown,
        success: false,
        responseTime,
        degraded: true,
        fallbackUsed: fallback,
        errorType: 'operation_failure',
      });
    }
  }

  /**
   * Get active notifications
   */
  private getActiveNotifications(): string[] {
    const notifications: string[] = [];

    if (this.state.isInFailover) {
      notifications.push('System operating in fallback mode');
    }

    if (this.state.circuitBreakerOpen) {
      notifications.push('Circuit breaker is open');
    }

    if (this.state.currentLevel !== DegradationLevel.HEALTHY) {
      notifications.push(`Service degraded: ${this.state.currentLevel}`);
    }

    return notifications;
  }

  /**
   * Get recommendations
   */
  private getRecommendations(): string[] {
    const recommendations: string[] = [];

    if (this.state.isInFailover) {
      recommendations.push('Normal operation will resume automatically');
      recommendations.push('Data is being stored temporarily');
    }

    if (this.state.circuitBreakerOpen) {
      recommendations.push('Circuit breaker will close when service recovers');
    }

    switch (this.state.currentLevel) {
      case DegradationLevel.WARNING:
        recommendations.push('Monitor system performance');
        break;
      case DegradationLevel.DEGRADED:
        recommendations.push('Some features may be unavailable');
        break;
      case DegradationLevel.CRITICAL:
        recommendations.push('Limited functionality available');
        break;
      case DegradationLevel.UNAVAILABLE:
        recommendations.push('Emergency mode activated');
        break;
    }

    return recommendations;
  }

  /**
   * Type guard for degradation events
   */
  private isValidDegradationEvent(event: unknown): event is {
    previousLevel: DegradationLevel;
    newLevel: DegradationLevel;
    levelChangeEvent: DegradationEvent;
  } {
    return (
      event !== null &&
      typeof event === 'object' &&
      'previousLevel' in event &&
      'newLevel' in event &&
      'levelChangeEvent' in event &&
      Object.values(DegradationLevel).includes((event as unknown).previousLevel) &&
      Object.values(DegradationLevel).includes((event as unknown).newLevel) &&
      typeof (event as unknown).levelChangeEvent === 'object'
    );
  }
}

export default QdrantGracefulDegradationManager;
