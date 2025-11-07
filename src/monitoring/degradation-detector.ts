// @ts-nocheck
/**
 * Qdrant Degradation Detector
 *
 * Monitors Qdrant health and detects degradation scenarios, providing
 * early warning signals and automatic failover triggering. Integrates with
 * circuit breakers and health monitoring for comprehensive degradation management.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { EventEmitter } from 'events';
import { QdrantHealthMonitor, QdrantConnectionStatus } from './qdrant-health-monitor.js';
import { CircuitBreakerMonitor } from './circuit-breaker-monitor.js';
import { logger } from '@/utils/logger.js';
import { HealthStatus } from '../types/unified-health-interfaces.js';

/**
 * Degradation levels
 */
export enum DegradationLevel {
  HEALTHY = 'healthy',
  WARNING = 'warning',
  DEGRADED = 'degraded',
  CRITICAL = 'critical',
  UNAVAILABLE = 'unavailable',
}

/**
 * Degradation triggers
 */
export interface DegradationTrigger {
  id: string;
  name: string;
  enabled: boolean;
  threshold: number;
  windowMs: number;
  consecutiveFailures: number;
  currentValue: number;
  lastTriggered?: Date;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Degradation event
 */
export interface DegradationEvent {
  id: string;
  timestamp: Date;
  level: DegradationLevel;
  trigger: string;
  description: string;
  metrics: {
    qdrantHealth?: HealthStatus;
    connectionStatus?: QdrantConnectionStatus;
    circuitBreakerOpen?: boolean;
    responseTime?: number;
    errorRate?: number;
    consecutiveFailures?: number;
  };
  recommendations: string[];
  autoFailoverTriggered: boolean;
  estimatedRecoveryTime?: number;
}

/**
 * Degradation detector configuration
 */
export interface DegradationDetectorConfig {
  // Detection thresholds
  thresholds: {
    responseTimeWarning: number;      // ms
    responseTimeCritical: number;     // ms
    errorRateWarning: number;         // percentage
    errorRateCritical: number;        // percentage
    consecutiveFailuresWarning: number;
    consecutiveFailuresCritical: number;
    circuitOpenThreshold: number;     // consecutive checks
    healthCheckIntervalMs: number;
    degradationWindowMs: number;      // time window for degradation detection
  };

  // Auto-failover settings
  autoFailover: {
    enabled: boolean;
    triggerLevel: DegradationLevel;
    minDurationBeforeFailover: number; // ms
    maxFailoverAttempts: number;
    failoverCooldownMs: number;
  };

  // Notification settings
  notifications: {
    enabled: boolean;
    channels: ('log' | 'event' | 'webhook')[];
    webhookUrl?: string;
    rateLimitMs: number;
  };

  // Recovery settings
  recovery: {
    enabled: boolean;
    healthCheckIntervalMs: number;
    consecutiveSuccessesRequired: number;
    maxRecoveryAttempts: number;
  };
}

/**
 * Qdrant Degradation Detector
 */
export class QdrantDegradationDetector extends EventEmitter {
  private config: DegradationDetectorConfig;
  private qdrantMonitor: QdrantHealthMonitor;
  private circuitMonitor: CircuitBreakerMonitor;
  private isRunning = false;
  private monitoringInterval: NodeJS.Timeout | null = null;
  private recoveryInterval: NodeJS.Timeout | null = null;

  // State tracking
  private currentLevel: DegradationLevel = DegradationLevel.HEALTHY;
  private degradationStartTime: Date | null = null;
  private lastFailoverTime: Date | null = null;
  private failoverAttempts = 0;
  private consecutiveSuccesses = 0;
  private degradationHistory: DegradationEvent[] = [];

  // Rate limiting
  private lastNotificationTime = 0;

  // Triggers
  private triggers: Map<string, DegradationTrigger> = new Map();

  constructor(
    qdrantMonitor: QdrantHealthMonitor,
    circuitMonitor: CircuitBreakerMonitor,
    config?: Partial<DegradationDetectorConfig>
  ) {
    super();

    this.qdrantMonitor = qdrantMonitor;
    this.circuitMonitor = circuitMonitor;

    this.config = {
      thresholds: {
        responseTimeWarning: 2000,
        responseTimeCritical: 5000,
        errorRateWarning: 10,
        errorRateCritical: 25,
        consecutiveFailuresWarning: 3,
        consecutiveFailuresCritical: 5,
        circuitOpenThreshold: 2,
        healthCheckIntervalMs: 15000,
        degradationWindowMs: 60000,
      },
      autoFailover: {
        enabled: true,
        triggerLevel: DegradationLevel.CRITICAL,
        minDurationBeforeFailover: 30000,
        maxFailoverAttempts: 3,
        failoverCooldownMs: 300000, // 5 minutes
      },
      notifications: {
        enabled: true,
        channels: ['log', 'event'],
        rateLimitMs: 30000,
      },
      recovery: {
        enabled: true,
        healthCheckIntervalMs: 30000,
        consecutiveSuccessesRequired: 3,
        maxRecoveryAttempts: 10,
      },
      ...config,
    };

    this.initializeTriggers();
    this.setupEventListeners();
  }

  /**
   * Start degradation monitoring
   */
  start(): void {
    if (this.isRunning) {
      logger.warn('Degradation detector is already running');
      return;
    }

    this.isRunning = true;

    // Start monitoring interval
    this.monitoringInterval = setInterval(
      () => this.performDegradationCheck(),
      this.config.thresholds.healthCheckIntervalMs
    );

    // Start recovery interval if in degraded state
    if (this.currentLevel !== DegradationLevel.HEALTHY) {
      this.startRecoveryMonitoring();
    }

    logger.info('Qdrant degradation detector started', {
      healthCheckInterval: this.config.thresholds.healthCheckIntervalMs,
      autoFailoverEnabled: this.config.autoFailover.enabled,
    });

    this.emit('started');
  }

  /**
   * Stop degradation monitoring
   */
  stop(): void {
    if (!this.isRunning) {
      logger.warn('Degradation detector is not running');
      return;
    }

    this.isRunning = false;

    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }

    if (this.recoveryInterval) {
      clearInterval(this.recoveryInterval);
      this.recoveryInterval = null;
    }

    logger.info('Qdrant degradation detector stopped');
    this.emit('stopped');
  }

  /**
   * Get current degradation level
   */
  getCurrentLevel(): DegradationLevel {
    return this.currentLevel;
  }

  /**
   * Get degradation metrics
   */
  getMetrics(): {
    currentLevel: DegradationLevel;
    degradationDuration: number;
    failoverAttempts: number;
    lastFailoverTime?: Date;
    consecutiveSuccesses: number;
    triggers: DegradationTrigger[];
    recentEvents: DegradationEvent[];
  } {
    return {
      currentLevel: this.currentLevel,
      degradationDuration: this.degradationStartTime
        ? Date.now() - this.degradationStartTime.getTime()
        : 0,
      failoverAttempts: this.failoverAttempts,
      lastFailoverTime: this.lastFailoverTime || undefined,
      consecutiveSuccesses: this.consecutiveSuccesses,
      triggers: Array.from(this.triggers.values()),
      recentEvents: this.degradationHistory.slice(-10),
    };
  }

  /**
   * Manually trigger failover (for testing or emergencies)
   */
  triggerManualFailover(reason: string): boolean {
    if (!this.config.autoFailover.enabled) {
      logger.warn('Manual failover requested but auto-failover is disabled');
      return false;
    }

    logger.warn({ reason }, 'Manual failover triggered');

    const event: DegradationEvent = {
      id: this.generateEventId(),
      timestamp: new Date(),
      level: DegradationLevel.CRITICAL,
      trigger: 'manual',
      description: `Manual failover triggered: ${reason}`,
      metrics: {},
      recommendations: ['Investigate the manual trigger reason', 'Monitor system recovery'],
      autoFailoverTriggered: true,
    };

    this.recordDegradationEvent(event);
    this.emitFailoverEvent(event);

    return true;
  }

  /**
   * Force health status check
   */
  async forceHealthCheck(): Promise<void> {
    await this.performDegradationCheck();
  }

  // === Private Methods ===

  /**
   * Initialize degradation triggers
   */
  private initializeTriggers(): void {
    const triggers: Omit<DegradationTrigger, 'id' | 'currentValue' | 'lastTriggered'>[] = [
      {
        name: 'high_response_time',
        enabled: true,
        threshold: this.config.thresholds.responseTimeWarning,
        windowMs: this.config.thresholds.degradationWindowMs,
        consecutiveFailures: this.config.thresholds.consecutiveFailuresWarning,
        severity: 'medium',
      },
      {
        name: 'critical_response_time',
        enabled: true,
        threshold: this.config.thresholds.responseTimeCritical,
        windowMs: this.config.thresholds.degradationWindowMs,
        consecutiveFailures: this.config.thresholds.consecutiveFailuresCritical,
        severity: 'critical',
      },
      {
        name: 'high_error_rate',
        enabled: true,
        threshold: this.config.thresholds.errorRateWarning,
        windowMs: this.config.thresholds.degradationWindowMs,
        consecutiveFailures: this.config.thresholds.consecutiveFailuresWarning,
        severity: 'medium',
      },
      {
        name: 'critical_error_rate',
        enabled: true,
        threshold: this.config.thresholds.errorRateCritical,
        windowMs: this.config.thresholds.degradationWindowMs,
        consecutiveFailures: this.config.thresholds.consecutiveFailuresCritical,
        severity: 'critical',
      },
      {
        name: 'circuit_breaker_open',
        enabled: true,
        threshold: 1,
        windowMs: this.config.thresholds.degradationWindowMs,
        consecutiveFailures: this.config.thresholds.circuitOpenThreshold,
        severity: 'high',
      },
      {
        name: 'consecutive_failures',
        enabled: true,
        threshold: this.config.thresholds.consecutiveFailuresWarning,
        windowMs: this.config.thresholds.degradationWindowMs,
        consecutiveFailures: this.config.thresholds.consecutiveFailuresWarning,
        severity: 'medium',
      },
    ];

    triggers.forEach(trigger => {
      this.triggers.set(trigger.name, {
        ...trigger,
        id: this.generateEventId(),
        currentValue: 0,
      });
    });
  }

  /**
   * Setup event listeners
   */
  private setupEventListeners(): void {
    // Listen to Qdrant health monitor events
    this.qdrantMonitor.on('status_change', (event) => {
      this.handleQdrantStatusChange(event);
    });

    this.qdrantMonitor.on('health_check_error', (error) => {
      this.handleQdrantHealthCheckError(error);
    });

    // Listen to circuit breaker monitor events
    this.circuitMonitor.on('alert', (alert) => {
      if (alert.serviceName === 'qdrant') {
        this.handleCircuitBreakerAlert(alert);
      }
    });

    this.circuitMonitor.on('circuit_state_change', (event) => {
      if (event.serviceName === 'qdrant') {
        this.handleCircuitStateChange(event);
      }
    });
  }

  /**
   * Perform degradation check
   */
  private async performDegradationCheck(): Promise<void> {
    try {
      // Get current metrics
      const qdrantStatus = this.qdrantMonitor.getCurrentStatus();
      const qdrantMetrics = this.qdrantMonitor.getCurrentMetrics();
      const circuitStatus = this.circuitMonitor.getHealthStatus('qdrant');

      // Evaluate triggers
      const triggeredTriggers: DegradationTrigger[] = [];

      for (const [name, trigger] of this.triggers) {
        if (!trigger.enabled) continue;

        const isTriggered = this.evaluateTrigger(trigger, qdrantStatus, qdrantMetrics, circuitStatus);

        if (isTriggered) {
          trigger.currentValue = trigger.threshold;
          trigger.lastTriggered = new Date();
          triggeredTriggers.push(trigger);
        } else {
          trigger.currentValue = 0;
        }
      }

      // Determine new degradation level
      const newLevel = this.calculateDegradationLevel(triggeredTriggers, qdrantStatus, circuitStatus);

      if (newLevel !== this.currentLevel) {
        this.handleDegradationLevelChange(newLevel, triggeredTriggers, qdrantStatus, qdrantMetrics, circuitStatus);
      }

      // Check for auto-failover conditions
      if (this.shouldTriggerAutoFailover(newLevel)) {
        this.triggerAutoFailover(newLevel, triggeredTriggers);
      }

    } catch (error) {
      logger.error({ error }, 'Degradation check failed');
    }
  }

  /**
   * Evaluate a specific trigger
   */
  private evaluateTrigger(
    trigger: DegradationTrigger,
    qdrantStatus: HealthStatus,
    qdrantMetrics: any,
    circuitStatus: any
  ): boolean {
    switch (trigger.name) {
      case 'high_response_time':
        return qdrantMetrics.averageResponseTime > trigger.threshold;

      case 'critical_response_time':
        return qdrantMetrics.averageResponseTime > trigger.threshold;

      case 'high_error_rate':
        return qdrantMetrics.errorRate > trigger.threshold;

      case 'critical_error_rate':
        return qdrantMetrics.errorRate > trigger.threshold;

      case 'circuit_breaker_open':
        return circuitStatus?.isOpen || false;

      case 'consecutive_failures':
        // This would be tracked based on consecutive health check failures
        return false; // Simplified for now

      default:
        return false;
    }
  }

  /**
   * Calculate degradation level
   */
  private calculateDegradationLevel(
    triggeredTriggers: DegradationTrigger[],
    qdrantStatus: HealthStatus,
    circuitStatus: any
  ): DegradationLevel {
    // Check for critical triggers
    const criticalTriggers = triggeredTriggers.filter(t => t.severity === 'critical');
    if (criticalTriggers.length > 0) {
      return DegradationLevel.CRITICAL;
    }

    // Check for high severity triggers
    const highTriggers = triggeredTriggers.filter(t => t.severity === 'high');
    if (highTriggers.length > 0) {
      return DegradationLevel.DEGRADED;
    }

    // Check for medium severity triggers
    const mediumTriggers = triggeredTriggers.filter(t => t.severity === 'medium');
    if (mediumTriggers.length > 0) {
      return DegradationLevel.WARNING;
    }

    // Base on Qdrant status
    switch (qdrantStatus) {
      case HealthStatus.UNHEALTHY:
        return DegradationLevel.CRITICAL;
      case HealthStatus.DEGRADED:
        return DegradationLevel.DEGRADED;
      case HealthStatus.HEALTHY:
        return DegradationLevel.HEALTHY;
      default:
        return DegradationLevel.WARNING;
    }
  }

  /**
   * Handle degradation level change
   */
  private handleDegradationLevelChange(
    newLevel: DegradationLevel,
    triggeredTriggers: DegradationTrigger[],
    qdrantStatus: HealthStatus,
    qdrantMetrics: any,
    circuitStatus: any
  ): void {
    const previousLevel = this.currentLevel;
    this.currentLevel = newLevel;

    // Update degradation start time
    if (newLevel !== DegradationLevel.HEALTHY && !this.degradationStartTime) {
      this.degradationStartTime = new Date();
    } else if (newLevel === DegradationLevel.HEALTHY) {
      this.degradationStartTime = null;
      this.consecutiveSuccesses = 0;
    }

    // Create degradation event
    const event: DegradationEvent = {
      id: this.generateEventId(),
      timestamp: new Date(),
      level: newLevel,
      trigger: triggeredTriggers.map(t => t.name).join(', ') || 'status_change',
      description: this.generateDegradationDescription(newLevel, triggeredTriggers, qdrantStatus),
      metrics: {
        qdrantHealth: qdrantStatus,
        connectionStatus: this.qdrantMonitor.getCurrentConnectionStatus(),
        circuitBreakerOpen: circuitStatus?.isOpen,
        responseTime: qdrantMetrics.averageResponseTime,
        errorRate: qdrantMetrics.errorRate,
      },
      recommendations: this.generateRecommendations(newLevel, triggeredTriggers),
      autoFailoverTriggered: false,
      estimatedRecoveryTime: this.estimateRecoveryTime(newLevel),
    };

    this.recordDegradationEvent(event);
    this.emitDegradationEvent(event);

    logger[newLevel === DegradationLevel.CRITICAL ? 'error' : 'warn'](
      {
        previousLevel,
        newLevel,
        triggeredTriggers: triggeredTriggers.map(t => t.name),
        degradationDuration: this.degradationStartTime
          ? Date.now() - this.degradationStartTime.getTime()
          : 0,
      },
      `Degradation level changed from ${previousLevel} to ${newLevel}`
    );

    this.emit('level_change', { previousLevel, newLevel, event });
  }

  /**
   * Check if auto-failover should be triggered
   */
  private shouldTriggerAutoFailover(level: DegradationLevel): boolean {
    if (!this.config.autoFailover.enabled) {
      return false;
    }

    if (level !== this.config.autoFailover.triggerLevel) {
      return false;
    }

    // Check minimum duration
    if (this.degradationStartTime) {
      const degradationDuration = Date.now() - this.degradationStartTime.getTime();
      if (degradationDuration < this.config.autoFailover.minDurationBeforeFailover) {
        return false;
      }
    }

    // Check cooldown
    if (this.lastFailoverTime) {
      const timeSinceLastFailover = Date.now() - this.lastFailoverTime.getTime();
      if (timeSinceLastFailover < this.config.autoFailover.failoverCooldownMs) {
        return false;
      }
    }

    // Check max attempts
    if (this.failoverAttempts >= this.config.autoFailover.maxFailoverAttempts) {
      return false;
    }

    return true;
  }

  /**
   * Trigger auto-failover
   */
  private triggerAutoFailover(level: DegradationLevel, triggeredTriggers: DegradationTrigger[]): void {
    this.failoverAttempts++;
    this.lastFailoverTime = new Date();

    const event: DegradationEvent = {
      id: this.generateEventId(),
      timestamp: new Date(),
      level,
      trigger: 'auto_failover',
      description: `Auto-failover triggered due to ${level} degradation`,
      metrics: {},
      recommendations: [
        'Monitor fallback storage usage',
        'Investigate Qdrant connectivity issues',
        'Prepare for manual intervention if needed',
      ],
      autoFailoverTriggered: true,
      estimatedRecoveryTime: this.estimateRecoveryTime(level),
    };

    this.recordDegradationEvent(event);
    this.emitFailoverEvent(event);

    logger.error(
      {
        level,
        triggeredTriggers: triggeredTriggers.map(t => t.name),
        failoverAttempt: this.failoverAttempts,
        maxAttempts: this.config.autoFailover.maxFailoverAttempts,
      },
      'Auto-failover triggered'
    );
  }

  /**
   * Start recovery monitoring
   */
  private startRecoveryMonitoring(): void {
    if (!this.config.recovery.enabled) {
      return;
    }

    if (this.recoveryInterval) {
      clearInterval(this.recoveryInterval);
    }

    this.recoveryInterval = setInterval(
      () => this.checkForRecovery(),
      this.config.recovery.healthCheckIntervalMs
    );
  }

  /**
   * Check for recovery conditions
   */
  private async checkForRecovery(): Promise<void> {
    try {
      const qdrantStatus = this.qdrantMonitor.getCurrentStatus();

      if (qdrantStatus === HealthStatus.HEALTHY) {
        this.consecutiveSuccesses++;

        if (this.consecutiveSuccesses >= this.config.recovery.consecutiveSuccessesRequired) {
          this.handleRecovery();
        }
      } else {
        this.consecutiveSuccesses = 0;
      }

    } catch (error) {
      logger.error({ error }, 'Recovery check failed');
      this.consecutiveSuccesses = 0;
    }
  }

  /**
   * Handle recovery
   */
  private handleRecovery(): void {
    const previousLevel = this.currentLevel;
    this.currentLevel = DegradationLevel.HEALTHY;
    this.degradationStartTime = null;
    this.consecutiveSuccesses = 0;
    this.failoverAttempts = 0;

    // Stop recovery monitoring
    if (this.recoveryInterval) {
      clearInterval(this.recoveryInterval);
      this.recoveryInterval = null;
    }

    const event: DegradationEvent = {
      id: this.generateEventId(),
      timestamp: new Date(),
      level: DegradationLevel.HEALTHY,
      trigger: 'recovery',
      description: 'Qdrant service has recovered',
      metrics: {
        qdrantHealth: HealthStatus.HEALTHY,
        connectionStatus: QdrantConnectionStatus.CONNECTED,
      },
      recommendations: [
        'Monitor service stability',
        'Consider reducing alert thresholds if recoveries are frequent',
        'Review incident reports for improvement opportunities',
      ],
      autoFailoverTriggered: false,
    };

    this.recordDegradationEvent(event);
    this.emitDegradationEvent(event);

    logger.info(
      { previousLevel, consecutiveSuccesses: this.config.recovery.consecutiveSuccessesRequired },
      'Qdrant service recovered'
    );

    this.emit('recovery', { previousLevel, event });
  }

  // === Event Handlers ===

  private handleQdrantStatusChange(event: any): void {
    logger.debug({ event }, 'Qdrant status change detected');
    // Trigger immediate degradation check
    this.performDegradationCheck();
  }

  private handleQdrantHealthCheckError(error: any): void {
    logger.warn({ error }, 'Qdrant health check error detected');
    // Trigger immediate degradation check
    this.performDegradationCheck();
  }

  private handleCircuitBreakerAlert(alert: any): void {
    logger.debug({ alert }, 'Circuit breaker alert detected');
    // Trigger immediate degradation check
    this.performDegradationCheck();
  }

  private handleCircuitStateChange(event: any): void {
    logger.debug({ event }, 'Circuit breaker state change detected');
    // Trigger immediate degradation check
    this.performDegradationCheck();
  }

  // === Utility Methods ===

  private generateDegradationDescription(
    level: DegradationLevel,
    triggeredTriggers: DegradationTrigger[],
    qdrantStatus: HealthStatus
  ): string {
    const triggerNames = triggeredTriggers.map(t => t.name.replace('_', ' ')).join(', ');

    switch (level) {
      case DegradationLevel.WARNING:
        return `Performance degradation detected: ${triggerNames}`;
      case DegradationLevel.DEGRADED:
        return `Service degraded: ${triggerNames}`;
      case DegradationLevel.CRITICAL:
        return `Critical service issues: ${triggerNames}`;
      case DegradationLevel.UNAVAILABLE:
        return `Service unavailable: ${triggerNames}`;
      default:
        return 'Service operating normally';
    }
  }

  private generateRecommendations(
    level: DegradationLevel,
    triggeredTriggers: DegradationTrigger[]
  ): string[] {
    const recommendations: string[] = [];

    switch (level) {
      case DegradationLevel.WARNING:
        recommendations.push('Monitor response times and error rates');
        recommendations.push('Check Qdrant resource utilization');
        break;

      case DegradationLevel.DEGRADED:
        recommendations.push('Investigate Qdrant connectivity issues');
        recommendations.push('Check network latency and timeouts');
        recommendations.push('Monitor circuit breaker status');
        break;

      case DegradationLevel.CRITICAL:
        recommendations.push('Immediate investigation required');
        recommendations.push('Check Qdrant service logs');
        recommendations.push('Verify database availability');
        recommendations.push('Consider manual intervention');
        break;

      case DegradationLevel.UNAVAILABLE:
        recommendations.push('Service is unavailable - emergency response');
        recommendations.push('Check infrastructure status');
        recommendations.push('Engage on-call engineering team');
        break;
    }

    // Add trigger-specific recommendations
    for (const trigger of triggeredTriggers) {
      switch (trigger.name) {
        case 'high_response_time':
        case 'critical_response_time':
          recommendations.push('Optimize queries and check resource bottlenecks');
          break;
        case 'high_error_rate':
        case 'critical_error_rate':
          recommendations.push('Review error logs and fix root causes');
          break;
        case 'circuit_breaker_open':
          recommendations.push('Wait for circuit breaker recovery or manual reset');
          break;
      }
    }

    return recommendations;
  }

  private estimateRecoveryTime(level: DegradationLevel): number {
    switch (level) {
      case DegradationLevel.WARNING:
        return 5 * 60 * 1000; // 5 minutes
      case DegradationLevel.DEGRADED:
        return 15 * 60 * 1000; // 15 minutes
      case DegradationLevel.CRITICAL:
        return 30 * 60 * 1000; // 30 minutes
      case DegradationLevel.UNAVAILABLE:
        return 60 * 60 * 1000; // 1 hour
      default:
        return 0;
    }
  }

  private recordDegradationEvent(event: DegradationEvent): void {
    this.degradationHistory.push(event);

    // Keep only last 100 events
    if (this.degradationHistory.length > 100) {
      this.degradationHistory = this.degradationHistory.slice(-100);
    }
  }

  private emitDegradationEvent(event: DegradationEvent): void {
    this.emit('degradation_event', event);

    // Send notifications if enabled
    if (this.config.notifications.enabled) {
      this.sendNotification(event);
    }
  }

  private emitFailoverEvent(event: DegradationEvent): void {
    this.emit('failover_triggered', event);

    // Send notifications if enabled
    if (this.config.notifications.enabled) {
      this.sendNotification(event);
    }
  }

  private sendNotification(event: DegradationEvent): void {
    const now = Date.now();

    // Rate limiting
    if (now - this.lastNotificationTime < this.config.notifications.rateLimitMs) {
      return;
    }

    this.lastNotificationTime = now;

    // Send to different channels
    for (const channel of this.config.notifications.channels) {
      switch (channel) {
        case 'log':
          logger[event.level === DegradationLevel.CRITICAL ? 'error' : 'warn'](
            {
              eventId: event.id,
              level: event.level,
              trigger: event.trigger,
              description: event.description,
            },
            `Degradation notification: ${event.description}`
          );
          break;

        case 'event':
          this.emit('notification', event);
          break;

        case 'webhook':
          if (this.config.notifications.webhookUrl) {
            // Implement webhook notification
            this.sendWebhookNotification(event);
          }
          break;
      }
    }
  }

  private async sendWebhookNotification(event: DegradationEvent): Promise<void> {
    // Implement webhook notification logic
    logger.debug({ eventId: event.id }, 'Webhook notification sent');
  }

  private generateEventId(): string {
    return `deg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

export default QdrantDegradationDetector;
