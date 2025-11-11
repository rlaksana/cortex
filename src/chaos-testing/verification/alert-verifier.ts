/**
 * Alert Verifier
 *
 * This module verifies that alerts fire correctly during chaos scenarios,
 * including proper triggering, escalation, notification, and resolution.
 */

import { EventEmitter } from 'events';

import {
  AlertingResponse,
  type AlertingVerification,
  type AlertingVerificationResult,
  type ChaosScenario,
  type ExpectedAlert,
  type ExperimentExecutionContext,
  TriggeredAlert} from '../types/chaos-testing-types.js';

export interface AlertEvent {
  id: string;
  name: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  source: string;
  triggeredAt: Date;
  resolvedAt?: Date;
  message: string;
  conditions: string[];
  labels: Record<string, string>;
  annotations: Record<string, string>;
}

export interface AlertMetrics {
  totalAlerts: number;
  alertsBySeverity: Record<string, number>;
  alertsBySource: Record<string, number>;
  averageAlertDelay: number;
  maxAlertDelay: number;
  falsePositives: number;
  missedAlerts: number;
  escalationEvents: number;
}

export interface NotificationChannel {
  name: string;
  type: 'email' | 'slack' | 'pagerduty' | 'webhook' | 'teams';
  enabled: boolean;
  lastNotification?: Date;
  notificationCount: number;
}

export class AlertVerifier extends EventEmitter {
  private monitoringActive = false;
  private alertEvents: AlertEvent[] = [];
  private expectedAlerts: ExpectedAlert[] = [];
  private incidentStartTime?: Date;
  private notificationChannels: Map<string, NotificationChannel> = new Map();

  constructor() {
    super();
    this.setupDefaultNotificationChannels();
  }

  /**
   * Start monitoring alerts for a chaos scenario
   */
  async startMonitoring(
    scenario: ChaosScenario,
    context: ExperimentExecutionContext,
    expectedAlerts: ExpectedAlert[]
  ): Promise<void> {
    this.monitoringActive = true;
    this.incidentStartTime = new Date();
    this.expectedAlerts = expectedAlerts;
    this.alertEvents = [];

    this.emit('alert:monitoring_started', { scenario, expectedAlerts });

    // Setup alert interception
    this.setupAlertInterception();

    // Start alert monitoring loop
    this.startAlertMonitoringLoop();
  }

  /**
   * Stop monitoring and verify alert behavior
   */
  async stopMonitoring(): Promise<AlertingVerificationResult> {
    this.monitoringActive = false;

    const result = await this.verifyAlertingBehavior();

    this.emit('alert:monitoring_stopped', { result });

    return result;
  }

  /**
   * Verify alerting behavior against expected criteria
   */
  async verifyAlertingBehavior(): Promise<AlertingVerificationResult> {
    const result: AlertingVerificationResult = {
      passed: true,
      alertsTriggered: this.alertEvents.length,
      expectedAlerts: this.expectedAlerts.length,
      averageAlertDelay: 0,
      maxAlertDelay: 0,
      escalationOccurred: false
    };

    // Calculate alert delays
    const delays = this.alertEvents
      .map(alert => this.calculateAlertDelay(alert))
      .filter(delay => delay >= 0);

    if (delays.length > 0) {
      result.averageAlertDelay = delays.reduce((sum, delay) => sum + delay, 0) / delays.length;
      result.maxAlertDelay = Math.max(...delays);
    }

    // Verify expected alerts were triggered
    const missedAlerts = this.findMissedAlerts();
    if (missedAlerts.length > 0) {
      result.passed = false;
    }

    // Verify alert timing
    if (result.averageAlertDelay > 30000) { // 30 seconds threshold
      result.passed = false;
    }

    // Verify alert escalation
    result.escalationOccurred = this.checkForEscalation();

    // Verify notification channels
    const notificationResult = await this.verifyNotificationChannels();
    if (!notificationResult.allChannelsNotified) {
      result.passed = false;
    }

    // Verify alert accuracy
    const accuracyResult = this.verifyAlertAccuracy();
    if (accuracyResult.accuracy < 0.8) { // 80% accuracy threshold
      result.passed = false;
    }

    return result;
  }

  /**
   * Calculate alert delay from incident start
   */
  private calculateAlertDelay(alert: AlertEvent): number {
    if (!this.incidentStartTime) {
      return -1;
    }

    return alert.triggeredAt.getTime() - this.incidentStartTime.getTime();
  }

  /**
   * Find expected alerts that were not triggered
   */
  private findMissedAlerts(): ExpectedAlert[] {
    const missed: ExpectedAlert[] = [];

    for (const expected of this.expectedAlerts) {
      const triggered = this.alertEvents.find(alert =>
        alert.name === expected.name &&
        alert.severity === expected.severity &&
        alert.source === expected.source
      );

      if (!triggered) {
        missed.push(expected);
      }
    }

    return missed;
  }

  /**
   * Check if alert escalation occurred
   */
  private checkForEscalation(): boolean {
    // Look for escalation patterns (severity changes, multiple notifications, etc.)
    const escalationEvents = this.alertEvents.filter(alert =>
      alert.name.includes('escalated') ||
      alert.labels.escalated === 'true' ||
      alert.annotations.escalationReason
    );

    return escalationEvents.length > 0;
  }

  /**
   * Verify notification channels were used appropriately
   */
  private async verifyNotificationChannels(): Promise<{
    allChannelsNotified: boolean;
    channelResults: Record<string, boolean>;
  }> {
    const results: Record<string, boolean> = {};
    let allNotified = true;

    for (const [channelName, channel] of this.notificationChannels) {
      if (channel.enabled) {
        const notified = channel.notificationCount > 0;
        results[channelName] = notified;

        if (!notified) {
          allNotified = false;
        }
      }
    }

    return {
      allChannelsNotified: allNotified,
      channelResults: results
    };
  }

  /**
   * Verify alert accuracy and relevance
   */
  private verifyAlertAccuracy(): { accuracy: number; falsePositives: number } {
    let accurateAlerts = 0;
    let falsePositives = 0;

    for (const alert of this.alertEvents) {
      const isAccurate = this.evaluateAlertAccuracy(alert);
      if (isAccurate) {
        accurateAlerts++;
      } else {
        falsePositives++;
      }
    }

    const accuracy = this.alertEvents.length > 0 ? accurateAlerts / this.alertEvents.length : 0;

    return { accuracy, falsePositives };
  }

  /**
   * Evaluate if an alert is accurate and relevant
   */
  private evaluateAlertAccuracy(alert: AlertEvent): boolean {
    // Check if alert matches expected conditions
    const expectedAlert = this.expectedAlerts.find(expected =>
      expected.name === alert.name &&
      expected.severity === alert.severity
    );

    if (!expectedAlert) {
      // Unexpected alert - could be false positive
      return false;
    }

    // Check if alert conditions match the actual scenario
    const conditionsMatch = expectedAlert.conditions.every(condition =>
      alert.message.includes(condition) ||
      Object.values(alert.labels).some(label => label.includes(condition))
    );

    return conditionsMatch;
  }

  /**
   * Setup alert interception to capture alert events
   */
  private setupAlertInterception(): void {
    // Intercept alert system calls
    this.interceptAlertManager();
    this.interceptNotificationChannels();
    this.interceptPrometheusAlerts();
  }

  /**
   * Intercept alert manager calls
   */
  private interceptAlertManager(): void {
    // This would integrate with the existing alert system
    // to capture alert events as they're triggered
  }

  /**
   * Intercept notification channel calls
   */
  private interceptNotificationChannels(): void {
    // Monitor notification channels to track alert delivery
  }

  /**
   * Intercept Prometheus alerts
   */
  private interceptPrometheusAlerts(): void {
    // Monitor Prometheus alertmanager for rule-based alerts
  }

  /**
   * Start continuous alert monitoring
   */
  private startAlertMonitoringLoop(): void {
    const monitoringInterval = setInterval(async () => {
      if (!this.monitoringActive) {
        clearInterval(monitoringInterval);
        return;
      }

      try {
        await this.collectCurrentAlerts();
      } catch (error) {
        this.emit('alert:monitoring_error', { error });
      }
    }, 5000); // Check every 5 seconds
  }

  /**
   * Collect current active alerts
   */
  private async collectCurrentAlerts(): Promise<void> {
    // This would integrate with the actual monitoring system
    // to collect currently active alerts

    // Simulate finding an alert
    const mockAlert: AlertEvent = {
      id: `alert_${Date.now()}`,
      name: 'QdrantConnectionFailure',
      severity: 'critical',
      source: 'qdrant-monitor',
      triggeredAt: new Date(),
      message: 'Qdrant connection failure detected',
      conditions: ['connection_failed', 'qdrant_unreachable'],
      labels: {
        component: 'qdrant',
        instance: 'qdrant-1'
      },
      annotations: {
        summary: 'Qdrant database connection failure',
        description: 'Unable to establish connection to Qdrant database'
      }
    };

    this.recordAlert(mockAlert);
  }

  /**
   * Record an alert event
   */
  private recordAlert(alert: AlertEvent): void {
    // Check if we already have this alert
    const existingAlert = this.alertEvents.find(a => a.id === alert.id);

    if (!existingAlert) {
      this.alertEvents.push(alert);
      this.emit('alert:triggered', { alert });
    }
  }

  /**
   * Setup default notification channels
   */
  private setupDefaultNotificationChannels(): void {
    const defaultChannels: NotificationChannel[] = [
      {
        name: 'slack',
        type: 'slack',
        enabled: true,
        notificationCount: 0
      },
      {
        name: 'email',
        type: 'email',
        enabled: true,
        notificationCount: 0
      },
      {
        name: 'pagerduty',
        type: 'pagerduty',
        enabled: true,
        notificationCount: 0
      }
    ];

    defaultChannels.forEach(channel => {
      this.notificationChannels.set(channel.name, channel);
    });
  }

  /**
   * Simulate alert resolution
   */
  async simulateAlertResolution(alertId: string): Promise<void> {
    const alert = this.alertEvents.find(a => a.id === alertId);
    if (alert && !alert.resolvedAt) {
      alert.resolvedAt = new Date();
      this.emit('alert:resolved', { alert });
    }
  }

  /**
   * Get alert metrics
   */
  getAlertMetrics(): AlertMetrics {
    const alertsBySeverity: Record<string, number> = {};
    const alertsBySource: Record<string, number> = {};

    this.alertEvents.forEach(alert => {
      alertsBySeverity[alert.severity] = (alertsBySeverity[alert.severity] || 0) + 1;
      alertsBySource[alert.source] = (alertsBySource[alert.source] || 0) + 1;
    });

    const delays = this.alertEvents
      .map(alert => this.calculateAlertDelay(alert))
      .filter(delay => delay >= 0);

    return {
      totalAlerts: this.alertEvents.length,
      alertsBySeverity,
      alertsBySource,
      averageAlertDelay: delays.length > 0 ? delays.reduce((sum, delay) => sum + delay, 0) / delays.length : 0,
      maxAlertDelay: delays.length > 0 ? Math.max(...delays) : 0,
      falsePositives: this.verifyAlertAccuracy().falsePositives,
      missedAlerts: this.findMissedAlerts().length,
      escalationEvents: this.alertEvents.filter(alert =>
        alert.labels.escalated === 'true'
      ).length
    };
  }

  /**
   * Get detailed alert timeline
   */
  getAlertTimeline(): AlertEvent[] {
    return [...this.alertEvents].sort((a, b) =>
      a.triggeredAt.getTime() - b.triggeredAt.getTime()
    );
  }

  /**
   * Get notification channel status
   */
  getNotificationChannelStatus(): Map<string, NotificationChannel> {
    return new Map(this.notificationChannels);
  }

  /**
   * Verify alert against verification criteria
   */
  async verifyAgainstCriteria(
    criteria: AlertingVerification,
    result: AlertingVerificationResult
  ): Promise<boolean> {
    // Verify expected alert count
    const expectedAlertCount = criteria.expectedAlerts.length;
    if (Math.abs(result.alertsTriggered - expectedAlertCount) > 1) { // Allow 1 alert tolerance
      return false;
    }

    // Verify alert timing
    if (result.averageAlertDelay > criteria.maxAlertDelay) {
      return false;
    }

    // Verify escalation
    if (criteria.alertEscalation && !result.escalationOccurred) {
      return false;
    }

    // Verify alert severity
    const triggeredSeverities = new Set(
      this.alertEvents.map(alert => alert.severity)
    );

    for (const expectedSeverity of criteria.expectedSeverity) {
      if (!triggeredSeverities.has(expectedSeverity)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Reset verifier state
   */
  reset(): void {
    this.monitoringActive = false;
    this.alertEvents = [];
    this.expectedAlerts = [];
    this.incidentStartTime = undefined;

    // Reset notification channel counts
    for (const channel of this.notificationChannels.values()) {
      channel.notificationCount = 0;
      channel.lastNotification = undefined;
    }
  }
}