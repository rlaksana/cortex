// @ts-nocheck
import { logger } from '@/utils/logger.js';

/**
 * Security Metrics Service
 * Provides comprehensive security monitoring and analytics
 */

export interface SecurityEvent {
  id: string;
  timestamp: Date;
  type: SecurityEventType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  description: string;
  metadata?: Record<string, any>;
  resolved: boolean;
  resolvedAt?: Date;
  assignedTo?: string;
}

export enum SecurityEventType {
  AUTHENTICATION_FAILURE = 'authentication_failure',
  UNAUTHORIZED_ACCESS = 'unauthorized_access',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  MALICIOUS_REQUEST = 'malicious_request',
  DATA_ACCESS_VIOLATION = 'data_access_violation',
  SYSTEM_COMPROMISE = 'system_compromise',
  MALWARE_DETECTED = 'malware_detected',
  VULNERABILITY_FOUND = 'vulnerability_found',
  POLICY_VIOLATION = 'policy_violation',
}

export interface SecurityMetrics {
  // Event counts by severity
  criticalEvents: number;
  highEvents: number;
  mediumEvents: number;
  lowEvents: number;

  // Event counts by type
  authenticationFailures: number;
  unauthorizedAccess: number;
  rateLimitExceeded: number;
  suspiciousActivity: number;
  maliciousRequests: number;
  dataAccessViolations: number;
  systemCompromises: number;
  malwareDetected: number;
  vulnerabilitiesFound: number;
  policyViolations: number;

  // Resolution metrics
  unresolvedEvents: number;
  averageResolutionTime: number;
  resolutionRate: number;

  // Time-based metrics
  eventsLast24Hours: number;
  eventsLast7Days: number;
  eventsLast30Days: number;

  // Trend metrics
  trendDirection: 'increasing' | 'decreasing' | 'stable';
  trendPercentage: number;

  // Risk metrics
  riskScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

export interface SecurityAlert {
  id: string;
  type: 'threshold' | 'anomaly' | 'policy' | 'trend';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  threshold?: number;
  currentValue?: number;
  timestamp: Date;
  acknowledged: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: Date;
}

export class SecurityMetricsService {
  private events: SecurityEvent[] = [];
  private alerts: SecurityAlert[] = [];
  private thresholds: Record<string, number> = {
    criticalEventsPerHour: 1,
    highEventsPerHour: 5,
    authenticationFailuresPerMinute: 10,
    suspiciousActivityPerHour: 20,
    unresolvedEventsThreshold: 50,
    riskScoreThreshold: 70,
  };

  constructor() {
    this.initializeMetrics();
    this.startBackgroundMonitoring();
  }

  /**
   * Record a security event
   */
  public recordEvent(event: Omit<SecurityEvent, 'id'>): SecurityEvent {
    const securityEvent: SecurityEvent = {
      ...event,
      id: this.generateEventId(),
    };

    this.events.push(securityEvent);
    logger.info('Security event recorded', {
      eventId: securityEvent.id,
      type: securityEvent.type,
      severity: securityEvent.severity,
      source: securityEvent.source,
    });

    this.checkThresholds(securityEvent);
    this.updateRiskScore();

    return securityEvent;
  }

  /**
   * Resolve a security event
   */
  public resolveEvent(eventId: string, resolvedBy: string): boolean {
    const event = this.events.find((e) => e.id === eventId);
    if (!event) {
      logger.warn('Attempted to resolve non-existent event', { eventId });
      return false;
    }

    event.resolved = true;
    event.resolvedAt = new Date();
    event.assignedTo = resolvedBy;

    logger.info('Security event resolved', {
      eventId,
      resolvedBy,
      resolvedAt: event.resolvedAt,
    });

    this.updateRiskScore();
    return true;
  }

  /**
   * Get current security metrics
   */
  public getMetrics(): SecurityMetrics {
    const now = new Date();
    const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const last7Days = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const last30Days = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    const recentEvents = this.events.filter((e) => e.timestamp >= last24Hours);
    const weekEvents = this.events.filter((e) => e.timestamp >= last7Days);
    const monthEvents = this.events.filter((e) => e.timestamp >= last30Days);

    const unresolvedEvents = this.events.filter((e) => !e.resolved);
    const resolvedEvents = this.events.filter((e) => e.resolved);

    const criticalEvents = recentEvents.filter((e) => e.severity === 'critical').length;
    const highEvents = recentEvents.filter((e) => e.severity === 'high').length;
    const mediumEvents = recentEvents.filter((e) => e.severity === 'medium').length;
    const lowEvents = recentEvents.filter((e) => e.severity === 'low').length;

    // Calculate average resolution time
    const resolutionTimes = resolvedEvents
      .filter((e) => e.resolvedAt)
      .map((e) => e.resolvedAt!.getTime() - e.timestamp.getTime());

    const averageResolutionTime =
      resolutionTimes.length > 0
        ? resolutionTimes.reduce((a, b) => a + b, 0) / resolutionTimes.length / (1000 * 60) // minutes
        : 0;

    const resolutionRate =
      this.events.length > 0 ? (resolvedEvents.length / this.events.length) * 100 : 0;

    // Calculate trend
    const trend = this.calculateTrend(recentEvents);

    // Calculate risk score
    const riskScore = this.calculateRiskScore(criticalEvents, highEvents, mediumEvents, lowEvents);
    const riskLevel = this.getRiskLevel(riskScore);

    return {
      criticalEvents,
      highEvents,
      mediumEvents,
      lowEvents,
      authenticationFailures: recentEvents.filter(
        (e) => e.type === SecurityEventType.AUTHENTICATION_FAILURE
      ).length,
      unauthorizedAccess: recentEvents.filter(
        (e) => e.type === SecurityEventType.UNAUTHORIZED_ACCESS
      ).length,
      rateLimitExceeded: recentEvents.filter(
        (e) => e.type === SecurityEventType.RATE_LIMIT_EXCEEDED
      ).length,
      suspiciousActivity: recentEvents.filter(
        (e) => e.type === SecurityEventType.SUSPICIOUS_ACTIVITY
      ).length,
      maliciousRequests: recentEvents.filter((e) => e.type === SecurityEventType.MALICIOUS_REQUEST)
        .length,
      dataAccessViolations: recentEvents.filter(
        (e) => e.type === SecurityEventType.DATA_ACCESS_VIOLATION
      ).length,
      systemCompromises: recentEvents.filter((e) => e.type === SecurityEventType.SYSTEM_COMPROMISE)
        .length,
      malwareDetected: recentEvents.filter((e) => e.type === SecurityEventType.MALWARE_DETECTED)
        .length,
      vulnerabilitiesFound: recentEvents.filter(
        (e) => e.type === SecurityEventType.VULNERABILITY_FOUND
      ).length,
      policyViolations: recentEvents.filter((e) => e.type === SecurityEventType.POLICY_VIOLATION)
        .length,
      unresolvedEvents: unresolvedEvents.length,
      averageResolutionTime,
      resolutionRate,
      eventsLast24Hours: recentEvents.length,
      eventsLast7Days: weekEvents.length,
      eventsLast30Days: monthEvents.length,
      trendDirection: trend.direction,
      trendPercentage: trend.percentage,
      riskScore,
      riskLevel,
    };
  }

  /**
   * Get recent security events
   */
  public getRecentEvents(limit: number = 50, severity?: string): SecurityEvent[] {
    let events = [...this.events].sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    if (severity) {
      events = events.filter((e) => e.severity === severity);
    }

    return events.slice(0, limit);
  }

  /**
   * Get active security alerts
   */
  public getAlerts(): SecurityAlert[] {
    return this.alerts
      .filter((alert) => !alert.acknowledged)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  /**
   * Acknowledge a security alert
   */
  public acknowledgeAlert(alertId: string, acknowledgedBy: string): boolean {
    const alert = this.alerts.find((a) => a.id === alertId);
    if (!alert) {
      logger.warn('Attempted to acknowledge non-existent alert', { alertId });
      return false;
    }

    alert.acknowledged = true;
    alert.acknowledgedBy = acknowledgedBy;
    alert.acknowledgedAt = new Date();

    logger.info('Security alert acknowledged', {
      alertId,
      acknowledgedBy,
      acknowledgedAt: alert.acknowledgedAt,
    });

    return true;
  }

  /**
   * Get security dashboard data
   */
  public getDashboardData() {
    const metrics = this.getMetrics();
    const recentEvents = this.getRecentEvents(10);
    const activeAlerts = this.getAlerts();
    const topThreats = this.getTopThreats();
    const resolutionStats = this.getResolutionStats();

    return {
      summary: {
        totalEvents: metrics.eventsLast24Hours,
        unresolvedEvents: metrics.unresolvedEvents,
        riskScore: metrics.riskScore,
        riskLevel: metrics.riskLevel,
        trendDirection: metrics.trendDirection,
      },
      metrics,
      recentEvents,
      activeAlerts,
      topThreats,
      resolutionStats,
      lastUpdated: new Date(),
    };
  }

  /**
   * Update security thresholds
   */
  public updateThresholds(newThresholds: Partial<typeof this.thresholds>): void {
    this.thresholds = { ...this.thresholds, ...newThresholds } as Record<string, number>;
    logger.info('Security thresholds updated', { thresholds: this.thresholds });
  }

  /**
   * Export security data for external analysis
   */
  public exportData(startDate: Date, endDate: Date): SecurityEvent[] {
    return this.events.filter(
      (event) => event.timestamp >= startDate && event.timestamp <= endDate
    );
  }

  private initializeMetrics(): void {
    logger.info('Security metrics service initialized');
  }

  private startBackgroundMonitoring(): void {
    // Check for anomalies every 5 minutes
    setInterval(
      () => {
        this.checkForAnomalies();
      },
      5 * 60 * 1000
    );

    // Update risk score every minute
    setInterval(() => {
      this.updateRiskScore();
    }, 60 * 1000);

    // Clean up old events (keep last 90 days)
    setInterval(
      () => {
        this.cleanupOldEvents();
      },
      24 * 60 * 60 * 1000
    );
  }

  private generateEventId(): string {
    return `sec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private checkThresholds(event: SecurityEvent): void {
    const recentEvents = this.events.filter(
      (e) => e.timestamp >= new Date(Date.now() - 60 * 60 * 1000) // Last hour
    );

    // Check critical events threshold
    const criticalCount = recentEvents.filter((e) => e.severity === 'critical').length;
    if (criticalCount >= this.thresholds.criticalEventsPerHour) {
      this.createAlert({
        type: 'threshold',
        severity: 'critical',
        title: 'Critical Events Threshold Exceeded',
        description: `${criticalCount} critical events in the last hour (threshold: ${this.thresholds.criticalEventsPerHour})`,
        threshold: this.thresholds.criticalEventsPerHour,
        currentValue: criticalCount,
      });
    }

    // Check authentication failures threshold
    const authFailures = recentEvents.filter(
      (e) => e.type === SecurityEventType.AUTHENTICATION_FAILURE
    ).length;
    if (authFailures >= this.thresholds.authenticationFailuresPerMinute) {
      this.createAlert({
        type: 'threshold',
        severity: 'high',
        title: 'Authentication Failures Threshold Exceeded',
        description: `${authFailures} authentication failures in the last hour`,
        threshold: this.thresholds.authenticationFailuresPerMinute,
        currentValue: authFailures,
      });
    }

    // Check unresolved events threshold
    const unresolvedCount = this.events.filter((e) => !e.resolved).length;
    if (unresolvedCount >= this.thresholds.unresolvedEventsThreshold) {
      this.createAlert({
        type: 'threshold',
        severity: 'medium',
        title: 'Unresolved Events Threshold Exceeded',
        description: `${unresolvedCount} unresolved security events`,
        threshold: this.thresholds.unresolvedEventsThreshold,
        currentValue: unresolvedCount,
      });
    }
  }

  private checkForAnomalies(): void {
    const metrics = this.getMetrics();

    // Detect sudden spikes in events
    if (metrics.trendDirection === 'increasing' && metrics.trendPercentage > 50) {
      this.createAlert({
        type: 'anomaly',
        severity: 'high',
        title: 'Security Events Spike Detected',
        description: `${metrics.trendPercentage}% increase in security events detected`,
        currentValue: metrics.eventsLast24Hours,
      });
    }

    // Detect unusual patterns
    const recentEvents = this.getRecentEvents(100);
    const uniqueSources = new Set(recentEvents.map((e) => e.source)).size;

    if (recentEvents.length > 50 && uniqueSources === 1) {
      this.createAlert({
        type: 'anomaly',
        severity: 'medium',
        title: 'Unusual Event Pattern Detected',
        description: `High volume of events from single source: ${recentEvents[0]?.source}`,
        currentValue: recentEvents.length,
      });
    }
  }

  private updateRiskScore(): void {
    const metrics = this.getMetrics();
    const newScore = this.calculateRiskScore(
      metrics.criticalEvents,
      metrics.highEvents,
      metrics.mediumEvents,
      metrics.lowEvents
    );

    // Check if risk score threshold is exceeded
    if (newScore >= this.thresholds.riskScoreThreshold) {
      this.createAlert({
        type: 'threshold',
        severity: 'critical',
        title: 'Risk Score Threshold Exceeded',
        description: `Current risk score: ${newScore} (threshold: ${this.thresholds.riskScoreThreshold})`,
        threshold: this.thresholds.riskScoreThreshold,
        currentValue: newScore,
      });
    }
  }

  private calculateRiskScore(critical: number, high: number, medium: number, low: number): number {
    // Weighted risk calculation
    const criticalWeight = 25;
    const highWeight = 10;
    const mediumWeight = 5;
    const lowWeight = 1;

    const rawScore =
      critical * criticalWeight + high * highWeight + medium * mediumWeight + low * lowWeight;

    // Normalize to 0-100 scale
    return Math.min(100, Math.round(rawScore));
  }

  private getRiskLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
    if (score >= 75) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    return 'low';
  }

  private calculateTrend(events: SecurityEvent[]): {
    direction: 'increasing' | 'decreasing' | 'stable';
    percentage: number;
  } {
    if (events.length < 10) {
      return { direction: 'stable', percentage: 0 };
    }

    const midpoint = Math.floor(events.length / 2);
    const firstHalf = events.slice(midpoint);
    const secondHalf = events.slice(0, midpoint);

    const firstHalfCount = firstHalf.length;
    const secondHalfCount = secondHalf.length;

    if (firstHalfCount === secondHalfCount) {
      return { direction: 'stable', percentage: 0 };
    }

    const percentage = Math.abs((firstHalfCount - secondHalfCount) / secondHalfCount) * 100;
    const direction = firstHalfCount > secondHalfCount ? 'increasing' : 'decreasing';

    return { direction, percentage: Math.round(percentage) };
  }

  private createAlert(alert: Omit<SecurityAlert, 'id' | 'timestamp' | 'acknowledged'>): void {
    const securityAlert: SecurityAlert = {
      ...alert,
      id: this.generateEventId(),
      timestamp: new Date(),
      acknowledged: false,
    };

    this.alerts.push(securityAlert);
    logger.warn('Security alert created', {
      alertId: securityAlert.id,
      type: securityAlert.type,
      severity: securityAlert.severity,
      title: securityAlert.title,
    });
  }

  private getTopThreats(): Array<{ type: SecurityEventType; count: number; percentage: number }> {
    const last24Hours = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentEvents = this.events.filter((e) => e.timestamp >= last24Hours);

    const threatCounts = new Map<SecurityEventType, number>();
    recentEvents.forEach((event) => {
      threatCounts.set(event.type, (threatCounts.get(event.type) || 0) + 1);
    });

    const totalEvents = recentEvents.length;
    return Array.from(threatCounts.entries())
      .map(([type, count]) => ({
        type,
        count,
        percentage: totalEvents > 0 ? Math.round((count / totalEvents) * 100) : 0,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }

  private getResolutionStats(): {
    averageTime: number;
    fastestResolution: number;
    slowestResolution: number;
    totalResolved: number;
  } {
    const resolvedEvents = this.events.filter((e) => e.resolved && e.resolvedAt);

    if (resolvedEvents.length === 0) {
      return {
        averageTime: 0,
        fastestResolution: 0,
        slowestResolution: 0,
        totalResolved: 0,
      };
    }

    const resolutionTimes = resolvedEvents.map(
      (e) => (e.resolvedAt!.getTime() - e.timestamp.getTime()) / (1000 * 60) // minutes
    );

    return {
      averageTime: Math.round(resolutionTimes.reduce((a, b) => a + b, 0) / resolutionTimes.length),
      fastestResolution: Math.min(...resolutionTimes),
      slowestResolution: Math.max(...resolutionTimes),
      totalResolved: resolvedEvents.length,
    };
  }

  private cleanupOldEvents(): void {
    const cutoffDate = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000); // 90 days ago
    const initialCount = this.events.length;

    this.events = this.events.filter((event) => event.timestamp >= cutoffDate);

    const removedCount = initialCount - this.events.length;
    if (removedCount > 0) {
      logger.info('Old security events cleaned up', {
        removedCount,
        remainingCount: this.events.length,
      });
    }
  }
}

// Singleton instance
export const securityMetricsService = new SecurityMetricsService();
