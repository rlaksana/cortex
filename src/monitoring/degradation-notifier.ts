/**
 * Qdrant Degradation Notifier
 *
 * Provides user-visible notifications during Qdrant degradation scenarios.
 * Supports multiple notification channels, rate limiting, and message templating.
 * Integrates with the degradation detector to provide clear visibility to users
 * and operators about system state.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { EventEmitter } from 'events';
import { logger } from '@/utils/logger.js';
import { DegradationEvent, DegradationLevel } from './degradation-detector.js';

/**
 * Notification channel types
 */
export enum NotificationChannel {
  LOG = 'log',
  CONSOLE = 'console',
  WEBHOOK = 'webhook',
  SLACK = 'slack',
  EMAIL = 'email',
  DASHBOARD = 'dashboard',
  API = 'api',
}

/**
 * Notification message template
 */
export interface NotificationTemplate {
  level: DegradationLevel;
  title: string;
  message: string;
  actions?: Array<{
    label: string;
    url?: string;
    method?: string;
  }>;
  severity: 'info' | 'warning' | 'error' | 'critical';
  estimatedDuration?: string;
  recommendedActions?: string[];
}

/**
 * Notification recipient
 */
export interface NotificationRecipient {
  id: string;
  name: string;
  channels: NotificationChannel[];
  contactInfo: {
    email?: string;
    slack?: string;
    webhook?: string;
    phone?: string;
  };
  preferences: {
    quietHours?: { start: string; end: string };
    maxNotificationsPerHour?: number;
    levels?: DegradationLevel[];
  };
}

/**
 * Notification delivery status
 */
export interface NotificationDelivery {
  id: string;
  eventId: string;
  recipientId: string;
  channel: NotificationChannel;
  status: 'pending' | 'sent' | 'failed' | 'rate_limited';
  sentAt?: Date;
  error?: string;
  retryCount: number;
}

/**
 * Notification statistics
 */
export interface NotificationStatistics {
  totalSent: number;
  totalFailed: number;
  rateLimited: number;
  byLevel: Record<DegradationLevel, number>;
  byChannel: Record<NotificationChannel, number>;
  averageDeliveryTime: number;
  lastNotificationTime?: Date;
  currentlyActiveNotifications: number;
}

/**
 * Degradation notifier configuration
 */
export interface DegradationNotifierConfig {
  // Rate limiting
  rateLimit: {
    enabled: boolean;
    maxNotificationsPerMinute: number;
    maxNotificationsPerHour: number;
    cooldownPeriodMs: number;
  };

  // Message formatting
  formatting: {
    includeTimestamp: boolean;
    includeMetrics: boolean;
    includeRecommendations: boolean;
    useMarkdown: boolean;
    truncateLongMessages: boolean;
    maxMessageLength: number;
  };

  // Delivery settings
  delivery: {
    retryAttempts: number;
    retryDelayMs: number;
    timeoutMs: number;
    enableBatching: boolean;
    batchSize: number;
    batchTimeoutMs: number;
  };

  // Channels
  channels: {
    enabled: NotificationChannel[];
    webhookUrl?: string;
    slackWebhookUrl?: string;
    emailSettings?: {
      smtpHost: string;
      smtpPort: number;
      username: string;
      password: string;
      from: string;
    };
  };

  // UI settings
  ui: {
    showUserFacingMessages: boolean;
    bannerMessage: string;
    detailedLogsEnabled: boolean;
    progressIndicatorEnabled: boolean;
  };
}

/**
 * Qdrant Degradation Notifier
 */
export class QdrantDegradationNotifier extends EventEmitter {
  private config: DegradationNotifierConfig;
  private recipients: Map<string, NotificationRecipient> = new Map();
  private deliveryHistory: NotificationDelivery[] = [];
  private activeNotifications: Map<string, DegradationEvent> = new Map();

  // Rate limiting
  private notificationCounts: Map<string, { count: number; lastReset: number }> = new Map();
  private lastGlobalNotification = 0;

  // Message templates
  private templates: Map<DegradationLevel, NotificationTemplate> = new Map();

  constructor(config?: Partial<DegradationNotifierConfig>) {
    super();

    this.config = {
      rateLimit: {
        enabled: true,
        maxNotificationsPerMinute: 10,
        maxNotificationsPerHour: 50,
        cooldownPeriodMs: 30000,
      },
      formatting: {
        includeTimestamp: true,
        includeMetrics: true,
        includeRecommendations: true,
        useMarkdown: false,
        truncateLongMessages: true,
        maxMessageLength: 2000,
      },
      delivery: {
        retryAttempts: 3,
        retryDelayMs: 5000,
        timeoutMs: 10000,
        enableBatching: false,
        batchSize: 10,
        batchTimeoutMs: 5000,
      },
      channels: {
        enabled: [NotificationChannel.LOG, NotificationChannel.CONSOLE],
      },
      ui: {
        showUserFacingMessages: true,
        bannerMessage: 'Database performance is degraded. Some features may be temporarily unavailable.',
        detailedLogsEnabled: true,
        progressIndicatorEnabled: true,
      },
      ...config,
    };

    this.initializeTemplates();
    logger.info('Qdrant degradation notifier initialized', {
      enabledChannels: this.config.channels.enabled,
      rateLimitEnabled: this.config.rateLimit.enabled,
    });
  }

  /**
   * Add notification recipient
   */
  addRecipient(recipient: NotificationRecipient): void {
    this.recipients.set(recipient.id, recipient);
    logger.debug({ recipientId: recipient.id }, 'Added notification recipient');
  }

  /**
   * Remove notification recipient
   */
  removeRecipient(recipientId: string): void {
    this.recipients.delete(recipientId);
    logger.debug({ recipientId }, 'Removed notification recipient');
  }

  /**
   * Send notification for degradation event
   */
  async sendNotification(event: DegradationEvent): Promise<NotificationDelivery[]> {
    const deliveries: NotificationDelivery[] = [];

    try {
      // Check rate limits
      if (!this.checkRateLimits(event)) {
        logger.debug({ eventId: event.id }, 'Notification rate limited');
        return [];
      }

      // Track active notification
      this.activeNotifications.set(event.id, event);

      // Get message template
      const template = this.getTemplateForLevel(event.level);

      // Format message
      const message = this.formatMessage(event, template);

      // Send to all recipients
      for (const recipient of this.recipients.values()) {
        if (this.shouldNotifyRecipient(recipient, event)) {
          const recipientDeliveries = await this.sendToRecipient(recipient, event, message, template);
          deliveries.push(...recipientDeliveries);
        }
      }

      // Update statistics
      this.updateStatistics(deliveries);

      logger.debug(
        {
          eventId: event.id,
          level: event.level,
          deliveriesCount: deliveries.length,
          successfulDeliveries: deliveries.filter(d => d.status === 'sent').length,
        },
        'Degradation notification sent'
      );

      this.emit('notification_sent', { event, deliveries });

    } catch (error) {
      logger.error({ error, eventId: event.id }, 'Failed to send degradation notification');
      this.emit('notification_error', { event, error });
    }

    return deliveries;
  }

  /**
   * Send recovery notification
   */
  async sendRecoveryNotification(event: DegradationEvent): Promise<NotificationDelivery[]> {
    const recoveryEvent: DegradationEvent = {
      ...event,
      level: DegradationLevel.HEALTHY,
      trigger: 'recovery',
      description: 'Qdrant service has recovered and is operating normally',
      recommendations: [
        'Monitor system stability',
        'Review incident reports for improvement opportunities',
        'Verify all services are functioning correctly',
      ],
    };

    return await this.sendNotification(recoveryEvent);
  }

  /**
   * Clear active notification
   */
  clearNotification(eventId: string): void {
    this.activeNotifications.delete(eventId);
    logger.debug({ eventId }, 'Cleared active notification');
  }

  /**
   * Get current notification statistics
   */
  getStatistics(): NotificationStatistics {
    const stats: NotificationStatistics = {
      totalSent: 0,
      totalFailed: 0,
      rateLimited: 0,
      byLevel: {
        [DegradationLevel.HEALTHY]: 0,
        [DegradationLevel.WARNING]: 0,
        [DegradationLevel.DEGRADED]: 0,
        [DegradationLevel.CRITICAL]: 0,
        [DegradationLevel.UNAVAILABLE]: 0,
      },
      byChannel: {} as Record<NotificationChannel, number>,
      averageDeliveryTime: 0,
      currentlyActiveNotifications: this.activeNotifications.size,
    };

    // Initialize channel counts
    for (const channel of Object.values(NotificationChannel)) {
      stats.byChannel[channel] = 0;
    }

    // Calculate statistics from delivery history
    const recentDeliveries = this.deliveryHistory.filter(
      d => Date.now() - d.sentAt!.getTime() < 24 * 60 * 60 * 1000 // Last 24 hours
    );

    let totalDeliveryTime = 0;
    let deliveryCount = 0;

    for (const delivery of recentDeliveries) {
      switch (delivery.status) {
        case 'sent':
          stats.totalSent++;
          {
            const lvl = (delivery as any).level as DegradationLevel | undefined;
            if (lvl !== undefined) stats.byLevel[lvl]++;
          }
          stats.byChannel[delivery.channel]++;
          break;
        case 'failed':
          stats.totalFailed++;
          break;
        case 'rate_limited':
          stats.rateLimited++;
          break;
      }

      if (delivery.sentAt) {
        totalDeliveryTime += delivery.sentAt.getTime();
        deliveryCount++;
      }
    }

    stats.averageDeliveryTime = deliveryCount > 0 ? totalDeliveryTime / deliveryCount : 0;
    stats.lastNotificationTime = recentDeliveries.length > 0
      ? recentDeliveries[recentDeliveries.length - 1].sentAt
      : undefined;

    return stats;
  }

  /**
   * Get active notifications
   */
  getActiveNotifications(): DegradationEvent[] {
    return Array.from(this.activeNotifications.values());
  }

  /**
   * Get user-facing message for current state
   */
  getUserFacingMessage(): {
    message: string;
    level: DegradationLevel;
    showProgress: boolean;
    actions: string[];
  } | null {
    if (!this.config.ui.showUserFacingMessages || this.activeNotifications.size === 0) {
      return null;
    }

    // Get highest priority active notification
    const events = Array.from(this.activeNotifications.values());
    const highestEvent = events.reduce((highest, current) => {
      const severityOrder = [
        DegradationLevel.UNAVAILABLE,
        DegradationLevel.CRITICAL,
        DegradationLevel.DEGRADED,
        DegradationLevel.WARNING,
        DegradationLevel.HEALTHY,
      ];
      return severityOrder.indexOf(current.level) < severityOrder.indexOf(highest.level) ? current : highest;
    });

    return {
      message: this.config.ui.bannerMessage,
      level: highestEvent.level,
      showProgress: this.config.ui.progressIndicatorEnabled,
      actions: this.getUserFacingActions(highestEvent),
    };
  }

  // === Private Methods ===

  /**
   * Initialize message templates
   */
  private initializeTemplates(): void {
    this.templates.set(DegradationLevel.WARNING, {
      level: DegradationLevel.WARNING,
      title: 'Performance Degradation Warning',
      message: 'Qdrant database is experiencing performance degradation. Some operations may be slower than usual.',
      severity: 'warning',
      estimatedDuration: '5-15 minutes',
      recommendedActions: [
        'Monitor response times',
        'Check recent query patterns',
        'Consider reducing query complexity',
      ],
    });

    this.templates.set(DegradationLevel.DEGRADED, {
      level: DegradationLevel.DEGRADED,
      title: 'Service Degraded',
      message: 'Qdrant database service is degraded. Some features may be temporarily unavailable or operating with reduced functionality.',
      severity: 'error',
      estimatedDuration: '15-30 minutes',
      recommendedActions: [
        'Use alternative features when possible',
        'Save work frequently',
        'Monitor system status updates',
      ],
      actions: [
        { label: 'View System Status', url: '/health' },
        { label: 'Report Issue', url: '/support' },
      ],
    });

    this.templates.set(DegradationLevel.CRITICAL, {
      level: DegradationLevel.CRITICAL,
      title: 'Critical Service Issues',
      message: 'Qdrant database is experiencing critical issues. Many features are unavailable. We are working to resolve the problem.',
      severity: 'critical',
      estimatedDuration: '30-60 minutes',
      recommendedActions: [
        'Avoid making changes until service is restored',
        'Monitor for recovery notifications',
        'Contact support if issues persist',
      ],
      actions: [
        { label: 'Emergency Status', url: '/emergency' },
        { label: 'Contact Support', url: '/support/urgent' },
      ],
    });

    this.templates.set(DegradationLevel.UNAVAILABLE, {
      level: DegradationLevel.UNAVAILABLE,
      title: 'Service Unavailable',
      message: 'Qdrant database is currently unavailable. All database-dependent features are offline. Emergency response is in progress.',
      severity: 'critical',
      estimatedDuration: '60+ minutes',
      recommendedActions: [
        'Do not attempt database operations',
        'Wait for service restoration',
        'Follow emergency procedures',
      ],
      actions: [
        { label: 'Emergency Dashboard', url: '/emergency' },
        { label: 'Incident Hotline', url: 'tel:1800-555-0199' },
      ],
    });

    this.templates.set(DegradationLevel.HEALTHY, {
      level: DegradationLevel.HEALTHY,
      title: 'Service Recovered',
      message: 'Qdrant database service has been restored and is operating normally.',
      severity: 'info',
      recommendedActions: [
        'Verify all features are working',
        'Check for any data inconsistencies',
        'Monitor system stability',
      ],
    });
  }

  /**
   * Get template for degradation level
   */
  private getTemplateForLevel(level: DegradationLevel): NotificationTemplate {
    return this.templates.get(level) || this.templates.get(DegradationLevel.WARNING)!;
  }

  /**
   * Format message based on event and template
   */
  private formatMessage(event: DegradationEvent, template: NotificationTemplate): string {
    let message = '';

    if (this.config.formatting.includeTimestamp) {
      message += `[${event.timestamp.toISOString()}] `;
    }

    message += `**${template.title}**\n\n`;
    message += `${template.message}\n\n`;

    if (event.description && event.description !== template.message) {
      message += `Details: ${event.description}\n\n`;
    }

    if (this.config.formatting.includeMetrics && event.metrics) {
      message += 'Current Metrics:\n';
      if (event.metrics.responseTime) {
        message += `- Response Time: ${event.metrics.responseTime}ms\n`;
      }
      if (event.metrics.errorRate) {
        message += `- Error Rate: ${event.metrics.errorRate.toFixed(2)}%\n`;
      }
      if (event.metrics.consecutiveFailures) {
        message += `- Consecutive Failures: ${event.metrics.consecutiveFailures}\n`;
      }
      message += '\n';
    }

    if (this.config.formatting.includeRecommendations && event.recommendations.length > 0) {
      message += 'Recommendations:\n';
      for (const recommendation of event.recommendations) {
        message += `- ${recommendation}\n`;
      }
      message += '\n';
    }

    if (template.estimatedDuration) {
      message += `Estimated Recovery Time: ${template.estimatedDuration}\n\n`;
    }

    if (template.actions && template.actions.length > 0) {
      message += 'Actions:\n';
      for (const action of template.actions) {
        message += `- [${action.label}]${action.url ? `(${action.url})` : ''}\n`;
      }
    }

    // Truncate if too long
    if (this.config.formatting.truncateLongMessages && message.length > this.config.formatting.maxMessageLength) {
      message = message.substring(0, this.config.formatting.maxMessageLength - 3) + '...';
    }

    return message;
  }

  /**
   * Check if should notify recipient
   */
  private shouldNotifyRecipient(recipient: NotificationRecipient, event: DegradationEvent): boolean {
    // Check level preferences
    if (recipient.preferences.levels && !recipient.preferences.levels.includes(event.level)) {
      return false;
    }

    // Check quiet hours
    if (recipient.preferences.quietHours) {
      const now = new Date();
      const currentTime = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;
      const { start, end } = recipient.preferences.quietHours;

      if (currentTime >= start && currentTime <= end && event.level !== DegradationLevel.CRITICAL) {
        return false;
      }
    }

    // Check hourly rate limit for recipient
    if (recipient.preferences.maxNotificationsPerHour) {
      const hourlyCount = this.getRecipientNotificationCount(recipient.id, 'hour');
      if (hourlyCount >= recipient.preferences.maxNotificationsPerHour) {
        return false;
      }
    }

    return true;
  }

  /**
   * Send notification to recipient
   */
  private async sendToRecipient(
    recipient: NotificationRecipient,
    event: DegradationEvent,
    message: string,
    template: NotificationTemplate
  ): Promise<NotificationDelivery[]> {
    const deliveries: NotificationDelivery[] = [];

    for (const channel of recipient.channels) {
      if (!this.config.channels.enabled.includes(channel)) {
        continue;
      }

      const delivery: NotificationDelivery = {
        id: this.generateDeliveryId(),
        eventId: event.id,
        recipientId: recipient.id,
        channel,
        status: 'pending',
        retryCount: 0,
      };

      try {
        await this.sendToChannel(channel, recipient, message, template);
        delivery.status = 'sent';
        delivery.sentAt = new Date();
      } catch (error) {
        delivery.status = 'failed';
        delivery.error = error instanceof Error ? error.message : 'Unknown error';

        // Schedule retry if configured
        if (delivery.retryCount < this.config.delivery.retryAttempts) {
          setTimeout(() => {
            this.retryDelivery(delivery, recipient, message, template);
          }, this.config.delivery.retryDelayMs);
        }
      }

      deliveries.push(delivery);
      this.deliveryHistory.push(delivery);
    }

    return deliveries;
  }

  /**
   * Send to specific channel
   */
  private async sendToChannel(
    channel: NotificationChannel,
    recipient: NotificationRecipient,
    message: string,
    template: NotificationTemplate
  ): Promise<void> {
    const logWithSeverity = (
      sev: 'info' | 'error' | 'warning' | 'critical',
      meta: any,
      msg: string
    ) => {
      if (sev === 'warning' && (logger as any).warn) return (logger as any).warn(meta, msg);
      if (sev === 'critical' && (logger as any).error) return logger.error(meta, msg);
      if (sev === 'info' && (logger as any).info) return logger.info(meta, msg);
      if (sev === 'error' && (logger as any).error) return logger.error(meta, msg);
      return logger.info?.(meta, msg);
    };
    switch (channel) {
      case NotificationChannel.LOG:
        logWithSeverity(template.severity as any, { recipientId: recipient.id }, message);
        break;

      case NotificationChannel.CONSOLE:
        console.log(`[${template.severity.toUpperCase()}] ${message}`);
        break;

      case NotificationChannel.WEBHOOK:
        if (this.config.channels.webhookUrl) {
          await this.sendWebhook(this.config.channels.webhookUrl, message, template);
        }
        break;

      case NotificationChannel.SLACK:
        if (this.config.channels.slackWebhookUrl) {
          await this.sendSlackNotification(this.config.channels.slackWebhookUrl, message, template);
        }
        break;

      case NotificationChannel.EMAIL:
        if (recipient.contactInfo.email && this.config.channels.emailSettings) {
          await this.sendEmail(recipient.contactInfo.email, message, template);
        }
        break;

      case NotificationChannel.DASHBOARD:
        // Update dashboard UI
        this.emit('dashboard_update', { message, template, recipientId: recipient.id });
        break;

      case NotificationChannel.API:
        // Send via API callback
        this.emit('api_notification', { message, template, recipientId: recipient.id });
        break;

      default:
        throw new Error(`Unsupported notification channel: ${channel}`);
    }
  }

  /**
   * Check rate limits
   */
  private checkRateLimits(event: DegradationEvent): boolean {
    if (!this.config.rateLimit.enabled) {
      return true;
    }

    const now = Date.now();

    // Global cooldown
    if (now - this.lastGlobalNotification < this.config.rateLimit.cooldownPeriodMs) {
      return false;
    }

    // Per-minute rate limit
    const minuteKey = `${Math.floor(now / 60000)}`;
    const minuteCount = this.notificationCounts.get(minuteKey)?.count || 0;
    if (minuteCount >= this.config.rateLimit.maxNotificationsPerMinute) {
      return false;
    }

    // Per-hour rate limit
    const hourKey = `${Math.floor(now / 3600000)}`;
    const hourCount = this.notificationCounts.get(hourKey)?.count || 0;
    if (hourCount >= this.config.rateLimit.maxNotificationsPerHour) {
      return false;
    }

    // Update counters
    this.notificationCounts.set(minuteKey, { count: minuteCount + 1, lastReset: now });
    this.notificationCounts.set(hourKey, { count: hourCount + 1, lastReset: now });
    this.lastGlobalNotification = now;

    return true;
  }

  /**
   * Get recipient notification count
   */
  private getRecipientNotificationCount(recipientId: string, period: 'minute' | 'hour'): number {
    const now = Date.now();
    const cutoff = period === 'minute' ? now - 60000 : now - 3600000;

    return this.deliveryHistory.filter(
      d => d.recipientId === recipientId &&
           d.sentAt &&
           d.sentAt.getTime() > cutoff &&
           d.status === 'sent'
    ).length;
  }

  /**
   * Retry failed delivery
   */
  private async retryDelivery(
    delivery: NotificationDelivery,
    recipient: NotificationRecipient,
    message: string,
    template: NotificationTemplate
  ): Promise<void> {
    delivery.retryCount++;

    try {
      await this.sendToChannel(delivery.channel, recipient, message, template);
      delivery.status = 'sent';
      delivery.sentAt = new Date();

      logger.debug(
        { deliveryId: delivery.id, retryCount: delivery.retryCount },
        'Notification delivery retry successful'
      );

    } catch (error) {
      delivery.status = 'failed';
      delivery.error = error instanceof Error ? error.message : 'Unknown error';

      logger.warn(
        { deliveryId: delivery.id, retryCount: delivery.retryCount, error: delivery.error },
        'Notification delivery retry failed'
      );

      // Schedule another retry if under limit
      if (delivery.retryCount < this.config.delivery.retryAttempts) {
        setTimeout(() => {
          this.retryDelivery(delivery, recipient, message, template);
        }, this.config.delivery.retryDelayMs * delivery.retryCount);
      }
    }
  }

  /**
   * Update statistics
   */
  private updateStatistics(deliveries: NotificationDelivery[]): void {
    // Clean old delivery history (keep last 1000)
    if (this.deliveryHistory.length > 1000) {
      this.deliveryHistory = this.deliveryHistory.slice(-1000);
    }
  }

  /**
   * Get user-facing actions
   */
  private getUserFacingActions(event: DegradationEvent): string[] {
    const actions: string[] = [];

    switch (event.level) {
      case DegradationLevel.WARNING:
        actions.push('Continue using the system normally');
        actions.push('Monitor performance for changes');
        break;

      case DegradationLevel.DEGRADED:
        actions.push('Save work frequently');
        actions.push('Try again later if operations fail');
        actions.push('Use alternative features when possible');
        break;

      case DegradationLevel.CRITICAL:
        actions.push('Avoid making important changes');
        actions.push('Wait for service restoration');
        actions.push('Contact support if needed');
        break;

      case DegradationLevel.UNAVAILABLE:
        actions.push('Wait for service to be restored');
        actions.push('Do not refresh the page repeatedly');
        actions.push('Follow status updates');
        break;
    }

    return actions;
  }

  // === Channel-specific implementations ===

  private async sendWebhook(url: string, message: string, template: NotificationTemplate): Promise<void> {
    const payload = {
      title: template.title,
      message,
      severity: template.severity,
      timestamp: new Date().toISOString(),
      source: 'qdrant-degradation-notifier',
    };

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(this.config.delivery.timeoutMs),
    });

    if (!response.ok) {
      throw new Error(`Webhook delivery failed: ${response.status} ${response.statusText}`);
    }
  }

  private async sendSlackNotification(url: string, message: string, template: NotificationTemplate): Promise<void> {
    const payload = {
      text: template.title,
      attachments: [
        {
          color: template.severity === 'critical' ? 'danger' :
                 template.severity === 'error' ? 'warning' :
                 template.severity === 'warning' ? 'warning' : 'good',
          text: message,
          fields: [
            {
              title: 'Severity',
              value: template.severity.toUpperCase(),
              short: true,
            },
            {
              title: 'Source',
              value: 'Qdrant Degradation Monitor',
              short: true,
            },
          ],
          ts: Math.floor(Date.now() / 1000),
        },
      ],
    };

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(this.config.delivery.timeoutMs),
    });

    if (!response.ok) {
      throw new Error(`Slack delivery failed: ${response.status} ${response.statusText}`);
    }
  }

  private async sendEmail(email: string, message: string, template: NotificationTemplate): Promise<void> {
    // Email implementation would go here
    logger.debug({ email, template: template.title }, 'Email notification would be sent');
  }

  /**
   * Generate delivery ID
   */
  private generateDeliveryId(): string {
    return `del_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  stop?: unknown|undefined
  start?: unknown|undefined}

export default QdrantDegradationNotifier;
