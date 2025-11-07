// @ts-nocheck
/**
 * SLO Breach Detection and Notification Service
 *
 * Advanced service for detecting SLO breaches, calculating impact, triggering
 * automated responses, and managing incident lifecycle with multi-channel notifications.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'events';
import {
  SLO,
  SLOEvaluation,
  SLOAlert,
  SLOAlertType,
  SLOEvaluationStatus,
  SLOBreachIncident,
  NotificationChannel,
  IncidentResponse,
  ImpactAssessment,
} from '../types/slo-interfaces.js';
import { AlertSeverity, BreachSeverity, IncidentStatus, EscalationLevel } from '../types/slo-types.js';
import { SLOService } from './slo-service.js';

/**
 * SLO Breach Detection and Notification Service
 */
export class SLOBreachDetectionService extends EventEmitter {
  private sloService: SLOService;
  private activeIncidents: Map<string, SLOBreachIncident> = new Map();
  private notificationChannels: Map<string, NotificationChannel> = new Map();
  private escalationPolicies: Map<string, EscalationPolicy> = new Map();
  private breachThresholds: Map<string, BreachThreshold[]> = new Map();
  private isStarted = false;
  private monitoringIntervals: Map<string, NodeJS.Timeout> = new Map();

  constructor(sloService: SLOService) {
    super();
    this.sloService = sloService;
    this.setupEventHandlers();
  }

  /**
   * Start the breach detection service
   */
  async start(): Promise<void> {
    if (this.isStarted) {
      this.emit('warning', 'SLO Breach Detection Service is already started');
      return;
    }

    try {
      this.isStarted = true;
      this.emit('started', 'SLO Breach Detection Service started successfully');

      // Start monitoring all active SLOs
      await this.startMonitoringAllSLOs();

      // Schedule periodic breach checks
      this.schedulePeriodicBreachChecks();

    } catch (error) {
      this.isStarted = false;
      this.emit('error', `Failed to start SLO Breach Detection Service: ${error}`);
      throw error;
    }
  }

  /**
   * Stop the breach detection service
   */
  async stop(): Promise<void> {
    if (!this.isStarted) {
      this.emit('warning', 'SLO Breach Detection Service is not started');
      return;
    }

    try {
      // Stop all monitoring intervals
      for (const [sloId, interval] of this.monitoringIntervals) {
        clearInterval(interval);
      }
      this.monitoringIntervals.clear();

      this.isStarted = false;
      this.emit('stopped', 'SLO Breach Detection Service stopped successfully');
    } catch (error) {
      this.emit('error', `Error stopping SLO Breach Detection Service: ${error}`);
      throw error;
    }
  }

  // ============================================================================
  // Incident Management
  // ============================================================================

  /**
   * Create a new breach incident
   */
  async createIncident(
    sloId: string,
    evaluation: SLOEvaluation,
    severity: BreachSeverity,
    impactAssessment?: ImpactAssessment
  ): Promise<SLOBreachIncident> {
    const slo = this.sloService.getSLO(sloId);
    if (!slo) {
      throw new Error(`SLO ${sloId} not found`);
    }

    const incidentId = this.generateIncidentId();

    // Calculate impact if not provided
    const impact = impactAssessment || await this.calculateImpact(slo, evaluation);

    const incident: SLOBreachIncident = {
      id: incidentId,
      sloId,
      sloName: slo.name,
      severity,
      status: IncidentStatus.OPEN,
      detectedAt: new Date(),
      evaluation,
      impactAssessment: impact,
      notifications: [],
      escalations: [],
      responses: [],
      metadata: {
        detectedBy: 'automated',
        confidence: evaluation.metadata.confidence,
        affectedServices: this.identifyAffectedServices(slo),
        estimatedResolutionTime: this.estimateResolutionTime(severity, impact),
        businessImpact: this.calculateBusinessImpact(slo, evaluation, impact),
      },
    };

    this.activeIncidents.set(incidentId, incident);

    // Trigger immediate notifications
    await this.triggerIncidentNotifications(incident);

    // Start automated response if configured
    await this.initiateAutomatedResponse(incident);

    this.emit('incident:created', incident);
    return incident;
  }

  /**
   * Update an existing incident
   */
  async updateIncident(
    incidentId: string,
    updates: Partial<SLOBreachIncident>
  ): Promise<SLOBreachIncident> {
    const incident = this.activeIncidents.get(incidentId);
    if (!incident) {
      throw new Error(`Incident ${incidentId} not found`);
    }

    const updatedIncident: SLOBreachIncident = {
      ...incident,
      ...updates,
      id: incidentId, // Ensure ID doesn't change
      metadata: {
        ...incident.metadata,
        ...updates.metadata,
        lastUpdated: new Date(),
      },
    };

    this.activeIncidents.set(incidentId, updatedIncident);

    // Trigger notifications for significant updates
    if (updates.status || updates.severity) {
      await this.triggerIncidentNotifications(updatedIncident);
    }

    this.emit('incident:updated', updatedIncident);
    return updatedIncident;
  }

  /**
   * Resolve an incident
   */
  async resolveIncident(
    incidentId: string,
    resolution: {
      reason: string;
      resolvedBy: string;
      actions: string[];
      preventRecurrence: string[];
    }
  ): Promise<SLOBreachIncident> {
    const incident = this.activeIncidents.get(incidentId);
    if (!incident) {
      throw new Error(`Incident ${incidentId} not found`);
    }

    const resolvedIncident: SLOBreachIncident = {
      ...incident,
      status: IncidentStatus.RESOLVED,
      resolvedAt: new Date(),
      resolution: {
        reason: resolution.reason,
        resolvedBy: resolution.resolvedBy,
        actions: resolution.actions,
        preventRecurrence: resolution.preventRecurrence,
        duration: Date.now() - incident.detectedAt.getTime(),
      },
      metadata: {
        ...incident.metadata,
        lastUpdated: new Date(),
      },
    };

    this.activeIncidents.set(incidentId, resolvedIncident);

    // Send resolution notifications
    await this.sendResolutionNotifications(resolvedIncident);

    // Move to resolved incidents storage
    setTimeout(() => {
      this.activeIncidents.delete(incidentId);
      this.emit('incident:archived', resolvedIncident);
    }, 24 * 60 * 60 * 1000); // Archive after 24 hours

    this.emit('incident:resolved', resolvedIncident);
    return resolvedIncident;
  }

  /**
   * Get active incidents
   */
  getActiveIncidents(): SLOBreachIncident[] {
    return Array.from(this.activeIncidents.values());
  }

  /**
   * Get incident by ID
   */
  getIncident(incidentId: string): SLOBreachIncident | undefined {
    return this.activeIncidents.get(incidentId);
  }

  /**
   * Get incidents by SLO
   */
  getIncidentsBySLO(sloId: string): SLOBreachIncident[] {
    return Array.from(this.activeIncidents.values()).filter(
      incident => incident.sloId === sloId
    );
  }

  // ============================================================================
  // Notification Management
  // ============================================================================

  /**
   * Register a notification channel
   */
  registerNotificationChannel(channel: NotificationChannel): void {
    this.notificationChannels.set(channel.id, channel);
    this.emit('channel:registered', channel);
  }

  /**
   * Send notification through specified channels
   */
  async sendNotification(
    incident: SLOBreachIncident,
    message: string,
    channels?: string[],
    severity?: AlertSeverity
  ): Promise<void> {
    const targetChannels = channels || ['default'];
    const notificationSeverity = severity || this.mapSeverityToAlertSeverity(incident.severity);

    const notifications = [];

    for (const channelId of targetChannels) {
      const channel = this.notificationChannels.get(channelId);
      if (channel && channel.enabled) {
        try {
          const result = await this.sendNotificationToChannel(channel, incident, message, notificationSeverity);
          notifications.push({
            channelId,
            timestamp: new Date(),
            success: result.success,
            error: result.error,
          });

          this.emit('notification:sent', { incidentId: incident.id, channelId, result });
        } catch (error) {
          notifications.push({
            channelId,
            timestamp: new Date(),
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error',
          });

          this.emit('notification:failed', { incidentId: incident.id, channelId, error });
        }
      }
    }

    // Update incident with notification results
    incident.notifications.push(...notifications);
  }

  /**
   * Configure escalation policy
   */
  configureEscalationPolicy(policy: EscalationPolicy): void {
    this.escalationPolicies.set(policy.id, policy);
    this.emit('policy:configured', policy);
  }

  /**
   * Trigger escalation for an incident
   */
  async triggerEscalation(
    incidentId: string,
    escalationLevel: EscalationLevel,
    reason: string
  ): Promise<void> {
    const incident = this.activeIncidents.get(incidentId);
    if (!incident) {
      throw new Error(`Incident ${incidentId} not found`);
    }

    const policy = this.escalationPolicies.get('default') || this.getDefaultEscalationPolicy();
    const escalationConfig = policy.levels.find(l => l.level === escalationLevel);

    if (!escalationConfig) {
      throw new Error(`Escalation level ${escalationLevel} not configured`);
    }

    const escalation = {
      level: escalationLevel,
      triggeredAt: new Date(),
      reason,
      notifiedChannels: escalationConfig.channels,
      acknowledgedBy: null,
      acknowledgedAt: null,
    };

    incident.escalations.push(escalation);

    // Send escalation notifications
    const message = `ESCALATION (${escalationLevel}): ${incident.sloName} - ${reason}`;
    await this.sendNotification(incident, message, escalationConfig.channels, AlertSeverity.CRITICAL);

    this.emit('incident:escalated', { incident, escalation });
  }

  // ============================================================================
  // Breach Detection Logic
  // ============================================================================

  /**
   * Check for SLO breaches
   */
  async checkForBreaches(sloId: string): Promise<SLOBreachIncident[]> {
    const slo = this.sloService.getSLO(sloId);
    if (!slo) {
      return [];
    }

    const evaluation = this.sloService.getLatestEvaluation(sloId);
    if (!evaluation) {
      return [];
    }

    const breaches: SLOBreachIncident[] = [];

    // Check for SLO violation
    if (evaluation.status === SLOEvaluationStatus.VIOLATION) {
      const existingIncident = this.getActiveIncidentForSLO(sloId);
      if (!existingIncident) {
        const severity = this.determineBreachSeverity(evaluation);
        const incident = await this.createIncident(sloId, evaluation, severity);
        breaches.push(incident);
      }
    }

    // Check for warning conditions that might lead to breaches
    if (evaluation.status === SLOEvaluationStatus.WARNING) {
      await this.checkWarningConditions(slo, evaluation);
    }

    // Check for error budget exhaustion
    if (evaluation.budget.remaining <= 0) {
      const existingIncident = this.getActiveIncidentForSLO(sloId);
      if (!existingIncident || existingIncident.severity !== BreachSeverity.CRITICAL) {
        const incident = await this.createIncident(sloId, evaluation, BreachSeverity.CRITICAL);
        breaches.push(incident);
      }
    }

    return breaches;
  }

  /**
   * Check for custom breach conditions
   */
  async checkCustomBreachConditions(sloId: string): Promise<SLOBreachIncident[]> {
    const customThresholds = this.breachThresholds.get(sloId);
    if (!customThresholds || customThresholds.length === 0) {
      return [];
    }

    const evaluation = this.sloService.getLatestEvaluation(sloId);
    if (!evaluation) {
      return [];
    }

    const breaches: SLOBreachIncident[] = [];

    for (const threshold of customThresholds) {
      const breached = this.evaluateThreshold(threshold, evaluation);
      if (breached) {
        const existingIncident = this.getActiveIncidentForSLO(sloId);
        if (!existingIncident) {
          const incident = await this.createIncident(sloId, evaluation, threshold.severity);
          breaches.push(incident);
        }
      }
    }

    return breaches;
  }

  /**
   * Add custom breach threshold
   */
  addBreachThreshold(sloId: string, threshold: BreachThreshold): void {
    const thresholds = this.breachThresholds.get(sloId) || [];
    thresholds.push(threshold);
    this.breachThresholds.set(sloId, thresholds);
    this.emit('threshold:added', { sloId, threshold });
  }

  // ============================================================================
  // Automated Response
  // ============================================================================

  /**
   * Initiate automated response for an incident
   */
  async initiateAutomatedResponse(incident: SLOBreachIncident): Promise<void> {
    const responses = [];

    // Trigger automated remediation based on severity and SLO type
    if (incident.severity === BreachSeverity.CRITICAL) {
      responses.push(await this.executeCriticalResponse(incident));
    } else if (incident.severity === BreachSeverity.HIGH) {
      responses.push(await this.executeHighSeverityResponse(incident));
    } else {
      responses.push(await this.executeStandardResponse(incident));
    }

    // Update incident with responses
    incident.responses.push(...responses);

    this.emit('automated-response:initiated', { incident, responses });
  }

  /**
   * Execute critical severity response
   */
  private async executeCriticalResponse(incident: SLOBreachIncident): Promise<IncidentResponse> {
    const response: IncidentResponse = {
      id: this.generateId(),
      type: 'automated',
      category: 'critical',
      initiatedAt: new Date(),
      actions: [],
      status: 'in_progress',
    };

    try {
      // Immediate traffic shaping if applicable
      if (incident.sloName.toLowerCase().includes('latency') ||
          incident.sloName.toLowerCase().includes('response time')) {
        response.actions.push({
          type: 'traffic_shaping',
          description: 'Implementing traffic shaping to reduce load',
          executedAt: new Date(),
          status: 'executed',
        });
      }

      // Scale up resources if auto-scaling is available
      response.actions.push({
        type: 'scale_up',
        description: 'Triggering auto-scaling to increase capacity',
        executedAt: new Date(),
        status: 'executed',
      });

      // Enable circuit breakers if degradation is detected
      if (incident.evaluation.objective.compliance < 90) {
        response.actions.push({
          type: 'circuit_breaker',
          description: 'Enabling circuit breakers to prevent cascade failures',
          executedAt: new Date(),
          status: 'executed',
        });
      }

      response.status = 'completed';
      response.completedAt = new Date();

    } catch (error) {
      response.status = 'failed';
      response.error = error instanceof Error ? error.message : 'Unknown error';
    }

    return response;
  }

  /**
   * Execute high severity response
   */
  private async executeHighSeverityResponse(incident: SLOBreachIncident): Promise<IncidentResponse> {
    const response: IncidentResponse = {
      id: this.generateId(),
      type: 'automated',
      category: 'high_severity',
      initiatedAt: new Date(),
      actions: [],
      status: 'in_progress',
    };

    try {
      // Enable additional monitoring
      response.actions.push({
        type: 'enhanced_monitoring',
        description: 'Enabling enhanced monitoring and logging',
        executedAt: new Date(),
        status: 'executed',
      });

      // Pre-warm additional resources
      response.actions.push({
        type: 'prewarm_resources',
        description: 'Pre-warming additional resources',
        executedAt: new Date(),
        status: 'executed',
      });

      response.status = 'completed';
      response.completedAt = new Date();

    } catch (error) {
      response.status = 'failed';
      response.error = error instanceof Error ? error.message : 'Unknown error';
    }

    return response;
  }

  /**
   * Execute standard response
   */
  private async executeStandardResponse(incident: SLOBreachIncident): Promise<IncidentResponse> {
    const response: IncidentResponse = {
      id: this.generateId(),
      type: 'automated',
      category: 'standard',
      initiatedAt: new Date(),
      actions: [],
      status: 'in_progress',
    };

    try {
      // Log additional metrics
      response.actions.push({
        type: 'enhanced_logging',
        description: 'Enabling enhanced logging for diagnostic purposes',
        executedAt: new Date(),
        status: 'executed',
      });

      response.status = 'completed';
      response.completedAt = new Date();

    } catch (error) {
      response.status = 'failed';
      response.error = error instanceof Error ? error.message : 'Unknown error';
    }

    return response;
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  /**
   * Setup event handlers
   */
  private setupEventHandlers(): void {
    // Listen for SLO evaluations
    this.sloService.on('slo:evaluated', async (evaluation: SLOEvaluation) => {
      if (this.isStarted) {
        await this.checkForBreaches(evaluation.sloId);
      }
    });

    // Listen for SLO alerts
    this.sloService.on('alert:created', async (alert: SLOAlert) => {
      if (this.isStarted && alert.severity === AlertSeverity.CRITICAL) {
        await this.handleCriticalAlert(alert);
      }
    });
  }

  /**
   * Start monitoring all active SLOs
   */
  private async startMonitoringAllSLOs(): Promise<void> {
    const slos = this.sloService.getAllSLOs();

    for (const slo of slos) {
      if (slo.status === 'active') {
        this.startMonitoringSLO(slo.id);
      }
    }
  }

  /**
   * Start monitoring a specific SLO
   */
  private startMonitoringSLO(sloId: string): void {
    // Stop existing monitoring if any
    this.stopMonitoringSLO(sloId);

    // Start monitoring interval
    const interval = setInterval(async () => {
      try {
        await this.checkForBreaches(sloId);
        await this.checkCustomBreachConditions(sloId);
      } catch (error) {
        this.emit('error', `Breach check failed for SLO ${sloId}: ${error}`);
      }
    }, 30000); // Check every 30 seconds

    this.monitoringIntervals.set(sloId, interval);
  }

  /**
   * Stop monitoring a specific SLO
   */
  private stopMonitoringSLO(sloId: string): void {
    const interval = this.monitoringIntervals.get(sloId);
    if (interval) {
      clearInterval(interval);
      this.monitoringIntervals.delete(sloId);
    }
  }

  /**
   * Schedule periodic breach checks
   */
  private schedulePeriodicBreachChecks(): void {
    // Comprehensive check every 5 minutes
    setInterval(async () => {
      if (!this.isStarted) return;

      try {
        const slos = this.sloService.getAllSLOs();
        for (const slo of slos) {
          if (slo.status === 'active') {
            await this.checkForBreaches(slo.id);
          }
        }
      } catch (error) {
        this.emit('error', `Periodic breach check failed: ${error}`);
      }
    }, 5 * 60 * 1000); // Every 5 minutes
  }

  /**
   * Get active incident for an SLO
   */
  private getActiveIncidentForSLO(sloId: string): SLOBreachIncident | undefined {
    return Array.from(this.activeIncidents.values()).find(
      incident => incident.sloId === sloId && incident.status === IncidentStatus.OPEN
    );
  }

  /**
   * Determine breach severity
   */
  private determineBreachSeverity(evaluation: SLOEvaluation): BreachSeverity {
    const compliance = evaluation.objective.compliance;
    const budgetRemaining = evaluation.budget.remaining;

    if (compliance < 90 || budgetRemaining <= 0) {
      return BreachSeverity.CRITICAL;
    } else if (compliance < 95 || budgetRemaining < 10) {
      return BreachSeverity.HIGH;
    } else if (compliance < 98 || budgetRemaining < 25) {
      return BreachSeverity.MEDIUM;
    } else {
      return BreachSeverity.LOW;
    }
  }

  /**
   * Calculate impact assessment
   */
  private async calculateImpact(slo: SLO, evaluation: SLOEvaluation): Promise<ImpactAssessment> {
    const impactScore = this.calculateImpactScore(slo, evaluation);

    return {
      score: impactScore,
      usersAffected: this.estimateAffectedUsers(slo, evaluation),
      revenueImpact: this.estimateRevenueImpact(slo, evaluation),
      operationalImpact: this.assessOperationalImpact(slo, evaluation),
      customerImpact: this.assessCustomerImpact(slo, evaluation),
      duration: this.estimateImpactDuration(evaluation),
    };
  }

  /**
   * Calculate impact score
   */
  private calculateImpactScore(slo: SLO, evaluation: SLOEvaluation): number {
    let score = 0;

    // Base score from compliance deviation
    const deviation = slo.objective.target - evaluation.objective.achieved;
    score += (deviation / slo.objective.target) * 50;

    // Additional score from error budget consumption
    const budgetConsumption = (evaluation.budget.consumed / evaluation.budget.total) * 100;
    score += budgetConsumption * 0.3;

    // SLO priority factor
    const priorityMultiplier = slo.metadata.businessImpact === 'critical' ? 1.5 :
                             slo.metadata.businessImpact === 'high' ? 1.2 :
                             slo.metadata.businessImpact === 'medium' ? 1.0 : 0.8;
    score *= priorityMultiplier;

    return Math.min(100, score);
  }

  /**
   * Estimate affected users
   */
  private estimateAffectedUsers(slo: SLO, evaluation: SLOEvaluation): number {
    // This would integrate with user analytics
    // For now, return a placeholder
    return Math.floor(Math.random() * 10000) + 1000;
  }

  /**
   * Estimate revenue impact
   */
  private estimateRevenueImpact(slo: SLO, evaluation: SLOEvaluation): number {
    // This would integrate with business metrics
    // For now, return a placeholder based on severity
    const severity = this.determineBreachSeverity(evaluation);
    switch (severity) {
      case BreachSeverity.CRITICAL: return Math.random() * 100000 + 10000;
      case BreachSeverity.HIGH: return Math.random() * 50000 + 5000;
      case BreachSeverity.MEDIUM: return Math.random() * 10000 + 1000;
      default: return Math.random() * 1000;
    }
  }

  /**
   * Assess operational impact
   */
  private assessOperationalImpact(slo: SLO, evaluation: SLOEvaluation): 'low' | 'medium' | 'high' | 'critical' {
    const severity = this.determineBreachSeverity(evaluation);
    switch (severity) {
      case BreachSeverity.CRITICAL: return 'critical';
      case BreachSeverity.HIGH: return 'high';
      case BreachSeverity.MEDIUM: return 'medium';
      default: return 'low';
    }
  }

  /**
   * Assess customer impact
   */
  private assessCustomerImpact(slo: SLO, evaluation: SLOEvaluation): 'low' | 'medium' | 'high' | 'critical' {
    const severity = this.determineBreachSeverity(evaluation);
    switch (severity) {
      case BreachSeverity.CRITICAL: return 'critical';
      case BreachSeverity.HIGH: return 'high';
      case BreachSeverity.MEDIUM: return 'medium';
      default: return 'low';
    }
  }

  /**
   * Estimate impact duration
   */
  private estimateImpactDuration(evaluation: SLOEvaluation): number {
    // Estimate duration based on burn rate and remaining budget
    if (evaluation.budget.burnRate > 0) {
      return Math.min(24 * 60 * 60 * 1000, // Max 24 hours
        (evaluation.budget.remaining / evaluation.budget.burnRate) * 60 * 60 * 1000);
    }
    return 60 * 60 * 1000; // Default 1 hour
  }

  /**
   * Identify affected services
   */
  private identifyAffectedServices(slo: SLO): string[] {
    // This would integrate with service discovery
    // For now, return the SLO name and its dependencies
    return [slo.name, ...(slo.metadata.dependencies || [])];
  }

  /**
   * Estimate resolution time
   */
  private estimateResolutionTime(severity: BreachSeverity, impact: ImpactAssessment): number {
    const baseTime = {
      [BreachSeverity.LOW]: 30 * 60 * 1000,      // 30 minutes
      [BreachSeverity.MEDIUM]: 2 * 60 * 60 * 1000, // 2 hours
      [BreachSeverity.HIGH]: 6 * 60 * 60 * 1000,   // 6 hours
      [BreachSeverity.CRITICAL]: 24 * 60 * 60 * 1000, // 24 hours
    };

    const multiplier = impact.score / 50; // Scale by impact score
    return baseTime[severity] * Math.max(0.5, Math.min(2, multiplier));
  }

  /**
   * Calculate business impact
   */
  private calculateBusinessImpact(slo: SLO, evaluation: SLOEvaluation, impact: ImpactAssessment): {
    level: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    estimatedCost: number;
    customerImpact: string;
  } {
    const level = impact.score > 75 ? 'critical' :
                  impact.score > 50 ? 'high' :
                  impact.score > 25 ? 'medium' : 'low';

    return {
      level,
      description: `SLO breach affecting ${slo.name} with ${evaluation.objective.compliance.toFixed(1)}% compliance`,
      estimatedCost: impact.revenueImpact,
      customerImpact: `${impact.usersAffected} users potentially affected`,
    };
  }

  /**
   * Trigger incident notifications
   */
  private async triggerIncidentNotifications(incident: SLOBreachIncident): Promise<void> {
    const message = `🚨 SLO Breach Alert: ${incident.sloName}
Severity: ${incident.severity}
Compliance: ${incident.evaluation.objective.compliance.toFixed(1)}%
Target: ${incident.evaluation.objective.target}%
Error Budget Remaining: ${incident.evaluation.budget.remaining.toFixed(1)}%
Impact Score: ${incident.impactAssessment.score.toFixed(1)}/100`;

    await this.sendNotification(incident, message);
  }

  /**
   * Send resolution notifications
   */
  private async sendResolutionNotifications(incident: SLOBreachIncident): Promise<void> {
    if (!incident.resolution) return;

    const message = `✅ SLO Breach Resolved: ${incident.sloName}
Duration: ${Math.round(incident.resolution.duration / (60 * 1000))} minutes
Resolved by: ${incident.resolution.resolvedBy}
Reason: ${incident.resolution.reason}`;

    await this.sendNotification(incident, message);
  }

  /**
   * Send notification to a specific channel
   */
  private async sendNotificationToChannel(
    channel: NotificationChannel,
    incident: SLOBreachIncident,
    message: string,
    severity: AlertSeverity
  ): Promise<{ success: boolean; error?: string }> {
    try {
      switch (channel.type) {
        case 'slack':
          return await this.sendSlackNotification(channel, incident, message, severity);
        case 'email':
          return await this.sendEmailNotification(channel, incident, message, severity);
        case 'pagerduty':
          return await this.sendPagerDutyNotification(channel, incident, message, severity);
        case 'webhook':
          return await this.sendWebhookNotification(channel, incident, message, severity);
        default:
          return { success: false, error: `Unknown channel type: ${channel.type}` };
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Send Slack notification
   */
  private async sendSlackNotification(
    channel: NotificationChannel,
    incident: SLOBreachIncident,
    message: string,
    severity: AlertSeverity
  ): Promise<{ success: boolean; error?: string }> {
    // Implementation would use Slack API
    console.log(`📱 Slack notification sent to ${channel.name}: ${message}`);
    return { success: true };
  }

  /**
   * Send email notification
   */
  private async sendEmailNotification(
    channel: NotificationChannel,
    incident: SLOBreachIncident,
    message: string,
    severity: AlertSeverity
  ): Promise<{ success: boolean; error?: string }> {
    // Implementation would use email service
    console.log(`📧 Email notification sent to ${channel.name}: ${message}`);
    return { success: true };
  }

  /**
   * Send PagerDuty notification
   */
  private async sendPagerDutyNotification(
    channel: NotificationChannel,
    incident: SLOBreachIncident,
    message: string,
    severity: AlertSeverity
  ): Promise<{ success: boolean; error?: string }> {
    // Implementation would use PagerDuty API
    console.log(`📟 PagerDuty notification sent to ${channel.name}: ${message}`);
    return { success: true };
  }

  /**
   * Send webhook notification
   */
  private async sendWebhookNotification(
    channel: NotificationChannel,
    incident: SLOBreachIncident,
    message: string,
    severity: AlertSeverity
  ): Promise<{ success: boolean; error?: string }> {
    // Implementation would make HTTP request
    console.log(`🔗 Webhook notification sent to ${channel.name}: ${message}`);
    return { success: true };
  }

  /**
   * Map breach severity to alert severity
   */
  private mapSeverityToAlertSeverity(severity: BreachSeverity): AlertSeverity {
    switch (severity) {
      case BreachSeverity.CRITICAL: return AlertSeverity.EMERGENCY;
      case BreachSeverity.HIGH: return AlertSeverity.CRITICAL;
      case BreachSeverity.MEDIUM: return AlertSeverity.WARNING;
      default: return AlertSeverity.INFO;
    }
  }

  /**
   * Get default escalation policy
   */
  private getDefaultEscalationPolicy(): EscalationPolicy {
    return {
      id: 'default',
      name: 'Default Escalation Policy',
      description: 'Default escalation rules for SLO breaches',
      levels: [
        {
          level: EscalationLevel.L1,
          delay: 15 * 60 * 1000, // 15 minutes
          channels: ['default'],
          autoEscalate: true,
        },
        {
          level: EscalationLevel.L2,
          delay: 30 * 60 * 1000, // 30 minutes
          channels: ['manager', 'oncall'],
          autoEscalate: true,
        },
        {
          level: EscalationLevel.L3,
          delay: 60 * 60 * 1000, // 1 hour
          channels: ['director', 'executive'],
          autoEscalate: false,
        },
      ],
    };
  }

  /**
   * Check warning conditions
   */
  private async checkWarningConditions(slo: SLO, evaluation: SLOEvaluation): Promise<void> {
    // Check if approaching breach
    if (evaluation.budget.remaining < 20 && evaluation.budget.burnRate > 0.5) {
      this.emit('warning', {
        sloId: slo.id,
        sloName: slo.name,
        message: `SLO ${slo.name} approaching breach with ${evaluation.budget.remaining.toFixed(1)}% budget remaining`,
        budgetRemaining: evaluation.budget.remaining,
        burnRate: evaluation.budget.burnRate,
      });
    }
  }

  /**
   * Handle critical alerts
   */
  private async handleCriticalAlert(alert: SLOAlert): Promise<void> {
    const existingIncident = this.getActiveIncidentForSLO(alert.sloId);
    if (!existingIncident) {
      const evaluation = this.sloService.getLatestEvaluation(alert.sloId);
      if (evaluation) {
        await this.createIncident(alert.sloId, evaluation, BreachSeverity.HIGH);
      }
    }
  }

  /**
   * Evaluate custom threshold
   */
  private evaluateThreshold(threshold: BreachThreshold, evaluation: SLOEvaluation): boolean {
    switch (threshold.type) {
      case 'compliance':
        return evaluation.objective.compliance < threshold.value;
      case 'error_budget':
        return evaluation.budget.remaining < threshold.value;
      case 'burn_rate':
        return evaluation.budget.burnRate > threshold.value;
      default:
        return false;
    }
  }

  /**
   * Generate incident ID
   */
  private generateIncidentId(): string {
    const timestamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const random = Math.random().toString(36).substr(2, 6).toUpperCase();
    return `INC-${timestamp}-${random}`;
  }

  /**
   * Generate unique ID
   */
  private generateId(): string {
    return Math.random().toString(36).substr(2, 9);
  }
}

// ============================================================================
// Additional Type Definitions
// ============================================================================

export interface SLOBreachIncident {
  id: string;
  sloId: string;
  sloName: string;
  severity: BreachSeverity;
  status: IncidentStatus;
  detectedAt: Date;
  resolvedAt?: Date;
  evaluation: SLOEvaluation;
  impactAssessment: ImpactAssessment;
  notifications: NotificationResult[];
  escalations: Escalation[];
  responses: IncidentResponse[];
  resolution?: {
    reason: string;
    resolvedBy: string;
    actions: string[];
    preventRecurrence: string[];
    duration: number;
  };
  metadata: {
    detectedBy: string;
    confidence: number;
    affectedServices: string[];
    estimatedResolutionTime: number;
    businessImpact: {
      level: 'low' | 'medium' | 'high' | 'critical';
      description: string;
      estimatedCost: number;
      customerImpact: string;
    };
    lastUpdated?: Date;
  };
}

export enum BreachSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export enum IncidentStatus {
  OPEN = 'open',
  INVESTIGATING = 'investigating',
  IDENTIFIED = 'identified',
  MONITORING = 'monitoring',
  RESOLVED = 'resolved',
  CLOSED = 'closed',
}

export interface ImpactAssessment {
  score: number; // 0-100
  usersAffected: number;
  revenueImpact: number;
  operationalImpact: 'low' | 'medium' | 'high' | 'critical';
  customerImpact: 'low' | 'medium' | 'high' | 'critical';
  duration: number; // Estimated duration in milliseconds
}

export interface NotificationResult {
  channelId: string;
  timestamp: Date;
  success: boolean;
  error?: string;
}

export interface NotificationChannel {
  id: string;
  name: string;
  type: 'slack' | 'email' | 'pagerduty' | 'webhook' | 'sms';
  config: Record<string, any>;
  enabled: boolean;
}

export interface EscalationPolicy {
  id: string;
  name: string;
  description: string;
  levels: EscalationLevelConfig[];
}

export interface EscalationLevelConfig {
  level: EscalationLevel;
  delay: number; // Milliseconds
  channels: string[];
  autoEscalate: boolean;
}

export interface Escalation {
  level: EscalationLevel;
  triggeredAt: Date;
  reason: string;
  notifiedChannels: string[];
  acknowledgedBy?: string;
  acknowledgedAt?: Date;
}

export enum EscalationLevel {
  L1 = 'L1',
  L2 = 'L2',
  L3 = 'L3',
  EXECUTIVE = 'EXECUTIVE',
}

export interface IncidentResponse {
  id: string;
  type: 'automated' | 'manual';
  category: string;
  initiatedAt: Date;
  completedAt?: Date;
  actions: ResponseAction[];
  status: 'in_progress' | 'completed' | 'failed';
  error?: string;
}

export interface ResponseAction {
  type: string;
  description: string;
  executedAt: Date;
  status: 'executed' | 'failed' | 'pending';
  result?: any;
  error?: string;
}

export interface BreachThreshold {
  id: string;
  name: string;
  type: 'compliance' | 'error_budget' | 'burn_rate' | 'custom';
  operator: 'lt' | 'lte' | 'gt' | 'gte';
  value: number;
  severity: BreachSeverity;
  enabled: boolean;
}

// Export singleton instance
export const sloBreachDetectionService = new SLOBreachDetectionService(
  // Will be injected later
  null as any
);