// @ts-nocheck
/**
 * On-Call Management and Escalation Service for MCP Cortex
 *
 * Provides comprehensive on-call management capabilities:
 * - On-call schedule and rotation management
 * - Escalation policy execution
 * - Alert acknowledgement and assignment
 * - On-call handoff and override management
 * - Escalation path tracking and reporting
 * - Integration with notification channels
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'events';
import { logger } from '@/utils/logger.js';
import { Alert, AlertSeverity, EscalationPolicy, EscalationRule } from './alert-management-service.js';

// ============================================================================
// On-Call Management Interfaces
// ============================================================================

export interface OnCallUser {
  id: string;
  name: string;
  email: string;
  phone?: string;
  slackUserId?: string;
  timezone: string;
  skills: string[];
  maxConcurrentAlerts: number;
  notificationPreferences: NotificationPreferences;
  workingHours?: WorkingHours;
  vacationPeriods?: VacationPeriod[];
}

export interface NotificationPreferences {
  email: boolean;
  sms: boolean;
  phone: boolean;
  slack: boolean;
  push: boolean;
  quietHours?: {
    start: string; // HH:MM
    end: string;   // HH:MM
    timezone: string;
  };
  escalationDelay: number; // minutes
}

export interface WorkingHours {
  days: number[]; // 0-6 (Sunday-Saturday)
  start: string;  // HH:MM
  end: string;    // HH:MM
  timezone: string;
}

export interface VacationPeriod {
  start: Date;
  end: Date;
  reason?: string;
  approvedBy: string;
}

export interface OnCallAssignment {
  id: string;
  userId: string;
  scheduleId: string;
  rotationId: string;
  start: Date;
  end: Date;
  status: 'scheduled' | 'active' | 'completed' | 'cancelled';
  assignedBy: string;
  notes?: string;
}

export interface OnCallHandoff {
  id: string;
  fromUserId: string;
  toUserId: string;
  timestamp: Date;
  notes?: string;
  acknowledgedBy?: string;
  acknowledgedAt?: Date;
  status: 'pending' | 'acknowledged' | 'rejected';
}

export interface EscalationPath {
  id: string;
  name: string;
  description: string;
  levels: EscalationLevel[];
  default: boolean;
  tags: string[];
}

export interface EscalationLevel {
  level: number;
  delay: number; // minutes
  users: string[];
  groups: string[];
  conditions: EscalationCondition[];
  actions: EscalationAction[];
}

export interface EscalationCondition {
  type: 'time' | 'severity' | 'count' | 'custom';
  criteria: Record<string, any>;
}

export interface EscalationAction {
  type: 'notify' | 'reassign' | 'create_incident' | 'custom';
  config: Record<string, any>;
}

export interface AlertAssignment {
  alertId: string;
  userId: string;
  assignedAt: Date;
  assignedBy: string;
  status: 'assigned' | 'acknowledged' | 'resolved' | 'escalated';
  notes?: string;
}

export interface OnCallMetrics {
  totalUsers: number;
  activeAssignments: number;
  pendingHandoffs: number;
  averageResponseTime: number;
  escalationRate: number;
  userWorkloads: Record<string, UserWorkload>;
}

export interface UserWorkload {
  userId: string;
  activeAlerts: number;
  acknowledgedAlerts: number;
  resolvedAlerts: number;
  averageResponseTime: number;
  lastActivity: Date;
}

// ============================================================================
// On-Call Management Service
// ============================================================================

export class OnCallManagementService extends EventEmitter {
  private users: Map<string, OnCallUser> = new Map();
  private schedules: Map<string, OnCallSchedule> = new Map();
  private assignments: Map<string, OnCallAssignment> = new Map();
  private handoffs: Map<string, OnCallHandoff> = new Map();
  private escalationPaths: Map<string, EscalationPath> = new Map();
  private alertAssignments: Map<string, AlertAssignment> = new Map();

  private evaluationInterval: NodeJS.Timeout | null = null;
  private isShuttingDown = false;

  constructor(private config: OnCallServiceConfig) {
    super();
    this.initializeDefaultUsers();
    this.initializeDefaultEscalationPaths();
    this.startEvaluation();
  }

  // ========================================================================
  // User Management
  // ========================================================================

  /**
   * Register a new on-call user
   */
  async registerUser(user: OnCallUser): Promise<void> {
    try {
      this.validateUser(user);
      this.users.set(user.id, user);

      logger.info({ userId: user.id, name: user.name }, 'On-call user registered');

      this.emit('user_registered', user);
    } catch (error) {
      logger.error({ userId: user.id, error }, 'Failed to register on-call user');
      throw error;
    }
  }

  /**
   * Update on-call user information
   */
  async updateUser(userId: string, updates: Partial<OnCallUser>): Promise<void> {
    try {
      const user = this.users.get(userId);
      if (!user) {
        throw new Error(`User not found: ${userId}`);
      }

      const updatedUser = { ...user, ...updates };
      this.validateUser(updatedUser);
      this.users.set(userId, updatedUser);

      logger.info({ userId, updates }, 'On-call user updated');

      this.emit('user_updated', updatedUser);
    } catch (error) {
      logger.error({ userId, error }, 'Failed to update on-call user');
      throw error;
    }
  }

  /**
   * Get on-call user by ID
   */
  getUser(userId: string): OnCallUser | undefined {
    return this.users.get(userId);
  }

  /**
   * Get all on-call users
   */
  getAllUsers(): OnCallUser[] {
    return Array.from(this.users.values());
  }

  /**
   * Get available on-call users (not on vacation, within working hours)
   */
  getAvailableUsers(): OnCallUser[] {
    const now = new Date();
    return Array.from(this.users.values()).filter(user => {
      // Check if user is on vacation
      if (user.vacationPeriods?.some(vacation =>
        now >= vacation.start && now <= vacation.end
      )) {
        return false;
      }

      // Check working hours if specified
      if (user.workingHours) {
        return this.isWithinWorkingHours(now, user.workingHours);
      }

      return true;
    });
  }

  // ========================================================================
  // Schedule and Assignment Management
  // ========================================================================

  /**
   * Create or update on-call schedule
   */
  async upsertSchedule(schedule: OnCallSchedule): Promise<void> {
    try {
      this.validateSchedule(schedule);
      this.schedules.set(schedule.id, schedule);

      // Generate future assignments
      await this.generateAssignments(schedule);

      logger.info({ scheduleId: schedule.id, name: schedule.name }, 'On-call schedule upserted');

      this.emit('schedule_updated', schedule);
    } catch (error) {
      logger.error({ scheduleId: schedule.id, error }, 'Failed to upsert on-call schedule');
      throw error;
    }
  }

  /**
   * Get current on-call assignments
   */
  getCurrentAssignments(): OnCallAssignment[] {
    const now = new Date();
    return Array.from(this.assignments.values()).filter(assignment =>
      assignment.status === 'active' &&
      assignment.start <= now &&
      assignment.end >= now
    );
  }

  /**
   * Get on-call user for a specific schedule
   */
  getCurrentOnCallUser(scheduleId: string): OnCallUser | null {
    const currentAssignments = this.getCurrentAssignments();
    const assignment = currentAssignments.find(a => a.scheduleId === scheduleId);
    return assignment ? this.users.get(assignment.userId) || null : null;
  }

  /**
   * Assign alert to on-call user
   */
  async assignAlert(alertId: string, options: AlertAssignmentOptions): Promise<AlertAssignment> {
    try {
      let targetUserId = options.userId;

      // If no specific user, find appropriate on-call user
      if (!targetUserId) {
        const best = await this.findBestOnCallUser(options);
        if (best) {
          targetUserId = best;
        }
      }

      if (!targetUserId) {
        throw new Error('No available on-call user found for alert assignment');
      }

      const user = this.users.get(targetUserId);
      if (!user) {
        throw new Error(`User not found: ${targetUserId}`);
      }

      // Check user workload
      const currentWorkload = this.getUserWorkload(targetUserId);
      if (currentWorkload.activeAlerts >= user.maxConcurrentAlerts) {
        // Escalate or find alternative user
        const alt = await this.findEscalationUser(targetUserId, options);
        if (alt) {
          targetUserId = alt;
        } else {
          throw new Error('All on-call users are at capacity');
        }
      }

      const assignment: AlertAssignment = {
        alertId,
        userId: targetUserId,
        assignedAt: new Date(),
        assignedBy: options.assignedBy || 'system',
        status: 'assigned',
        notes: options.notes,
      };

      this.alertAssignments.set(alertId, assignment);

      logger.info({
        alertId,
        userId: targetUserId,
        assignedBy: assignment.assignedBy,
      }, 'Alert assigned to on-call user');

      this.emit('alert_assigned', assignment);

      return assignment;
    } catch (error) {
      logger.error({ alertId, error }, 'Failed to assign alert to on-call user');
      throw error;
    }
  }

  /**
   * Acknowledge alert assignment
   */
  async acknowledgeAlertAssignment(alertId: string, userId: string, notes?: string): Promise<void> {
    try {
      const assignment = this.alertAssignments.get(alertId);
      if (!assignment) {
        throw new Error(`Alert assignment not found: ${alertId}`);
      }

      if (assignment.userId !== userId) {
        throw new Error(`User ${userId} is not assigned to alert ${alertId}`);
      }

      assignment.status = 'acknowledged';
      if (notes) {
        assignment.notes = notes;
      }

      logger.info({ alertId, userId }, 'Alert assignment acknowledged');

      this.emit('alert_acknowledged', assignment);
    } catch (error) {
      logger.error({ alertId, userId, error }, 'Failed to acknowledge alert assignment');
      throw error;
    }
  }

  // ========================================================================
  // Escalation Management
  // ========================================================================

  /**
   * Execute escalation policy for alert
   */
  async executeEscalation(
    alert: Alert,
    escalationPolicy: EscalationPolicy,
    currentLevel: number = 0
  ): Promise<EscalationResult> {
    try {
      if (!escalationPolicy.enabled || currentLevel >= escalationPolicy.rules.length) {
        return {
          escalated: false,
          reason: 'No more escalation levels available',
        };
      }

      const escalationRule = escalationPolicy.rules[currentLevel];
      const escalationPath = this.getDefaultEscalationPath();

      if (!escalationPath) {
        return {
          escalated: false,
          reason: 'No default escalation path configured',
        };
      }

      const escalationLevel = escalationPath.levels.find(
        level => level.level === currentLevel
      );

      if (!escalationLevel) {
        return {
          escalated: false,
          reason: `Escalation level ${currentLevel} not found in path`,
        };
      }

      // Check escalation conditions
      const canEscalate = await this.checkEscalationConditions(
        escalationLevel.conditions,
        alert,
        currentLevel
      );

      if (!canEscalate) {
        return {
          escalated: false,
          reason: 'Escalation conditions not met',
        };
      }

      // Find escalation targets
      const targets = await this.findEscalationTargets(escalationLevel, alert);
      if (targets.length === 0) {
        return {
          escalated: false,
          reason: 'No escalation targets available',
        };
      }

      // Execute escalation actions
      const results = await this.executeEscalationActions(
        escalationLevel.actions,
        alert,
        targets
      );

      logger.info({
        alertId: alert.id,
        escalationLevel: currentLevel,
        targets: targets.map(t => t.userId),
        results,
      }, 'Alert escalation executed');

      this.emit('alert_escalated', {
        alert,
        escalationLevel: currentLevel,
        targets,
        results,
      });

      return {
        escalated: true,
        escalationLevel: currentLevel,
        targets,
        results,
      };
    } catch (error) {
      logger.error({ alertId: alert.id, error }, 'Failed to execute alert escalation');
      return {
        escalated: false,
        reason: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Create escalation path
   */
  async createEscalationPath(path: EscalationPath): Promise<void> {
    try {
      this.validateEscalationPath(path);
      this.escalationPaths.set(path.id, path);

      logger.info({ pathId: path.id, name: path.name }, 'Escalation path created');

      this.emit('escalation_path_created', path);
    } catch (error) {
      logger.error({ pathId: path.id, error }, 'Failed to create escalation path');
      throw error;
    }
  }

  /**
   * Get escalation path by ID
   */
  getEscalationPath(pathId: string): EscalationPath | undefined {
    return this.escalationPaths.get(pathId);
  }

  /**
   * Get default escalation path
   */
  getDefaultEscalationPath(): EscalationPath | undefined {
    return Array.from(this.escalationPaths.values()).find(path => path.default);
  }

  // ========================================================================
  // Handoff Management
  // ========================================================================

  /**
   * Initiate on-call handoff
   */
  async initiateHandoff(
    fromUserId: string,
    toUserId: string,
    notes?: string
  ): Promise<OnCallHandoff> {
    try {
      const fromUser = this.users.get(fromUserId);
      const toUser = this.users.get(toUserId);

      if (!fromUser) {
        throw new Error(`Source user not found: ${fromUserId}`);
      }

      if (!toUser) {
        throw new Error(`Target user not found: ${toUserId}`);
      }

      const handoff: OnCallHandoff = {
        id: this.generateHandoffId(),
        fromUserId,
        toUserId,
        timestamp: new Date(),
        notes,
        status: 'pending',
      };

      this.handoffs.set(handoff.id, handoff);

      // Send handoff notification
      await this.sendHandoffNotification(handoff);

      logger.info({
        handoffId: handoff.id,
        fromUserId,
        toUserId,
      }, 'On-call handoff initiated');

      this.emit('handoff_initiated', handoff);

      return handoff;
    } catch (error) {
      logger.error({ fromUserId, toUserId, error }, 'Failed to initiate on-call handoff');
      throw error;
    }
  }

  /**
   * Acknowledge on-call handoff
   */
  async acknowledgeHandoff(handoffId: string, userId: string): Promise<void> {
    try {
      const handoff = this.handoffs.get(handoffId);
      if (!handoff) {
        throw new Error(`Handoff not found: ${handoffId}`);
      }

      if (handoff.toUserId !== userId) {
        throw new Error(`User ${userId} is not the target of handoff ${handoffId}`);
      }

      if (handoff.status !== 'pending') {
        throw new Error(`Handoff ${handoffId} is not in pending state`);
      }

      handoff.status = 'acknowledged';
      handoff.acknowledgedBy = userId;
      handoff.acknowledgedAt = new Date();

      // Transfer active assignments
      await this.transferActiveAssignments(handoff.fromUserId, handoff.toUserId);

      logger.info({
        handoffId,
        fromUserId: handoff.fromUserId,
        toUserId: handoff.toUserId,
      }, 'On-call handoff acknowledged');

      this.emit('handoff_acknowledged', handoff);
    } catch (error) {
      logger.error({ handoffId, userId, error }, 'Failed to acknowledge on-call handoff');
      throw error;
    }
  }

  // ========================================================================
  // Metrics and Monitoring
  // ========================================================================

  /**
   * Get on-call metrics
   */
  getOnCallMetrics(): OnCallMetrics {
    const now = new Date();
    const activeAssignments = this.getCurrentAssignments();
    const pendingHandoffs = Array.from(this.handoffs.values()).filter(
      h => h.status === 'pending'
    );

    const userWorkloads: Record<string, UserWorkload> = {};
    const alertAssignments = Array.from(this.alertAssignments.values());
    const userAlerts = new Map<string, typeof alertAssignments>();

    // Group alerts by user
    alertAssignments.forEach(assignment => {
      if (!userAlerts.has(assignment.userId)) {
        userAlerts.set(assignment.userId, []);
      }
      userAlerts.get(assignment.userId)!.push(assignment);
    });

    // Calculate workload for each user
    this.users.forEach(user => {
      const userAssignmentList = userAlerts.get(user.id) || [];
      const activeAlerts = userAssignmentList.filter(a =>
        ['assigned', 'acknowledged'].includes(a.status)
      );
      const acknowledgedAlerts = userAssignmentList.filter(a =>
        a.status === 'acknowledged'
      );
      const resolvedAlerts = userAssignmentList.filter(a =>
        a.status === 'resolved'
      );

      userWorkloads[user.id] = {
        userId: user.id,
        activeAlerts: activeAlerts.length,
        acknowledgedAlerts: acknowledgedAlerts.length,
        resolvedAlerts: resolvedAlerts.length,
        averageResponseTime: this.calculateAverageResponseTime(userAssignmentList),
        lastActivity: this.getLastUserActivity(userAssignmentList),
      };
    });

    return {
      totalUsers: this.users.size,
      activeAssignments: activeAssignments.length,
      pendingHandoffs: pendingHandoffs.length,
      averageResponseTime: this.calculateAverageResponseTime(alertAssignments),
      escalationRate: this.calculateEscalationRate(alertAssignments),
      userWorkloads,
    };
  }

  // ========================================================================
  // Private Helper Methods
  // ========================================================================

  private initializeDefaultUsers(): void {
    const defaultUsers: OnCallUser[] = [
      {
        id: 'user-1',
        name: 'John Doe',
        email: 'john.doe@example.com',
        phone: '+1234567890',
        slackUserId: 'U123456',
        timezone: 'America/New_York',
        skills: ['database', 'infrastructure', 'networking'],
        maxConcurrentAlerts: 5,
        notificationPreferences: {
          email: true,
          sms: true,
          phone: true,
          slack: true,
          push: false,
          escalationDelay: 15,
        },
        workingHours: {
          days: [1, 2, 3, 4, 5], // Monday-Friday
          start: '09:00',
          end: '17:00',
          timezone: 'America/New_York',
        },
      },
      {
        id: 'user-2',
        name: 'Jane Smith',
        email: 'jane.smith@example.com',
        phone: '+0987654321',
        slackUserId: 'U654321',
        timezone: 'America/Los_Angeles',
        skills: ['application', 'monitoring', 'performance'],
        maxConcurrentAlerts: 3,
        notificationPreferences: {
          email: true,
          sms: false,
          phone: true,
          slack: true,
          push: true,
          escalationDelay: 10,
          quietHours: {
            start: '22:00',
            end: '07:00',
            timezone: 'America/Los_Angeles',
          },
        },
      },
      {
        id: 'user-3',
        name: 'Mike Johnson',
        email: 'mike.johnson@example.com',
        phone: '+1122334455',
        slackUserId: 'U789012',
        timezone: 'Europe/London',
        skills: ['security', 'compliance', 'database'],
        maxConcurrentAlerts: 4,
        notificationPreferences: {
          email: true,
          sms: true,
          phone: false,
          slack: true,
          push: true,
          escalationDelay: 20,
        },
      },
    ];

    defaultUsers.forEach(user => {
      this.users.set(user.id, user);
    });
  }

  private initializeDefaultEscalationPaths(): void {
    const defaultPath: EscalationPath = {
      id: 'default-escalation-path',
      name: 'Default Escalation Path',
      description: 'Standard escalation path for all alerts',
      default: true,
      tags: ['default', 'standard'],
      levels: [
        {
          level: 0,
          delay: 15, // 15 minutes
          users: ['user-1', 'user-2'],
          groups: ['on-call-primary'],
          conditions: [
            {
              type: 'time',
              criteria: { delay: 15 },
            },
          ],
          actions: [
            {
              type: 'notify',
              config: {
                channels: ['email', 'slack', 'sms'],
                urgency: 'high',
              },
            },
          ],
        },
        {
          level: 1,
          delay: 30, // 30 minutes from level 0
          users: ['user-3'],
          groups: ['on-call-secondary', 'team-lead'],
          conditions: [
            {
              type: 'time',
              criteria: { delay: 30 },
            },
            {
              type: 'severity',
              criteria: { minSeverity: 'warning' },
            },
          ],
          actions: [
            {
              type: 'notify',
              config: {
                channels: ['email', 'phone', 'slack'],
                urgency: 'critical',
              },
            },
            {
              type: 'create_incident',
              config: {
                severity: 'high',
                notifyAll: true,
              },
            },
          ],
        },
        {
          level: 2,
          delay: 60, // 60 minutes from level 0
          users: [],
          groups: ['on-call-manager', 'incident-commander'],
          conditions: [
            {
              type: 'time',
              criteria: { delay: 60 },
            },
            {
              type: 'severity',
              criteria: { minSeverity: 'critical' },
            },
          ],
          actions: [
            {
              type: 'notify',
              config: {
                channels: ['all'],
                urgency: 'emergency',
              },
            },
            {
              type: 'create_incident',
              config: {
                severity: 'critical',
                notifyAll: true,
                warRoom: true,
              },
            },
          ],
        },
      ],
    };

    this.escalationPaths.set(defaultPath.id, defaultPath);
  }

  private startEvaluation(): void {
    this.evaluationInterval = setInterval(async () => {
      if (!this.isShuttingDown) {
        try {
          await this.evaluateSchedules();
          await this.checkPendingHandoffs();
          await this.updateMetrics();
        } catch (error) {
          logger.error({ error }, 'Error in on-call evaluation interval');
        }
      }
    }, 60000); // Every minute
  }

  private async evaluateSchedules(): Promise<void> {
    const now = new Date();

    // Check for schedule transitions
    for (const schedule of this.schedules.values()) {
      const currentAssignment = this.getCurrentOnCallUser(schedule.id);
      const nextUser = this.getNextOnCallUser(schedule, now);

      if (nextUser && (!currentAssignment || currentAssignment.id !== nextUser.id)) {
        // Schedule transition is needed
        await this.scheduleHandoff(currentAssignment?.id, nextUser.id, schedule.id);
      }
    }
  }

  private async checkPendingHandoffs(): Promise<void> {
    const pendingHandoffs = Array.from(this.handoffs.values()).filter(
      h => h.status === 'pending'
    );

    for (const handoff of pendingHandoffs) {
      // Check if handoff has timed out
      const timeout = Date.now() - (handoff.timestamp.getTime() + 30 * 60 * 1000); // 30 minutes
      if (timeout > 0) {
        logger.warn({
          handoffId: handoff.id,
          timeout: timeout,
        }, 'On-call handoff timed out');

        // Auto-escalate or notify manager
        await this.handleHandoffTimeout(handoff);
      }
    }
  }

  private async updateMetrics(): Promise<void> {
    // Periodic metrics update
    const metrics = this.getOnCallMetrics();
    this.emit('metrics_updated', metrics);
  }

  private validateUser(user: OnCallUser): void {
    if (!user.id || !user.name || !user.email) {
      throw new Error('User must have id, name, and email');
    }

    if (!user.timezone) {
      throw new Error('User must have a timezone');
    }

    if (user.maxConcurrentAlerts <= 0) {
      throw new Error('Max concurrent alerts must be greater than 0');
    }
  }

  private validateSchedule(schedule: OnCallSchedule): void {
    if (!schedule.id || !schedule.name || !schedule.timezone) {
      throw new Error('Schedule must have id, name, and timezone');
    }

    if (!schedule.rotations || schedule.rotations.length === 0) {
      throw new Error('Schedule must have at least one rotation');
    }
  }

  private validateEscalationPath(path: EscalationPath): void {
    if (!path.id || !path.name) {
      throw new Error('Escalation path must have id and name');
    }

    if (!path.levels || path.levels.length === 0) {
      throw new Error('Escalation path must have at least one level');
    }
  }

  private isWithinWorkingHours(date: Date, workingHours: WorkingHours): boolean {
    const timeZoneDate = new Date(date.toLocaleString('en-US', { timeZone: workingHours.timezone }));
    const dayOfWeek = timeZoneDate.getDay();
    const currentTime = timeZoneDate.getHours() * 60 + timeZoneDate.getMinutes();
    const startTime = this.parseTime(workingHours.start);
    const endTime = this.parseTime(workingHours.end);

    return workingHours.days.includes(dayOfWeek) &&
           currentTime >= startTime &&
           currentTime <= endTime;
  }

  private parseTime(timeStr: string): number {
    const [hours, minutes] = timeStr.split(':').map(Number);
    return hours * 60 + minutes;
  }

  private async generateAssignments(schedule: OnCallSchedule): Promise<void> {
    // Generate assignments for the next 90 days
    const startDate = new Date();
    const endDate = new Date(startDate.getTime() + 90 * 24 * 60 * 60 * 1000);

    for (const rotation of schedule.rotations) {
      await this.generateRotationAssignments(rotation, startDate, endDate);
    }
  }

  private async generateRotationAssignments(
    rotation: OnCallRotation,
    startDate: Date,
    endDate: Date
  ): Promise<void> {
    // Placeholder implementation - would need to handle different rotation types
    const durationMs = this.getRotationDuration(rotation);
    let currentTime = rotation.startTime;

    while (currentTime < endDate) {
      const userIndex = Math.floor(
        (currentTime.getTime() - rotation.startTime.getTime()) / durationMs
      ) % rotation.users.length;
      const userId = rotation.users[userIndex];

      const assignment: OnCallAssignment = {
        id: this.generateAssignmentId(),
        userId,
        scheduleId: '', // Would be set by caller
        rotationId: rotation.id,
        start: new Date(currentTime),
        end: new Date(currentTime.getTime() + durationMs),
        status: 'scheduled',
        assignedBy: 'system',
      };

      this.assignments.set(assignment.id, assignment);
      currentTime = new Date(currentTime.getTime() + durationMs);
    }
  }

  private getRotationDuration(rotation: OnCallRotation): number {
    switch (rotation.type) {
      case 'daily':
        return 24 * 60 * 60 * 1000; // 1 day
      case 'weekly':
        return 7 * 24 * 60 * 60 * 1000; // 1 week
      case 'monthly':
        return 30 * 24 * 60 * 60 * 1000; // ~1 month
      default:
        return 24 * 60 * 60 * 1000; // Default to 1 day
    }
  }

  private getNextOnCallUser(schedule: OnCallSchedule, currentTime: Date): OnCallUser | null {
    // Simplified implementation - would need to handle complex rotation logic
    const rotation = schedule.rotations[0]; // Use first rotation
    if (!rotation) return null;

    const durationMs = this.getRotationDuration(rotation);
    const userIndex = Math.floor(
      (currentTime.getTime() - rotation.startTime.getTime()) / durationMs
    ) % rotation.users.length;
    const userId = rotation.users[userIndex];

    return this.users.get(userId) || null;
  }

  private async findBestOnCallUser(options: AlertAssignmentOptions): Promise<string | null> {
    const availableUsers = this.getAvailableUsers();

    // Filter by skills if required
    let candidates = availableUsers;
    if (options.requiredSkills && options.requiredSkills.length > 0) {
      candidates = availableUsers.filter(user =>
        options.requiredSkills!.some(skill => user.skills.includes(skill))
      );
    }

    if (candidates.length === 0) return null;

    // Sort by workload (fewest active alerts first)
    candidates.sort((a, b) => {
      const workloadA = this.getUserWorkload(a.id);
      const workloadB = this.getUserWorkload(b.id);
      return workloadA.activeAlerts - workloadB.activeAlerts;
    });

    return candidates[0].id;
  }

  private async findEscalationUser(currentUserId: string, options: AlertAssignmentOptions): Promise<string | null> {
    const currentUser = this.users.get(currentUserId);
    if (!currentUser) return null;

    // Find next best user
    const availableUsers = this.getAvailableUsers().filter(u => u.id !== currentUserId);

    // Filter by skills
    let candidates = availableUsers;
    if (options.requiredSkills && options.requiredSkills.length > 0) {
      candidates = availableUsers.filter(user =>
        options.requiredSkills!.some(skill => user.skills.includes(skill))
      );
    }

    if (candidates.length === 0) return null;

    // Sort by workload and availability
    candidates.sort((a, b) => {
      const workloadA = this.getUserWorkload(a.id);
      const workloadB = this.getUserWorkload(b.id);

      if (workloadA.activeAlerts !== workloadB.activeAlerts) {
        return workloadA.activeAlerts - workloadB.activeAlerts;
      }

      // Prefer users with matching skills
      const skillMatchA = a.skills.filter(s => currentUser.skills.includes(s)).length;
      const skillMatchB = b.skills.filter(s => currentUser.skills.includes(s)).length;

      return skillMatchB - skillMatchA;
    });

    return candidates[0].id;
  }

  private getUserWorkload(userId: string): UserWorkload {
    const userAssignments = Array.from(this.alertAssignments.values()).filter(
      assignment => assignment.userId === userId
    );

    const activeAlerts = userAssignments.filter(a =>
      ['assigned', 'acknowledged'].includes(a.status)
    ).length;

    return {
      userId,
      activeAlerts,
      acknowledgedAlerts: userAssignments.filter(a => a.status === 'acknowledged').length,
      resolvedAlerts: userAssignments.filter(a => a.status === 'resolved').length,
      averageResponseTime: this.calculateAverageResponseTime(userAssignments),
      lastActivity: this.getLastUserActivity(userAssignments),
    };
  }

  private calculateAverageResponseTime(assignments: AlertAssignment[]): number {
    // Placeholder implementation - would need acknowledgment timestamps
    return 0;
  }

  private getLastUserActivity(assignments: AlertAssignment[]): Date {
    const latestAssignment = assignments.reduce((latest, current) =>
      current.assignedAt > latest.assignedAt ? current : latest,
      assignments[0]
    );
    return latestAssignment?.assignedAt || new Date();
  }

  private calculateEscalationRate(assignments: AlertAssignment[]): number {
    // Placeholder implementation
    return 0;
  }

  private async checkEscalationConditions(
    conditions: EscalationCondition[],
    alert: Alert,
    currentLevel: number
  ): Promise<boolean> {
    for (const condition of conditions) {
      const result = await this.evaluateEscalationCondition(condition, alert, currentLevel);
      if (!result) {
        return false;
      }
    }
    return true;
  }

  private async evaluateEscalationCondition(
    condition: EscalationCondition,
    alert: Alert,
    currentLevel: number
  ): Promise<boolean> {
    switch (condition.type) {
      case 'time':
        const delay = condition.criteria.delay || 15;
        const timeSinceAlert = Date.now() - alert.timestamp.getTime();
        return timeSinceAlert >= delay * 60 * 1000;

      case 'severity':
        const minSeverity = condition.criteria.minSeverity || 'warning';
        return this.compareSeverity(alert.severity, minSeverity) >= 0;

      case 'count':
        // Would need to count related alerts
        return true;

      case 'custom':
        // Custom condition evaluation
        return true;

      default:
        return true;
    }
  }

  private compareSeverity(severity1: string, severity2: string): number {
    const severityOrder = {
      'info': 0,
      'warning': 1,
      'critical': 2,
      'emergency': 3,
    };

    return (severityOrder[severity1 as keyof typeof severityOrder] || 0) -
           (severityOrder[severity2 as keyof typeof severityOrder] || 0);
  }

  private async findEscalationTargets(
    escalationLevel: EscalationLevel,
    alert: Alert
  ): Promise<Array<{ userId: string; user: OnCallUser }>> {
    const targets: Array<{ userId: string; user: OnCallUser }> = [];

    // Find users
    for (const userId of escalationLevel.users) {
      const user = this.users.get(userId);
      if (user && this.isUserAvailable(user)) {
        targets.push({ userId, user });
      }
    }

    // If no specific users available, find available users with matching skills
    if (targets.length === 0) {
      const availableUsers = this.getAvailableUsers();
      for (const user of availableUsers) {
        targets.push({ userId: user.id, user });
      }
    }

    return targets;
  }

  private isUserAvailable(user: OnCallUser): boolean {
    const now = new Date();

    // Check vacation
    if (user.vacationPeriods?.some(vacation =>
      now >= vacation.start && now <= vacation.end
    )) {
      return false;
    }

    // Check working hours
    if (user.workingHours && !this.isWithinWorkingHours(now, user.workingHours)) {
      return false;
    }

    // Check quiet hours
    if (user.notificationPreferences.quietHours) {
      const quietHours = user.notificationPreferences.quietHours;
      const quietTime = new Date(now.toLocaleString('en-US', { timeZone: quietHours.timezone }));
      const currentTime = quietTime.getHours() * 60 + quietTime.getMinutes();
      const quietStart = this.parseTime(quietHours.start);
      const quietEnd = this.parseTime(quietHours.end);

      // Handle overnight quiet hours
      if (quietStart > quietEnd) {
        if (currentTime >= quietStart || currentTime <= quietEnd) {
          // During quiet hours, check if alert is critical enough
          return false; // Simplified - would check alert severity
        }
      } else {
        if (currentTime >= quietStart && currentTime <= quietEnd) {
          return false; // Simplified - would check alert severity
        }
      }
    }

    return true;
  }

  private async executeEscalationActions(
    actions: EscalationAction[],
    alert: Alert,
    targets: Array<{ userId: string; user: OnCallUser }>
  ): Promise<any[]> {
    const results: any[] = [];

    for (const action of actions) {
      try {
        const result = await this.executeEscalationAction(action, alert, targets);
        results.push(result);
      } catch (error) {
        logger.error({ action, error }, 'Failed to execute escalation action');
        results.push({ success: false, error: error instanceof Error ? error.message : 'Unknown error' });
      }
    }

    return results;
  }

  private async executeEscalationAction(
    action: EscalationAction,
    alert: Alert,
    targets: Array<{ userId: string; user: OnCallUser }>
  ): Promise<any> {
    switch (action.type) {
      case 'notify':
        return await this.executeNotificationAction(action.config, alert, targets);
      case 'reassign':
        return await this.executeReassignAction(action.config, alert, targets);
      case 'create_incident':
        return await this.executeCreateIncidentAction(action.config, alert, targets);
      case 'custom':
        return await this.executeCustomAction(action.config, alert, targets);
      default:
        throw new Error(`Unknown escalation action type: ${action.type}`);
    }
  }

  private async executeNotificationAction(
    config: any,
    alert: Alert,
    targets: Array<{ userId: string; user: OnCallUser }>
  ): Promise<any> {
    // Placeholder for notification execution
    logger.info({
      action: 'notify',
      alertId: alert.id,
      targets: targets.map(t => t.userId),
      config,
    }, 'Executing notification escalation action');

    return {
      success: true,
      notifiedUsers: targets.map(t => t.userId),
      channels: config.channels || ['email'],
    };
  }

  private async executeReassignAction(
    config: any,
    alert: Alert,
    targets: Array<{ userId: string; user: OnCallUser }>
  ): Promise<any> {
    // Reassign alert to escalation targets
    const reassignments: string[] = [];

    for (const target of targets) {
      try {
        await this.assignAlert(alert.id, {
          userId: target.userId,
          assignedBy: 'escalation',
          notes: `Escalated from previous assignment`,
        });
        reassignments.push(target.userId);
      } catch (error) {
        logger.error({ userId: target.userId, error }, 'Failed to reassign alert during escalation');
      }
    }

    return {
      success: reassignments.length > 0,
      reassignedUsers: reassignments,
    };
  }

  private async executeCreateIncidentAction(
    config: any,
    alert: Alert,
    targets: Array<{ userId: string; user: OnCallUser }>
  ): Promise<any> {
    // Placeholder for incident creation
    logger.info({
      action: 'create_incident',
      alertId: alert.id,
      severity: config.severity,
      notifyAll: config.notifyAll,
    }, 'Creating incident from alert escalation');

    return {
      success: true,
      incidentId: `incident-${Date.now()}`,
      severity: config.severity || 'high',
      assignedTo: targets.map(t => t.userId),
    };
  }

  private async executeCustomAction(
    config: any,
    alert: Alert,
    targets: Array<{ userId: string; user: OnCallUser }>
  ): Promise<any> {
    // Placeholder for custom action execution
    logger.info({
      action: 'custom',
      alertId: alert.id,
      config,
    }, 'Executing custom escalation action');

    return {
      success: true,
      action: config.action || 'unknown',
    };
  }

  private generateAssignmentId(): string {
    return `assignment-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateHandoffId(): string {
    return `handoff-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private async sendHandoffNotification(handoff: OnCallHandoff): Promise<void> {
    // Placeholder for handoff notification
    logger.info({
      handoffId: handoff.id,
      fromUserId: handoff.fromUserId,
      toUserId: handoff.toUserId,
    }, 'Sending handoff notification');
  }

  private async scheduleHandoff(
    fromUserId: string | undefined,
    toUserId: string,
    scheduleId: string
  ): Promise<void> {
    if (fromUserId && fromUserId !== toUserId) {
      await this.initiateHandoff(
        fromUserId,
        toUserId,
        `Scheduled handoff for ${scheduleId}`
      );
    }
  }

  private async transferActiveAssignments(fromUserId: string, toUserId: string): Promise<void> {
    const activeAssignments = Array.from(this.alertAssignments.values()).filter(
      assignment => assignment.userId === fromUserId &&
      ['assigned', 'acknowledged'].includes(assignment.status)
    );

    for (const assignment of activeAssignments) {
      assignment.userId = toUserId;
      assignment.status = 'assigned'; // Reset to assigned
      assignment.notes = `Transferred from ${fromUserId} due to handoff`;
    }

    logger.info({
      fromUserId,
      toUserId,
      transferredAssignments: activeAssignments.length,
    }, 'Transferred active assignments during handoff');
  }

  private async handleHandoffTimeout(handoff: OnCallHandoff): Promise<void> {
    // Handle handoff timeout - escalate to manager or notify team
    logger.warn({
      handoffId: handoff.id,
      fromUserId: handoff.fromUserId,
      toUserId: handoff.toUserId,
    }, 'Handling handoff timeout');

    this.emit('handoff_timeout', handoff);
  }

  /**
   * Cleanup method
   */
  cleanup(): void {
    this.isShuttingDown = true;

    if (this.evaluationInterval) {
      clearInterval(this.evaluationInterval);
      this.evaluationInterval = null;
    }

    this.removeAllListeners();
    logger.info('On-call management service cleaned up');
  }
}

// ============================================================================
// Supporting Interfaces
// ============================================================================

export interface OnCallServiceConfig {
  evaluationIntervalMs: number;
  handoffTimeoutMinutes: number;
  defaultMaxConcurrentAlerts: number;
  defaultEscalationDelay: number;
}

export interface OnCallSchedule {
  id: string;
  name: string;
  description?: string;
  timezone: string;
  rotations: OnCallRotation[];
  overrides: OnCallOverride[];
}

export interface OnCallRotation {
  id: string;
  name: string;
  users: string[];
  type: 'daily' | 'weekly' | 'monthly';
  startTime: Date;
  endTime?: Date;
  handoffTime?: string;
}

export interface OnCallOverride {
  id: string;
  userId: string;
  startTime: Date;
  endTime: Date;
  reason?: string;
}

export interface AlertAssignmentOptions {
  userId?: string;
  assignedBy?: string;
  requiredSkills?: string[];
  priority?: 'low' | 'medium' | 'high' | 'critical';
  notes?: string;
}

export interface EscalationResult {
  escalated: boolean;
  escalationLevel?: number;
  targets?: Array<{ userId: string; user: OnCallUser }>;
  results?: any[];
  reason?: string;
}

// Export singleton instance
export const onCallManagementService = new OnCallManagementService({
  evaluationIntervalMs: 60000,
  handoffTimeoutMinutes: 30,
  defaultMaxConcurrentAlerts: 5,
  defaultEscalationDelay: 15,
});
