
/**
 * Service Level Objective (SLO) Service
 *
 * Core service for calculating, monitoring, and managing SLOs with real-time
 * evaluation, error budget tracking, and burn rate calculations.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'events';

import {
  AlertSeverity,
  BurnRateTrend,
  type SLI,
  SLIAggregation,
  type SLIMeasurement,
  type SLO,
  type SLOAlert,
  SLOAlertType,
  type SLOEvaluation,
  SLOEvaluationStatus,
  type SLOFrameworkConfig,
  SLOPeriod,
  type TimeWindow,
  validateSLO,
  type ValidationResult,
} from '../types/slo-interfaces.js';
import { HealthStatus } from '../types/unified-health-interfaces.js';

/**
 * SLO Service - Main service for SLO management and evaluation
 */
export class SLOService extends EventEmitter {
  private config: SLOFrameworkConfig;
  private slis: Map<string, SLI> = new Map();
  private slos: Map<string, SLO> = new Map();
  private measurements: Map<string, SLIMeasurement[]> = new Map();
  private evaluations: Map<string, SLOEvaluation[]> = new Map();
  private evaluationIntervals: Map<string, NodeJS.Timeout> = new Map();
  private isStarted = false;

  constructor(config: Partial<SLOFrameworkConfig> = {}) {
    super();
    this.config = this.mergeConfig(config);
  }

  /**
   * Start the SLO service
   */
  async start(): Promise<void> {
    if (this.isStarted) {
      this.emit('warning', 'SLO Service is already started');
      return;
    }

    try {
      this.isStarted = true;
      this.emit('started', 'SLO Service started successfully');

      // Start evaluation intervals for active SLOs
      for (const [sloId, slo] of this.slos) {
        if (slo.status === 'active') {
          this.startSLOEvaluation(slo);
        }
      }
    } catch (error) {
      this.isStarted = false;
      this.emit('error', `Failed to start SLO Service: ${error}`);
      throw error;
    }
  }

  /**
   * Stop the SLO service
   */
  async stop(): Promise<void> {
    if (!this.isStarted) {
      this.emit('warning', 'SLO Service is not started');
      return;
    }

    try {
      // Clear all evaluation intervals
      for (const [sloId, interval] of this.evaluationIntervals) {
        clearInterval(interval);
      }
      this.evaluationIntervals.clear();

      this.isStarted = false;
      this.emit('stopped', 'SLO Service stopped successfully');
    } catch (error) {
      this.emit('error', `Error stopping SLO Service: ${error}`);
      throw error;
    }
  }

  // ============================================================================
  // SLI Management
  // ============================================================================

  /**
   * Create or update an SLI
   */
  async createSLI(sli: SLI): Promise<SLI> {
    // Validate SLI
    const validation = this.validateSLI(sli);
    if (!validation.valid) {
      throw new Error(`Invalid SLI: ${validation.errors.join(', ')}`);
    }

    this.slis.set(sli.id, sli);
    this.emit('sli:created', sli);
    return sli;
  }

  /**
   * Get an SLI by ID
   */
  getSLI(id: string): SLI | undefined {
    return this.slis.get(id);
  }

  /**
   * Get all SLIs
   */
  getAllSLIs(): SLI[] {
    return Array.from(this.slis.values());
  }

  /**
   * Delete an SLI
   */
  async deleteSLI(id: string): Promise<boolean> {
    // Check if SLI is referenced by any SLOs
    const referencingSLOs = Array.from(this.slos.values()).filter(slo => slo.sli === id);
    if (referencingSLOs.length > 0) {
      throw new Error(`Cannot delete SLI ${id}: referenced by ${referencingSLOs.length} SLOs`);
    }

    const deleted = this.slis.delete(id);
    if (deleted) {
      // Clean up measurements
      this.measurements.delete(id);
      this.emit('sli:deleted', id);
    }
    return deleted;
  }

  // ============================================================================
  // SLO Management
  // ============================================================================

  /**
   * Create or update an SLO
   */
  async createSLO(slo: SLO): Promise<SLO> {
    // Validate SLO
    const validation = validateSLO(slo);
    if (!validation.valid) {
      throw new Error(`Invalid SLO: ${validation.errors.join(', ')}`);
    }

    // Check if referenced SLI exists
    const sli = this.slis.get(slo.sli);
    if (!sli) {
      throw new Error(`SLI ${slo.sli} not found`);
    }

    // Set metadata
    slo.metadata.createdAt = new Date();
    slo.metadata.updatedAt = new Date();

    this.slos.set(slo.id, slo);

    // Start evaluation if service is running and SLO is active
    if (this.isStarted && slo.status === 'active') {
      this.startSLOEvaluation(slo);
    }

    this.emit('slo:created', slo);
    return slo;
  }

  /**
   * Get an SLO by ID
   */
  getSLO(id: string): SLO | undefined {
    return this.slos.get(id);
  }

  /**
   * Get all SLOs
   */
  getAllSLOs(): SLO[] {
    return Array.from(this.slos.values());
  }

  /**
   * Update an SLO
   */
  async updateSLO(id: string, updates: Partial<SLO>): Promise<SLO> {
    const existing = this.slos.get(id);
    if (!existing) {
      throw new Error(`SLO ${id} not found`);
    }

    const updated: SLO = {
      ...existing,
      ...updates,
      id, // Ensure ID doesn't change
      metadata: {
        ...existing.metadata,
        ...updates.metadata,
        updatedAt: new Date(),
      },
    };

    // Validate updated SLO
    const validation = validateSLO(updated);
    if (!validation.valid) {
      throw new Error(`Invalid SLO update: ${validation.errors.join(', ')}`);
    }

    this.slos.set(id, updated);

    // Restart evaluation if status changed
    if (updates.status) {
      if (updates.status === 'active' && this.isStarted) {
        this.startSLOEvaluation(updated);
      } else {
        this.stopSLOEvaluation(id);
      }
    }

    this.emit('slo:updated', updated);
    return updated;
  }

  /**
   * Delete an SLO
   */
  async deleteSLO(id: string): Promise<boolean> {
    const deleted = this.slos.delete(id);
    if (deleted) {
      // Stop evaluation
      this.stopSLOEvaluation(id);

      // Clean up evaluations
      this.evaluations.delete(id);

      this.emit('slo:deleted', id);
    }
    return deleted;
  }

  // ============================================================================
  // Data Ingestion
  // ============================================================================

  /**
   * Add SLI measurements
   */
  async addMeasurements(measurements: SLIMeasurement[]): Promise<void> {
    for (const measurement of measurements) {
      const sliMeasurements = this.measurements.get(measurement.sliId) || [];
      sliMeasurements.push(measurement);

      // Sort by timestamp
      sliMeasurements.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

      // Enforce data retention
      const retentionPeriod = this.config.storage.retention.raw;
      const cutoffTime = Date.now() - retentionPeriod;
      const filtered = sliMeasurements.filter(m => m.timestamp.getTime() > cutoffTime);

      this.measurements.set(measurement.sliId, filtered);
    }

    this.emit('measurements:added', measurements);
  }

  /**
   * Get measurements for an SLI
   */
  getMeasurements(sliId: string, timeWindow?: TimeWindow): SLIMeasurement[] {
    const measurements = this.measurements.get(sliId) || [];

    if (!timeWindow) {
      return [...measurements];
    }

    const now = Date.now();
    let startTime: number;
    let endTime: number;

    if (timeWindow.type === 'rolling') {
      endTime = now;
      startTime = now - timeWindow.duration;
    } else if (timeWindow.type === 'fixed' && timeWindow.start && timeWindow.end) {
      startTime = timeWindow.start.getTime();
      endTime = timeWindow.end.getTime();
    } else {
      return [...measurements];
    }

    return measurements.filter(m =>
      m.timestamp.getTime() >= startTime && m.timestamp.getTime() <= endTime
    );
  }

  // ============================================================================
  // SLO Evaluation
  // ============================================================================

  /**
   * Evaluate an SLO
   */
  async evaluateSLO(sloId: string, timeWindow?: TimeWindow): Promise<SLOEvaluation> {
    const slo = this.slos.get(sloId);
    if (!slo) {
      throw new Error(`SLO ${sloId} not found`);
    }

    const sli = this.slis.get(slo.sli);
    if (!sli) {
      throw new Error(`SLI ${slo.sli} not found`);
    }

    // Determine evaluation window
    const evaluationWindow = timeWindow || this.getEvaluationWindow(slo);

    // Get measurements for the evaluation period
    const measurements = this.getMeasurements(slo.sli, evaluationWindow);

    // Calculate SLI value from measurements
    const sliValue = this.calculateSLIValue(sli, measurements);

    // Calculate SLO compliance
    const compliance = this.calculateCompliance(sliValue, slo.objective.target);

    // Calculate error budget metrics
    const budget = this.calculateErrorBudget(slo, sliValue, evaluationWindow);

    // Determine status
    const status = this.determineSLOStatus(compliance, budget);

    // Generate alerts if needed
    const alerts = await this.generateSLOAlerts(slo, status, compliance, budget);

    const evaluation: SLOEvaluation = {
      id: this.generateId(),
      sloId,
      timestamp: new Date(),
      period: {
        start: new Date(Date.now() - evaluationWindow.duration),
        end: new Date(),
      },
      objective: {
        target: slo.objective.target,
        achieved: sliValue,
        compliance,
      },
      budget,
      status,
      alerts,
      metadata: {
        evaluationDuration: 0, // Will be set by the caller
        dataPoints: measurements.length,
        confidence: this.calculateConfidence(measurements),
      },
    };

    // Store evaluation
    const sloEvaluations = this.evaluations.get(sloId) || [];
    sloEvaluations.push(evaluation);

    // Enforce retention
    const retentionPeriod = this.config.storage.retention.daily;
    const cutoffTime = Date.now() - retentionPeriod;
    const filtered = sloEvaluations.filter(e => e.timestamp.getTime() > cutoffTime);

    this.evaluations.set(sloId, filtered);

    this.emit('slo:evaluated', evaluation);
    return evaluation;
  }

  /**
   * Get evaluations for an SLO
   */
  getEvaluations(sloId: string, limit?: number): SLOEvaluation[] {
    const evaluations = this.evaluations.get(sloId) || [];
    return limit ? evaluations.slice(-limit) : [...evaluations];
  }

  /**
   * Get latest evaluation for an SLO
   */
  getLatestEvaluation(sloId: string): SLOEvaluation | undefined {
    const evaluations = this.getEvaluations(sloId);
    return evaluations.length > 0 ? evaluations[evaluations.length - 1] : undefined;
  }

  // ============================================================================
  // SLO Status and Health
  // ============================================================================

  /**
   * Get overall SLO status summary
   */
  getSLOStatusSummary(): {
    total: number;
    active: number;
    compliant: number;
    violating: number;
    warning: number;
    insufficientData: number;
    byStatus: Record<SLOEvaluationStatus, number>;
    bySeverity: Record<AlertSeverity, number>;
  } {
    const summary = {
      total: 0,
      active: 0,
      compliant: 0,
      violating: 0,
      warning: 0,
      insufficientData: 0,
      byStatus: {} as Record<SLOEvaluationStatus, number>,
      bySeverity: {} as Record<AlertSeverity, number>,
    };

    // Initialize counters
    Object.values(SLOEvaluationStatus).forEach(status => {
      summary.byStatus[status] = 0;
    });
    Object.values(AlertSeverity).forEach(severity => {
      summary.bySeverity[severity] = 0;
    });

    for (const slo of this.slos.values()) {
      summary.total++;
      if (slo.status === 'active') {
        summary.active++;

        const evaluation = this.getLatestEvaluation(slo.id);
        if (evaluation) {
          summary.byStatus[evaluation.status]++;

          if (evaluation.status === SLOEvaluationStatus.COMPLIANT) {
            summary.compliant++;
          } else if (evaluation.status === SLOEvaluationStatus.VIOLATION) {
            summary.violating++;
          } else if (evaluation.status === SLOEvaluationStatus.WARNING) {
            summary.warning++;
          } else if (evaluation.status === SLOEvaluationStatus.INSUFFICIENT_DATA) {
            summary.insufficientData++;
          }

          // Count alerts by severity
          for (const alert of evaluation.alerts) {
            summary.bySeverity[alert.severity]++;
          }
        } else {
          summary.byStatus[SLOEvaluationStatus.INSUFFICIENT_DATA]++;
          summary.insufficientData++;
        }
      }
    }

    return summary;
  }

  /**
   * Get SLOs that need attention
   */
  getSLOsNeedingAttention(): Array<{
    slo: SLO;
    evaluation?: SLOEvaluation;
    alerts: SLOAlert[];
    priority: 'critical' | 'high' | 'medium' | 'low';
  }> {
    const needsAttention = [];

    for (const slo of this.slos.values()) {
      if (slo.status !== 'active') continue;

      const evaluation = this.getLatestEvaluation(slo.id);
      const alerts = evaluation?.alerts || [];

      if (!evaluation ||
          evaluation.status === SLOEvaluationStatus.VIOLATION ||
          evaluation.status === SLOEvaluationStatus.WARNING ||
          alerts.some(a => a.severity === AlertSeverity.CRITICAL || a.severity === AlertSeverity.EMERGENCY)) {

        needsAttention.push({
          slo,
          evaluation,
          alerts,
          priority: this.calculatePriority(slo, evaluation, alerts),
        });
      }
    }

    return needsAttention.sort((a, b) => this.comparePriority(a.priority, b.priority));
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  /**
   * Merge configuration with defaults
   */
  private mergeConfig(config: Partial<SLOFrameworkConfig>): SLOFrameworkConfig {
    return {
      monitoring: {
        evaluationInterval: 60000, // 1 minute
        dataRetentionPeriod: 90 * 24 * 60 * 60 * 1000, // 90 days
        batchSize: 1000,
        maxConcurrency: 10,
        ...config.monitoring,
      },
      storage: {
        type: 'influxdb',
        connection: {},
        retention: {
          raw: 7 * 24 * 60 * 60 * 1000, // 7 days
          hourly: 30 * 24 * 60 * 60 * 1000, // 30 days
          daily: 365 * 24 * 60 * 60 * 1000, // 1 year
        },
        ...config.storage,
      },
      alerting: {
        enabled: true,
        defaultChannels: [],
        rateLimiting: {
          maxAlertsPerMinute: 10,
          maxAlertsPerHour: 100,
          ...config.alerting?.rateLimiting,
        },
        ...config.alerting,
      },
      dashboard: {
        enabled: true,
        defaultRefreshInterval: 30000, // 30 seconds
        maxWidgets: 50,
        ...config.dashboard,
      },
      analytics: {
        enabled: true,
        predictionWindow: 24 * 60 * 60 * 1000, // 24 hours
        anomalyDetection: {
          enabled: true,
          sensitivity: 0.5,
          minConfidence: 0.8,
          ...config.analytics?.anomalyDetection,
        },
        ...config.analytics,
      },
      security: {
        authentication: {
          enabled: false,
          method: 'oauth',
          ...config.security?.authentication,
        },
        authorization: {
          enabled: false,
          roles: {},
          ...config.security?.authorization,
        },
        ...config.security,
      },
    };
  }

  /**
   * Validate an SLI
   */
  private validateSLI(sli: SLI): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!sli.id || sli.id.trim() === '') {
      errors.push('SLI ID is required');
    }

    if (!sli.name || sli.name.trim() === '') {
      errors.push('SLI name is required');
    }

    if (!sli.measurement) {
      errors.push('Measurement configuration is required');
    }

    if (sli.thresholds.target < 0 || sli.thresholds.target > 100) {
      errors.push('Target threshold must be between 0 and 100');
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Start evaluation for an SLO
   */
  private startSLOEvaluation(slo: SLO): void {
    // Stop existing evaluation if any
    this.stopSLOEvaluation(slo.id);

    // Start new evaluation interval
    const interval = setInterval(async () => {
      try {
        await this.evaluateSLO(slo.id);
      } catch (error) {
        this.emit('error', `SLO evaluation failed for ${slo.id}: ${error}`);
      }
    }, this.config.monitoring.evaluationInterval);

    this.evaluationIntervals.set(slo.id, interval);
  }

  /**
   * Stop evaluation for an SLO
   */
  private stopSLOEvaluation(sloId: string): void {
    const interval = this.evaluationIntervals.get(sloId);
    if (interval) {
      clearInterval(interval);
      this.evaluationIntervals.delete(sloId);
    }
  }

  /**
   * Get evaluation window for an SLO
   */
  private getEvaluationWindow(slo: SLO): TimeWindow {
    const objectivePeriod = slo.objective.period;

    switch (objectivePeriod) {
      case SLOPeriod.ROLLING_7_DAYS:
        return { type: 'rolling', duration: 7 * 24 * 60 * 60 * 1000 };
      case SLOPeriod.ROLLING_30_DAYS:
        return { type: 'rolling', duration: 30 * 24 * 60 * 60 * 1000 };
      case SLOPeriod.ROLLING_90_DAYS:
        return { type: 'rolling', duration: 90 * 24 * 60 * 60 * 1000 };
      case SLOPeriod.CALENDAR_MONTH:
        return this.getCalendarMonthWindow();
      case SLOPeriod.CALENDAR_QUARTER:
        return this.getCalendarQuarterWindow();
      case SLOPeriod.CALENDAR_YEAR:
        return this.getCalendarYearWindow();
      default:
        return { type: 'rolling', duration: 30 * 24 * 60 * 60 * 1000 };
    }
  }

  /**
   * Get current calendar month window
   */
  private getCalendarMonthWindow(): TimeWindow {
    const now = new Date();
    const start = new Date(now.getFullYear(), now.getMonth(), 1);
    const end = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59, 999);

    return {
      type: 'fixed',
      duration: end.getTime() - start.getTime(),
      start,
      end,
    };
  }

  /**
   * Get current calendar quarter window
   */
  private getCalendarQuarterWindow(): TimeWindow {
    const now = new Date();
    const quarter = Math.floor(now.getMonth() / 3);
    const start = new Date(now.getFullYear(), quarter * 3, 1);
    const end = new Date(now.getFullYear(), quarter * 3 + 3, 0, 23, 59, 59, 999);

    return {
      type: 'fixed',
      duration: end.getTime() - start.getTime(),
      start,
      end,
    };
  }

  /**
   * Get current calendar year window
   */
  private getCalendarYearWindow(): TimeWindow {
    const now = new Date();
    const start = new Date(now.getFullYear(), 0, 1);
    const end = new Date(now.getFullYear(), 11, 31, 23, 59, 59, 999);

    return {
      type: 'fixed',
      duration: end.getTime() - start.getTime(),
      start,
      end,
    };
  }

  /**
   * Calculate SLI value from measurements
   */
  private calculateSLIValue(sli: SLI, measurements: SLIMeasurement[]): number {
    if (measurements.length === 0) {
      return 0;
    }

    const values = measurements.map(m => m.value);
    const aggregation = sli.measurement.aggregation;

    switch (aggregation) {
      case SLIAggregation.AVERAGE:
        return values.reduce((sum, val) => sum + val, 0) / values.length;
      case SLIAggregation.MEDIAN:
        const sorted = [...values].sort((a, b) => a - b);
        const mid = Math.floor(sorted.length / 2);
        return sorted.length % 2 === 0
          ? (sorted[mid - 1] + sorted[mid]) / 2
          : sorted[mid];
      case SLIAggregation.P95:
        const p95Index = Math.floor(values.length * 0.95);
        return values.sort((a, b) => a - b)[p95Index];
      case SLIAggregation.P99:
        const p99Index = Math.floor(values.length * 0.99);
        return values.sort((a, b) => a - b)[p99Index];
      case SLIAggregation.MAX:
        return Math.max(...values);
      case SLIAggregation.MIN:
        return Math.min(...values);
      case SLIAggregation.SUM:
        return values.reduce((sum, val) => sum + val, 0);
      case SLIAggregation.COUNT:
        return values.length;
      case SLIAggregation.RATE:
        // Calculate rate based on time window
        if (measurements.length < 2) return 0;
        const timeSpan = measurements[measurements.length - 1].timestamp.getTime() -
                        measurements[0].timestamp.getTime();
        return (values.length / timeSpan) * 1000; // Rate per second
      case SLIAggregation.RATIO:
        // For ratio calculations, assume values are success/total pairs
        const totalSuccess = values.reduce((sum, val) => sum + val, 0);
        const totalRequests = measurements.length * 100; // Assuming each measurement represents 100 requests
        return totalRequests > 0 ? (totalSuccess / totalRequests) * 100 : 0;
      default:
        return values.reduce((sum, val) => sum + val, 0) / values.length;
    }
  }

  /**
   * Calculate compliance percentage
   */
  private calculateCompliance(achieved: number, target: number): number {
    if (target === 0) return 100;
    return Math.min((achieved / target) * 100, 100);
  }

  /**
   * Calculate error budget metrics
   */
  private calculateErrorBudget(
    slo: SLO,
    sliValue: number,
    evaluationWindow: TimeWindow
  ): {
    total: number;
    consumed: number;
    remaining: number;
    burnRate: number;
    trend: BurnRateTrend;
  } {
    const errorBudget = slo.budgeting.errorBudget;
    const total = errorBudget;

    // Calculate consumed budget based on current performance
    const deviation = Math.max(0, slo.objective.target - sliValue);
    const consumed = (deviation / (100 - slo.objective.target)) * total;
    const remaining = Math.max(0, total - consumed);

    // Calculate burn rate (rate of budget consumption)
    const burnRate = this.calculateBurnRate(slo.id, evaluationWindow);

    // Determine trend
    const trend = this.calculateBurnRateTrend(slo.id);

    return {
      total,
      consumed,
      remaining,
      burnRate,
      trend,
    };
  }

  /**
   * Calculate current burn rate
   */
  private calculateBurnRate(sloId: string, evaluationWindow: TimeWindow): number {
    const evaluations = this.getEvaluations(sloId);
    if (evaluations.length < 2) return 0;

    const recentEvaluations = evaluations.slice(-10); // Last 10 evaluations
    if (recentEvaluations.length < 2) return 0;

    const latest = recentEvaluations[recentEvaluations.length - 1];
    const previous = recentEvaluations[recentEvaluations.length - 2];

    const timeDiff = latest.timestamp.getTime() - previous.timestamp.getTime();
    const budgetDiff = latest.budget.consumed - previous.budget.consumed;

    if (timeDiff <= 0) return 0;

    // Convert to hourly burn rate
    const hourlyBurnRate = (budgetDiff / timeDiff) * (60 * 60 * 1000);
    return Math.max(0, hourlyBurnRate);
  }

  /**
   * Calculate burn rate trend
   */
  private calculateBurnRateTrend(sloId: string): BurnRateTrend {
    const evaluations = this.getEvaluations(sloId);
    if (evaluations.length < 3) return BurnRateTrend.UNKNOWN;

    const recentEvaluations = evaluations.slice(-5);
    const burnRates = recentEvaluations.map(e => e.budget.burnRate);

    // Simple trend analysis
    let increasing = 0;
    let decreasing = 0;

    for (let i = 1; i < burnRates.length; i++) {
      if (burnRates[i] > burnRates[i - 1] * 1.1) {
        increasing++;
      } else if (burnRates[i] < burnRates[i - 1] * 0.9) {
        decreasing++;
      }
    }

    if (increasing > decreasing) return BurnRateTrend.INCREASING;
    if (decreasing > increasing) return BurnRateTrend.DECREASING;
    return BurnRateTrend.STABLE;
  }

  /**
   * Determine SLO evaluation status
   */
  private determineSLOStatus(
    compliance: number,
    budget: any
  ): SLOEvaluationStatus {
    // Check for violation
    if (compliance < 95 || budget.remaining <= 0) {
      return SLOEvaluationStatus.VIOLATION;
    }

    // Check for warning
    if (compliance < 98 || budget.remaining < budget.total * 0.2) {
      return SLOEvaluationStatus.WARNING;
    }

    // Check for sufficient data
    if (budget.burnRate === 0 && budget.consumed === 0) {
      return SLOEvaluationStatus.INSUFFICIENT_DATA;
    }

    return SLOEvaluationStatus.COMPLIANT;
  }

  /**
   * Generate SLO alerts
   */
  private async generateSLOAlerts(
    slo: SLO,
    status: SLOEvaluationStatus,
    compliance: number,
    budget: any
  ): Promise<SLOAlert[]> {
    const alerts: SLOAlert[] = [];

    if (!slo.alerting.enabled) {
      return alerts;
    }

    // Check burn rate alerts
    for (const burnRateAlert of slo.budgeting.burnRateAlerts) {
      if (budget.burnRate > burnRateAlert.threshold) {
        alerts.push({
          id: this.generateId(),
          sloId: slo.id,
          type: SLOAlertType.BURN_RATE_HIGH,
          severity: burnRateAlert.severity,
          title: `High Burn Rate Alert`,
          message: `SLO ${slo.name} burn rate is ${budget.burnRate.toFixed(2)}x, exceeding threshold of ${burnRateAlert.threshold}x`,
          timestamp: new Date(),
          acknowledged: false,
          resolved: false,
          metadata: {
            threshold: burnRateAlert.threshold,
            actualValue: budget.burnRate,
            evaluationWindow: slo.objective.window,
          },
        });
      }
    }

    // Check budget exhaustion
    if (budget.remaining <= 0) {
      alerts.push({
        id: this.generateId(),
        sloId: slo.id,
        type: SLOAlertType.BUDGET_EXHAUSTED,
        severity: AlertSeverity.CRITICAL,
        title: `Error Budget Exhausted`,
        message: `SLO ${slo.name} has exhausted its error budget`,
        timestamp: new Date(),
        acknowledged: false,
        resolved: false,
        metadata: {
          threshold: 0,
          actualValue: budget.remaining,
          evaluationWindow: slo.objective.window,
        },
      });
    }

    // Check SLO violation
    if (status === SLOEvaluationStatus.VIOLATION) {
      alerts.push({
        id: this.generateId(),
        sloId: slo.id,
        type: SLOAlertType.SLO_VIOLATION,
        severity: AlertSeverity.CRITICAL,
        title: `SLO Violation`,
        message: `SLO ${slo.name} is in violation with ${compliance.toFixed(2)}% compliance`,
        timestamp: new Date(),
        acknowledged: false,
        resolved: false,
        metadata: {
          threshold: slo.objective.target,
          actualValue: compliance,
          evaluationWindow: slo.objective.window,
        },
      });
    }

    // Check compliance warning
    if (status === SLOEvaluationStatus.WARNING) {
      alerts.push({
        id: this.generateId(),
        sloId: slo.id,
        type: SLOAlertType.COMPLIANCE_WARNING,
        severity: AlertSeverity.WARNING,
        title: `SLO Compliance Warning`,
        message: `SLO ${slo.name} compliance is ${compliance.toFixed(2)}%, approaching threshold`,
        timestamp: new Date(),
        acknowledged: false,
        resolved: false,
        metadata: {
          threshold: slo.objective.target,
          actualValue: compliance,
          evaluationWindow: slo.objective.window,
        },
      });
    }

    return alerts;
  }

  /**
   * Calculate confidence in measurements
   */
  private calculateConfidence(measurements: SLIMeasurement[]): number {
    if (measurements.length === 0) return 0;

    // Calculate average data quality
    const avgCompleteness = measurements.reduce((sum, m) => sum + m.quality.completeness, 0) / measurements.length;
    const avgAccuracy = measurements.reduce((sum, m) => sum + m.quality.accuracy, 0) / measurements.length;
    const avgTimeliness = measurements.reduce((sum, m) => sum + m.quality.timeliness, 0) / measurements.length;

    // Factor in data volume
    const volumeFactor = Math.min(measurements.length / 100, 1); // Normalized to 100 data points

    return (avgCompleteness * 0.4 + avgAccuracy * 0.3 + avgTimeliness * 0.2 + volumeFactor * 0.1);
  }

  /**
   * Calculate priority for SLO attention
   */
  private calculatePriority(
    slo: SLO,
    evaluation: SLOEvaluation | undefined,
    alerts: SLOAlert[]
  ): 'critical' | 'high' | 'medium' | 'low' {
    if (!evaluation) return 'medium';

    // Emergency alerts get critical priority
    if (alerts.some(a => a.severity === AlertSeverity.EMERGENCY)) {
      return 'critical';
    }

    // Critical alerts get high priority
    if (alerts.some(a => a.severity === AlertSeverity.CRITICAL)) {
      return 'high';
    }

    // Violations get high priority
    if (evaluation.status === SLOEvaluationStatus.VIOLATION) {
      return 'high';
    }

    // Warnings get medium priority
    if (evaluation.status === SLOEvaluationStatus.WARNING) {
      return 'medium';
    }

    // Low remaining budget gets medium priority
    if (evaluation.budget.remaining < evaluation.budget.total * 0.1) {
      return 'medium';
    }

    return 'low';
  }

  /**
   * Compare priority levels
   */
  private comparePriority(a: 'critical' | 'high' | 'medium' | 'low', b: 'critical' | 'high' | 'medium' | 'low'): number {
    const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return priorityOrder[a] - priorityOrder[b];
  }

  /**
   * Generate unique ID
   */
  private generateId(): string {
    return Math.random().toString(36).substr(2, 9);
  }
}

// Export singleton instance
export const sloService = new SLOService();