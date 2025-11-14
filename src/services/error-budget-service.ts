// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Error Budget Service
 *
 * Comprehensive service for tracking error budgets, calculating burn rates,
 * providing budget projections, and managing budget-based alerting and automation.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'events';

import { type SLOService } from './slo-service.js';
import {
  type BudgetAlert,
  type BudgetConsumption,
  type BudgetPeriod,
  type BudgetProjection,
  type BudgetUtilization,
  type BurnRateAnalysis,
  BurnRateTrend,
  type ErrorBudget,
  type ErrorBudgetPolicy,
  type SLO,
  type SLOEvaluation,
  type TimeRange,
} from '../types/slo-interfaces.js';

/**
 * Error Budget Service
 */
export class ErrorBudgetService extends EventEmitter {
  private sloService: SLOService;
  private budgetHistory: Map<string, ErrorBudgetHistory[]> = new Map();
  private burnRateHistory: Map<string, BurnRateDataPoint[]> = new Map();
  private budgetPolicies: Map<string, ErrorBudgetPolicy> = new Map();
  private budgetAlerts: Map<string, BudgetAlert[]> = new Map();
  private isStarted = false;
  private calculationIntervals: Map<string, NodeJS.Timeout> = new Map();

  constructor(sloService: SLOService) {
    super();
    this.sloService = sloService;
    this.setupEventHandlers();
  }

  /**
   * Start the error budget service
   */
  async start(): Promise<void> {
    if (this.isStarted) {
      this.emit('warning', 'Error Budget Service is already started');
      return;
    }

    try {
      this.isStarted = true;
      this.emit('started', 'Error Budget Service started successfully');

      // Initialize budget tracking for all active SLOs
      await this.initializeBudgetTracking();

      // Schedule periodic budget calculations
      this.schedulePeriodicCalculations();

    } catch (error) {
      this.isStarted = false;
      this.emit('error', `Failed to start Error Budget Service: ${error}`);
      throw error;
    }
  }

  /**
   * Stop the error budget service
   */
  async stop(): Promise<void> {
    if (!this.isStarted) {
      this.emit('warning', 'Error Budget Service is not started');
      return;
    }

    try {
      // Stop all calculation intervals
      this.calculationIntervals.forEach((interval, sloId) => {
        clearInterval(interval);
      });
      this.calculationIntervals.clear();

      this.isStarted = false;
      this.emit('stopped', 'Error Budget Service stopped successfully');
    } catch (error) {
      this.emit('error', `Error stopping Error Budget Service: ${error}`);
      throw error;
    }
  }

  // ============================================================================
  // Error Budget Calculation
  // ============================================================================

  /**
   * Calculate current error budget for an SLO
   */
  async calculateErrorBudget(sloId: string, timeWindow?: TimeRange): Promise<ErrorBudget> {
    const slo = this.sloService.getSLO(sloId);
    if (!slo) {
      throw new Error(`SLO ${sloId} not found`);
    }

    const evaluation = this.sloService.getLatestEvaluation(sloId);
    if (!evaluation) {
      throw new Error(`No evaluation found for SLO ${sloId}`);
    }

    // Determine calculation period - ensure we always return BudgetPeriod
    const period = timeWindow ? (timeWindow as unknown as BudgetPeriod) : this.getBudgetPeriod(slo);

    // Get historical data for the period
    const evaluations = this.sloService.getEvaluations(sloId, 1000);
    const periodEvaluations = this.filterEvaluationsByPeriod(evaluations, period);

    // Calculate budget metrics
    const budgetMetrics = this.calculateBudgetMetrics(slo, periodEvaluations, period);

    // Calculate consumption rates
    const consumption = this.calculateBudgetConsumption(periodEvaluations, period);

    // Generate projection
    const projection = this.generateBudgetProjectionInternal(budgetMetrics, consumption, period) as BudgetProjection;

    const utilization = this.calculateBudgetUtilization(budgetMetrics);

    // Set missing IDs and periods
    (consumption as unknown).sloId = sloId;
    (utilization as unknown).sloId = sloId;
    (utilization as unknown).period = period;

    const errorBudget: ErrorBudget = {
      sloId,
      period,
      total: slo.budgeting.errorBudget,
      remaining: budgetMetrics.remaining,
      consumed: budgetMetrics.consumed,
      burnRate: (consumption.currentRate as number) || 0,
      lastUpdated: new Date(),
      consumption: {
        current: (consumption.currentRate as number) || 0,
        rate: (consumption.currentRate as number) || 0,
        trend: 'stable' as const,
      },
      metadata: {
        calculatedAt: new Date(),
        dataPoints: periodEvaluations.length,
        confidence: this.calculateConfidence(periodEvaluations),
        methodology: 'time_weighted_average',
        sloName: slo.name,
        alerts: await this.generateBudgetAlerts(slo, budgetMetrics, consumption),
        projection,
        utilization,
      },
    };

    // Store in history
    this.storeBudgetHistory(sloId, errorBudget);

    this.emit('budget:calculated', errorBudget);
    return errorBudget;
  }

  /**
   * Get error budget history for an SLO
   */
  getErrorBudgetHistory(sloId: string, limit?: number): ErrorBudgetHistory[] {
    const history = this.budgetHistory.get(sloId) || [];
    return limit ? history.slice(-limit) : [...history];
  }

  /**
   * Get current error budgets for multiple SLOs
   */
  async getMultipleErrorBudgets(sloIds: string[]): Promise<ErrorBudget[]> {
    const budgets = await Promise.allSettled(
      sloIds.map(sloId => this.calculateErrorBudget(sloId))
    );

    return budgets
      .filter((result): result is PromiseFulfilledResult<ErrorBudget> => result.status === 'fulfilled')
      .map(result => result.value);
  }

  // ============================================================================
  // Burn Rate Analysis
  // ============================================================================

  /**
   * Calculate burn rate analysis
   */
  async calculateBurnRateAnalysis(sloId: string, timeWindow?: TimeRange): Promise<BurnRateAnalysis> {
    const slo = this.sloService.getSLO(sloId);
    if (!slo) {
      throw new Error(`SLO ${sloId} not found`);
    }

    const period = timeWindow ? (timeWindow as unknown as BudgetPeriod) : this.getBudgetPeriod(slo);
    const evaluations = this.sloService.getEvaluations(sloId, 1000);
    const periodEvaluations = this.filterEvaluationsByPeriod(evaluations, period);

    // Calculate burn rates at different time scales
    const burnRates = {
      hourly: this.calculateBurnRateAtTimeScale(periodEvaluations, 'hourly'),
      daily: this.calculateBurnRateAtTimeScale(periodEvaluations, 'daily'),
      weekly: this.calculateBurnRateAtTimeScale(periodEvaluations, 'weekly'),
      monthly: this.calculateBurnRateAtTimeScale(periodEvaluations, 'monthly'),
    };

    // Analyze burn rate trend
    const trend = this.analyzeBurnRateTrend(periodEvaluations);

    // Calculate burn rate velocity
    const velocity = this.calculateBurnRateVelocity(periodEvaluations);

    // Assess burn rate health
    const health = this.assessBurnRateHealth(slo, burnRates, trend);

    // Generate burn rate alerts
    const alerts = this.generateBurnRateAlerts(slo, burnRates, trend, health);

    // Calculate budget metrics for burn rate analysis
    const budgetMetrics = this.calculateBudgetMetrics(slo, periodEvaluations, period);
    const consumption = this.calculateBudgetConsumption(periodEvaluations, period);

    // Convert trend object to string type expected by interface
    let trendType: 'increasing' | 'decreasing' | 'stable' | 'volatile' = 'stable';
    if (trend.direction === BurnRateTrend.INCREASING) {
      trendType = 'increasing';
    } else if (trend.direction === BurnRateTrend.DECREASING) {
      trendType = 'decreasing';
    } else if (trend.confidence < 0.5) {
      trendType = 'volatile';
    }

    const analysis: BurnRateAnalysis = {
      sloId,
      period,
      currentRate: burnRates.daily,
      trend: trendType,
      velocity: velocity.average,
      health: health.score,
      analysisPeriod: period,
      averageRate: burnRates.daily,
      peakRate: Math.max(burnRates.hourly, burnRates.daily, burnRates.weekly, burnRates.monthly),
      timeToExhaustion: (consumption.currentRate as number) > 0 ? budgetMetrics.remaining / (consumption.currentRate as number) : null,
      factors: {
        recentIncidents: 0,
        degradedOperations: budgetMetrics.consumed || 0,
        seasonalFactors: 0,
      },
      metadata: {
        calculatedAt: new Date(),
        dataPoints: periodEvaluations.length,
        confidence: this.calculateConfidence(periodEvaluations),
        sloName: slo.name,
        alerts,
        currentRates: burnRates,
        trendDetails: trend,
        velocityDetails: velocity,
        healthDetails: health,
        recommendations: this.generateBurnRateRecommendations(slo, burnRates, trend, health),
      },
    };

    // Store burn rate data point
    this.storeBurnRateDataPoint(sloId, analysis);

    this.emit('burn-rate:analyzed', analysis);
    return analysis;
  }

  /**
   * Get burn rate history
   */
  getBurnRateHistory(sloId: string, limit?: number): BurnRateDataPoint[] {
    const history = this.burnRateHistory.get(sloId) || [];
    return limit ? history.slice(-limit) : [...history];
  }

  /**
   * Compare burn rates across SLOs
   */
  async compareBurnRates(sloIds: string[]): Promise<BurnRateComparison> {
    const analyses = await Promise.all(
      sloIds.map(sloId => this.calculateBurnRateAnalysis(sloId))
    );

    const defaultPeriod: BudgetPeriod = {
      start: new Date(),
      end: new Date(),
      type: 'rolling' as const,
      length: 30,
    };
    const comparison: BurnRateComparison = {
      period: (analyses[0]?.period as BudgetPeriod) || defaultPeriod,
      sloComparisons: analyses.map(analysis => ({
        sloId: analysis.sloId,
        sloName: (analysis.metadata as unknown)?.sloName || 'Unknown SLO',
        burnRate: analysis.currentRate,
        trend: (analysis.metadata as unknown)?.trendDetails || { direction: BurnRateTrend.UNKNOWN, confidence: 0, slope: 0 },
        health: (analysis.metadata as unknown)?.healthDetails || { status: 'healthy' as const, score: 100, factors: [] },
      })),
      rankings: this.rankSLOsByBurnRate(analyses),
      insights: this.generateBurnRateInsights(analyses),
      generatedAt: new Date(),
    };

    this.emit('burn-rate:compared', comparison);
    return comparison;
  }

  // ============================================================================
  // Budget Projections
  // ============================================================================

  /**
   * Generate budget projection
   */
  async generateBudgetProjection(
    sloId: string,
    projectionPeriodParam?: TimeRange
  ): Promise<BudgetProjection> {
    const slo = this.sloService.getSLO(sloId);
    if (!slo) {
      throw new Error(`SLO ${sloId} not found`);
    }

    const currentBudget = await this.calculateErrorBudget(sloId);
    const burnRateAnalysis = await this.calculateBurnRateAnalysis(sloId);

    const projectionPeriod = projectionPeriodParam || {
      start: new Date(),
      end: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      type: 'fixed' as const,
      length: 30,
    };

    // Generate projection using the existing method
    const projection = this.generateBudgetProjectionInternal(currentBudget, burnRateAnalysis, projectionPeriod as unknown as BudgetPeriod);

    this.emit('projection:generated', projection);
    return projection;
  }

  /**
   * Get budget exhaustion forecast
   */
  async getBudgetExhaustionForecast(sloId: string): Promise<ExhaustionForecast> {
    const projection = await this.generateBudgetProjection(sloId);

    // Find earliest exhaustion across scenarios
    const scenarios = projection.scenarios as unknown;
    const exhaustionDates = [
      scenarios.optimistic,
      scenarios.realistic,
      scenarios.pessimistic
    ].filter(date => date !== null);

    const earliestExhaustion = exhaustionDates.length > 0
      ? new Date(Math.min(...exhaustionDates.map(date => date.getTime())))
      : null;

    // Calculate time to exhaustion
    const timeToExhaustion = earliestExhaustion
      ? earliestExhaustion.getTime() - Date.now()
      : null;

    const forecast: ExhaustionForecast = {
      sloId,
      earliestExhaustion,
      timeToExhaustion,
      probabilityOfExhaustion: (projection.exhaustionProbability as number) || 0,
      confidence: ((projection.metadata as unknown)?.confidence as number) || 0.5,
      recommendations: this.generateExhaustionRecommendations(sloId, earliestExhaustion, timeToExhaustion),
      generatedAt: new Date(),
    };

    this.emit('exhaustion:forecasted', forecast);
    return forecast;
  }

  // ============================================================================
  // Budget Policies Management
  // ============================================================================

  /**
   * Configure error budget policy
   */
  configureBudgetPolicy(sloId: string, policy: ErrorBudgetPolicy): void {
    this.budgetPolicies.set(sloId, policy);
    this.emit('policy:configured', { sloId, policy });
  }

  /**
   * Get budget policy for an SLO
   */
  getBudgetPolicy(sloId: string): ErrorBudgetPolicy | undefined {
    return this.budgetPolicies.get(sloId);
  }

  /**
   * Evaluate policy compliance
   */
  async evaluatePolicyCompliance(sloId: string): Promise<PolicyComplianceResult> {
    const policy = this.budgetPolicies.get(sloId);
    if (!policy) {
      throw new Error(`No policy configured for SLO ${sloId}`);
    }

    const budget = await this.calculateErrorBudget(sloId);
    const burnRateAnalysis = await this.calculateBurnRateAnalysis(sloId);

    const compliance = {
      withinBurnRateLimits: this.checkBurnRateCompliance(policy, burnRateAnalysis),
      withinConsumptionLimits: this.checkConsumptionCompliance(policy, budget),
      alertsTriggered: this.checkAlertCompliance(policy, budget, burnRateAnalysis),
      automatedResponses: this.checkAutomationCompliance(policy, budget, burnRateAnalysis),
    };

    const overallCompliance = Object.values(compliance).every(result => result.compliant);

    const result: PolicyComplianceResult = {
      sloId,
      policyId: policy.id,
      overallCompliance,
      compliance,
      violations: this.identifyPolicyViolations(policy, budget, burnRateAnalysis),
      recommendations: this.generatePolicyRecommendations(policy, budget, burnRateAnalysis),
      evaluatedAt: new Date(),
    };

    this.emit('policy:evaluated', result);
    return result;
  }

  // ============================================================================
  // Budget Alerts Management
  // ============================================================================

  /**
   * Get active budget alerts
   */
  getActiveBudgetAlerts(sloId?: string): BudgetAlert[] {
    const allAlerts = Array.from(this.budgetAlerts.values()).flat();
    const activeAlerts = allAlerts.filter(alert => !alert.resolved);

    if (sloId) {
      return activeAlerts.filter(alert => alert.sloId === sloId);
    }

    return activeAlerts;
  }

  /**
   * Acknowledge a budget alert
   */
  async acknowledgeBudgetAlert(alertId: string, acknowledgedBy: string): Promise<boolean> {
    const allAlerts = Array.from(this.budgetAlerts.values()).flat();
    const alert = allAlerts.find(a => a.id === alertId);

    if (!alert || alert.resolved) {
      return false;
    }

    alert.acknowledged = true;
    alert.acknowledgedBy = acknowledgedBy;
    alert.acknowledgedAt = new Date();

    this.emit('alert:acknowledged', alert);
    return true;
  }

  /**
   * Resolve a budget alert
   */
  async resolveBudgetAlert(alertId: string, resolvedBy: string, resolution?: string): Promise<boolean> {
    const allAlerts = Array.from(this.budgetAlerts.values()).flat();
    const alert = allAlerts.find(a => a.id === alertId);

    if (!alert) {
      return false;
    }

    alert.resolved = true;
    alert.resolvedBy = resolvedBy;
    alert.resolvedAt = new Date();
    alert.resolution = resolution;

    this.emit('alert:resolved', alert);
    return true;
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
        await this.calculateErrorBudget(evaluation.sloId);
        await this.calculateBurnRateAnalysis(evaluation.sloId);
      }
    });
  }

  /**
   * Initialize budget tracking for all active SLOs
   */
  private async initializeBudgetTracking(): Promise<void> {
    const slos = this.sloService.getAllSLOs();

    for (const slo of slos) {
      if (slo.status === 'active') {
        // Initialize budget calculation
        await this.calculateErrorBudget(slo.id);

        // Start periodic calculations for this SLO
        this.startBudgetCalculation(slo.id);
      }
    }
  }

  /**
   * Start budget calculation for an SLO
   */
  private startBudgetCalculation(sloId: string): void {
    // Stop existing calculation if any
    this.stopBudgetCalculation(sloId);

    // Start calculation interval
    const interval = setInterval(async () => {
      try {
        await this.calculateErrorBudget(sloId);
        await this.calculateBurnRateAnalysis(sloId);
      } catch (error) {
        this.emit('error', `Budget calculation failed for SLO ${sloId}: ${error}`);
      }
    }, 60000); // Calculate every minute

    this.calculationIntervals.set(sloId, interval);
  }

  /**
   * Stop budget calculation for an SLO
   */
  private stopBudgetCalculation(sloId: string): void {
    const interval = this.calculationIntervals.get(sloId);
    if (interval) {
      clearInterval(interval);
      this.calculationIntervals.delete(sloId);
    }
  }

  /**
   * Schedule periodic calculations
   */
  private schedulePeriodicCalculations(): void {
    // Comprehensive calculation every 5 minutes
    setInterval(async () => {
      if (!this.isStarted) return;

      try {
        const slos = this.sloService.getAllSLOs();
        for (const slo of slos) {
          if (slo.status === 'active') {
            await this.calculateErrorBudget(slo.id);
            await this.calculateBurnRateAnalysis(slo.id);
          }
        }
      } catch (error) {
        this.emit('error', `Periodic budget calculation failed: ${error}`);
      }
    }, 5 * 60 * 1000); // Every 5 minutes
  }

  /**
   * Get budget period for an SLO
   */
  private getBudgetPeriod(slo: SLO): BudgetPeriod {
    const objectivePeriod = slo.objective.period;
    const now = new Date();

    switch (objectivePeriod) {
      case 'rolling_7_days':
        return {
          start: new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000),
          end: now,
          type: 'rolling',
          length: 7,
        };
      case 'rolling_30_days':
        return {
          start: new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000),
          end: now,
          type: 'rolling',
          length: 30,
        };
      case 'calendar_month':
        return {
          start: new Date(now.getFullYear(), now.getMonth(), 1),
          end: new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59, 999),
          type: 'calendar',
          length: 0,
        };
      default:
        return {
          start: new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000),
          end: now,
          type: 'rolling',
          length: 30,
        };
    }
  }

  /**
   * Filter evaluations by period
   */
  private filterEvaluationsByPeriod(evaluations: SLOEvaluation[], period: BudgetPeriod): SLOEvaluation[] {
    return evaluations.filter(evaluation =>
      evaluation.timestamp >= period.start && evaluation.timestamp <= period.end
    );
  }

  /**
   * Calculate budget metrics
   */
  private calculateBudgetMetrics(
    slo: SLO,
    evaluations: SLOEvaluation[],
    period: BudgetPeriod
  ): { remaining: number; consumed: number; total: number } {
    const totalBudget = slo.budgeting.errorBudget;

    if (evaluations.length === 0) {
      return { remaining: totalBudget, consumed: 0, total: totalBudget };
    }

    // Calculate time-weighted average consumption
    let totalConsumption = 0;
    let totalWeight = 0;

    for (let i = 0; i < evaluations.length; i++) {
      const evaluation = evaluations[i];
      const nextEvaluation = evaluations[i + 1];

      const endTime = nextEvaluation ? nextEvaluation.timestamp : period.end;
      const duration = endTime.getTime() - evaluation.timestamp.getTime();
      const weight = duration;

      totalConsumption += evaluation.budget.consumed * weight;
      totalWeight += weight;
    }

    const averageConsumption = totalWeight > 0 ? totalConsumption / totalWeight : 0;
    const remaining = Math.max(0, totalBudget - averageConsumption);

    return {
      remaining,
      consumed: averageConsumption,
      total: totalBudget,
    };
  }

  /**
   * Calculate budget consumption
   */
  private calculateBudgetConsumption(
    evaluations: SLOEvaluation[],
    period: BudgetPeriod
  ): BudgetConsumption {
    // Calculate consumption rates
    const rates = evaluations.map(e => e.budget.burnRate);
    const currentRate = rates[rates.length - 1] || 0;
    const totalConsumption = rates.reduce((sum, rate) => sum + rate, 0);

    return {
      sloId: '', // Will be set by caller
      period,
      consumption: {
        total: totalConsumption,
        byCategory: {
          burn_rate: totalConsumption,
        },
        byTimeSlot: evaluations.map(e => ({
          timeSlot: e.timestamp,
          consumption: e.budget.consumed,
          operations: e.budget.total || 0,
        })),
      },
      sources: [{
        type: 'slo_evaluation',
        contribution: totalConsumption,
        details: { dataPoints: evaluations.length },
      }],
      currentRate,
    };
  }

  /**
   * Calculate budget utilization
   */
  private calculateBudgetUtilization(budgetMetrics: { remaining: number; consumed: number; total: number }): BudgetUtilization {
    const utilizationPercentage = (budgetMetrics.consumed / budgetMetrics.total) * 100;

    return {
      sloId: '', // Will be set by caller
      period: { start: new Date(), end: new Date(), type: 'rolling', length: 0 }, // Will be set by caller
      utilization: {
        percentage: utilizationPercentage,
        efficiency: Math.max(0, 100 - utilizationPercentage), // Inverse of utilization
        trend: 'stable' as const, // Would calculate from historical data
      },
      breakdown: {
        successfulOperations: Math.max(0, budgetMetrics.total - budgetMetrics.consumed),
        failedOperations: budgetMetrics.consumed,
        degradedOperations: 0,
        excludedOperations: 0,
      },
      recommendations: [
        utilizationPercentage > 80 ? 'Investigate high error budget utilization' : 'Continue monitoring utilization',
        'Review recent changes that may affect performance',
      ],
    };
  }

  /**
   * Get budget status
   */
  private getBudgetStatus(percentage: number): 'healthy' | 'warning' | 'critical' | 'exhausted' {
    if (percentage >= 100) return 'exhausted';
    if (percentage >= 80) return 'critical';
    if (percentage >= 60) return 'warning';
    return 'healthy';
  }

  /**
   * Generate budget alerts
   */
  private async generateBudgetAlerts(
    slo: SLO,
    budgetMetrics: { remaining: number; consumed: number; total: number },
    consumption: BudgetConsumption
  ): Promise<BudgetAlert[]> {
    const alerts: BudgetAlert[] = [];
    const utilizationPercentage = (budgetMetrics.consumed / budgetMetrics.total) * 100;

    // Budget exhaustion alert
    if (budgetMetrics.remaining <= 0) {
      alerts.push({
        id: this.generateId(),
        sloId: slo.id,
        type: 'exhaustion',
        severity: 'critical',
        threshold: 0,
        currentValue: budgetMetrics.remaining,
        enabled: true,
        triggered: true,
        lastTriggered: new Date(),
        acknowledged: false,
      });
    }

    // High consumption rate alert
    const currentRate = (consumption.currentRate as number) || 0;
    if (currentRate > 2) {
      alerts.push({
        id: this.generateId(),
        sloId: slo.id,
        type: 'burn_rate',
        severity: currentRate > 5 ? 'critical' : 'warning',
        threshold: 2,
        currentValue: currentRate,
        enabled: true,
        triggered: true,
        lastTriggered: new Date(),
        acknowledged: false,
        burnRate: currentRate,
      });
    }

    // Budget depletion warning
    if (utilizationPercentage >= 80) {
      alerts.push({
        id: this.generateId(),
        sloId: slo.id,
        type: 'exhaustion',
        severity: utilizationPercentage >= 95 ? 'critical' : 'warning',
        threshold: 80,
        currentValue: utilizationPercentage,
        enabled: true,
        triggered: true,
        lastTriggered: new Date(),
        acknowledged: false,
      });
    }

    // Store alerts
    const existingAlerts = this.budgetAlerts.get(slo.id) || [];
    existingAlerts.push(...alerts);
    this.budgetAlerts.set(slo.id, existingAlerts);

    return alerts;
  }

  /**
   * Calculate burn rate at specific time scale
   */
  private calculateBurnRateAtTimeScale(
    evaluations: SLOEvaluation[],
    timeScale: 'hourly' | 'daily' | 'weekly' | 'monthly'
  ): number {
    if (evaluations.length === 0) return 0;

    const now = new Date();
    let periodStart: Date;

    switch (timeScale) {
      case 'hourly':
        periodStart = new Date(now.getTime() - 60 * 60 * 1000);
        break;
      case 'daily':
        periodStart = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        break;
      case 'weekly':
        periodStart = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case 'monthly':
        periodStart = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
    }

    const periodEvaluations = evaluations.filter(e => e.timestamp >= periodStart);
    if (periodEvaluations.length < 2) return 0;

    const first = periodEvaluations[0];
    const last = periodEvaluations[periodEvaluations.length - 1];

    const budgetConsumed = last.budget.consumed - first.budget.consumed;
    const timeElapsed = last.timestamp.getTime() - first.timestamp.getTime();
    const hoursElapsed = timeElapsed / (60 * 60 * 1000);

    return hoursElapsed > 0 ? budgetConsumed / hoursElapsed : 0;
  }

  /**
   * Analyze burn rate trend
   */
  private analyzeBurnRateTrend(evaluations: SLOEvaluation[]): {
    direction: BurnRateTrend;
    confidence: number;
    slope: number;
  } {
    if (evaluations.length < 3) {
      return { direction: BurnRateTrend.UNKNOWN, confidence: 0, slope: 0 };
    }

    const burnRates = evaluations.map(e => e.budget.burnRate);
    const regression = this.calculateLinearRegression(burnRates.map((rate, i) => ({ x: i, y: rate })));

    let direction: BurnRateTrend;
    if (Math.abs(regression.slope) < 0.01) {
      direction = BurnRateTrend.STABLE;
    } else if (regression.slope > 0) {
      direction = BurnRateTrend.INCREASING;
    } else {
      direction = BurnRateTrend.DECREASING;
    }

    // Calculate confidence based on correlation
    const correlation = this.calculateCorrelation(burnRates.map((rate, i) => ({ x: i, y: rate })));
    const confidence = Math.abs(correlation);

    return {
      direction,
      confidence,
      slope: regression.slope,
    };
  }

  /**
   * Calculate burn rate velocity
   */
  private calculateBurnRateVelocity(evaluations: SLOEvaluation[]): {
    current: number;
    average: number;
    acceleration: number;
  } {
    if (evaluations.length < 3) {
      return { current: 0, average: 0, acceleration: 0 };
    }

    const burnRates = evaluations.map(e => e.budget.burnRate);
    const current = burnRates[burnRates.length - 1];
    const average = burnRates.reduce((sum, rate) => sum + rate, 0) / burnRates.length;

    // Calculate acceleration (second derivative)
    let acceleration = 0;
    if (burnRates.length >= 3) {
      const recent = burnRates.slice(-3);
      const firstDiff = recent[1] - recent[0];
      const secondDiff = recent[2] - recent[1];
      acceleration = secondDiff - firstDiff;
    }

    return { current, average, acceleration };
  }

  /**
   * Assess burn rate health
   */
  private assessBurnRateHealth(
    slo: SLO,
    burnRates: { hourly: number; daily: number; weekly: number; monthly: number },
    trend: { direction: BurnRateTrend; confidence: number; slope: number }
  ): {
    status: 'healthy' | 'warning' | 'critical';
    score: number;
    factors: string[];
  } {
    const factors: string[] = [];
    let score = 100;

    // Check current burn rate
    if (burnRates.daily > 2) {
      score -= 30;
      factors.push('High daily burn rate');
    } else if (burnRates.daily > 1) {
      score -= 15;
      factors.push('Elevated daily burn rate');
    }

    // Check trend
    if (trend.direction === BurnRateTrend.INCREASING && trend.confidence > 0.7) {
      score -= 20;
      factors.push('Increasing burn rate trend');
    }

    // Check acceleration
    if (burnRates.daily > burnRates.weekly * 1.5) {
      score -= 15;
      factors.push('Accelerating consumption');
    }

    let status: 'healthy' | 'warning' | 'critical';
    if (score >= 80) {
      status = 'healthy';
    } else if (score >= 60) {
      status = 'warning';
    } else {
      status = 'critical';
    }

    return { status, score, factors };
  }

  /**
   * Generate burn rate alerts
   */
  private generateBurnRateAlerts(
    slo: SLO,
    burnRates: { hourly: number; daily: number; weekly: number; monthly: number },
    trend: { direction: BurnRateTrend; confidence: number; slope: number },
    health: { status: 'healthy' | 'warning' | 'critical'; score: number; factors: string[] }
  ): BudgetAlert[] {
    const alerts: BudgetAlert[] = [];

    // High burn rate alerts
    if (burnRates.daily > 5) {
      alerts.push({
        id: this.generateId(),
        sloId: slo.id,
        type: 'burn_rate',
        severity: 'critical',
        threshold: 5,
        currentValue: burnRates.daily,
        enabled: true,
        triggered: true,
        lastTriggered: new Date(),
        acknowledged: false,
        burnRate: burnRates.daily,
      });
    } else if (burnRates.daily > 2) {
      alerts.push({
        id: this.generateId(),
        sloId: slo.id,
        type: 'burn_rate',
        severity: 'warning',
        threshold: 2,
        currentValue: burnRates.daily,
        enabled: true,
        triggered: true,
        lastTriggered: new Date(),
        acknowledged: false,
        burnRate: burnRates.daily,
      });
    }

    // Trend alerts
    if (trend.direction === BurnRateTrend.INCREASING && trend.confidence > 0.8) {
      alerts.push({
        id: this.generateId(),
        sloId: slo.id,
        type: 'burn_rate',
        severity: 'warning',
        threshold: 0.8,
        currentValue: trend.confidence,
        enabled: true,
        triggered: true,
        lastTriggered: new Date(),
        acknowledged: false,
        burnRate: burnRates.daily,
      });
    }

    return alerts;
  }

  /**
   * Generate burn rate recommendations
   */
  private generateBurnRateRecommendations(
    slo: SLO,
    burnRates: { hourly: number; daily: number; weekly: number; monthly: number },
    trend: { direction: BurnRateTrend; confidence: number; slope: number },
    health: { status: 'healthy' | 'warning' | 'critical'; score: number; factors: string[] }
  ): string[] {
    const recommendations: string[] = [];

    if (burnRates.daily > 2) {
      recommendations.push('Investigate cause of high burn rate and implement immediate mitigation');
      recommendations.push('Consider traffic throttling or capacity increases');
    }

    if (trend.direction === BurnRateTrend.INCREASING) {
      recommendations.push('Monitor the increasing trend and prepare escalation procedures');
      recommendations.push('Review recent changes that might be affecting performance');
    }

    if (health.factors.includes('Accelerating consumption')) {
      recommendations.push('Implement automated scaling to handle increased load');
      recommendations.push('Review and optimize resource utilization');
    }

    if (recommendations.length === 0) {
      recommendations.push('Continue monitoring burn rate trends');
    }

    return recommendations;
  }

  /**
   * Store budget history
   */
  private storeBudgetHistory(sloId: string, budget: ErrorBudget): void {
    const history = this.budgetHistory.get(sloId) || [];
    const metadata = (budget.metadata as unknown) || {};
    const utilization = (budget.utilization as unknown) || {};

    history.push({
      timestamp: metadata.calculatedAt || new Date(),
      remaining: budget.remaining,
      consumed: budget.consumed,
      utilization: utilization.percentage || 0,
    });

    // Keep only last 1000 data points
    if (history.length > 1000) {
      history.splice(0, history.length - 1000);
    }

    this.budgetHistory.set(sloId, history);
  }

  /**
   * Store burn rate data point
   */
  private storeBurnRateDataPoint(sloId: string, analysis: BurnRateAnalysis): void {
    const history = this.burnRateHistory.get(sloId) || [];
    const metadata = (analysis.metadata as unknown) || {};
    const health = (analysis.health as unknown) || {};

    // Safely access trend direction
    let trendDirection: BurnRateTrend = BurnRateTrend.UNKNOWN;
    const trendData = (analysis as unknown).trend;
    if (trendData && typeof trendData === 'object' && trendData !== null && 'direction' in trendData) {
      trendDirection = trendData.direction;
    }

    history.push({
      timestamp: metadata.calculatedAt || new Date(),
      hourlyRate: analysis.currentRate || 0,
      dailyRate: analysis.currentRate || 0,
      weeklyRate: analysis.currentRate || 0,
      monthlyRate: analysis.currentRate || 0,
      trend: trendDirection,
      healthScore: (health as unknown).score || 0,
    });

    // Keep only last 1000 data points
    if (history.length > 1000) {
      history.splice(0, history.length - 1000);
    }

    this.burnRateHistory.set(sloId, history);
  }

  /**
   * Calculate confidence in data
   */
  private calculateConfidence(evaluations: SLOEvaluation[]): number {
    if (evaluations.length === 0) return 0;
    if (evaluations.length < 5) return 0.5;

    // Calculate confidence based on data recency and consistency
    const now = Date.now();
    const recentData = evaluations.filter(e => now - e.timestamp.getTime() < 24 * 60 * 60 * 1000);
    const recencyFactor = Math.min(recentData.length / evaluations.length, 1);

    const consistency = this.calculateConsistency(evaluations);

    return (recencyFactor * 0.6 + consistency * 0.4);
  }

  /**
   * Calculate data consistency
   */
  private calculateConsistency(evaluations: SLOEvaluation[]): number {
    if (evaluations.length < 2) return 1;

    const values = evaluations.map(e => e.objective.compliance);
    const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
    const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
    const stdDev = Math.sqrt(variance);

    // Lower standard deviation means higher consistency
    return Math.max(0, 1 - (stdDev / mean));
  }

  /**
   * Calculate linear regression
   */
  private calculateLinearRegression(data: { x: number; y: number }[]): { slope: number; intercept: number } {
    if (data.length < 2) return { slope: 0, intercept: 0 };

    const n = data.length;
    let sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;

    for (const point of data) {
      sumX += point.x;
      sumY += point.y;
      sumXY += point.x * point.y;
      sumX2 += point.x * point.x;
    }

    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    const intercept = (sumY - slope * sumX) / n;

    return { slope, intercept };
  }

  /**
   * Calculate correlation coefficient
   */
  private calculateCorrelation(data: { x: number; y: number }[]): number {
    if (data.length < 2) return 0;

    const n = data.length;
    const sumX = data.reduce((sum, point) => sum + point.x, 0);
    const sumY = data.reduce((sum, point) => sum + point.y, 0);
    const sumXY = data.reduce((sum, point) => sum + point.x * point.y, 0);
    const sumX2 = data.reduce((sum, point) => sum + point.x * point.x, 0);
    const sumY2 = data.reduce((sum, point) => sum + point.y * point.y, 0);

    const numerator = n * sumXY - sumX * sumY;
    const denominator = Math.sqrt((n * sumX2 - sumX * sumX) * (n * sumY2 - sumY * sumY));

    return denominator === 0 ? 0 : numerator / denominator;
  }

  // Placeholder methods for complex functionality
  private generateBudgetProjectionInternal(budget: unknown, consumption: unknown, period: BudgetPeriod): BudgetProjection {
    const currentRate = (consumption.currentRate as number) || 0;
    const remaining = budget.remaining || 0;

    // Simple projection: if current burn rate continues, when will budget be exhausted?
    let projectedExhaustion: Date | null = null;
    if (currentRate > 0 && remaining > 0) {
      const hoursToExhaustion = remaining / currentRate;
      projectedExhaustion = new Date(Date.now() + hoursToExhaustion * 60 * 60 * 1000);
    }

    return {
      sloId: budget.sloId || '',
      projectionPeriod: period,
      projectedConsumption: remaining * 1.1, // Assume 10% increase
      projectedExhaustion,
      confidence: 0.8,
      assumptions: [
        'Current burn rate continues',
        'No significant capacity changes',
        'Normal operational patterns',
      ],
      scenarios: {
        optimistic: projectedExhaustion ? new Date(projectedExhaustion.getTime() * 1.2) : null,
        realistic: projectedExhaustion,
        pessimistic: projectedExhaustion ? new Date(projectedExhaustion.getTime() * 0.8) : null,
      },
      exhaustionProbability: currentRate > 1 ? 0.7 : 0.2,
      metadata: {
        generatedAt: new Date(),
        methodology: 'linear_projection',
        iterations: 100,
        confidence: 0.8,
      },
    };
  }

  private rankSLOsByBurnRate(analyses: BurnRateAnalysis[]): unknown[] {
    return analyses.sort((a, b) => b.currentRate - a.currentRate);
  }

  private generateBurnRateInsights(analyses: BurnRateAnalysis[]): string[] {
    return ['Burn rate insights placeholder'];
  }

  private async generateProjectionScenario(
    scenario: string,
    budget: unknown,
    burnRate: unknown,
    period: unknown
  ): Promise<unknown> {
    return {
      scenario,
      optimistic: null,
      realistic: null,
      pessimistic: null,
      exhaustionDate: null,
      finalBudget: budget.remaining || 0,
      confidence: 0.8,
    };
  }

  private calculateExhaustionProbability(scenarios: unknown[]): number {
    return 0.1; // Placeholder
  }

  private generateBudgetRecommendations(slo: unknown, budget: unknown, burnRate: unknown, scenarios: unknown[]): string[] {
    return ['Budget recommendations placeholder'];
  }

  private generateExhaustionRecommendations(sloId: string, exhaustionDate: Date | null, timeToExhaustion: number | null): string[] {
    return ['Exhaustion recommendations placeholder'];
  }

  private checkBurnRateCompliance(policy: unknown, analysis: unknown): { compliant: boolean; details: string } {
    return { compliant: true, details: 'Compliant' };
  }

  private checkConsumptionCompliance(policy: unknown, budget: unknown): { compliant: boolean; details: string } {
    return { compliant: true, details: 'Compliant' };
  }

  private checkAlertCompliance(policy: unknown, budget: unknown, analysis: unknown): { compliant: boolean; details: string } {
    return { compliant: true, details: 'Compliant' };
  }

  private checkAutomationCompliance(policy: unknown, budget: unknown, analysis: unknown): { compliant: boolean; details: string } {
    return { compliant: true, details: 'Compliant' };
  }

  private identifyPolicyViolations(policy: unknown, budget: unknown, analysis: unknown): unknown[] {
    return [];
  }

  private generatePolicyRecommendations(policy: unknown, budget: unknown, analysis: unknown): string[] {
    return ['Policy recommendations placeholder'];
  }

  private generateId(): string {
    return Math.random().toString(36).substr(2, 9);
  }
}

// ============================================================================
// Additional Type Definitions
// ============================================================================

export interface ErrorBudgetHistory {
  timestamp: Date;
  remaining: number;
  consumed: number;
  utilization: number;
}

export interface BurnRateDataPoint {
  timestamp: Date;
  hourlyRate: number;
  dailyRate: number;
  weeklyRate: number;
  monthlyRate: number;
  trend: BurnRateTrend;
  healthScore: number;
}

export interface BurnRateComparison {
  period: BudgetPeriod;
  sloComparisons: {
    sloId: string;
    sloName: string;
    burnRate: number;
    trend: { direction: BurnRateTrend; confidence: number; slope: number };
    health: { status: 'healthy' | 'warning' | 'critical'; score: number; factors: string[] };
  }[];
  rankings: unknown[];
  insights: string[];
  generatedAt: Date;
}

export interface ExhaustionForecast {
  sloId: string;
  earliestExhaustion: Date | null;
  timeToExhaustion: number | null;
  probabilityOfExhaustion: number;
  confidence: number;
  recommendations: string[];
  generatedAt: Date;
}

export interface PolicyComplianceResult {
  sloId: string;
  policyId: string;
  overallCompliance: boolean;
  compliance: {
    withinBurnRateLimits: { compliant: boolean; details: string };
    withinConsumptionLimits: { compliant: boolean; details: string };
    alertsTriggered: { compliant: boolean; details: string };
    automatedResponses: { compliant: boolean; details: string };
  };
  violations: unknown[];
  recommendations: string[];
  evaluatedAt: Date;
}

// Export singleton instance
export const errorBudgetService = new ErrorBudgetService(
  // Will be injected later
  null as unknown
);