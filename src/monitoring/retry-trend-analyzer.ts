/**
 * Retry Budget Trend Analyzer
 *
 * Advanced historical tracking and trend analysis system for retry patterns,
 * circuit breaker behavior, and SLO compliance. Provides predictive analytics,
 * anomaly detection, and comprehensive reporting capabilities.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { EventEmitter } from 'events';
import { logger } from '@/utils/logger.js';
import {
  retryBudgetMonitor,
  type RetryBudgetMetrics,
  type RetryConsumptionEvent
} from './retry-budget-monitor.js';
import {
  circuitBreakerMonitor,
  type CircuitBreakerHealthStatus,
  type CircuitBreakerEvent
} from './circuit-breaker-monitor.js';

/**
 * Time window for trend analysis
 */
export enum AnalysisWindow {
  LAST_HOUR = '1h',
  LAST_6_HOURS = '6h',
  LAST_24_HOURS = '24h',
  LAST_7_DAYS = '7d',
  LAST_30_DAYS = '30d',
  LAST_QUARTER = '90d',
}

/**
 * Trend direction
 */
export enum TrendDirection {
  IMPROVING = 'improving',
  DEGRADING = 'degrading',
  STABLE = 'stable',
  UNKNOWN = 'unknown',
}

/**
 * Anomaly detection result
 */
export interface AnomalyDetection {
  timestamp: Date;
  serviceName: string;
  metric: string;
  anomalyType: 'spike' | 'drop' | 'pattern_change' | 'unusual_variance';
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number; // 0-1
  expectedValue: number;
  actualValue: number;
  deviationPercent: number;
  description: string;
  potentialCauses: string[];
}

/**
 * Trend analysis result
 */
export interface TrendAnalysis {
  serviceName: string;
  metric: string;
  window: AnalysisWindow;
  direction: TrendDirection;
  strength: number; // 0-1, how strong the trend is
  slope: number; // rate of change
  correlation: number; // correlation coefficient
  seasonality: {
    detected: boolean;
    period?: number; // in hours/days
    strength?: number;
  };
  forecast: {
    nextHour: number;
    nextDay: number;
    nextWeek: number;
    confidence: number;
  };
  dataPoints: Array<{
    timestamp: Date;
    value: number;
  }>;
}

/**
 * Comparative analysis result
 */
export interface ComparativeAnalysis {
  serviceName: string;
  comparisonPeriod: AnalysisWindow;
  baselinePeriod: AnalysisWindow;
  metrics: {
    [metricName: string]: {
      current: number;
      baseline: number;
      changePercent: number;
      significance: 'insignificant' | 'minor' | 'moderate' | 'major';
      trend: TrendDirection;
    };
  };
  overallHealth: {
    current: number; // 0-100 health score
    baseline: number;
    changePercent: number;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
  };
  recommendations: string[];
}

/**
 * Predictive analysis result
 */
export interface PredictiveAnalysis {
  serviceName: string;
  predictionType: 'budget_exhaustion' | 'slo_violation' | 'circuit_failure' | 'performance_degradation';
  timeToEvent: number; // hours until predicted event
  confidence: number; // 0-1
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  contributingFactors: Array<{
    factor: string;
    impact: number; // 0-1
    trend: TrendDirection;
  }>;
  mitigationStrategies: string[];
  probability: {
    nextHour: number;
    nextDay: number;
    nextWeek: number;
  };
}

/**
 * Pattern detection result
 */
export interface PatternDetection {
  serviceName: string;
  patternType: 'daily' | 'weekly' | 'business_hours' | 'incident_related' | 'load_related';
  description: string;
  confidence: number;
  schedule: {
    startTime?: string; // HH:MM
    endTime?: string; // HH:MM
    daysOfWeek?: number[]; // 0-6 (Sunday-Saturday)
  };
  impact: {
    averageIncrease: number; // percentage
    peakIncrease: number; // percentage
    duration: number; // hours
  };
}

/**
 * Trend analyzer configuration
 */
export interface RetryTrendAnalyzerConfig {
  // Data retention
  retention: {
    rawEventsDays: number;
    hourlyAggregationDays: number;
    dailyAggregationDays: number;
  };

  // Analysis settings
  analysis: {
    minDataPoints: number;
    trendStrengthThreshold: number;
    anomalySensitivity: number;
    forecastHorizonDays: number;
  };

  // Pattern detection
  patterns: {
    enabled: boolean;
    minConfidence: number;
    minDuration: number; // hours
  };

  // Anomaly detection
  anomalyDetection: {
    enabled: boolean;
    algorithm: 'statistical' | 'ml' | 'hybrid';
    sensitivity: number;
    minConfidence: number;
  };

  // Performance
  performance: {
    batchSize: number;
    processingIntervalMinutes: number;
    cacheEnabled: boolean;
    cacheTtlMinutes: number;
  };
}

/**
 * Historical data point
 */
interface HistoricalDataPoint {
  timestamp: Date;
  serviceName: string;
  metrics: {
    [metricName: string]: number;
  };
}

/**
 * Aggregated data point
 */
interface AggregatedDataPoint {
  timestamp: Date;
  serviceName: string;
  period: 'hour' | 'day';
  metrics: {
    [metricName: string]: {
      min: number;
      max: number;
      avg: number;
      sum: number;
      count: number;
    };
  };
}

/**
 * Comprehensive Retry Budget Trend Analyzer
 */
export class RetryTrendAnalyzer extends EventEmitter {
  private config: RetryTrendAnalyzerConfig;
  private isRunning = false;
  private startTime: number;

  // Data storage
  private rawData: Map<string, HistoricalDataPoint[]> = new Map();
  private hourlyData: Map<string, AggregatedDataPoint[]> = new Map();
  private dailyData: Map<string, AggregatedDataPoint[]> = new Map();

  // Analysis cache
  private trendCache: Map<string, { analysis: TrendAnalysis; timestamp: number }> = new Map();
  private anomalyCache: Map<string, { anomalies: AnomalyDetection[]; timestamp: number }> = new Map();
  private patternCache: Map<string, { patterns: PatternDetection[]; timestamp: number }> = new Map();

  // Processing
  private processingInterval: NodeJS.Timeout | null = null;

  constructor(config?: Partial<RetryTrendAnalyzerConfig>) {
    super();

    this.config = {
      retention: {
        rawEventsDays: 7,
        hourlyAggregationDays: 30,
        dailyAggregationDays: 365,
      },
      analysis: {
        minDataPoints: 10,
        trendStrengthThreshold: 0.3,
        anomalySensitivity: 0.7,
        forecastHorizonDays: 7,
      },
      patterns: {
        enabled: true,
        minConfidence: 0.7,
        minDuration: 2,
      },
      anomalyDetection: {
        enabled: true,
        algorithm: 'hybrid',
        sensitivity: 0.8,
        minConfidence: 0.6,
      },
      performance: {
        batchSize: 1000,
        processingIntervalMinutes: 15,
        cacheEnabled: true,
        cacheTtlMinutes: 30,
      },
      ...config,
    };

    this.startTime = Date.now();
    this.setupEventListeners();
  }

  /**
   * Start the trend analyzer
   */
  start(): void {
    if (this.isRunning) {
      logger.warn('Retry trend analyzer is already running');
      return;
    }

    this.isRunning = true;

    // Start processing interval
    this.processingInterval = setInterval(
      () => this.processHistoricalData(),
      this.config.performance.processingIntervalMinutes * 60 * 1000
    );

    // Perform initial processing
    this.processHistoricalData();

    logger.info(
      {
        processingInterval: this.config.performance.processingIntervalMinutes,
        retentionDays: this.config.retention.rawEventsDays,
      },
      'Retry trend analyzer started'
    );

    this.emit('started');
  }

  /**
   * Stop the trend analyzer
   */
  stop(): void {
    if (!this.isRunning) {
      logger.warn('Retry trend analyzer is not running');
      return;
    }

    this.isRunning = false;

    if (this.processingInterval) {
      clearInterval(this.processingInterval);
      this.processingInterval = null;
    }

    logger.info('Retry trend analyzer stopped');
    this.emit('stopped');
  }

  /**
   * Analyze trends for a service and metric
   */
  analyzeTrends(serviceName: string, metric: string, window: AnalysisWindow): TrendAnalysis | null {
    const cacheKey = `${serviceName}:${metric}:${window}`;

    if (this.config.performance.cacheEnabled) {
      const cached = this.trendCache.get(cacheKey);
      if (cached && Date.now() - cached.timestamp < this.config.performance.cacheTtlMinutes * 60 * 1000) {
        return cached.analysis;
      }
    }

    const dataPoints = this.getDataPointsForWindow(serviceName, metric, window);
    if (dataPoints.length < this.config.analysis.minDataPoints) {
      return null;
    }

    const analysis = this.performTrendAnalysis(serviceName, metric, window, dataPoints);

    if (this.config.performance.cacheEnabled) {
      this.trendCache.set(cacheKey, { analysis, timestamp: Date.now() });
    }

    return analysis;
  }

  /**
   * Detect anomalies for a service
   */
  detectAnomalies(serviceName: string, hours: number = 24): AnomalyDetection[] {
    const cacheKey = `${serviceName}:anomalies:${hours}`;

    if (this.config.performance.cacheEnabled) {
      const cached = this.anomalyCache.get(cacheKey);
      if (cached && Date.now() - cached.timestamp < this.config.performance.cacheTtlMinutes * 60 * 1000) {
        return cached.anomalies;
      }
    }

    if (!this.config.anomalyDetection.enabled) {
      return [];
    }

    const anomalies = this.performAnomalyDetection(serviceName, hours);

    if (this.config.performance.cacheEnabled) {
      this.anomalyCache.set(cacheKey, { anomalies, timestamp: Date.now() });
    }

    return anomalies;
  }

  /**
   * Detect patterns for a service
   */
  detectPatterns(serviceName: string): PatternDetection[] {
    const cacheKey = `${serviceName}:patterns`;

    if (this.config.performance.cacheEnabled) {
      const cached = this.patternCache.get(cacheKey);
      if (cached && Date.now() - cached.timestamp < this.config.performance.cacheTtlMinutes * 60 * 1000) {
        return cached.patterns;
      }
    }

    if (!this.config.patterns.enabled) {
      return [];
    }

    const patterns = this.performPatternDetection(serviceName);

    if (this.config.performance.cacheEnabled) {
      this.patternCache.set(cacheKey, { patterns, timestamp: Date.now() });
    }

    return patterns;
  }

  /**
   * Perform comparative analysis
   */
  performComparativeAnalysis(
    serviceName: string,
    comparisonPeriod: AnalysisWindow,
    baselinePeriod: AnalysisWindow
  ): ComparativeAnalysis | null {
    const comparisonData = this.getDataPointsForWindow(serviceName, 'budget_utilization_percent', comparisonPeriod);
    const baselineData = this.getDataPointsForWindow(serviceName, 'budget_utilization_percent', baselinePeriod);

    if (comparisonData.length < 5 || baselineData.length < 5) {
      return null;
    }

    const currentAvg = this.calculateAverage(comparisonData.map(d => d.value));
    const baselineAvg = this.calculateAverage(baselineData.map(d => d.value));
    const changePercent = baselineAvg > 0 ? ((currentAvg - baselineAvg) / baselineAvg) * 100 : 0;

    const metrics = {
      budget_utilization_percent: {
        current: currentAvg,
        baseline: baselineAvg,
        changePercent,
        significance: this.calculateSignificance(Math.abs(changePercent)),
        trend: this.determineTrendDirection(comparisonData),
      },
    };

    const overallHealth = {
      current: this.calculateHealthScore(serviceName, comparisonData),
      baseline: this.calculateHealthScore(serviceName, baselineData),
      changePercent: 0,
      riskLevel: this.determineRiskLevel(currentAvg),
    };

    overallHealth.changePercent = overallHealth.baseline > 0
      ? ((overallHealth.current - overallHealth.baseline) / overallHealth.baseline) * 100
      : 0;

    const recommendations = this.generateRecommendations(serviceName, metrics, overallHealth);

    return {
      serviceName,
      comparisonPeriod,
      baselinePeriod,
      metrics,
      overallHealth,
      recommendations,
    };
  }

  /**
   * Perform predictive analysis
   */
  performPredictiveAnalysis(serviceName: string): PredictiveAnalysis[] {
    const predictions: PredictiveAnalysis[] = [];

    // Budget exhaustion prediction
    const budgetPrediction = this.predictBudgetExhaustion(serviceName);
    if (budgetPrediction) {
      predictions.push(budgetPrediction);
    }

    // SLO violation prediction
    const sloPrediction = this.predictSLOViolation(serviceName);
    if (sloPrediction) {
      predictions.push(sloPrediction);
    }

    // Circuit failure prediction
    const circuitPrediction = this.predictCircuitFailure(serviceName);
    if (circuitPrediction) {
      predictions.push(circuitPrediction);
    }

    return predictions;
  }

  /**
   * Get comprehensive report for a service
   */
  getServiceReport(serviceName: string, window: AnalysisWindow = AnalysisWindow.LAST_7_DAYS): {
    serviceName: string;
    window: AnalysisWindow;
    timestamp: Date;
    summary: {
      overallHealth: number;
      trend: TrendDirection;
      riskLevel: 'low' | 'medium' | 'high' | 'critical';
      anomalyCount: number;
      patternCount: number;
    };
    trends: TrendAnalysis[];
    anomalies: AnomalyDetection[];
    patterns: PatternDetection[];
    predictions: PredictiveAnalysis[];
    comparison: ComparativeAnalysis | null;
    recommendations: string[];
  } {
    const timestamp = new Date();
    const trends: TrendAnalysis[] = [];
    const anomalies = this.detectAnomalies(serviceName);
    const patterns = this.detectPatterns(serviceName);
    const predictions = this.performPredictiveAnalysis(serviceName);

    // Analyze key metrics
    const keyMetrics = [
      'budget_utilization_percent',
      'retry_rate_percent',
      'success_rate_variance',
      'response_time_p95',
    ];

    for (const metric of keyMetrics) {
      const trend = this.analyzeTrends(serviceName, metric, window);
      if (trend) {
        trends.push(trend);
      }
    }

    // Calculate overall health and trend
    const overallHealth = this.calculateOverallHealth(serviceName, window);
    const overallTrend = this.calculateOverallTrend(trends);
    const riskLevel = this.determineRiskLevel(overallHealth);

    // Generate comparison with previous period
    const comparison = this.performComparativeAnalysis(
      serviceName,
      window,
      this.getPreviousWindow(window)
    );

    // Generate recommendations
    const recommendations = this.generateServiceRecommendations(
      serviceName,
      trends,
      anomalies,
      patterns,
      predictions
    );

    return {
      serviceName,
      window,
      timestamp,
      summary: {
        overallHealth,
        trend: overallTrend,
        riskLevel,
        anomalyCount: anomalies.length,
        patternCount: patterns.length,
      },
      trends,
      anomalies,
      patterns,
      predictions,
      comparison,
      recommendations,
    };
  }

  /**
   * Process historical data
   */
  private processHistoricalData(): void {
    try {
      // Get current metrics
      const retryMetrics = retryBudgetMonitor.getAllMetrics();
      const circuitMetrics = circuitBreakerMonitor.getAllHealthStatuses();

      // Store current data points
      for (const [serviceName, retryMetric] of retryMetrics) {
        this.storeDataPoint(serviceName, retryMetric, circuitMetrics.get(serviceName));
      }

      // Perform aggregations
      this.performHourlyAggregation();
      this.performDailyAggregation();

      // Clean up old data
      this.cleanupOldData();

      // Clear cache periodically
      if (Math.random() < 0.1) { // 10% chance each cycle
        this.cleanupCache();
      }

      this.emit('data_processed', { timestamp: new Date() });
    } catch (error) {
      logger.error({ error }, 'Failed to process historical data');
    }
  }

  /**
   * Store data point
   */
  private storeDataPoint(
    serviceName: string,
    retryMetrics: RetryBudgetMetrics,
    circuitMetrics?: CircuitBreakerHealthStatus
  ): void {
    const dataPoint: HistoricalDataPoint = {
      timestamp: new Date(),
      serviceName,
      metrics: {
        budget_utilization_percent: retryMetrics.current.budgetUtilizationPercent,
        retry_rate_percent: retryMetrics.current.retryRatePercent,
        success_rate_variance: retryMetrics.slo.successRateVariance,
        response_time_p95: retryMetrics.performance.responseTimeP95,
        remaining_retries_hour: retryMetrics.current.budgetRemainingHour,
        slo_compliance: retryMetrics.slo.overallCompliance ? 1 : 0,
        circuit_failure_rate: circuitMetrics?.metrics.failureRate || 0,
        circuit_consecutive_failures: circuitMetrics?.metrics.consecutiveFailures || 0,
      },
    };

    if (!this.rawData.has(serviceName)) {
      this.rawData.set(serviceName, []);
    }

    const serviceData = this.rawData.get(serviceName)!;
    serviceData.push(dataPoint);

    // Limit raw data size
    const maxSize = this.config.retention.rawEventsDays * 24 * 60; // Assuming 1-minute intervals
    if (serviceData.length > maxSize) {
      serviceData.splice(0, serviceData.length - maxSize);
    }
  }

  /**
   * Perform hourly aggregation
   */
  private performHourlyAggregation(): void {
    // Implementation would aggregate raw data into hourly buckets
    // For now, this is a placeholder
  }

  /**
   * Perform daily aggregation
   */
  private performDailyAggregation(): void {
    // Implementation would aggregate hourly data into daily buckets
    // For now, this is a placeholder
  }

  /**
   * Clean up old data
   */
  private cleanupOldData(): void {
    const now = Date.now();

    // Clean up raw data
    const rawCutoff = now - (this.config.retention.rawEventsDays * 24 * 60 * 60 * 1000);
    for (const [serviceName, data] of this.rawData) {
      const filtered = data.filter(point => point.timestamp.getTime() >= rawCutoff);
      this.rawData.set(serviceName, filtered);
    }

    // Clean up aggregated data
    // Similar cleanup for hourly and daily data
  }

  /**
   * Clean up cache
   */
  private cleanupCache(): void {
    const cutoff = Date.now() - (this.config.performance.cacheTtlMinutes * 60 * 1000);

    for (const [key, cached] of this.trendCache) {
      if (cached.timestamp < cutoff) {
        this.trendCache.delete(key);
      }
    }

    for (const [key, cached] of this.anomalyCache) {
      if (cached.timestamp < cutoff) {
        this.anomalyCache.delete(key);
      }
    }

    for (const [key, cached] of this.patternCache) {
      if (cached.timestamp < cutoff) {
        this.patternCache.delete(key);
      }
    }
  }

  /**
   * Get data points for time window
   */
  private getDataPointsForWindow(serviceName: string, metric: string, window: AnalysisWindow): Array<{ timestamp: Date; value: number }> {
    const data = this.rawData.get(serviceName) || [];
    const now = Date.now();
    let windowMs: number;

    switch (window) {
      case AnalysisWindow.LAST_HOUR:
        windowMs = 60 * 60 * 1000;
        break;
      case AnalysisWindow.LAST_6_HOURS:
        windowMs = 6 * 60 * 60 * 1000;
        break;
      case AnalysisWindow.LAST_24_HOURS:
        windowMs = 24 * 60 * 60 * 1000;
        break;
      case AnalysisWindow.LAST_7_DAYS:
        windowMs = 7 * 24 * 60 * 60 * 1000;
        break;
      case AnalysisWindow.LAST_30_DAYS:
        windowMs = 30 * 24 * 60 * 60 * 1000;
        break;
      case AnalysisWindow.LAST_QUARTER:
        windowMs = 90 * 24 * 60 * 60 * 1000;
        break;
    }

    const cutoff = now - windowMs;
    return data
      .filter(point => point.timestamp.getTime() >= cutoff && point.metrics[metric] !== undefined)
      .map(point => ({
        timestamp: point.timestamp,
        value: point.metrics[metric]!,
      }))
      .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }

  /**
   * Perform trend analysis
   */
  private performTrendAnalysis(
    serviceName: string,
    metric: string,
    window: AnalysisWindow,
    dataPoints: Array<{ timestamp: Date; value: number }>
  ): TrendAnalysis {
    // Calculate linear regression
    const regression = this.calculateLinearRegression(dataPoints);

    // Determine trend direction and strength
    const direction = this.determineTrendDirection(dataPoints);
    const strength = Math.abs(regression.slope) * this.config.analysis.trendStrengthThreshold;

    // Detect seasonality
    const seasonality = this.detectSeasonality(dataPoints);

    // Generate forecast
    const forecast = this.generateForecast(dataPoints, regression);

    return {
      serviceName,
      metric,
      window,
      direction,
      strength: Math.min(1, strength),
      slope: regression.slope,
      correlation: regression.correlation,
      seasonality,
      forecast,
      dataPoints,
    };
  }

  /**
   * Perform anomaly detection
   */
  private performAnomalyDetection(serviceName: string, hours: number): AnomalyDetection[] {
    const anomalies: AnomalyDetection[] = [];
    const data = this.rawData.get(serviceName) || [];
    const cutoff = Date.now() - (hours * 60 * 60 * 1000);
    const recentData = data.filter(point => point.timestamp.getTime() >= cutoff);

    for (const metric of Object.keys(recentData[0]?.metrics || {})) {
      const values = recentData.map(point => point.metrics[metric]).filter(v => v !== undefined);
      if (values.length < 10) continue;

      const metricAnomalies = this.detectMetricAnomalies(serviceName, metric, recentData);
      anomalies.push(...metricAnomalies);
    }

    return anomalies.sort((a, b) => b.confidence - a.confidence);
  }

  /**
   * Detect anomalies for a specific metric
   */
  private detectMetricAnomalies(
    serviceName: string,
    metric: string,
    data: HistoricalDataPoint[]
  ): AnomalyDetection[] {
    const anomalies: AnomalyDetection[] = [];
    const values = data.map(point => point.metrics[metric]).filter(v => v !== undefined) as number[];

    if (values.length < 10) return anomalies;

    const stats = this.calculateStatistics(values);
    const threshold = stats.stdDev * this.config.anomalyDetection.sensitivity;

    for (let i = 0; i < data.length; i++) {
      const point = data[i];
      const value = point.metrics[metric];

      if (value === undefined) continue;

      const deviation = Math.abs(value - stats.mean);
      const deviationPercent = (deviation / stats.mean) * 100;

      if (deviation > threshold && deviationPercent > 20) {
        const anomalyType = value > stats.mean + threshold ? 'spike' : 'drop';
        const severity = this.determineAnomalySeverity(deviationPercent);
        const confidence = Math.min(1, deviation / (stats.stdDev * 3));

        anomalies.push({
          timestamp: point.timestamp,
          serviceName,
          metric,
          anomalyType,
          severity,
          confidence,
          expectedValue: stats.mean,
          actualValue: value,
          deviationPercent,
          description: `${metric} ${anomalyType === 'spike' ? 'spiked' : 'dropped'} to ${value.toFixed(2)} (expected: ${stats.mean.toFixed(2)})`,
          potentialCauses: this.generatePotentialCauses(metric, anomalyType, point.timestamp),
        });
      }
    }

    return anomalies;
  }

  /**
   * Perform pattern detection
   */
  private performPatternDetection(serviceName: string): PatternDetection[] {
    const patterns: PatternDetection[] = [];
    const data = this.rawData.get(serviceName) || [];

    if (data.length < 168) return patterns; // Need at least 1 week of data

    // Detect daily patterns
    const dailyPattern = this.detectDailyPattern(serviceName, data);
    if (dailyPattern) patterns.push(dailyPattern);

    // Detect weekly patterns
    const weeklyPattern = this.detectWeeklyPattern(serviceName, data);
    if (weeklyPattern) patterns.push(weeklyPattern);

    // Detect business hours patterns
    const businessHoursPattern = this.detectBusinessHoursPattern(serviceName, data);
    if (businessHoursPattern) patterns.push(businessHoursPattern);

    return patterns.filter(p => p.confidence >= this.config.patterns.minConfidence);
  }

  /**
   * Detect daily pattern
   */
  private detectDailyPattern(serviceName: string, data: HistoricalDataPoint[]): PatternDetection | null {
    // Group data by hour of day
    const hourlyData = new Map<number, number[]>();

    for (const point of data) {
      const hour = point.timestamp.getHours();
      const utilization = point.metrics.budget_utilization_percent || 0;

      if (!hourlyData.has(hour)) {
        hourlyData.set(hour, []);
      }
      hourlyData.get(hour)!.push(utilization);
    }

    // Calculate hourly averages
    const hourlyAverages = Array.from(hourlyData.entries())
      .map(([hour, values]) => ({
        hour,
        avg: values.reduce((sum, v) => sum + v, 0) / values.length,
      }))
      .sort((a, b) => a.hour - b.hour);

    // Detect pattern (e.g., higher usage during certain hours)
    const maxAvg = Math.max(...hourlyAverages.map(h => h.avg));
    const minAvg = Math.min(...hourlyAverages.map(h => h.avg));
    const variance = maxAvg - minAvg;

    if (variance < 10) return null; // No significant pattern

    // Find peak hours
    const peakHours = hourlyAverages
      .filter(h => h.avg > (maxAvg + minAvg) / 2)
      .map(h => h.hour);

    return {
      serviceName,
      patternType: 'daily',
      description: `Higher retry budget utilization during hours: ${peakHours.join(', ')}`,
      confidence: Math.min(1, variance / 50),
      schedule: {
        startTime: peakHours[0] ? `${peakHours[0].toString().padStart(2, '0')}:00` : undefined,
        endTime: peakHours[peakHours.length - 1] ? `${(peakHours[peakHours.length - 1] + 1).toString().padStart(2, '0')}:00` : undefined,
      },
      impact: {
        averageIncrease: variance / minAvg * 100,
        peakIncrease: (maxAvg - minAvg) / minAvg * 100,
        duration: peakHours.length,
      },
    };
  }

  /**
   * Detect weekly pattern
   */
  private detectWeeklyPattern(serviceName: string, data: HistoricalDataPoint[]): PatternDetection | null {
    // Similar to daily pattern but by day of week
    // Implementation would be similar to detectDailyPattern
    return null;
  }

  /**
   * Detect business hours pattern
   */
  private detectBusinessHoursPattern(serviceName: string, data: HistoricalDataPoint[]): PatternDetection | null {
    // Compare business hours (9-17, Mon-Fri) vs non-business hours
    const businessHours = data.filter(point => {
      const hour = point.timestamp.getHours();
      const day = point.timestamp.getDay();
      return day >= 1 && day <= 5 && hour >= 9 && hour <= 17;
    });

    const nonBusinessHours = data.filter(point => !businessHours.includes(point));

    if (businessHours.length < 10 || nonBusinessHours.length < 10) return null;

    const businessAvg = this.calculateAverage(businessHours.map(p => p.metrics.budget_utilization_percent || 0));
    const nonBusinessAvg = this.calculateAverage(nonBusinessHours.map(p => p.metrics.budget_utilization_percent || 0));
    const difference = Math.abs(businessAvg - nonBusinessAvg);

    if (difference < 5) return null; // No significant difference

    const higherDuringBusiness = businessAvg > nonBusinessAvg;

    return {
      serviceName,
      patternType: 'business_hours',
      description: `Retry budget utilization is ${higherDuringBusiness ? 'higher' : 'lower'} during business hours`,
      confidence: Math.min(1, difference / 30),
      schedule: {
        startTime: '09:00',
        endTime: '17:00',
        daysOfWeek: [1, 2, 3, 4, 5], // Monday-Friday
      },
      impact: {
        averageIncrease: higherDuringBusiness ? (businessAvg / nonBusinessAvg - 1) * 100 : (nonBusinessAvg / businessAvg - 1) * 100,
        peakIncrease: difference,
        duration: 8, // 8 business hours
      },
    };
  }

  /**
   * Predict budget exhaustion
   */
  private predictBudgetExhaustion(serviceName: string): PredictiveAnalysis | null {
    const trend = this.analyzeTrends(serviceName, 'budget_utilization_percent', AnalysisWindow.LAST_24_HOURS);
    if (!trend || trend.direction !== TrendDirection.DEGRADING) return null;

    const currentMetrics = retryBudgetMonitor.getMetrics(serviceName);
    if (!currentMetrics) return null;

    const currentUtilization = currentMetrics.current.budgetUtilizationPercent;
    const hoursToExhaustion = (100 - currentUtilization) / (trend.slope * 60); // slope is per minute

    if (hoursToExhaustion <= 0 || hoursToExhaustion > 168) return null; // Only predict within next week

    const confidence = Math.min(1, trend.strength * 0.8);
    const riskLevel = hoursToExhaustion < 2 ? 'critical' :
                     hoursToExhaustion < 6 ? 'high' :
                     hoursToExhaustion < 24 ? 'medium' : 'low';

    return {
      serviceName,
      predictionType: 'budget_exhaustion',
      timeToEvent: hoursToExhaustion,
      confidence,
      riskLevel,
      contributingFactors: [
        {
          factor: 'Increasing budget utilization trend',
          impact: trend.strength,
          trend: trend.direction,
        },
      ],
      mitigationStrategies: [
        'Reduce retry rate for non-critical operations',
        'Investigate root cause of increasing retries',
        'Consider increasing retry budget limits',
      ],
      probability: {
        nextHour: Math.min(1, hoursToExhaustion < 1 ? confidence : 0),
        nextDay: Math.min(1, hoursToExhaustion < 24 ? confidence * 0.8 : 0),
        nextWeek: Math.min(1, confidence * 0.6),
      },
    };
  }

  /**
   * Predict SLO violation
   */
  private predictSLOViolation(serviceName: string): PredictiveAnalysis | null {
    const trends = [
      this.analyzeTrends(serviceName, 'success_rate_variance', AnalysisWindow.LAST_6_HOURS),
      this.analyzeTrends(serviceName, 'response_time_p95', AnalysisWindow.LAST_6_HOURS),
    ].filter(t => t !== null) as TrendAnalysis[];

    const degradingTrends = trends.filter(t => t.direction === TrendDirection.DEGRADING);
    if (degradingTrends.length === 0) return null;

    const currentMetrics = retryBudgetMonitor.getMetrics(serviceName);
    if (!currentMetrics || currentMetrics.slo.overallCompliance) return null;

    const avgStrength = degradingTrends.reduce((sum, t) => sum + t.strength, 0) / degradingTrends.length;
    const confidence = Math.min(1, avgStrength * 0.7);
    const riskLevel = avgStrength > 0.7 ? 'critical' : avgStrength > 0.4 ? 'high' : 'medium';

    return {
      serviceName,
      predictionType: 'slo_violation',
      timeToEvent: 2, // SLO violations are typically imminent
      confidence,
      riskLevel,
      contributingFactors: degradingTrends.map(t => ({
        factor: `Degrading ${t.metric}`,
        impact: t.strength,
        trend: t.direction,
      })),
      mitigationStrategies: [
        'Investigate performance degradation causes',
        'Implement emergency scaling measures',
        'Reduce non-essential load',
      ],
      probability: {
        nextHour: confidence,
        nextDay: confidence * 0.9,
        nextWeek: confidence * 0.7,
      },
    };
  }

  /**
   * Predict circuit failure
   */
  private predictCircuitFailure(serviceName: string): PredictiveAnalysis | null {
    const circuitMetrics = circuitBreakerMonitor.getHealthStatus(serviceName);
    if (!circuitMetrics || circuitMetrics.state === 'open') return null;

    const failureTrend = this.analyzeTrends(serviceName, 'circuit_failure_rate', AnalysisWindow.LAST_HOUR);
    if (!failureTrend || failureTrend.direction !== TrendDirection.DEGRADING) return null;

    const consecutiveFailures = circuitMetrics.metrics.consecutiveFailures;
    const confidence = Math.min(1, (failureTrend.strength + consecutiveFailures / 10) * 0.8);
    const riskLevel = consecutiveFailures > 5 ? 'critical' :
                     consecutiveFailures > 3 ? 'high' :
                     consecutiveFailures > 1 ? 'medium' : 'low';

    return {
      serviceName,
      predictionType: 'circuit_failure',
      timeToEvent: consecutiveFailures > 3 ? 0.5 : consecutiveFailures > 1 ? 2 : 6,
      confidence,
      riskLevel,
      contributingFactors: [
        {
          factor: 'Increasing failure rate',
          impact: failureTrend.strength,
          trend: failureTrend.direction,
        },
        {
          factor: `Consecutive failures: ${consecutiveFailures}`,
          impact: Math.min(1, consecutiveFailures / 10),
          trend: TrendDirection.DEGRADING,
        },
      ],
      mitigationStrategies: [
        'Investigate service health and connectivity',
        'Check for upstream dependencies',
        'Consider manual circuit breaker reset',
      ],
      probability: {
        nextHour: confidence,
        nextDay: confidence * 0.8,
        nextWeek: confidence * 0.5,
      },
    };
  }

  // Helper methods
  private calculateLinearRegression(data: Array<{ timestamp: Date; value: number }>): { slope: number; correlation: number } {
    if (data.length < 2) return { slope: 0, correlation: 0 };

    const n = data.length;
    const x = data.map((_, i) => i);
    const y = data.map(d => d.value);

    const sumX = x.reduce((sum, val) => sum + val, 0);
    const sumY = y.reduce((sum, val) => sum + val, 0);
    const sumXY = x.reduce((sum, val, i) => sum + val * y[i], 0);
    const sumXX = x.reduce((sum, val) => sum + val * val, 0);
    const sumYY = y.reduce((sum, val) => sum + val * val, 0);

    const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);
    const correlation = (n * sumXY - sumX * sumY) /
      Math.sqrt((n * sumXX - sumX * sumX) * (n * sumYY - sumY * sumY));

    return { slope, correlation: isNaN(correlation) ? 0 : correlation };
  }

  private determineTrendDirection(data: Array<{ timestamp: Date; value: number }>): TrendDirection {
    if (data.length < 3) return TrendDirection.UNKNOWN;

    const regression = this.calculateLinearRegression(data);
    if (Math.abs(regression.slope) < 0.01) return TrendDirection.STABLE;
    return regression.slope > 0 ? TrendDirection.IMPROVING : TrendDirection.DEGRADING;
  }

  private detectSeasonality(data: Array<{ timestamp: Date; value: number }>): { detected: boolean; period?: number; strength?: number } {
    // Simplified seasonality detection
    // In a real implementation, this would use more sophisticated algorithms
    return { detected: false };
  }

  private generateForecast(data: Array<{ timestamp: Date; value: number }>, regression: { slope: number; correlation: number }): { nextHour: number; nextDay: number; nextWeek: number; confidence: number } {
    const lastValue = data[data.length - 1].value;
    const confidence = Math.abs(regression.correlation);

    return {
      nextHour: lastValue + (regression.slope * 60),
      nextDay: lastValue + (regression.slope * 60 * 24),
      nextWeek: lastValue + (regression.slope * 60 * 24 * 7),
      confidence,
    };
  }

  private calculateStatistics(values: number[]): { mean: number; stdDev: number; min: number; max: number } {
    const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
    const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
    const stdDev = Math.sqrt(variance);
    const min = Math.min(...values);
    const max = Math.max(...values);

    return { mean, stdDev, min, max };
  }

  private determineAnomalySeverity(deviationPercent: number): 'low' | 'medium' | 'high' | 'critical' {
    if (deviationPercent > 100) return 'critical';
    if (deviationPercent > 50) return 'high';
    if (deviationPercent > 25) return 'medium';
    return 'low';
  }

  private generatePotentialCauses(metric: string, anomalyType: 'spike' | 'drop', timestamp: Date): string[] {
    const hour = timestamp.getHours();
    const isBusinessHours = hour >= 9 && hour <= 17;

    const causes = [
      'Unusual traffic pattern',
      'Service dependency issues',
      'Network connectivity problems',
      'Configuration changes',
    ];

    if (isBusinessHours) {
      causes.push('Peak business hours activity');
    }

    if (anomalyType === 'spike') {
      causes.push('Load spike or traffic surge');
      causes.push('Cascading failure effects');
    } else {
      causes.push('Service recovery or load reduction');
      causes.push('Successful fix implementation');
    }

    return causes.slice(0, 3);
  }

  private calculateAverage(values: number[]): number {
    return values.length > 0 ? values.reduce((sum, val) => sum + val, 0) / values.length : 0;
  }

  private calculateSignificance(changePercent: number): 'insignificant' | 'minor' | 'moderate' | 'major' {
    if (Math.abs(changePercent) < 5) return 'insignificant';
    if (Math.abs(changePercent) < 15) return 'minor';
    if (Math.abs(changePercent) < 30) return 'moderate';
    return 'major';
  }

  private determineRiskLevel(value: number): 'low' | 'medium' | 'high' | 'critical' {
    if (value < 50) return 'low';
    if (value < 70) return 'medium';
    if (value < 85) return 'high';
    return 'critical';
  }

  private calculateHealthScore(serviceName: string, data: Array<{ timestamp: Date; value: number }>): number {
    if (data.length === 0) return 100;

    const values = data.map(d => d.value);
    const avg = this.calculateAverage(values);

    // Lower utilization is better for health score
    return Math.max(0, Math.min(100, 100 - avg));
  }

  private calculateOverallHealth(serviceName: string, window: AnalysisWindow): number {
    const utilizationTrend = this.analyzeTrends(serviceName, 'budget_utilization_percent', window);
    const retryRateTrend = this.analyzeTrends(serviceName, 'retry_rate_percent', window);
    const sloTrend = this.analyzeTrends(serviceName, 'slo_compliance', window);

    let healthScore = 100;

    if (utilizationTrend) {
      if (utilizationTrend.direction === TrendDirection.DEGRADING) {
        healthScore -= utilizationTrend.strength * 30;
      } else if (utilizationTrend.direction === TrendDirection.IMPROVING) {
        healthScore += utilizationTrend.strength * 10;
      }
    }

    if (retryRateTrend && retryRateTrend.direction === TrendDirection.DEGRADING) {
      healthScore -= retryRateTrend.strength * 20;
    }

    if (sloTrend && sloTrend.direction === TrendDirection.DEGRADING) {
      healthScore -= sloTrend.strength * 25;
    }

    return Math.max(0, Math.min(100, healthScore));
  }

  private calculateOverallTrend(trends: TrendAnalysis[]): TrendDirection {
    if (trends.length === 0) return TrendDirection.UNKNOWN;

    const degrading = trends.filter(t => t.direction === TrendDirection.DEGRADING).length;
    const improving = trends.filter(t => t.direction === TrendDirection.IMPROVING).length;
    const stable = trends.filter(t => t.direction === TrendDirection.STABLE).length;

    if (degrading > improving && degrading > stable) return TrendDirection.DEGRADING;
    if (improving > degrading && improving > stable) return TrendDirection.IMPROVING;
    return TrendDirection.STABLE;
  }

  private getPreviousWindow(window: AnalysisWindow): AnalysisWindow {
    switch (window) {
      case AnalysisWindow.LAST_HOUR:
        return AnalysisWindow.LAST_HOUR;
      case AnalysisWindow.LAST_6_HOURS:
        return AnalysisWindow.LAST_6_HOURS;
      case AnalysisWindow.LAST_24_HOURS:
        return AnalysisWindow.LAST_24_HOURS;
      case AnalysisWindow.LAST_7_DAYS:
        return AnalysisWindow.LAST_7_DAYS;
      case AnalysisWindow.LAST_30_DAYS:
        return AnalysisWindow.LAST_30_DAYS;
      case AnalysisWindow.LAST_QUARTER:
        return AnalysisWindow.LAST_QUARTER;
    }
  }

  private generateRecommendations(
    serviceName: string,
    metrics: any,
    overallHealth: any
  ): string[] {
    const recommendations: string[] = [];

    if (overallHealth.riskLevel === 'critical') {
      recommendations.push('IMMEDIATE ACTION REQUIRED: Service health is critical');
    }

    if (metrics.budget_utilization_percent?.changePercent > 20) {
      recommendations.push('Monitor retry budget consumption closely');
    }

    if (overallHealth.current < 50) {
      recommendations.push('Consider scaling up service resources');
    }

    return recommendations;
  }

  private generateServiceRecommendations(
    serviceName: string,
    trends: TrendAnalysis[],
    anomalies: AnomalyDetection[],
    patterns: PatternDetection[],
    predictions: PredictiveAnalysis[]
  ): string[] {
    const recommendations: string[] = [];

    // Based on trends
    const degradingTrends = trends.filter(t => t.direction === TrendDirection.DEGRADING);
    if (degradingTrends.length > 0) {
      recommendations.push('Multiple metrics showing degrading trends - investigate root causes');
    }

    // Based on anomalies
    if (anomalies.length > 5) {
      recommendations.push('High number of anomalies detected - review system stability');
    }

    // Based on predictions
    const criticalPredictions = predictions.filter(p => p.riskLevel === 'critical');
    if (criticalPredictions.length > 0) {
      recommendations.push('Critical predictions detected - immediate attention required');
    }

    // Based on patterns
    if (patterns.length > 0) {
      recommendations.push('Predictable patterns detected - consider automated adjustments');
    }

    return recommendations;
  }

  /**
   * Set up event listeners
   */
  private setupEventListeners(): void {
    // Listen to retry budget monitor events
    retryBudgetMonitor.on('metrics_updated', (event: any) => {
      // Data will be processed in the next cycle
    });

    // Listen to circuit breaker events
    circuitBreakerMonitor.on('alert', (event: any) => {
      // Log circuit breaker events for pattern analysis
    });
  }
}

// Export singleton instance
export const retryTrendAnalyzer = new RetryTrendAnalyzer();
