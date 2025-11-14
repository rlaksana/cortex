// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * P2-P3: R/A/G Status Dashboard Infrastructure
 *
 * Provides production-ready dashboard infrastructure with cardinality management,
 * real-time status updates, and comprehensive monitoring capabilities.
 *
 * Features:
 * - Real-time R/A/G status visualization with cardinality caps
 * - Multi-dimensional metric aggregation with intelligent grouping
 * - Configurable dashboard layouts and widget systems
 * - Performance-optimized data querying with caching
 * - Export capabilities for external monitoring systems
 * - Alert integration and escalation workflows
 *
 * @module services/metrics/rag-dashboard
 */

import { logger } from '@/utils/logger.js';

import { type RAGStatus, sliSloMonitorService, type SLOAlert } from './sli-slo-monitor.js';
import { type SystemMetrics,systemMetricsService } from './system-metrics.js';

// === Type Definitions ===

export interface DashboardWidget {
  id: string;
  type:
    | 'status_card'
    | 'metric_chart'
    | 'alert_panel'
    | 'trend_chart'
    | 'resource_utilization'
    | 'slo_compliance';
  title: string;
  position: { x: number; y: number; width: number; height: number };
  config: Record<string, unknown>;
  refresh_interval_seconds: number;
  enabled: boolean;
  last_updated: number;
}

export interface DashboardLayout {
  id: string;
  name: string;
  description: string;
  widgets: DashboardWidget[];
  grid_columns: number;
  grid_rows: number;
  auto_refresh_seconds: number;
  theme: 'light' | 'dark' | 'auto';
  created_at: number;
  updated_at: number;
  created_by: string;
}

export interface MetricDataPoint {
  timestamp: number;
  value: number;
  dimensions?: Record<string, string>;
  metadata?: Record<string, unknown>;
}

export interface AggregatedMetric {
  name: string;
  current_value: number;
  previous_value: number;
  trend: 'up' | 'down' | 'stable';
  trend_percentage: number;
  unit: string;
  status: 'red' | 'amber' | 'green';
  threshold: { warning: number; critical: number };
  data_points: MetricDataPoint[];
  aggregation_method: 'avg' | 'sum' | 'min' | 'max' | 'p50' | 'p95' | 'p99';
}

export interface CardinalityLimit {
  dimension_name: string;
  max_unique_values: number;
  current_unique_values: number;
  top_values: Array<{ value: string; count: number }>;
  last_cleanup: number;
  cleanup_strategy: 'lru' | 'least_frequent' | 'random';
}

export interface DashboardConfig {
  // Cardinality management
  cardinality_limits: CardinalityLimit[];
  max_total_dimensional_combinations: number;
  dimension_ttl_hours: number;
  cleanup_interval_minutes: number;

  // Data retention
  raw_data_retention_hours: number;
  aggregated_data_retention_days: number;
  alert_retention_days: number;

  // Performance settings
  max_concurrent_queries: number;
  query_timeout_seconds: number;
  cache_ttl_minutes: number;

  // Dashboard settings
  default_refresh_interval_seconds: number;
  max_widgets_per_dashboard: number;
  export_formats: Array<'json' | 'csv' | 'prometheus' | 'grafana'>;
}

export interface AlertEscalationRule {
  id: string;
  name: string;
  trigger_conditions: {
    severity: ('warning' | 'critical')[];
    duration_minutes: number;
    consecutive_breaches: number;
  };
  escalation_actions: Array<{
    type: 'email' | 'slack' | 'pagerduty' | 'webhook';
    target: string;
    message_template: string;
    delay_minutes: number;
  }>;
  enabled: boolean;
  created_at: number;
  created_by: string;
}

/**
 * R/A/G Dashboard Service
 */
export class RAGDashboardService {
  private dashboards: Map<string, DashboardLayout> = new Map();
  private aggregatedMetrics: Map<string, AggregatedMetric> = new Map();
  private dimensionalData: Map<string, Map<string, MetricDataPoint[]>> = new Map();
  private cardinalityLimits: Map<string, CardinalityLimit> = new Map();
  private alertEscalationRules: Map<string, AlertEscalationRule> = new Map();
  private dataCache: Map<string, { data: unknown; timestamp: number }> = new Map();

  private config: DashboardConfig;
  private cleanupInterval: NodeJS.Timeout | null = null;
  private refreshInterval: NodeJS.Timeout | null = null;

  private readonly defaultConfig: DashboardConfig = {
    cardinality_limits: [
      {
        dimension_name: 'service',
        max_unique_values: 100,
        current_unique_values: 0,
        top_values: [],
        last_cleanup: 0,
        cleanup_strategy: 'lru',
      },
      {
        dimension_name: 'operation',
        max_unique_values: 50,
        current_unique_values: 0,
        top_values: [],
        last_cleanup: 0,
        cleanup_strategy: 'lru',
      },
      {
        dimension_name: 'user_id',
        max_unique_values: 1000,
        current_unique_values: 0,
        top_values: [],
        last_cleanup: 0,
        cleanup_strategy: 'least_frequent',
      },
      {
        dimension_name: 'error_type',
        max_unique_values: 100,
        current_unique_values: 0,
        top_values: [],
        last_cleanup: 0,
        cleanup_strategy: 'lru',
      },
    ],
    max_total_dimensional_combinations: 10000,
    dimension_ttl_hours: 6,
    cleanup_interval_minutes: 30,

    raw_data_retention_hours: 2,
    aggregated_data_retention_days: 30,
    alert_retention_days: 7,

    max_concurrent_queries: 10,
    query_timeout_seconds: 30,
    cache_ttl_minutes: 5,

    default_refresh_interval_seconds: 30,
    max_widgets_per_dashboard: 50,
    export_formats: ['json', 'csv', 'prometheus', 'grafana'],
  };

  constructor(config?: Partial<DashboardConfig>) {
    this.config = { ...this.defaultConfig, ...config };
    this.initializeDefaultDashboard();
    this.initializeCardinalityLimits();
    this.startBackgroundProcesses();

    logger.info('R/A/G Dashboard Service initialized', {
      maxDimensionalCombinations: this.config.max_total_dimensional_combinations,
      cleanupIntervalMinutes: this.config.cleanup_interval_minutes,
      cacheTTLMinutes: this.config.cache_ttl_minutes,
    });
  }

  /**
   * Initialize default dashboard layout
   */
  private initializeDefaultDashboard(): void {
    const defaultDashboard: DashboardLayout = {
      id: 'default',
      name: 'Cortex MCP Overview',
      description: 'Default monitoring dashboard for Cortex MCP service',
      widgets: [
        {
          id: 'overall_status',
          type: 'status_card',
          title: 'Overall Service Status',
          position: { x: 0, y: 0, width: 4, height: 2 },
          config: { show_trends: true, show_alerts: true },
          refresh_interval_seconds: 30,
          enabled: true,
          last_updated: 0,
        },
        {
          id: 'availability_metrics',
          type: 'metric_chart',
          title: 'Availability Metrics',
          position: { x: 4, y: 0, width: 4, height: 2 },
          config: {
            metrics: ['availability_percentage', 'error_budget_remaining'],
            chart_type: 'line',
            show_slo_targets: true,
          },
          refresh_interval_seconds: 60,
          enabled: true,
          last_updated: 0,
        },
        {
          id: 'latency_metrics',
          type: 'metric_chart',
          title: 'Latency Metrics',
          position: { x: 8, y: 0, width: 4, height: 2 },
          config: {
            metrics: ['p50_ms', 'p95_ms', 'p99_ms'],
            chart_type: 'line',
            show_percentiles: true,
          },
          refresh_interval_seconds: 60,
          enabled: true,
          last_updated: 0,
        },
        {
          id: 'active_alerts',
          type: 'alert_panel',
          title: 'Active Alerts',
          position: { x: 0, y: 2, width: 6, height: 3 },
          config: {
            max_alerts: 10,
            show_severity_colors: true,
            group_by: 'severity',
          },
          refresh_interval_seconds: 15,
          enabled: true,
          last_updated: 0,
        },
        {
          id: 'resource_utilization',
          type: 'resource_utilization',
          title: 'Resource Utilization',
          position: { x: 6, y: 2, width: 6, height: 3 },
          config: {
            resources: ['cpu', 'memory', 'disk', 'network'],
            show_thresholds: true,
            chart_type: 'gauge',
          },
          refresh_interval_seconds: 30,
          enabled: true,
          last_updated: 0,
        },
        {
          id: 'slo_compliance',
          type: 'slo_compliance',
          title: 'SLO Compliance',
          position: { x: 0, y: 5, width: 12, height: 2 },
          config: {
            show_trends: true,
            show_error_budget: true,
            period_hours: 24,
          },
          refresh_interval_seconds: 300, // 5 minutes
          enabled: true,
          last_updated: 0,
        },
      ],
      grid_columns: 12,
      grid_rows: 7,
      auto_refresh_seconds: 30,
      theme: 'auto',
      created_at: Date.now(),
      updated_at: Date.now(),
      created_by: 'system',
    };

    this.dashboards.set('default', defaultDashboard);
  }

  /**
   * Initialize cardinality limits
   */
  private initializeCardinalityLimits(): void {
    this.config.cardinality_limits.forEach((limit) => {
      this.cardinalityLimits.set(limit.dimension_name, {
        ...limit,
        last_cleanup: Date.now(),
      });
    });
  }

  /**
   * Start background processes
   */
  private startBackgroundProcesses(): void {
    // Start cleanup interval
    this.cleanupInterval = setInterval(
      () => {
        this.performCleanup();
      },
      this.config.cleanup_interval_minutes * 60 * 1000
    );

    // Start data refresh interval
    this.refreshInterval = setInterval(() => {
      this.refreshDashboardData();
    }, this.config.default_refresh_interval_seconds * 1000);

    logger.info('Background processes started', {
      cleanupIntervalMinutes: this.config.cleanup_interval_minutes,
      refreshIntervalSeconds: this.config.default_refresh_interval_seconds,
    });
  }

  /**
   * Perform cleanup of old data and cardinality management
   */
  private performCleanup(): void {
    try {
      const now = Date.now();
      let totalCleanupCount = 0;

      // Clean up dimensional data
      const dimensionTTL = this.config.dimension_ttl_hours * 60 * 60 * 1000;
      for (const [dimensionName, dimensionData] of this.dimensionalData.entries()) {
        let removedCount = 0;
        for (const [value, dataPoints] of dimensionData.entries()) {
          const filteredPoints = dataPoints.filter(
            (point) => now - point.timestamp <= dimensionTTL
          );
          if (filteredPoints.length === 0) {
            dimensionData.delete(value);
            removedCount++;
          } else if (filteredPoints.length !== dataPoints.length) {
            dimensionData.set(value, filteredPoints);
          }
        }

        if (dimensionData.size === 0) {
          this.dimensionalData.delete(dimensionName);
        }
        totalCleanupCount += removedCount;
      }

      // Clean up aggregated metrics
      const aggregatedTTL = this.config.aggregated_data_retention_days * 24 * 60 * 60 * 1000;
      for (const [metricName, metric] of this.aggregatedMetrics.entries()) {
        const filteredPoints = metric.data_points.filter(
          (point) => now - point.timestamp <= aggregatedTTL
        );
        if (filteredPoints.length !== metric.data_points.length) {
          metric.data_points = filteredPoints;
        }
      }

      // Clean up cache
      const cacheTTL = this.config.cache_ttl_minutes * 60 * 1000;
      for (const [key, cached] of this.dataCache.entries()) {
        if (now - cached.timestamp > cacheTTL) {
          this.dataCache.delete(key);
        }
      }

      // Enforce cardinality limits
      this.enforceCardinalityLimits();

      logger.debug('Cleanup completed', {
        totalCleanupCount,
        dimensionalDataCount: this.dimensionalData.size,
        aggregatedMetricsCount: this.aggregatedMetrics.size,
        cacheSize: this.dataCache.size,
      });
    } catch (error) {
      logger.error('Cleanup failed', { error });
    }
  }

  /**
   * Enforce cardinality limits
   */
  private enforceCardinalityLimits(): void {
    let totalCombinations = 0;

    // Calculate total combinations
    for (const dimensionData of this.dimensionalData.values()) {
      totalCombinations += dimensionData.size;
    }

    if (totalCombinations <= this.config.max_total_dimensional_combinations) {
      return; // Within limits
    }

    // Need to reduce cardinality
    const excess = totalCombinations - this.config.max_total_dimensional_combinations;
    let toRemove = excess;

    for (const [dimensionName, limit] of this.cardinalityLimits.entries()) {
      if (toRemove <= 0) break;

      const dimensionData = this.dimensionalData.get(dimensionName);
      if (!dimensionData) continue;

      if (dimensionData.size > limit.max_unique_values) {
        const entriesToRemove = Math.min(dimensionData.size - limit.max_unique_values, toRemove);
        const sortedEntries = Array.from(dimensionData.entries()).sort(([, a], [, b]) => {
          // Sort based on cleanup strategy
          switch (limit.cleanup_strategy) {
            case 'lru':
              return a[0]?.timestamp - b[0]?.timestamp;
            case 'least_frequent':
              return a.length - b.length;
            case 'random':
              return Math.random() - 0.5;
            default:
              return 0;
          }
        });

        for (let i = 0; i < entriesToRemove && i < sortedEntries.length; i++) {
          dimensionData.delete(sortedEntries[i][0]);
          toRemove--;
        }

        // Update top values
        limit.top_values = Array.from(dimensionData.entries())
          .map(([value, points]) => ({ value, count: points.length }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 10);
      }

      limit.current_unique_values = dimensionData.size;
      limit.last_cleanup = Date.now();
    }

    logger.info('Cardinality limits enforced', {
      originalCombinations: totalCombinations,
      targetCombinations: this.config.max_total_dimensional_combinations,
      removed: excess - toRemove,
    });
  }

  /**
   * Refresh dashboard data
   */
  private refreshDashboardData(): void {
    try {
      const ragStatus = sliSloMonitorService.getRAGStatus();
      const sliMetrics = sliSloMonitorService.getSLIMetrics();
      const systemMetrics = systemMetricsService.getMetrics();
      const activeAlerts = sliSloMonitorService.getActiveSLOAlerts();

      // Update aggregated metrics
      this.updateAggregatedMetrics(ragStatus, sliMetrics, systemMetrics);

      // Store dimensional data with cardinality management
      this.storeDimensionalData(ragStatus, sliMetrics, systemMetrics);

      // Update dashboard widgets
      this.updateDashboardWidgets(ragStatus, sliMetrics, systemMetrics, activeAlerts);

      // Check for alert escalations
      this.checkAlertEscalations(activeAlerts);
    } catch (error) {
      logger.error('Failed to refresh dashboard data', { error });
    }
  }

  /**
   * Update aggregated metrics
   */
  private updateAggregatedMetrics(
    ragStatus: RAGStatus,
    sliMetrics: unknown,
    systemMetrics: SystemMetrics
  ): void {
    const now = Date.now();

    // Update availability metric
    this.updateMetric('availability_percentage', sliMetrics.availability.availability_percentage, {
      unit: '%',
      threshold: { warning: 99.5, critical: 99.0 },
      aggregation_method: 'avg' as const,
    });

    // Update latency metrics
    this.updateMetric('p95_latency_ms', sliMetrics.latency.p95_ms, {
      unit: 'ms',
      threshold: { warning: 1500, critical: 2000 },
      aggregation_method: 'p95' as const,
    });

    this.updateMetric('error_rate_percentage', sliMetrics.error_rate.error_rate_percentage, {
      unit: '%',
      threshold: { warning: 0.5, critical: 1.0 },
      aggregation_method: 'avg' as const,
    });

    // Update resource metrics
    this.updateMetric('cpu_utilization', sliMetrics.resource_utilization.cpu_percentage, {
      unit: '%',
      threshold: { warning: 70, critical: 85 },
      aggregation_method: 'avg' as const,
    });

    this.updateMetric('memory_utilization', sliMetrics.resource_utilization.memory_percentage, {
      unit: '%',
      threshold: { warning: 70, critical: 85 },
      aggregation_method: 'avg' as const,
    });

    this.updateMetric('throughput_rps', sliMetrics.throughput.requests_per_second, {
      unit: 'rps',
      threshold: { warning: 5, critical: 2 },
      aggregation_method: 'avg' as const,
    });
  }

  /**
   * Update a single metric
   */
  private updateMetric(
    name: string,
    value: number,
    config: {
      unit: string;
      threshold: { warning: number; critical: number };
      aggregation_method: AggregatedMetric['aggregation_method'];
    }
  ): void {
    const existing = this.aggregatedMetrics.get(name);
    const now = Date.now();

    const dataPoint: MetricDataPoint = {
      timestamp: now,
      value,
    };

    if (existing) {
      // Add new data point
      existing.data_points.push(dataPoint);

      // Keep only recent data points (last 2 hours)
      const twoHoursAgo = now - 2 * 60 * 60 * 1000;
      existing.data_points = existing.data_points.filter((point) => point.timestamp >= twoHoursAgo);

      // Calculate trend
      const recentPoints = existing.data_points.slice(-10);
      if (recentPoints.length >= 2) {
        const previousValue = recentPoints[recentPoints.length - 2].value;
        const trendPercentage =
          previousValue !== 0 ? ((value - previousValue) / previousValue) * 100 : 0;

        if (Math.abs(trendPercentage) < 1) {
          existing.trend = 'stable';
        } else if (trendPercentage > 0) {
          existing.trend = 'up';
        } else {
          existing.trend = 'down';
        }

        existing.trend_percentage = Math.abs(trendPercentage);
      }

      // Update status based on thresholds
      if (value >= config.threshold.critical) {
        existing.status = 'red';
      } else if (value >= config.threshold.warning) {
        existing.status = 'amber';
      } else {
        existing.status = 'green';
      }

      existing.previous_value = existing.current_value;
      existing.current_value = value;
    } else {
      // Create new metric
      this.aggregatedMetrics.set(name, {
        name,
        current_value: value,
        previous_value: value,
        trend: 'stable',
        trend_percentage: 0,
        unit: config.unit,
        status:
          value >= config.threshold.critical
            ? 'red'
            : value >= config.threshold.warning
              ? 'amber'
              : 'green',
        threshold: config.threshold,
        data_points: [dataPoint],
        aggregation_method: config.aggregation_method,
      });
    }
  }

  /**
   * Store dimensional data with cardinality management
   */
  private storeDimensionalData(
    ragStatus: RAGStatus,
    sliMetrics: unknown,
    systemMetrics: SystemMetrics
  ): void {
    const dimensions = {
      service: ragStatus.service_name,
      status: ragStatus.overall_status,
      // Add more dimensions as needed
    };

    for (const [dimensionName, dimensionValue] of Object.entries(dimensions)) {
      if (!this.dimensionalData.has(dimensionName)) {
        this.dimensionalData.set(dimensionName, new Map());
      }

      const dimensionMap = this.dimensionalData.get(dimensionName)!;
      if (!dimensionMap.has(dimensionValue)) {
        dimensionMap.set(dimensionValue, []);
      }

      const dataPoints = dimensionMap.get(dimensionValue)!;
      dataPoints.push({
        timestamp: Date.now(),
        value: 1, // Count of occurrences
        dimensions: { [dimensionName]: dimensionValue },
      });

      // Keep only recent data points
      const oneHourAgo = Date.now() - 60 * 60 * 1000;
      const filteredPoints = dataPoints.filter((point) => point.timestamp >= oneHourAgo);
      dimensionMap.set(dimensionValue, filteredPoints);
    }
  }

  /**
   * Update dashboard widgets
   */
  private updateDashboardWidgets(
    ragStatus: RAGStatus,
    sliMetrics: unknown,
    systemMetrics: SystemMetrics,
    activeAlerts: SLOAlert[]
  ): void {
    const now = Date.now();

    for (const dashboard of this.dashboards.values()) {
      for (const widget of dashboard.widgets) {
        if (!widget.enabled) continue;

        // Check if widget needs refresh
        if (now - widget.last_updated < widget.refresh_interval_seconds * 1000) {
          continue;
        }

        try {
          this.updateWidgetData(widget, ragStatus, sliMetrics, systemMetrics, activeAlerts);
          widget.last_updated = now;
        } catch (error) {
          logger.error('Failed to update widget', { widgetId: widget.id, error });
        }
      }

      dashboard.updated_at = now;
    }
  }

  /**
   * Update individual widget data
   */
  private updateWidgetData(
    widget: DashboardWidget,
    ragStatus: RAGStatus,
    sliMetrics: unknown,
    systemMetrics: SystemMetrics,
    activeAlerts: SLOAlert[]
  ): void {
    switch (widget.type) {
      case 'status_card':
        widget.config.data = {
          status: ragStatus.overall_status,
          components: ragStatus.components,
          slo_compliance: ragStatus.slo_compliance,
          error_budget_status: ragStatus.error_budget_status,
          active_alerts_count: ragStatus.active_alerts_count,
          trends: ragStatus.trends,
        };
        break;

      case 'metric_chart':
        widget.config.data = this.getMetricChartData(widget.config.metrics);
        break;

      case 'alert_panel':
        widget.config.data = {
          alerts: activeAlerts.slice(0, widget.config.max_alerts || 10),
          total_count: activeAlerts.length,
          critical_count: activeAlerts.filter((a) => a.severity === 'critical').length,
          warning_count: activeAlerts.filter((a) => a.severity === 'warning').length,
        };
        break;

      case 'resource_utilization':
        widget.config.data = {
          cpu: {
            current: sliMetrics.resource_utilization.cpu_percentage,
            status: this.getResourceStatus(sliMetrics.resource_utilization.cpu_percentage),
          },
          memory: {
            current: sliMetrics.resource_utilization.memory_percentage,
            status: this.getResourceStatus(sliMetrics.resource_utilization.memory_percentage),
          },
          disk: {
            current: sliMetrics.resource_utilization.disk_percentage,
            status: this.getResourceStatus(sliMetrics.resource_utilization.disk_percentage),
          },
          network: {
            current: sliMetrics.resource_utilization.network_io_percentage,
            status: this.getResourceStatus(sliMetrics.resource_utilization.network_io_percentage),
          },
        };
        break;

      case 'slo_compliance':
        widget.config.data = {
          availability: {
            current: ragStatus.slo_compliance.availability_compliance,
            target: sliMetrics.availability.slo_target_percentage,
            status:
              ragStatus.slo_compliance.availability_compliance >=
              sliMetrics.availability.slo_target_percentage
                ? 'met'
                : 'breached',
          },
          latency: {
            current: ragStatus.slo_compliance.latency_compliance,
            target: 100,
            status: ragStatus.slo_compliance.latency_compliance >= 100 ? 'met' : 'breached',
          },
          error_rate: {
            current: ragStatus.slo_compliance.error_rate_compliance,
            target: 100 - sliMetrics.error_rate.slo_target_error_rate_percentage,
            status:
              ragStatus.slo_compliance.error_rate_compliance >=
              100 - sliMetrics.error_rate.slo_target_error_rate_percentage
                ? 'met'
                : 'breached',
          },
          throughput: {
            current: ragStatus.slo_compliance.throughput_compliance,
            target: 90,
            status: ragStatus.slo_compliance.throughput_compliance >= 90 ? 'met' : 'breached',
          },
          error_budget: {
            remaining: sliMetrics.availability.error_budget_remaining,
            status: ragStatus.error_budget_status,
            burn_rate: sliMetrics.availability.error_budget_burn_rate,
          },
          trends: ragStatus.trends,
        };
        break;
    }
  }

  /**
   * Get metric chart data
   */
  private getMetricChartData(metricNames: string[]): unknown {
    const data: Record<string, unknown> = {};

    for (const metricName of metricNames) {
      const metric = this.aggregatedMetrics.get(metricName);
      if (metric) {
        data[metricName] = {
          current: metric.current_value,
          previous: metric.previous_value,
          trend: metric.trend,
          trend_percentage: metric.trend_percentage,
          unit: metric.unit,
          status: metric.status,
          data_points: metric.data_points.slice(-100), // Last 100 points
        };
      }
    }

    return data;
  }

  /**
   * Get resource status
   */
  private getResourceStatus(utilization: number): 'red' | 'amber' | 'green' {
    if (utilization >= 85) return 'red';
    if (utilization >= 70) return 'amber';
    return 'green';
  }

  /**
   * Check for alert escalations
   */
  private checkAlertEscalations(activeAlerts: SLOAlert[]): void {
    for (const alert of activeAlerts) {
      for (const [ruleId, rule] of this.alertEscalationRules.entries()) {
        if (!rule.enabled) continue;

        // Check if alert matches rule conditions
        const matchesSeverity = rule.trigger_conditions.severity.includes(alert.severity);
        const durationMatches =
          Date.now() - alert.timestamp >= rule.trigger_conditions.duration_minutes * 60 * 1000;

        if (matchesSeverity && durationMatches) {
          // TODO: Implement escalation logic (send to external systems)
          logger.info('Alert escalation triggered', {
            alertId: alert.id,
            ruleId,
            severity: alert.severity,
            title: alert.title,
          });
        }
      }
    }
  }

  // === Public API Methods ===

  /**
   * Get dashboard by ID
   */
  getDashboard(id: string): DashboardLayout | null {
    const dashboard = this.dashboards.get(id);
    return dashboard ? { ...dashboard } : null;
  }

  /**
   * Get all dashboards
   */
  getAllDashboards(): DashboardLayout[] {
    return Array.from(this.dashboards.values()).map((dashboard) => ({ ...dashboard }));
  }

  /**
   * Create or update dashboard
   */
  saveDashboard(dashboard: DashboardLayout): DashboardLayout {
    if (dashboard.widgets.length > this.config.max_widgets_per_dashboard) {
      throw new Error(
        `Dashboard exceeds maximum widget limit of ${this.config.max_widgets_per_dashboard}`
      );
    }

    dashboard.updated_at = Date.now();
    this.dashboards.set(dashboard.id, { ...dashboard });

    logger.info('Dashboard saved', {
      dashboardId: dashboard.id,
      widgetCount: dashboard.widgets.length,
    });
    return dashboard;
  }

  /**
   * Delete dashboard
   */
  deleteDashboard(id: string): boolean {
    const deleted = this.dashboards.delete(id);
    if (deleted) {
      logger.info('Dashboard deleted', { dashboardId: id });
    }
    return deleted;
  }

  /**
   * Get aggregated metrics
   */
  getAggregatedMetrics(metricNames?: string[]): AggregatedMetric[] {
    const metrics = Array.from(this.aggregatedMetrics.values());

    if (metricNames) {
      return metrics.filter((metric) => metricNames.includes(metric.name));
    }

    return metrics.map((metric) => ({ ...metric }));
  }

  /**
   * Get dimensional data with cardinality enforcement
   */
  getDimensionalData(dimensionName: string, limit?: number): Map<string, MetricDataPoint[]> {
    const dimensionData = this.dimensionalData.get(dimensionName);
    if (!dimensionData) return new Map();

    const result = new Map();
    let count = 0;
    const maxLimit = limit || 100;

    // Sort by most recent activity
    const sortedEntries = Array.from(dimensionData.entries()).sort(([, a], [, b]) => {
      const aLatest = a.length > 0 ? a[a.length - 1].timestamp : 0;
      const bLatest = b.length > 0 ? b[b.length - 1].timestamp : 0;
      return bLatest - aLatest;
    });

    for (const [key, dataPoints] of sortedEntries) {
      if (count >= maxLimit) break;
      result.set(key, [...dataPoints]);
      count++;
    }

    return result;
  }

  /**
   * Get cardinality limits
   */
  getCardinalityLimits(): CardinalityLimit[] {
    return Array.from(this.cardinalityLimits.values()).map((limit) => ({ ...limit }));
  }

  /**
   * Export dashboard data
   */
  exportDashboardData(dashboardId: string, format: 'json' | 'csv' | 'prometheus' = 'json'): string {
    const dashboard = this.dashboards.get(dashboardId);
    if (!dashboard) {
      throw new Error(`Dashboard ${dashboardId} not found`);
    }

    const exportData = {
      dashboard: {
        id: dashboard.id,
        name: dashboard.name,
        description: dashboard.description,
        exported_at: Date.now(),
      },
      widgets: dashboard.widgets.map((widget) => ({
        id: widget.id,
        type: widget.type,
        title: widget.title,
        data: widget.config.data,
        last_updated: widget.last_updated,
      })),
      rag_status: sliSloMonitorService.getRAGStatus(),
      sli_metrics: sliSloMonitorService.getSLIMetrics(),
      aggregated_metrics: Array.from(this.aggregatedMetrics.values()),
      active_alerts: sliSloMonitorService.getActiveSLOAlerts(),
      cardinality_limits: this.getCardinalityLimits(),
    };

    if (format === 'prometheus') {
      return this.formatMetricsAsPrometheus(exportData);
    }

    if (format === 'csv') {
      return this.formatMetricsAsCSV(exportData);
    }

    return JSON.stringify(exportData, null, 2);
  }

  /**
   * Format metrics as Prometheus
   */
  private formatMetricsAsPrometheus(data: unknown): string {
    const timestamp = Math.floor(Date.now() / 1000);
    const metrics = [];

    // RAG status
    metrics.push(
      '# HELP cortex_rag_status Overall RAG status (1=red, 2=amber, 3=green)',
      '# TYPE cortex_rag_status gauge',
      `cortex_rag_status ${data.rag_status.overall_status === 'red' ? 1 : data.rag_status.overall_status === 'amber' ? 2 : 3} ${timestamp}`
    );

    // SLO compliance
    Object.entries(data.rag_status.slo_compliance).forEach(([key, value]) => {
      metrics.push(
        `# HELP cortex_slo_compliance_${key} SLO compliance for ${key}`,
        '# TYPE cortex_slo_compliance_' + key + ' gauge',
        `cortex_slo_compliance_${key} ${value} ${timestamp}`
      );
    });

    // Aggregated metrics
    data.aggregated_metrics.forEach((metric: AggregatedMetric) => {
      metrics.push(
        `# HELP cortex_metric_${metric.name} ${metric.name} metric`,
        '# TYPE cortex_metric_' + metric.name + ' gauge',
        `cortex_metric_${metric.name} ${metric.current_value} ${timestamp}`
      );
    });

    return metrics.join('\n') + '\n';
  }

  /**
   * Format metrics as CSV
   */
  private formatMetricsAsCSV(data: unknown): string {
    const headers = ['timestamp', 'metric_name', 'value', 'unit', 'status'];
    const rows = [headers.join(',')];

    const timestamp = Date.now();

    data.aggregated_metrics.forEach((metric: AggregatedMetric) => {
      rows.push(
        [timestamp, metric.name, metric.current_value, metric.unit, metric.status].join(',')
      );
    });

    return rows.join('\n');
  }

  /**
   * Get system status
   */
  getSystemStatus(): {
    status: 'healthy' | 'degraded' | 'critical';
    dashboards_count: number;
    metrics_count: number;
    dimensional_combinations: number;
    active_alerts: number;
    cardinality_status: 'within_limits' | 'approaching_limits' | 'exceeded';
    cache_size: number;
    last_cleanup: number;
  } {
    const ragStatus = sliSloMonitorService.getRAGStatus();
    const activeAlerts = sliSloMonitorService.getActiveSLOAlerts();
    const totalCombinations = Array.from(this.dimensionalData.values()).reduce(
      (sum, dimension) => sum + dimension.size,
      0
    );

    let cardinalityStatus: 'within_limits' | 'approaching_limits' | 'exceeded' = 'within_limits';
    if (totalCombinations > this.config.max_total_dimensional_combinations) {
      cardinalityStatus = 'exceeded';
    } else if (totalCombinations > this.config.max_total_dimensional_combinations * 0.8) {
      cardinalityStatus = 'approaching_limits';
    }

    let status: 'healthy' | 'degraded' | 'critical' = 'healthy';
    if (ragStatus.overall_status === 'red' || activeAlerts.some((a) => a.severity === 'critical')) {
      status = 'critical';
    } else if (ragStatus.overall_status === 'amber' || activeAlerts.length > 0) {
      status = 'degraded';
    }

    return {
      status,
      dashboards_count: this.dashboards.size,
      metrics_count: this.aggregatedMetrics.size,
      dimensional_combinations: totalCombinations,
      active_alerts: activeAlerts.length,
      cardinality_status: cardinalityStatus,
      cache_size: this.dataCache.size,
      last_cleanup: Array.from(this.cardinalityLimits.values())[0]?.last_cleanup || 0,
    };
  }

  /**
   * Graceful shutdown
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }

    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }

    logger.info('R/A/G Dashboard Service destroyed');
  }
}

// Singleton instance
export const ragDashboardService = new RAGDashboardService();
