
/**
 * AI Metrics Service - Comprehensive Monitoring for AI Operations
 *
 * Provides detailed monitoring and metrics collection for all AI services including:
 * - ZAI client performance metrics
 * - AI orchestrator operations tracking
 * - Background processor job metrics
 * - Insight generation performance
 * - Contradiction detection metrics
 * - Resource usage and cost tracking
 * - Quality metrics and success rates
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from '@/utils/logger.js';

// Local boundary helpers (timestamps/severity)
const asEpoch = (v: unknown): number => Number(v ?? Date.now());
const asDate  = (v: unknown): Date   => new Date(asEpoch(v));
type ExternalSeverity = string;
type InternalSeverity = 'warning'|'critical'|'info';
const toSeverity = (s: ExternalSeverity): InternalSeverity => {
  const k = String(s || '').toLowerCase();
  if (k === 'critical' || k === 'crit') return 'critical';
  if (k === 'warn' || k === 'warning')  return 'warning';
  return 'info';
};
import type {
  AIMetricsSnapshot,
  AIOperationMetrics,
  AIOrchestratorMetrics,
  AIQualityMetrics,
  AIResourceMetrics,
  BackgroundProcessorMetrics,
  ZAIMetrics,
} from '../types/zai-interfaces.js';
import { performanceMonitor } from '../utils/performance-monitor.js';

/**
 * AI Metrics Configuration
 */
export interface AIMetricsConfig {
  /** Metrics collection interval in milliseconds */
  collectionInterval: number;
  /** History retention period in milliseconds */
  retentionPeriod: number;
  /** Enable detailed operation tracking */
  detailedTracking: boolean;
  /** Enable quality metrics calculation */
  qualityMetrics: boolean;
  /** Enable resource usage monitoring */
  resourceMonitoring: boolean;
  /** Enable cost tracking */
  costTracking: boolean;
  /** Metrics export formats */
  exportFormats: ('prometheus' | 'json' | 'influxdb')[];
  /** Alerting thresholds */
  alertThresholds: {
    /** Maximum acceptable latency in milliseconds */
    maxLatency: number;
    /** Minimum acceptable success rate (0-1) */
    minSuccessRate: number;
    /** Maximum acceptable error rate (0-1) */
    maxErrorRate: number;
    /** Maximum memory usage percentage */
    maxMemoryUsage: number;
    /** Maximum queue size */
    maxQueueSize: number;
  };
}

/**
 * AI Operation Metrics
 */
export interface AIOperationRecord {
  id: string;
  type: 'completion' | 'insight' | 'contradiction_detection' | 'embedding' | 'search';
  startTime: number;
  endTime?: number;
  latency?: number;
  status: 'pending' | 'success' | 'error' | 'timeout';
  error?: string;
  tokensUsed?: number;
  model?: string;
  confidence?: number;
  metadata?: Record<string, any>;
}

/**
 * AI Quality Metrics
 */
export interface AIQualitySnapshot {
  timestamp: number;
  insightAccuracy: number;
  contradictionDetectionAccuracy: number;
  semanticSearchRelevance: number;
  userSatisfactionScore: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
  averageConfidence: number;
  qualityScore: number;
}

/**
 * AI Resource Metrics
 */
export interface AIResourceSnapshot {
  timestamp: number;
  memoryUsage: {
    used: number;
    total: number;
    percentage: number;
  };
  cpuUsage: {
    user: number;
    system: number;
    idle: number;
  };
  gpuUsage?: {
    used: number;
    total: number;
    temperature: number;
  };
  networkIO: {
    bytesIn: number;
    bytesOut: number;
  };
  costMetrics: {
    requestsCost: number;
    tokenCost: number;
    storageCost: number;
    totalCost: number;
  };
}

/**
 * AI Metrics Service
 */
export class AIMetricsService {
  private config: AIMetricsConfig;
  private isStarted = false;
  private metricsCollectionInterval: NodeJS.Timeout | null = null;

  // Metrics storage
  private operationHistory: Map<string, AIOperationRecord> = new Map();
  private qualityHistory: AIQualitySnapshot[] = [];
  private resourceHistory: AIResourceSnapshot[] = [];
  private startTime = Date.now();

  // Current metrics
  private currentMetrics: AIMetricsSnapshot = {
    timestamp: asDate(Date.now()),
    orchestrator: {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageResponseTime: 0,
      activeSessions: 0,
      queuedRequests: 0,
      throughput: 0,
      errorRate: 0,
      circuitBreakerStatus: 'unknown',
    },
    backgroundProcessor: {
      queueSize: 0,
      processingRate: 0,
      averageProcessingTime: 0,
      errorRate: 0,
      activeWorkers: 0,
      completedTasks: 0,
      failedTasks: 0,
    },
    healthStatus: {
      status: 'healthy',
      timestamp: new Date(Date.now()),
      services: {
        zai: { status: 'healthy', lastCheck: new Date(), uptime: 0, errorRate: 0, responseTime: 0 },
        orchestrator: { status: 'healthy', lastCheck: new Date(), uptime: 0, errorRate: 0, responseTime: 0 },
        backgroundProcessor: { status: 'healthy', lastCheck: new Date(), uptime: 0, errorRate: 0, responseTime: 0 },
        insightService: { status: 'healthy', lastCheck: new Date(), uptime: 0, errorRate: 0, responseTime: 0 },
        contradictionDetector: { status: 'healthy', lastCheck: new Date(), uptime: 0, errorRate: 0, responseTime: 0 },
      },
      dependencies: {},
      overall: { uptime: 0, errorRate: 0, responseTime: 0, lastCheck: new Date() },
      performance: {
        latency: 0,
        throughput: 0,
        resources: { cpu: 0, memory: 0, disk: 0 },
      },
      alerts: [],
    },
    performance: {
      cpu: { usage: 0, threshold: 80, status: 'normal' },
      memory: { usage: 0, threshold: 80, status: 'normal' },
      responseTime: { average: 0, p95: 0, p99: 0, threshold: 1000, status: 'normal' },
      throughput: { current: 0, peak: 0, threshold: 100, status: 'normal' },
    },
    resources: {
      cpuUsage: 0,
      memoryUsage: 0,
      diskUsage: 0,
      networkIO: 0,
    },
    operations: {
      totalOperations: 0,
      successfulOperations: 0,
      failedOperations: 0,
      averageOperationTime: 0,
      operationTypes: {},
      // Additional properties for compatibility
      total: 0,
      successful: 0,
      failed: 0,
      pending: 0,
      averageLatency: 0,
      p95Latency: 0,
      p99Latency: 0,
      throughput: 0,
    },
    insights: {
      totalInsights: 0,
      successfulInsights: 0,
      failedInsights: 0,
      averageInsightTime: 0,
      insightTypes: {},
      // Additional properties for compatibility
      generated: 0,
      accuracy: 0,
      averageConfidence: 0,
      strategies: {
        pattern_recognition: 0,
        knowledge_gap: 0,
        anomaly_detection: 0,
        predictive_insight: 0,
        relationship_analysis: 0,
      },
    },
    contradiction: {
      totalContradictions: 0,
      resolvedContradictions: 0,
      pendingContradictions: 0,
      averageResolutionTime: 0,
      // Additional properties for compatibility
      detected: 0,
      accuracy: 0,
      falsePositives: 0,
      falseNegatives: 0,
      averageConfidence: 0,
      strategies: {
        factual_verification: 0,
        logical_contradiction: 0,
        semantic_contradiction: 0,
        temporal_contradiction: 0,
        procedural_contradiction: 0,
      },
    },
    quality: {
      averageQualityScore: 0,
      accuracyScore: 0,
      relevanceScore: 0,
      userSatisfactionScore: 0,
      // Additional properties for compatibility
      overall: 0,
      errorRate: 0,
      availability: 0,
    },
  };

  constructor(config: Partial<AIMetricsConfig> = {}) {
    this.config = {
      collectionInterval: 30000, // 30 seconds
      retentionPeriod: 24 * 60 * 60 * 1000, // 24 hours
      detailedTracking: true,
      qualityMetrics: true,
      resourceMonitoring: true,
      costTracking: false, // Disabled by default
      exportFormats: ['prometheus', 'json'],
      alertThresholds: {
        maxLatency: 5000, // 5 seconds
        minSuccessRate: 0.95,
        maxErrorRate: 0.05,
        maxMemoryUsage: 80,
        maxQueueSize: 1000,
      },
      ...config,
    };
  }

  /**
   * Start metrics collection
   */
  async start(): Promise<void> {
    if (this.isStarted) {
      logger.warn('AI metrics service already started');
      return;
    }

    try {
      logger.info('Starting AI metrics service...');

      // Start metrics collection interval
      this.metricsCollectionInterval = setInterval(() => {
        this.collectMetrics();
      }, this.config.collectionInterval);

      this.isStarted = true;
      logger.info('AI metrics service started successfully', {
        collectionInterval: this.config.collectionInterval,
        retentionPeriod: this.config.retentionPeriod,
      });
    } catch (error) {
      logger.error({ error }, 'Failed to start AI metrics service');
      throw error;
    }
  }

  /**
   * Stop metrics collection
   */
  async stop(): Promise<void> {
    if (!this.isStarted) {
      logger.warn('AI metrics service not started');
      return;
    }

    try {
      logger.info('Stopping AI metrics service...');

      if (this.metricsCollectionInterval) {
        clearInterval(this.metricsCollectionInterval);
        this.metricsCollectionInterval = null;
      }

      this.isStarted = false;
      logger.info('AI metrics service stopped successfully');
    } catch (error) {
      logger.error({ error }, 'Error stopping AI metrics service');
      throw error;
    }
  }

  /**
   * Record an AI operation
   */
  recordOperation(operation: Omit<AIOperationRecord, 'id'>): string {
    const id = `ai_op_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const record: AIOperationRecord = { id, ...operation };

    this.operationHistory.set(id, record);

    // Update current metrics
    this.updateOperationMetrics(record);

    logger.debug({ operation: record }, 'AI operation recorded');
    return id;
  }

  /**
   * Complete an operation
   */
  completeOperation(
    id: string,
    result: {
      status: 'success' | 'error' | 'timeout';
      latency?: number;
      error?: string;
      tokensUsed?: number;
      confidence?: number;
    }
  ): void {
    const operation = this.operationHistory.get(id);
    if (!operation) {
      logger.warn({ id }, 'Operation not found for completion');
      return;
    }

    operation.status = result.status;
    operation.endTime = Date.now();
    operation.latency = result.latency || operation.endTime - operation.startTime;
    operation.error = result.error;
    operation.tokensUsed = result.tokensUsed;
    operation.confidence = result.confidence;

    this.updateOperationMetrics(operation);

    logger.debug({ operation, result }, 'AI operation completed');
  }

  /**
   * Record insight generation metrics
   */
  recordInsightMetrics(metrics: {
    strategy: string;
    accuracy?: number;
    confidence?: number;
    processingTime: number;
    itemsProcessed: number;
  }): void {
    const insights = this.currentMetrics.insights;
    if (!insights) return;

    insights.generated = (insights.generated || 0) + 1;
    insights.totalInsights = (insights.totalInsights || 0) + 1;

    if (metrics.accuracy) {
      insights.accuracy = ((insights.accuracy || 0) + metrics.accuracy) / 2;
    }

    if (metrics.confidence) {
      insights.averageConfidence = ((insights.averageConfidence || 0) + metrics.confidence) / 2;
    }

    const strategy = metrics.strategy as keyof typeof insights.strategies;
    if (insights.strategies && strategy in insights.strategies) {
      insights.strategies[strategy]++;
    }
  }

  /**
   * Record contradiction detection metrics
   */
  recordContradictionMetrics(metrics: {
    strategy: string;
    detected: number;
    falsePositives?: number;
    falseNegatives?: number;
    accuracy?: number;
    confidence?: number;
  }): void {
    const contradiction = this.currentMetrics.contradiction;
    if (!contradiction) return;

    contradiction.detected = (contradiction.detected || 0) + metrics.detected;
    contradiction.totalContradictions = (contradiction.totalContradictions || 0) + metrics.detected;

    if (metrics.falsePositives) {
      contradiction.falsePositives = (contradiction.falsePositives || 0) + metrics.falsePositives;
    }

    if (metrics.falseNegatives) {
      contradiction.falseNegatives = (contradiction.falseNegatives || 0) + metrics.falseNegatives;
    }

    if (metrics.accuracy) {
      contradiction.accuracy = ((contradiction.accuracy || 0) + metrics.accuracy) / 2;
    }

    if (metrics.confidence) {
      contradiction.averageConfidence = ((contradiction.averageConfidence || 0) + metrics.confidence) / 2;
    }

    const strategy = metrics.strategy as keyof typeof contradiction.strategies;
    if (contradiction.strategies && strategy in contradiction.strategies) {
      contradiction.strategies[strategy]++;
    }
  }

  /**
   * Get current metrics snapshot
   */
  getCurrentMetrics(): AIMetricsSnapshot {
    return { ...this.currentMetrics };
  }

  /**
   * Get operation history
   */
  getOperationHistory(filter?: {
    type?: string;
    status?: string;
    timeRange?: { start: number; end: number };
    limit?: number;
  }): AIOperationRecord[] {
    let operations = Array.from(this.operationHistory.values());

    if (filter) {
      if (filter.type) {
        operations = operations.filter((op) => op.type === filter.type);
      }
      if (filter.status) {
        operations = operations.filter((op) => op.status === filter.status);
      }
      if (filter.timeRange) {
        operations = operations.filter(
          (op) => op.startTime >= filter.timeRange!.start && op.startTime <= filter.timeRange!.end
        );
      }
    }

    // Sort by start time (newest first)
    operations.sort((a, b) => b.startTime - a.startTime);

    return filter?.limit ? operations.slice(0, filter.limit) : operations;
  }

  /**
   * Get quality metrics history
   */
  getQualityHistory(timeRange?: { start: number; end: number }): AIQualitySnapshot[] {
    let history = [...this.qualityHistory];

    if (timeRange) {
      history = history.filter(
        (snapshot) => snapshot.timestamp >= timeRange.start && snapshot.timestamp <= timeRange.end
      );
    }

    return history;
  }

  /**
   * Get resource metrics history
   */
  getResourceHistory(timeRange?: { start: number; end: number }): AIResourceSnapshot[] {
    let history = [...this.resourceHistory];

    if (timeRange) {
      history = history.filter(
        (snapshot) => snapshot.timestamp >= timeRange.start && snapshot.timestamp <= timeRange.end
      );
    }

    return history;
  }

  /**
   * Export metrics in Prometheus format
   */
  getPrometheusMetrics(): string {
    const metrics = this.currentMetrics;
    const timestamp = Date.now();

    let prometheus = '';

    // Operation metrics
    prometheus += `# HELP ai_operations_total Total number of AI operations\const asEpoch = (v: unknown): number => Number(v ?? Date.now());
const asDate  = (v: unknown): Date   => new Date(asEpoch(v));

type ExternalSeverity = string;
type InternalSeverity = 'warning'|'critical'|'info';
const toSeverity = (s: ExternalSeverity): InternalSeverity => {
  const k = String(s || '').toLowerCase();
  if (k === 'critical' || k === 'crit') return 'critical';
  if (k === 'warn' || k === 'warning')  return 'warning';
  return 'info';
};\nn`;
    prometheus += `# TYPE ai_operations_total counter\n`;
    prometheus += `ai_operations_total ${(metrics.operations?.total ?? 0)} ${timestamp}\n\n`;

    prometheus += `# HELP ai_operations_successful Number of successful AI operations\n`;
    prometheus += `# TYPE ai_operations_successful counter\n`;
    prometheus += `ai_operations_successful ${(metrics.operations?.successful ?? 0)} ${timestamp}\n\n`;

    prometheus += `# HELP ai_operations_failed Number of failed AI operations\n`;
    prometheus += `# TYPE ai_operations_failed counter\n`;
    prometheus += `ai_operations_failed ${(metrics.operations?.failed ?? 0)} ${timestamp}\n\n`;

    prometheus += `# HELP ai_operation_latency_seconds AI operation latency in seconds\n`;
    prometheus += `# TYPE ai_operation_latency_seconds histogram\n`;
    prometheus += `ai_operation_latency_seconds_sum ${(metrics.operations?.averageLatency ?? 0) / 1000} ${timestamp}\n`;
    prometheus += `ai_operation_latency_seconds_count ${(metrics.operations?.total ?? 0)} ${timestamp}\n\n`;

    // Insight metrics
    prometheus += `# HELP ai_insights_generated Total number of insights generated\n`;
    prometheus += `# TYPE ai_insights_generated counter\n`;
    prometheus += `ai_insights_generated ${(metrics.insights?.generated ?? 0)} ${timestamp}\n\n`;

    prometheus += `# HELP ai_insight_accuracy Insight accuracy score\n`;
    prometheus += `# TYPE ai_insight_accuracy gauge\n`;
    prometheus += `ai_insight_accuracy ${(metrics.insights?.accuracy ?? 0)} ${timestamp}\n\n`;

    // Contradiction detection metrics
    prometheus += `# HELP ai_contradictions_detected Total number of contradictions detected\n`;
    prometheus += `# TYPE ai_contradictions_detected counter\n`;
    prometheus += `ai_contradictions_detected ${(metrics.contradiction?.detected ?? 0)} ${timestamp}\n\n`;

    prometheus += `# HELP ai_contradiction_accuracy Contradiction detection accuracy\n`;
    prometheus += `# TYPE ai_contradiction_accuracy gauge\n`;
    prometheus += `ai_contradiction_accuracy ${(metrics.contradiction?.accuracy ?? 0)} ${timestamp}\n\n`;

    // Resource metrics
    prometheus += `# HELP ai_memory_usage_percentage AI service memory usage percentage\n`;
    prometheus += `# TYPE ai_memory_usage_percentage gauge\n`;
    prometheus += `ai_memory_usage_percentage ${metrics.resources.memoryUsage} ${timestamp}\n\n`;

    prometheus += `# HELP ai_cpu_usage_percentage AI service CPU usage percentage\n`;
    prometheus += `# TYPE ai_cpu_usage_percentage gauge\n`;
    prometheus += `ai_cpu_usage_percentage ${metrics.resources.cpuUsage} ${timestamp}\n\n`;

    // Quality metrics
    prometheus += `# HELP ai_quality_overall Overall AI service quality score\n`;
    prometheus += `# TYPE ai_quality_overall gauge\n`;
    prometheus += `ai_quality_overall ${(metrics.quality?.overall ?? 0)} ${timestamp}\n\n`;

    prometheus += `# HELP ai_availability AI service availability percentage\n`;
    prometheus += `# TYPE ai_availability gauge\n`;
    prometheus += `ai_availability ${(metrics.quality?.availability ?? 0)} ${timestamp}\n\n`;

    return prometheus;
  }

  /**
   * Check alert thresholds
   */
  checkAlertThresholds(): Array<{
    type: string;
    severity: 'warning' | 'critical';
    metric: string;
    value: number;
    threshold: number;
    message: string;
  }> {
    const alerts = [];
    const metrics = this.currentMetrics;

    // Latency alert
    if ((metrics.operations?.averageLatency ?? 0) > this.config.alertThresholds.maxLatency) {
      alerts.push({
        type: 'latency',
        severity: 'warning' as const,
        metric: 'averageLatency',
        value: metrics.operations?.averageLatency ?? 0,
        threshold: this.config.alertThresholds.maxLatency,
        message: `AI operation latency (${metrics.operations?.averageLatency ?? 0}ms) exceeds threshold (${this.config.alertThresholds.maxLatency}ms)`,
      });
    }

    // Success rate alert
    const totalOps = metrics.operations?.total ?? metrics.operations?.totalOperations ?? 0;
    const successOps = metrics.operations?.successful ?? metrics.operations?.successfulOperations ?? 0;
    const successRate = totalOps > 0 ? successOps / totalOps : 0;
    if (successRate < this.config.alertThresholds.minSuccessRate) {
      alerts.push({
        type: 'success_rate',
        severity: 'critical' as const,
        metric: 'successRate',
        value: successRate,
        threshold: this.config.alertThresholds.minSuccessRate,
        message: `AI success rate (${(successRate * 100).toFixed(1)}%) below threshold (${(this.config.alertThresholds.minSuccessRate * 100).toFixed(1)}%)`,
      });
    }

    // Memory usage alert
    if (metrics.resources.memoryUsage > this.config.alertThresholds.maxMemoryUsage) {
      alerts.push({
        type: 'memory',
        severity: 'warning' as const,
        metric: 'memoryUsage',
        value: metrics.resources.memoryUsage,
        threshold: this.config.alertThresholds.maxMemoryUsage,
        message: `AI memory usage (${metrics.resources.memoryUsage}%) exceeds threshold (${this.config.alertThresholds.maxMemoryUsage}%)`,
      });
    }

    return alerts;
  }

  /**
   * Update operation metrics
   */
  private updateOperationMetrics(operation: AIOperationRecord): void {
    const metrics = this.currentMetrics.operations;
    if (!metrics) return;

    if (operation.status === 'success') {
      metrics.successful = (metrics.successful || 0) + 1;
      metrics.successfulOperations = (metrics.successfulOperations || 0) + 1;
    } else if (operation.status === 'error' || operation.status === 'timeout') {
      metrics.failed = (metrics.failed || 0) + 1;
      metrics.failedOperations = (metrics.failedOperations || 0) + 1;
    }

    if (operation.status === 'pending') {
      metrics.pending = (metrics.pending || 0) + 1;
    } else {
      metrics.pending = Math.max(0, (metrics.pending || 0) - 1);
    }

    metrics.total = this.operationHistory.size;
    metrics.totalOperations = this.operationHistory.size;

    // Calculate average latency
    const completedOperations = Array.from(this.operationHistory.values()).filter(
      (op) => op.status !== 'pending' && op.latency
    );

    if (completedOperations.length > 0) {
      const totalLatency = completedOperations.reduce((sum, op) => sum + (op.latency || 0), 0);
      metrics.averageLatency = totalLatency / completedOperations.length;

      // Calculate percentiles
      const latencies = completedOperations.map((op) => op.latency || 0).sort((a, b) => a - b);
      const p95Index = Math.floor(latencies.length * 0.95);
      const p99Index = Math.floor(latencies.length * 0.99);
      metrics.p95Latency = latencies[p95Index] || 0;
      metrics.p99Latency = latencies[p99Index] || 0;
    }

    // Calculate throughput (operations per second)
    const timeWindow = 60000; // 1 minute
    const now = Date.now();
    const recentOperations = completedOperations.filter(
      (op) => op.endTime && op.endTime > now - timeWindow
    );
    metrics.throughput = recentOperations.length / (timeWindow / 1000);
  }

  /**
   * Collect metrics periodically
   */
  private collectMetrics(): void {
    try {
      const now = Date.now();

      // Update timestamp
      this.currentMetrics.timestamp = new Date(now);

      // Collect resource metrics
      if (this.config.resourceMonitoring) {
        this.collectResourceMetrics(now);
      }

      // Calculate quality metrics
      if (this.config.qualityMetrics) {
        this.calculateQualityMetrics(now);
      }

      // Cleanup old data
      this.cleanupOldData(now);

      // Check alert thresholds
      const alerts = this.checkAlertThresholds();
      if (alerts.length > 0) {
        logger.warn({ alerts }, 'AI metrics alert thresholds exceeded');
      }
    } catch (error) {
      logger.error({ error }, 'Error collecting AI metrics');
    }
  }

  /**
   * Collect resource metrics
   */
  private collectResourceMetrics(timestamp: number): void {
    const memoryUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    this.currentMetrics.resources.memoryUsage =
      (memoryUsage.heapUsed / memoryUsage.heapTotal) * 100;

    this.currentMetrics.resources.cpuUsage = ((cpuUsage.user + cpuUsage.system) / 1000000) * 100; // Convert to percentage

    // Store resource snapshot
    if (this.config.resourceMonitoring) {
      const snapshot: AIResourceSnapshot = {
        timestamp,
        memoryUsage: {
          used: memoryUsage.heapUsed,
          total: memoryUsage.heapTotal,
          percentage: this.currentMetrics.resources.memoryUsage,
        },
        cpuUsage: {
          user: cpuUsage.user,
          system: cpuUsage.system,
          idle: 0, // Not available in Node.js
        },
        networkIO: {
          bytesIn: 0, // Not easily available
          bytesOut: 0,
        },
        costMetrics: {
          requestsCost: 0,
          tokenCost: 0,
          storageCost: 0,
          totalCost: 0,
        },
      };

      this.resourceHistory.push(snapshot);
    }
  }

  /**
   * Calculate quality metrics
   */
  private calculateQualityMetrics(timestamp: number): void {
    const metrics = this.currentMetrics;
    // Ensure quality bag exists once, then use the alias `q`
    const q = (this.currentMetrics.quality ??= {
      averageQualityScore: 0,
      accuracyScore: 0,
      relevanceScore: 0,
      userSatisfactionScore: 0,
    });

    // Calculate overall quality score
    const insightWeight = 0.3;
    const contradictionWeight = 0.3;
    const performanceWeight = 0.4;

    const insightScore = metrics.insights?.accuracy ?? 0;
    const contradictionScore = metrics.contradiction?.accuracy ?? 0;
    const totalOps = (metrics.operations?.total ?? metrics.operations?.totalOperations) ?? 0;
    const successOps = (metrics.operations?.successful ?? metrics.operations?.successfulOperations) ?? 0;
    const failOps = (metrics.operations?.failed ?? metrics.operations?.failedOperations) ?? 0;
    const performanceScore = totalOps > 0 ? successOps / totalOps : 1;

    q.overall =
      insightScore * insightWeight +
      contradictionScore * contradictionWeight +
      performanceScore * performanceWeight;

    // Calculate availability (uptime in percentage)
    const uptimeMs = Date.now() - this.startTime;
    q.availability = 100; // Assume full availability unless degraded

    // Calculate error rate
    q.errorRate = totalOps > 0 ? failOps / totalOps : 0;

    // Store quality snapshot
    if (this.config.qualityMetrics) {
      const snapshot: AIQualitySnapshot = {
        timestamp,
        insightAccuracy: metrics.insights?.accuracy ?? 0,
        contradictionDetectionAccuracy: metrics.contradiction?.accuracy ?? 0,
        semanticSearchRelevance: 0, // Not tracked yet
        userSatisfactionScore: q.userSatisfactionScore,
        falsePositiveRate: 0, // Not tracked yet
        falseNegativeRate: 0, // Not tracked yet
        averageConfidence:
          ((metrics.insights?.averageConfidence ?? 0) + (metrics.contradiction?.averageConfidence ?? 0)) / 2,
        qualityScore: q.overall,
      };

      this.qualityHistory.push(snapshot);
    }
  }

  /**
   * Cleanup old data based on retention period
   */
  private cleanupOldData(now: number): void {
    const cutoffTime = now - this.config.retentionPeriod;

    // Cleanup operation history
    for (const [id, operation] of this.operationHistory.entries()) {
      if (operation.startTime < cutoffTime) {
        this.operationHistory.delete(id);
      }
    }

    // Cleanup quality history
    this.qualityHistory = this.qualityHistory.filter(
      (snapshot) => snapshot.timestamp >= cutoffTime
    );

    // Cleanup resource history
    this.resourceHistory = this.resourceHistory.filter(
      (snapshot) => snapshot.timestamp >= cutoffTime
    );
  }
}

/**
 * Default AI metrics service instance
 */
export const aiMetricsService = new AIMetricsService();
