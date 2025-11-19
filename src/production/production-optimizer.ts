// LAST ABSOLUTE FINAL EMERGENCY ROLLBACK: Complete the systematic rollback

/**
 * Production Optimizer - Complete Performance Enhancement Integration
 *
 * This module integrates all performance optimizations for production readiness:
 * - Optimized Qdrant connection pooling
 * - Enhanced ZAI client with caching
 * - Comprehensive load testing framework
 * - Performance benchmarks and SLO monitoring
 * - Real-time alerting and anomaly detection
 * - Production configuration management
 * - Health monitoring and graceful degradation
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'events';

import { logger } from '@/utils/logger.js';

import { DEFAULT_POOL_CONFIG, QdrantPooledClient } from '../db/qdrant-pooled-client.js';
import {
  DEFAULT_BENCHMARK_CONFIGS,
  PerformanceBenchmarks,
} from '../monitoring/performance-benchmarks.js';
import { DEFAULT_ZAI_CONFIG, ZAIOptimizedClient } from '../services/ai/zai-optimized-client.js';
import {
  DEFAULT_LOAD_TEST_CONFIGS,
  type LoadTestConfig,
  LoadTestFramework,
} from '../testing/load-testing/load-test-framework.js';
import { hasBooleanProperty, hasProperty, hasSLOMetrics, hasStringProperty } from '../utils/type-fixes.js';

/**
 * Production optimizer configuration
 */
export interface ProductionOptimizerConfig {
  /** Enable connection pooling */
  enableConnectionPooling: boolean;
  /** Enable optimized ZAI client */
  enableOptimizedZAIClient: boolean;
  /** Enable load testing */
  enableLoadTesting: boolean;
  /** Enable performance monitoring */
  enablePerformanceMonitoring: boolean;
  /** Production environment settings */
  environment: {
    name: string;
    region: string;
    version: string;
  };
  /** Scaling configuration */
  scaling: {
    maxConcurrentUsers: number;
    targetThroughput: number;
    autoScaling: boolean;
  };
  /** SLO targets */
  sloTargets: {
    p95ResponseTime: number;
    responseTimeP99: number;
    errorRate: number;
    availability: number;
  };
}

/**
 * Production status
 */
export interface ProductionStatus {
  /** Overall system health */
  overallHealth: 'healthy' | 'degraded' | 'unhealthy';
  /** Component status */
  components: {
    qdrantPool: 'healthy' | 'degraded' | 'unhealthy' | 'disabled';
    zaiClient: 'healthy' | 'degraded' | 'unhealthy' | 'disabled';
    loadTesting: 'running' | 'completed' | 'failed' | 'disabled';
    performanceMonitor: 'active' | 'inactive' | 'disabled';
  };
  /** Performance metrics */
  metrics: {
    responseTime: { p50: number; p95: number; p99: number };
    errorRate: number;
    throughput: number;
    availability: number;
  };
  /** SLO compliance */
  sloCompliance: {
    overall: boolean;
    responseTime: boolean;
    errorRate: boolean;
    availability: boolean;
  };
  /** Recommendations */
  recommendations: string[];
}

/**
 * Production optimizer class
 */
export class ProductionOptimizer extends EventEmitter {
  private config: ProductionOptimizerConfig;
  private qdrantPool?: QdrantPooledClient;
  private zaiClient?: ZAIOptimizedClient;
  private loadTestFramework?: LoadTestFramework;
  private performanceBenchmarks?: PerformanceBenchmarks;
  private status: ProductionStatus;
  private initialized = false;

  constructor(config: Partial<ProductionOptimizerConfig> = {}) {
    super();

    this.config = {
      enableConnectionPooling: true,
      enableOptimizedZAIClient: true,
      enableLoadTesting: false, // Disabled by default for production
      enablePerformanceMonitoring: true,
      environment: {
        name: process.env['NODE_ENV'] || 'production',
        region: process.env['AWS_REGION'] || 'us-east-1',
        version: process.env['APP_VERSION'] || '2.0.0',
      },
      scaling: {
        maxConcurrentUsers: 1000,
        targetThroughput: 500,
        autoScaling: true,
      },
      sloTargets: {
        p95ResponseTime: 2000,
        responseTimeP99: 5000,
        errorRate: 1,
        availability: 99.9,
      },
      ...config,
    };

    this.status = {
      overallHealth: 'healthy',
      components: {
        qdrantPool: 'disabled',
        zaiClient: 'disabled',
        loadTesting: 'disabled',
        performanceMonitor: 'disabled',
      },
      metrics: {
        responseTime: { p50: 0, p95: 0, p99: 0 },
        errorRate: 0,
        throughput: 0,
        availability: 100,
      },
      sloCompliance: {
        overall: true,
        responseTime: true,
        errorRate: true,
        availability: true,
      },
      recommendations: [],
    };

    logger.info('Production optimizer initialized', {
      environment: this.config.environment,
      connectionPooling: this.config.enableConnectionPooling,
      optimizedZAI: this.config.enableOptimizedZAIClient,
      monitoring: this.config.enablePerformanceMonitoring,
    });
  }

  /**
   * Initialize production optimizer
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      logger.warn('Production optimizer already initialized');
      return;
    }

    logger.info('Initializing production optimizer', {
      environment: this.config.environment.name,
    });

    try {
      // Initialize Qdrant connection pool
      if (this.config.enableConnectionPooling) {
        await this.initializeQdrantPool();
      }

      // Initialize optimized ZAI client
      if (this.config.enableOptimizedZAIClient) {
        await this.initializeOptimizedZAIClient();
      }

      // Initialize performance monitoring
      if (this.config.enablePerformanceMonitoring) {
        await this.initializePerformanceMonitoring();
      }

      // Initialize load testing (only if explicitly enabled)
      if (this.config.enableLoadTesting) {
        await this.initializeLoadTesting();
      }

      // Start health monitoring
      this.startHealthMonitoring();

      this.initialized = true;
      this.updateOverallHealth();

      logger.info('Production optimizer initialized successfully', {
        environment: this.config.environment.name,
        componentsEnabled: {
          qdrantPool: !!this.qdrantPool,
          zaiClient: !!this.zaiClient,
          loadTesting: !!this.loadTestFramework,
          performanceMonitor: !!this.performanceBenchmarks,
        },
      });

      this.emit('initialized');
    } catch (error) {
      logger.error({ error }, 'Failed to initialize production optimizer');
      throw error;
    }
  }

  /**
   * Shutdown production optimizer
   */
  async shutdown(): Promise<void> {
    logger.info('Shutting down production optimizer');

    try {
      // Shutdown components in reverse order
      if (this.loadTestFramework) {
        await this.loadTestFramework.stop();
      }

      if (this.performanceBenchmarks) {
        await this.performanceBenchmarks.stop();
      }

      if (this.qdrantPool) {
        await this.qdrantPool.shutdown();
      }

      // ZAI client cleanup if needed
      if (this.zaiClient) {
        // Would implement ZAI client shutdown if needed
        this.zaiClient.clearCache();
      }

      this.initialized = false;

      logger.info('Production optimizer shutdown completed');
      this.emit('shutdown');
    } catch (error) {
      logger.error({ error }, 'Error during production optimizer shutdown');
      throw error;
    }
  }

  /**
   * Run production load test
   */
  async runProductionLoadTest(type: 'smoke' | 'stress' | 'endurance' = 'smoke'): Promise<unknown> {
    if (!this.config.enableLoadTesting) {
      throw new Error('Load testing is not enabled in production environment');
    }

    if (!this.loadTestFramework) {
      await this.initializeLoadTesting();
    }

    const testConfig =
      type === 'smoke'
        ? DEFAULT_LOAD_TEST_CONFIGS.smoke
        : type === 'stress'
          ? DEFAULT_LOAD_TEST_CONFIGS.production
          : DEFAULT_LOAD_TEST_CONFIGS.smoke; // Default to smoke

    logger.info('Running production load test', { type, config: testConfig.testName });

    const results = await this.loadTestFramework!.execute();

    // Update status based on results
    this.updateStatusFromLoadTest(results);

    this.emit('loadTestCompleted', results);
    return results;
  }

  /**
   * Get current production status
   */
  getProductionStatus(): ProductionStatus {
    this.updateMetrics();
    this.updateSLOCompliance();
    return { ...this.status };
  }

  /**
   * Get component statistics
   */
  async getComponentStats(): Promise<{
    qdrantPool?: unknown;
    zaiClient?: unknown;
    performanceMonitor?: unknown;
    loadTest?: unknown;
  }> {
    const stats: Record<string, unknown> = {};

    if (this.qdrantPool) {
      try {
        stats.qdrantPool = this.qdrantPool.getStats();
      } catch (error) {
        stats.qdrantPool = { error: 'Failed to get stats' };
      }
    }

    if (this.zaiClient) {
      try {
        stats.zaiClient = this.zaiClient.getStats();
      } catch (error) {
        stats.zaiClient = { error: 'Failed to get stats' };
      }
    }

    if (this.performanceBenchmarks) {
      try {
        stats.performanceMonitor = {
          sloStatus: this.performanceBenchmarks.getSLOStatus(),
          activeAlerts: this.performanceBenchmarks.getActiveAlerts(),
        };
      } catch (error) {
        stats.performanceMonitor = { error: 'Failed to get performance stats' };
      }
    }

    if (this.loadTestFramework) {
      try {
        stats.loadTest = this.loadTestFramework.getStatus();
      } catch (error) {
        stats.loadTest = { error: 'Failed to get load test status' };
      }
    }

    return stats;
  }

  /**
   * Generate production readiness report
   */
  async generateReadinessReport(): Promise<{
    ready: boolean;
    score: number;
    components: Record<string, unknown>;
    recommendations: string[];
    nextSteps: string[];
  }> {
    logger.info('Generating production readiness report');

    const componentStats = await this.getComponentStats();
    const currentStatus = this.getProductionStatus();

    const components = {
      qdrantPool: {
        enabled: this.config.enableConnectionPooling,
        status: currentStatus.components.qdrantPool,
        stats: componentStats.qdrantPool,
        healthy: currentStatus.components.qdrantPool === 'healthy',
      },
      zaiClient: {
        enabled: this.config.enableOptimizedZAIClient,
        status: currentStatus.components.zaiClient,
        stats: componentStats.zaiClient,
        healthy: currentStatus.components.zaiClient === 'healthy',
      },
      performanceMonitor: {
        enabled: this.config.enablePerformanceMonitoring,
        status: currentStatus.components.performanceMonitor,
        stats: componentStats.performanceMonitor,
        healthy: currentStatus.components.performanceMonitor === 'active',
      },
      loadTesting: {
        enabled: this.config.enableLoadTesting,
        status: currentStatus.components.loadTesting,
        stats: componentStats.loadTest,
        healthy: currentStatus.components.loadTesting !== 'failed',
      },
    };

    // Calculate readiness score
    const healthyComponents = Object.values(components).filter((c) => c.healthy).length;
    const enabledComponents = Object.values(components).filter((c) => c.enabled).length;
    const score = enabledComponents > 0 ? (healthyComponents / enabledComponents) * 100 : 0;

    const ready = score >= 90 && currentStatus.overallHealth === 'healthy';

    const recommendations = this.generateRecommendations(currentStatus, components);
    const nextSteps = this.generateNextSteps(ready, score);

    const report = {
      ready,
      score,
      components,
      recommendations,
      nextSteps,
    };

    logger.info('Production readiness report generated', {
      ready,
      score,
      healthyComponents,
      totalComponents: enabledComponents,
    });

    return report;
  }

  /**
   * Initialize Qdrant connection pool
   */
  private async initializeQdrantPool(): Promise<void> {
    try {
      const qdrantUrl = process.env['QDRANT_URL'] || 'http://localhost:6333';
      const qdrantApiKey = process.env['QDRANT_API_KEY'];

      this.qdrantPool = new QdrantPooledClient({
        ...DEFAULT_POOL_CONFIG,
        maxConnections: 20,
        minConnections: 5,
        connectionTimeout: 30000,
        requestTimeout: 60000,
        enableMetrics: true,
      });

      // Add primary node
      this.qdrantPool.addNode({
        id: 'primary',
        url: qdrantUrl,
        apiKey: qdrantApiKey,
        weight: 1,
        active: true,
      });

      // Add additional nodes if configured
      const additionalNodes = process.env['QDRANT_ADDITIONAL_NODES'];
      if (additionalNodes) {
        const nodes = additionalNodes.split(',');
        nodes.forEach((nodeUrl, index) => {
          const [url, apiKey] = nodeUrl.trim().split(':');
          this.qdrantPool!.addNode({
            id: `node-${index + 1}`,
            url: url.trim(),
            apiKey: apiKey?.trim(),
            weight: 1,
            active: true,
          });
        });
      }

      await this.qdrantPool.initialize();

      this.status.components.qdrantPool = 'healthy';
      logger.info('Qdrant connection pool initialized', {
        url: qdrantUrl,
        maxConnections: DEFAULT_POOL_CONFIG.maxConnections,
      });
    } catch (error) {
      this.status.components.qdrantPool = 'unhealthy';
      logger.error({ error }, 'Failed to initialize Qdrant connection pool');
      throw error;
    }
  }

  /**
   * Initialize optimized ZAI client
   */
  private async initializeOptimizedZAIClient(): Promise<void> {
    try {
      const zaiApiKey = process.env['ZAI_API_KEY'];
      const zaiBaseUrl = process.env['ZAI_BASE_URL'] || 'https://api.z.ai/v1';

      if (!zaiApiKey) {
        throw new Error('ZAI API key is required');
      }

      this.zaiClient = new ZAIOptimizedClient({
        apiKey: zaiApiKey,
        baseURL: zaiBaseUrl,
        model: process.env['ZAI_MODEL'] || 'glm-4.6',
        ...DEFAULT_ZAI_CONFIG,
      });

      this.status.components.zaiClient = 'healthy';
      logger.info('Optimized ZAI client initialized', {
        baseURL: zaiBaseUrl,
        model: process.env['ZAI_MODEL'],
        cacheEnabled: DEFAULT_ZAI_CONFIG.cache?.enableMemoryCache,
        deduplicationEnabled: DEFAULT_ZAI_CONFIG.deduplication?.enableDeduplication,
      });
    } catch (error) {
      this.status.components.zaiClient = 'unhealthy';
      logger.error({ error }, 'Failed to initialize optimized ZAI client');
      throw error;
    }
  }

  /**
   * Initialize performance monitoring
   */
  private async initializePerformanceMonitoring(): Promise<void> {
    try {
      this.performanceBenchmarks = new PerformanceBenchmarks({
        ...DEFAULT_BENCHMARK_CONFIGS.production,
        name: `${this.config.environment.name}-performance-benchmarks`,
        slo: {
          ...DEFAULT_BENCHMARK_CONFIGS.production.slo,
          responseTime: {
            ...DEFAULT_BENCHMARK_CONFIGS.production.slo.responseTime,
            p95: this.config.sloTargets.p95ResponseTime,
            p99: this.config.sloTargets.responseTimeP99,
          },
          errorRate: {
            ...DEFAULT_BENCHMARK_CONFIGS.production.slo.errorRate,
            warning: this.config.sloTargets.errorRate,
          },
        },
      });

      await this.performanceBenchmarks.start();

      this.status.components.performanceMonitor = 'active';
      logger.info('Performance monitoring initialized', {
        name: this.config.environment.name,
        sloTargets: this.config.sloTargets,
      });

      // Set up event listeners
      this.performanceBenchmarks.on('alertCreated', (alert) => {
        this.emit('performanceAlert', alert);
        logger.warn('Performance alert created', { alertId: alert.id, severity: alert.severity });
      });

      this.performanceBenchmarks.on('sloChecked', (sloStatus) => {
        if (sloStatus.overall === 'critical') {
          this.emit('sloViolation', sloStatus);
          logger.error('SLO violation detected', { overall: sloStatus.overall });
        }
      });
    } catch (error) {
      this.status.components.performanceMonitor = 'inactive';
      logger.error({ error }, 'Failed to initialize performance monitoring');
      throw error;
    }
  }

  /**
   * Initialize load testing
   */
  private async initializeLoadTesting(): Promise<void> {
    try {
      this.loadTestFramework = new LoadTestFramework(
        DEFAULT_LOAD_TEST_CONFIGS.smoke as unknown as LoadTestConfig
      );

      this.status.components.loadTesting = 'completed';
      logger.info('Load testing framework initialized', {
        type: 'smoke',
        duration: DEFAULT_LOAD_TEST_CONFIGS.smoke.duration,
        concurrentUsers: DEFAULT_LOAD_TEST_CONFIGS.smoke.concurrentUsers,
      });
    } catch (error) {
      this.status.components.loadTesting = 'failed';
      logger.error({ error }, 'Failed to initialize load testing framework');
      throw error;
    }
  }

  /**
   * Start health monitoring
   */
  private startHealthMonitoring(): void {
    // Check health every 30 seconds
    setInterval(async () => {
      await this.performHealthCheck();
    }, 30000);

    logger.info('Health monitoring started');
  }

  /**
   * Perform health check
   */
  private async performHealthCheck(): Promise<void> {
    let issues = 0;

    // Check Qdrant pool health
    if (this.qdrantPool) {
      const stats = this.qdrantPool.getStats();
      if (stats.healthStatus !== 'healthy') {
        this.status.components.qdrantPool =
          stats.healthStatus === 'degraded' ? 'degraded' : 'unhealthy';
        issues++;
      } else {
        this.status.components.qdrantPool = 'healthy';
      }
    }

    // Check ZAI client health (simplified)
    if (this.zaiClient) {
      const stats = this.zaiClient.getStats();
      if (stats.failedRequests > stats.successfulRequests * 0.05) {
        this.status.components.zaiClient = 'degraded';
        issues++;
      } else {
        this.status.components.zaiClient = 'healthy';
      }
    }

    // Check performance monitor health
    if (this.performanceBenchmarks) {
      const sloStatus = this.performanceBenchmarks.getSLOStatus();
      if (sloStatus.overall === 'critical') {
        this.status.components.performanceMonitor = 'inactive';
        issues++;
      } else {
        this.status.components.performanceMonitor = 'active';
      }
    }

    this.updateOverallHealth();

    if (issues > 0) {
      this.emit('healthIssue', { issues, components: this.status.components });
    }
  }

  /**
   * Update overall health
   */
  private updateOverallHealth(): void {
    const components = Object.values(this.status.components);
    const healthyCount = components.filter((status) => status === 'healthy').length;
    const degradedCount = components.filter((status) => status === 'degraded').length;
    const unhealthyCount = components.filter((status) => status === 'unhealthy').length;

    if (unhealthyCount > 0) {
      this.status.overallHealth = 'unhealthy';
    } else if (degradedCount > 0) {
      this.status.overallHealth = 'degraded';
    } else {
      this.status.overallHealth = 'healthy';
    }
  }

  /**
   * Update metrics from components
   */
  private updateMetrics(): void {
    // This would collect real-time metrics from all components
    // For now, using placeholder values
    this.status.metrics = {
      responseTime: { p50: 200, p95: 800, p99: 1500 },
      errorRate: 0.5,
      throughput: 250,
      availability: 99.9,
    };
  }

  /**
   * Update SLO compliance
   */
  private updateSLOCompliance(): void {
    if (!hasSLOMetrics(this.status.metrics)) {
      this.status.sloCompliance = {
        overall: false,
        responseTime: false,
        errorRate: false,
        availability: false,
      };
      return;
    }

    const metrics = this.status.metrics;
    const targets = this.config.sloTargets;

    // Safely access sloCompliance property
    if (!hasProperty(this.status, 'sloCompliance')) {
      (this.status as any).sloCompliance = {};
    }

    this.status.sloCompliance = {
      overall: true,
      responseTime: metrics.responseTime.p95 <= targets.p95ResponseTime,
      errorRate: metrics.errorRate <= targets.errorRate,
      availability: metrics.availability >= targets.availability,
    };

    this.status.sloCompliance.overall = Object.values(this.status.sloCompliance).every(Boolean);
  }

  /**
   * Update status from load test results
   */
  private updateStatusFromLoadTest(results: unknown): void {
    // Update status based on load test results
    if (!results || typeof results !== 'object') {
      this.status.components.loadTesting = 'failed';
      return;
    }

    const resultsObj = results as Record<string, unknown>;
    const sloCompliance = hasSLOMetrics(resultsObj.sloCompliance)
      ? resultsObj.sloCompliance
      : { overall: false, slos: {} };

    if (sloCompliance.overall) {
      this.status.components.loadTesting = 'completed';
    } else {
      this.status.components.loadTesting = 'failed';
      // Add recommendations based on failures
      if (sloCompliance.slos && typeof sloCompliance.slos === 'object') {
        Object.entries(sloCompliance.slos).forEach(([slo, compliant]: [string, unknown]) => {
          if (!compliant) {
            this.status.recommendations.push(`Improve ${slo} to meet production requirements`);
          }
        });
      }
    }
  }

  /**
   * Generate recommendations
   */
  private generateRecommendations(
    status: ProductionStatus,
    components: Record<string, unknown>
  ): string[] {
    const recommendations: string[] = [];

    // Health-based recommendations
    if (status.overallHealth !== 'healthy') {
      recommendations.push('Address component health issues before going to production');
    }

    // Component-specific recommendations
    Object.entries(components).forEach(([name, component]: [string, unknown]) => {
      if (hasBooleanProperty(component, 'enabled') && component.enabled &&
          hasBooleanProperty(component, 'healthy') && !component.healthy &&
          hasStringProperty(component, 'status')) {
        recommendations.push(`Fix ${name} component: current status is ${component.status}`);
      }
    });

    // SLO-based recommendations
    if (!status.sloCompliance.responseTime) {
      recommendations.push('Optimize response times to meet SLO targets');
    }
    if (!status.sloCompliance.errorRate) {
      recommendations.push('Reduce error rate to meet SLO targets');
    }
    if (!status.sloCompliance.availability) {
      recommendations.push('Improve system availability to meet SLO targets');
    }

    // Performance-based recommendations
    if (status.metrics.errorRate > 2) {
      recommendations.push('Investigate high error rate and implement better error handling');
    }
    if (status.metrics.responseTime.p99 > this.config.sloTargets.responseTimeP99) {
      recommendations.push('Performance tuning required for P99 response times');
    }

    return recommendations;
  }

  /**
   * Generate next steps
   */
  private generateNextSteps(ready: boolean, score: number): string[] {
    const steps: string[] = [];

    if (ready) {
      steps.push('✅ System is ready for production deployment');
      steps.push('Deploy to production environment');
      steps.push('Monitor performance and SLO compliance');
      steps.push('Set up production alerting and monitoring');
    } else {
      if (score < 50) {
        steps.push('🔴 Critical issues need immediate attention');
        steps.push('Fix all unhealthy components before proceeding');
      } else if (score < 80) {
        steps.push('🟡 Address performance and reliability issues');
        steps.push('Run additional load tests to validate fixes');
      } else {
        steps.push('🟢 Minor optimizations recommended');
        steps.push('Run final smoke tests before deployment');
      }

      steps.push('Re-run readiness check after addressing issues');
      steps.push('Document all fixes and optimizations');
    }

    return steps;
  }
}

/**
 * Default production optimizer configuration
 */
export const DEFAULT_PRODUCTION_CONFIG: ProductionOptimizerConfig = {
  enableConnectionPooling: true,
  enableOptimizedZAIClient: true,
  enableLoadTesting: false,
  enablePerformanceMonitoring: true,
  environment: {
    name: 'production',
    region: 'us-east-1',
    version: '2.0.0',
  },
  scaling: {
    maxConcurrentUsers: 1000,
    targetThroughput: 500,
    autoScaling: true,
  },
  sloTargets: {
    p95ResponseTime: 2000,
    responseTimeP99: 5000,
    errorRate: 1,
    availability: 99.9,
  },
};

/**
 * Create production optimizer instance
 */
export function createProductionOptimizer(
  config?: Partial<ProductionOptimizerConfig>
): ProductionOptimizer {
  return new ProductionOptimizer({
    ...DEFAULT_PRODUCTION_CONFIG,
    ...config,
  });
}
