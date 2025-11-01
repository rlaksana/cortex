/**
 * Monitoring Service Mocks for CI Testing
 *
 * Provides consistent mocks for monitoring services to ensure
 * tests don't generate noise in CI logs or depend on external systems.
 */

import { vi } from 'vitest';

// Mock structured logger
export const mockStructuredLogger = {
  // Logging methods
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  trace: vi.fn(),

  // Structured logging
  logOperation: vi.fn(),
  logPerformance: vi.fn(),
  logError: vi.fn(),
  logAudit: vi.fn(),
  logSecurity: vi.fn(),

  // Context logging
  withContext: vi.fn().mockReturnThis(),
  withOperationId: vi.fn().mockReturnThis(),
  withUserId: vi.fn().mockReturnThis(),
  withMetadata: vi.fn().mockReturnThis(),

  // Batch operations
  logBatch: vi.fn(),
  flush: vi.fn().mockResolvedValue(true),

  // Metrics
  getMetrics: vi.fn().mockReturnValue({
    totalLogs: 0,
    errorCount: 0,
    warnCount: 0,
    debugCount: 0,
    lastLogTime: null,
  }),

  // Configuration
  setLevel: vi.fn(),
  getLevel: vi.fn().mockReturnValue('info'),
  isEnabled: vi.fn().mockReturnValue(true),
};

// Mock metrics service
export const mockMetricsService = {
  // Counter operations
  incrementCounter: vi.fn(),
  incrementCounterBy: vi.fn(),
  getCounter: vi.fn().mockReturnValue(0),
  resetCounter: vi.fn(),

  // Gauge operations
  setGauge: vi.fn(),
  incrementGauge: vi.fn(),
  decrementGauge: vi.fn(),
  getGauge: vi.fn().mockReturnValue(0),

  // Histogram operations
  recordHistogram: vi.fn(),
  recordDuration: vi.fn(),
  getHistogramStats: vi.fn().mockReturnValue({
    count: 0,
    sum: 0,
    min: 0,
    max: 0,
    mean: 0,
    p50: 0,
    p95: 0,
    p99: 0,
  }),

  // Timer operations
  startTimer: vi.fn().mockReturnValue({
    stop: vi.fn().mockReturnValue(100),
    end: vi.fn().mockReturnValue(100),
  }),

  // Batch operations
  recordMultiple: vi.fn(),
  flushMetrics: vi.fn().mockResolvedValue(true),

  // System metrics
  getSystemMetrics: vi.fn().mockResolvedValue({
    memory: {
      used: 100 * 1024 * 1024, // 100MB
      total: 1024 * 1024 * 1024, // 1GB
      percentage: 9.77,
    },
    cpu: {
      usage: 25.5,
      loadAverage: [1.2, 1.1, 1.0],
    },
    disk: {
      used: 500 * 1024 * 1024, // 500MB
      total: 10 * 1024 * 1024 * 1024, // 10GB
      percentage: 4.88,
    },
  }),

  // Export metrics
  exportMetrics: vi.fn().mockResolvedValue({
    timestamp: new Date().toISOString(),
    metrics: {},
  }),

  // Health check
  healthCheck: vi.fn().mockResolvedValue({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: 3600,
  }),
};

// Mock slow query logger
export const mockSlowQueryLogger = {
  // Query logging
  logSlowQuery: vi.fn(),
  logQueryAnalysis: vi.fn(),
  logPerformanceRegression: vi.fn(),

  // Query analysis
  analyzeQuery: vi.fn().mockReturnValue({
    complexity: 'medium',
    optimizationSuggestions: [],
    estimatedImprovement: 0,
  }),

  // Alerting
  checkThresholds: vi.fn().mockReturnValue({
    alerts: [],
    thresholdBreached: false,
  }),

  // Reporting
  getSlowQueries: vi.fn().mockReturnValue([]),
  getSlowQueryReport: vi.fn().mockReturnValue({
    totalQueries: 0,
    slowQueries: 0,
    averageDuration: 0,
    slowestQueries: [],
  }),

  // Cleanup
  clearOldQueries: vi.fn().mockResolvedValue(0),
  getRetentionStats: vi.fn().mockReturnValue({
    totalQueries: 0,
    oldQueries: 0,
    retentionRate: 1.0,
  }),
};

// Mock performance collector
export const mockPerformanceCollector = {
  // Performance tracking
  startOperation: vi.fn().mockReturnValue('mock-operation-id'),
  endOperation: vi.fn(),
  recordMetric: vi.fn(),

  // Analysis
  analyzePerformance: vi.fn().mockReturnValue({
    averageDuration: 100,
    p95Duration: 200,
    p99Duration: 300,
    totalOperations: 0,
    slowOperations: [],
  }),

  // Reporting
  generateReport: vi.fn().mockReturnValue({
    timestamp: new Date().toISOString(),
    summary: {
      totalOperations: 0,
      averageDuration: 0,
      slowOperations: 0,
    },
    details: [],
  }),

  // Thresholds
  setThresholds: vi.fn(),
  checkThresholds: vi.fn().mockReturnValue([]),
  getThresholds: vi.fn().mockReturnValue({
    warning: 1000,
    critical: 5000,
  }),

  // Export
  exportData: vi.fn().mockResolvedValue({
    timestamp: new Date().toISOString(),
    data: [],
  }),
};

// Mock telemetry service
export const mockTelemetryService = {
  // Event tracking
  trackEvent: vi.fn(),
  trackUserAction: vi.fn(),
  trackSystemEvent: vi.fn(),
  trackError: vi.fn(),

  // Metrics collection
  collectMetrics: vi.fn().mockResolvedValue({
    timestamp: new Date().toISOString(),
    metrics: {
      events: 0,
      errors: 0,
      performance: {},
    },
  }),

  // Session tracking
  startSession: vi.fn().mockReturnValue('mock-session-id'),
  endSession: vi.fn(),
  updateSession: vi.fn(),

  // Health and status
  healthCheck: vi.fn().mockResolvedValue({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: 3600,
  }),

  // Configuration
  configure: vi.fn(),
  isEnabled: vi.fn().mockReturnValue(true),
  getConfiguration: vi.fn().mockReturnValue({
    enabled: true,
    samplingRate: 1.0,
    batchSize: 100,
  }),
};

// Mock health check service
export const mockHealthCheckService = {
  // Health checks
  checkHealth: vi.fn().mockResolvedValue({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    services: {
      database: { status: 'healthy', latency: 5 },
      embeddings: { status: 'healthy', latency: 15 },
      cache: { status: 'healthy', latency: 1 },
    },
  }),

  checkServiceHealth: vi.fn().mockImplementation(async (serviceName: string) => {
    return {
      service: serviceName,
      status: 'healthy',
      latency: Math.random() * 50 + 1,
      lastCheck: new Date().toISOString(),
    };
  }),

  // Detailed health report
  generateHealthReport: vi.fn().mockResolvedValue({
    timestamp: new Date().toISOString(),
    overallStatus: 'healthy',
    services: {},
    uptime: 3600,
    version: '1.0.0',
  }),

  // Monitoring
  startMonitoring: vi.fn(),
  stopMonitoring: vi.fn(),
  isMonitoring: vi.fn().mockReturnValue(false),

  // Alerts
  checkAlerts: vi.fn().mockReturnValue([]),
  createAlert: vi.fn(),
  resolveAlert: vi.fn(),
  getActiveAlerts: vi.fn().mockReturnValue([]),
};

// Test utilities for monitoring testing
export const monitoringTestHelpers = {
  /**
   * Create a mock log entry
   */
  createMockLogEntry: (level: string = 'info', message: string = 'Test message') => ({
    level,
    message,
    timestamp: new Date().toISOString(),
    metadata: { test: true },
  }),

  /**
   * Create a mock metric value
   */
  createMockMetric: (name: string, value: number, type: string = 'counter') => ({
    name,
    value,
    type,
    timestamp: new Date().toISOString(),
    labels: { test: true },
  }),

  /**
   * Create a mock performance metric
   */
  createMockPerformanceMetric: (operation: string, duration: number) => ({
    operation,
    duration,
    timestamp: new Date().toISOString(),
    success: true,
    metadata: { test: true },
  }),

  /**
   * Assert logging behavior
   */
  assertLoggingBehavior: (mockFn: any, expectedLevel: string, expectedMessage: string) => {
    expect(mockFn).toHaveBeenCalledWith(
      expect.objectContaining({
        level: expectedLevel,
        message: expect.stringContaining(expectedMessage),
      })
    );
  },

  /**
   * Assert metric recording
   */
  assertMetricRecorded: (mockFn: any, expectedName: string, expectedValue: number) => {
    expect(mockFn).toHaveBeenCalledWith(
      expectedName,
      expectedValue,
      expect.any(Object) // metadata
    );
  },

  /**
   * Create test performance data
   */
  createTestPerformanceData: (count: number = 10) => {
    return Array.from({ length: count }, (_, index) => ({
      operation: `test-operation-${index}`,
      duration: Math.random() * 1000 + 10,
      timestamp: new Date(Date.now() - index * 1000).toISOString(),
      success: Math.random() > 0.1, // 90% success rate
    }));
  },

  /**
   * Reset all monitoring mocks
   */
  resetMonitoringMocks: () => {
    Object.values(mockStructuredLogger).forEach(method => {
      if (vi.isMockFunction(method)) {
        vi.clearAllMocks();
      }
    });
    Object.values(mockMetricsService).forEach(method => {
      if (vi.isMockFunction(method)) {
        vi.clearAllMocks();
      }
    });
    Object.values(mockSlowQueryLogger).forEach(method => {
      if (vi.isMockFunction(method)) {
        vi.clearAllMocks();
      }
    });
  },
};

// Export for use in tests
export {
  mockStructuredLogger as structuredLogger,
  mockMetricsService as metricsService,
  mockSlowQueryLogger as slowQueryLogger,
  mockPerformanceCollector as performanceCollector,
  mockTelemetryService as telemetryService,
  mockHealthCheckService as healthCheckService,
};