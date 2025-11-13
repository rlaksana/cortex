/**
 * Logging Service Type Definitions
 *
 * Comprehensive type definitions for the logging service including
 * log entries, configurations, and operation results.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'fatal';

export interface LogEntry {
  level: LogLevel;
  message: string;
  context?: Record<string, unknown>;
  correlationId?: string;
  timestamp: string;
  service?: string;
  version?: string;
  userId?: string;
  sessionId?: string;
  requestId?: string;
  traceId?: string;
  spanId?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface LogQueryOptions {
  level?: LogLevel | LogLevel[];
  timeRange?: {
    start: Date;
    end: Date;
  };
  context?: Record<string, unknown>;
  contextFilters?: {
    [key: string]: unknown | unknown[];
  };
  messagePattern?: RegExp | string;
  correlationId?: string;
  userId?: string;
  service?: string;
  limit?: number;
  offset?: number;
  sortBy?: 'timestamp' | 'level' | 'message';
  sortOrder?: 'asc' | 'desc';
}

export interface LogSearchResult {
  logs: LogEntry[];
  total: number;
  hasMore: boolean;
  nextOffset?: number;
  searchTime: number;
}

export interface LogFilterOptions {
  levels: LogLevel[];
  timeRange: {
    start: Date;
    end: Date;
  };
  contextFilters: {
    [key: string]: unknown | unknown[];
  };
  messagePattern?: RegExp | string;
  tags?: string[];
  excludePatterns?: RegExp[];
}

export interface LogStorageConfig {
  type: 'file' | 'database' | 'cloud' | 'hybrid';
  directory?: string;
  maxSize?: string; // e.g., '100MB'
  maxFiles?: number;
  compression?: boolean;
  encryption?: boolean;
  backupLocation?: string;
  connectionConfig?: unknown;
  retryPolicy?: {
    attempts: number;
    backoffMs: number;
    maxBackoffMs: number;
  };
}

export interface LogRetentionConfig {
  defaultDays: number;
  errorDays: number;
  auditDays: number;
  debugDays?: number;
  cleanupInterval: string; // e.g., '1h', '24h'
  archiveLocation?: string;
  compressionFormat?: 'gzip' | 'zip' | 'lz4';
  deleteAfterArchive?: boolean;
}

export interface LogStreamingConfig {
  enabled: boolean;
  bufferSize: number;
  flushInterval: number; // milliseconds
  retryAttempts: number;
  subscribers?: string[];
  protocols?: {
    websocket?: boolean;
    sse?: boolean;
    tcp?: boolean;
    udp?: boolean;
  };
  authentication?: {
    enabled: boolean;
    tokenRequired: boolean;
    allowedOrigins: string[];
  };
}

export interface LogAnalyticsConfig {
  enabled: boolean;
  metricsInterval: number; // milliseconds
  aggregationWindow: number; // milliseconds
  metrics: string[];
  retentionDays?: number;
  exportFormat?: 'json' | 'csv' | 'parquet';
  dashboard?: {
    enabled: boolean;
    refreshInterval: number;
    widgets: string[];
  };
}

export interface LogSecurityConfig {
  masking: {
    enabled: boolean;
    patterns: string[];
    replacement: string;
    customPatterns?: Array<{
      name: string;
      pattern: RegExp;
      replacement: string;
    }>;
  };
  accessControl: {
    enabled: boolean;
    roles: {
      [role: string]: string[];
    };
    defaultRole: string;
    ipWhitelist?: string[];
    tokenValidation?: boolean;
  };
  encryption: {
    enabled: boolean;
    algorithm: string;
    keyRotationDays: number;
    keyProvider?: 'local' | 'aws' | 'azure' | 'gcp';
  };
  audit: {
    enabled: boolean;
    accessLogging: boolean;
    modificationLogging: boolean;
    exportLogging: boolean;
  };
}

export interface LogAnalytics {
  logVolume: {
    total: number;
    byLevel: Record<LogLevel, number>;
    byService: Record<string, number>;
    timeWindow: string;
  };
  errorRate: {
    current: number;
    trend: 'increasing' | 'decreasing' | 'stable';
    threshold: number;
  };
  averageResponseTime: number;
  throughput: number;
  memoryUsage: {
    current: number;
    peak: number;
    threshold: number;
  };
  diskUsage: {
    current: number;
    available: number;
    threshold: number;
  };
}

export interface LogHealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  uptime: number;
  lastCheck: string;
  components: {
    storage: 'healthy' | 'degraded' | 'unhealthy';
    buffer: 'healthy' | 'degraded' | 'unhealthy';
    queue: 'healthy' | 'degraded' | 'unhealthy';
    analytics: 'healthy' | 'degraded' | 'unhealthy';
  };
  memoryUsage: {
    current: number;
    peak: number;
    limit: number;
  };
  diskUsage: {
    current: number;
    available: number;
    limit: number;
  };
  bufferStatus: {
    size: number;
    capacity: number;
    utilizationRate: number;
  };
  queueStatus: {
    size: number;
    processingRate: number;
    errorRate: number;
  };
}

export interface LogArchiveResult {
  success: boolean;
  archivePath: string;
  originalSize: number;
  compressedSize: number;
  compressionRatio: number;
  archivedFiles: string[];
  errors?: string[];
}

export interface LogCleanupResult {
  deletedFiles: number;
  freedSpace: number;
  archivedFiles: number;
  errors: string[];
  duration: number;
}

export interface LogBatchResult {
  successful: number;
  failed: number;
  duration: number;
  errors: Array<{
    entry: LogEntry;
    error: string;
  }>;
}

export interface LogAlert {
  type: 'error_rate' | 'log_volume' | 'response_time' | 'storage' | 'memory';
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  current: number;
  threshold: number;
  timestamp: string;
  resolved?: boolean;
  resolvedAt?: string;
}

export interface LogStream {
  subscribe: (callback: (log: LogEntry) => void) => string;
  unsubscribe: (subscriptionId: string) => void;
  pause: () => void;
  resume: () => void;
  close: () => void;
  isActive: boolean;
  subscriberCount: number;
}

export interface LogComplianceReport {
  regulation: string;
  period: {
    start: string;
    end: string;
  };
  dataAccessEvents: {
    total: number;
    byUser: Record<string, number>;
    byDataType: Record<string, number>;
  };
  dataModifications: {
    total: number;
    byUser: Record<string, number>;
    byType: Record<string, number>;
  };
  dataRetention: {
    totalRecords: number;
    retentionPoliciesApplied: number;
    expiredRecordsDeleted: number;
  };
  securityEvents: {
    total: number;
    byType: Record<string, number>;
    bySeverity: Record<string, number>;
  };
  auditTrail: {
    完整性Verified: boolean;
    tamperingDetected: boolean;
    lastVerification: string;
  };
  generatedAt: string;
  generatedBy: string;
}

export interface LogServiceIntegration {
  serviceName: string;
  correlationId: string;
  metadata: {
    version: string;
    environment: string;
    region?: string;
    deployment?: string;
  };
  endpoints?: {
    health: string;
    metrics: string;
    logs: string;
  };
  authentication?: {
    type: 'jwt' | 'api_key' | 'oauth';
    credentials: unknown;
  };
}

export interface LogTemplate {
  id: string;
  name: string;
  template: string;
  variables: string[];
  category: string;
  description?: string;
  examples?: Array<{
    name: string;
    variables: Record<string, unknown>;
    result: string;
  }>;
}

export interface LogAggregationOptions {
  groupBy: string[];
  timeWindow: string;
  metrics: string[];
  filters?: Record<string, unknown>;
  sortOrder?: 'asc' | 'desc';
  limit?: number;
}

export interface LogAggregation {
  groups: Array<{
    key: Record<string, unknown>;
    metrics: Record<string, number>;
  }>;
  timeRange: {
    start: string;
    end: string;
  };
  totalGroups: number;
  executionTime: number;
}

export interface LogCorrelationContext {
  correlationId: string;
  traceId?: string;
  spanId?: string;
  parentSpanId?: string;
  service?: string;
  version?: string;
  userId?: string;
  sessionId?: string;
  tags?: Record<string, string>;
  baggage?: Record<string, string>;
}

export interface LogWriteOptions {
  async?: boolean;
  priority?: 'low' | 'normal' | 'high' | 'critical';
  retryAttempts?: number;
  timeout?: number;
  skipBuffer?: boolean;
  compress?: boolean;
  encrypt?: boolean;
}

export interface LogWriteResult {
  success: boolean;
  logId?: string;
  timestamp: string;
  duration: number;
  buffered?: boolean;
  error?: string;
}

export interface LogMetrics {
  timestamp: string;
  counters: Record<string, number>;
  gauges: Record<string, number>;
  histograms: Record<
    string,
    {
      count: number;
      sum: number;
      min: number;
      max: number;
      buckets: Record<string, number>;
    }
  >;
  timers: Record<
    string,
    {
      count: number;
      sum: number;
      min: number;
      max: number;
      mean: number;
      median: number;
      p95: number;
      p99: number;
    }
  >;
}

export interface LogConfiguration {
  storage: LogStorageConfig;
  retention: LogRetentionConfig;
  streaming: LogStreamingConfig;
  analytics: LogAnalyticsConfig;
  security: LogSecurityConfig;
  templates?: LogTemplate[];
  performance?: {
    maxConcurrentWrites: number;
    batchSize: number;
    flushInterval: number;
    compressionThreshold: number;
  };
  monitoring?: {
    healthCheckInterval: number;
    metricsInterval: number;
    alertThresholds: Record<string, number>;
  };
}
