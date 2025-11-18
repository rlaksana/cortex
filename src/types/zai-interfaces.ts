/**
 * ZAI Service Interfaces and Types
 *
 * Comprehensive type definitions for ZAI API integration with glm-4.6 model
 * Following Vercel AI SDK patterns and TypeScript best practices
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

/**
 * ZAI API configuration interface
 */
export interface ZAIConfig {
  apiKey: string;
  baseURL?: string;
  url?: string; // Adding url property for compatibility
  model: string;
  timeout?: number;
  maxRetries?: number;
  retries?: number; // Adding retries property for compatibility
  retryDelay?: number;
  retry_delay?: number; // Adding retry_delay property for compatibility
  circuitBreakerThreshold?: number;
  circuitBreakerTimeout?: number;
  enableLogging?: boolean;
  rateLimitRPM?: number;
  // Extended properties for production config
  circuitBreaker?: {
    enabled: boolean;
    threshold: number;
    resetTimeout: number;
    monitoringWindow: number;
  };
  rateLimiting?: {
    enabled: boolean;
    requestsPerMinute: number;
    requestsPerHour: number;
    burstLimit: number;
    backoffStrategy: string;
  };
  authentication?: {
    apiKey: string;
    keyRotationEnabled: boolean;
    keyRotationInterval: number;
  };
}

/**
 * ZAI API message format
 */
export interface ZAIMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
  timestamp?: number;
  metadata?: Record<string, unknown>;
}

/**
 * ZAI chat completion request
 */
export interface ZAIChatRequest {
  messages: ZAIMessage[];
  model?: string;
  temperature?: number;
  maxTokens?: number;
  topP?: number;
  frequencyPenalty?: number;
  presencePenalty?: number;
  stop?: string | string[];
  stream?: boolean;
  user?: string;
  metadata?: Record<string, unknown>;
}

/**
 * ZAI API response choice
 */
export interface ZAIChoice {
  index: number;
  message: ZAIMessage;
  finishReason: 'stop' | 'length' | 'content_filter';
  delta?: Partial<ZAIMessage>;
}

/**
 * ZAI usage information
 */
export interface ZAIUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  estimatedCost?: number;
}

/**
 * ZAI chat completion response
 */
export interface ZAIChatResponse {
  id: string;
  object: 'chat.completion';
  created: number;
  model: string;
  choices: ZAIChoice[];
  usage: ZAIUsage;
  systemFingerprint?: string;
  processingTime?: number;
  cached?: boolean;
}

/**
 * ZAI streaming response chunk
 */
export interface ZAIStreamChunk {
  id: string;
  object: 'chat.completion.chunk';
  created: number;
  model: string;
  choices: ZAIChoice[];
  delta?: Partial<ZAIMessage>;
  finished?: boolean;
}

/**
 * ZAI error response
 */
export interface ZAIErrorResponse {
  error: {
    message: string;
    type: string;
    code?: string;
    param?: string;
  };
}

/**
 * ZAI service status
 */
export interface ZAIServiceStatus {
  status: 'healthy' | 'degraded' | 'down';
  lastCheck: number;
  responseTime: number;
  errorRate: number;
  circuitBreakerState: 'closed' | 'open' | 'half-open';
  consecutiveFailures: number;
  uptime: number;
}

/**
 * ZAI provider metrics
 */
export interface ZAIMetrics {
  timestamp: Date;
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageResponseTime: number;
  p95ResponseTime: number;
  p99ResponseTime: number;
  totalTokensUsed: number;
  totalCost: number;
  cacheHitRate: number;
  errorRate: number;
  uptime: number;
  lastReset: number;
  // Additional properties for compatibility
  requestCount: number;
  successCount: number;
  errorCount: number;
  throughput: number;
  circuitBreakerStatus: 'closed' | 'open' | 'half-open';
  tokensUsed: number;
  cost: number;
}

/**
 * Background job types for ZAI operations
 */
export type ZAIJobType =
  | 'chat_completion'
  | 'batch_completion'
  | 'embedding_generation'
  | 'content_analysis'
  | 'text_transformation'
  | 'summarization'
  | 'classification';

/**
 * ZAI background job interface
 */
export interface ZAIJob {
  id: string;
  type: ZAIJobType;
  priority: 'low' | 'normal' | 'high' | 'critical';
  payload: ZAIChatRequest | unknown;
  options: {
    timeout?: number;
    retries?: number;
    metadata?: Record<string, unknown>;
  };
  status: 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled';
  createdAt: number;
  startedAt?: number;
  completedAt?: number;
  result?: unknown;
  error?: ZAIErrorResponse;
  attempts: number;
  maxAttempts: number;
  timeout?: number; // Adding timeout property for compatibility
  maxRetries?: number; // Adding maxRetries property for compatibility
  metadata?: Record<string, unknown>; // Adding metadata property for compatibility
}

/**
 * Circuit breaker states
 */
export type CircuitBreakerState = 'closed' | 'open' | 'half-open';

/**
 * Circuit breaker configuration
 */
export interface CircuitBreakerConfig {
  failureThreshold: number;
  timeout: number;
  monitoringPeriod: number;
  expectedRecoveryTime: number;
}

/**
 * Circuit breaker interface
 */
export interface CircuitBreaker {
  state: CircuitBreakerState;
  failureCount: number;
  lastFailureTime: number;
  nextAttempt: number;
  config: CircuitBreakerConfig;
}

/**
 * AI provider interface for abstraction
 */
export interface AIProvider {
  name: string;
  model: string;
  isAvailable(): Promise<boolean>;
  generateCompletion(request: ZAIChatRequest): Promise<ZAIChatResponse>;
  generateStreamingCompletion(request: ZAIChatRequest): AsyncGenerator<ZAIStreamChunk>;
  getMetrics(): ZAIMetrics;
  reset(): void;
}

/**
 * AI orchestrator configuration
 */
export interface AIOrchestratorConfig {
  primaryProvider: 'zai' | 'openai';
  fallbackProvider: 'zai' | 'openai';
  autoFailover: boolean;
  healthCheckInterval: number;
  fallbackThreshold: number;
  enabled?: boolean; // Adding enabled property for compatibility
  providerConfigs: {
    zai: ZAIConfig;
    openai: unknown; // OpenAI config if needed
  };
  // Extended properties for production config
  features?: {
    insights: unknown;
    contradiction_detection: unknown;
    semantic_search: unknown;
    background_processing: unknown;
  };
  performance?: {
    latencyTargets: unknown;
    throughputTargets: unknown;
    resourceLimits: unknown;
    caching: unknown;
  };
  quality?: {
    accuracyThresholds: unknown;
    confidenceThresholds: unknown;
    monitoring: unknown;
    fallback: unknown;
  };
}

/**
 * Request queue configuration
 */
export interface RequestQueueConfig {
  maxSize: number;
  concurrency: number;
  timeoutMs: number;
  retryAttempts: number;
  retryDelayMs: number;
  priorityQueue: boolean;
}

/**
 * Rate limiter interface
 */
export interface RateLimiter {
  isAllowed(): Promise<boolean>;
  getRemainingTokens(): number;
  getResetTime(): number;
  reset(): void;
}

/**
 * Cache interface for ZAI responses
 */
export interface ZAICache {
  get(key: string): Promise<ZAIChatResponse | null>;
  set(key: string, value: ZAIChatResponse, ttlMs?: number): Promise<void>;
  delete(key: string): Promise<void>;
  clear(): Promise<void>;
  size(): Promise<number>;
  stats(): Promise<{
    hits: number;
    misses: number;
    hitRate: number;
  }>;
}

/**
 * ZAI service events
 */
export type ZAIEvent =
  | { type: 'request_started'; data: { requestId: string; payload: ZAIChatRequest } }
  | {
      type: 'request_completed';
      data: { requestId: string; response: ZAIChatResponse; duration: number };
    }
  | {
      type: 'request_failed';
      data: { requestId: string; error: ZAIErrorResponse; duration: number };
    }
  | { type: 'circuit_breaker_opened'; data: { provider: string; reason: string } }
  | { type: 'circuit_breaker_closed'; data: { provider: string } }
  | { type: 'provider_failed_over'; data: { from: string; to: string; reason: string } }
  | { type: 'job_queued'; data: { jobId: string; type: ZAIJobType } }
  | { type: 'job_started'; data: { jobId: string } }
  | { type: 'job_completed'; data: { jobId: string; result: unknown } }
  | { type: 'job_failed'; data: { jobId: string; error: unknown } };

/**
 * Event listener type
 */
export type ZAIEventListener = (event: ZAIEvent) => void | Promise<void>;

/**
 * Background processor configuration
 */
export interface BackgroundProcessorConfig {
  maxConcurrency: number;
  queueSize: number;
  retryAttempts: number;
  retryDelayMs: number;
  timeoutMs: number;
  enablePriorityQueue: boolean;
  persistJobs: boolean;
  metricsInterval: number;
  enabled?: boolean; // Adding enabled property for compatibility
  // Extended properties for production config
  batchSize?: number;
  processingInterval?: number;
  maxQueueSize?: number;
}

/**
 * Background processor status
 */
export interface BackgroundProcessorStatus {
  status: 'running' | 'paused' | 'stopped';
  activeJobs: number;
  queuedJobs: number;
  completedJobs: number;
  failedJobs: number;
  averageProcessingTime: number;
  uptime: number;
  memoryUsage: {
    used: number;
    total: number;
    percentage: number;
  };
}

/**
 * ZAI service health check response
 */
export interface ZAIHealthCheckResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: number;
  uptime: number;
  errorRate: number;
  responseTime: number;
  details?: Record<string, unknown>;
  provider: {
    name: string;
    status: ZAIServiceStatus;
    latency: number;
    lastSuccess: number;
  };
  orchestrator: {
    status: 'active' | 'failed_over' | 'degraded';
    activeProvider: string;
    fallbackProvider: string;
    failoverCount: number;
  };
  backgroundProcessor: {
    status: BackgroundProcessorStatus;
    queueSize: number;
    processingRate: number;
  };
  metrics: {
    totalRequests: number;
    successRate: number;
    averageLatency: number;
    errorRate: number;
  };
}

/**
 * ZAI API error types
 */
export enum ZAIErrorType {
  AUTHENTICATION_ERROR = 'authentication_error',
  RATE_LIMIT_ERROR = 'rate_limit_error',
  INVALID_REQUEST_ERROR = 'invalid_request_error',
  INSUFFICIENT_QUOTA = 'insufficient_quota',
  MODEL_NOT_FOUND = 'model_not_found',
  CONTENT_FILTER = 'content_filter',
  TIMEOUT_ERROR = 'timeout_error',
  NETWORK_ERROR = 'network_error',
  UNKNOWN_ERROR = 'unknown_error',
}

/**
 * Custom error class for ZAI operations
 */
export class ZAIError extends Error {
  public readonly type: ZAIErrorType;
  public readonly code?: string;
  public readonly param?: string;
  public readonly statusCode?: number;

  constructor(
    message: string,
    type: ZAIErrorType,
    code?: string,
    param?: string,
    statusCode?: number
  ) {
    super(message);
    this.name = 'ZAIError';
    this.type = type;
    this.code = code;
    this.param = param;
    this.statusCode = statusCode;
  }

  static fromErrorResponse(errorResponse: ZAIErrorResponse): ZAIError {
    return new ZAIError(
      errorResponse.error.message,
      errorResponse.error.type as ZAIErrorType,
      errorResponse.error.code,
      errorResponse.error.param
    );
  }

  static fromNetworkError(error: Error): ZAIError {
    return new ZAIError(
      error.message,
      ZAIErrorType['NETWORK_ERROR'],
      undefined,
      undefined,
      undefined
    );
  }

  static fromTimeoutError(timeout: number): ZAIError {
    return new ZAIError(
      `Request timed out after ${timeout}ms`,
      ZAIErrorType['TIMEOUT_ERROR'],
      'timeout',
      undefined,
      undefined
    );
  }
}

/**
 * Request validation schemas
 */
export interface ZAIRequestValidation {
  isValidRequest(request: ZAIChatRequest): { valid: boolean; errors: string[] };
  sanitizeRequest(request: ZAIChatRequest): ZAIChatRequest;
  validateMessage(message: ZAIMessage): { valid: boolean; errors: string[] };
  getMaxTokensLimit(model: string): number;
  getContextWindowSize(model: string): number;
}

/**
 * Content filter interface
 */
export interface ZAIContentFilter {
  filterContent(content: string): {
    filtered: boolean;
    reason?: string;
    originalContent: string;
    filteredContent?: string;
  };
  isContentAllowed(content: string): boolean;
  getFilteredCategories(): string[];
}

/**
 * Performance monitoring interface
 */
export interface ZAIPerformanceMonitor {
  recordRequestStart(requestId: string): void;
  recordRequestEnd(requestId: string, success: boolean, responseTime: number): void;
  recordError(error: ZAIError, context?: Record<string, unknown>): void;
  getPerformanceMetrics(): {
    averageResponseTime: number;
    p95ResponseTime: number;
    p99ResponseTime: number;
    throughput: number;
    errorRate: number;
  };
  getMetricsByTimeRange(start: number, end: number): unknown;
  reset(): void;
}

/**
 * AI Health Status interface
 */
export interface AIHealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: Date;
  services: {
    zai: ServiceHealth;
    orchestrator: ServiceHealth;
    backgroundProcessor: ServiceHealth;
    insightService: ServiceHealth;
    contradictionDetector: ServiceHealth;
  };
  overall: {
    uptime: number;
    errorRate: number;
    responseTime: number;
    lastCheck: Date;
  };
  dependencies?: Record<string, DependencyHealth>;
  performance?: {
    latency: number;
    throughput: number;
    resources: {
      cpu: number;
      memory: number;
      disk: number;
    };
  };
  circuitBreaker?: {
    status: CircuitBreakerHealth;
    activeBreakers: string[];
    recentTrips: Array<{
      timestamp: Date;
      service: string;
      reason: string;
    }>;
  };
  alerts?: AIAlert[];
}

/**
 * Health Check Result interface
 */
export interface HealthCheckResult {
  service: string;
  status: 'pass' | 'fail' | 'warn';
  timestamp: Date;
  duration: number;
  message?: string;
  details?: Record<string, unknown>;
  metrics?: {
    responseTime: number;
    successRate: number;
    errorCount: number;
  };
}

/**
 * Dependency Health interface
 */
export interface DependencyHealth {
  name: string;
  type: 'database' | 'service' | 'api' | 'queue' | 'cache';
  status: 'healthy' | 'degraded' | 'unhealthy';
  responseTime?: number;
  lastCheck: Date;
  errorRate: number;
  details?: {
    connectionStatus: string;
    version?: string;
    endpoint?: string;
  };
  // Allow additional properties for extended compatibility
  [key: string]: unknown;
}

/**
 * Circuit Breaker Health interface
 */
export interface CircuitBreakerHealth {
  name: string;
  state: 'closed' | 'open' | 'half-open';
  status?: 'normal' | 'warning' | 'critical' | 'healthy' | 'degraded' | 'unhealthy'; // Added for compatibility
  failureCount: number;
  failureThreshold: number;
  recoveryTimeout: number;
  lastStateChange: Date;
  requestsInWindow: number;
  successCount: number;
}

/**
 * Performance Health interface
 */
export interface PerformanceHealth {
  cpu: {
    usage: number;
    threshold: number;
    status: 'normal' | 'warning' | 'critical';
  };
  memory: {
    usage: number;
    threshold: number;
    status: 'normal' | 'warning' | 'critical';
  };
  responseTime: {
    average: number;
    p95: number;
    p99: number;
    threshold: number;
    status: 'normal' | 'warning' | 'critical';
  };
  throughput: {
    current: number;
    peak: number;
    threshold: number;
    status: 'normal' | 'warning' | 'critical';
  };
  // Alternative structure for compatibility
  p50?: number;
  p95?: number;
  p99?: number;
  current?: number;
  peak?: number;
  average?: number;
}

/**
 * Service Health interface
 */
export interface ServiceHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  lastCheck: Date;
  uptime: number;
  errorRate: number;
  responseTime: number;
  details?: Record<string, unknown>;
}

/**
 * AI Orchestrator Metrics interface
 */
export interface AIOrchestratorMetrics {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageResponseTime: number;
  activeSessions: number;
  queuedRequests: number;
  throughput: number;
  errorRate: number;
  circuitBreakerStatus: string;
}

/**
 * Background Processor Metrics interface
 */
export interface BackgroundProcessorMetrics {
  queueSize: number;
  processingRate: number;
  averageProcessingTime: number;
  errorRate: number;
  activeWorkers: number;
  completedTasks: number;
  failedTasks: number;
}

/**
 * AI Metrics Snapshot interface
 */
export interface AIMetricsSnapshot {
  timestamp: Date;
  orchestrator: AIOrchestratorMetrics;
  backgroundProcessor: BackgroundProcessorMetrics;
  healthStatus: AIHealthStatus;
  performance: PerformanceHealth;
  resources: {
    cpuUsage: number;
    memoryUsage: number;
    diskUsage: number;
    networkIO: number;
  };
  operations?: {
    totalOperations: number;
    successfulOperations: number;
    failedOperations: number;
    averageOperationTime: number;
    operationTypes: Record<string, number>;
    // Additional properties for compatibility
    total?: number;
    successful?: number;
    failed?: number;
    pending?: number;
    averageLatency?: number;
    p95Latency?: number;
    p99Latency?: number;
    throughput?: number;
  };
  insights?: {
    totalInsights: number;
    successfulInsights: number;
    failedInsights: number;
    averageInsightTime: number;
    insightTypes: Record<string, number>;
    // Additional properties for compatibility
    generated?: number;
    accuracy?: number;
    averageConfidence?: number;
    strategies?: Record<string, number>;
  };
  contradiction?: {
    totalContradictions: number;
    resolvedContradictions: number;
    pendingContradictions: number;
    averageResolutionTime: number;
    // Additional properties for compatibility
    detected?: number;
    falsePositives?: number;
    falseNegatives?: number;
    accuracy?: number;
    averageConfidence?: number;
    strategies?: Record<string, number>;
  };
  quality?: {
    averageQualityScore: number;
    accuracyScore: number;
    relevanceScore: number;
    userSatisfactionScore: number;
    // Additional properties for compatibility
    overall?: number;
    availability?: number;
    errorRate?: number;
  };
}

/**
 * AI Quality Metrics interface
 */
export interface AIQualityMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  confidenceScore: number;
  responseRelevance: number;
  userSatisfaction: number;
  timestamp: Date;
}

/**
 * AI Resource Metrics interface
 */
export interface AIResourceMetrics {
  cpuUsage: number;
  memoryUsage: number;
  gpuUsage?: number;
  diskUsage: number;
  networkIO: {
    bytesIn: number;
    bytesOut: number;
  };
  activeConnections: number;
  queuedRequests: number;
  timestamp: Date;
}

/**
 * AI Operation Metrics interface
 */
export interface AIOperationMetrics {
  operation: string;
  startTime: Date;
  endTime?: Date;
  duration?: number;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  inputSize: number;
  outputSize: number;
  tokensUsed?: number;
  cost?: number;
  error?: string;
}

/**
 * AI Alert interface
 */
export interface AIAlert {
  id: string;
  type: 'error' | 'warning' | 'info';
  severity: 'low' | 'medium' | 'high' | 'critical' | 'info' | 'warning' | 'error'; // Extended for compatibility
  title: string;
  message: string;
  timestamp: Date;
  service: string;
  metric?: string;
  threshold?: number;
  currentValue?: number;
  resolved: boolean;
  resolvedAt?: Date;
  details?: unknown;
}

/**
 * AI Incident interface
 */
export interface AIIncident {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'resolved' | 'closed';
  startTime: Date;
  endTime?: Date;
  affectedServices: string[];
  rootCause?: string;
  resolution?: string;
  impact: {
    usersAffected: number;
    downtime: number;
    errorsCount: number;
  };
  timeline: Array<{
    timestamp: Date;
    event: string;
    details?: string;
  }>;
}

/**
 * AI Recommendation interface
 */
export interface AIRecommendation {
  id: string;
  type: 'performance' | 'reliability' | 'security' | 'cost';
  priority: 'low' | 'medium' | 'high';
  title: string;
  description: string;
  rationale: string;
  expectedImpact: string;
  implementation: {
    complexity: 'low' | 'medium' | 'high';
    estimatedTime: string;
    prerequisites: string[];
  };
  timestamp: Date;
  status: 'pending' | 'in_progress' | 'completed' | 'rejected';
}

/**
 * AI Quality Report interface
 */
export interface AIQualityReport {
  id: string;
  period: {
    start: Date;
    end: Date;
  };
  overall: {
    qualityScore: number;
    accuracyScore: number;
    performanceScore: number;
    reliabilityScore: number;
  };
  metrics: {
    totalRequests: number;
    successfulRequests: number;
    errorRate: number;
    averageResponseTime: number;
    userSatisfaction: number;
  };
  issues: Array<{
    type: string;
    count: number;
    severity: string;
    description: string;
  }>;
  recommendations: AIRecommendation[];
  generatedAt: Date;
}

/**
 * AI Cost Analysis interface
 */
export interface AICostAnalysis {
  period: {
    start: Date;
    end: Date;
  };
  totalCost: number;
  costBreakdown: {
    apiCalls: number;
    compute: number;
    storage: number;
    network: number;
    other: number;
  };
  costByService: Record<string, number>;
  costByOperation: Record<string, number>;
  trends: {
    dailyCosts: Array<{
      date: string;
      cost: number;
    }>;
    forecast: number;
  };
  optimization: {
    potentialSavings: number;
    recommendations: AIRecommendation[];
  };
}

/**
 * AI Operability Metrics interface
 */
export interface AIOperabilityMetrics {
  availability: {
    uptime: number;
    downtime: number;
    availabilityPercentage: number;
  };
  performance: {
    averageResponseTime: number;
    p95ResponseTime: number;
    throughput: number;
    errorRate: number;
  };
  quality: {
    accuracy: number;
    userSatisfaction: number;
    successRate: number;
  };
  incidents: {
    totalIncidents: number;
    meanTimeToResolution: number;
    meanTimeBetweenFailures: number;
  };
  resources: {
    cpuUtilization: number;
    memoryUtilization: number;
    diskUtilization: number;
  };
}

/**
 * ZAI Optimized Client Options interface
 */
export interface ZAIOptimizedClientOptions {
  apiKey: string;
  baseURL: string;
  model: string;
  cache?: CacheConfig;
  deduplication?: DeduplicationConfig;
  rateLimit?: RateLimitConfig;
  performance?: PerformanceConfig;
  enableCircuitBreaker?: boolean;
  circuitBreakerThreshold?: number;
  circuitBreakerTimeout?: number;
  enableLogging?: boolean;
  maxRetries?: number;
  timeout?: number;
}

/**
 * Cache Configuration interface
 */
export interface CacheConfig {
  enabled?: boolean;
  maxSize?: number;
  ttlMs?: number;
  strategy?: string;
  // Extended properties for compatibility
  enableMemoryCache?: boolean;
  memoryCacheSize?: number;
  defaultTTL?: number;
  enableRedisCache?: boolean;
  redisOptions?: {
    host: string;
    port: number;
  };
  compressionThreshold?: number;
  enableIntelligentCache?: boolean;
}

/**
 * Deduplication Configuration interface
 */
export interface DeduplicationConfig {
  enabled?: boolean;
  strategy?: string;
  windowMs?: number;
  maxDeduplicationEntries?: number;
  // Extended properties for compatibility
  enableDeduplication?: boolean;
  deduplicationWindow?: number;
  maxPendingRequests?: number;
}

/**
 * Rate Limit Configuration interface
 */
export interface RateLimitConfig {
  enabled?: boolean;
  requestsPerMinute?: number;
  requestsPerHour?: number;
  burstLimit?: number;
  // Extended properties for compatibility
  enableRateLimit?: boolean;
  burstCapacity?: number;
  strategy?: string;
}

/**
 * Performance Configuration interface
 */
export interface PerformanceConfig {
  enableMetrics?: boolean;
  metricsInterval?: number;
  enableTracing?: boolean;
  enableProfiling?: boolean;
  // Extended properties for compatibility
  enableBatching?: boolean;
  maxBatchSize?: number;
  batchTimeout?: number;
  enableStreaming?: boolean;
  enableConnectionPool?: boolean;
  maxConnections?: number;
  requestTimeout?: number;
  enableCompression?: boolean;
}

/**
 * Additional dependency interface for extended compatibility
 */
export interface DependencyHealthExtended extends DependencyHealth {
  extendedStatus?: 'normal' | 'warning' | 'critical';
  zai?: DependencyHealth;
  orchestrator?: DependencyHealth;
  backgroundProcessor?: DependencyHealth;
  insightService?: DependencyHealth;
  contradictionDetector?: DependencyHealth;
}

/**
 * Export all types and interfaces
 */
// Duplicate exports removed - types are already exported above
