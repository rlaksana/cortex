/**
 * Core interfaces for the Cortex Memory MCP system
 * Provides contracts for knowledge management operations
 */

export interface KnowledgeItem {
  id?: string;
  kind: string;
  content?: string; // Add content property for compatibility
  scope: {
    project?: string;
    branch?: string;
    org?: string;
  };
  data: Record<string, any>;
  metadata?: Record<string, any>; // Add metadata property for compatibility
  created_at?: string;
  updated_at?: string;
  expiry_at?: string; // P6-T6.1: Add expiry timestamp
}

export interface KnowledgeItemForStorage {
  kind: string;
  content?: string;
  scope: {
    project?: string;
    branch?: string;
    org?: string;
  };
  data: Record<string, any>;
  metadata?: Record<string, any>;
}

export interface StoreResult {
  id: string;
  status: 'inserted' | 'updated' | 'skipped_dedupe' | 'deleted';
  kind: string;
  created_at: string;
}

export interface StoreError {
  index: number;
  error_code: string;
  message: string;
  field?: string;
  stack?: string;
  timestamp?: string;
}

export interface AutonomousContext {
  action_performed: 'created' | 'updated' | 'deleted' | 'skipped' | 'batch';
  similar_items_checked: number;
  duplicates_found: number;
  contradictions_detected: boolean;
  recommendation: string;
  reasoning: string;
  user_message_suggestion: string;
  dedupe_threshold_used?: number;
  dedupe_method?: 'content_hash' | 'semantic_similarity' | 'combined' | 'none';
  dedupe_enabled?: boolean;
}

export interface SearchResult {
  id: string;
  kind: string;
  scope: Record<string, any>;
  data: Record<string, any>;
  created_at: string;
  confidence_score: number;
  match_type: 'exact' | 'fuzzy' | 'semantic' | 'keyword' | 'hybrid' | 'expanded' | 'graph';
  highlight?: string[];
}

export interface SearchQuery {
  query: string;
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
  };
  types?: string[];
  kind?: string; // Add kind property for compatibility
  mode?: 'auto' | 'fast' | 'deep';
  limit?: number;
  top_k?: number;
  expand?: 'relations' | 'parents' | 'children' | 'none'; // P4-T4.2: Graph expansion options
}

export interface ItemResult {
  input_index: number;
  status: 'stored' | 'skipped_dedupe' | 'business_rule_blocked' | 'validation_error';
  kind: string;
  content?: string;
  id?: string;
  reason?: string;
  existing_id?: string;
  error_code?: string;
  created_at?: string;
  expiry_at?: string; // P6-T6.1: Add expiry timestamp for item tracking
}

export interface BatchSummary {
  stored: number;
  skipped_dedupe: number;
  business_rule_blocked: number;
  validation_error?: number;
  total: number;
  merges_performed?: number;
  merge_details?: Array<{
    existing_id: string;
    new_id: string;
    similarity: number;
    action: 'merged';
  }>;
}

export interface MemoryStoreResponse {
  // Enhanced response format
  items: ItemResult[];
  summary: BatchSummary;

  // Legacy fields for backward compatibility
  stored: StoreResult[];
  errors: StoreError[];
  autonomous_context: AutonomousContext;
}

export interface MemoryFindResponse {
  results: SearchResult[];
  items: SearchResult[]; // Add items property for compatibility
  total_count: number;
  total?: number; // Add total property for compatibility
  autonomous_context: {
    search_mode_used: string;
    results_found: number;
    confidence_average: number;
    user_message_suggestion: string;
  };
}

/**
 * Repository interface for knowledge persistence operations
 */
export interface KnowledgeRepository {
  store(_item: KnowledgeItem): Promise<StoreResult>;
  update(_id: string, _item: Partial<KnowledgeItem>): Promise<StoreResult>;
  delete(_id: string): Promise<boolean>;
  findById(_id: string): Promise<KnowledgeItem | null>;
  findSimilar(_item: KnowledgeItem, _threshold?: number): Promise<KnowledgeItem[]>;
}

/**
 * Search result wrapper for individual search methods
 */
export interface SearchMethodResult {
  results: SearchResult[];
  totalCount: number;
  strategy?: string;
  executionTime?: number;
}

/**
 * Service interface for search operations
 */
export interface SearchService {
  search(_query: SearchQuery): Promise<MemoryFindResponse>;
  validateQuery(_query: SearchQuery): Promise<boolean>;
  // P3-T3.1: New search methods
  semantic(query: SearchQuery): Promise<SearchMethodResult>;
  keyword(query: SearchQuery): Promise<SearchMethodResult>;
  hybrid(query: SearchQuery): Promise<SearchMethodResult>;
  // P3-T3.2: Mode-based search method
  searchByMode(query: SearchQuery): Promise<SearchMethodResult>;
}

/**
 * Service interface for validation operations
 */
/**
 * Result of business rule validation
 */
export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Business validator interface for knowledge type-specific validation
 */
export interface BusinessValidator {
  getType(): string;
  validate(item: KnowledgeItem): Promise<ValidationResult>;
}

/**
 * Registry for managing business validators
 */
export interface ValidatorRegistry {
  registerValidator(type: string, validator: BusinessValidator): void;
  getValidator(type: string): BusinessValidator | null;
  getSupportedTypes(): string[];
  validateBatch(items: KnowledgeItem[]): Promise<ValidationResult[]>;
}

export interface ValidationService {
  validateStoreInput(_items: unknown[]): Promise<{ valid: boolean; errors: StoreError[] }>;
  validateFindInput(_input: unknown): Promise<{ valid: boolean; errors: string[] }>;
  validateKnowledgeItem(_item: KnowledgeItem): Promise<{ valid: boolean; errors: string[] }>;
}

/**
 * Service interface for deduplication operations
 */
export interface DeduplicationService {
  checkDuplicates(
    _items: KnowledgeItem[]
  ): Promise<{ duplicates: KnowledgeItem[]; originals: KnowledgeItem[] }>;
  removeDuplicates(_items: KnowledgeItem[]): Promise<KnowledgeItem[]>;
}

/**
 * Service interface for similarity detection
 */
export interface SimilarityService {
  findSimilar(_item: KnowledgeItem, _threshold?: number): Promise<KnowledgeItem[]>;
  calculateSimilarity(_item1: KnowledgeItem, _item2: KnowledgeItem): Promise<number>;
}

/**
 * Service interface for audit logging
 */
export interface AuditService {
  logOperation(_operation: string, _data: Record<string, any>): Promise<void>;
  logAccess(_resource: string, _userId?: string): Promise<void>;
  logError(_error: Error, _context: Record<string, any>): Promise<void>;
}

/**
 * Memory store request interface
 */
export interface MemoryStoreRequest {
  items: any[];
}

/**
 * Memory find request interface
 */
export interface MemoryFindRequest {
  query: string;
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
  };
  types?: string[];
  mode?: 'auto' | 'fast' | 'deep';
  limit?: number;
  expand?: 'relations' | 'parents' | 'children' | 'none'; // P4-T4.2: Graph expansion options
}

/**
 * Delete request interface
 */
export interface DeleteRequest {
  id: string;
  kind?: string;
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
  };
  cascade_relations?: boolean;
}

/**
 * Smart find request interface
 */
export interface SmartFindRequest {
  query: string;
  scope?: Record<string, unknown>;
  types?: string[];
  top_k?: number;
  mode?: 'auto' | 'fast' | 'deep';
  enable_auto_fix?: boolean;
  return_corrections?: boolean;
  max_attempts?: number;
  timeout_per_attempt_ms?: number;
}

/**
 * Smart find result interface
 */
export interface SmartFindResult {
  hits: Array<{
    kind: string;
    id: string;
    title: string;
    snippet: string;
    score: number;
    scope?: Record<string, unknown>;
    updated_at?: string;
    route_used: string;
    confidence: number;
  }>;
  suggestions: string[];
  autonomous_metadata: {
    strategy_used: 'fast' | 'deep' | 'fast_then_deep_fallback';
    mode_requested: string;
    mode_executed: string;
    confidence: 'high' | 'medium' | 'low';
    total_results: number;
    avg_score: number;
    fallback_attempted: boolean;
    recommendation: string;
    user_message_suggestion: string;
  };
  corrections?: {
    original_query: string;
    final_query: string;
    attempts: Array<{
      attempt_number: number;
      query: string;
      mode: string;
      sanitization_level?: string;
      error?: string;
      success: boolean;
      timestamp: number;
      duration_ms: number;
    }>;
    transformations: string[];
    total_attempts: number;
    auto_fixes_applied: string[];
    patterns_detected: string[];
    final_sanitization_level: string;
    recommendation: string;
  };
  debug?: Record<string, unknown>;
  graph?: any;
}

/**
 * Analytics interfaces
 */

export interface KnowledgeAnalytics {
  totalEntities: number;
  totalRelations: number;
  totalObservations: number;
  knowledgeTypeDistribution: Record<string, number>;
  growthMetrics: {
    dailyGrowthRate: number;
    weeklyGrowthRate: number;
    monthlyGrowthRate: number;
    totalGrowthThisPeriod: number;
  };
  contentMetrics: {
    averageContentLength: number;
    totalContentLength: number;
    contentComplexity: 'low' | 'medium' | 'high';
  };
  scopeDistribution: Record<string, number>;
  temporalDistribution: Record<string, number>;
}

export interface RelationshipAnalytics {
  totalRelations: number;
  relationTypeDistribution: Record<string, number>;
  graphDensity: number;
  averageDegree: number;
  centralityMeasures: {
    betweenness: Record<string, number>;
    closeness: Record<string, number>;
    eigenvector: Record<string, number>;
  };
  clusteringCoefficients: Record<string, number>;
  pathLengths: {
    averageShortestPath: number;
    diameter: number;
    distribution: Record<string, number>;
  };
}

export interface PerformanceAnalytics {
  queryPerformance: {
    averageResponseTime: number;
    p95ResponseTime: number;
    p99ResponseTime: number;
    throughput: number;
    errorRate: number;
  };
  storageUtilization: {
    totalStorageUsed: number;
    storageByType: Record<string, number>;
    growthRate: number;
  };
  systemMetrics: {
    cpuUsage: number;
    memoryUsage: number;
    diskIO: number;
    networkIO: number;
  };
  bottlenecks: Array<{
    type: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    recommendation: string;
  }>;
  optimizationSuggestions: string[];
}

export interface UserBehaviorAnalytics {
  searchPatterns: {
    commonQueries: Array<{
      query: string;
      frequency: number;
    }>;
    queryComplexity: {
      simple: number;
      medium: number;
      complex: number;
    };
    filtersUsage: Record<string, number>;
  };
  contentInteraction: {
    mostViewedTypes: Record<string, number>;
    averageSessionDuration: number;
    bounceRate: number;
  };
  usageTrends: {
    dailyActiveUsers: number;
    retentionRate: number;
    featureAdoption: Record<string, number>;
  };
  engagementMetrics: {
    totalInteractions: number;
    averageInteractionsPerSession: number;
    peakActivityHours: number[];
  };
}

export interface PredictiveAnalytics {
  growthPredictions: {
    nextMonth: {
      entities: number;
      relations: number;
      observations: number;
    };
    nextQuarter: {
      entities: number;
      relations: number;
      observations: number;
    };
    nextYear: {
      entities: number;
      relations: number;
      observations: number;
    };
  };
  trendPredictions: {
    knowledgeTypes: Record<
      string,
      {
        trend: 'increasing' | 'decreasing' | 'stable';
        confidence: number;
      }
    >;
    scopes: Record<
      string,
      {
        trend: 'increasing' | 'decreasing' | 'stable';
        confidence: number;
      }
    >;
    contentComplexity: 'increasing' | 'decreasing' | 'stable';
  };
  anomalyDetection: {
    detectedAnomalies: Array<{
      type: string;
      timestamp: Date;
      severity: 'low' | 'medium' | 'high' | 'critical';
      description: string;
    }>;
    confidenceScores: Record<string, number>;
    recommendedActions: string[];
  };
  insights: {
    keyInsights: string[];
    recommendations: string[];
    riskFactors: string[];
  };
}

export interface AnalyticsReport {
  id: string;
  title: string;
  generatedAt: Date;
  timeRange?: {
    startDate: Date;
    endDate: Date;
  };
  filters?: AnalyticsFilter;
  data: any;
  visualizations: Array<{
    type: string;
    title: string;
    data: any;
  }>;
  summary: string;
  metadata: {
    totalDataPoints: number;
    processingTimeMs: number;
    cacheHit: boolean;
  };
}

export interface AnalyticsQuery {
  type: 'knowledge' | 'relationships' | 'performance' | 'user_behavior' | 'predictive';
  title?: string;
  timeRange?: {
    startDate: Date;
    endDate: Date;
  };
  filters?: AnalyticsFilter;
  aggregations?: Array<{
    field: string;
    operation: 'count' | 'sum' | 'average' | 'min' | 'max';
    groupBy?: string;
  }>;
  limit?: number;
}

export interface AnalyticsFilter {
  scope?: {
    project?: string;
    org?: string;
    branch?: string;
  };
  dateRange?: {
    startDate?: Date;
    endDate?: Date;
  };
  types?: string[];
  tags?: Record<string, string>;
}

/**
 * Storage Service Interfaces
 */

export interface StorageBucket {
  name: string;
  region: string;
  creationDate: Date;
  objectCount: number;
  sizeBytes: number;
  versioning: boolean;
  encryption: boolean | StorageEncryption;
  lifecycleRules: StorageLifecycleRule[];
  accessControl: BucketAccessControl;
  publicAccess: boolean;
  website?: WebsiteConfig;
  cors?: CorsConfig;
}

export interface StorageObject {
  key: string;
  size: number;
  etag: string;
  lastModified: Date;
  contentType: string;
  storageClass: string;
  versionId?: string;
  metadata?: Record<string, string>;
  tags?: Record<string, string>;
  encrypted: boolean;
  compressed: boolean;
  originalSize?: number;
  compressedSize?: number;
  url?: string;
}

export interface StorageMetrics {
  totalObjects: number;
  totalSizeBytes: number;
  averageObjectSize: number;
  storageUtilization: number;
  objectCountByType: Record<string, number>;
  sizeDistribution: {
    small: number; // < 1MB
    medium: number; // 1MB - 100MB
    large: number; // 100MB - 1GB
    xlarge: number; // > 1GB
  };
  growthRate: {
    daily: number;
    weekly: number;
    monthly: number;
  };
  compressionRatio: number;
  deduplicationRatio: number;
}

export interface StorageAnalytics {
  usagePatterns: StorageUsagePattern[];
  performanceMetrics: StoragePerformance;
  costAnalysis: StorageCostAnalysis;
  accessPatterns: StorageAccessPattern[];
  recommendations: StorageRecommendation[];
  anomalies: StorageAnomaly[];
  forecasts: StorageForecast[];
}

export interface StorageConfig {
  provider: 's3' | 'gcs' | 'azure' | 'minio';
  region: string;
  bucket: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  endpoint?: string;
  encryption: StorageEncryption | boolean;
  versioning: boolean;
  compression: StorageCompression | boolean;
  caching: StorageCache | boolean;
  cdn: StorageCDN | boolean;
  monitoring: StorageMonitoring | boolean;
  backup: StorageBackupConfig | boolean;
  security: StorageSecurityConfig;
  performance: StoragePerformanceConfig;
}

export interface UploadRequest {
  key: string;
  body: Buffer;
  contentType: string;
  metadata?: Record<string, string>;
  tags?: Record<string, string>;
  encryption?: StorageEncryption;
  compression?: boolean;
  storageClass?: string;
  acl?: string;
  serverSideEncryption?: string;
  sseKmsKeyId?: string;
}

export interface DownloadRequest {
  key: string;
  versionId?: string;
  range?: string;
  ifMatch?: string;
  ifNoneMatch?: string;
  ifModifiedSince?: Date;
  ifUnmodifiedSince?: Date;
}

export interface StoragePermissions {
  read: string[];
  write: string[];
  delete: string[];
  admin: string[];
  public: boolean;
  anonymousRead: boolean;
  authenticatedRead: boolean;
}

export interface StorageBackup {
  backupId: string;
  sourceBucket: string;
  destinationBucket: string;
  destinationRegion?: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  createdAt: Date;
  completedAt?: Date;
  totalObjects: number;
  totalSizeBytes: number;
  objectsProcessed: number;
  bytesTransferred: number;
  includeVersions: boolean;
  encryption?: StorageEncryption;
  compression: boolean;
  retentionDays?: number;
}

export interface StorageIntegrity {
  checkId: string;
  type: 'checksum' | 'full_verification' | 'sample_verification';
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  checkedObjects: number;
  totalObjects: number;
  passedObjects: number;
  failedObjects: number;
  issues: IntegrityIssue[];
  successRate: number;
  startTime: Date;
  completionTime?: Date;
}

export interface StorageOptimization {
  optimizationId: string;
  type: 'compression' | 'deduplication' | 'lifecycle' | 'cleanup';
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  targetObjects: number;
  processedObjects: number;
  spaceSaved: number;
  costSaved: number;
  recommendations: string[];
  startTime: Date;
  completionTime?: Date;
}

export interface StoragePerformance {
  uploadMetrics: {
    count: number;
    averageLatency: number;
    p95Latency: number;
    p99Latency: number;
    throughput: number;
    errorRate: number;
  };
  downloadMetrics: {
    count: number;
    averageLatency: number;
    p95Latency: number;
    p99Latency: number;
    throughput: number;
    errorRate: number;
  };
  storageMetrics: {
    readIOPS: number;
    writeIOPS: number;
    throughput: number;
    latency: number;
  };
  cacheMetrics: {
    hitRate: number;
    missRate: number;
    evictionRate: number;
    size: number;
  };
}

export interface StorageSecurity {
  encryption: {
    atRest: boolean;
    inTransit: boolean;
    algorithm: string;
    keyRotationEnabled: boolean;
  };
  accessControl: {
    policies: StoragePolicy[];
    mfaDelete: boolean;
    versionLock: boolean;
    legalHold: boolean;
  };
  monitoring: {
    auditLogging: boolean;
    accessLogging: boolean;
    threatDetection: boolean;
  };
  compliance: {
    standards: string[];
    certifications: string[];
    regions: string[];
  };
}

export interface StorageUsageMetrics {
  timeSeriesData: StorageTimeSeriesData[];
  topConsumers: StorageConsumer[];
  growthTrends: StorageGrowthTrend[];
  forecastedUsage: StorageForecast[];
  costAnalysis: StorageCostAnalysis;
  recommendations: StorageRecommendation[];
}

// Supporting Interfaces

export interface StorageEncryption {
  enabled: boolean;
  algorithm: 'AES256' | 'AES128' | 'aws:kms';
  kmsKeyId?: string;
  bucketKeyEnabled?: boolean;
  context?: Record<string, string>;
}

export interface StorageCompression {
  enabled: boolean;
  algorithm: 'gzip' | 'lz4' | 'zstd';
  level: number;
  threshold: number; // Minimum file size to compress
}

export interface StorageCache {
  enabled: boolean;
  ttl: number;
  maxSize: number;
  evictionPolicy: 'LRU' | 'LFU' | 'FIFO';
  persistenceEnabled: boolean;
}

export interface StorageCDN {
  enabled: boolean;
  distributionId?: string;
  domainName?: string;
  cacheBehavior: {
    pathPattern: string;
    minTTL: number;
    maxTTL: number;
    defaultTTL: number;
  }[];
  invalidationSupport: boolean;
}

export interface StorageMonitoring {
  enabled: boolean;
  metrics: string[];
  alertThresholds: {
    errorRate: number;
    latency: number;
    storageUtilization: number;
  };
  notifications: {
    email: string[];
    webhook?: string;
  };
}

export interface StorageBackupConfig {
  enabled: boolean;
  schedule: string;
  retentionDays: number;
  destinationBucket: string;
  destinationRegion?: string;
  includeVersions: boolean;
  compression: boolean;
  encryption: boolean;
}

export interface StorageSecurityConfig {
  encryption: StorageEncryption;
  accessControl: StoragePermissions;
  mfaDelete: boolean;
  legalHold: boolean;
  auditLogging: boolean;
  accessLogging: boolean;
  threatDetection: boolean;
}

export interface StoragePerformanceConfig {
  multipartThreshold: number;
  chunkSize: number;
  maxConcurrency: number;
  timeoutMs: number;
  retryAttempts: number;
  bandwidthThrottling?: {
    enabled: boolean;
    maxBandwidthMBps: number;
  };
}

export interface StorageLifecycleRule {
  id: string;
  status: 'Enabled' | 'Disabled';
  filter?: {
    prefix?: string;
    tags?: Record<string, string>;
  };
  transitions?: Array<{
    days: number;
    storageClass: string;
  }>;
  expiration?:
    | {
        days?: number;
        date?: Date;
      }
    | { days?: number; date?: Date; expiredObjectDeleteMarker?: boolean };
  noncurrentVersionTransitions?: Array<{
    noncurrentDays: number;
    storageClass: string;
  }>;
  noncurrentVersionExpiration?: {
    noncurrentDays: number;
  };
  abortIncompleteMultipartUpload?: {
    daysAfterInitiation: number;
  };
}

export interface BucketAccessControl {
  owner: string;
  grants: Array<{
    grantee: {
      type: string;
      displayName?: string;
      emailAddress?: string;
      uri?: string;
    };
    permission: string;
  }>;
}

export interface WebsiteConfig {
  indexDocument: string;
  errorDocument?: string;
  redirectAllRequestsTo?: {
    hostName: string;
    protocol?: string;
  };
  routingRules?: Array<{
    condition: {
      keyPrefixEquals?: string;
      httpErrorCodeReturnedEquals?: string;
    };
    redirect: {
      protocol?: string;
      hostName?: string;
      replaceKeyPrefixWith?: string;
      replaceKeyWith?: string;
      httpRedirectCode?: string;
    };
  }>;
}

export interface CorsConfig {
  corsRules: Array<{
    allowedHeaders: string[];
    allowedMethods: string[];
    allowedOrigins: string[];
    exposeHeaders: string[];
    maxAgeSeconds: number;
  }>;
}

export interface StorageUsagePattern {
  timestamp: Date;
  totalStorage: number;
  storageGrowth: number;
  accessCount: number;
  uniqueUsers: number;
  popularObjects: Array<{
    key: string;
    accessCount: number;
  }>;
}

export interface StorageCostAnalysis {
  totalMonthlyCost: number;
  costByStorageClass: Record<string, number>;
  costByOperations: Record<string, number>;
  costByDataTransfer: Record<string, number>;
  forecastedCost: number;
  recommendations: string[];
}

export interface StorageAccessPattern {
  objectId: string;
  accessCount: number;
  lastAccessed: Date;
  accessPattern: 'sequential' | 'random' | 'hot' | 'cold';
  userAgents: string[];
  geoLocations: string[];
}

export interface StorageRecommendation {
  type: 'compression' | 'lifecycle' | 'cleanup' | 'security' | 'performance';
  priority: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  estimatedSavings?: {
    storage?: number;
    cost?: number;
    performance?: number;
  };
  effort: 'low' | 'medium' | 'high';
}

export interface StorageAnomaly {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  timestamp: Date;
  affectedObjects: string[];
  confidenceScore: number;
  recommendedActions: string[];
}

export interface StorageForecast {
  metric: string;
  timeHorizon: string;
  forecastedValues: Array<{
    timestamp: Date;
    value: number;
    confidence: number;
  }>;
  trend: 'increasing' | 'decreasing' | 'stable';
  accuracy: number;
}

export interface IntegrityIssue {
  objectId: string;
  issueType: 'checksum_mismatch' | 'corruption' | 'missing' | 'inconsistent';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  detectedAt: Date;
  recommendedAction: string;
}

export interface StorageTimeSeriesData {
  timestamp: Date;
  totalStorage: number;
  objectCount: number;
  uploadCount: number;
  downloadCount: number;
  deleteCount: number;
  bandwidthUsed: number;
}

export interface StorageConsumer {
  id: string;
  name: string;
  type: 'user' | 'application' | 'service';
  storageUsed: number;
  objectCount: number;
  bandwidthUsed: number;
  requestCount: number;
}

export interface StorageGrowthTrend {
  period: 'daily' | 'weekly' | 'monthly';
  trend: 'increasing' | 'decreasing' | 'stable';
  rate: number;
  projectedValues: Array<{
    date: Date;
    value: number;
  }>;
}

export interface StoragePolicy {
  id: string;
  name: string;
  effect: 'Allow' | 'Deny';
  principal: string | string[];
  action: string | string[];
  resource: string | string[];
  conditions?: Record<string, any>;
}
