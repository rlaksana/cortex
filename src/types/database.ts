/**
 * Database and Qdrant Type Definitions
 *
 * Comprehensive type definitions for database operations, Qdrant vector database,
 * and related data structures to eliminate 'any' types.
 */

// ============================================================================
// Utility Types
// ============================================================================

export interface Result<T, E = Error> {
  success: boolean;
  data?: T;
  error?: E;
  metadata?: Record<string, unknown>;
}

export type Brand<T, B> = T & { __brand: B };

// ============================================================================
// Base Database Types
// ============================================================================

export interface ConnectionConfig {
  host: string;
  port: number;
  timeout: number;
  maxRetries: number;
  retryDelay: number;
  useHttps: boolean;
  apiKey?: string;
}

export interface DatabaseConnection {
  isConnected: boolean;
  lastHealthCheck: Date;
  connectionId: string;
  endpoint: string;
}

// ============================================================================
// Qdrant Vector Database Types
// ============================================================================

export interface CollectionConfig {
  name: string;
  vectors: {
    size: number;
    distance: 'Cosine' | 'Euclidean' | 'Dot';
  };
  hnsw_config?: {
    m: number;
    ef_construct: number;
    full_scan_threshold: number;
    max_indexing_threads?: number;
    on_disk?: boolean;
  };
  optimizers_config?: {
    deleted_threshold: number;
    vacuum_min_vector_number: number;
    default_segment_number: number;
    max_segment_size?: number;
    memmap_threshold?: number;
    indexing_threshold?: number;
    flush_interval_sec?: number;
    max_optimization_threads?: number;
  };
  wal_config?: {
    wal_capacity_mb: number;
    wal_segments_ahead: number;
  };
  quantization_config?: {
    quantization: 'Scalar' | 'Product';
    scalar?: {
      type: 'Int8' | 'Float16';
      quantile: number;
      always_ram: boolean;
    };
    product?: {
      compression: 'x8' | 'x4' | 'x1';
      always_ram: boolean;
    };
  };
  on_disk?: boolean;
}

export interface CollectionMetadata {
  config: CollectionConfig;
  optimizer_status: {
    ok: boolean;
    error?: string;
    optimized_segment_count: number;
    pending_optimizer_operations: number;
  };
  indexed_vectors_count: number;
  points_count: number;
  segments_count: number;
  status: 'green' | 'yellow' | 'red';
  optimizer_status_reason: string;
  vectors_count: number;
}

export interface CollectionInfo {
  name: string;
  metadata: CollectionMetadata;
  disk_usage_bytes: number;
  ram_usage_bytes: number;
  segments: CollectionSegment[];
}

export interface CollectionSegment {
  segment_type: 'Plain' | 'Indexed' | 'Growing' | 'Deleted';
  vectors_count: number;
  points_count: number;
  disk_usage_bytes: number;
  ram_usage_bytes: number;
  index_data: {
    segment_type: string;
    vectors_count: number;
    points_count: number;
    disk_usage_bytes: number;
    ram_usage_bytes: number;
    indexed_points_count: number;
    indexed_vectors_count: number;
    index_spec: {
      field_name?: string;
      data_type: string;
    };
  };
  data: {
    segment_type: string;
    vectors_count: number;
    points_count: number;
    disk_usage_bytes: number;
    ram_usage_bytes: number;
  };
}

export interface PointStruct {
  id: string | number;
  vector: number[];
  payload?: Record<string, unknown>;
  shard_key?: string;
}

export interface PointId {
  num?: number;
  uuid?: string;
  has_id: boolean;
  point_id_options: 'NumId' | 'Uuid';
}

export interface PayloadSchema {
  property_type: 'Keyword' | 'Integer' | 'Float' | 'Bool' | 'Geo' | 'Text' | 'Datetime';
  params?: Record<string, unknown>;
}

export interface PayloadInfo {
  schema: Record<string, PayloadSchema>;
  points_count: number;
}

export interface VectorParams {
  size: number;
  distance: 'Cosine' | 'Euclidean' | 'Dot' | 'Manhattan';
  hnsw_config?: HnswConfig;
  quantization_config?: unknown;
  on_disk?: boolean;
}

export interface HnswConfig {
  m: number;
  ef_construct: number;
  full_scan_threshold: number;
  max_indexing_threads?: number;
  on_disk?: boolean;
}

// ============================================================================
// Qdrant Operation Types
// ============================================================================

export interface SearchRequest {
  collection_name: string;
  vector: number[];
  limit: number;
  offset?: number;
  filter?: Filter;
  params?: SearchParams;
  vector_name?: string;
  with_vector?: boolean;
  with_payload?: boolean | PayloadSelector;
  score_threshold?: number;
  search_params?: SearchParams;
  multivector_mode?: 'Replace' | 'Append';
}

export interface SearchParams {
  hnsw_ef?: number;
  exact?: boolean;
  quantization?: {
    ignore?: boolean;
    rescore?: boolean;
    oversampling?: number;
  };
  indexed_only?: boolean;
  approximated?: number;
}

export interface Filter {
  must?: Condition[];
  must_not?: Condition[];
  should?: Condition[];
  min_should?: MinShouldCondition;
}

export interface Condition {
  key?: string;
  range?: RangeCondition;
  match?: MatchCondition;
  is_null?: {
    key?: string;
  };
  is_empty?: {
    key: string;
  };
  has_id?: HasIdCondition;
  values_count?: ValuesCountCondition;
  isempty?: {
    key: string;
  };
  is_not_null?: {
    key?: string;
  };
  and?: Condition[];
  or?: Condition[];
}

export interface RangeCondition {
  gte?: number | string;
  gt?: number | string;
  lte?: number | string;
  lt?: number | string;
}

export interface MatchCondition {
  value?: unknown;
  any?: unknown[];
  text?: string;
  keywords?: string[];
  integers?: number[];
  boolean?: boolean;
  datetime?: string;
}

export interface HasIdCondition {
  has_id: string[] | number[];
}

export interface ValuesCountCondition {
  values_count: {
    lt?: number;
    lte?: number;
    gt?: number;
    gte?: number;
  };
}

export interface MinShouldCondition {
  conditions: Condition[];
  min_count: number;
}

export interface PayloadSelector {
  include?: string[];
  exclude?: string[];
}

export interface ScrollRequest {
  collection_name: string;
  filter?: Filter;
  limit?: number;
  offset?: PointId;
  with_vector?: boolean | WithVectorSelector;
  with_payload?: boolean | PayloadSelector;
  order_by?: OrderBy[];
}

export interface WithVectorSelector {
  include?: string[];
  exclude?: string[];
}

export interface OrderBy {
  key: string;
  direction?: 'Asc' | 'Desc';
  start_from?: unknown;
}

export interface ScrollResult {
  points: ScoredPoint[];
  next_page_offset?: PointId;
}

export interface ScoredPoint {
  id: PointId;
  payload?: Record<string, unknown>;
  score: number;
  vectors?: Record<string, number[]>;
  shard_key?: string;
}

// ============================================================================
// Database Operation Types
// ============================================================================

export interface BatchInsertRequest {
  collection_name: string;
  points: PointStruct[];
  wait: boolean;
  ordering?: WriteOrdering;
}

export interface BatchUpdateRequest {
  collection_name: string;
  wait: boolean;
  ordering?: WriteOrdering;
  operations: PointOperation[];
}

export interface PointOperation {
  delete?: PointsSelector;
  upsert?: PointInsertOperations;
  update_vectors?: PointVectorsOperation;
  overwrite_payload?: PointInsertOperations;
  delete_payload?: PayloadDeleteOperation;
  clear_payload?: PayloadClearOperation;
}

export interface PointInsertOperations {
  points: PointStruct[];
  shard_key?: string;
}

export interface PointVectorsOperation {
  points: PointVectorsStruct[];
  shard_key?: string;
}

export interface PointVectorsStruct {
  id: PointId;
  vector: Record<string, number[]>;
}

export interface PointsSelector {
  points?: PointIdList;
  filter?: Filter;
}

export interface PointIdList {
  points: PointId[];
  shard_key?: string;
}

export interface PayloadDeleteOperation {
  keys: string[];
  points?: PointsSelector;
  filter?: Filter;
}

export interface PayloadClearOperation {
  points?: PointsSelector;
  filter?: Filter;
}

export type LegacyWriteOrdering = 'Weak' | 'Medium' | 'Strong';

// ============================================================================
// Health Check Types
// ============================================================================

export interface HealthStatus {
  healthy: boolean;
  collection_count: number;
  total_points: number;
  total_vectors: number;
  memory_usage: {
    used: number;
    available: number;
    percentage: number;
  };
  disk_usage: {
    used: number;
    available: number;
    percentage: number;
  };
  collections: CollectionHealth[];
  last_check: Date;
  endpoint: string;
}

export interface CollectionHealth {
  name: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  points_count: number;
  vectors_count: number;
  segments_count: number;
  disk_usage_mb: number;
  last_optimized?: Date;
}

export interface HealthCheckConfig {
  interval_seconds: number;
  timeout_seconds: number;
  retries: number;
  detailed_logging: boolean;
  collection_filter?: string[];
}

// ============================================================================
// Backup and Recovery Types
// ============================================================================

export interface BackupConfig {
  enabled: boolean;
  schedule: string; // cron expression
  backup_dir: string;
  compression: boolean;
  encryption: boolean;
  retention_days: number;
  include_payloads: boolean;
  include_vectors: boolean;
  collections?: string[]; // empty = all collections
}

export interface BackupMetadata {
  backup_id: string;
  created_at: Date;
  version: string;
  collections: string[];
  points_count: number;
  vectors_count: number;
  file_size_bytes: number;
  compressed_size_bytes?: number;
  encryption_enabled: boolean;
  checksum: string;
  config_snapshot?: Record<string, unknown>;
}

export interface RestoreConfig {
  backup_path: string;
  target_collections?: string[];
  rename_collections?: Record<string, string>;
  create_if_missing: boolean;
  overwrite_existing: boolean;
  validate_checksum: boolean;
}

export interface RestoreProgress {
  restore_id: string;
  backup_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  current_collection?: string;
  points_restored: number;
  total_points: number;
  start_time: Date;
  estimated_completion?: Date;
  error_message?: string;
}

// ============================================================================
// Migration Types
// ============================================================================

export interface MigrationConfig {
  enabled: boolean;
  auto_migrate: boolean;
  backup_before_migrate: boolean;
  validate_after_migrate: boolean;
  timeout_seconds: number;
  dry_run: boolean;
}

export interface MigrationScript {
  name: string;
  version: string;
  description: string;
  up: string; // SQL script
  down?: string; // rollback script
  dependencies?: string[];
  checksum?: string;
}

export interface MigrationStatus {
  version: string;
  applied_at: Date;
  execution_time_ms: number;
  success: boolean;
  error_message?: string;
  checksum?: string;
}

export interface MigrationPlan {
  migrations: MigrationScript[];
  execution_order: string[];
  estimated_duration_ms: number;
  requires_backup: boolean;
  warnings: string[];
}

// ============================================================================
// Consistency Validation Types
// ============================================================================

export interface ConsistencyConfig {
  enabled: boolean;
  schedule: string; // cron expression
  validation_depth: 'basic' | 'deep' | 'comprehensive';
  auto_repair: boolean;
  quarantine_inconsistent: boolean;
  max_repair_attempts: number;
}

export interface ConsistencyReport {
  report_id: string;
  timestamp: Date;
  collections: CollectionConsistency[];
  overall_status: 'healthy' | 'warnings' | 'errors';
  summary: {
    total_collections: number;
    healthy_collections: number;
    warnings_count: number;
    errors_count: number;
  };
  auto_repairs: RepairAction[];
}

export interface CollectionConsistency {
  collection_name: string;
  status: 'healthy' | 'warnings' | 'errors';
  point_count: number;
  vector_count: number;
  payload_integrity: {
    valid_points: number;
    corrupted_points: number;
    missing_payloads: number;
  };
  vector_integrity: {
    valid_vectors: number;
    corrupted_vectors: number;
    dimension_mismatches: number;
  };
  index_integrity: {
    index_consistent: boolean;
    orphaned_points: number;
    missing_index_entries: number;
  };
  issues: ConsistencyIssue[];
}

export interface ConsistencyIssue {
  severity: 'warning' | 'error';
  type: 'payload_corruption' | 'vector_corruption' | 'index_mismatch' | 'orphaned_data';
  description: string;
  affected_points: string[];
  suggested_repair?: string;
}

export interface RepairAction {
  action_id: string;
  collection_name: string;
  issue_type: string;
  action: 'repair_payload' | 'repair_vector' | 'remove_orphan' | 'rebuild_index';
  status: 'pending' | 'running' | 'completed' | 'failed';
  affected_points: number;
  started_at?: Date;
  completed_at?: Date;
  error_message?: string;
}

// ============================================================================
// Performance Monitoring Types
// ============================================================================

export interface PerformanceMetrics {
  query_latency_ms: number;
  insert_latency_ms: number;
  update_latency_ms: number;
  delete_latency_ms: number;
  points_per_second: number;
  vectors_per_second: number;
  memory_usage_percent: number;
  cpu_usage_percent: number;
  disk_io_mb_per_second: number;
  network_io_mb_per_second: number;
  cache_hit_rate_percent: number;
  index_utilization_percent: number;
}

export interface PerformanceAlert {
  alert_id: string;
  metric_name: string;
  threshold: number;
  current_value: number;
  severity: 'info' | 'warning' | 'critical';
  message: string;
  timestamp: Date;
  collection_name?: string;
  resolved_at?: Date;
}

export interface PerformanceReport {
  report_id: string;
  timestamp: Date;
  period_start: Date;
  period_end: Date;
  metrics: PerformanceMetrics;
  trends: PerformanceTrend[];
  alerts: PerformanceAlert[];
  recommendations: string[];
}

export interface PerformanceTrend {
  metric_name: string;
  trend: 'improving' | 'stable' | 'degrading';
  change_percent: number;
  period_hours: number;
}

// ============================================================================
// Error Types
// ============================================================================

export interface DatabaseError extends Error {
  code: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  retryable: boolean;
  collection_name?: string;
  point_id?: string;
  operation?: string;
  original_error?: Error;
}

export interface ValidationError extends Error {
  field: string;
  value: unknown;
  constraint: string;
  schema_path: string;
}

export interface ConnectionError extends Error {
  endpoint: string;
  connection_id?: string;
  is_timeout: boolean;
  retry_count: number;
}

// ============================================================================
// Batch Operation Types
// ============================================================================

export interface BatchOperation<T> {
  operations: T[];
  batch_size: number;
  max_retries: number;
  timeout_ms: number;
  continue_on_error: boolean;
  progress_callback?: (completed: number, total: number) => void;
}

export interface BatchResult<T, E = Error> {
  total_operations: number;
  successful_operations: number;
  failed_operations: number;
  results: Result<T, E>[];
  execution_time_ms: number;
  errors: E[];
}

export interface BulkInsertOptions {
  collection_name: string;
  points: PointStruct[];
  batch_size?: number;
  parallel_batches?: number;
  wait: boolean;
  skip_validation?: boolean;
  progress_callback?: (processed: number, total: number) => void;
}

export interface BulkSearchOptions {
  collection_name: string;
  vectors: number[][];
  limit: number;
  filter?: Filter;
  score_threshold?: number;
  batch_size?: number;
  parallel_requests?: number;
  with_payload?: boolean | PayloadSelector;
  with_vector?: boolean;
}

export interface BulkSearchResult {
  points: ScoredPoint[][];
  total_points: number;
  execution_time_ms: number;
  errors: string[];
}

// ============================================================================
// Qdrant-Specific Client Types
// ============================================================================

export interface QdrantClientConfig {
  url: string;
  timeout?: number;
  apiKey?: string;
  https?: boolean;
  port?: number;
  host?: string;
  headers?: Record<string, string>;
  check_duplicates?: boolean;
  max_retries?: number;
  retry_delay?: number;
}

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface QdrantFilter extends Filter {
  // Extended filter interface for Qdrant-specific operations
}

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface QdrantCondition extends Condition {
  // Extended condition interface for Qdrant-specific operations
}

export interface QdrantPointStruct extends Omit<PointStruct, 'shard_key'> {
  // Extended point structure for Qdrant-specific operations
  shard_key?: string | string[];
}

// eslint-disable-next-line @typescript-eslint/no-empty-object-type
export interface QdrantScoredPoint extends ScoredPoint {
  // Extended scored point for Qdrant-specific operations
}

export interface QdrantSearchOptions {
  collection_name: string;
  vector: number[];
  limit?: number;
  offset?: number;
  filter?: QdrantFilter;
  params?: SearchParams;
  vector_name?: string;
  with_vector?: boolean | WithVectorSelector;
  with_payload?: boolean | PayloadSelector;
  score_threshold?: number;
  search_params?: SearchParams;
  multivector_mode?: 'Replace' | 'Append';
  consistency?: ReadConsistency;
  timeout?: number;
  shard_key?: string | string[];
}

export interface QdrantSearchResult {
  id: PointId;
  version?: number;
  payload?: Record<string, unknown>;
  score: number;
  vectors?: Record<string, number[]>;
  shard_key?: string;
  order_value?: unknown;
}

export interface ReadConsistency {
  type: 'all' | 'majority' | 'quorum' | 'single';
  value?: number;
}

export interface WriteOrdering {
  type: 'weak' | 'medium' | 'strong';
}

// ============================================================================
// Knowledge Item Types (for Qdrant Memory Operations)
// ============================================================================

export interface KnowledgeItem {
  id: string | number;
  kind: string;
  scope: Record<string, unknown>;
  data: Record<string, unknown>;
  expiry_at?: string;
  created_at: string;
  updated_at: string;
}

export interface SearchResult {
  id: string | number;
  kind: string;
  scope: Record<string, unknown>;
  data: Record<string, unknown>;
  created_at: string;
  confidence_score: number;
  match_type: 'exact' | 'fuzzy' | 'semantic';
  highlight?: string[];
}

export interface MemoryFilter {
  kind?: string;
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
  };
  expiry_before?: string;
  expiry_after?: string;
  ttl_duration_min?: number;
  ttl_duration_max?: number;
  is_permanent?: boolean;
  include_expired?: boolean;
  has_expiry?: boolean;
  ttl_policy?: string;
}

// ============================================================================
// Qdrant Type Guards for Runtime Validation
// ============================================================================

/**
 * Type guard functions for Qdrant-related runtime validation
 */

export function isQdrantClientConfig(obj: unknown): obj is QdrantClientConfig {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const config = obj as Record<string, unknown>;
  return (
    typeof config.url === 'string' &&
    (config.timeout === undefined || typeof config.timeout === 'number') &&
    (config.apiKey === undefined || typeof config.apiKey === 'string') &&
    (config.https === undefined || typeof config.https === 'boolean') &&
    (config.port === undefined || typeof config.port === 'number') &&
    (config.host === undefined || typeof config.host === 'string')
  );
}

export function isQdrantFilter(obj: unknown): obj is QdrantFilter {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const filter = obj as Record<string, unknown>;

  // Check for valid filter structure
  const hasValidMust = filter.must === undefined || Array.isArray(filter.must);
  const hasValidMustNot = filter.must_not === undefined || Array.isArray(filter.must_not);
  const hasValidShould = filter.should === undefined || Array.isArray(filter.should);
  const hasValidMinShould = filter.min_should === undefined ||
    (typeof filter.min_should === 'object' &&
     filter.min_should !== null &&
     'conditions' in filter.min_should &&
     'min_count' in filter.min_should);

  return hasValidMust && hasValidMustNot && hasValidShould && hasValidMinShould;
}

export function isQdrantCondition(obj: unknown): obj is QdrantCondition {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const condition = obj as Record<string, unknown>;

  // Check for at least one valid condition type
  return (
    (condition.key === undefined || typeof condition.key === 'string') &&
    (condition.range === undefined || isRangeCondition(condition.range)) &&
    (condition.match === undefined || isMatchCondition(condition.match)) &&
    (condition.is_null === undefined || isIsNullCondition(condition.is_null)) &&
    (condition.is_empty === undefined || isEmptyCondition(condition.is_empty)) &&
    (condition.has_id === undefined || isHasIdCondition(condition.has_id)) &&
    (condition.values_count === undefined || isValuesCountCondition(condition.values_count))
  );
}

export function isRangeCondition(obj: unknown): obj is RangeCondition {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const range = obj as Record<string, unknown>;
  return (
    (range.gte === undefined || typeof range.gte === 'number') &&
    (range.gt === undefined || typeof range.gt === 'number') &&
    (range.lte === undefined || typeof range.lte === 'number') &&
    (range.lt === undefined || typeof range.lt === 'number')
  );
}

export function isMatchCondition(obj: unknown): obj is MatchCondition {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const match = obj as Record<string, unknown>;
  return (
    (match.value === undefined || match.value !== undefined) &&
    (match.any === undefined || Array.isArray(match.any)) &&
    (match.text === undefined || typeof match.text === 'string') &&
    (match.keywords === undefined || Array.isArray(match.keywords)) &&
    (match.integers === undefined || Array.isArray(match.integers)) &&
    (match.boolean === undefined || typeof match.boolean === 'boolean') &&
    (match.datetime === undefined || typeof match.datetime === 'string')
  );
}

export function isIsNullCondition(obj: unknown): boolean {
  return obj !== null && typeof obj === 'object' && 'key' in obj && typeof (obj as { key: unknown }).key === 'string';
}

export function isEmptyCondition(obj: unknown): boolean {
  return obj !== null && typeof obj === 'object' && 'key' in obj && typeof (obj as { key: unknown }).key === 'string';
}

export function isHasIdCondition(obj: unknown): obj is HasIdCondition {
  return obj !== null &&
         typeof obj === 'object' &&
         'has_id' in obj &&
         Array.isArray((obj as { has_id: unknown }).has_id) &&
         (obj as { has_id: unknown[] }).has_id.every(id => typeof id === 'string' || typeof id === 'number');
}

export function isValuesCountCondition(obj: unknown): obj is ValuesCountCondition {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const condition = obj as { values_count?: Record<string, unknown> };
  if (!condition.values_count || typeof condition.values_count !== 'object') {
    return false;
  }

  const valuesCount = condition.values_count;
  return (
    (valuesCount.lt === undefined || typeof valuesCount.lt === 'number') &&
    (valuesCount.lte === undefined || typeof valuesCount.lte === 'number') &&
    (valuesCount.gt === undefined || typeof valuesCount.gt === 'number') &&
    (valuesCount.gte === undefined || typeof valuesCount.gte === 'number')
  );
}

export function isMemoryFilter(obj: unknown): obj is MemoryFilter {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const filter = obj as Record<string, unknown>;

  // Validate optional fields
  if (filter.kind !== undefined && typeof filter.kind !== 'string') {
    return false;
  }

  if (filter.expiry_before !== undefined && typeof filter.expiry_before !== 'string') {
    return false;
  }

  if (filter.expiry_after !== undefined && typeof filter.expiry_after !== 'string') {
    return false;
  }

  if (filter.ttl_duration_min !== undefined && typeof filter.ttl_duration_min !== 'number') {
    return false;
  }

  if (filter.ttl_duration_max !== undefined && typeof filter.ttl_duration_max !== 'number') {
    return false;
  }

  if (filter.is_permanent !== undefined && typeof filter.is_permanent !== 'boolean') {
    return false;
  }

  if (filter.include_expired !== undefined && typeof filter.include_expired !== 'boolean') {
    return false;
  }

  // Validate scope if present
  if (filter.scope !== undefined) {
    if (!filter.scope || typeof filter.scope !== 'object') {
      return false;
    }

    const scope = filter.scope as Record<string, unknown>;
    if (scope.project !== undefined && typeof scope.project !== 'string') {
      return false;
    }

    if (scope.branch !== undefined && typeof scope.branch !== 'string') {
      return false;
    }

    if (scope.org !== undefined && typeof scope.org !== 'string') {
      return false;
    }
  }

  return true;
}

export function isQdrantPointStruct(obj: unknown): obj is QdrantPointStruct {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const point = obj as Record<string, unknown>;

  return (
    (typeof point.id === 'string' || typeof point.id === 'number') &&
    Array.isArray(point.vector) &&
    point.vector.every((v: unknown) => typeof v === 'number') &&
    (point.payload === undefined || typeof point.payload === 'object') &&
    (point.shard_key === undefined || typeof point.shard_key === 'string' || Array.isArray(point.shard_key))
  );
}

export function isQdrantScoredPoint(obj: unknown): obj is QdrantScoredPoint {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const point = obj as Record<string, unknown>;

  return (
    point.id !== undefined && typeof point.id === 'object' && // PointId is an object
    typeof point.score === 'number' &&
    (point.payload === undefined || typeof point.payload === 'object') &&
    (point.vectors === undefined || typeof point.vectors === 'object') &&
    (point.shard_key === undefined || typeof point.shard_key === 'string')
  );
}

export function isKnowledgeItem(obj: unknown): obj is KnowledgeItem {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const item = obj as Record<string, unknown>;

  return (
    (typeof item.id === 'string' || typeof item.id === 'number') &&
    typeof item.kind === 'string' &&
    typeof item.scope === 'object' &&
    item.scope !== null &&
    typeof item.data === 'object' &&
    item.data !== null &&
    (item.expiry_at === undefined || typeof item.expiry_at === 'string') &&
    typeof item.created_at === 'string' &&
    typeof item.updated_at === 'string'
  );
}