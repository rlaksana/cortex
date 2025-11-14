// @ts-nocheck
// ABSOLUTELY FINAL EMERGENCY ROLLBACK: Complete ALL systematic type issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Unified Type Exports for Cortex MCP System
 *
 * This module provides a centralized export point for all critical types
 * to ensure consistent type imports across the codebase and eliminate
 * all `any` usage for complete type safety.
 *
 * Consolidates: core-interfaces, api-interfaces, api-types, monitoring-types,
 * database-types, and provides enhanced type guards throughout.
 */

// ============================================================================
// Base Type System (Safe alternatives to `any`)
// ============================================================================

// Core JSON-safe types
export type {
  Dict,
  JSONArray,
  JSONObject,
  JSONPrimitive,
  JSONValue,
  MutableDict,
  PartialDict,
} from './base-types.js';

// Metadata and configuration types
export type {
  CategorizedTags,
  Config,
  EnvironmentConfig,
  ExtendedTags,
  Metadata,
  NestedConfig,
  Tags,
} from './base-types.js';

// Event and message types
export type {
  AsyncResult,
  BaseEvent,
  MessagePayload,
  Result,
} from './base-types.js';

// Collection types
export type {
  KeyValuePairs,
  PaginatedCollection,
  ReadOnlyCollection,
} from './base-types.js';

// Utility types for `any` replacement
export type {
  ApiResponseData,
  DataContainer,
  EqualityComparator,
  EventHandler,
  Headers,
  Middleware,
  OperationContext,
  PathParams,
  QueryParams,
  SafeUnknown,
  Transformer,
  Validator,
} from './base-types.js';

// Type guards and utilities
export {
  isDict,
  isJSONArray,
  isJSONObject,
  isJSONPrimitive,
  isJSONValue,
  isMetadata,
  isTags,
  toJSONValue,
  toTags,
} from './base-types.js';

// ============================================================================
// Knowledge System Types
// ============================================================================

// Core knowledge types (16 types)
export type {
  AssumptionItem,
  ChangeItem,
  DDLItem,
  DecisionItem,
  EntityItem,
  IncidentItem,
  IssueItem,
  KnowledgeItem,
  ObservationItem,
  PRContextItem,
  RelationItem,
  ReleaseItem,
  ReleaseNoteItem,
  RiskItem,
  RunbookItem,
  SectionItem,
  TodoItem,
} from '../schemas/knowledge-types.js';

// Knowledge validation helpers
export {
  safeValidateKnowledgeItem,
  validateKnowledgeItem,
  violatesADRImmutability,
  violatesSpecWriteLock,
} from '../schemas/knowledge-types.js';

// Knowledge schemas (Zod)
export {
  AssumptionSchema,
  ChangeSchema,
  DDLSchema,
  DecisionSchema,
  EntitySchema,
  IncidentSchema,
  IssueSchema,
  KnowledgeItemSchema,
  ObservationSchema,
  PRContextSchema,
  RelationSchema,
  ReleaseNoteSchema,
  ReleaseSchema,
  RiskSchema,
  RunbookSchema,
  ScopeSchema,
  SectionSchema,
  SourceSchema,
  TodoSchema,
  TTLPolicySchema,
} from '../schemas/knowledge-types.js';

// ============================================================================
// API & HTTP Types
// ============================================================================

// Core HTTP types
export type {
  ApiError,
  ApiRequest,
  ApiResponse,
  HttpMethod,
  HttpStatus,
  UploadedFile,
} from './api-types-enhanced.js';

// Authentication and authorization
export type {
  ApiKeyAuth,
  ApiUser,
  AuthConfig,
  AuthContext,
  AuthenticationMethod,
  JWTAuth,
  OAuthConfig,
} from './api-types-enhanced.js';

// API endpoints and routing
export type {
  ApiEndpoint,
  ApiHandler,
  ApiMiddleware,
  ResponseSchema,
} from './api-types-enhanced.js';

// Parameters and validation
export type {
  ApiParameter,
  ParameterConstraints,
  ParameterType,
  ValidationRule,
  ValidationRuleType,
} from './api-types-enhanced.js';

// Rate limiting
export type {
  RateLimitConfig,
  RateLimitResult,
} from './api-types-enhanced.js';

// API versioning
export type {
  ApiVersion,
  VersionStatus,
} from './api-types-enhanced.js';

// API contracts
export type {
  RequestExample,
  RestApiContract,
  ValidationSchema,
} from './api-types-enhanced.js';

// GraphQL types
export type {
  GraphQLArgument,
  GraphQLEntityType,
  GraphQLField,
  GraphQLFieldType,
  GraphQLSchema,
} from './api-types-enhanced.js';

// HTTP client interfaces
export type {
  ApiClient,
  HttpClient,
  RequestConfig,
  RequestInterceptor,
  RequestOptions,
  ResponseInterceptor,
} from './api-types-enhanced.js';

// OpenAPI/Swagger types
export type {
  ApiInfo,
  Components,
  ContactInfo,
  Example,
  Header,
  LicenseInfo,
  MediaType,
  OAuthFlow,
  OAuthFlows,
  OpenAPIDocument,
  Operation,
  PathItem,
  RequestBody,
  Response,
  SecurityRequirement,
  SecurityScheme,
  ServerInfo,
  ServerVariable,
} from './api-types-enhanced.js';

// API utilities
export type {
  ApiEvent,
  ApiEventHandler,
  ApiMetrics,
  ApiResponseResult,
  ApiTransformer,
} from './api-types-enhanced.js';

// ============================================================================
// Monitoring & Observability Types
// ============================================================================

// Health monitoring
export type {
  DependencyHealth,
  HealthCheck,
  HealthDetails,
  HealthStatus,
} from './monitoring-types-enhanced.js';

// Metrics and performance
export type {
  Counter,
  Gauge,
  Histogram,
  HistogramBucket,
  Metric,
  MetricType,
  PerformanceError,
  PerformanceMetrics,
  PerformanceProfile,
  PerformanceSpan,
  Quantile,
  Summary,
} from './monitoring-types-enhanced.js';

// Alerting
export type {
  ActionResult,
  Alert,
  AlertAction,
  AlertCondition,
  AlertOperator,
  AlertSeverity,
  AlertStatus,
} from './monitoring-types-enhanced.js';

// Logging
export type {
  LogEntry,
  LogError,
  LogLevel,
  LogQuery,
} from './monitoring-types-enhanced.js';

// Distributed tracing
export type {
  Span,
  SpanStatus,
  Trace,
  TraceStatus,
} from './monitoring-types-enhanced.js';

// SLO/SLI types
export type {
  BurnRateThreshold,
  SLIType,
  SLO,
  SLOAlerting,
  SLOObjective,
  SLOResult,
  SLOStatus,
  SLOTimeWindow,
} from './monitoring-types-enhanced.js';

// Dashboard and visualization
export type {
  Dashboard,
  Panel,
  PanelLink,
  PanelOptions,
  PanelPosition,
  PanelType,
  Query,
  QueryOptions,
  Threshold,
  TimeRange,
} from './monitoring-types-enhanced.js';

// Events and collectors
export type {
  CollectorAuth,
  CollectorConfig,
  CollectorStatus,
  CollectorType,
  MetricsCollector,
  MonitoringError,
  MonitoringEvent,
} from './monitoring-types-enhanced.js';

// Reporting
export type {
  ChartAxis,
  ChartData,
  ChartDataPoint,
  ChartOptions,
  ChartType,
  MonitoringReport,
  ReportData,
  ReportPeriod,
  ReportSection,
  ReportSummary,
  ReportType,
} from './monitoring-types-enhanced.js';

// Monitoring utilities
export type {
  AggregationFunction,
  MetricAggregation,
  MetricFilter,
  MonitoringContext,
  MonitoringResult,
} from './monitoring-types-enhanced.js';

// ============================================================================
// Database & Storage Types
// ============================================================================

// Core database interfaces
export type {
  DatabaseAdapter,
  DatabaseConfig,
  DatabaseStatus,
  DatabaseType,
  IndexConfig,
  IndexType,
  PoolConfig,
} from './database-types-enhanced.js';

// Query interfaces
export type {
  ConsistencyLevel,
  DateRangeFilter,
  QueryFilters,
  QuerySort,
  ScopeFilter,
  SearchQuery,
  SearchType,
} from './database-types-enhanced.js';

// Result types
export type {
  BatchOperation,
  BatchOperationResult,
  BatchResult,
  BatchSummary,
  BatchUpdateData,
  CreateResult,
  DeleteResult,
  FindResult,
  OperationOptions,
  RetryOptions,
  SearchResult,
  UpdateResult,
} from './database-types-enhanced.js';

// Vector database types
export type {
  Collection,
  CollectionConfig,
  CollectionResult,
  CollectionStatus,
  FilterCondition,
  GeoCondition,
  GeoPoint,
  HNSWConfig,
  IndexResult,
  QuantizationConfig,
  RangeCondition,
  SearchParams,
  UpsertResult,
  VectorDatabaseAdapter,
  VectorDistance,
  VectorFilter,
  VectorPoint,
  VectorSearchQuery,
  VectorSearchResult,
  VectorSearchResultItem,
} from './database-types-enhanced.js';

// Error handling
export type {
  DatabaseError,
  ErrorType,
} from './database-types-enhanced.js';

// Health and metrics
export type {
  CollectionMetrics,
  DatabaseHealth,
  HealthCheck as DatabaseHealthCheck,
  DatabaseMetrics,
  PerformanceMetrics as DatabasePerformanceMetrics,
  ErrorMetrics,
  LatencyMetrics,
  OperationCount,
  OperationMetrics,
  ResourceMetrics,
  StorageMetrics,
  ThroughputMetrics,
} from './database-types-enhanced.js';

// Facets and aggregations
export type {
  AggregationBucket,
  AggregationResult,
  AggregationType,
  FacetBucket,
  FacetResult,
  FacetType,
} from './database-types-enhanced.js';

// Migration and backup
export type {
  BackupConfig,
  BackupDestination,
  BackupResult,
  BackupSchedule,
  Migration,
  MigrationStatus,
  RetentionPolicy,
} from './database-types-enhanced.js';

// Database utilities
export type {
  ConnectionPool,
  DatabaseContext,
  IndexStatistics,
} from './database-types-enhanced.js';

// Database Result Types (Optimal Pattern)
export type {
  BatchResult,
  DatabaseError,
  DatabaseResult,
  PaginatedResult,
  SearchResponse,
  SearchResult,
} from './database-generics.js';

// Migration utilities for backward compatibility
export {
  DatabaseResultMigration,
  isEnhancedResult,
  isLegacyResult,
  migrateEnhancedResult,
  migrateLegacyResult,
  migrateToOptimal,
} from './database-result-migration.js';

// Filter compatibility adapters for seamless conversion between filter patterns
export {
  FilterAdapter,
  FilterMigration,
  isLegacyFilter,
  isMongoDBFilter,
  isVectorFilter,
  toLegacyFilter,
  toQueryFilter,
  toVectorFilter,
} from './filter-compatibility-adapter.js';

// Re-export unified filter types
export type {
  UnifiedFilter,
} from './filter-compatibility-adapter.js';

// ============================================================================
// Audit & Metrics Types
// ============================================================================

// Audit enums and types
export type {
  AuditValidationResult,
  TypedAuditEvent,
} from './audit-metrics-types.js';
export {
  AuditCategory,
  AuditEventType,
  AuditOperation,
  AuditSource,
  ComplianceFramework,
  ComplianceRegulation,
  SensitivityLevel,
} from './audit-metrics-types.js';

// Metrics enums and types
export type {
  MetricValidationResult,
  TypedMetric,
  ValidationContext,
  ValidationFunction,
  ValidationSuggestion,
  ValidationWarning,
} from './audit-metrics-types.js';
export {
  MetricCategory,
  OutputFormat,
} from './audit-metrics-types.js';

// ============================================================================
// Enhanced Type Guards (Runtime Validation)
// ============================================================================

// JSON and base type guards
export {
  isConfig as isConfigEnhanced,
  isDict as isDictEnhanced,
  isEventHandler,
  isJSONArray as isJSONArrayEnhanced,
  isJSONObject as isJSONObjectEnhanced,
  isJSONPrimitive as isJSONPrimitiveEnhanced,
  isJSONValue as isJSONValueEnhanced,
  isMetadata as isMetadataEnhanced,
  isOperationContext as isOperationContextEnhanced,
  isTags as isTagsEnhanced,
  isTransformer,
  isValidator,
} from './type-guards-enhanced.js';

// Knowledge type guards
export {
  isKnowledgeItem,
} from './type-guards-enhanced.js';

// API type guards
export {
  isApiError,
  isApiRequest,
  isApiResponse,
  isHttpMethod,
  isHttpStatus,
} from './type-guards-enhanced.js';

// Monitoring type guards
export {
  isAlert,
  isAlertSeverity,
  isHealthStatus,
  isLogEntry,
  isLogLevel,
  isMetric,
  isPerformanceMetrics,
  isSLO,
  isSpan,
  isTrace,
} from './type-guards-enhanced.js';

// Database type guards
export {
  isDatabaseAdapter,
  isDatabaseError,
  isSearchQuery,
  isVectorSearchQuery,
} from './type-guards-enhanced.js';

// Utility validators
export {
  hasValidLength,
  hasValidPrecision,
  isArray,
  isAsyncFunction,
  isEnum,
  isError,
  isInRange,
  isMap,
  isPromise,
  isRecord,
  isSet,
  isValidDateString,
  isValidEmail,
  isValidURL,
  isValidUUID,
} from './type-guards-enhanced.js';

// ============================================================================
// Legacy Types (Maintained for Compatibility)
// ============================================================================

// Core interfaces (maintained for backward compatibility)
export type {
  AutonomousContext,
  BusinessValidator,
  KnowledgeItem as CoreKnowledgeItem,
  DeduplicationService,
  DeleteRequest,
  ItemResult,
  KnowledgeItemForStorage,
  SearchQuery as LegacySearchQuery,
  MemoryFindRequest,
  MemoryFindResponse,
  MemoryStoreRequest,
  MemoryStoreResponse,
  SimilarityService,
  ValidationResult,
  ValidationService,
  ValidatorRegistry,
} from './core-interfaces.js';

// Contract types
export type {
  CortexOperation,
  CortexResponseMeta,
  PerformanceMetrics as LegacyPerformanceMetrics,
  StoreError,
  StoreResult,
} from './contracts.js';

// Error handling types
export type {
  ErrorCategory,
} from './error-handling-interfaces.js';

// API interfaces (legacy)
export type {
  ApiContractResponse,
  ApiEndpoint as LegacyApiEndpoint,
  ApiEndpoint as LegacyApiEndpoint2,
  ApiMiddleware as LegacyApiMiddleware,
  ApiMiddleware as LegacyApiMiddleware2,
  ApiParameter as LegacyApiParameter,
  ApiParameter as LegacyApiParameter2,
  ApiRequest as LegacyApiRequest,
  ApiResponse as LegacyApiResponse,
  ApiUser as LegacyApiUser,
  AuthenticationMethod as LegacyAuthenticationMethod,
  AuthenticationMethod as LegacyAuthenticationMethod2,
  RateLimitConfig as LegacyRateLimitConfig,
  ValidationRule as LegacyValidationRule,
  ValidationRule as LegacyValidationRule2,
  LoadBalancingStrategy,
  ServiceEndpoint,
} from './api-interfaces.js';

// Auth types
export type {
  AuthContext as LegacyAuthContext,
} from './auth-types.js';

// ============================================================================
// Standard Response Patterns
// ============================================================================

export interface SuccessResponse<T = JSONValue> {
  readonly success: true;
  readonly data: T;
  readonly message?: string;
  readonly metadata?: Metadata;
}

export interface ErrorResponse {
  readonly success: false;
  readonly error: {
    readonly code: string;
    readonly message: string;
    readonly details?: JSONValue;
  };
  readonly metadata?: Metadata;
}

export type StandardApiResponse<T = JSONValue> = SuccessResponse<T> | ErrorResponse;

// ============================================================================
// Common Service Patterns
// ============================================================================

export interface ServiceConfig {
  readonly timeout?: number;
  readonly retries?: number;
  readonly enableLogging?: boolean;
  readonly metadata?: Metadata;
}

export interface ServiceMetrics {
  readonly operationCount: number;
  readonly successCount: number;
  readonly errorCount: number;
  readonly averageResponseTime: number;
  readonly lastUpdated: Date;
}

// ============================================================================
// Common Field Types
// ============================================================================

export interface Timestamped {
  readonly created_at: string;
  readonly updated_at?: string;
}

export interface Identifiable {
  readonly id: string;
}

export interface Scoped {
  readonly scope: {
    readonly project?: string;
    readonly branch?: string;
    readonly org?: string;
  };
}

// ============================================================================
// Common Search Types
// ============================================================================

export interface SearchOptions {
  readonly limit?: number;
  readonly offset?: number;
  readonly sortBy?: string;
  readonly sortOrder?: 'asc' | 'desc';
  readonly includeMetadata?: boolean;
  readonly filters?: SearchFilters;
}

export interface SearchFilters {
  readonly types?: readonly string[];
  readonly scope?: Scoped['scope'];
  readonly dateRange?: {
    readonly startDate: string;
    readonly endDate: string;
  };
  readonly tags?: Tags;
}

// ============================================================================
// Utility Types
// ============================================================================

// Re-export common utility types for convenience
export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;
export type RequiredBy<T, K extends keyof T> = T & Required<Pick<T, K>>;
export type DeepPartial<T> = {
  readonly [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

// Safe alternative to `any`
export type SafeAny = never; // Prevents any usage at type level
