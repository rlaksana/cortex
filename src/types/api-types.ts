/**
 * API Type Definitions for Cortex MCP System
 *
 * Provides comprehensive type safety for API interfaces including:
 * - REST API interface contracts
 * - GraphQL schema validation types
 * - API request/response type safety
 * - OpenAPI specification types
 * - Client SDK types
 * - API versioning types
 */

// ============================================================================
// REST API Interface Contracts
// ============================================================================

export interface RestApiContract<TRequest = unknown, TResponse = unknown> {
  endpoint: string;
  method: HttpMethod;
  pathParams?: Record<string, string>;
  queryParams?: Record<string, unknown>;
  requestBody?: TRequest;
  responseType: TResponse;
  headers?: Record<string, string>;
  auth?: AuthRequirement;
  rateLimit?: RateLimitConfig;
  validation?: ValidationSchema<TRequest>;
}

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

export interface AuthRequirement {
  required: boolean;
  scopes?: string[];
  apiKey?: boolean;
  oauth?: OAuthConfig;
}

export interface OAuthConfig {
  provider: string;
  scopes: string[];
  flow: 'authorization_code' | 'client_credentials' | 'implicit';
}

export interface RateLimitConfig {
  requests: number;
  windowMs: number;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
}

export interface ValidationSchema<T> {
  body?: T;
  params?: Record<string, unknown>;
  query?: Record<string, unknown>;
  headers?: Record<string, unknown>;
}

// ============================================================================
// HTTP Request/Response Types
// ============================================================================

export interface HttpRequest<T = unknown> {
  method: HttpMethod;
  url: string;
  headers: Record<string, string>;
  params?: Record<string, string>;
  query?: Record<string, unknown>;
  body?: T;
  timestamp: number;
  id: string;
  userAgent?: string;
  ip?: string;
}

export interface HttpResponse<T = unknown> {
  status: HttpStatus;
  headers: Record<string, string>;
  body?: T;
  timestamp: number;
  requestId: string;
  duration: number;
  size: number;
}

export type HttpStatus =
  | 200
  | 201
  | 202
  | 204
  | 301
  | 302
  | 304
  | 400
  | 401
  | 403
  | 404
  | 409
  | 422
  | 429
  | 500
  | 502
  | 503
  | 504;

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
  timestamp: string;
  requestId: string;
  stack?: string;
  errors?: ValidationError[];
}

export interface ValidationError {
  field: string;
  message: string;
  value?: unknown;
  constraint?: string;
}

// ============================================================================
// GraphQL Schema Types
// ============================================================================

export interface GraphQLSchema {
  query: string;
  mutation?: string;
  subscription?: string;
  types: GraphQLType[];
  directives?: GraphQLDirective[];
}

export interface GraphQLType {
  name: string;
  kind: 'SCALAR' | 'OBJECT' | 'INTERFACE' | 'UNION' | 'ENUM' | 'INPUT_OBJECT' | 'LIST' | 'NON_NULL';
  fields?: GraphQLField[];
  interfaces?: string[];
  possibleTypes?: string[];
}

export interface GraphQLField {
  name: string;
  type: string;
  args?: GraphQLArgument[];
  description?: string;
  deprecationReason?: string;
}

export interface GraphQLArgument {
  name: string;
  type: string;
  defaultValue?: unknown;
  description?: string;
}

export interface GraphQLDirective {
  name: string;
  locations: string[];
  args?: GraphQLArgument[];
  description?: string;
}

export interface GraphQLRequest {
  query: string;
  variables?: Record<string, unknown>;
  operationName?: string;
  extensions?: Record<string, unknown>;
}

export interface GraphQLResponse<T = unknown> {
  data?: T;
  errors?: GraphQLError[];
  extensions?: Record<string, unknown>;
}

export interface GraphQLError {
  message: string;
  locations?: GraphQLErrorLocation[];
  path?: Array<string | number>;
  extensions?: Record<string, unknown>;
}

export interface GraphQLErrorLocation {
  line: number;
  column: number;
}

// ============================================================================
// OpenAPI Specification Types
// ============================================================================

export interface OpenAPIDocument {
  openapi: string;
  info: OpenAPIInfo;
  servers?: OpenAPIServer[];
  paths: OpenAPIPaths;
  components?: OpenAPIComponents;
  security?: OpenAPIRequirement[];
  tags?: OpenAPITag[];
  externalDocs?: OpenAPIExternalDocumentation;
}

export interface OpenAPIInfo {
  title: string;
  description?: string;
  version: string;
  termsOfService?: string;
  contact?: OpenAPIContact;
  license?: OpenAPILicense;
}

export interface OpenAPIContact {
  name?: string;
  url?: string;
  email?: string;
}

export interface OpenAPILicense {
  name: string;
  url?: string;
}

export interface OpenAPIServer {
  url: string;
  description?: string;
  variables?: Record<string, OpenAPIServerVariable>;
}

export interface OpenAPIServerVariable {
  enum?: string[];
  default: string;
  description?: string;
}

export interface OpenAPIPaths {
  [path: string]: OpenAPIPathItem;
}

export interface OpenAPIPathItem {
  summary?: string;
  description?: string;
  get?: OpenAPIOperation;
  put?: OpenAPIOperation;
  post?: OpenAPIOperation;
  delete?: OpenAPIOperation;
  options?: OpenAPIOperation;
  head?: OpenAPIOperation;
  patch?: OpenAPIOperation;
  trace?: OpenAPIOperation;
  parameters?: OpenAPIParameter[];
}

export interface OpenAPIOperation {
  tags?: string[];
  summary?: string;
  description?: string;
  operationId?: string;
  parameters?: OpenAPIParameter[];
  requestBody?: OpenAPIRequestBody;
  responses: OpenAPIResponses;
  security?: OpenAPIRequirement[];
  deprecated?: boolean;
}

export interface OpenAPIParameter {
  name: string;
  in: 'query' | 'header' | 'path' | 'cookie';
  description?: string;
  required?: boolean;
  deprecated?: boolean;
  schema: OpenAPISchema;
  example?: unknown;
}

export interface OpenAPIRequestBody {
  description?: string;
  content: Record<string, OpenAPIMediaType>;
  required?: boolean;
}

export interface OpenAPIResponses {
  [statusCode: string]: OpenAPIResponse;
}

export interface OpenAPIResponse {
  description: string;
  headers?: Record<string, OpenAPIHeader>;
  content?: Record<string, OpenAPIMediaType>;
}

export interface OpenAPIHeader {
  description?: string;
  required?: boolean;
  deprecated?: boolean;
  schema: OpenAPISchema;
}

export interface OpenAPIMediaType {
  schema: OpenAPISchema;
  example?: unknown;
  examples?: Record<string, OpenAPIExample>;
}

export interface OpenAPIExample {
  summary?: string;
  description?: string;
  value?: unknown;
  externalValue?: string;
}

export interface OpenAPIComponents {
  schemas?: Record<string, OpenAPISchema>;
  responses?: Record<string, OpenAPIResponse>;
  parameters?: Record<string, OpenAPIParameter>;
  examples?: Record<string, OpenAPIExample>;
  requestBodies?: Record<string, OpenAPIRequestBody>;
  headers?: Record<string, OpenAPIHeader>;
  securitySchemes?: Record<string, OpenAPISecurityScheme>;
  links?: Record<string, OpenAPILink>;
  callbacks?: Record<string, OpenAPICallback>;
}

export interface OpenAPISchema {
  type?: string;
  format?: string;
  title?: string;
  description?: string;
  default?: unknown;
  multipleOf?: number;
  maximum?: number;
  exclusiveMaximum?: number;
  minimum?: number;
  exclusiveMinimum?: number;
  maxLength?: number;
  minLength?: number;
  pattern?: string;
  maxItems?: number;
  minItems?: number;
  uniqueItems?: boolean;
  maxProperties?: number;
  minProperties?: number;
  required?: string[];
  enum?: unknown[];
  allOf?: OpenAPISchema[];
  oneOf?: OpenAPISchema[];
  anyOf?: OpenAPISchema[];
  not?: OpenAPISchema;
  items?: OpenAPISchema;
  properties?: Record<string, OpenAPISchema>;
  additionalProperties?: boolean | OpenAPISchema;
  readOnly?: boolean;
  writeOnly?: boolean;
  deprecated?: boolean;
}

export interface OpenAPIRequirement {
  [name: string]: string[];
}

export interface OpenAPITag {
  name: string;
  description?: string;
  externalDocs?: OpenAPIExternalDocumentation;
}

export interface OpenAPIExternalDocumentation {
  description?: string;
  url: string;
}

export interface OpenAPISecurityScheme {
  type: 'apiKey' | 'http' | 'oauth2' | 'openIdConnect';
  description?: string;
  name?: string;
  in?: 'query' | 'header' | 'cookie';
  scheme?: string;
  bearerFormat?: string;
  flows?: OAuthFlows;
  openIdConnectUrl?: string;
}

export interface OAuthFlows {
  implicit?: OAuthFlow;
  password?: OAuthFlow;
  clientCredentials?: OAuthFlow;
  authorizationCode?: OAuthFlow;
}

export interface OAuthFlow {
  authorizationUrl?: string;
  tokenUrl?: string;
  refreshUrl?: string;
  scopes: Record<string, string>;
}

export interface OpenAPILink {
  operationRef?: string;
  operationId?: string;
  parameters?: Record<string, unknown>;
  requestBody?: unknown;
  description?: string;
  server?: OpenAPIServer;
}

export interface OpenAPICallback {
  [callbackUrl: string]: OpenAPIPathItem;
}

// ============================================================================
// Client SDK Types
// ============================================================================

export interface ApiClientConfig {
  baseUrl: string;
  apiKey?: string;
  timeout?: number;
  retries?: number;
  retryDelay?: number;
  headers?: Record<string, string>;
  auth?: AuthConfig;
  interceptors?: InterceptorConfig[];
}

export interface AuthConfig {
  type: 'apiKey' | 'bearer' | 'basic' | 'oauth';
  credentials: ApiKeyCredentials | BearerCredentials | BasicCredentials | OAuthCredentials;
}

export interface ApiKeyCredentials {
  key: string;
  headerName?: string;
  queryParam?: string;
}

export interface BearerCredentials {
  token: string;
}

export interface BasicCredentials {
  username: string;
  password: string;
}

export interface OAuthCredentials {
  clientId: string;
  clientSecret: string;
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
}

export interface InterceptorConfig {
  type: 'request' | 'response';
  handler: string | ((...args: unknown[]) => unknown);
  options?: Record<string, unknown>;
}

export interface ApiClient {
  config: ApiClientConfig;
  request<T = unknown>(options: RequestOptions): Promise<ApiResponse<T>>;
  get<T = unknown>(url: string, options?: RequestOptions): Promise<ApiResponse<T>>;
  post<T = unknown>(url: string, data?: unknown, options?: RequestOptions): Promise<ApiResponse<T>>;
  put<T = unknown>(url: string, data?: unknown, options?: RequestOptions): Promise<ApiResponse<T>>;
  patch<T = unknown>(url: string, data?: unknown, options?: RequestOptions): Promise<ApiResponse<T>>;
  delete<T = unknown>(url: string, options?: RequestOptions): Promise<ApiResponse<T>>;
}

export interface RequestOptions {
  headers?: Record<string, string>;
  params?: Record<string, unknown>;
  query?: Record<string, unknown>;
  timeout?: number;
  retries?: number;
  signal?: AbortSignal;
}

export interface ApiResponse<T = unknown> {
  data: T;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  config: RequestOptions;
  request?: unknown;
}

export interface SdkMethod<TRequest = unknown, TResponse = unknown> {
  name: string;
  description?: string;
  parameters: SdkParameter[];
  returnType: TResponse;
  requestType?: TRequest;
  deprecationMessage?: string;
  exampleRequest?: TRequest;
  exampleResponse?: TResponse;
}

export interface SdkParameter {
  name: string;
  type: string;
  required: boolean;
  description?: string;
  defaultValue?: unknown;
  validation?: ValidationRule[];
}

export interface ValidationRule {
  type: 'required' | 'min' | 'max' | 'pattern' | 'custom';
  constraint: unknown;
  message?: string;
}

// ============================================================================
// API Versioning Types
// ============================================================================

export interface ApiVersion {
  version: string;
  status: 'active' | 'deprecated' | 'beta' | 'alpha' | 'experimental';
  releasedAt?: string;
  sunsetAt?: string;
  deprecationMessage?: string;
  migrationGuide?: string;
  breakingChanges?: BreakingChange[];
}

export interface BreakingChange {
  type: 'field_removed' | 'field_type_changed' | 'endpoint_removed' | 'response_type_changed';
  description: string;
  migrationPath?: string;
}

export interface VersionedEndpoint {
  endpoint: string;
  versions: Record<string, VersionedEndpointConfig>;
  defaultVersion?: string;
}

export interface VersionedEndpointConfig {
  version: string;
  contract: RestApiContract;
  deprecationInfo?: DeprecationInfo;
  migrationInfo?: MigrationInfo;
}

export interface DeprecationInfo {
  deprecatedAt: string;
  sunsetAt: string;
  reason: string;
  replacementEndpoint?: string;
  migrationGuide?: string;
}

export interface MigrationInfo {
  fromVersion: string;
  toVersion: string;
  changes: MigrationChange[];
  automatedMigration?: boolean;
  migrationScript?: string;
}

export interface MigrationChange {
  type: 'add' | 'remove' | 'modify' | 'rename';
  path: string;
  oldValue?: unknown;
  newValue?: unknown;
  breaking: boolean;
}

// ============================================================================
// Integration and Performance Types
// ============================================================================

export interface ServiceIntegration {
  name: string;
  version: string;
  endpoints: IntegrationEndpoint[];
  authentication: AuthRequirement;
  rateLimit?: RateLimitConfig;
  healthCheck?: HealthCheckConfig;
  circuitBreaker?: CircuitBreakerConfig;
}

export interface IntegrationEndpoint {
  name: string;
  method: HttpMethod;
  path: string;
  timeout: number;
  retries: number;
  circuitBreaker?: CircuitBreakerEndpointConfig;
}

export interface HealthCheckConfig {
  endpoint: string;
  interval: number;
  timeout: number;
  expectedStatus: HttpStatus;
  healthyThreshold: number;
  unhealthyThreshold: number;
}

export interface CircuitBreakerConfig {
  enabled: boolean;
  failureThreshold: number;
  recoveryTimeout: number;
  monitoringPeriod: number;
  expectedRecoveryTime: number;
}

export interface CircuitBreakerEndpointConfig {
  overrideGlobal?: boolean;
  failureThreshold?: number;
  recoveryTimeout?: number;
}

export interface PerformanceMetrics {
  requestCount: number;
  errorCount: number;
  averageResponseTime: number;
  p50ResponseTime: number;
  p95ResponseTime: number;
  p99ResponseTime: number;
  throughput: number;
  errorRate: number;
  timestamp: string;
}

export interface ApiMonitoring {
  endpoint: string;
  method: HttpMethod;
  metrics: PerformanceMetrics[];
  alerts: MonitoringAlert[];
  dashboards?: MonitoringDashboard[];
}

export interface MonitoringAlert {
  name: string;
  type: 'error_rate' | 'response_time' | 'throughput' | 'availability';
  threshold: number;
  condition: 'greater_than' | 'less_than' | 'equals';
  enabled: boolean;
  channels: AlertChannel[];
}

export interface AlertChannel {
  type: 'email' | 'slack' | 'webhook' | 'pagerduty';
  destination: string;
  enabled: boolean;
}

export interface MonitoringDashboard {
  name: string;
  description?: string;
  widgets: DashboardWidget[];
  refreshInterval?: number;
}

export interface DashboardWidget {
  type: 'chart' | 'metric' | 'table' | 'heatmap';
  title: string;
  query: string;
  config: Record<string, unknown>;
}

// ============================================================================
// Error Handling Types
// ============================================================================

export interface ApiErrorHandler {
  handleError(error: ApiError, context: ErrorContext): ApiErrorResponse;
  logError(error: ApiError, context: ErrorContext): void;
  reportError(error: ApiError, context: ErrorContext): void;
}

export interface ErrorContext {
  request: HttpRequest;
  endpoint?: string;
  userId?: string;
  sessionId?: string;
  correlationId: string;
  timestamp: number;
}

export interface ApiErrorResponse {
  error: ApiError;
  statusCode: HttpStatus;
  headers: Record<string, string>;
  correlationId: string;
  timestamp: string;
}

export interface ErrorCategory {
  type:
    | 'client_error'
    | 'server_error'
    | 'network_error'
    | 'timeout_error'
    | 'authentication_error';
  severity: 'low' | 'medium' | 'high' | 'critical';
  actionable: boolean;
  retryable: boolean;
}

export interface ErrorMapping {
  [errorCode: string]: {
    category: ErrorCategory;
    httpStatus: HttpStatus;
    message?: string;
    userMessage?: string;
    resolution?: string;
  };
}

// ============================================================================
// Utility Types
// ============================================================================

export type ApiResponseData<T> = T extends Promise<infer U> ? U : T;
export type ApiRequestBody<T> = T extends RestApiContract<infer R, unknown> ? R : never;
export type ApiResponseBody<T> = T extends RestApiContract<unknown, infer R> ? R : never;

export type ExtractEndpoints<T extends Record<string, RestApiContract>> = {
  [K in keyof T]: T[K];
};

export type EndpointMethod<T extends RestApiContract> = T['method'];
export type EndpointPath<T extends RestApiContract> = T['endpoint'];
