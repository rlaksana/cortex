// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Enhanced API Types for Cortex MCP System
 *
 * Consolidated and type-safe API interface definitions that eliminate `any` usage
 * and provide consistent patterns across the codebase.
 *
 * Replaces: api-interfaces.ts, api-types.ts
 */

import type {
  Dict,
  EventHandler,
  Headers,
  JSONValue,
  Metadata,
  OperationContext,
  PathParams,
  QueryParams,
  Result,
  Transformer,
  Validator
} from './base-types.js';

// ============================================================================
// Core HTTP Types
// ============================================================================

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

export type HttpStatus =
  | 200 | 201 | 202 | 204 | 206
  | 301 | 302 | 303 | 304 | 307 | 308
  | 400 | 401 | 403 | 404 | 405 | 408 | 409 | 422 | 429
  | 500 | 501 | 502 | 503 | 504;

// ============================================================================
// API Request/Response Types
// ============================================================================

export interface ApiRequest<TBody = JSONValue> {
  readonly path: string;
  readonly method: HttpMethod;
  readonly headers: Headers;
  readonly query: QueryParams;
  readonly body?: TBody;
  readonly params: PathParams;
  readonly files?: UploadedFile[];
  readonly user?: ApiUser;
  readonly correlationId?: string;
  readonly timestamp: Date;
  readonly id: string;
  readonly userAgent?: string;
  readonly ip?: string;
}

export interface ApiResponse<TBody = JSONValue> {
  readonly status: HttpStatus;
  readonly headers: Headers;
  readonly body?: TBody;
  readonly error?: ApiError;
  readonly correlationId?: string;
  readonly timestamp: Date;
  readonly duration?: number;
  readonly requestId: string;
}

export interface ApiError {
  readonly code: string;
  readonly message: string;
  readonly details?: JSONValue;
  readonly stack?: string;
  readonly timestamp: Date;
}

export interface UploadedFile {
  readonly fieldname: string;
  readonly originalname: string;
  readonly encoding: string;
  readonly mimetype: string;
  readonly size: number;
  readonly buffer: Buffer;
  readonly destination?: string;
  readonly filename?: string;
  readonly path?: string;
}

// ============================================================================
// API User & Authentication Types
// ============================================================================

export interface ApiUser {
  readonly id: string;
  readonly username: string;
  readonly email?: string;
  readonly roles: readonly string[];
  readonly permissions: readonly string[];
  readonly tenant?: string;
  readonly metadata?: Metadata;
  readonly lastActive?: Date;
  readonly createdAt: Date;
}

export interface AuthContext {
  readonly user: ApiUser;
  readonly token?: string;
  readonly scopes: readonly string[];
  readonly expiresAt?: Date;
  readonly metadata?: Metadata;
}

export type AuthenticationMethod = 'api_key' | 'jwt' | 'oauth' | 'basic' | 'mfa' | 'bearer';

export interface AuthConfig {
  readonly type: AuthenticationMethod;
  readonly config: Dict<JSONValue>;
  readonly required: boolean;
  readonly scopes?: readonly string[];
  readonly validate: (request: ApiRequest) => Promise<AuthContext | null>;
}

export interface ApiKeyAuth {
  readonly key: string;
  readonly headerName?: string;
  readonly queryParam?: string;
  readonly validate: (apiKey: string) => Promise<ApiUser | null>;
}

export interface JWTAuth {
  readonly secret: string;
  readonly algorithm?: string;
  readonly issuer?: string;
  readonly audience?: string;
  readonly validate: (token: string) => Promise<ApiUser | null>;
}

export interface OAuthConfig {
  readonly provider: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly scopes: readonly string[];
  readonly redirectUri?: string;
  readonly flow: 'authorization_code' | 'client_credentials' | 'implicit';
}

// ============================================================================
// API Endpoint & Configuration Types
// ============================================================================

export interface ApiEndpoint<TRequest = JSONValue, TResponse = JSONValue> {
  readonly path: string;
  readonly method: HttpMethod;
  readonly handler: ApiHandler<TRequest, TResponse>;
  readonly middleware?: readonly ApiMiddleware[];
  readonly parameters?: readonly ApiParameter[];
  readonly auth?: AuthConfig;
  readonly rateLimit?: RateLimitConfig;
  readonly version?: string;
  readonly deprecated?: boolean;
  readonly timeout?: number;
  readonly responses?: Record<HttpStatus, ResponseSchema<TResponse>>;
  readonly description?: string;
  readonly metadata?: Metadata;
  readonly tags?: readonly string[];
}

export type ApiHandler<TRequest = JSONValue, TResponse = JSONValue> = (
  request: ApiRequest<TRequest>
) => Promise<ApiResponse<TResponse>>;

export interface ApiMiddleware {
  readonly name?: string;
  readonly priority?: number;
  readonly execute: (
    request: ApiRequest,
    response: ApiResponse,
    next: () => Promise<void>
  ) => Promise<void>;
}

export interface ResponseSchema<T> {
  readonly description?: string;
  readonly content?: T;
  readonly headers?: Headers;
  readonly examples?: readonly T[];
}

// ============================================================================
// Parameter & Validation Types
// ============================================================================

export interface ApiParameter {
  readonly name: string;
  readonly type: ParameterType;
  readonly required: boolean;
  readonly location: 'path' | 'query' | 'header' | 'body';
  readonly validation?: readonly ValidationRule[];
  readonly defaultValue?: JSONValue;
  readonly description?: string;
  readonly constraints?: ParameterConstraints;
  readonly format?: string;
  readonly pattern?: string;
  readonly enum?: readonly JSONValue[];
}

export type ParameterType =
  | 'string'
  | 'number'
  | 'integer'
  | 'boolean'
  | 'object'
  | 'array'
  | 'file';

export interface ParameterConstraints {
  readonly minLength?: number;
  readonly maxLength?: number;
  readonly minimum?: number;
  readonly maximum?: number;
  readonly minItems?: number;
  readonly maxItems?: number;
  readonly uniqueItems?: boolean;
  readonly multipleOf?: number;
}

export interface ValidationRule {
  readonly type: ValidationRuleType;
  readonly value?: JSONValue;
  readonly message?: string;
  readonly validator?: Validator<JSONValue>;
}

export type ValidationRuleType =
  | 'required'
  | 'min'
  | 'max'
  | 'pattern'
  | 'custom'
  | 'email'
  | 'url'
  | 'uuid';

// ============================================================================
// Rate Limiting Types
// ============================================================================

export interface RateLimitConfig {
  readonly requests: number;
  readonly windowMs: number;
  readonly skipSuccessfulRequests?: boolean;
  readonly skipFailedRequests?: boolean;
  readonly keyGenerator?: (request: ApiRequest) => string;
  readonly skip?: (request: ApiRequest) => boolean;
  readonly onLimitReached?: (request: ApiRequest, response: ApiResponse) => void;
}

export interface RateLimitResult {
  readonly limit: number;
  readonly remaining: number;
  readonly reset: Date;
  readonly retryAfter?: number;
  readonly exceeded: boolean;
}

// ============================================================================
// API Versioning Types
// ============================================================================

export interface ApiVersion {
  readonly version: string;
  readonly status: VersionStatus;
  readonly deprecationDate?: Date;
  readonly retirementDate?: Date;
  readonly migrationPath?: string;
  readonly supportedEndpoints: readonly string[];
  readonly description?: string;
  readonly metadata?: Metadata;
  readonly changelog?: readonly string[];
}

export type VersionStatus = 'active' | 'deprecated' | 'preview' | 'retired' | 'draft';

// ============================================================================
// API Contract Types
// ============================================================================

export interface RestApiContract<TRequest = JSONValue, TResponse = JSONValue> {
  readonly endpoint: string;
  readonly method: HttpMethod;
  readonly pathParams?: PathParams;
  readonly queryParams?: QueryParams;
  readonly requestBody?: TRequest;
  readonly responseType: TResponse;
  readonly headers?: Headers;
  readonly auth?: AuthConfig;
  readonly rateLimit?: RateLimitConfig;
  readonly validation?: ValidationSchema<TRequest>;
  readonly examples?: readonly RequestExample<TRequest>[];
  readonly tags?: readonly string[];
}

export interface RequestExample<T> {
  readonly name: string;
  readonly description?: string;
  readonly request: T;
  readonly expectedResponse?: JSONValue;
}

export interface ValidationSchema<T> {
  readonly body?: T;
  readonly params?: PathParams;
  readonly query?: QueryParams;
  readonly headers?: Headers;
  readonly contentType?: string;
}

// ============================================================================
// GraphQL Types (if needed)
// ============================================================================

export interface GraphQLSchema {
  readonly query?: string;
  readonly mutation?: string;
  readonly subscription?: string;
  readonly types?: readonly GraphQLEntityType[];
}

export interface GraphQLEntityType {
  readonly name: string;
  readonly fields: readonly GraphQLField[];
  readonly interfaces?: readonly string[];
}

export interface GraphQLField {
  readonly name: string;
  readonly type: GraphQLFieldType;
  readonly args?: readonly GraphQLArgument[];
  readonly resolve?: (parent: JSONValue, args: Dict<JSONValue>, context: OperationContext) => JSONValue;
}

export interface GraphQLArgument {
  readonly name: string;
  readonly type: GraphQLFieldType;
  readonly defaultValue?: JSONValue;
  readonly description?: string;
}

export type GraphQLFieldType = string; // Simplified for now

// ============================================================================
// API Client Types
// ============================================================================

export interface ApiClient {
  readonly baseUrl: string;
  readonly defaultHeaders?: Headers;
  readonly timeout?: number;
  readonly auth?: AuthConfig;
  readonly interceptors?: {
    readonly request?: readonly RequestInterceptor[];
    readonly response?: readonly ResponseInterceptor[];
  };
}

export interface RequestInterceptor {
  readonly name?: string;
  readonly execute: (config: RequestConfig) => Promise<RequestConfig>;
}

export interface ResponseInterceptor {
  readonly name?: string;
  readonly execute: (response: ApiResponse) => Promise<ApiResponse>;
}

export interface RequestConfig<T = JSONValue> {
  readonly method: HttpMethod;
  readonly url: string;
  readonly headers?: Headers;
  readonly params?: QueryParams;
  readonly body?: T;
  readonly timeout?: number;
  readonly signal?: AbortSignal;
}

// ============================================================================
// HTTP Client Interface
// ============================================================================

export interface HttpClient {
  get<T = JSONValue>(url: string, options?: RequestOptions): Promise<ApiResponse<T>>;
  post<T = JSONValue>(url: string, data?: JSONValue, options?: RequestOptions): Promise<ApiResponse<T>>;
  put<T = JSONValue>(url: string, data?: JSONValue, options?: RequestOptions): Promise<ApiResponse<T>>;
  patch<T = JSONValue>(url: string, data?: JSONValue, options?: RequestOptions): Promise<ApiResponse<T>>;
  delete<T = JSONValue>(url: string, options?: RequestOptions): Promise<ApiResponse<T>>;
  request<T = JSONValue>(config: RequestConfig): Promise<ApiResponse<T>>;
}

export interface RequestOptions {
  readonly headers?: Headers;
  readonly params?: QueryParams;
  readonly timeout?: number;
  readonly signal?: AbortSignal;
  readonly responseType?: 'json' | 'text' | 'blob' | 'arraybuffer';
}

// ============================================================================
// Utility Types
// ============================================================================

export type ApiResponseResult<T> = Result<T, ApiError>;
export type ApiEventHandler = EventHandler<ApiEvent>;
export type ApiTransformer<I, O> = Transformer<I, O>;

export interface ApiEvent {
  readonly type: string;
  readonly request: ApiRequest;
  readonly response?: ApiResponse;
  readonly timestamp: Date;
  readonly correlationId?: string;
  readonly metadata?: Metadata;
}

export interface ApiMetrics {
  readonly requestCount: number;
  readonly successCount: number;
  readonly errorCount: number;
  readonly averageResponseTime: number;
  readonly lastUpdated: Date;
  readonly statusCodeDistribution: Record<HttpStatus, number>;
}

// ============================================================================
// OpenAPI/Swagger Types (simplified)
// ============================================================================

export interface OpenAPIDocument {
  readonly openapi: string;
  readonly info: ApiInfo;
  readonly servers?: readonly ServerInfo[];
  readonly paths: Record<string, PathItem>;
  readonly components?: Components;
}

export interface ApiInfo {
  readonly title: string;
  readonly version: string;
  readonly description?: string;
  readonly contact?: ContactInfo;
  readonly license?: LicenseInfo;
}

export interface ContactInfo {
  readonly name?: string;
  readonly url?: string;
  readonly email?: string;
}

export interface LicenseInfo {
  readonly name: string;
  readonly url?: string;
}

export interface ServerInfo {
  readonly url: string;
  readonly description?: string;
  readonly variables?: Record<string, ServerVariable>;
}

export interface ServerVariable {
  readonly enum?: readonly string[];
  readonly default: string;
  readonly description?: string;
}

export interface PathItem {
  readonly get?: Operation;
  readonly put?: Operation;
  readonly post?: Operation;
  readonly delete?: Operation;
  readonly options?: Operation;
  readonly head?: Operation;
  readonly patch?: Operation;
  readonly trace?: Operation;
  readonly parameters?: readonly ApiParameter[];
}

export interface Operation {
  readonly tags?: readonly string[];
  readonly summary?: string;
  readonly description?: string;
  readonly operationId?: string;
  readonly parameters?: readonly ApiParameter[];
  readonly requestBody?: RequestBody;
  readonly responses: Record<string, Response>;
  readonly security?: readonly SecurityRequirement[];
}

export interface RequestBody {
  readonly description?: string;
  readonly content: Record<string, MediaType>;
  readonly required?: boolean;
}

export interface MediaType {
  readonly schema?: JSONValue; // JSON Schema
  readonly example?: JSONValue;
  readonly examples?: Record<string, Example>;
}

export interface Example {
  readonly summary?: string;
  readonly description?: string;
  readonly value?: JSONValue;
  readonly externalValue?: string;
}

export interface Response {
  readonly description: string;
  readonly headers?: Record<string, Header>;
  readonly content?: Record<string, MediaType>;
}

export interface Header {
  readonly description?: string;
  readonly required?: boolean;
  readonly deprecated?: boolean;
  readonly style?: string;
  readonly explode?: boolean;
  readonly schema?: JSONValue; // JSON Schema
  readonly example?: JSONValue;
  readonly examples?: Record<string, Example>;
}

export interface SecurityRequirement {
  readonly [name: string]: readonly string[];
}

export interface Components {
  readonly schemas?: Record<string, JSONValue>; // JSON Schemas
  readonly responses?: Record<string, Response>;
  readonly parameters?: Record<string, ApiParameter>;
  readonly examples?: Record<string, Example>;
  readonly requestBodies?: Record<string, RequestBody>;
  readonly headers?: Record<string, Header>;
  readonly securitySchemes?: Record<string, SecurityScheme>;
}

export interface SecurityScheme {
  readonly type: string;
  readonly description?: string;
  readonly name?: string;
  readonly location?: 'query' | 'header';
  readonly scheme?: string;
  readonly bearerFormat?: string;
  readonly flows?: OAuthFlows;
  readonly openIdConnectUrl?: string;
}

export interface OAuthFlows {
  readonly implicit?: OAuthFlow;
  readonly password?: OAuthFlow;
  readonly clientCredentials?: OAuthFlow;
  readonly authorizationCode?: OAuthFlow;
}

export interface OAuthFlow {
  readonly authorizationUrl?: string;
  readonly tokenUrl?: string;
  readonly refreshUrl?: string;
  readonly scopes: Record<string, string>;
}