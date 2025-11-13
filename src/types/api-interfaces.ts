/**
 * API Service Type Definitions
 *
 * Comprehensive type definitions for advanced API service functionality including
 * RESTful APIs, GraphQL, versioning, authentication, rate limiting, and monitoring.
 */

export interface ApiEndpoint {
  path: string;
  method: string;
  handler: (request: ApiRequest) => Promise<unknown>;
  middleware?: Array<
    (req: ApiRequest, res: ApiResponse, next: () => Promise<void>) => Promise<void>
  >;
  parameters?: ApiParameter[];
  authentication?: AuthenticationMethod[];
  rateLimit?: RateLimitConfig;
  version?: string;
  deprecated?: boolean;
  timeout?: number;
  responses?: Record<string, unknown>;
  description?: string;
  metadata?: Record<string, unknown>;
}

export interface ApiVersion {
  version: string;
  status: 'active' | 'deprecated' | 'preview' | 'retired';
  deprecationDate?: Date;
  retirementDate?: Date;
  migrationPath?: string;
  supportedEndpoints: string[];
  description?: string;
  metadata?: Record<string, unknown>;
}

export interface ApiRequest {
  path: string;
  method: string;
  headers: Record<string, string>;
  query: Record<string, string>;
  body?: unknown;
  params?: Record<string, string>;
  files?: UploadedFile[];
  user?: ApiUser;
  correlationId?: string;
  timestamp: Date;
}

export interface ApiResponse {
  status: number;
  headers: Record<string, string>;
  body?: unknown;
  error?: ApiError;
  correlationId?: string;
  timestamp: Date;
  duration?: number;
}

export interface ApiParameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  required: boolean;
  in: 'path' | 'query' | 'header' | 'body';
  validation?: ValidationRule[];
  defaultValue?: unknown;
  description?: string;
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  pattern?: string;
  enum?: unknown[];
  minItems?: number;
  maxItems?: number;
  format?: string;
}

export interface ValidationRule {
  type: 'required' | 'min' | 'max' | 'pattern' | 'custom';
  value?: unknown;
  message?: string;
  validator?: (value: unknown) => boolean | string;
}

export interface ApiMiddleware {
  name?: string;
  priority?: number;
  execute: (request: ApiRequest, response: ApiResponse, next: () => Promise<void>) => Promise<void>;
}

export interface AuthenticationMethod {
  type: 'api_key' | 'jwt' | 'oauth' | 'basic' | 'mfa';
  config: Record<string, unknown>;
  validate: (request: ApiRequest) => Promise<ApiUser | null>;
}

export interface ApiUser {
  id: string;
  username: string;
  roles: string[];
  permissions: string[];
  metadata?: Record<string, unknown>;
  authentication?: {
    method: string;
    expires?: Date;
    refreshToken?: string;
  };
}

export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  keyGenerator?: (request: ApiRequest) => string;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  headers?: boolean;
}

export interface GraphQLSchema {
  typeDefs: string;
  resolvers: Record<string, unknown>;
  subscriptions?: Record<string, unknown>;
  context?: (request: ApiRequest) => Promise<unknown>;
}

export interface ApiMetrics {
  endpoint: string;
  method: string;
  status: number;
  duration: number;
  timestamp: Date;
  userAgent?: string;
  userId?: string;
  error?: string;
  client?: string;
  totalRequests?: number;
  averageResponseTime?: number;

  successfulRequests?: unknown

  failedRequests?: unknown

  endpointMetrics?: unknown
}

export interface ServiceEndpoint {
  name: string;
  url: string;
  healthCheck?: string;
  timeout?: number;
  retries?: number;
  circuitBreaker?: CircuitBreakerConfig;
  loadBalancing?: LoadBalancingStrategy;
}

export interface CircuitBreakerConfig {
  threshold: number;
  timeout: number;
  resetTimeout: number;
  monitoring?: boolean;
}

export interface LoadBalancingStrategy {
  type: 'round-robin' | 'least-connections' | 'random' | 'weighted';
  config?: Record<string, unknown>;
}

export interface UploadedFile {
  name: string;
  originalName: string;
  mimeType: string;
  size: number;
  buffer?: Buffer;
  path?: string;
}

export interface ApiError {
  code: string;
  message: string;
  details?: unknown;
  stack?: string;
}

export interface OpenAPIDocument {
  openapi: string;
  info: {
    title: string;
    version: string;
    description?: string;
  };
  servers?: Array<{
    url: string;
    description?: string;
  }>;
  paths: Record<string, unknown>;
  components?: {
    schemas?: Record<string, unknown>;
    securitySchemes?: Record<string, unknown>;
  };
  security?: Array<Record<string, string[]>>;
}
