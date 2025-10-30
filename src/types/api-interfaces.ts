/**
 * API Service Type Definitions
 *
 * Comprehensive type definitions for advanced API service functionality including
 * RESTful APIs, GraphQL, versioning, authentication, rate limiting, and monitoring.
 */

export interface ApiEndpoint {
  path: string;
  method: string;
  handler: (request: ApiRequest) => Promise<any>;
  middleware?: Array<
    (req: ApiRequest, res: ApiResponse, next: () => Promise<void>) => Promise<void>
  >;
  parameters?: ApiParameter[];
  authentication?: AuthenticationMethod[];
  rateLimit?: RateLimitConfig;
  version?: string;
  deprecated?: boolean;
  timeout?: number;
  responses?: Record<string, any>;
  description?: string;
  metadata?: Record<string, any>;
}

export interface ApiVersion {
  version: string;
  status: 'active' | 'deprecated' | 'preview' | 'retired';
  deprecationDate?: Date;
  retirementDate?: Date;
  migrationPath?: string;
  supportedEndpoints: string[];
  description?: string;
  metadata?: Record<string, any>;
}

export interface ApiRequest {
  path: string;
  method: string;
  headers: Record<string, string>;
  query: Record<string, string>;
  body?: any;
  params?: Record<string, string>;
  files?: UploadedFile[];
  user?: ApiUser;
  correlationId?: string;
  timestamp: Date;
}

export interface ApiResponse {
  status: number;
  headers: Record<string, string>;
  body?: any;
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
  defaultValue?: any;
  description?: string;
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  pattern?: string;
  enum?: any[];
  minItems?: number;
  maxItems?: number;
  format?: string;
}

export interface ValidationRule {
  type: 'required' | 'min' | 'max' | 'pattern' | 'custom';
  value?: any;
  message?: string;
  validator?: (value: any) => boolean | string;
}

export interface ApiMiddleware {
  name?: string;
  priority?: number;
  execute: (request: ApiRequest, response: ApiResponse, next: () => Promise<void>) => Promise<void>;
}

export interface AuthenticationMethod {
  type: 'api-key' | 'jwt' | 'oauth' | 'basic' | 'mfa';
  config: Record<string, any>;
  validate: (request: ApiRequest) => Promise<ApiUser | null>;
}

export interface ApiUser {
  id: string;
  username: string;
  roles: string[];
  permissions: string[];
  metadata?: Record<string, any>;
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
  resolvers: Record<string, any>;
  subscriptions?: Record<string, any>;
  context?: (request: ApiRequest) => Promise<any>;
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
  config?: Record<string, any>;
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
  details?: any;
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
  paths: Record<string, any>;
  components?: {
    schemas?: Record<string, any>;
    securitySchemes?: Record<string, any>;
  };
  security?: Array<Record<string, string[]>>;
}
