/**
 * API Service - Comprehensive API management for Cortex Memory system
 * Provides RESTful API, GraphQL, authentication, rate limiting, and monitoring capabilities
 */

import type {
  ApiEndpoint,
  ApiMetrics,
  ApiRequest,
  ApiResponse,
  ApiVersion,
  AuthenticationMethod,
  GraphQLSchema,
  RateLimitConfig,
} from '../types/api-interfaces.js';

export interface UploadedFile {
  fieldname: string;
  originalname: string;
  encoding: string;
  mimetype: string;
  size: number;
  buffer: Buffer;
}

export interface ApiUser {
  id: string;
  username: string;
  roles: string[];
  permissions: string[];
  metadata?: Record<string, unknown>;
}

/**
 * API Service class
 */
export class ApiService {
  private endpoints: Map<string, ApiEndpoint> = new Map();
  private versions: Map<string, ApiVersion> = new Map();
  private metrics: ApiMetrics[] = [];
  private aggregatedMetrics: {
    totalRequests: number;
    successfulRequests: number;
    failedRequests: number;
    averageResponseTime: number;
    requestsPerSecond: number;
    endpointMetrics: Record<string, unknown>;
    errorRates: Record<string, number>;
    statusCodes: Record<string, number>;
  };
  private rateLimitStore: Map<string, { count: number; resetTime: number }> = new Map();

  constructor() {
    this.aggregatedMetrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageResponseTime: 0,
      requestsPerSecond: 0,
      endpointMetrics: {},
      errorRates: {},
      statusCodes: {},
    };
  }

  /**
   * Register a new API endpoint
   */
  async registerEndpoint(endpoint: ApiEndpoint): Promise<void> {
    const key = `${endpoint.method}:${endpoint.path}`;
    this.endpoints.set(key, endpoint);
  }

  /**
   * Register API version
   */
  async registerVersion(version: ApiVersion): Promise<void> {
    this.versions.set(version.version, version);
  }

  /**
   * Get all registered endpoints
   */
  getEndpoints(): ApiEndpoint[] {
    return Array.from(this.endpoints.values());
  }

  /**
   * Get all registered versions
   */
  getVersions(): ApiVersion[] {
    return Array.from(this.versions.values());
  }

  /**
   * Get endpoint by path and method
   */
  getEndpoint(path: string, method: string): ApiEndpoint | undefined {
    const key = `${method}:${path}`;
    return this.endpoints.get(key);
  }

  /**
   * Handle API request
   */
  async handleRequest(request: ApiRequest): Promise<ApiResponse> {
    const startTime = Date.now();

    try {
      // Check rate limiting
      if (!(await this.checkRateLimit(request))) {
        return {
          status: 429,
          body: { error: 'Rate limit exceeded' },
          headers: { 'Content-Type': 'application/json' },
          timestamp: new Date(),
        };
      }

      // Find endpoint
      const endpoint = this.getEndpoint(request.path, request.method);
      if (!endpoint) {
        return {
          status: 404,
          body: { error: 'Endpoint not found' },
          headers: { 'Content-Type': 'application/json' },
          timestamp: new Date(),
        };
      }

      // Check authentication
      if (endpoint.authentication && endpoint.authentication.length > 0) {
        const authResult = await this.authenticate(request, endpoint.authentication);
        if (!authResult.valid) {
          return {
            status: 401,
            body: { error: authResult.error || 'Authentication failed' },
            headers: { 'Content-Type': 'application/json' },
            timestamp: new Date(),
          };
        }
        // Attach user to request
        if (authResult.user) {
          request.user = authResult.user;
        }
      }

      // Execute endpoint handler
      const result = await endpoint.handler(request);

      // Update metrics
      const duration = Date.now() - startTime;
      this.updateMetrics(request.path, request.method, 200, duration);

      return {
        status: 200,
        body: result,
        headers: { 'Content-Type': 'application/json' },
        timestamp: new Date(),
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      this.updateMetrics(request.path, request.method, 500, duration);

      return {
        status: 500,
        body: { error: error instanceof Error ? error.message : 'Internal server error' },
        headers: { 'Content-Type': 'application/json' },
        timestamp: new Date(),
      };
    }
  }

  /**
   * Register GraphQL schema
   */
  async registerGraphQLSchema(schema: GraphQLSchema): Promise<void> {
    // Stub implementation for GraphQL schema registration
  }

  /**
   * Execute GraphQL query
   */
  async executeGraphQLQuery(
    query: string,
    variables?: Record<string, unknown>,
    context?: unknown
  ): Promise<unknown> {
    // Stub implementation for GraphQL query execution
    return { data: null, errors: [] };
  }

  /**
   * Get API metrics
   */
  getMetrics(): ApiMetrics[] {
    return [...this.metrics];
  }

  /**
   * Get aggregated metrics
   */
  getAggregatedMetrics(): {
    totalRequests: number;
    successfulRequests: number;
    failedRequests: number;
    averageResponseTime: number;
    requestsPerSecond: number;
    endpointMetrics: Record<string, unknown>;
    errorRates: Record<string, number>;
    statusCodes: Record<string, number>;
  } {
    return { ...this.aggregatedMetrics };
  }

  /**
   * Reset metrics
   */
  resetMetrics(): void {
    this.metrics = [];
    this.aggregatedMetrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageResponseTime: 0,
      requestsPerSecond: 0,
      endpointMetrics: {},
      errorRates: {},
      statusCodes: {},
    };
  }

  /**
   * Configure rate limiting
   */
  configureRateLimit(config: RateLimitConfig): void {
    // Stub implementation for rate limiting configuration
  }

  /**
   * Generate OpenAPI documentation
   */
  async generateOpenAPIDoc(version?: string): Promise<unknown> {
    // Stub implementation for OpenAPI documentation generation
    return {
      openapi: '3.0.0',
      info: { title: 'Cortex Memory API', version: version || '1.0.0' },
      paths: {},
    };
  }

  /**
   * Validate API request
   */
  async validateRequest(
    request: ApiRequest,
    endpoint: ApiEndpoint
  ): Promise<{
    valid: boolean;
    errors: string[];
  }> {
    const errors: string[] = [];

    // Validate required parameters
    if (endpoint.parameters) {
      for (const param of endpoint.parameters) {
        if (param.required && !request.params?.[param.name] && !request.query[param.name]) {
          errors.push(`Missing required parameter: ${param.name}`);
        }
      }
    }

    return { valid: errors.length === 0, errors };
  }

  // Private helper methods

  private async checkRateLimit(request: ApiRequest): Promise<boolean> {
    // Simple rate limiting implementation
    const clientId = request.headers['x-client-id'] || request.user?.id || 'anonymous';
    const now = Date.now();
    const windowMs = 60000; // 1 minute window
    const maxRequests = 100; // Max requests per window

    const clientData = this.rateLimitStore.get(clientId);

    if (!clientData || now > clientData.resetTime) {
      this.rateLimitStore.set(clientId, {
        count: 1,
        resetTime: now + windowMs,
      });
      return true;
    }

    if (clientData.count >= maxRequests) {
      return false;
    }

    clientData.count++;
    return true;
  }

  private async authenticate(
    request: ApiRequest,
    methods: AuthenticationMethod[]
  ): Promise<{ valid: boolean; user?: ApiUser; error?: string }> {
    for (const method of methods) {
      try {
        const user = await method.validate(request);
        if (user) {
          return { valid: true, user };
        }
      } catch (error) {
        // Continue to next method if validation fails
        continue;
      }
    }

    return { valid: false, error: 'Invalid authentication credentials' };
  }

  private updateMetrics(path: string, method: string, statusCode: number, duration: number): void {
    // Create individual metric entry
    const metric: ApiMetrics = {
      endpoint: path,
      method,
      status: statusCode,
      duration,
      timestamp: new Date(),
      userAgent: '', // Will be populated from request if available
    };

    // Add to metrics array (keep last 1000 entries to prevent memory issues)
    this.metrics.push(metric);
    if (this.metrics.length > 1000) {
      this.metrics = this.metrics.slice(-1000);
    }

    // Update aggregated metrics
    this.aggregatedMetrics.totalRequests++;

    if (statusCode >= 200 && statusCode < 300) {
      this.aggregatedMetrics.successfulRequests++;
    } else {
      this.aggregatedMetrics.failedRequests++;
    }

    // Update average response time
    this.aggregatedMetrics.averageResponseTime =
      (this.aggregatedMetrics.averageResponseTime * (this.aggregatedMetrics.totalRequests - 1) +
        duration) /
      this.aggregatedMetrics.totalRequests;

    // Update endpoint metrics
    const endpointKey = `${method}:${path}`;
    if (!this.aggregatedMetrics.endpointMetrics[endpointKey]) {
      this.aggregatedMetrics.endpointMetrics[endpointKey] = {
        requests: 0,
        averageResponseTime: 0,
        errorRate: 0,
      };
    }

    const endpointMetric = this.aggregatedMetrics.endpointMetrics[endpointKey];
    endpointMetric.requests++;
    endpointMetric.averageResponseTime =
      (endpointMetric.averageResponseTime * (endpointMetric.requests - 1) + duration) /
      endpointMetric.requests;

    if (statusCode >= 400) {
      endpointMetric.errorRate =
        (endpointMetric.errorRate * (endpointMetric.requests - 1) + 1) / endpointMetric.requests;
    }

    // Update status codes
    const statusCodeKey = statusCode.toString();
    this.aggregatedMetrics.statusCodes[statusCodeKey] =
      (this.aggregatedMetrics.statusCodes[statusCodeKey] || 0) + 1;
  }
}

// Export singleton instance
export const apiService = new ApiService();

// Export convenience functions
export const registerApiEndpoint = (endpoint: ApiEndpoint) => apiService.registerEndpoint(endpoint);

export const registerApiVersion = (version: ApiVersion) => apiService.registerVersion(version);

export const handleApiRequest = (request: ApiRequest) => apiService.handleRequest(request);

export const getApiMetrics = () => apiService.getMetrics();

export const generateApiDocumentation = (version?: string) =>
  apiService.generateOpenAPIDoc(version);
