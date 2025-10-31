/**
 * Advanced API Service Implementation
 *
 * Comprehensive API service providing RESTful endpoint management, GraphQL support,
 * versioning, authentication, rate limiting, monitoring, and cross-service integration.
 */

import type {
  ApiEndpoint,
  ApiVersion,
  ApiRequest,
  ApiResponse,
  RateLimitConfig,
  GraphQLSchema,
  ApiMetrics,
  ApiMiddleware,
} from '../types/api-interfaces.js';

export class ApiService {
  private endpoints: Map<string, ApiEndpoint> = new Map();
  private versions: Map<string, ApiVersion> = new Map();
  private requestMetrics: Map<string, ApiMetrics[]> = new Map();
  private activeConnections: Set<string> = new Set();
  private middleware: ApiMiddleware[] = [];
  private schemas: Map<string, GraphQLSchema> = new Map();
  private rateLimits: Map<string, RateLimitConfig> = new Map();
  private clientUsage: Map<string, { count: number; lastReset: number }> = new Map();
  private defaultTimeout: number = 30000; // 30 seconds default

  /**
   * Register a RESTful API endpoint
   */
  async registerEndpoint(endpoint: ApiEndpoint): Promise<void> {
    const key = `${endpoint.method}:${endpoint.path}`;
    this.endpoints.set(key, endpoint);
  }

  /**
   * Register an API version
   */
  async registerVersion(version: ApiVersion): Promise<void> {
    // Validate version format
    if (!this.isValidVersion(version.version)) {
      throw new Error(`Invalid version format: ${version.version}`);
    }

    // Check if version already exists
    if (this.versions.has(version.version)) {
      throw new Error(`Version ${version.version} already exists`);
    }

    this.versions.set(version.version, version);
  }

  /**
   * Process an API request
   */
  async processRequest(request: ApiRequest): Promise<ApiResponse> {
    const startTime = Date.now();
    const connectionId = this.generateConnectionId();
    let response: ApiResponse;

    // Track active connection
    this.activeConnections.add(connectionId);

    try {
      // Find endpoint
      const endpoint = this.findEndpoint(request.path, request.method);
      if (!endpoint) {
        response = {
          status: 404,
          headers: {},
          body: { error: 'Endpoint not found' },
          timestamp: new Date(),
          ...(request.correlationId && { correlationId: request.correlationId }),
        };
        return response;
      }

      // Validate request parameters
      const validationResult = this.validateRequest(request, endpoint);
      if (!validationResult.isValid) {
        response = {
          status: 400,
          headers: {},
          body: {
            error: 'Bad Request',
            details: validationResult.errors,
          },
          timestamp: new Date(),
          ...(request.correlationId && { correlationId: request.correlationId }),
        };
        return response;
      }

      // Execute request with timeout
      const timeoutMs = endpoint.timeout || this.defaultTimeout;
      const handlerPromise = this.executeWithMiddleware(request, endpoint);

      const timeoutPromise = new Promise<ApiResponse>((_, reject) => {
        setTimeout(() => {
          reject(new Error('Request timeout'));
        }, timeoutMs);
      });

      try {
        const handlerResult = await Promise.race([handlerPromise, timeoutPromise]);

        // Ensure response is properly formatted
        response = {
          status: 200,
          headers: {},
          body: handlerResult,
          timestamp: new Date(),
          ...(request.correlationId && { correlationId: request.correlationId }),
        };
      } catch (_error) {
        if (_error instanceof Error && _error.message === 'Request timeout') {
          response = {
            status: 408,
            headers: {},
            body: { error: 'Request timeout' },
            timestamp: new Date(),
            ...(request.correlationId && { correlationId: request.correlationId }),
          };
        } else {
          throw _error;
        }
      }
    } catch (_error) {
      response = {
        status: 500,
        headers: {},
        body: { error: 'Internal server error' },
        timestamp: new Date(),
        ...(request.correlationId && { correlationId: request.correlationId }),
      };
    } finally {
      // Remove connection from active connections
      this.activeConnections.delete(connectionId);
    }

    // Add duration
    response.duration = Date.now() - startTime;

    // Record metrics
    this.recordMetrics(request, response);

    return response;
  }

  /**
   * Execute request with middleware chain
   */
  private async executeWithMiddleware(request: ApiRequest, endpoint: ApiEndpoint): Promise<any> {
    // Apply middleware in sequence
    const executeMiddleware = async (middlewareArray: any[], index: number = 0): Promise<void> => {
      if (index >= middlewareArray.length) {
        return;
      }

      const middleware = middlewareArray[index];
      await middleware(request, {} as ApiResponse, async () => {
        await executeMiddleware(middlewareArray, index + 1);
      });
    };

    // Apply endpoint-level middleware first
    if (endpoint.middleware) {
      await executeMiddleware(endpoint.middleware);
    }

    // Apply global middleware
    await executeMiddleware(this.middleware);

    // Execute endpoint handler
    const result = await endpoint.handler(request);

    return result;
  }

  /**
   * Generate unique connection ID
   */
  private generateConnectionId(): string {
    return `conn_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Find endpoint by path and method
   */
  private findEndpoint(path: string, method: string): ApiEndpoint | undefined {
    // Direct match
    const directKey = `${method}:${path}`;
    if (this.endpoints.has(directKey)) {
      return this.endpoints.get(directKey);
    }

    // Parameterized match
    for (const [, endpoint] of this.endpoints.entries()) {
      if (this.pathMatches(path, endpoint.path) && endpoint.method === method) {
        return endpoint;
      }
    }

    return undefined;
  }

  /**
   * Check if request path matches endpoint path (supports parameters)
   */
  private pathMatches(requestPath: string, endpointPath: string): boolean {
    const requestParts = requestPath.split('/').filter(Boolean);
    const endpointParts = endpointPath.split('/').filter(Boolean);

    if (requestParts.length !== endpointParts.length) {
      return false;
    }

    for (let i = 0; i < endpointParts.length; i++) {
      const endpointPart = endpointParts[i];
      const requestPart = requestParts[i];

      // Parameter match
      if (endpointPart.startsWith(':')) {
        continue;
      }

      if (endpointPart !== requestPart) {
        return false;
      }
    }

    return true;
  }

  /**
   * Validate version format
   */
  private isValidVersion(version: string): boolean {
    // Support both semantic versioning (x.y.z) and simple versions (v1, v2, etc.)
    const semanticVersionPattern = /^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$/;
    const simpleVersionPattern = /^v\d+(\.\d+)*$/;
    return semanticVersionPattern.test(version) || simpleVersionPattern.test(version);
  }

  /**
   * Record request metrics
   */
  private recordMetrics(request: ApiRequest, response: ApiResponse): void {
    const metrics: ApiMetrics = {
      endpoint: request.path,
      method: request.method,
      status: response.status,
      duration: response.duration || 0,
      timestamp: new Date(),
      ...(request.user?.id && { userId: request.user.id }),
      ...(response.error?.code && { error: response.error.code }),
    };

    const key = `${request.method}:${request.path}`;
    if (!this.requestMetrics.has(key)) {
      this.requestMetrics.set(key, []);
    }

    this.requestMetrics.get(key)!.push(metrics);

    // Keep only last 1000 metrics per endpoint
    const metricsArray = this.requestMetrics.get(key)!;
    if (metricsArray.length > 1000) {
      metricsArray.splice(0, metricsArray.length - 1000);
    }
  }

  /**
   * Register GraphQL schema
   */
  async registerGraphQLSchema(name: string, schema: GraphQLSchema): Promise<void> {
    this.schemas.set(name, schema);
  }

  /**
   * Execute GraphQL query
   */
  async executeGraphQLQuery(
    _schemaName: string,
    _query: string,
    _variables?: any,
    _context?: any
  ): Promise<any> {
    // Mock GraphQL execution - in real implementation, use graphql-js
    return {
      data: {},
      errors: [],
    };
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    details: Record<string, any>;
  }> {
    const uptime = process.uptime();

    // System resource monitoring (mock implementation)
    const systemResources = {
      memory: {
        used: Math.random() * 100, // Mock memory usage percentage
        available: Math.random() * 100,
        total: 100,
      },
      cpu: {
        usage: Math.random() * 100, // Mock CPU usage percentage
        loadAverage: [Math.random(), Math.random(), Math.random()],
      },
      disk: {
        used: Math.random() * 100, // Mock disk usage percentage
        available: Math.random() * 100,
        total: 100,
      },
    };

    // Determine health status based on system resources
    let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
    const issues: string[] = [];

    // Memory checks
    if (systemResources.memory.used > 90) {
      status = 'unhealthy';
      issues.push('Critical memory usage');
    } else if (systemResources.memory.used > 80) {
      status = 'degraded';
      issues.push('High memory usage');
    }

    // CPU checks
    if (systemResources.cpu.usage > 90) {
      status = 'unhealthy';
      issues.push('Critical CPU usage');
    } else if (systemResources.cpu.usage > 80) {
      status = 'degraded';
      issues.push('High CPU usage');
    }

    // Disk checks
    if (systemResources.disk.used > 95) {
      status = 'unhealthy';
      issues.push('Critical disk usage');
    } else if (systemResources.disk.used > 85) {
      status = 'degraded';
      issues.push('High disk usage');
    }

    // Connection checks
    if (this.activeConnections.size > 1000) {
      status = status === 'unhealthy' ? 'unhealthy' : 'degraded';
      issues.push('High connection count');
    }

    const details = {
      uptime: Math.floor(uptime),
      uptimeFormatted: this.formatUptime(uptime),
      timestamp: new Date().toISOString(),
      activeConnections: this.activeConnections.size,
      totalEndpoints: this.endpoints.size,
      totalVersions: this.versions.size,
      metricsEndpoints: this.requestMetrics.size,
      memoryUsage: systemResources.memory.used,
      cpuUsage: systemResources.cpu.usage,
      diskUsage: systemResources.disk.used,
      systemResources,
      issues: issues.length > 0 ? issues : undefined,
      memoryUsagePercent: Math.round(systemResources.memory.used),
      cpuUsagePercent: Math.round(systemResources.cpu.usage),
      diskUsagePercent: Math.round(systemResources.disk.used),
    };

    return {
      status,
      details,
    };
  }

  /**
   * Format uptime into human readable format
   */
  private formatUptime(seconds: number): string {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);

    const parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);

    return parts.join(' ');
  }

  /**
   * Get system resource usage
   */
  async getSystemResources(): Promise<{
    memory: { used: number; available: number; total: number };
    cpu: { usage: number; loadAverage: number[] };
    disk: { used: number; available: number; total: number };
  }> {
    // Mock implementation - in real implementation, use actual system monitoring
    return {
      memory: {
        used: Math.random() * 100,
        available: Math.random() * 100,
        total: 100,
      },
      cpu: {
        usage: Math.random() * 100,
        loadAverage: [Math.random(), Math.random(), Math.random()],
      },
      disk: {
        used: Math.random() * 100,
        available: Math.random() * 100,
        total: 100,
      },
    };
  }

  /**
   * Get metrics for analysis
   */
  async getMetrics(endpoint?: string, method?: string): Promise<ApiMetrics[]> {
    if (!endpoint && !method) {
      // Return all metrics
      const allMetrics: ApiMetrics[] = [];
      for (const metrics of this.requestMetrics.values()) {
        allMetrics.push(...metrics);
      }
      return allMetrics;
    }

    const key = method ? `${method}:${endpoint}` : `*:${endpoint}`;
    return this.requestMetrics.get(key) || [];
  }

  /**
   * Generate OpenAPI documentation for a version
   */
  async generateOpenApiDoc(version: string): Promise<any> {
    const apiVersion = this.versions.get(version);
    if (!apiVersion) {
      throw new Error(`Version ${version} not found`);
    }

    return {
      openapi: '3.0.0',
      info: {
        title: 'Cortex API',
        version: apiVersion.version,
        description: apiVersion.description || 'Cortex Memory API',
      },
      paths: Object.fromEntries(
        Array.from(this.endpoints.entries()).map(([_key, endpoint]) => [
          endpoint.path,
          {
            [endpoint.method.toLowerCase()]: {
              summary: endpoint.description || 'API Endpoint',
              responses: endpoint.responses || {
                200: { description: 'Success' },
              },
            },
          },
        ])
      ),
    };
  }

  /**
   * Validate request against endpoint parameters
   */
  private validateRequest(
    request: ApiRequest,
    endpoint: ApiEndpoint
  ): {
    isValid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    if (!endpoint.parameters) {
      return { isValid: true, errors: [] };
    }

    for (const param of endpoint.parameters) {
      let value: any;
      let source: string;

      // Get parameter value from appropriate location
      switch (param.in) {
        case 'body':
          value = request.body?.[param.name];
          source = 'request body';
          break;
        case 'header':
          value = request.headers?.[param.name.toLowerCase()];
          source = 'headers';
          break;
        case 'query':
          value = request.query?.[param.name];
          source = 'query parameters';
          break;
        default:
          continue; // Skip unsupported parameter locations
      }

      // Check if required parameter is missing
      if (param.required && (value === undefined || value === null)) {
        errors.push(`Required parameter '${param.name}' is missing from ${source}`);
        continue;
      }

      // Skip validation if parameter is not provided and not required
      if (value === undefined || value === null) {
        continue;
      }

      // Type validation
      if (param.type) {
        const typeError = this.validateParameterType(param.name, value, param.type, source);
        if (typeError) {
          errors.push(typeError);
        }
      }

      // String-specific validations
      if (param.type === 'string') {
        if (param.minLength !== undefined && value.length < param.minLength) {
          errors.push(
            `Parameter '${param.name}' must be at least ${param.minLength} characters long`
          );
        }
        if (param.maxLength !== undefined && value.length > param.maxLength) {
          errors.push(
            `Parameter '${param.name}' must be at most ${param.maxLength} characters long`
          );
        }
        if (param.pattern && !new RegExp(param.pattern).test(value)) {
          errors.push(`Parameter '${param.name}' does not match required pattern`);
        }
        if (param.enum && !param.enum.includes(value)) {
          errors.push(`Parameter '${param.name}' must be one of: ${param.enum.join(', ')}`);
        }
      }

      // Number-specific validations
      if (param.type === 'number') {
        const numValue = Number(value);
        if (isNaN(numValue)) {
          errors.push(`Parameter '${param.name}' must be a valid number`);
        } else {
          if (param.minimum !== undefined && numValue < param.minimum) {
            errors.push(`Parameter '${param.name}' must be at least ${param.minimum}`);
          }
          if (param.maximum !== undefined && numValue > param.maximum) {
            errors.push(`Parameter '${param.name}' must be at most ${param.maximum}`);
          }
        }
      }

      // Array-specific validations
      if (param.type === 'array') {
        if (!Array.isArray(value)) {
          errors.push(`Parameter '${param.name}' must be an array`);
        } else {
          if (param.minItems !== undefined && value.length < param.minItems) {
            errors.push(`Parameter '${param.name}' must have at least ${param.minItems} items`);
          }
          if (param.maxItems !== undefined && value.length > param.maxItems) {
            errors.push(`Parameter '${param.name}' must have at most ${param.maxItems} items`);
          }
        }
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  /**
   * Validate parameter type
   */
  private validateParameterType(
    name: string,
    value: any,
    expectedType: string,
    source: string
  ): string | null {
    switch (expectedType) {
      case 'string':
        if (typeof value !== 'string') {
          return `Parameter '${name}' in ${source} must be a string, got ${typeof value}`;
        }
        break;
      case 'number':
        if (typeof value !== 'number' && !/^\d+(\.\d+)?$/.test(String(value))) {
          return `Parameter '${name}' in ${source} must be a number, got ${typeof value}`;
        }
        break;
      case 'boolean':
        if (typeof value !== 'boolean' && !/^(true|false)$/i.test(String(value))) {
          return `Parameter '${name}' in ${source} must be a boolean, got ${typeof value}`;
        }
        break;
      case 'array':
        if (!Array.isArray(value)) {
          return `Parameter '${name}' in ${source} must be an array, got ${typeof value}`;
        }
        break;
      case 'object':
        if (typeof value !== 'object' || value === null || Array.isArray(value)) {
          return `Parameter '${name}' in ${source} must be an object, got ${typeof value}`;
        }
        break;
      default:
        // Unknown type, skip validation
        break;
    }
    return null;
  }

  /**
   * Validate API key authentication
   */
  async validateApiKey(request: ApiRequest): Promise<boolean> {
    const apiKey =
      request.headers?.['x-api-key'] || request.headers?.['authorization']?.replace('Bearer ', '');
    if (!apiKey) {
      return false;
    }

    // Mock validation - in real implementation, validate against database/API key service
    return apiKey.startsWith('ak_') && apiKey.length > 10;
  }

  /**
   * Validate authentication
   */
  async validateAuthentication(request: ApiRequest): Promise<boolean> {
    // Check for API key authentication
    const apiKey =
      request.headers?.['x-api-key'] || request.headers?.['authorization']?.replace('Bearer ', '');
    if (apiKey) {
      const isValid = await this.validateApiKey(request);
      if (isValid) {
        return true;
      }
    }

    // Check for JWT token authentication
    const token = request.headers?.['authorization']?.replace('Bearer ', '');
    if (token && token.startsWith('eyJ')) {
      // Mock JWT validation - in real implementation, verify JWT signature and claims
      try {
        const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
        return !!payload.sub; // Return true if subject exists
      } catch {
        return false;
      }
    }

    // Check for OAuth 2.0 bearer token
    const bearerToken = request.headers?.['authorization']?.replace('Bearer ', '');
    if (bearerToken && bearerToken.startsWith('oauth_')) {
      return bearerToken.length > 10; // Mock OAuth validation
    }

    return false;
  }

  /**
   * Get authentication details (for internal use)
   */
  async getAuthenticationDetails(request: ApiRequest): Promise<{
    isValid: boolean;
    userId?: string;
    error?: string;
  }> {
    const isValid = await this.validateAuthentication(request);
    if (isValid) {
      return { isValid: true, userId: 'authenticated-user' };
    }
    return { isValid: false, error: 'Authentication failed' };
  }

  /**
   * Cleanup expired connections
   */
  async cleanup(): Promise<void> {
    // Mock cleanup - in real implementation, handle connection cleanup
    this.activeConnections.clear();
  }

  /**
   * Cleanup expired connections (alias for cleanup)
   */
  async cleanupExpiredConnections(): Promise<void> {
    await this.cleanup();
  }

  /**
   * Register rate limit configuration
   */
  async registerRateLimit(config: RateLimitConfig): Promise<void> {
    this.rateLimits.set(config.windowMs.toString(), config);
  }

  /**
   * Check rate limit for client
   */
  async checkRateLimit(
    clientId: string,
    endpoint?: string
  ): Promise<{
    allowed: boolean;
    limit: number;
    remaining: number;
    resetTime: number;
  }> {
    const now = Date.now();
    const key = `${clientId}:${endpoint || '*'}`;
    const usage = this.clientUsage.get(key);

    // Get rate limit config (mock - use default)
    const config: RateLimitConfig = {
      windowMs: 60000, // 1 minute
      maxRequests: 100,
    };

    if (!usage || now - usage.lastReset > config.windowMs) {
      // Reset or initialize usage
      this.clientUsage.set(key, {
        count: 1,
        lastReset: now,
      });
      return {
        allowed: true,
        limit: config.maxRequests,
        remaining: config.maxRequests - 1,
        resetTime: now + config.windowMs,
      };
    }

    if (usage.count >= config.maxRequests) {
      return {
        allowed: false,
        limit: config.maxRequests,
        remaining: 0,
        resetTime: usage.lastReset + config.windowMs,
      };
    }

    usage.count++;
    return {
      allowed: true,
      limit: config.maxRequests,
      remaining: config.maxRequests - usage.count,
      resetTime: usage.lastReset + config.windowMs,
    };
  }

  /**
   * Log request for analytics
   */
  async logRequest(request: ApiRequest, response: ApiResponse, duration?: number): Promise<void> {
    const metrics: ApiMetrics = {
      endpoint: request.path,
      method: request.method,
      status: response.status,
      duration: duration || response.duration || 0,
      timestamp: new Date(),
      client: request.headers?.['x-client-id'] || 'unknown',
      ...(request.user?.id && { userId: request.user.id }),
      ...(response.error?.code && { error: response.error.code }),
    };

    const key = `${request.method}:${request.path}`;
    if (!this.requestMetrics.has(key)) {
      this.requestMetrics.set(key, []);
    }

    this.requestMetrics.get(key)!.push(metrics);

    // Keep only last 1000 metrics per endpoint
    const metricsArray = this.requestMetrics.get(key)!;
    if (metricsArray.length > 1000) {
      metricsArray.splice(0, metricsArray.length - 1000);
    }
  }

  /**
   * Get system memory usage
   */
  getMemoryUsage(): { used: number; total: number; free: number } {
    // Mock implementation - in real implementation, use actual memory monitoring
    const used = Math.random() * 100;
    const total = 100;
    const free = total - used;

    return { used, total, free };
  }

  /**
   * Get uptime in seconds
   */
  getUptime(): number {
    return Math.floor(process.uptime());
  }

  /**
   * Get performance metrics
   */
  async getPerformanceMetrics(): Promise<{
    averageResponseTime: number;
    requestsPerSecond: number;
    errorRate: number;
    totalRequests: number;
  }> {
    const allMetrics: ApiMetrics[] = [];
    for (const metrics of this.requestMetrics.values()) {
      allMetrics.push(...metrics);
    }

    if (allMetrics.length === 0) {
      return {
        averageResponseTime: 0,
        requestsPerSecond: 0,
        errorRate: 0,
        totalRequests: 0,
      };
    }

    const totalRequests = allMetrics.length;
    const averageResponseTime =
      allMetrics.reduce((sum, m) => sum + (m.duration || 0), 0) / totalRequests;
    const errorCount = allMetrics.filter((m) => m.status >= 400).length;
    const errorRate = (errorCount / totalRequests) * 100;

    // Calculate requests per second over the last minute
    const oneMinuteAgo = new Date(Date.now() - 60000);
    const recentRequests = allMetrics.filter((m) => m.timestamp >= oneMinuteAgo);
    const requestsPerSecond = recentRequests.length / 60;

    return {
      averageResponseTime: Math.round(averageResponseTime * 100) / 100,
      requestsPerSecond: Math.round(requestsPerSecond * 100) / 100,
      errorRate: Math.round(errorRate * 100) / 100,
      totalRequests,
    };
  }
}
