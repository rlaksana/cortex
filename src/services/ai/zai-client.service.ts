/**
 * ZAI Client Service
 *
 * Production-ready ZAI API client with glm-4.6 model integration,
 * comprehensive error handling, circuit breakers, and monitoring
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { randomUUID } from 'crypto';

import { logger } from '@/utils/logger.js';

import { InMemoryCache } from './utils/in-memory-cache.js';
import { SimplePerformanceMonitor } from './utils/performance-monitor.js';
import { SimpleRateLimiter } from './utils/rate-limiter.js';
import { zaiConfigManager } from '../../config/zai-config.js';
import { ServiceAdapterBase } from '../../interfaces/service-adapter.js';
import type {
  AIServiceStatus,
  IZAIClientService,
  ServiceResponse,
} from '../../interfaces/service-interfaces.js';
import type {
  CircuitBreaker,
  RateLimiter,
  ZAICache,
  ZAIChatRequest,
  ZAIChatResponse,
  ZAIConfig,
  ZAIErrorResponse,
  ZAIEvent,
  ZAIEventListener,
  ZAIMetrics,
  ZAIPerformanceMonitor,
  ZAIServiceStatus,
  ZAIStreamChunk,
} from '../../types/zai-interfaces.js';
import { ZAIError, ZAIErrorType } from '../../types/zai-interfaces.js';

/**
 * Production-ready ZAI client service
 */
export class ZAIClientService extends ServiceAdapterBase implements IZAIClientService {
  private _config: ZAIConfig;
  private circuitBreaker: CircuitBreaker;
  private rateLimiter: RateLimiter;
  private cache: ZAICache;
  private performanceMonitor: ZAIPerformanceMonitor;
  private eventListeners: Set<ZAIEventListener> = new Set();
  private metrics: ZAIMetrics;
  private lastHealthCheck = 0;
  private healthCheckInterval = 60000; // 1 minute

  constructor(config?: ZAIConfig) {
    super('ZAIClientService');
    this._config = config || zaiConfigManager.getZAIConfig();
    this.metrics = {
      timestamp: new Date(),
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageResponseTime: 0,
      p95ResponseTime: 0,
      p99ResponseTime: 0,
      totalTokensUsed: 0,
      totalCost: 0,
      cacheHitRate: 0,
      errorRate: 0,
      uptime: 0,
      lastReset: Date.now(),
      // Compatibility properties
      requestCount: 0,
      successCount: 0,
      errorCount: 0,
      throughput: 0,
      circuitBreakerStatus: 'closed' as const,
      tokensUsed: 0,
      cost: 0,
    };

    this.circuitBreaker = {
      state: 'closed',
      failureCount: 0,
      lastFailureTime: 0,
      nextAttempt: 0,
      config: {
        failureThreshold: this._config.circuitBreakerThreshold || 5,
        timeout: this._config.circuitBreakerTimeout || 60000,
        monitoringPeriod: 30000,
        expectedRecoveryTime: 30000,
      },
    };

    // Initialize rate limiter (RPM -> requests per second)
    const requestsPerSecond = Math.ceil(this._config.rateLimitRPM! / 60);
    this.rateLimiter = new SimpleRateLimiter(requestsPerSecond, 1000);

    // Initialize cache
    this.cache = new InMemoryCache();

    // Initialize performance monitor
    this.performanceMonitor = new SimplePerformanceMonitor();
  }

  /**
   * Generate chat completion
   */
  async generateCompletion(request: ZAIChatRequest): Promise<ServiceResponse<ZAIChatResponse>> {
    return this.executeOperation(
      async () => {
        const requestId = randomUUID();
        const startTime = Date.now();

        // Validate request
        this.validateRequest(request);

        // Check rate limit
        if (!(await this.rateLimiter.isAllowed())) {
          throw new ZAIError(
            'Rate limit exceeded',
            ZAIErrorType['RATE_LIMIT_ERROR'],
            'rate_limit_exceeded'
          );
        }

        // Check circuit breaker
        if (!this.canExecuteRequest()) {
          throw new ZAIError(
            'Service temporarily unavailable due to circuit breaker',
            ZAIErrorType['UNKNOWN_ERROR'],
            'circuit_breaker_open'
          );
        }

        // Emit request started event
        this.emitEvent({
          type: 'request_started',
          data: { requestId, payload: request },
        });

        // Check cache first
        const cacheKey = this.generateCacheKey(request);
        const cachedResponse = await this.cache.get(cacheKey);
        if (cachedResponse) {
          this.emitEvent({
            type: 'request_completed',
            data: { requestId, response: cachedResponse, duration: Date.now() - startTime },
          });
          return { ...cachedResponse, cached: true };
        }

        // Make API request
        const response = await this.makeAPICall(request, requestId);

        // Cache successful response
        await this.cache.set(cacheKey, response);

        // Update metrics
        this.updateMetrics(true, response, Date.now() - startTime);

        // Reset circuit breaker on success
        this.resetCircuitBreaker();

        // Emit request completed event
        this.emitEvent({
          type: 'request_completed',
          data: { requestId, response, duration: Date.now() - startTime },
        });

        return response;
      },
      'generateCompletion',
      { request }
    );
  }

  /**
   * Generate streaming completion
   */
  async generateStreamingCompletion(request: ZAIChatRequest): Promise<AsyncGenerator<ZAIStreamChunk>> {
    // Simplified streaming implementation that returns Promise<AsyncGenerator>
    async function* streamGenerator(this: ZAIClientService): AsyncGenerator<ZAIStreamChunk> {
      const requestId = randomUUID();

      try {
        // Validation and setup similar to generateCompletion
        this.validateRequest(request);

        if (!(await this.rateLimiter.isAllowed())) {
          throw new ZAIError(
            'Rate limit exceeded',
            ZAIErrorType['RATE_LIMIT_ERROR'],
            'rate_limit_exceeded'
          );
        }

        if (!this.canExecuteRequest()) {
          throw new ZAIError(
            'Service temporarily unavailable due to circuit breaker',
            ZAIErrorType['UNKNOWN_ERROR'],
            'circuit_breaker_open'
          );
        }

        // For streaming, we'll make the actual API call
        // This is a simplified implementation - in production, you'd handle streaming properly
        const response = await this.makeAPICall(request, requestId);

        // Yield the response as a single chunk
        // In a real implementation, you'd process the actual streaming response
        yield {
          id: response.id,
          object: 'chat.completion.chunk',
          created: response.created,
          model: response.model,
          choices: response.choices,
          finished: true,
        };
      } catch (error) {
        const zaiError = error instanceof ZAIError ? error : this.convertToZAIError(error);
        throw zaiError;
      }
    }

    return streamGenerator.call(this);
  }

  /**
   * Check if service is available (internal method)
   */
  async _isAvailable(): Promise<boolean> {
    try {
      // Quick health check
      if (this.circuitBreaker.state === 'open') {
        if (Date.now() > this.circuitBreaker.nextAttempt) {
          // Try to close circuit breaker
          this.circuitBreaker.state = 'half-open';
        } else {
          return false;
        }
      }

      // Test with a simple request
      await this.generateCompletion({
        messages: [{ role: 'user', content: 'test' }],
        maxTokens: 1,
      });

      return true;
    } catch (_error) {
      return false;
    }
  }

  /**
   * Get service status (internal method)
   */
  async _getServiceStatus(): Promise<ZAIServiceStatus> {
    const now = Date.now();
    const isHealthy = await this._isAvailable();

    return {
      status: isHealthy ? 'healthy' : this.circuitBreaker.state === 'open' ? 'down' : 'degraded',
      lastCheck: now,
      responseTime: this.metrics.averageResponseTime,
      errorRate: this.metrics.errorRate,
      circuitBreakerState: this.circuitBreaker.state,
      consecutiveFailures: this.circuitBreaker.failureCount,
      uptime: now - this.startTime, // Use base class startTime
    };
  }

  /**
   * Make actual API call to ZAI
   */
  private async makeAPICall(request: ZAIChatRequest, requestId: string): Promise<ZAIChatResponse> {
    const startTime = Date.now();
    this.performanceMonitor.recordRequestStart(requestId);

    try {
      const response = await fetch(`${this._config.baseURL}/v1/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this._config.apiKey}`,
        },
        body: JSON.stringify({
          model: this._config.model,
          messages: request.messages,
          temperature: request.temperature,
          max_tokens: request.maxTokens,
          top_p: request.topP,
          frequency_penalty: request.frequencyPenalty,
          presence_penalty: request.presencePenalty,
          stop: request.stop,
          stream: false,
          user: request.user,
          ...request.metadata,
        }),
        signal: AbortSignal.timeout(this._config.timeout!),
      });

      if (!response.ok) {
        const errorData: ZAIErrorResponse = await response.json().catch(() => ({
          error: {
            message: `HTTP ${response.status}: ${response.statusText}`,
            type: 'http_error',
          },
        }));
        throw ZAIError.fromErrorResponse(errorData);
      }

      const data = await response.json();
      const processingTime = Date.now() - startTime;

      this.performanceMonitor.recordRequestEnd(requestId, true, processingTime);

      return {
        id: data.id,
        object: 'chat.completion',
        created: data.created,
        model: data.model,
        choices: data.choices,
        usage: {
          promptTokens: data.usage?.prompt_tokens || 0,
          completionTokens: data.usage?.completion_tokens || 0,
          totalTokens: data.usage?.total_tokens || 0,
        },
        processingTime,
        cached: false,
      };
    } catch (error) {
      const processingTime = Date.now() - startTime;
      this.performanceMonitor.recordRequestEnd(requestId, false, processingTime);
      throw error;
    }
  }

  /**
   * Validate request
   */
  private validateRequest(request: ZAIChatRequest): void {
    if (!request.messages || request.messages.length === 0) {
      throw new ZAIError(
        'Messages are required',
        ZAIErrorType['INVALID_REQUEST_ERROR'],
        'missing_messages'
      );
    }

    if (request.messages.some((msg) => !msg.role || !msg.content)) {
      throw new ZAIError(
        'All messages must have role and content',
        ZAIErrorType['INVALID_REQUEST_ERROR'],
        'invalid_message_format'
      );
    }

    if (request.maxTokens && request.maxTokens < 1) {
      throw new ZAIError(
        'maxTokens must be greater than 0',
        ZAIErrorType['INVALID_REQUEST_ERROR'],
        'invalid_max_tokens'
      );
    }
  }

  /**
   * Generate cache key for request
   */
  private generateCacheKey(request: ZAIChatRequest): string {
    const keyData = {
      messages: request.messages,
      model: this._config.model,
      temperature: request.temperature,
      maxTokens: request.maxTokens,
      topP: request.topP,
    };
    return Buffer.from(JSON.stringify(keyData)).toString('base64');
  }

  /**
   * Check if request can be executed (circuit breaker check)
   */
  private canExecuteRequest(): boolean {
    if (this.circuitBreaker.state === 'closed') {
      return true;
    }

    if (this.circuitBreaker.state === 'half-open') {
      return true;
    }

    if (this.circuitBreaker.state === 'open') {
      return Date.now() > this.circuitBreaker.nextAttempt;
    }

    return false;
  }

  /**
   * Handle circuit breaker failure
   */
  private handleCircuitBreakerFailure(): void {
    this.circuitBreaker.failureCount++;
    this.circuitBreaker.lastFailureTime = Date.now();

    if (this.circuitBreaker.failureCount >= this.circuitBreaker.config.failureThreshold) {
      this.circuitBreaker.state = 'open';
      this.circuitBreaker.nextAttempt = Date.now() + this.circuitBreaker.config.timeout;

      this.emitEvent({
        type: 'circuit_breaker_opened',
        data: {
          provider: 'zai',
          reason: `Failure threshold reached: ${this.circuitBreaker.failureCount}`,
        },
      });

      logger.warn(
        {
          failureCount: this.circuitBreaker.failureCount,
          nextAttempt: this.circuitBreaker.nextAttempt,
        },
        'ZAI circuit breaker opened'
      );
    }
  }

  /**
   * Reset circuit breaker on success
   */
  private resetCircuitBreaker(): void {
    if (this.circuitBreaker.state === 'half-open') {
      this.circuitBreaker.state = 'closed';
      this.circuitBreaker.failureCount = 0;

      this.emitEvent({
        type: 'circuit_breaker_closed',
        data: { provider: 'zai' },
      });

      logger.info('ZAI circuit breaker closed');
    }
  }

  /**
   * Update service metrics
   */
  private updateMetrics(
    success: boolean,
    response: ZAIChatResponse | null,
    duration: number
  ): void {
    this.metrics.requestCount++;

    if (success) {
      this.metrics.successCount++;

      if (response) {
        this.metrics.tokensUsed += response.usage.totalTokens;

        // Update average response time (exponential moving average)
        const alpha = 0.1;
        this.metrics.averageResponseTime =
          alpha * duration + (1 - alpha) * this.metrics.averageResponseTime;
      }
    } else {
      this.metrics.errorCount++;
    }

    this.metrics.errorRate =
      this.metrics.requestCount > 0 ? this.metrics.errorCount / this.metrics.requestCount : 0;
  }

  /**
   * Convert generic error to ZAIError
   */
  private convertToZAIError(error: unknown): ZAIError {
    if (error instanceof ZAIError) {
      return error;
    }

    if (error instanceof Error && error.name === 'AbortError') {
      return new ZAIError(
        'Request timeout',
        ZAIErrorType['TIMEOUT_ERROR'],
        'timeout',
        undefined,
        undefined
      );
    }

    if (error instanceof Error && error.name === 'TypeError' && error.message.includes('fetch')) {
      return new ZAIError(
        'Network error',
        ZAIErrorType['NETWORK_ERROR'],
        'network_error',
        undefined,
        undefined
      );
    }

    return new ZAIError(
      error instanceof Error ? error.message : 'Unknown error occurred',
      ZAIErrorType['UNKNOWN_ERROR'],
      'unknown',
      undefined,
      undefined
    );
  }

  /**
   * Emit event to all listeners
   */
  private async emitEvent(event: ZAIEvent): Promise<void> {
    const listeners = Array.from(this.eventListeners);
    await Promise.allSettled(
      listeners.map((listener) => {
        try {
          return listener(event);
        } catch (error) {
          logger.error({ error, event }, 'Error in ZAI event listener');
        }
      })
    );
  }

  // ============================================================================
  // IZAIClientService IMPLEMENTATION
  // ============================================================================

  // ============================================================================
  // IAIService IMPLEMENTATION
  // ============================================================================

  /**
   * Check if service is available
   */
  async isAvailable(): Promise<ServiceResponse<{ available: boolean }>> {
    return this.executeOperation(
      async () => {
        // Check circuit breaker state and other health indicators
        const circuitBreakerHealthy = this.circuitBreaker.state === 'closed';
        const rateLimitHealthy = await this.rateLimiter.isAllowed().catch(() => false);
        const available = circuitBreakerHealthy && rateLimitHealthy;
        return { available };
      },
      'isAvailable',
      {}
    );
  }

  /**
   * Get service status
   */
  async getServiceStatus(): Promise<ServiceResponse<AIServiceStatus>> {
    return this.executeOperation(
      async () => {
        const status = await this._getServiceStatus();
        // Convert ZAIServiceStatus to AIServiceStatus
        return {
          status:
            status.status === 'healthy'
              ? 'healthy'
              : status.status === 'degraded'
                ? 'degraded'
                : 'down',
          lastCheck: new Date().toISOString(),
          responseTime: status.responseTime,
          errorRate: status.errorRate,
          circuitBreakerState: status.circuitBreakerState,
          consecutiveFailures: status.consecutiveFailures,
          uptime: process.uptime(),
        };
      },
      'getServiceStatus',
      {}
    );
  }

  /**
   * Get service metrics
   */
  async getMetrics(): Promise<ServiceResponse<ZAIMetrics>> {
    return this.executeOperation(
      async () => {
        return this.metrics;
      },
      'getMetrics',
      {}
    );
  }

  /**
   * Reset metrics
   */
  override async reset(): Promise<ServiceResponse<void>> {
    return this.executeOperation(
      async () => {
        this.metrics = {
          timestamp: new Date(),
          totalRequests: 0,
          successfulRequests: 0,
          failedRequests: 0,
          averageResponseTime: 0,
          p95ResponseTime: 0,
          p99ResponseTime: 0,
          totalTokensUsed: 0,
          totalCost: 0,
          cacheHitRate: 0,
          errorRate: 0,
          uptime: 0,
          lastReset: Date.now(),
          // Compatibility properties
          requestCount: 0,
          successCount: 0,
          errorCount: 0,
          throughput: 0,
          circuitBreakerStatus: 'closed' as const,
          tokensUsed: 0,
          cost: 0,
        };
      },
      'reset',
      {}
    );
  }

  /**
   * Add event listener
   */
  addEventListener(listener: ZAIEventListener): ServiceResponse<void> {
    try {
      this.eventListeners.add(listener);
      return {
        success: true,
        metadata: {
          serviceName: this.serviceName,
          processingTimeMs: 0,
          source: this.serviceName,
        },
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'ADD_LISTENER_ERROR',
          message: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date().toISOString(),
          retryable: false,
        },
        metadata: {
          serviceName: this.serviceName,
          processingTimeMs: 0,
          source: this.serviceName,
        },
      };
    }
  }

  /**
   * Remove event listener
   */
  removeEventListener(listener: ZAIEventListener): ServiceResponse<void> {
    try {
      this.eventListeners.delete(listener);
      return {
        success: true,
        metadata: {
          serviceName: this.serviceName,
          processingTimeMs: 0,
          source: this.serviceName,
        },
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'REMOVE_LISTENER_ERROR',
          message: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date().toISOString(),
          retryable: false,
        },
        metadata: {
          serviceName: this.serviceName,
          processingTimeMs: 0,
          source: this.serviceName,
        },
      };
    }
  }

  /**
   * Health check implementation for ZAI service
   */
  override async healthCheck(): Promise<ServiceResponse<{ status: 'healthy' | 'unhealthy' }>> {
    return this.executeOperation(async () => {
      const now = Date.now();

      // Only perform actual health check if enough time has passed
      if (now - this.lastHealthCheck < this.healthCheckInterval) {
        return { status: 'healthy' };
      }

      this.lastHealthCheck = now;

      // Check circuit breaker state
      if (this.circuitBreaker.state === 'open') {
        return { status: 'unhealthy' };
      }

      // Check error rate
      const errorRate = this.metrics.requestCount > 0
        ? this.metrics.errorCount / this.metrics.requestCount
        : 0;

      // Consider unhealthy if error rate is above 50%
      if (errorRate > 0.5) {
        return { status: 'unhealthy' };
      }

      return { status: 'healthy' };
    }, 'healthCheck');
  }
}

/**
 * Export singleton instance
 */
export const zaiClientService = new ZAIClientService();

/**
 * Export service class for testing
 */
export { ZAIClientService as ZAIClient };

