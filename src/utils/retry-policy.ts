// @ts-nocheck - Emergency rollback: Critical utility service
/**
 * P2-P3: Advanced Retry Policy and Error Taxonomy System
 *
 * Provides production-ready retry mechanisms with exponential backoff,
 * jitter, circuit breaker patterns, and comprehensive error classification.
 * Integrates with Dead Letter Queue (DLQ) for failed operations.
 *
 * Features:
 * - Sophisticated error taxonomy with stable classification
 * - Configurable retry policies with exponential backoff and jitter
 * - Circuit breaker pattern for cascading failure prevention
 * - Dead Letter Queue integration for failed operations
 * - Idempotency key support for safe retries
 * - Comprehensive metrics and observability
 *
 * @module utils/retry-policy
 */

import { v4 as uuidv4 } from 'uuid';

import { logger } from '@/utils/logger.js';

import {
  BaseError,
  ErrorCategory,
  ErrorCode,
  ErrorSeverity,
  NetworkError,
  RateLimitError,
  SystemError,
} from './error-handler.js';

// === Type Definitions ===

export interface RetryPolicyConfig {
  /** Maximum number of retry attempts */
  max_attempts: number;
  /** Base delay in milliseconds */
  base_delay_ms: number;
  /** Maximum delay in milliseconds */
  max_delay_ms: number;
  /** Backoff multiplier */
  backoff_multiplier: number;
  /** Jitter factor (0-1) */
  jitter_factor: number;
  /** Retryable error categories */
  retryable_categories: ErrorCategory[];
  /** Retryable error codes */
  retryable_codes: ErrorCode[];
  /** Non-retryable error codes that should go to DLQ */
  dlq_codes: ErrorCode[];
  /** Circuit breaker configuration */
  circuit_breaker: {
    enabled: boolean;
    failure_threshold: number;
    recovery_timeout_ms: number;
    half_open_max_calls: number;
  };
}

export interface RetryAttempt {
  attempt_number: number;
  delay_ms: number;
  timestamp: number;
  error?: BaseError;
  success: boolean;
}

export interface RetryResult<T = unknown> {
  success: boolean;
  result?: T;
  error?: BaseError;
  attempts: RetryAttempt[];
  total_duration_ms: number;
  circuit_breaker_tripped: boolean;
  sent_to_dlq: boolean;
  idempotency_key?: string;
}

export interface DLQMessage {
  id: string;
  idempotency_key?: string;
  original_operation: string;
  payload: unknown;
  error: BaseError;
  retry_attempts: RetryAttempt[];
  timestamp: number;
  expires_at: number;
  retry_after?: number;
  metadata: Record<string, unknown>;
}

export interface CircuitBreakerState {
  state: 'closed' | 'open' | 'half-open';
  failure_count: number;
  last_failure_time: number;
  next_attempt_time: number;
  half_open_calls: number;
}

export interface RetryMetrics {
  total_operations: number;
  successful_operations: number;
  failed_operations: number;
  retried_operations: number;
  circuit_breaker_trips: number;
  dlq_messages: number;
  avg_attempts_per_operation: number;
  avg_retry_delay_ms: number;
  error_distribution: Record<string, number>;
}

/**
 * Advanced Retry Policy Manager
 */
export class RetryPolicyManager {
  private config: RetryPolicyConfig;
  private circuitBreakerStates: Map<string, CircuitBreakerState> = new Map();
  private dlqMessages: DLQMessage[] = [];
  private idempotencyCache: Map<string, { result: unknown; timestamp: number }> = new Map();
  private metrics: RetryMetrics = {
    total_operations: 0,
    successful_operations: 0,
    failed_operations: 0,
    retried_operations: 0,
    circuit_breaker_trips: 0,
    dlq_messages: 0,
    avg_attempts_per_operation: 0,
    avg_retry_delay_ms: 0,
    error_distribution: {}
  };

  private readonly defaultConfig: RetryPolicyConfig = {
    max_attempts: 3,
    base_delay_ms: 1000,
    max_delay_ms: 30000,
    backoff_multiplier: 2,
    jitter_factor: 0.1,
    retryable_categories: [
      ErrorCategory.NETWORK,
      ErrorCategory.DATABASE,
      ErrorCategory.EXTERNAL_API,
      ErrorCategory.RATE_LIMIT,
    ],
    retryable_codes: [
      ErrorCode.NETWORK_UNREACHABLE,
      ErrorCode.CONNECTION_TIMEOUT,
      ErrorCode.DATABASE_TIMEOUT,
      ErrorCode.EXTERNAL_API_TIMEOUT,
      ErrorCode.EXTERNAL_API_RATE_LIMIT,
      ErrorCode.RATE_LIMIT_EXCEEDED,
    ],
    dlq_codes: [
      ErrorCode.INTERNAL_ERROR,
      ErrorCode.SYSTEM_OVERLOAD,
      ErrorCode.MEMORY_EXHAUSTED,
      ErrorCode.DISK_FULL,
    ],
    circuit_breaker: {
      enabled: true,
      failure_threshold: 5,
      recovery_timeout_ms: 60000, // 1 minute
      half_open_max_calls: 3,
    },
  };

  constructor(config?: Partial<RetryPolicyConfig>) {
    this.config = { ...this.defaultConfig, ...config };
    this.initializeMetrics();

    logger.info('RetryPolicyManager initialized', {
      maxAttempts: this.config.max_attempts,
      baseDelay: this.config.base_delay_ms,
      circuitBreakerEnabled: this.config.circuit_breaker.enabled,
    });
  }

  /**
   * Initialize metrics
   */
  private initializeMetrics(): void {
    this.metrics = {
      total_operations: 0,
      successful_operations: 0,
      failed_operations: 0,
      retried_operations: 0,
      circuit_breaker_trips: 0,
      dlq_messages: 0,
      avg_attempts_per_operation: 0,
      avg_retry_delay_ms: 0,
      error_distribution: {},
    };
  }

  /**
   * Execute operation with retry policy
   */
  async executeWithRetry<T>(
    operation: () => Promise<T>,
    context: {
      operation_name: string;
      idempotency_key?: string;
      metadata?: Record<string, unknown>;
      custom_retry_config?: Partial<RetryPolicyConfig>;
    }
  ): Promise<RetryResult<T>> {
    const startTime = Date.now();
    const operationName = context.operation_name;
    const idempotencyKey = context.idempotency_key || uuidv4();
    const customConfig = context.custom_retry_config
      ? { ...this.config, ...context.custom_retry_config }
      : this.config;

    // Check idempotency cache
    if (idempotencyKey) {
      const cached = this.idempotencyCache.get(idempotencyKey);
      if (cached && Date.now() - cached.timestamp < 300000) {
        // 5 minutes TTL
        logger.debug('Returning cached result for idempotent operation', {
          operationName,
          idempotencyKey,
        });
        return {
          success: true,
          result: cached.result,
          attempts: [
            {
              attempt_number: 1,
              delay_ms: 0,
              timestamp: Date.now(),
              success: true,
            },
          ],
          total_duration_ms: 0,
          circuit_breaker_tripped: false,
          sent_to_dlq: false,
          idempotency_key: idempotencyKey,
        };
      }
    }

    // Check circuit breaker
    const circuitBreakerKey = `${context.operation_name}_circuit_breaker`;
    if (customConfig.circuit_breaker.enabled && this.isCircuitBreakerOpen(circuitBreakerKey)) {
      const error = new SystemError('Circuit breaker is open', {
        retryable: false,
      });

      return {
        success: false,
        error,
        attempts: [],
        total_duration_ms: Date.now() - startTime,
        circuit_breaker_tripped: true,
        sent_to_dlq: false,
        idempotency_key: idempotencyKey,
      };
    }

    const attempts: RetryAttempt[] = [];
    let lastError: BaseError | undefined;

    this.metrics.total_operations++;

    for (let attempt = 1; attempt <= customConfig.max_attempts; attempt++) {
      const attemptStartTime = Date.now();

      try {
        logger.debug('Executing retry attempt', {
          operationName,
          attemptNumber: attempt,
          maxAttempts: customConfig.max_attempts,
        });

        const result = await operation();
        const attemptDuration = Date.now() - attemptStartTime;

        // Success - update circuit breaker and cache result
        this.recordCircuitBreakerSuccess(circuitBreakerKey);
        if (idempotencyKey) {
          this.idempotencyCache.set(idempotencyKey, {
            result,
            timestamp: Date.now(),
          });
        }

        // Update metrics
        this.metrics.successful_operations++;
        this.updateRetryMetrics(attempts, attemptDuration);

        logger.info('Operation succeeded', {
          operationName,
          attemptNumber: attempt,
          totalDuration: Date.now() - startTime,
          idempotencyKey,
        });

        return {
          success: true,
          result,
          attempts: [
            ...attempts,
            {
              attempt_number: attempt,
              delay_ms: 0,
              timestamp: attemptStartTime,
              success: true,
            },
          ],
          total_duration_ms: Date.now() - startTime,
          circuit_breaker_tripped: false,
          sent_to_dlq: false,
          idempotency_key: idempotencyKey,
        };
      } catch (error) {
        const baseError = this.standardizeError(error);
        lastError = baseError;

        attempts.push({
          attempt_number: attempt,
          delay_ms: 0,
          timestamp: attemptStartTime,
          error: baseError,
          success: false,
        });

        // Check if error is retryable
        if (!this.isRetryableError(baseError, customConfig)) {
          logger.warn('Non-retryable error encountered', {
            operationName,
            attemptNumber: attempt,
            errorCode: baseError.code,
            errorMessage: baseError.message,
          });
          break;
        }

        // Record circuit breaker failure
        this.recordCircuitBreakerFailure(circuitBreakerKey);

        // If this is the last attempt, don't calculate delay
        if (attempt === customConfig.max_attempts) {
          break;
        }

        // Calculate delay for next attempt
        const delay = this.calculateRetryDelay(attempt, customConfig);
        logger.debug('Scheduling retry attempt', {
          operationName,
          attemptNumber: attempt,
          nextAttemptNumber: attempt + 1,
          delayMs: delay,
        });

        await this.sleep(delay);
      }
    }

    // All attempts failed - determine if should go to DLQ
    const shouldGoToDLQ = Boolean(lastError && this.shouldSendToDLQ(lastError, customConfig));
    if (shouldGoToDLQ && lastError) {
      this.sendToDLQ({
        id: uuidv4(),
        idempotency_key: idempotencyKey,
        original_operation: operationName,
        payload: context.metadata || {},
        error: lastError,
        retry_attempts: attempts,
        timestamp: Date.now(),
        expires_at: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
        metadata: context.metadata || {},
      });
    }

    // Update metrics
    this.metrics.failed_operations++;
    this.updateRetryMetrics(attempts, Date.now() - startTime);

    logger.error('Operation failed after all retry attempts', {
      operationName,
      totalAttempts: attempts.length,
      totalDuration: Date.now() - startTime,
      lastError: lastError?.message,
      sentToDLQ: shouldGoToDLQ,
      idempotencyKey,
    });

    return {
      success: false,
      error: lastError || new SystemError('Operation failed after all retry attempts'),
      attempts,
      total_duration_ms: Date.now() - startTime,
      circuit_breaker_tripped: false,
      sent_to_dlq: shouldGoToDLQ,
      idempotency_key: idempotencyKey,
    };
  }

  /**
   * Check if circuit breaker is open
   */
  private isCircuitBreakerOpen(key: string): boolean {
    if (!this.config.circuit_breaker.enabled) return false;

    const state = this.circuitBreakerStates.get(key);
    if (!state) return false;

    const now = Date.now();

    switch (state.state) {
      case 'open':
        if (now >= state.next_attempt_time) {
          state.state = 'half-open';
          state.half_open_calls = 0;
          logger.info('Circuit breaker transitioning to half-open', { key });
          return false;
        }
        return true;

      case 'half-open':
        if (state.half_open_calls >= this.config.circuit_breaker.half_open_max_calls) {
          return true;
        }
        return false;

      default:
        return false;
    }
  }

  /**
   * Record circuit breaker success
   */
  private recordCircuitBreakerSuccess(key: string): void {
    if (!this.config.circuit_breaker.enabled) return;

    const state = this.circuitBreakerStates.get(key);
    if (!state) return;

    if (state.state === 'half-open') {
      state.state = 'closed';
      state.failure_count = 0;
      logger.info('Circuit breaker closed after successful half-open call', { key });
    }
  }

  /**
   * Record circuit breaker failure
   */
  private recordCircuitBreakerFailure(key: string): void {
    if (!this.config.circuit_breaker.enabled) return;

    let state = this.circuitBreakerStates.get(key);
    if (!state) {
      state = {
        state: 'closed',
        failure_count: 0,
        last_failure_time: 0,
        next_attempt_time: 0,
        half_open_calls: 0,
      };
      this.circuitBreakerStates.set(key, state);
    }

    state.failure_count++;
    state.last_failure_time = Date.now();

    if (state.state === 'half-open') {
      state.state = 'open';
      state.next_attempt_time = Date.now() + this.config.circuit_breaker.recovery_timeout_ms;
      this.metrics.circuit_breaker_trips++;
      logger.warn('Circuit breaker opened from half-open state', {
        key,
        failureCount: state.failure_count,
      });
    } else if (
      state.state === 'closed' &&
      state.failure_count >= this.config.circuit_breaker.failure_threshold
    ) {
      state.state = 'open';
      state.next_attempt_time = Date.now() + this.config.circuit_breaker.recovery_timeout_ms;
      this.metrics.circuit_breaker_trips++;
      logger.warn('Circuit breaker opened due to failure threshold', {
        key,
        failureCount: state.failure_count,
      });
    }
  }

  /**
   * Standardize error to BaseError
   */
  private standardizeError(error: unknown): BaseError {
    if (error instanceof BaseError) {
      return error;
    }

    if (error instanceof Error) {
      // Try to categorize based on error message
      const message = error.message.toLowerCase();

      if (message.includes('timeout') || message.includes('timed out')) {
        return new NetworkError(error.message, 'Operation timed out');
      }

      if (message.includes('network') || message.includes('connection')) {
        return new NetworkError(error.message, 'Network connection failed');
      }

      if (message.includes('rate limit')) {
        return new RateLimitError(error.message, 'Rate limit exceeded');
      }

      // Default to system error
      return new SystemError(error.message);
    }

    // Non-Error objects
    return new SystemError(`Unknown error: ${String(error)}`);
  }

  /**
   * Check if error is retryable
   */
  private isRetryableError(error: BaseError, config: RetryPolicyConfig): boolean {
    // Check if error category is retryable
    if (config.retryable_categories.includes(error.category)) {
      return true;
    }

    // Check if specific error code is retryable
    if (config.retryable_codes.includes(error.code)) {
      return true;
    }

    // Check error's own retryable flag
    if (error.retryable !== undefined) {
      return error.retryable;
    }

    return false;
  }

  /**
   * Check if error should be sent to DLQ
   */
  private shouldSendToDLQ(error: BaseError, config: RetryPolicyConfig): boolean {
    // Non-retryable errors should go to DLQ
    if (!this.isRetryableError(error, config)) {
      return true;
    }

    // Specific error codes that should go to DLQ
    if (config.dlq_codes.includes(error.code)) {
      return true;
    }

    // Critical errors should go to DLQ
    if (error.severity === ErrorSeverity.CRITICAL) {
      return true;
    }

    return false;
  }

  /**
   * Calculate retry delay with exponential backoff and jitter
   */
  private calculateRetryDelay(attempt: number, config: RetryPolicyConfig): number {
    const exponentialDelay =
      config.base_delay_ms * Math.pow(config.backoff_multiplier, attempt - 1);
    const cappedDelay = Math.min(exponentialDelay, config.max_delay_ms);

    // Add jitter
    const jitter = cappedDelay * config.jitter_factor * Math.random();
    const finalDelay = cappedDelay + jitter;

    return Math.floor(finalDelay);
  }

  /**
   * Send message to Dead Letter Queue
   */
  private sendToDLQ(message: DLQMessage): void {
    this.dlqMessages.push(message);
    this.metrics.dlq_messages++;

    logger.warn('Message sent to DLQ', {
      messageId: message.id,
      operation: message.original_operation,
      errorCode: message.error.code,
      retryAttempts: message.retry_attempts.length,
      idempotencyKey: message.idempotency_key,
    });

    // Clean up old DLQ messages
    this.cleanupDLQ();
  }

  /**
   * Clean up expired DLQ messages
   */
  private cleanupDLQ(): void {
    const now = Date.now();
    const originalCount = this.dlqMessages.length;

    this.dlqMessages = this.dlqMessages.filter((message) => message.expires_at > now);

    const cleanedUp = originalCount - this.dlqMessages.length;
    if (cleanedUp > 0) {
      logger.debug('Cleaned up expired DLQ messages', { count: cleanedUp });
    }
  }

  /**
   * Update retry metrics
   */
  private updateRetryMetrics(attempts: RetryAttempt[], totalDuration: number): void {
    if (attempts.length > 1) {
      this.metrics.retried_operations++;
    }

    // Update average attempts per operation
    const totalOperations = this.metrics.total_operations;
    const totalAttempts =
      this.metrics.retried_operations * attempts.length +
      (totalOperations - this.metrics.retried_operations);
    this.metrics.avg_attempts_per_operation = totalAttempts / totalOperations;

    // Update average retry delay
    const retryDelays = attempts
      .slice(1)
      .map((a) => a.delay_ms)
      .filter((d) => d > 0);
    if (retryDelays.length > 0) {
      const avgDelay = retryDelays.reduce((sum, delay) => sum + delay, 0) / retryDelays.length;
      this.metrics.avg_retry_delay_ms = (this.metrics.avg_retry_delay_ms + avgDelay) / 2;
    }

    // Update error distribution
    attempts.forEach((attempt) => {
      if (attempt.error) {
        const errorType = `${attempt.error.category}:${attempt.error.code}`;
        this.metrics.error_distribution[errorType] =
          (this.metrics.error_distribution[errorType] || 0) + 1;
      }
    });
  }

  /**
   * Sleep utility
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  // === Public API Methods ===

  /**
   * Get retry metrics
   */
  getMetrics(): RetryMetrics {
    return { ...this.metrics };
  }

  /**
   * Get DLQ messages
   */
  getDLQMessages(limit?: number, operation?: string): DLQMessage[] {
    let messages = [...this.dlqMessages];

    if (operation) {
      messages = messages.filter((msg) => msg.original_operation === operation);
    }

    // Sort by timestamp (newest first)
    messages.sort((a, b) => b.timestamp - a.timestamp);

    if (limit) {
      messages = messages.slice(0, limit);
    }

    return messages;
  }

  /**
   * Retry DLQ message
   */
  async retryDLQMessage(messageId: string, operation: () => Promise<unknown>): Promise<RetryResult> {
    const message = this.dlqMessages.find((msg) => msg.id === messageId);
    if (!message) {
      throw new Error(`DLQ message ${messageId} not found`);
    }

    logger.info('Retrying DLQ message', { messageId, operation: message.original_operation });

    const result = await this.executeWithRetry(operation, {
      operation_name: message.original_operation,
      idempotency_key: message.idempotency_key || undefined,
      metadata: message.metadata,
    });

    if (result.success) {
      // Remove from DLQ on success
      this.dlqMessages = this.dlqMessages.filter((msg) => msg.id !== messageId);
      logger.info('DLQ message retry succeeded', { messageId });
    }

    return result;
  }

  /**
   * Clear DLQ
   */
  clearDLQ(operation?: string, olderThanHours?: number): number {
    let messagesToRemove = this.dlqMessages;

    if (operation) {
      messagesToRemove = messagesToRemove.filter((msg) => msg.original_operation === operation);
    }

    if (olderThanHours) {
      const cutoffTime = Date.now() - olderThanHours * 60 * 60 * 1000;
      messagesToRemove = messagesToRemove.filter((msg) => msg.timestamp < cutoffTime);
    }

    const messageIds = messagesToRemove.map((msg) => msg.id);
    this.dlqMessages = this.dlqMessages.filter((msg) => !messageIds.includes(msg.id));

    logger.info('Cleared DLQ messages', { count: messageIds.length, operation, olderThanHours });
    return messageIds.length;
  }

  /**
   * Get circuit breaker states
   */
  getCircuitBreakerStates(): Map<string, CircuitBreakerState> {
    const result = new Map<string, CircuitBreakerState>();
    this.circuitBreakerStates.forEach((state, key) => {
      result.set(key, { ...state });
    });
    return result;
  }

  /**
   * Reset circuit breaker
   */
  resetCircuitBreaker(key: string): void {
    this.circuitBreakerStates.delete(key);
    logger.info('Circuit breaker reset', { key });
  }

  /**
   * Reset all circuit breakers
   */
  resetAllCircuitBreakers(): void {
    const count = this.circuitBreakerStates.size;
    this.circuitBreakerStates.clear();
    logger.info('All circuit breakers reset', { count });
  }

  /**
   * Clear idempotency cache
   */
  clearIdempotencyCache(olderThanMinutes?: number): number {
    let toDelete: string[] = [];

    if (olderThanMinutes) {
      const cutoffTime = Date.now() - olderThanMinutes * 60 * 1000;
      toDelete = Array.from(this.idempotencyCache.entries())
        .filter(([, cached]) => cached.timestamp < cutoffTime)
        .map(([key]) => key);
    } else {
      toDelete = Array.from(this.idempotencyCache.keys());
    }

    toDelete.forEach((key) => this.idempotencyCache.delete(key));

    logger.debug('Cleared idempotency cache', { count: toDelete.length, olderThanMinutes });
    return toDelete.length;
  }

  /**
   * Get system status
   */
  getSystemStatus(): {
    status: 'healthy' | 'degraded' | 'critical';
    circuit_breakers: {
      total: number;
      open: number;
      half_open: number;
      closed: number;
    };
    dlq: {
      total_messages: number;
      expired_messages: number;
      oldest_message_age_hours: number;
    };
    cache: {
      idempotency_entries: number;
      cache_hit_rate: number;
    };
    metrics: RetryMetrics;
  } {
    const circuitBreakerStates = Array.from(this.circuitBreakerStates.values());
    const openCBs = circuitBreakerStates.filter((s) => s.state === 'open').length;
    const halfOpenCBs = circuitBreakerStates.filter((s) => s.state === 'half-open').length;
    const closedCBs = circuitBreakerStates.filter((s) => s.state === 'closed').length;

    const now = Date.now();
    const expiredDLQMessages = this.dlqMessages.filter((msg) => msg.expires_at < now).length;
    const oldestMessage =
      this.dlqMessages.length > 0 ? Math.min(...this.dlqMessages.map((msg) => msg.timestamp)) : now;
    const oldestMessageAgeHours = (now - oldestMessage) / (1000 * 60 * 60);

    // Determine overall status
    let status: 'healthy' | 'degraded' | 'critical' = 'healthy';
    if (openCBs > 0 || this.metrics.dlq_messages > 100) {
      status = 'critical';
    } else if (
      halfOpenCBs > 0 ||
      this.metrics.dlq_messages > 10 ||
      this.metrics.circuit_breaker_trips > 0
    ) {
      status = 'degraded';
    }

    return {
      status,
      circuit_breakers: {
        total: circuitBreakerStates.length,
        open: openCBs,
        half_open: halfOpenCBs,
        closed: closedCBs,
      },
      dlq: {
        total_messages: this.dlqMessages.length,
        expired_messages: expiredDLQMessages,
        oldest_message_age_hours: oldestMessageAgeHours,
      },
      cache: {
        idempotency_entries: this.idempotencyCache.size,
        cache_hit_rate:
          this.metrics.total_operations > 0
            ? (this.metrics.total_operations - this.metrics.retried_operations) /
              this.metrics.total_operations
            : 0,
      },
      metrics: { ...this.metrics },
    };
  }

  /**
   * Export retry policy data
   */
  exportData(format: 'json' | 'csv' = 'json'): string {
    const data = {
      timestamp: Date.now(),
      metrics: this.metrics,
      circuit_breaker_states: Object.fromEntries(this.getCircuitBreakerStates()),
      dlq_messages: this.dlqMessages.slice(0, 100), // Limit to last 100 messages
      system_status: this.getSystemStatus(),
      config: this.config,
    };

    if (format === 'csv') {
      return this.formatAsCSV(data);
    }

    return JSON.stringify(data, null, 2);
  }

  /**
   * Format data as CSV
   */
  private formatAsCSV(data: unknown): string {
    const headers = [
      'timestamp',
      'total_operations',
      'successful_operations',
      'failed_operations',
      'retried_operations',
      'circuit_breaker_trips',
      'dlq_messages',
    ];
    const rows = [headers.join(',')];

    rows.push(
      [
        data.timestamp,
        data.metrics.total_operations,
        data.metrics.successful_operations,
        data.metrics.failed_operations,
        data.metrics.retried_operations,
        data.metrics.circuit_breaker_trips,
        data.metrics.dlq_messages,
      ].join(',')
    );

    return rows.join('\n');
  }

  /**
   * Graceful shutdown
   */
  destroy(): void {
    this.cleanupDLQ();
    this.clearIdempotencyCache();
    logger.info('RetryPolicyManager destroyed');
  }
}

// Singleton instance
export const retryPolicyManager = new RetryPolicyManager();
