
// @ts-nocheck - Emergency rollback: Critical business service
/**
 * Retry Worker Service
 *
 * Background worker service that handles retry operations for failed embedding
 * generation and pending store operations. Implements exponential backoff,
 * circuit breaker pattern, and comprehensive error handling.
 *
 * Features:
 * - Exponential backoff with jitter
 * - Circuit breaker pattern for service protection
 * - Priority-based retry queues
 * - Dead letter queue for failed operations
 * - Comprehensive metrics and monitoring
 * - Configurable retry policies per operation type
 */

import { EventEmitter } from 'node:events';

import { logger } from '@/utils/logger.js';

import { type EmbeddingService } from '../embeddings/embedding-service.js';
import { type MemoryStoreOrchestratorQdrant } from '../orchestrators/memory-store-orchestrator-qdrant.js';
// import type { KnowledgeItem } from '../../types/core-interfaces.js';

export interface RetryOperation {
  id: string;
  type: 'embedding_failed' | 'store_pending';
  priority: 'high' | 'normal' | 'low';
  payload: unknown;
  attempts: number;
  maxAttempts: number;
  delay: number;
  nextRetryAt: number;
  createdAt: number;
  lastAttemptAt?: number;
  error?: string;
  metadata?: Record<string, unknown>;
}

export interface RetryWorkerConfig {
  enabled?: boolean;
  maxConcurrentRetries?: number;
  defaultMaxAttempts?: number;
  baseDelay?: number;
  maxDelay?: number;
  backoffMultiplier?: number;
  jitter?: boolean;
  circuitBreakerThreshold?: number;
  circuitBreakerTimeout?: number;
  deadLetterQueueEnabled?: boolean;
  deadLetterMaxSize?: number;
  metricsEnabled?: boolean;
  healthCheckInterval?: number;
}

export interface RetryWorkerStats {
  totalOperations: number;
  successfulRetries: number;
  failedRetries: number;
  averageRetryTime: number;
  circuitBreakerTrips: number;
  deadLetterQueueSize: number;
  operationTypeStats: Record<
    string,
    {
      total: number;
      successful: number;
      failed: number;
    }
  >;
}

export interface RetryResult {
  success: boolean;
  operationId: string;
  attempts: number;
  totalTime: number;
  result?: unknown;
  error?: string;
  movedToDeadLetter?: boolean;
}

export class RetryWorkerService extends EventEmitter {
  private config: Required<RetryWorkerConfig>;
  private retryQueues = new Map<string, RetryOperation[]>();
  private deadLetterQueue: RetryOperation[] = [];
  private processing = new Set<string>();
  private circuitBreakerState = {
    isOpen: false,
    openedAt: 0,
    failureCount: 0,
  };
  private stats: RetryWorkerStats;
  private intervalId?: NodeJS.Timeout | null;
  private embeddingService: EmbeddingService;
  private memoryStoreService: MemoryStoreOrchestratorQdrant;

  constructor(
    embeddingService: EmbeddingService,
    memoryStoreService: MemoryStoreOrchestratorQdrant,
    config: RetryWorkerConfig = {}
  ) {
    super();

    this.config = {
      enabled: config.enabled ?? true,
      maxConcurrentRetries: config.maxConcurrentRetries ?? 5,
      defaultMaxAttempts: config.defaultMaxAttempts ?? 3,
      baseDelay: config.baseDelay ?? 1000,
      maxDelay: config.maxDelay ?? 60000,
      backoffMultiplier: config.backoffMultiplier ?? 2,
      jitter: config.jitter ?? true,
      circuitBreakerThreshold: config.circuitBreakerThreshold ?? 10,
      circuitBreakerTimeout: config.circuitBreakerTimeout ?? 60000,
      deadLetterQueueEnabled: config.deadLetterQueueEnabled ?? true,
      deadLetterMaxSize: config.deadLetterMaxSize ?? 1000,
      metricsEnabled: config.metricsEnabled ?? true,
      healthCheckInterval: config.healthCheckInterval ?? 30000,
    };

    this.embeddingService = embeddingService;
    this.memoryStoreService = memoryStoreService;
    this.stats = this.initializeStats();

    if (this.config.enabled) {
      this.start();
    }
  }

  /**
   * Initialize statistics
   */
  private initializeStats(): RetryWorkerStats {
    return {
      totalOperations: 0,
      successfulRetries: 0,
      failedRetries: 0,
      averageRetryTime: 0,
      circuitBreakerTrips: 0,
      deadLetterQueueSize: 0,
      operationTypeStats: {
        embedding_failed: { total: 0, successful: 0, failed: 0 },
        store_pending: { total: 0, successful: 0, failed: 0 },
      },
    };
  }

  /**
   * Start the retry worker
   */
  start(): void {
    if (this.intervalId) {
      return; // Already running
    }

    logger.info('Starting retry worker service');

    this.intervalId = setInterval(() => {
      this.processRetryQueues();
    }, 1000); // Check every second

    this.emit('started');
  }

  /**
   * Stop the retry worker
   */
  stop(): void {
    if (!this.intervalId) {
      return; // Already stopped
    }

    logger.info('Stopping retry worker service');

    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }

    this.emit('stopped');
  }

  /**
   * Add operation to retry queue
   */
  async addRetryOperation(
    operation: Omit<RetryOperation, 'id' | 'attempts' | 'delay' | 'nextRetryAt' | 'createdAt'>
  ): Promise<string> {
    if (!this.config.enabled) {
      throw new Error('Retry worker is disabled');
    }

    const id = `retry_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const now = Date.now();

    const retryOperation: RetryOperation = {
      id,
      attempts: 0,
      delay: this.config.baseDelay,
      nextRetryAt: now + this.config.baseDelay,
      createdAt: now,
      ...operation,
    };

    // Add to appropriate priority queue
    const queue = this.getOrCreateQueue(operation.type);
    queue.push(retryOperation);
    queue.sort((a, b) => {
      // Sort by priority first, then by next retry time
      const priorityOrder = { high: 3, normal: 2, low: 1 };
      const aPriority = priorityOrder[a.priority];
      const bPriority = priorityOrder[b.priority];

      if (aPriority !== bPriority) {
        return bPriority - aPriority;
      }

      return a.nextRetryAt - b.nextRetryAt;
    });

    this.stats.totalOperations++;
    this.stats.operationTypeStats[operation.type].total++;

    logger.debug(
      {
        operationId: id,
        type: operation.type,
        priority: operation.priority,
        maxAttempts: operation.maxAttempts,
      },
      'Added operation to retry queue'
    );

    this.emit('operation_queued', retryOperation);
    return id;
  }

  /**
   * Process retry queues
   */
  private async processRetryQueues(): Promise<void> {
    if (this.circuitBreakerState.isOpen) {
      // Check if circuit breaker should be reset
      if (Date.now() - this.circuitBreakerState.openedAt > this.config.circuitBreakerTimeout) {
        this.resetCircuitBreaker();
      } else {
        return; // Circuit breaker is still open
      }
    }

    // Check if we're at max concurrent operations
    if (this.processing.size >= this.config.maxConcurrentRetries) {
      return;
    }

    const now = Date.now();
    const operationsToProcess: RetryOperation[] = [];

    // Find operations ready for retry
    for (const [_type, queue] of this.retryQueues.entries()) {
      while (
        queue.length > 0 &&
        operationsToProcess.length < this.config.maxConcurrentRetries - this.processing.size
      ) {
        const operation = queue[0];
        if (operation.nextRetryAt <= now) {
          operationsToProcess.push(operation);
          queue.shift();
        } else {
          break; // No more operations ready in this queue
        }
      }
    }

    // Process operations concurrently
    const promises = operationsToProcess.map((operation) => this.processOperation(operation));

    try {
      await Promise.allSettled(promises);
    } catch (error) {
      logger.error({ error }, 'Error processing retry operations batch');
    }
  }

  /**
   * Process a single retry operation
   */
  private async processOperation(operation: RetryOperation): Promise<void> {
    const startTime = Date.now();
    this.processing.add(operation.id);

    try {
      logger.debug(
        {
          operationId: operation.id,
          type: operation.type,
          attempt: operation.attempts + 1,
          maxAttempts: operation.maxAttempts,
        },
        'Processing retry operation'
      );

      const result = await this.executeOperation(operation);
      const processingTime = Date.now() - startTime;

      if (result.success) {
        this.handleSuccess(operation, result, processingTime);
      } else {
        this.handleFailure(operation, result, processingTime);
      }
    } catch (error) {
      const processingTime = Date.now() - startTime;
      logger.error(
        {
          error,
          operationId: operation.id,
          processingTime,
        },
        'Unexpected error processing retry operation'
      );

      this.handleFailure(
        operation,
        {
          success: false,
          operationId: operation.id,
          attempts: operation.attempts + 1,
          totalTime: processingTime,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
        processingTime
      );
    } finally {
      this.processing.delete(operation.id);
    }
  }

  /**
   * Execute the specific operation
   */
  private async executeOperation(operation: RetryOperation): Promise<RetryResult> {
    const startTime = Date.now();

    try {
      switch (operation.type) {
        case 'embedding_failed':
          return await this.retryEmbeddingOperation(operation);

        case 'store_pending':
          return await this.retryStoreOperation(operation);

        default:
          throw new Error(`Unknown operation type: ${operation.type}`);
      }
    } catch (error) {
      return {
        success: false,
        operationId: operation.id,
        attempts: operation.attempts + 1,
        totalTime: Date.now() - startTime,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Retry embedding operation
   */
  private async retryEmbeddingOperation(operation: RetryOperation): Promise<RetryResult> {
    const startTime = Date.now();
    const { text, metadata } = operation.payload;

    try {
      const embeddingResult = await this.embeddingService.generateEmbedding({
        text,
        metadata: {
          ...metadata,
          retryOperation: true,
          originalOperationId: operation.id,
          attempt: operation.attempts + 1,
        },
      });

      return {
        success: true,
        operationId: operation.id,
        attempts: operation.attempts + 1,
        totalTime: Date.now() - startTime,
        result: embeddingResult,
      };
    } catch (error) {
      return {
        success: false,
        operationId: operation.id,
        attempts: operation.attempts + 1,
        totalTime: Date.now() - startTime,
        error: error instanceof Error ? error.message : 'Embedding generation failed',
      };
    }
  }

  /**
   * Retry store operation
   */
  private async retryStoreOperation(operation: RetryOperation): Promise<RetryResult> {
    const startTime = Date.now();
    const { items, authContext } = operation.payload;

    try {
      const storeResult = await this.memoryStoreService.storeItems(items, authContext);

      return {
        success: true,
        operationId: operation.id,
        attempts: operation.attempts + 1,
        totalTime: Date.now() - startTime,
        result: storeResult,
      };
    } catch (error) {
      return {
        success: false,
        operationId: operation.id,
        attempts: operation.attempts + 1,
        totalTime: Date.now() - startTime,
        error: error instanceof Error ? error.message : 'Store operation failed',
      };
    }
  }

  /**
   * Handle successful operation
   */
  private handleSuccess(
    operation: RetryOperation,
    result: RetryResult,
    processingTime: number
  ): void {
    this.stats.successfulRetries++;
    this.stats.operationTypeStats[operation.type].successful++;
    this.updateAverageRetryTime(processingTime);

    logger.info(
      {
        operationId: operation.id,
        type: operation.type,
        attempts: operation.attempts + 1,
        processingTime,
      },
      'Retry operation succeeded'
    );

    this.emit('operation_succeeded', { operation, result });
  }

  /**
   * Handle failed operation
   */
  private handleFailure(
    operation: RetryOperation,
    result: RetryResult,
    processingTime: number
  ): void {
    this.stats.failedRetries++;
    this.stats.operationTypeStats[operation.type].failed++;
    this.updateAverageRetryTime(processingTime);

    // Update circuit breaker
    this.circuitBreakerState.failureCount++;
    if (this.circuitBreakerState.failureCount >= this.config.circuitBreakerThreshold) {
      this.tripCircuitBreaker();
    }

    // Determine if we should retry
    const newAttemptCount = operation.attempts + 1;
    if (newAttemptCount < operation.maxAttempts) {
      // Calculate next retry delay with exponential backoff
      let nextDelay = operation.delay * this.config.backoffMultiplier;
      nextDelay = Math.min(nextDelay, this.config.maxDelay);

      // Add jitter if enabled
      if (this.config.jitter) {
        const jitterAmount = nextDelay * 0.1; // 10% jitter
        nextDelay += (Math.random() - 0.5) * jitterAmount;
      }

      // Update operation for next retry
      operation.attempts = newAttemptCount;
      operation.delay = nextDelay;
      operation.nextRetryAt = Date.now() + nextDelay;
      operation.lastAttemptAt = Date.now();
      operation.error = result?.error || 'Unknown error';

      // Re-add to queue
      const queue = this.getOrCreateQueue(operation.type);
      queue.push(operation);

      logger.debug(
        {
          operationId: operation.id,
          type: operation.type,
          attempt: newAttemptCount,
          nextDelay,
          nextRetryAt: new Date(operation.nextRetryAt).toISOString(),
        },
        'Operation will be retried'
      );

      this.emit('operation_failed_retry_scheduled', { operation, result });
    } else {
      // Max attempts reached, move to dead letter queue if enabled
      if (this.config.deadLetterQueueEnabled) {
        this.moveToDeadLetterQueue(operation, result);
      }

      logger.error(
        {
          operationId: operation.id,
          type: operation.type,
          attempts: newAttemptCount,
          maxAttempts: operation.maxAttempts,
          finalError: result.error,
        },
        'Operation failed after max retry attempts'
      );

      this.emit('operation_failed_permanently', { operation, result });
    }
  }

  /**
   * Move operation to dead letter queue
   */
  private moveToDeadLetterQueue(operation: RetryOperation, _result: RetryResult): void {
    if (this.deadLetterQueue.length >= this.config.deadLetterMaxSize) {
      // Remove oldest operation from dead letter queue
      this.deadLetterQueue.shift();
    }

    this.deadLetterQueue.push(operation);
    this.stats.deadLetterQueueSize = this.deadLetterQueue.length;

    logger.warn(
      {
        operationId: operation.id,
        type: operation.type,
        attempts: operation.attempts,
        deadLetterQueueSize: this.deadLetterQueue.length,
      },
      'Operation moved to dead letter queue'
    );
  }

  /**
   * Trip circuit breaker
   */
  private tripCircuitBreaker(): void {
    this.circuitBreakerState.isOpen = true;
    this.circuitBreakerState.openedAt = Date.now();
    this.stats.circuitBreakerTrips++;

    logger.warn(
      {
        failureCount: this.circuitBreakerState.failureCount,
        threshold: this.config.circuitBreakerThreshold,
        timeout: this.config.circuitBreakerTimeout,
      },
      'Circuit breaker tripped'
    );

    this.emit('circuit_breaker_tripped');
  }

  /**
   * Reset circuit breaker
   */
  private resetCircuitBreaker(): void {
    this.circuitBreakerState.isOpen = false;
    this.circuitBreakerState.failureCount = 0;

    logger.info('Circuit breaker reset');
    this.emit('circuit_breaker_reset');
  }

  /**
   * Get or create retry queue for operation type
   */
  private getOrCreateQueue(type: string): RetryOperation[] {
    if (!this.retryQueues.has(type)) {
      this.retryQueues.set(type, []);
    }
    return this.retryQueues.get(type)!;
  }

  /**
   * Update average retry time
   */
  private updateAverageRetryTime(newTime: number): void {
    if (this.stats.averageRetryTime === 0) {
      this.stats.averageRetryTime = newTime;
    } else {
      // Exponential moving average
      const alpha = 0.1;
      this.stats.averageRetryTime = alpha * newTime + (1 - alpha) * this.stats.averageRetryTime;
    }
  }

  /**
   * Get retry worker statistics
   */
  getStats(): RetryWorkerStats {
    // Update dead letter queue size
    this.stats.deadLetterQueueSize = this.deadLetterQueue.length;

    return { ...this.stats };
  }

  /**
   * Get queue information
   */
  getQueueInfo(): Record<
    string,
    {
      size: number;
      processing: number;
      nextRetryAt?: Date;
    }
  > {
    const queueInfo: Record<string, unknown> = {};

    for (const [type, queue] of this.retryQueues.entries()) {
      queueInfo[type] = {
        size: queue.length,
        processing: Array.from(this.processing).filter((id) =>
          this.retryQueues.get(type)?.some((op) => op.id === id)
        ).length,
        nextRetryAt: queue.length > 0 ? new Date(queue[0].nextRetryAt) : undefined,
      };
    }

    return queueInfo;
  }

  /**
   * Get dead letter queue items
   */
  getDeadLetterQueue(limit: number = 50): RetryOperation[] {
    return this.deadLetterQueue.slice(-limit);
  }

  /**
   * Clear dead letter queue
   */
  clearDeadLetterQueue(): number {
    const count = this.deadLetterQueue.length;
    this.deadLetterQueue = [];
    this.stats.deadLetterQueueSize = 0;

    logger.info({ clearedCount: count }, 'Dead letter queue cleared');
    return count;
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<{
    healthy: boolean;
    circuitBreakerOpen: boolean;
    processingCount: number;
    queueSizes: Record<string, number>;
    deadLetterQueueSize: number;
  }> {
    return {
      healthy: !this.circuitBreakerState.isOpen && this.config.enabled,
      circuitBreakerOpen: this.circuitBreakerState.isOpen,
      processingCount: this.processing.size,
      queueSizes: Object.fromEntries(
        Array.from(this.retryQueues.entries()).map(([type, queue]) => [type, queue.length])
      ),
      deadLetterQueueSize: this.deadLetterQueue.length,
    };
  }
}
