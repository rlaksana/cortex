/**
 * Response Builder Utility
 *
 * Standardized response building for MCP tools with
 * consistent metadata, error handling, and formatting
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { createResponseMeta, UnifiedToolResponse } from '../types/unified-response.interface';
import { logger } from './logger';

/**
 * Response builder context
 */
interface ResponseBuilderContext {
  operationType: string;
  startTime: number;
  requestId?: string;
  operationId?: string;
}

/**
 * Memory store response data
 */
interface MemoryStoreResponseData {
  success: boolean;
  stored: any[];
  errors: any[];
  summary?: any;
  total: number;
  batchId?: string;
  autonomous_context?: any;
}

/**
 * Memory find response data
 */
interface MemoryFindResponseData {
  query: string;
  strategy: string;
  confidence: number;
  total: number;
  items: any[];
  searchId?: string;
  strategyDetails?: any;
  observability?: any;
}

/**
 * Response metrics
 */
interface ResponseMetrics {
  executionTime: number;
  itemCount?: number;
  errorCount?: number;
  vectorUsed?: boolean;
  degraded?: boolean;
  confidenceScore?: number;
}

/**
 * Standardized response builder
 */
export class ResponseBuilder {
  private context: ResponseBuilderContext;

  constructor(operationType: string, startTime?: number) {
    this.context = {
      operationType,
      startTime: startTime || Date.now(),
      requestId: `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    };
  }

  /**
   * Create memory store response
   */
  createMemoryStoreResponse(
    data: MemoryStoreResponseData,
    additionalContext?: any
  ): UnifiedToolResponse {
    const duration = Date.now() - this.context.startTime;
    const metrics: ResponseMetrics = {
      executionTime: duration,
      itemCount: data.stored.length,
      errorCount: data.errors.length,
      confidenceScore: data.success ? 1.0 : 0.0,
    };

    return {
      data: {
        capabilities: this.getCapabilities(),
        success: data.success,
        stored: data.stored.length,
        stored_items: data.stored,
        errors: data.errors,
        summary: data.summary,
        total: data.total,
        autonomous_context: data.autonomous_context,
        audit_metadata: {
          batch_id: data.batchId || this.context.operationId,
          duration_ms: duration,
          audit_logged: true,
        },
        observability: this.createObservabilityData(metrics),
      },
      meta: createResponseMeta({
        strategy: 'autonomous_deduplication',
        vector_used: true,
        degraded: false,
        source: 'cortex_memory',
        execution_time_ms: duration,
        confidence_score: metrics.confidenceScore || 0,
        additional: {
          ...additionalContext,
          request_id: this.context.requestId,
          operation_id: this.context.operationId,
          items_processed: data.total,
          items_stored: data.stored.length,
          items_errors: data.errors.length,
        },
      }),
    };
  }

  /**
   * Create memory find response
   */
  createMemoryFindResponse(
    data: MemoryFindResponseData,
    additionalContext?: any
  ): UnifiedToolResponse {
    const duration = Date.now() - this.context.startTime;
    const metrics: ResponseMetrics = {
      executionTime: duration,
      itemCount: data.items.length,
      vectorUsed: data.observability?.vector_used || false,
      degraded: data.observability?.degraded || false,
      confidenceScore: data.confidence,
    };

    return {
      data: {
        capabilities: this.getCapabilities(),
        query: data.query,
        strategy: data.strategy,
        confidence: data.confidence,
        total: data.total,
        executionTime: duration,
        vector_used: metrics.vectorUsed,
        degraded: metrics.degraded,
        search_id: data.searchId || this.context.operationId,
        strategy_details: data.strategyDetails,
        items: data.items,
        audit_metadata: {
          search_id: data.searchId || this.context.operationId,
          duration_ms: duration,
          audit_logged: true,
          strategy_used: data.strategy,
          vector_used: metrics.vectorUsed,
          degraded: metrics.degraded,
        },
        observability: {
          source: 'cortex_memory',
          strategy: data.strategy,
          vector_used: metrics.vectorUsed,
          degraded: metrics.degraded,
          execution_time_ms: duration,
          confidence_average: data.confidence,
          search_id: data.searchId || this.context.operationId,
        },
      },
      meta: createResponseMeta({
        strategy: data.strategy as any,
        vector_used: Boolean(metrics.vectorUsed),
        degraded: Boolean(metrics.degraded),
        source: 'cortex_memory',
        execution_time_ms: duration,
        confidence_score: metrics.confidenceScore || 0,
        additional: {
          ...additionalContext,
          request_id: this.context.requestId,
          operation_id: this.context.operationId,
          search_id: data.searchId,
          query: data.query,
          results_found: data.total,
          mode: additionalContext?.mode || 'auto',
        },
      }),
    };
  }

  /**
   * Create error response
   */
  createErrorResponse(error: Error, additionalContext?: any): UnifiedToolResponse {
    const duration = Date.now() - this.context.startTime;

    return {
      data: {
        capabilities: this.getCapabilities(),
        success: false,
        error: {
          message: error.message,
          type: error.constructor.name,
          timestamp: Date.now(),
        },
        execution_time: duration,
        audit_metadata: {
          request_id: this.context.requestId,
          operation_id: this.context.operationId,
          duration_ms: duration,
          audit_logged: true,
          error_occurred: true,
        },
        observability: {
          source: 'cortex_memory',
          error: true,
          execution_time_ms: duration,
          confidence_score: 0.0,
        },
      },
      meta: createResponseMeta({
        strategy: 'error',
        vector_used: false,
        degraded: true,
        source: 'cortex_memory',
        execution_time_ms: duration,
        confidence_score: 0.0,
        additional: {
          ...additionalContext,
          request_id: this.context.requestId,
          operation_id: this.context.operationId,
          error_type: error.constructor.name,
          error_message: error.message,
        },
      }),
    };
  }

  /**
   * Create health check response
   */
  createHealthResponse(data: any, additionalContext?: any): UnifiedToolResponse {
    const duration = Date.now() - this.context.startTime;

    return {
      data: {
        capabilities: this.getCapabilities(),
        status: 'healthy',
        data,
        execution_time: duration,
        timestamp: Date.now(),
      },
      meta: createResponseMeta({
        strategy: 'health_check',
        vector_used: false,
        degraded: false,
        source: 'cortex_memory',
        execution_time_ms: duration,
        confidence_score: 1.0,
        additional: {
          ...additionalContext,
          request_id: this.context.requestId,
          operation_id: this.context.operationId,
          health_check_time: Date.now(),
        },
      }),
    };
  }

  /**
   * Get standard capabilities object
   */
  private getCapabilities() {
    return {
      vector: 'ok',
      chunking: 'disabled',
      ttl: 'disabled',
    };
  }

  /**
   * Create observability data
   */
  private createObservabilityData(metrics: ResponseMetrics) {
    return {
      source: 'cortex_memory',
      strategy: 'orchestrator_based',
      vector_used: metrics.vectorUsed || false,
      degraded: metrics.degraded || false,
      execution_time_ms: metrics.executionTime,
      confidence_score: metrics.confidenceScore || 0.0,
    };
  }

  /**
   * Set operation ID for tracking
   */
  setOperationId(operationId: string): ResponseBuilder {
    this.context.operationId = operationId;
    return this;
  }

  /**
   * Get current context
   */
  getContext(): ResponseBuilderContext {
    return { ...this.context };
  }
}

/**
 * Factory function for creating response builders
 */
export function createResponseBuilder(operationType: string, startTime?: number): ResponseBuilder {
  return new ResponseBuilder(operationType, startTime);
}

/**
 * Convenience function for memory store responses
 */
export function createMemoryStoreResponse(
  data: MemoryStoreResponseData,
  startTime?: number,
  additionalContext?: any
): UnifiedToolResponse {
  const builder = new ResponseBuilder('memory_store', startTime);
  if (additionalContext?.operationId) {
    builder.setOperationId(additionalContext.operationId);
  }
  return builder.createMemoryStoreResponse(data, additionalContext);
}

/**
 * Convenience function for memory find responses
 */
export function createMemoryFindResponse(
  data: MemoryFindResponseData,
  startTime?: number,
  additionalContext?: any
): UnifiedToolResponse {
  const builder = new ResponseBuilder('memory_find', startTime);
  if (additionalContext?.operationId) {
    builder.setOperationId(additionalContext.operationId);
  }
  return builder.createMemoryFindResponse(data, additionalContext);
}

/**
 * Convenience function for error responses
 */
export function createErrorResponse(
  error: Error,
  operationType: string = 'unknown',
  startTime?: number,
  additionalContext?: any
): UnifiedToolResponse {
  const builder = new ResponseBuilder(operationType, startTime);
  if (additionalContext?.operationId) {
    builder.setOperationId(additionalContext.operationId);
  }
  return builder.createErrorResponse(error, additionalContext);
}
