// EMERGENCY ROLLBACK: MCP response builders during TypeScript transition

/**
 * MCP Response Builders
 *
 * Provides standardized response builders for MCP tool execution results
 * with correlation tracking, argument sanitization, and consistent formatting.
 *
 * Features:
 * - Success and error response builders
 * - Correlation ID generation and tracking
 * - Argument sanitization and validation
 * - Response metadata management
 * - Performance tracking integration
 * - Response size limits and compression
 */

import type { ContentBlock } from '@modelcontextprotocol/sdk/types.js';
import { v4 as uuidv4 } from 'uuid';

import { McpBaseError, McpErrorFactory, type McpErrorResponse } from '@/types/mcp-error-types';

// MCP response metadata
export interface McpResponseMetadata {
  correlationId: string;
  timestamp: string;
  toolName?: string;
  executionId?: string;
  requestId?: string;
  userId?: string;
  sessionId?: string;
  responseSize: number;
  processingTime?: number;
  protocolVersion: string;
  serverVersion?: string;
}

// Success response data
export interface McpSuccessData {
  result?: unknown;
  metadata?: Record<string, unknown>;
  warnings?: string[];
  suggestions?: string[];
  nextActions?: Array<{
    type: string;
    description: string;
    parameters?: Record<string, unknown>;
  }>;
}

// MCP success response interface
export interface McpSuccessResponse {
  _meta: McpResponseMetadata;
  success: true;
  data: McpSuccessData;
  content: ContentBlock[];
}

// Sanitization configuration
export interface McpSanitizationConfig {
  maxStringLength?: number;
  maxArrayLength?: number;
  maxObjectDepth?: number;
  removePrivateKeys?: boolean;
  sanitizeKeys?: RegExp[];
  allowedKeys?: string[];
}

// Response builder configuration
export interface McpResponseBuilderConfig {
  defaultProtocolVersion?: string;
  defaultServerVersion?: string;
  maxResponseSize?: number;
  sanitization?: McpSanitizationConfig;
  enablePerformanceTracking?: boolean;
  enableCorrelationLogging?: boolean;
}

// Default configuration
const DEFAULT_CONFIG: Required<McpResponseBuilderConfig> = {
  defaultProtocolVersion: '2024-11-05',
  defaultServerVersion: '3.0.0',
  maxResponseSize: 1024 * 1024, // 1MB
  sanitization: {
    maxStringLength: 10000,
    maxArrayLength: 1000,
    maxObjectDepth: 10,
    removePrivateKeys: true,
    sanitizeKeys: [/password/i, /secret/i, /token/i, /key/i],
    allowedKeys: [],
  },
  enablePerformanceTracking: true,
  enableCorrelationLogging: true,
};

/**
 * MCP Response Builder Class
 *
 * Provides centralized response building with correlation tracking,
 * sanitization, and standardized formatting.
 */
export class McpResponseBuilder {
  private config: Required<McpResponseBuilderConfig>;
  private performanceTracker: Map<string, number> = new Map();

  constructor(config: McpResponseBuilderConfig = {}) {
    this.config = {
      defaultProtocolVersion:
        config.defaultProtocolVersion || DEFAULT_CONFIG.defaultProtocolVersion,
      defaultServerVersion: config.defaultServerVersion || DEFAULT_CONFIG.defaultServerVersion,
      maxResponseSize: config.maxResponseSize || DEFAULT_CONFIG.maxResponseSize,
      sanitization: { ...DEFAULT_CONFIG.sanitization, ...config.sanitization },
      enablePerformanceTracking:
        config.enablePerformanceTracking ?? DEFAULT_CONFIG.enablePerformanceTracking,
      enableCorrelationLogging:
        config.enableCorrelationLogging ?? DEFAULT_CONFIG.enableCorrelationLogging,
    };
  }

  /**
   * Generate a new correlation ID
   */
  generateCorrelationId(): string {
    return uuidv4();
  }

  /**
   * Start tracking performance for a correlation ID
   */
  startPerformanceTracking(correlationId: string): void {
    if (this.config.enablePerformanceTracking) {
      this.performanceTracker.set(correlationId, Date.now());
    }
  }

  /**
   * End performance tracking and return duration
   */
  endPerformanceTracking(correlationId: string): number | undefined {
    if (!this.config.enablePerformanceTracking) {
      return undefined;
    }

    const startTime = this.performanceTracker.get(correlationId);
    if (startTime) {
      const duration = Date.now() - startTime;
      this.performanceTracker.delete(correlationId);
      return duration;
    }

    return undefined;
  }

  /**
   * Create standardized response metadata
   */
  private createMetadata(
    correlationId: string,
    toolName?: string,
    executionId?: string,
    additionalContext?: {
      requestId?: string;
      userId?: string;
      sessionId?: string;
    }
  ): McpResponseMetadata {
    const processingTime = this.endPerformanceTracking(correlationId);

    return {
      correlationId,
      timestamp: new Date().toISOString(),
      toolName,
      executionId,
      requestId: additionalContext?.requestId,
      userId: additionalContext?.userId,
      sessionId: additionalContext?.sessionId,
      responseSize: 0, // Will be calculated later
      processingTime,
      protocolVersion: this.config.defaultProtocolVersion,
      serverVersion: this.config.defaultServerVersion,
    };
  }

  /**
   * Sanitize response data to prevent issues
   */
  private sanitizeData(data: unknown, depth = 0): unknown {
    if (depth > this.config.sanitization.maxObjectDepth) {
      return '[MAX_DEPTH_REACHED]';
    }

    if (data === null || data === undefined) {
      return data;
    }

    if (typeof data === 'string') {
      return data.length > this.config.sanitization.maxStringLength
        ? data.substring(0, this.config.sanitization.maxStringLength) + '...[TRUNCATED]'
        : data;
    }

    if (Array.isArray(data)) {
      if (data.length > this.config.sanitization.maxArrayLength) {
        return [...data.slice(0, this.config.sanitization.maxArrayLength), '...[TRUNCATED]'].map(
          (item) => this.sanitizeData(item, depth + 1)
        );
      }
      return data.map((item) => this.sanitizeData(item, depth + 1));
    }

    if (typeof data === 'object') {
      const sanitized: Record<string, unknown> = {};

      for (const [key, value] of Object.entries(data)) {
        // Check if key should be removed
        if (this.config.sanitization.removePrivateKeys && key.startsWith('_')) {
          continue;
        }

        // Check if key matches sanitization patterns
        const shouldSanitize = this.config.sanitization.sanitizeKeys.some((pattern) =>
          pattern.test(key)
        );

        if (shouldSanitize) {
          sanitized[key] = '[REDACTED]';
        } else if (
          this.config.sanitization.allowedKeys.length === 0 ||
          this.config.sanitization.allowedKeys.includes(key)
        ) {
          sanitized[key] = this.sanitizeData(value, depth + 1);
        }
      }

      return sanitized;
    }

    return data;
  }

  /**
   * Calculate response size
   */
  private calculateResponseSize(response: McpSuccessResponse | McpErrorResponse): number {
    return JSON.stringify(response).length;
  }

  /**
   * Build a success response
   */
  buildSuccessResponse(
    result: unknown,
    toolContext: {
      toolName: string;
      correlationId: string;
      executionId?: string;
    },
    options: {
      metadata?: Record<string, unknown>;
      warnings?: string[];
      suggestions?: string[];
      nextActions?: Array<{
        type: string;
        description: string;
        parameters?: Record<string, unknown>;
      }>;
      additionalContext?: {
        requestId?: string;
        userId?: string;
        sessionId?: string;
      };
    } = {}
  ): McpSuccessResponse {
    const { toolName, correlationId, executionId } = toolContext;

    // Create metadata
    const metadata = this.createMetadata(
      correlationId,
      toolName,
      executionId,
      options.additionalContext
    );

    // Sanitize data
    const sanitizedResult = this.sanitizeData(result);
    const sanitizedMetadata = options.metadata ? this.sanitizeData(options.metadata) : undefined;

    // Build success data
    const successData: McpSuccessData = {
      result: sanitizedResult,
      metadata: sanitizedMetadata as Record<string, unknown>,
      warnings: options.warnings,
      suggestions: options.suggestions,
      nextActions: options.nextActions,
    };

    // Build response
    const response: McpSuccessResponse = {
      _meta: metadata,
      success: true,
      data: successData,
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify(
            {
              success: true,
              result: sanitizedResult,
              correlationId,
              timestamp: metadata.timestamp,
              ...(options.warnings &&
                options.warnings.length > 0 && { warnings: options.warnings }),
              ...(options.suggestions &&
                options.suggestions.length > 0 && { suggestions: options.suggestions }),
              ...(options.metadata && { metadata: sanitizedMetadata }),
            },
            null,
            2
          ),
        },
      ],
    };

    // Update response size
    response._meta.responseSize = this.calculateResponseSize(response);

    // Log correlation if enabled
    if (this.config.enableCorrelationLogging) {
      console.error(
        `[CORRELATION] ${correlationId} | SUCCESS | ${toolName} | ${metadata.responseSize} bytes | ${metadata.processingTime}ms`
      );
    }

    return response;
  }

  /**
   * Build an error response from an error
   */
  buildErrorResponse(
    error: unknown,
    toolContext: {
      toolName: string;
      correlationId: string;
      executionId?: string;
    },
    options: {
      additionalContext?: {
        requestId?: string;
        userId?: string;
        sessionId?: string;
      };
      forceIncludeStackTrace?: boolean;
    } = {}
  ): McpErrorResponse {
    const { toolName, correlationId, executionId } = toolContext;

    // Convert to MCP error
    const mcpError =
      error instanceof McpBaseError
        ? error
        : McpErrorFactory.fromError(error, toolName, correlationId);

    // Update error context - commented out due to readonly property
    // if (!mcpError.toolContext) {
    //   mcpError.toolContext = {
    //     toolName,
    //     correlationId,
    //     executionId,
    //     timestamp: new Date().toISOString()
    //   };
    // }

    // Ensure correlation ID is set - commented out due to readonly property
    // if (!mcpError.correlationId) {
    //   mcpError.correlationId = correlationId;
    // }

    // Convert to error response
    const errorResponse = mcpError.toMcpResponse();

    // Update metadata
    if (errorResponse._meta) {
      const processingTime = this.endPerformanceTracking(correlationId);
      // errorResponse._meta.requestId = (options.additionalContext as any)?.requestId;
      // errorResponse._meta.userId = (options.additionalContext as any)?.userId;
      // errorResponse._meta.sessionId = (options.additionalContext as any)?.sessionId; // Temporarily comment out
      errorResponse._meta.toolName = toolName;
      errorResponse._meta.executionId = executionId;

      if (processingTime !== undefined) {
        // Add processing time to error context
        if (errorResponse.error.context) {
          (errorResponse.error.context as unknown).processingTime = processingTime;
        }
      }
    }

    // Include stack trace if requested and available
    if (options.forceIncludeStackTrace && mcpError.technicalDetails) {
      if (errorResponse.error.details) {
        errorResponse.error.details.stack = mcpError.technicalDetails;
      }
    }

    // Update response size
    const responseSize = this.calculateResponseSize(errorResponse);
    if (errorResponse._meta) {
      // Note: _meta is readonly in the interface, but we need to update it
      // This is a TypeScript limitation - we'll use type assertion
      (errorResponse._meta as unknown).responseSize = responseSize;
    }

    // Log correlation if enabled
    if (this.config.enableCorrelationLogging) {
      console.error(
        `[CORRELATION] ${correlationId} | ERROR | ${toolName} | ${mcpError.code} | ${responseSize} bytes`
      );
    }

    return errorResponse;
  }

  /**
   * Build a validation error response
   */
  buildValidationErrorResponse(
    validationErrors: Array<{
      field: string;
      message: string;
      receivedValue?: unknown;
      expectedType?: string;
    }>,
    toolContext: {
      toolName: string;
      correlationId: string;
      executionId?: string;
    },
    options: {
      additionalContext?: {
        requestId?: string;
        userId?: string;
        sessionId?: string;
      };
    } = {}
  ): McpErrorResponse {
    const errorMessage = `Validation failed: ${validationErrors.map((e) => e.message).join(', ')}`;
    const mcpError = McpErrorFactory.createValidationError(
      toolContext.toolName,
      validationErrors[0]?.field || 'unknown',
      errorMessage,
      {
        correlationId: toolContext.correlationId,
        receivedValue: validationErrors[0]?.receivedValue,
        expectedType: validationErrors[0]?.expectedType,
      }
    );

    return this.buildErrorResponse(mcpError, toolContext, options);
  }

  /**
   * Build a timeout error response
   */
  buildTimeoutErrorResponse(
    timeoutMs: number,
    toolContext: {
      toolName: string;
      correlationId: string;
      executionId?: string;
    },
    options: {
      additionalContext?: {
        requestId?: string;
        userId?: string;
        sessionId?: string;
      };
    } = {}
  ): McpErrorResponse {
    const mcpError = McpErrorFactory.createTimeoutError(toolContext.toolName, timeoutMs, {
      correlationId: toolContext.correlationId,
      executionId: toolContext.executionId,
    });

    return this.buildErrorResponse(mcpError, toolContext, options);
  }

  /**
   * Build a resource limit error response
   */
  buildResourceLimitErrorResponse(
    resourceType: string,
    reason: string,
    toolContext: {
      toolName: string;
      correlationId: string;
      executionId?: string;
    },
    options: {
      retryAfter?: number;
      additionalContext?: {
        requestId?: string;
        userId?: string;
        sessionId?: string;
      };
    } = {}
  ): McpErrorResponse {
    const mcpError = McpErrorFactory.createResourceError(resourceType, reason, {
      correlationId: toolContext.correlationId,
      retryable: true,
    });

    const errorResponse = this.buildErrorResponse(mcpError, toolContext, options);

    // Add retry after if specified
    if (options.retryAfter) {
      errorResponse.error.retryAfter = options.retryAfter;
    }

    return errorResponse;
  }

  /**
   * Get configuration
   */
  getConfig(): Readonly<Required<McpResponseBuilderConfig>> {
    return this.config;
  }

  /**
   * Update configuration
   */
  updateConfig(newConfig: Partial<McpResponseBuilderConfig>): void {
    this.config = {
      ...this.config,
      ...newConfig,
      sanitization: { ...this.config.sanitization, ...newConfig.sanitization },
    };
  }

  /**
   * Clean up old performance tracking data
   */
  cleanupPerformanceTracking(olderThanMs: number = 300000): void {
    // 5 minutes default
    const cutoff = Date.now() - olderThanMs;

    for (const [correlationId, startTime] of this.performanceTracker.entries()) {
      if (startTime < cutoff) {
        this.performanceTracker.delete(correlationId);
      }
    }
  }
}

// Default response builder instance
export const defaultResponseBuilder = new McpResponseBuilder();

// Convenience functions for quick response building
export function createMcpSuccessResponse(
  result: unknown,
  toolName: string,
  correlationId?: string,
  options?: {
    metadata?: Record<string, unknown>;
    warnings?: string[];
    suggestions?: string[];
  }
): McpSuccessResponse {
  const builder = new McpResponseBuilder();
  const finalCorrelationId = correlationId || builder.generateCorrelationId();

  return builder.buildSuccessResponse(
    result,
    { toolName, correlationId: finalCorrelationId },
    options
  );
}

export function createMcpErrorResponse(
  error: unknown,
  toolName: string,
  correlationId?: string,
  options?: {
    forceIncludeStackTrace?: boolean;
  }
): McpErrorResponse {
  const builder = new McpResponseBuilder();
  const finalCorrelationId = correlationId || builder.generateCorrelationId();

  return builder.buildErrorResponse(
    error,
    { toolName, correlationId: finalCorrelationId },
    options
  );
}

export function generateCorrelationId(): string {
  return defaultResponseBuilder.generateCorrelationId();
}
