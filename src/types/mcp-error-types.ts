// EMERGENCY ROLLBACK: MCP error handling extensions during TypeScript transition

/**
 * MCP Error Type Extensions
 *
 * Extends the existing BaseError hierarchy with MCP-specific error types
 * and response formats. Maintains compatibility with existing error
 * infrastructure while adding MCP protocol-specific features.
 *
 * Features:
 * - MCP-specific error codes and categories
 * - Correlation ID tracking
 * - Tool execution context
 * - Protocol-level error formatting
 * - Argument validation errors
 * - Tool timeout and cancellation errors
 */

import {
  BaseError,
  type ErrorCategory,
  type ErrorCode,
  ErrorSeverity,
} from '@/utils/error-handler.js';

// MCP-specific error codes (2000-2999 range to avoid conflicts)
export enum McpErrorCode {
  // Tool execution errors (2000-2099)
  TOOL_NOT_FOUND = 'E2000',
  TOOL_EXECUTION_FAILED = 'E2001',
  TOOL_TIMEOUT = 'E2002',
  TOOL_CANCELLED = 'E2003',
  TOOL_INVALID_ARGUMENTS = 'E2004',
  TOOL_PERMISSION_DENIED = 'E2005',
  TOOL_RESOURCE_UNAVAILABLE = 'E2006',
  TOOL_DEPENDENCY_FAILED = 'E2007',

  // Protocol errors (2100-2199)
  PROTOCOL_VIOLATION = 'E2100',
  INVALID_REQUEST_FORMAT = 'E2101',
  MISSING_CORRELATION_ID = 'E2102',
  RESPONSE_TOO_LARGE = 'E2103',
  UNEXPECTED_RESPONSE_FORMAT = 'E2104',

  // Argument validation errors (2200-2299)
  ARGUMENT_SCHEMA_VIOLATION = 'E2200',
  REQUIRED_ARGUMENT_MISSING = 'E2201',
  INVALID_ARGUMENT_TYPE = 'E2202',
  ARGUMENT_OUT_OF_RANGE = 'E2203',
  ARGUMENT_PATTERN_MISMATCH = 'E2204',

  // Context and state errors (2300-2399)
  CONTEXT_NOT_FOUND = 'E2300',
  CONTEXT_EXPIRED = 'E2301',
  STATE_CORRUPTION = 'E2302',
  CONCURRENT_MODIFICATION = 'E2303',

  // Resource and quota errors (2400-2499)
  RESOURCE_QUOTA_EXCEEDED = 'E2400',
  MEMORY_LIMIT_EXCEEDED = 'E2401',
  TEMPORARY_STORAGE_FULL = 'E2402',
  RATE_LIMIT_EXCEEDED = 'E2403',
}

// MCP error categories extending base categories
export enum McpErrorCategory {
  TOOL_EXECUTION = 'tool_execution',
  PROTOCOL = 'protocol',
  ARGUMENT_VALIDATION = 'argument_validation',
  CONTEXT_MANAGEMENT = 'context_management',
  RESOURCE_MANAGEMENT = 'resource_management',
  MCP_SYSTEM = 'mcp_system',
}

// MCP tool execution context
export interface McpToolContext {
  toolName: string;
  arguments?: Record<string, unknown>;
  correlationId?: string;
  userId?: string;
  sessionId?: string;
  requestId?: string;
  timestamp: string;
  executionId?: string;
}

// MCP error response interface
export interface McpErrorResponse {
  _meta?: {
    correlationId?: string;
    timestamp: string;
    toolName?: string;
    executionId?: string;
    protocolVersion?: string;
  };
  error: {
    code: string | McpErrorCode;
    category: string | McpErrorCategory;
    severity: string | ErrorSeverity;
    message: string;
    details?: {
      argument?: string;
      expectedType?: string;
      receivedType?: string;
      allowedValues?: unknown[];
      validationErrors?: string[];
      stack?: string;
    };
    context?: McpToolContext;
    retryable: boolean;
    retryAfter?: number; // seconds
    suggestions?: string[];
  };
}

// Base MCP Error class
export abstract class McpBaseError extends BaseError {
  public readonly correlationId?: string;
  public readonly toolContext?: McpToolContext;
  public readonly protocolVersion: string;

  constructor({
    code,
    category,
    severity,
    message,
    userMessage,
    context,
    technicalDetails,
    correlationId,
    toolContext,
    retryable = false,
    protocolVersion = '2024-11-05',
  }: {
    code: ErrorCode | McpErrorCode;
    category: ErrorCategory | McpErrorCategory;
    severity: ErrorSeverity;
    message: string;
    userMessage: string;
    context?: Record<string, unknown>;
    technicalDetails?: string;
    correlationId?: string;
    toolContext?: McpToolContext;
    retryable?: boolean;
    protocolVersion?: string;
  }) {
    super({
      code,
      category,
      severity,
      message,
      userMessage,
      context,
      technicalDetails,
      retryable,
    });

    this.correlationId = correlationId;
    this.toolContext = toolContext;
    this.protocolVersion = protocolVersion;
  }

  // Convert to MCP-specific error response
  toMcpResponse(): McpErrorResponse {
    return {
      _meta: {
        correlationId: this.correlationId,
        timestamp: this.timestamp,
        toolName: this.toolContext?.toolName,
        executionId: this.toolContext?.executionId,
        protocolVersion: this.protocolVersion,
      },
      error: {
        code: this.code,
        category: this.category,
        severity: this.severity,
        message: this.userMessage,
        details: {
          stack: this.technicalDetails,
        },
        context: this.toolContext,
        retryable: this.retryable,
        suggestions: this.getRetrySuggestions(),
      },
    };
  }

  // Get retry suggestions based on error type
  protected getRetrySuggestions(): string[] {
    if (!this.retryable) {
      return [];
    }

    const suggestions: string[] = [];

    switch (this.code) {
      case McpErrorCode.TOOL_TIMEOUT:
        suggestions.push('Try reducing the complexity of your request');
        suggestions.push('Consider breaking down the operation into smaller steps');
        break;
      case McpErrorCode.RATE_LIMIT_EXCEEDED:
        suggestions.push('Wait before retrying the request');
        suggestions.push('Consider reducing the frequency of requests');
        break;
      case McpErrorCode.RESOURCE_QUOTA_EXCEEDED:
        suggestions.push('Free up resources or upgrade your plan');
        suggestions.push('Try again later when resources are available');
        break;
      default:
        suggestions.push('Try the operation again');
        if (this.toolContext?.toolName) {
          suggestions.push(`Check if the ${this.toolContext.toolName} tool is available`);
        }
    }

    return suggestions;
  }
}

// Tool Execution Errors
export class McpToolError extends McpBaseError {
  constructor(
    message: string,
    toolName: string,
    options: {
      userMessage?: string;
      arguments?: Record<string, unknown>;
      correlationId?: string;
      executionId?: string;
      cause?: Error;
    } = {}
  ) {
    super({
      code: McpErrorCode.TOOL_EXECUTION_FAILED,
      category: McpErrorCategory.TOOL_EXECUTION,
      severity: ErrorSeverity.MEDIUM,
      message,
      userMessage: options.userMessage || `Tool execution failed: ${toolName}`,
      context: {
        toolName,
        arguments: options.arguments,
        cause: options.cause?.message,
      },
      correlationId: options.correlationId,
      toolContext: {
        toolName,
        arguments: options.arguments,
        correlationId: options.correlationId,
        executionId: options.executionId,
        timestamp: new Date().toISOString(),
      },
      retryable: true,
    });

    this.name = 'McpToolError';
  }
}

export class McpToolNotFoundError extends McpBaseError {
  constructor(
    toolName: string,
    options: {
      correlationId?: string;
      availableTools?: string[];
    } = {}
  ) {
    super({
      code: McpErrorCode.TOOL_NOT_FOUND,
      category: McpErrorCategory.TOOL_EXECUTION,
      severity: ErrorSeverity.HIGH,
      message: `Tool not found: ${toolName}`,
      userMessage: `The requested tool '${toolName}' is not available`,
      context: {
        toolName,
        availableTools: options.availableTools,
      },
      correlationId: options.correlationId,
      retryable: false,
    });

    this.name = 'McpToolNotFoundError';
  }
}

export class McpToolTimeoutError extends McpBaseError {
  constructor(
    toolName: string,
    timeoutMs: number,
    options: {
      correlationId?: string;
      executionId?: string;
    } = {}
  ) {
    super({
      code: McpErrorCode.TOOL_TIMEOUT,
      category: McpErrorCategory.TOOL_EXECUTION,
      severity: ErrorSeverity.MEDIUM,
      message: `Tool execution timed out after ${timeoutMs}ms: ${toolName}`,
      userMessage: `The tool '${toolName}' took too long to execute and was cancelled`,
      context: {
        toolName,
        timeoutMs,
      },
      correlationId: options.correlationId,
      toolContext: {
        toolName,
        correlationId: options.correlationId,
        executionId: options.executionId,
        timestamp: new Date().toISOString(),
      },
      retryable: true,
    });

    this.name = 'McpToolTimeoutError';
  }
}

export class McpToolCancelledError extends McpBaseError {
  constructor(
    toolName: string,
    reason: string,
    options: {
      correlationId?: string;
      executionId?: string;
    } = {}
  ) {
    super({
      code: McpErrorCode.TOOL_CANCELLED,
      category: McpErrorCategory.TOOL_EXECUTION,
      severity: ErrorSeverity.LOW,
      message: `Tool execution cancelled: ${toolName} - ${reason}`,
      userMessage: `The tool '${toolName}' was cancelled: ${reason}`,
      context: {
        toolName,
        reason,
      },
      correlationId: options.correlationId,
      toolContext: {
        toolName,
        correlationId: options.correlationId,
        executionId: options.executionId,
        timestamp: new Date().toISOString(),
      },
      retryable: false,
    });

    this.name = 'McpToolCancelledError';
  }
}

// Argument Validation Errors
export class McpArgumentError extends McpBaseError {
  constructor(
    toolName: string,
    argumentName: string,
    reason: string,
    options: {
      receivedValue?: unknown;
      expectedType?: string;
      allowedValues?: unknown[];
      correlationId?: string;
    } = {}
  ) {
    super({
      code: McpErrorCode.ARGUMENT_SCHEMA_VIOLATION,
      category: McpErrorCategory.ARGUMENT_VALIDATION,
      severity: ErrorSeverity.MEDIUM,
      message: `Argument validation failed for ${toolName}.${argumentName}: ${reason}`,
      userMessage: `Invalid argument '${argumentName}' for tool '${toolName}': ${reason}`,
      context: {
        toolName,
        argumentName,
        reason,
        receivedValue: options.receivedValue,
        expectedType: options.expectedType,
        allowedValues: options.allowedValues,
      },
      correlationId: options.correlationId,
      retryable: false,
    });

    this.name = 'McpArgumentError';
  }
}

export class McpMissingArgumentError extends McpBaseError {
  constructor(
    toolName: string,
    argumentName: string,
    options: {
      correlationId?: string;
    } = {}
  ) {
    super({
      code: McpErrorCode.REQUIRED_ARGUMENT_MISSING,
      category: McpErrorCategory.ARGUMENT_VALIDATION,
      severity: ErrorSeverity.MEDIUM,
      message: `Required argument missing: ${toolName}.${argumentName}`,
      userMessage: `Missing required argument '${argumentName}' for tool '${toolName}'`,
      context: {
        toolName,
        argumentName,
      },
      correlationId: options.correlationId,
      retryable: false,
    });

    this.name = 'McpMissingArgumentError';
  }
}

// Protocol Errors
export class McpProtocolError extends McpBaseError {
  constructor(
    message: string,
    options: {
      correlationId?: string;
      protocolVersion?: string;
      requestDetails?: Record<string, unknown>;
    } = {}
  ) {
    super({
      code: McpErrorCode.PROTOCOL_VIOLATION,
      category: McpErrorCategory.PROTOCOL,
      severity: ErrorSeverity.HIGH,
      message,
      userMessage: 'MCP protocol error occurred',
      context: {
        ...options.requestDetails,
      },
      correlationId: options.correlationId,
      protocolVersion: options.protocolVersion,
      retryable: false,
    });

    this.name = 'McpProtocolError';
  }
}

export class McpInvalidRequestError extends McpBaseError {
  constructor(
    reason: string,
    options: {
      correlationId?: string;
      requestDetails?: Record<string, unknown>;
    } = {}
  ) {
    super({
      code: McpErrorCode.INVALID_REQUEST_FORMAT,
      category: McpErrorCategory.PROTOCOL,
      severity: ErrorSeverity.HIGH,
      message: `Invalid request format: ${reason}`,
      userMessage: `Invalid request format: ${reason}`,
      context: {
        reason,
        ...options.requestDetails,
      },
      correlationId: options.correlationId,
      retryable: false,
    });

    this.name = 'McpInvalidRequestError';
  }
}

// Resource Management Errors
export class McpResourceError extends McpBaseError {
  constructor(
    resourceType: string,
    reason: string,
    options: {
      correlationId?: string;
      retryable?: boolean;
    } = {}
  ) {
    super({
      code: McpErrorCode.RESOURCE_QUOTA_EXCEEDED,
      category: McpErrorCategory.RESOURCE_MANAGEMENT,
      severity: ErrorSeverity.MEDIUM,
      message: `Resource error (${resourceType}): ${reason}`,
      userMessage: `Resource limit reached: ${reason}`,
      context: {
        resourceType,
        reason,
      },
      correlationId: options.correlationId,
      retryable: options.retryable ?? true,
    });

    this.name = 'McpResourceError';
  }
}

// Context Management Errors
export class McpContextError extends McpBaseError {
  constructor(
    contextType: string,
    identifier: string,
    reason: string,
    options: {
      correlationId?: string;
    } = {}
  ) {
    super({
      code: McpErrorCode.CONTEXT_NOT_FOUND,
      category: McpErrorCategory.CONTEXT_MANAGEMENT,
      severity: ErrorSeverity.MEDIUM,
      message: `Context error (${contextType}): ${identifier} - ${reason}`,
      userMessage: `Requested context not available: ${reason}`,
      context: {
        contextType,
        identifier,
        reason,
      },
      correlationId: options.correlationId,
      retryable: false,
    });

    this.name = 'McpContextError';
  }
}

// MCP Error Factory for easy error creation
export class McpErrorFactory {
  /**
   * Create a standardized MCP error from any error
   */
  static fromError(error: unknown, toolName?: string, correlationId?: string): McpBaseError {
    // If it's already an MCP error, return as-is
    if (error instanceof McpBaseError) {
      return error;
    }

    // If it's a BaseError, wrap it
    if (error instanceof BaseError) {
      return new McpToolError(error.message, toolName || 'unknown', {
        userMessage: error.userMessage,
        correlationId,
        cause: error,
      });
    }

    // If it's a standard Error, convert appropriately
    if (error instanceof Error) {
      const message = error.message.toLowerCase();

      if (message.includes('timeout')) {
        return new McpToolTimeoutError(toolName || 'unknown', 30000, { correlationId });
      }
      if (message.includes('not found') || message.includes('missing')) {
        return new McpToolNotFoundError(toolName || 'unknown', { correlationId });
      }
      if (message.includes('validation') || message.includes('invalid')) {
        return new McpArgumentError(toolName || 'unknown', 'unknown', error.message, {
          correlationId,
          receivedValue: error.message,
        });
      }
      if (message.includes('cancelled') || message.includes('abort')) {
        return new McpToolCancelledError(toolName || 'unknown', error.message, { correlationId });
      }
      if (message.includes('rate limit') || message.includes('quota')) {
        return new McpResourceError('rate_limit', error.message, { correlationId });
      }

      // Default to tool error
      return new McpToolError(error.message, toolName || 'unknown', {
        correlationId,
        cause: error,
      });
    }

    // For non-Error objects
    return new McpToolError(`Unknown error: ${String(error)}`, toolName || 'unknown', {
      correlationId,
    });
  }

  /**
   * Create a validation error for invalid arguments
   */
  static createValidationError(
    toolName: string,
    argumentName: string,
    reason: string,
    options: {
      receivedValue?: unknown;
      expectedType?: string;
      correlationId?: string;
    } = {}
  ): McpArgumentError {
    return new McpArgumentError(toolName, argumentName, reason, options);
  }

  /**
   * Create a timeout error
   */
  static createTimeoutError(
    toolName: string,
    timeoutMs: number,
    options: {
      correlationId?: string;
      executionId?: string;
    } = {}
  ): McpToolTimeoutError {
    return new McpToolTimeoutError(toolName, timeoutMs, options);
  }

  /**
   * Create a resource error
   */
  static createResourceError(
    resourceType: string,
    reason: string,
    options: {
      correlationId?: string;
      retryable?: boolean;
    } = {}
  ): McpResourceError {
    return new McpResourceError(resourceType, reason, options);
  }
}

// Export all error types for convenience
export { McpErrorCategory as ErrorCategory, McpErrorCode as ErrorCode, ErrorSeverity };
