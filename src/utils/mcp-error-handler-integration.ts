// NUCLEAR STRIKE: MCP error handler integration during TypeScript transition
// ALL ERRORS WILL BE ELIMINATED WITH MAXIMUM FORCE

/**
 * MCP Error Handler Integration
 *
 * Integrates all MCP error handling components into a unified system that can be
 * easily adopted throughout the cortex-mcp codebase. Provides convenience
 * functions and higher-level abstractions for common error handling patterns.
 *
 * Features:
 * - Unified error handling interface
 * - Automatic metrics collection
 * - Simplified tool wrapper patterns
 * - Integration with existing error middleware
 * - Convenience functions for common scenarios
 */

// NUCLEAR ATTACK: Import all modules with maximum force
import type { ContentBlock } from '@modelcontextprotocol/sdk/types.js';

import { type McpErrorAlert, mcpErrorMetrics } from '@/monitoring/mcp-error-metrics';
// NUCLEAR FORCE: Eliminate all import type errors
import {
  McpBaseError,
  McpErrorFactory,
  type McpToolContext,
  McpToolTimeoutError,
} from '@/types/mcp-error-types';
import { defaultResponseBuilder, type McpResponseBuilder } from '@/utils/mcp-response-builders';

// Integration configuration
export interface McpErrorIntegrationConfig {
  enableMetrics?: boolean;
  enableRealTimeAlerting?: boolean;
  defaultTimeout?: number;
  customResponseBuilder?: McpResponseBuilder;
}

// Tool execution result
export interface McpToolResult {
  success: boolean;
  content: ContentBlock[];
  correlationId: string;
  executionTime: number;
  metrics?: {
    errorType?: string;
    responseTime: number;
  };
}

// Integration class that ties everything together
export class McpErrorHandlerIntegration {
  private config: Required<McpErrorIntegrationConfig>;
  private responseBuilder: McpResponseBuilder;

  constructor(config: McpErrorIntegrationConfig = {}) {
    this.config = {
      enableMetrics: config.enableMetrics ?? true,
      enableRealTimeAlerting: config.enableRealTimeAlerting ?? true,
      defaultTimeout: config.defaultTimeout ?? 30000,
      customResponseBuilder: config.customResponseBuilder || defaultResponseBuilder,
    };

    this.responseBuilder = this.config.customResponseBuilder;

    // Set up metrics event listeners if enabled
    if (this.config.enableMetrics) {
      this.setupMetricsListeners();
    }
  }

  /**
   * Execute a tool with comprehensive MCP error handling
   */
  async executeTool<T = unknown>(
    toolName: string,
    operation: () => Promise<T>,
    options: {
      args?: Record<string, unknown>;
      correlationId?: string;
      timeout?: number;
      userId?: string;
      sessionId?: string;
      onSuccess?: (result: T) => ContentBlock[];
      onError?: (error: McpBaseError) => ContentBlock[];
    } = {}
  ): Promise<McpToolResult> {
    const correlationId = options.correlationId || this.responseBuilder.generateCorrelationId();
    const startTime = Date.now();
    const timeout = options.timeout ?? this.config.defaultTimeout;

    // Start performance tracking
    this.responseBuilder.startPerformanceTracking(correlationId);

    try {
      // Execute the operation with timeout
      const result = await this.executeWithTimeout(operation, timeout, toolName, correlationId);

      // Record success metrics
      if (this.config.enableMetrics) {
        mcpErrorMetrics.recordSuccess(toolName, Date.now() - startTime, correlationId);
      }

      // Build success response
      const content = options.onSuccess
        ? options.onSuccess(result)
        : this.responseBuilder.buildSuccessResponse(result, {
            toolName,
            correlationId,
            executionId: this.generateExecutionId(),
          }).content;

      return {
        success: true,
        content,
        correlationId,
        executionTime: Date.now() - startTime,
        metrics: {
          responseTime: Date.now() - startTime,
        },
      };
    } catch (error) {
      // Convert to MCP error
      const mcpError =
        error instanceof McpBaseError
          ? error
          : McpErrorFactory.fromError(error, toolName, correlationId);

      // Record error metrics
      if (this.config.enableMetrics) {
        mcpErrorMetrics.recordError(mcpError, correlationId);
      }

      // Build error response
      const content = options.onError
        ? options.onError(mcpError)
        : [
            {
              type: 'text' as const,
              text: JSON.stringify(
                this.responseBuilder.buildErrorResponse(mcpError, {
                  toolName,
                  correlationId,
                  executionId: this.generateExecutionId(),
                }),
                null,
                2
              ),
            },
          ];

      return {
        success: false,
        content,
        correlationId,
        executionTime: Date.now() - startTime,
        metrics: {
          errorType: mcpError.constructor.name,
          responseTime: Date.now() - startTime,
        },
      };
    }
  }

  /**
   * Validate arguments with proper error handling
   */
  validateArguments(
    toolName: string,
    args: Record<string, unknown>,
    schema: Record<
      string,
      {
        type?: string;
        required?: boolean;
        minLength?: number;
        maxLength?: number;
        pattern?: RegExp;
        enum?: unknown[];
        custom?: (value: unknown) => boolean | string;
      }
    >
  ): void {
    // Check required fields
    const requiredFields = Object.entries(schema)
      .filter(([, config]) => config.required)
      .map(([field]) => field);

    const missingFields = requiredFields.filter((field) => !(field in args));
    if (missingFields.length > 0) {
      throw McpErrorFactory.createValidationError(
        toolName,
        missingFields.join(', '),
        `Missing required fields: ${missingFields.join(', ')}`,
        {
          receivedValue: Object.keys(args),
          expectedType: `object with fields: ${requiredFields.join(', ')}`,
        }
      );
    }

    // Validate each field
    Object.entries(schema).forEach(([fieldName, config]) => {
      if (fieldName in args) {
        const value = args[fieldName];
        const validationError = this.validateFieldValue(fieldName, value, config);
        if (validationError) {
          throw McpErrorFactory.createValidationError(toolName, fieldName, validationError, {
            receivedValue: value,
            expectedType: config.type,
          });
        }
      }
    });
  }

  /**
   * Create a standardized tool wrapper
   */
  createToolWrapper<
    TArgs extends Record<string, unknown> = Record<string, unknown>,
    TResult = unknown,
  >(
    toolName: string,
    handler: (args: TArgs, context: McpToolContext) => Promise<TResult>,
    options: {
      schema?: Record<string, unknown>;
      timeout?: number;
      requireAuth?: boolean;
      rateLimit?: {
        windowMs: number;
        maxRequests: number;
      };
    } = {}
  ) {
    return async (args: TArgs, extra?: unknown): Promise<{ content: ContentBlock[] }> => {
      const correlationId = this.responseBuilder.generateCorrelationId();
      const context: McpToolContext = {
        toolName,
        arguments: args,
        correlationId,
        timestamp: new Date().toISOString(),
      };

      try {
        // Validate arguments if schema provided
        if (options.schema) {
          this.validateArguments(toolName, args as Record<string, unknown>, options.schema);
        }

        // Execute the tool
        const result = await this.executeTool(toolName, () => handler(args, context), {
          args,
          correlationId,
          timeout: options.timeout,
        });

        return {
          content: result.content,
        };
      } catch (error) {
        // Ensure we always return a properly formatted response
        const mcpError =
          error instanceof McpBaseError
            ? error
            : McpErrorFactory.fromError(error, toolName, correlationId);

        const errorResponse = this.responseBuilder.buildErrorResponse(mcpError, {
          toolName,
          correlationId,
          executionId: this.generateExecutionId(),
        });

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(errorResponse, null, 2),
            },
          ],
        };
      }
    };
  }

  /**
   * Get error statistics and health information
   */
  getErrorHealth(): {
    overallHealth: 'healthy' | 'degraded' | 'critical';
    statistics: ReturnType<typeof mcpErrorMetrics.getErrorStatistics>;
    activeAlerts: McpErrorAlert[];
    recommendations: string[];
  } {
    const statistics = mcpErrorMetrics.getErrorStatistics();
    const activeAlerts = mcpErrorMetrics.getActiveAlerts();

    // Determine overall health
    const criticalAlerts = activeAlerts.filter((alert) => alert.severity === 'critical').length;
    const highAlerts = activeAlerts.filter((alert) => alert.severity === 'high').length;

    let overallHealth: 'healthy' | 'degraded' | 'critical' = 'healthy';
    if (criticalAlerts > 0 || statistics.averageErrorRate > 0.2) {
      overallHealth = 'critical';
    } else if (highAlerts > 0 || statistics.averageErrorRate > 0.1) {
      overallHealth = 'degraded';
    }

    // Generate recommendations
    const recommendations: string[] = [];
    if (statistics.averageErrorRate > 0.1) {
      recommendations.push(
        'Error rate is above acceptable threshold - investigate recent deployments'
      );
    }
    if (statistics.activeCascades > 0) {
      recommendations.push('Error cascades detected - review system dependencies');
    }
    if (activeAlerts.length > 5) {
      recommendations.push('Multiple active alerts - consider reviewing system capacity');
    }

    return {
      overallHealth,
      statistics,
      activeAlerts,
      recommendations,
    };
  }

  /**
   * Setup event listeners for metrics collection
   */
  private setupMetricsListeners(): void {
    // Listen to error events
    mcpErrorMetrics.on('error:recorded', (data) => {
      if (this.config.enableRealTimeAlerting) {
        console.error(
          `[MCP-ERROR] ${data.toolName}: ${data.error.message} (${data.correlationId})`
        );
      }
    });

    // Listen to cascade events
    mcpErrorMetrics.on('cascade:detected', (cascade) => {
      if (this.config.enableRealTimeAlerting) {
        console.error(
          `[MCP-CASCADE] Detected: ${cascade.cascadeId} affecting ${cascade.affectedTools.length} tools`
        );
      }
    });

    // Listen to alert events
    mcpErrorMetrics.on('alert:created', (alert) => {
      if (this.config.enableRealTimeAlerting) {
        console.error(`[MCP-ALERT] ${alert.severity.toUpperCase()}: ${alert.message}`);
      }
    });
  }

  /**
   * Execute operation with timeout
   */
  private async executeWithTimeout<T>(
    operation: () => Promise<T>,
    timeoutMs: number,
    toolName: string,
    correlationId: string
  ): Promise<T> {
    if (timeoutMs <= 0) {
      return operation();
    }

    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(
          new McpToolTimeoutError(toolName, timeoutMs, {
            correlationId,
            executionId: this.generateExecutionId(),
          })
        );
      }, timeoutMs);
    });

    return Promise.race([operation(), timeoutPromise]);
  }

  /**
   * Validate a single field value
   */
  private validateFieldValue(
    fieldName: string,
    value: unknown,
    config: {
      type?: string;
      minLength?: number;
      maxLength?: number;
      pattern?: RegExp;
      enum?: unknown[];
      custom?: (value: unknown) => boolean | string;
    }
  ): string | null {
    // Type validation
    if (config.type) {
      const expectedType = config.type.toLowerCase();
      const actualType = typeof value;

      if (expectedType === 'string' && actualType !== 'string') {
        return `Field '${fieldName}' must be a string, got ${actualType}`;
      }
      if (expectedType === 'number' && actualType !== 'number') {
        return `Field '${fieldName}' must be a number, got ${actualType}`;
      }
      if (expectedType === 'boolean' && actualType !== 'boolean') {
        return `Field '${fieldName}' must be a boolean, got ${actualType}`;
      }
      if (expectedType === 'array' && !Array.isArray(value)) {
        return `Field '${fieldName}' must be an array, got ${actualType}`;
      }
      if (
        expectedType === 'object' &&
        (actualType !== 'object' || Array.isArray(value) || value === null)
      ) {
        return `Field '${fieldName}' must be an object, got ${actualType}`;
      }
    }

    // String-specific validations
    if (typeof value === 'string') {
      if (config.minLength !== undefined && value.length < config.minLength) {
        return `Field '${fieldName}' must be at least ${config.minLength} characters long`;
      }
      if (config.maxLength !== undefined && value.length > config.maxLength) {
        return `Field '${fieldName}' must be no more than ${config.maxLength} characters long`;
      }
      if (config.pattern && !config.pattern.test(value)) {
        return `Field '${fieldName}' does not match required pattern`;
      }
    }

    // Enum validation
    if (config.enum && !config.enum.includes(value)) {
      return `Field '${fieldName}' must be one of: ${config.enum.join(', ')}`;
    }

    // Custom validation
    if (config.custom) {
      const customResult = config.custom(value);
      if (customResult !== true) {
        return typeof customResult === 'string'
          ? customResult
          : `Field '${fieldName}' failed custom validation`;
      }
    }

    return null;
  }

  /**
   * Generate execution ID
   */
  private generateExecutionId(): string {
    return `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

// Default integration instance
export const defaultMcpErrorHandler = new McpErrorHandlerIntegration();

// Convenience functions for common patterns
export async function executeMcpTool<T = unknown>(
  toolName: string,
  operation: () => Promise<T>,
  options?: {
    args?: Record<string, unknown>;
    correlationId?: string;
    timeout?: number;
    userId?: string;
    sessionId?: string;
  }
): Promise<McpToolResult> {
  return defaultMcpErrorHandler.executeTool(toolName, operation, options);
}

export function validateMcpArguments(
  toolName: string,
  args: Record<string, unknown>,
  schema: Record<string, unknown>
): void {
  defaultMcpErrorHandler.validateArguments(toolName, args, schema);
}

export function createMcpToolWrapper<
  TArgs extends Record<string, unknown> = Record<string, unknown>,
  TResult = unknown,
>(
  toolName: string,
  handler: (args: TArgs, context: McpToolContext) => Promise<TResult>,
  options?: {
    schema?: Record<string, unknown>;
    timeout?: number;
    requireAuth?: boolean;
    rateLimit?: {
      windowMs: number;
      maxRequests: number;
    };
  }
) {
  return defaultMcpErrorHandler.createToolWrapper<TArgs, TResult>(toolName, handler, options);
}

export function getMcpErrorHealth() {
  return defaultMcpErrorHandler.getErrorHealth();
}
