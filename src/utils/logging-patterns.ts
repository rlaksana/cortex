/**
 * Logging Patterns Guide for Cortex Memory MCP
 *
 * This file provides standardized logging patterns and best practices
 * for consistent, structured logging across the entire codebase.
 */

import { createRequestLogger, logger as baseLogger } from '@/utils/logger.js';

/**
 * Log Level Guidelines
 *
 * DEBUG: Detailed information for debugging purposes
 * - Internal function execution details
 * - Variable states and values
 * - Development-only information
 * - Performance metrics for specific operations
 *
 * INFO: General information about system operation
 * - Application startup/shutdown
 * - Successful operations
 * - Configuration loaded
 * - User actions (non-sensitive)
 *
 * WARN: Warning conditions that don't prevent operation
 * - Deprecated API usage
 * - Performance degradation
 * - Configuration issues (with fallbacks)
 * - Retry attempts
 *
 * ERROR: Error conditions that affect operation
 * - Failed operations
 * - Authentication/authorization failures
 * - Database connection issues
 * - Invalid user input
 */

/**
 * Standard Log Patterns
 */

/**
 * Log a request start with correlation ID
 *
 * @param toolName - Name of the MCP tool
 * @param params - Request parameters (sanitized)
 * @returns Request logger with correlation context
 */
export function logRequestStart(toolName: string, params?: Record<string, any>) {
  const requestLogger = createRequestLogger(toolName);
  requestLogger.info(
    {
      tool_name: toolName,
      ...(params && { params: sanitizeLogParams(params) }),
    },
    `${toolName} request started`
  );
  return requestLogger;
}

/**
 * Log a successful request completion
 *
 * @param requestLogger - Request logger from logRequestStart
 * @param toolName - Name of the MCP tool
 * @param result - Operation result (summary)
 */
export function logRequestSuccess(
  requestLogger: typeof baseLogger,
  toolName: string,
  result?: any
) {
  requestLogger.info(
    {
      tool_name: toolName,
      ...(result && { result_summary: summarizeResult(result) }),
    },
    `${toolName} request completed successfully`
  );
}

/**
 * Log a request failure
 *
 * @param requestLogger - Request logger from logRequestStart
 * @param toolName - Name of the MCP tool
 * @param error - Error that occurred
 * @param context - Additional error context
 */
export function logRequestError(
  requestLogger: typeof baseLogger,
  toolName: string,
  error: Error | any,
  context?: Record<string, any>
) {
  requestLogger.error(
    {
      tool_name: toolName,
      error:
        error instanceof Error
          ? {
              name: error.name,
              message: error.message,
              stack: error.stack,
            }
          : error,
      ...context,
    },
    `${toolName} request failed`
  );
}

/**
 * Log database operations
 *
 * @param operation - Database operation type
 * @param table - Table name
 * @param duration_ms - Operation duration in milliseconds
 * @param recordCount - Number of records affected
 */
export function logDatabaseOperation(
  operation: string,
  table: string,
  duration_ms: number,
  recordCount?: number
) {
  const logData: any = {
    operation,
    table,
    sql_duration_ms: duration_ms,
  };

  if (recordCount !== undefined) {
    logData.record_count = recordCount;
  }

  if (duration_ms > 200) {
    // Slow query warning
    baseLogger.warn(logData, `Slow database operation: ${operation} on ${table}`);
  } else {
    baseLogger.debug(logData, `Database operation: ${operation} on ${table}`);
  }
}

/**
 * Log authentication events
 *
 * @param event - Authentication event type
 * @param userId - User ID (if available)
 * @param sessionId - Session ID (if available)
 * @param success - Whether authentication succeeded
 * @param reason - Reason for failure (if applicable)
 */
export function logAuthenticationEvent(
  event: 'login' | 'logout' | 'token_validation' | 'permission_check',
  userId?: string,
  sessionId?: string,
  success: boolean = true,
  reason?: string
) {
  const logData: any = {
    auth_event: event,
    success,
  };

  if (userId) logData.user_id = userId;
  if (sessionId) logData.session_id = sessionId;
  if (reason) logData.reason = reason;

  if (success) {
    baseLogger.info(logData, `Authentication event: ${event}`);
  } else {
    baseLogger.warn(logData, `Authentication failure: ${event}`);
  }
}

/**
 * Log business logic operations
 *
 * @param operation - Business operation description
 * @param entity_type - Type of entity being processed
 * @param entity_id - Entity identifier
 * @param action - Action performed
 * @param result - Operation result
 */
export function logBusinessOperation(
  operation: string,
  entity_type: string,
  entity_id?: string,
  action?: string,
  result?: 'success' | 'failure' | 'partial'
) {
  baseLogger.info(
    {
      business_operation: operation,
      entity_type,
      ...(entity_id && { entity_id }),
      ...(action && { action }),
      ...(result && { result }),
    },
    `Business operation: ${operation}`
  );
}

/**
 * Sanitize parameters for logging (remove sensitive data)
 *
 * @param params - Original parameters
 * @returns Sanitized parameters safe for logging
 */
function sanitizeLogParams(params: Record<string, any>): Record<string, any> {
  const sensitiveFields = [
    'password',
    'token',
    'key',
    'secret',
    'authorization',
    'api_key',
    'openai_api_key',
    'credentials',
  ];

  const sanitized: Record<string, any> = {};

  for (const [key, value] of Object.entries(params)) {
    if (sensitiveFields.some((field) => key.toLowerCase().includes(field))) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      // Recursively sanitize nested objects
      sanitized[key] = sanitizeLogParams(value);
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

/**
 * Summarize result for logging (avoid logging large payloads)
 *
 * @param result - Operation result
 * @returns Summary of the result
 */
function summarizeResult(result: any): any {
  if (Array.isArray(result)) {
    return { type: 'array', count: result.length };
  }

  if (typeof result === 'object' && result !== null) {
    const summary: any = { type: 'object' };

    // Include specific fields that are useful for logging
    const usefulFields = ['id', 'count', 'affected_rows', 'inserted_id', 'updated_count'];
    for (const field of usefulFields) {
      if (field in result) {
        summary[field] = result[field];
      }
    }

    // Check if this looks like a database result
    if ('rows' in result) {
      summary.row_count = result.rows?.length || 0;
    }

    return Object.keys(summary).length > 1 ? summary : { type: 'object' };
  }

  // For primitive types, just return the type
  return { type: typeof result };
}

/**
 * Performance logging helper
 *
 * @param operation - Operation being measured
 * @param startTime - Start time (Date.now() result)
 * @param context - Additional context
 */
export function logPerformance(
  operation: string,
  startTime: number,
  context?: Record<string, any>
) {
  const duration_ms = Date.now() - startTime;

  baseLogger.debug(
    {
      operation,
      duration_ms,
      ...context,
    },
    `Performance: ${operation} completed in ${duration_ms}ms`
  );

  if (duration_ms > 1000) {
    baseLogger.warn(
      {
        operation,
        duration_ms,
        ...context,
      },
      `Slow operation detected: ${operation} took ${duration_ms}ms`
    );
  }
}
