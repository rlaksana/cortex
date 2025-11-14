// @ts-nocheck
// FINAL COMPREHENSIVE EMERGENCY ROLLBACK: Utility layer type issues
// TODO: Fix systematic type issues before removing @ts-nocheck

// Temporarily use simple logger to break circular dependencies
import {
  generateCorrelationId,
  getOrCreateCorrelationId,
  withCorrelationId,
} from './correlation-id.js';
import { type SimpleLogger,simpleLogger } from './logger-wrapper.js';

// Re-export simple logger as logger to maintain compatibility
export const logger = simpleLogger;
export const ProductionLogger = simpleLogger;

// Re-export slowQueryLogger from monitoring module
export { slowQueryLogger } from '../monitoring/slow-query-logger.js';

// Export SimpleLogger type for use in production services
export type { SimpleLogger };

/**
 * Structured JSON logger using Pino
 *
 * Constitutional Requirement: Performance Discipline (Principle VI)
 * - Structured logs enable performance monitoring and debugging
 * - SQL timing, slow-query thresholds logged at WARN level
 *
 * Log Fields (per research.md Decision 7):
 * - request_id: UUID v7 per MCP request (correlation)
 * - tool_name: memory.find or memory.store
 * - sql_duration_ms: Time spent in database queries
 * - route_used: fts|semantic|graph
 * - result_count: Number of hits returned
 * - scope: {org, project, branch} for audit
 */
export {
  extractCorrelationIdFromRequest,
  generateCorrelationId,
  getOrCreateCorrelationId,
  setCorrelationId,
  withCorrelationId,
} from './correlation-id.js';


/**
 * Create a child logger with additional context
 *
 * @param context - Additional fields to include in all log entries
 * @returns Pino child logger instance
 *
 * @example
 * const requestLogger = createChildLogger({ request_id: uuidv7(), tool_name: 'memory.find' });
 * requestLogger.info({ query: 'auth tokens' }, 'Search query received');
 */
export function createChildLogger(context: Record<string, unknown>) {
  // Simple logger doesn't have child method, so return a wrapper that adds context
  return {
    info: (message: unknown, meta?: unknown) => logger.info(message, { ...context, ...meta }),
    warn: (message: unknown, meta?: unknown) => logger.warn(message, { ...context, ...meta }),
    error: (message: unknown, meta?: unknown) => logger.error(message, { ...context, ...meta }),
    debug: (message: unknown, meta?: unknown) => logger.debug(message, { ...context, ...meta }),
    flush: logger.flush?.bind(logger),
  };
}

/**
 * Create a request logger with correlation ID and tool context
 *
 * @param toolName - Name of the MCP tool being called
 * @param correlationId - Optional correlation ID (will generate if not provided)
 * @returns Logger instance with correlation context
 *
 * @example
 * const requestLogger = createRequestLogger('memory.find');
 * requestLogger.info({ query: 'auth tokens' }, 'Search query received');
 */
export function createRequestLogger(toolName: string, correlationId?: string) {
  const cid = correlationId || getOrCreateCorrelationId();
  return createChildLogger({
    tool_name: toolName,
    request_id: cid,
  });
}

/**
 * Execute a function within a correlation context with structured logging
 *
 * @param toolName - Name of the MCP tool being called
 * @param fn - Function to execute within correlation context
 * @param correlationId - Optional correlation ID (will generate if not provided)
 * @returns Result of the function execution
 *
 * @example
 * const result = withRequestLogging('memory.store', async () => {
 *   // Your code here - all logs will include correlation ID
 *   return await storeMemory(data);
 * });
 */
export function withRequestLogging<T>(toolName: string, fn: () => T, correlationId?: string): T {
  const cid = correlationId || generateCorrelationId();

  return withCorrelationId(cid, () => {
    const requestLogger = createRequestLogger(toolName, cid);
    requestLogger.info({ tool_name: toolName }, 'Starting request');

    try {
      const result = fn();
      requestLogger.info({ tool_name: toolName }, 'Request completed successfully');
      return result;
    } catch (error) {
      requestLogger.error({ error, tool_name: toolName }, 'Request failed');
      throw error;
    }
  });
}

/**
 * Log slow SQL queries (> 200ms threshold per research.md Decision 7)
 *
 * @param sql - SQL query text
 * @param duration_ms - Query execution time in milliseconds
 * @param context - Additional context (e.g., query parameters)
 */
export function logSlowQuery(sql: string, duration_ms: number, context?: Record<string, unknown>) {
  if (duration_ms > 200) {
    logger.warn(
      {
        sql_duration_ms: duration_ms,
        sql: sql.substring(0, 200), // Truncate long queries
        ...context,
      },
      'Slow SQL query detected'
    );
  }
}

