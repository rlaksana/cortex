import { logger } from './mcp-logger.js';
import {
  generateCorrelationId,
  withCorrelationId,
  getOrCreateCorrelationId,
} from './correlation-id.js';

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

// Re-export the logger and correlation ID utilities
export { logger };
export {
  generateCorrelationId,
  setCorrelationId,
  withCorrelationId,
  getOrCreateCorrelationId,
  extractCorrelationIdFromRequest,
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
  return logger.child(context) as ReturnType<typeof logger.child>;
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
