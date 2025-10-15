import pino from 'pino';

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

export const logger = pino(
  {
    level: process.env.LOG_LEVEL || 'info',
    formatters: {
      level: (label) => ({ level: label }),
    },
    base: {
      service: 'cortex-mcp',
      environment: process.env.NODE_ENV || 'development',
    },
    timestamp: pino.stdTimeFunctions.isoTime,
    redact: {
      paths: ['*.idempotency_key', '*.actor'], // PII redaction
      remove: true,
    },
  },
  pino.destination(2)
); // Write to stderr (fd 2) for MCP stdio protocol compatibility

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
  return logger.child(context);
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
