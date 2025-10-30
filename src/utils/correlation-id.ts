/**
 * Correlation ID utility for request tracing
 *
 * Provides unique identifiers for tracking requests across the MCP server
 * and enables better debugging and monitoring capabilities.
 */

import { randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';

/**
 * Async storage context for correlation IDs
 * This allows correlation IDs to be automatically included in all logs
 * within the same async request context.
 */
const correlationContext = new AsyncLocalStorage<string>();

/**
 * Generate a new correlation ID
 *
 * @returns UUID v7-style correlation ID for request tracking
 */
export function generateCorrelationId(): string {
  return randomUUID();
}

/**
 * Get the current correlation ID from async context
 *
 * @returns Current correlation ID or undefined if not set
 */
export function getCorrelationId(): string | undefined {
  return correlationContext.getStore();
}

/**
 * Set correlation ID for the current async context
 *
 * @param correlationId - Correlation ID to set for this context
 * @returns The correlation ID that was set
 */
export function setCorrelationId(correlationId: string): string {
  correlationContext.enterWith(correlationId);
  return correlationId;
}

/**
 * Run a function within a correlation context
 *
 * @param correlationId - Correlation ID for this context
 * @param fn - Function to execute within the correlation context
 * @returns Result of the function execution
 */
export function withCorrelationId<T>(correlationId: string, fn: () => T): T {
  return correlationContext.run(correlationId, fn);
}

/**
 * Get or create a correlation ID for the current context
 *
 * @returns Existing correlation ID or generates a new one
 */
export function getOrCreateCorrelationId(): string {
  const existing = getCorrelationId();
  if (existing) {
    return existing;
  }

  const newId = generateCorrelationId();
  setCorrelationId(newId);
  return newId;
}

/**
 * Extract correlation ID from MCP request if available
 *
 * @param request - MCP request object
 * @returns Correlation ID from request metadata or undefined
 */
export function extractCorrelationIdFromRequest(request: any): string | undefined {
  // Try to get correlation ID from various request locations
  return (
    request?.params?.meta?.correlationId || request?.meta?.correlationId || request?.correlationId
  );
}
