// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck


/**
 * Operation Types for Monitoring Services
 *
 * Shared enum to avoid circular dependencies between monitoring services
 */

export enum OperationType {
  MEMORY_STORE = 'memory_store',
  MEMORY_FIND = 'memory_find',
  EMBEDDING = 'embedding',
  SEARCH = 'search',
  VALIDATION = 'validation',
  AUDIT = 'audit',
  HEALTH_CHECK = 'health_check',
  BATCH_OPERATION = 'batch_operation',
  EXPORT = 'export',
  PURGE = 'purge',
  MAINTENANCE = 'maintenance',
  RATE_LIMIT = 'rate_limit',
  AUTH = 'auth',
  CHUNKING = 'chunking',
  DEDUPLICATION = 'deduplication',
  DATABASE_HEALTH = 'database_health',
  DATABASE_STATS = 'database_stats',
  AUTHENTICATION = 'authentication',
  SYSTEM = 'system',
  ERROR = 'error',
  KILL_SWITCH_TRIGGERED = 'kill_switch_triggered',
  KILL_SWITCH_DEACTIVATED = 'kill_switch_deactivated',
  KILL_SWITCH_RECOVERED = 'kill_switch_recovered',
}
