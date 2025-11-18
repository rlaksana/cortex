// FINAL COMPREHENSIVE EMERGENCY ROLLBACK: Utility layer type issues

/**
 * Utils module index file
 * Centralized exports for all utility functions and services
 */

export {
  extractCorrelationIdFromRequest,
  generateCorrelationId,
  getOrCreateCorrelationId,
  setCorrelationId,
  withCorrelationId,
} from './correlation-id.js';
export { createChildLogger, logger } from './logger.js';

// Re-export other utilities as needed
export * from './error-handler.js';
export * from './performance-monitor.js';
export * from './security.js';

// Export specific functions to avoid conflicts
export {
  // Configuration validators (excluding duplicates)
  isDict,
  isValidPort,
  isValidTimeout,
  validateAndNormalizeConfig,
  validateConfig,
} from './configuration-validators.js';

// Export specific type guards (excluding duplicates)
export {
  isArray,
  isBoolean,
  isDate,
  isEmpty,
  isFunction,
  isNonNull,
  isNotNull,
  isNumber,
  isObject,
  isPlainObject,
  isPrimitive,
  isString,
  isSymbol,
  isUndefined,
  isValidEmail,
  isValidUrl,
  // Excluding isEnvironmentConfig and isQdrantConfig to avoid conflicts
} from './type-guards.js';
