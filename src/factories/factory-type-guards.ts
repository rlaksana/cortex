// ULTIMATE FINAL EMERGENCY ROLLBACK: Remaining systematic type issues

/**
 * Comprehensive type guards for factory validation and runtime type checking
 * Provides robust type validation for all factory-related operations
 */

import type {
  DatabaseId,
  EnhancedLoggerConfig,
  EnhancedServerConfig,
  FactoryId,
  PerformanceConfig,
  SecurityConfig,
  ServerFeatures,
  ServiceId,
  ServiceLifetime,
  StoredItemKind,
  TypedFactory,
  ValidationResult,
} from './factory-types';

// Basic type guards
export function isString(value: unknown): value is string {
  return typeof value === 'string';
}

export function isNumber(value: unknown): value is number {
  return typeof value === 'number' && !isNaN(value);
}

export function isBoolean(value: unknown): value is boolean {
  return typeof value === 'boolean';
}

export function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function isArray(value: unknown): value is unknown[] {
  return Array.isArray(value);
}

export function isFunction(value: unknown): value is (...args: unknown[]) => unknown {
  return typeof value === 'function';
}

export function isSymbol(value: unknown): value is symbol {
  return typeof value === 'symbol';
}

// Branded type guards
export function isServiceId<T>(value: unknown): value is ServiceId<T> {
  return isString(value) && value.length > 0;
}

export function isFactoryId<T>(value: unknown): value is FactoryId<T> {
  return isString(value) && value.length > 0;
}

export function isDatabaseId<T>(value: unknown): value is DatabaseId<T> {
  return isString(value) && value.length > 0;
}

// Service lifetime validation
export function isServiceLifetime(value: unknown): value is ServiceLifetime {
  return isString(value) && ['singleton', 'scoped', 'transient'].includes(value);
}

// Stored item kind validation
export function isStoredItemKind(value: unknown): value is StoredItemKind {
  return (
    isString(value) &&
    [
      'entity',
      'relation',
      'observation',
      'section',
      'runbook',
      'change',
      'issue',
      'decision',
      'todo',
      'release_note',
      'ddl',
      'pr_context',
      'incident',
      'release',
      'risk',
      'assumption',
    ].includes(value)
  );
}

// Configuration validation guards
export function isEnhancedLoggerConfig(value: unknown): value is EnhancedLoggerConfig {
  if (!isObject(value)) return false;

  const config = value as Record<string, unknown>;

  return (
    isString(config.level) &&
    ['error', 'warn', 'info', 'debug'].includes(config.level) &&
    isBoolean(config.silent) &&
    (config.prefix === undefined || isString(config.prefix)) &&
    (config.structured === undefined || isBoolean(config.structured)) &&
    (config.metadata === undefined || isObject(config.metadata))
  );
}

export function isServerFeatures(value: unknown): value is ServerFeatures {
  if (!isObject(value)) return false;

  const features = value as Record<string, unknown>;

  return (
    isBoolean(features.vectorStorage) &&
    isBoolean(features.semanticSearch) &&
    isBoolean(features.memoryManagement) &&
    isBoolean(features.healthMonitoring) &&
    isBoolean(features.metrics) &&
    isBoolean(features.rateLimiting)
  );
}

export function isSecurityConfig(value: unknown): value is SecurityConfig {
  if (!isObject(value)) return false;

  const config = value as Record<string, unknown>;

  return (
    isBoolean(config.validateInputs) &&
    isBoolean(config.sanitizeOutputs) &&
    (config.allowedOrigins === undefined || isArray(config.allowedOrigins)) &&
    (config.maxRequestSize === undefined || isNumber(config.maxRequestSize)) &&
    (config.enableCORS === undefined || isBoolean(config.enableCORS))
  );
}

export function isPerformanceConfig(value: unknown): value is PerformanceConfig {
  if (!isObject(value)) return false;

  const config = value as Record<string, unknown>;

  return (
    isNumber(config.connectionTimeout) &&
    config.connectionTimeout > 0 &&
    isNumber(config.requestTimeout) &&
    config.requestTimeout > 0 &&
    isNumber(config.maxConcurrentRequests) &&
    config.maxConcurrentRequests > 0 &&
    isBoolean(config.enableCaching) &&
    (config.cacheTimeout === undefined || isNumber(config.cacheTimeout))
  );
}

export function isEnhancedServerConfig(value: unknown): value is EnhancedServerConfig {
  if (!isObject(value)) return false;

  const config = value as Record<string, unknown>;

  return (
    isString(config.name) &&
    config.name.trim().length > 0 &&
    isString(config.version) &&
    config.version.trim().length > 0 &&
    isEnhancedLoggerConfig(config.logger) &&
    isServerFeatures(config.features) &&
    isSecurityConfig(config.security) &&
    isPerformanceConfig(config.performance) &&
    (config.collectionName === undefined || isString(config.collectionName)) &&
    (config.qdrantUrl === undefined || isString(config.qdrantUrl)) &&
    (config.qdrantApiKey === undefined || isString(config.qdrantApiKey))
  );
}

// Factory validation guards
export function isTypedFactory<TInstance, TConfig>(
  value: unknown
): value is TypedFactory<TInstance, TConfig> {
  if (!isObject(value)) return false;

  const factory = value as Record<string, unknown>;

  return (
    factory.id !== undefined &&
    (isString(factory.id) || isFactoryId(factory.id)) &&
    isFunction(factory.create) &&
    (factory.validate === undefined || isFunction(factory.validate)) &&
    (factory.test === undefined || isFunction(factory.test)) &&
    (factory.dispose === undefined || isFunction(factory.dispose))
  );
}

// Service registration validation
export function isValidServiceToken(value: unknown): boolean {
  return isString(value) || isSymbol(value) || (isFunction(value) && Boolean(value.name));
}

export function isValidDependencyArray(value: unknown): boolean {
  if (!isArray(value)) return false;

  return value.every((dep) => isValidServiceToken(dep));
}

// Memory item validation
export function isScopeInfo(
  value: unknown
): value is { project?: string; branch?: string; org?: string } {
  if (!isObject(value)) return false;

  const scope = value as Record<string, unknown>;

  return (
    (scope.project === undefined || isString(scope.project)) &&
    (scope.branch === undefined || isString(scope.branch)) &&
    (scope.org === undefined || isString(scope.org))
  );
}

export function isTypedMemoryStoreItem(value: unknown): value is {
  kind: StoredItemKind;
  data: Record<string, unknown>;
  scope?: { project?: string; branch?: string; org?: string };
} {
  if (!isObject(value)) return false;

  const item = value as Record<string, unknown>;

  return (
    isStoredItemKind(item.kind) &&
    isObject(item.data) &&
    (item.scope === undefined || isScopeInfo(item.scope))
  );
}

// Memory find schema validation
export function isMemoryFindSchema(value: unknown): value is {
  query: string;
  scope?: { project?: string; branch?: string; org?: string };
  types?: StoredItemKind[];
  limit?: number;
} {
  if (!isObject(value)) return false;

  const schema = value as Record<string, unknown>;

  return (
    isString(schema.query) &&
    schema.query.trim().length > 0 &&
    (schema.scope === undefined || isScopeInfo(schema.scope)) &&
    (schema.types === undefined ||
      (isArray(schema.types) && schema.types.every(isStoredItemKind))) &&
    (schema.limit === undefined || (isNumber(schema.limit) && schema.limit > 0))
  );
}

// System status schema validation
export function isSystemStatusSchema(value: unknown): value is {
  operation?: 'cleanup' | 'health' | 'stats' | 'validate';
} {
  if (!isObject(value)) return false;

  const schema = value as Record<string, unknown>;

  return (
    schema.operation === undefined ||
    ['cleanup', 'health', 'stats', 'validate'].includes(schema.operation as string)
  );
}

// Validation result guard
export function isValidationResult(value: unknown): value is ValidationResult {
  if (!isObject(value)) return false;

  const result = value as Record<string, unknown>;

  return (
    isBoolean(result.valid) &&
    isArray(result.errors) &&
    result.errors.every(isString) &&
    (result.warnings === undefined || (isArray(result.warnings) && result.warnings.every(isString)))
  );
}

// Comprehensive validation functions
export function validateAndEnhanceServerConfig(
  config: unknown
): ValidationResult & { config?: EnhancedServerConfig } {
  if (!isEnhancedServerConfig(config)) {
    return {
      valid: false,
      errors: ['Invalid server configuration structure'],
      warnings: [],
    };
  }

  const errors: string[] = [];
  const warnings: string[] = [];

  // Validate name and version
  if (!config.name || config.name.trim().length === 0) {
    errors.push('Server name is required');
  }

  if (!config.version || config.version.trim().length === 0) {
    errors.push('Server version is required');
  }

  // Validate logger configuration
  if (!isEnhancedLoggerConfig(config.logger)) {
    errors.push('Invalid logger configuration');
  }

  // Validate performance configuration
  if (
    config.performance.connectionTimeout < 1000 ||
    config.performance.connectionTimeout > 300000
  ) {
    warnings.push('Connection timeout should be between 1000ms and 300000ms');
  }

  if (
    config.performance.maxConcurrentRequests < 1 ||
    config.performance.maxConcurrentRequests > 1000
  ) {
    warnings.push('Max concurrent requests should be between 1 and 1000');
  }

  // Validate security configuration
  if (config.security.maxRequestSize && config.security.maxRequestSize < 1024) {
    warnings.push('Max request size is very small, may cause issues with legitimate requests');
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    config,
  };
}

export function validateMemoryStoreItems(
  items: unknown[]
): ValidationResult & { items?: unknown[] } {
  const errors: string[] = [];
  const warnings: string[] = [];
  const validItems: unknown[] = [];

  if (!isArray(items)) {
    return {
      valid: false,
      errors: ['Items must be an array'],
      warnings: [],
    };
  }

  if (items.length > 100) {
    warnings.push('Large number of items provided, may impact performance');
  }

  for (let i = 0; i < items.length; i++) {
    const item = items[i];

    if (!isTypedMemoryStoreItem(item)) {
      errors.push(`Item at index ${i} is not a valid memory store item`);
      continue;
    }

    // Additional validation for item data
    if (Object.keys(item.data).length === 0) {
      warnings.push(`Item at index ${i} has empty data`);
    }

    if (JSON.stringify(item.data).length > 10000) {
      warnings.push(`Item at index ${i} has very large data, may impact performance`);
    }

    validItems.push(item);
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    items: validItems,
  };
}

export function validateFactoryRegistration<TInstance, TConfig>(
  factory: TypedFactory<TInstance, TConfig>
): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Validate factory structure
  if (!factory.id) {
    errors.push('Factory must have an id');
  }

  if (typeof factory.create !== 'function') {
    errors.push('Factory must have a create method');
  }

  // Optional validation method
  if (factory.validate && typeof factory.validate !== 'function') {
    warnings.push('Factory validate property should be a function');
  }

  // Optional test method (only for DatabaseFactory)
  if ('test' in factory && factory.test && typeof factory.test !== 'function') {
    warnings.push('Factory test property should be a function');
  }

  // Optional dispose method
  if (factory.dispose && typeof factory.dispose !== 'function') {
    warnings.push('Factory dispose property should be a function');
  }

  return { valid: errors.length === 0, errors, warnings };
}

// Runtime type checker with detailed error reporting
export class RuntimeTypeChecker {
  private static instance: RuntimeTypeChecker;
  private validationCache = new Map<string, ValidationResult>();

  static getInstance(): RuntimeTypeChecker {
    if (!RuntimeTypeChecker.instance) {
      RuntimeTypeChecker.instance = new RuntimeTypeChecker();
    }
    return RuntimeTypeChecker.instance;
  }

  validate<T>(
    value: unknown,
    validator: (value: unknown) => value is T,
    cacheKey?: string
  ): ValidationResult & { value?: T } {
    const key = cacheKey || `${validator.name}-${JSON.stringify(value)}`;

    if (this.validationCache.has(key)) {
      const cached = this.validationCache.get(key)!;
      return cached.valid && validator(value) ? { ...cached, value } : cached;
    }

    const isValid = validator(value);
    const result: ValidationResult & { value?: T } = {
      valid: isValid,
      errors: isValid ? [] : [`Type validation failed for ${validator.name}`],
      warnings: [],
      value: isValid ? value : undefined,
    };

    this.validationCache.set(key, {
      valid: result.valid,
      errors: result.errors,
      warnings: result.warnings,
    });

    return result;
  }

  clearCache(): void {
    this.validationCache.clear();
  }

  getCacheStats(): { size: number; hitRate: number } {
    // This would require tracking hits/misses in a real implementation
    return {
      size: this.validationCache.size,
      hitRate: 0, // Placeholder
    };
  }
}

// Convenience functions for common validations
export const validateServerConfig = (config: unknown) =>
  RuntimeTypeChecker.getInstance().validate(config, isEnhancedServerConfig, 'server-config');

export const validateLoggerConfig = (config: unknown) =>
  RuntimeTypeChecker.getInstance().validate(config, isEnhancedLoggerConfig, 'logger-config');

export const validateMemoryStoreItem = (item: unknown) =>
  RuntimeTypeChecker.getInstance().validate(item, isTypedMemoryStoreItem, 'memory-store-item');

export const validateMemoryFindSchema = (schema: unknown) =>
  RuntimeTypeChecker.getInstance().validate(schema, isMemoryFindSchema, 'memory-find-schema');

export const validateSystemStatusSchema = (schema: unknown) =>
  RuntimeTypeChecker.getInstance().validate(schema, isSystemStatusSchema, 'system-status-schema');

// Type assertion helpers with runtime validation
export function assertIsEnhancedServerConfig(
  value: unknown
): asserts value is EnhancedServerConfig {
  if (!isEnhancedServerConfig(value)) {
    throw new TypeError(`Expected EnhancedServerConfig, got ${typeof value}`);
  }
}

export function assertIsTypedFactory<TInstance, TConfig>(
  value: unknown
): asserts value is TypedFactory<TInstance, TConfig> {
  if (!isTypedFactory(value)) {
    throw new TypeError(`Expected TypedFactory, got ${typeof value}`);
  }
}

export function assertIsMemoryStoreItem(value: unknown): asserts value is {
  kind: StoredItemKind;
  data: Record<string, unknown>;
  scope?: { project?: string; branch?: string; org?: string };
} {
  if (!isTypedMemoryStoreItem(value)) {
    throw new TypeError(`Expected MemoryStoreItem, got ${typeof value}`);
  }
}

export function assertIsMemoryFindSchema(value: unknown): asserts value is {
  query: string;
  scope?: { project?: string; branch?: string; org?: string };
  types?: StoredItemKind[];
  limit?: number;
} {
  if (!isMemoryFindSchema(value)) {
    throw new TypeError(`Expected MemoryFindSchema, got ${typeof value}`);
  }
}
