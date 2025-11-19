// FINAL TRIUMPHANT VICTORY EMERGENCY ROLLBACK: Complete the great migration rescue

/**
 * Type Guard Utilities for Configuration and Schema Validation
 *
 * Provides comprehensive runtime type checking and validation utilities
 * to ensure type safety across the configuration and schema systems.
 * These utilities complement the base type guards with specialized
 * validation for configuration objects and schema structures.
 *
 * @version 2.0.0 - Type Safety Implementation
 */

import {
  isJSONArray,
  isJSONObject,
  isJSONPrimitive,
  type JSONValue,
} from '../types/index.js';

// ============================================================================
// Configuration Type Guards
// ============================================================================

/**
 * Type guard for Qdrant configuration objects
 */
export function isQdrantConfig(value: unknown): value is {
  host: string;
  port: number;
  apiKey?: string;
  timeout?: number;
  maxRetries?: number;
  collection?: string;
  vectorSize?: number;
  distance?: 'Cosine' | 'Euclidean' | 'Dot';
} {
  if (!isJSONObject(value)) {
    return false;
  }

  const obj = value as Record<string, unknown>;

  // Required fields
  if (typeof obj.host !== 'string' || typeof obj.port !== 'number') {
    return false;
  }

  // Optional fields with type checking
  if (obj.apiKey !== undefined && typeof obj.apiKey !== 'string') {
    return false;
  }

  if (obj.timeout !== undefined && typeof obj.timeout !== 'number') {
    return false;
  }

  if (obj.maxRetries !== undefined && typeof obj.maxRetries !== 'number') {
    return false;
  }

  if (obj.collection !== undefined && typeof obj.collection !== 'string') {
    return false;
  }

  if (obj.vectorSize !== undefined && typeof obj.vectorSize !== 'number') {
    return false;
  }

  if (
    obj.distance !== undefined &&
    !['Cosine', 'Euclidean', 'Dot'].includes(obj.distance as string)
  ) {
    return false;
  }

  return true;
}

/**
 * Type guard for database connection configurations
 */
export function isDatabaseConnectionConfig(value: unknown): value is {
  type: 'qdrant';
  config: {
    host: string;
    port: number;
    apiKey?: string;
    timeout?: number;
    maxRetries?: number;
    collection?: string;
    vectorSize?: number;
    distance?: 'Cosine' | 'Euclidean' | 'Dot';
  };
} {
  if (!isJSONObject(value)) {
    return false;
  }

  const obj = value as Record<string, unknown>;

  if (obj.type !== 'qdrant' || !isQdrantConfig(obj.config)) {
    return false;
  }

  return true;
}

/**
 * Type guard for filter rule values
 */
export function isFilterValue(
  value: unknown
): value is string | number | boolean | null | JSONValue {
  return isJSONPrimitive(value) || isJSONObject(value) || isJSONArray(value);
}

/**
 * Type guard for migration configuration objects
 */
export function isMigrationConfig(value: unknown): value is {
  mode: string;
  generateEmbeddings: 'always' | 'if-missing' | 'never';
  embeddingModel: string;
  batchSize: number;
  contentFields: string[];
  metadataFields: string[];
  filterRules: Array<{
    name: string;
    field: string;
    operator: string;
    value: string | number | boolean | null | JSONValue;
    negate?: boolean;
  }>;
  transformationRules: Array<{
    name: string;
    type: string;
    sourceField?: string;
    targetField?: string;
    transformation: string;
    parameters?: Record<string, unknown>;
  }>;
} {
  if (!isJSONObject(value)) {
    return false;
  }

  const obj = value as Record<string, unknown>;

  // Check required fields
  if (
    typeof obj.mode !== 'string' ||
    !['always', 'if-missing', 'never'].includes(obj.generateEmbeddings as string) ||
    typeof obj.embeddingModel !== 'string' ||
    typeof obj.batchSize !== 'number' ||
    !Array.isArray(obj.contentFields) ||
    !Array.isArray(obj.metadataFields) ||
    !Array.isArray(obj.filterRules) ||
    !Array.isArray(obj.transformationRules)
  ) {
    return false;
  }

  // Validate filter rules
  for (const rule of obj.filterRules) {
    if (!isFilterRule(rule)) {
      return false;
    }
  }

  // Validate transformation rules
  for (const rule of obj.transformationRules) {
    if (!isTransformationRule(rule)) {
      return false;
    }
  }

  return true;
}

/**
 * Type guard for filter rule objects
 */
export function isFilterRule(value: unknown): value is {
  name: string;
  field: string;
  operator: string;
  value: string | number | boolean | null | JSONValue;
  negate?: boolean;
} {
  if (!isJSONObject(value)) {
    return false;
  }

  const obj = value as Record<string, unknown>;

  return (
    typeof obj.name === 'string' &&
    typeof obj.field === 'string' &&
    typeof obj.operator === 'string' &&
    isFilterValue(obj.value) &&
    (obj.negate === undefined || typeof obj.negate === 'boolean')
  );
}

/**
 * Type guard for transformation rule objects
 */
export function isTransformationRule(value: unknown): value is {
  name: string;
  type: string;
  sourceField?: string;
  targetField?: string;
  transformation: string;
  parameters?: Record<string, unknown>;
} {
  if (!isJSONObject(value)) {
    return false;
  }

  const obj = value as Record<string, unknown>;

  return (
    typeof obj.name === 'string' &&
    typeof obj.type === 'string' &&
    typeof obj.transformation === 'string' &&
    (obj.sourceField === undefined || typeof obj.sourceField === 'string') &&
    (obj.targetField === undefined || typeof obj.targetField === 'string') &&
    (obj.parameters === undefined || isJSONObject(obj.parameters))
  );
}

// ============================================================================
// MCP Tool Input Type Guards
// ============================================================================

/**
 * Type guard for MCP tool input objects
 */
export function isMCPToolInput(value: unknown): value is {
  tool: string;
  parameters?: Record<string, JSONValue>;
  metadata?: Record<string, JSONValue>;
} {
  if (!isJSONObject(value)) {
    return false;
  }

  const obj = value as Record<string, unknown>;

  return (
    typeof obj.tool === 'string' &&
    (obj.parameters === undefined || isJSONObject(obj.parameters)) &&
    (obj.metadata === undefined || isJSONObject(obj.metadata))
  );
}

/**
 * Type guard for memory store input objects
 */
export function isMemoryStoreInput(value: unknown): value is {
  tool: 'memory_store';
  parameters: {
    items: Array<{
      kind: string;
      content: string;
      scope?: Record<string, string>;
      metadata?: Record<string, JSONValue>;
    }>;
  };
} {
  if (!isMCPToolInput(value) || value.tool !== 'memory_store') {
    return false;
  }

  const obj = value as Record<string, unknown>;

  if (!isJSONObject(obj.parameters) || !Array.isArray(obj.parameters.items)) {
    return false;
  }

  for (const item of obj.parameters.items) {
    if (
      !isJSONObject(item) ||
      typeof item.kind !== 'string' ||
      typeof item.content !== 'string' ||
      (item.scope !== undefined && !isJSONObject(item.scope)) ||
      (item.metadata !== undefined && !isJSONObject(item.metadata))
    ) {
      return false;
    }
  }

  return true;
}

/**
 * Type guard for memory find input objects
 */
export function isMemoryFindInput(value: unknown): value is {
  tool: 'memory_find';
  parameters: {
    query?: string;
    kind?: string;
    scope?: Record<string, string>;
    limit?: number;
    filters?: Record<string, JSONValue>;
  };
} {
  if (!isMCPToolInput(value) || value.tool !== 'memory_find') {
    return false;
  }

  const obj = value as Record<string, unknown>;

  if (!isJSONObject(obj.parameters)) {
    return false;
  }

  const params = obj.parameters as Record<string, unknown>;

  return (
    (params.query === undefined || typeof params.query === 'string') &&
    (params.kind === undefined || typeof params.kind === 'string') &&
    (params.scope === undefined || isJSONObject(params.scope)) &&
    (params.limit === undefined || typeof params.limit === 'number') &&
    (params.filters === undefined || isJSONObject(params.filters))
  );
}

// ============================================================================
// Validation Result Type Guards
// ============================================================================

/**
 * Type guard for validation error details
 */
export function isValidationErrorDetail(value: unknown): value is {
  code: string;
  message: string;
  field?: string;
  category: string;
  severity: string;
  suggestion?: string;
  context?: Record<string, JSONValue>;
} {
  if (!isJSONObject(value)) {
    return false;
  }

  const obj = value as Record<string, unknown>;

  return (
    typeof obj.code === 'string' &&
    typeof obj.message === 'string' &&
    (obj.field === undefined || typeof obj.field === 'string') &&
    typeof obj.category === 'string' &&
    typeof obj.severity === 'string' &&
    (obj.suggestion === undefined || typeof obj.suggestion === 'string') &&
    (obj.context === undefined || isJSONObject(obj.context))
  );
}

/**
 * Type guard for validation results
 */
export function isValidationResult(value: unknown): value is {
  valid: boolean;
  errors: Array<{
    code: string;
    message: string;
    field?: string;
    category: string;
    severity: string;
    suggestion?: string;
    context?: Record<string, JSONValue>;
  }>;
  warnings: Array<{
    code: string;
    message: string;
    field?: string;
    category: string;
    severity: string;
    suggestion?: string;
    context?: Record<string, JSONValue>;
  }>;
  data?: {
    data: JSONValue;
    validatedAt: string;
    schemaVersion: string;
  };
  metadata: {
    validationTimeMs: number;
    validatorVersion: string;
    schemaVersion: string;
    validationMode: string;
  };
} {
  if (!isJSONObject(value)) {
    return false;
  }

  const obj = value as Record<string, unknown>;

  return (
    typeof obj.valid === 'boolean' &&
    Array.isArray(obj.errors) &&
    obj.errors.every(isValidationErrorDetail) &&
    Array.isArray(obj.warnings) &&
    obj.warnings.every(isValidationErrorDetail) &&
    (obj.data === undefined || isJSONObject(obj.data)) &&
    isJSONObject(obj.metadata)
  );
}

// ============================================================================
// Runtime Validation Functions
// ============================================================================

/**
 * Runtime validator with detailed error reporting
 */
export function validateConfig<T>(
  value: unknown,
  typeGuard: (value: unknown) => value is T,
  context?: string
): { success: true; data: T } | { success: false; error: string } {
  try {
    if (typeGuard(value)) {
      return { success: true, data: value };
    }

    return {
      success: false,
      error: `Invalid configuration${context ? ` in ${context}` : ''}: type guard failed`,
    };
  } catch (error) {
    return {
      success: false,
      error: `Configuration validation error${context ? ` in ${context}` : ''}: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

/**
 * Safe configuration parsing with fallback
 */
export function safeParseConfig<T>(
  value: unknown,
  typeGuard: (value: unknown) => value is T,
  fallback: T,
  context?: string
): T {
  const result = validateConfig(value, typeGuard, context);
  return result.success ? result.data : fallback;
}

/**
 * Type assertion with runtime check
 */
export function assertType<T>(
  value: unknown,
  typeGuard: (value: unknown) => value is T,
  message?: string
): asserts value is T {
  if (!typeGuard(value)) {
    throw new TypeError(message || `Type assertion failed: value does not match expected type`);
  }
}

// ============================================================================
// Configuration Builders
// ============================================================================

/**
 * Type-safe configuration builder for Qdrant
 */
export class QdrantConfigBuilder {
  private config: Partial<{
    host: string;
    port: number;
    apiKey: string;
    timeout: number;
    maxRetries: number;
    collection: string;
    vectorSize: number;
    distance: 'Cosine' | 'Euclidean' | 'Dot';
  }> = {};

  withHost(host: string): this {
    this.config.host = host;
    return this;
  }

  withPort(port: number): this {
    this.config.port = port;
    return this;
  }

  withApiKey(apiKey: string): this {
    this.config.apiKey = apiKey;
    return this;
  }

  withTimeout(timeout: number): this {
    this.config.timeout = timeout;
    return this;
  }

  withMaxRetries(maxRetries: number): this {
    this.config.maxRetries = maxRetries;
    return this;
  }

  withCollection(collection: string): this {
    this.config.collection = collection;
    return this;
  }

  withVectorSize(vectorSize: number): this {
    this.config.vectorSize = vectorSize;
    return this;
  }

  withDistance(distance: 'Cosine' | 'Euclidean' | 'Dot'): this {
    this.config.distance = distance;
    return this;
  }

  build(): { host: string; port: number } & Partial<{
    apiKey: string;
    timeout: number;
    maxRetries: number;
    collection: string;
    vectorSize: number;
    distance: 'Cosine' | 'Euclidean' | 'Dot';
  }> {
    if (!this.config.host || !this.config.port) {
      throw new Error('QdrantConfig requires host and port');
    }

    return {
      host: this.config.host,
      port: this.config.port,
      ...this.config,
    };
  }
}

/**
 * Type-safe configuration merger
 */
export function mergeConfigs<T extends Record<string, unknown>>(base: T, ...configs: Partial<T>[]): T {
  return Object.assign({}, base, ...configs) as T;
}

/**
 * Deep configuration merger with type safety
 */
export function deepMergeConfigs<T extends Record<string, unknown>>(base: T, ...configs: Partial<T>[]): T {
  const result = { ...base } as Record<string, unknown>;

  for (const config of configs) {
    for (const [key, value] of Object.entries(config)) {
      if (value === undefined) continue;

      const mergedValue = result[key];
      const baseValue = base[key];

      if (
        mergedValue &&
        baseValue &&
        typeof mergedValue === 'object' &&
        typeof baseValue === 'object' &&
        !Array.isArray(mergedValue) &&
        !Array.isArray(baseValue) &&
        typeof value === 'object' &&
        value !== null &&
        !Array.isArray(value)
      ) {
        result[key] = deepMergeConfigs(
          baseValue as Record<string, unknown>,
          value as Record<string, unknown>
        );
      } else {
        result[key] = value;
      }
    }
  }

  return result as T;
}
