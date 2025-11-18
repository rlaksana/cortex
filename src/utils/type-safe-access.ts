/**
 * Type-Safe Object Access Utilities
 *
 * Provides comprehensive type-safe utilities for working with unknown data
 * and replacing unsafe type assertions with proper type guards.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import {
  hasPropertySimple,
  hasPropertySimpleOfType,
  isObject,
  safePropertyAccess,
  safePropertyAccessEnhanced,
} from './type-guards.js';

// ============================================================================
// Safe Object Access Functions (Replacements for unsafe `obj` function)
// ============================================================================

/**
 * Type-safe object accessor - replacement for unsafe `obj` function
 * Provides safe fallback when object is not of expected type
 */
export function safeObjectAccess<T extends Record<string, unknown>>(
  value: unknown,
  defaultValue: T
): T {
  if (isObject(value)) {
    return value as T;
  }
  return defaultValue;
}

/**
 * Enhanced safe object accessor with property validation
 */
export function safeObjectAccessWithValidation<T extends Record<string, unknown>>(
  value: unknown,
  defaultValue: T,
  propertyValidators?: Partial<Record<keyof T, (val: unknown) => boolean>>
): T {
  if (!isObject(value)) {
    return defaultValue;
  }

  const obj = value as Record<string, unknown>;

  // If no validators provided, return casted object
  if (!propertyValidators) {
    return obj as T;
  }

  // Validate each property if validator exists
  for (const [key, validator] of Object.entries(propertyValidators)) {
    const propertyValue = obj[key];
    if (propertyValue !== undefined && !validator(propertyValue)) {
      // Property exists but fails validation, return default
      return defaultValue;
    }
  }

  return obj as T;
}

/**
 * Safe property accessor with array handling
 */
export function safeArrayPropertyAccess<T>(
  obj: unknown,
  property: string,
  itemGuard: (value: unknown) => value is T,
  defaultValue: T[] = []
): T[] {
  if (!hasPropertySimple(obj, property)) {
    return defaultValue;
  }

  const value = (obj as Record<string, unknown>)[property];
  if (!Array.isArray(value)) {
    return defaultValue;
  }

  return value.filter(itemGuard);
}

/**
 * Safe nested object access
 */
export function safeNestedObjectAccess(
  obj: unknown,
  path: string[],
  fallbackValue: Record<string, unknown> = {}
): Record<string, unknown> {
  let current: unknown = obj;

  for (const key of path) {
    if (!hasPropertySimple(current, key)) {
      return fallbackValue;
    }

    current = (current as Record<string, unknown>)[key];

    if (!isObject(current)) {
      return fallbackValue;
    }
  }

  return current as Record<string, unknown>;
}

// ============================================================================
// MCP-Specific Type Guards
// ============================================================================

/**
 * Type guard for event data objects
 */
export function isEventData(obj: unknown): obj is Record<string, unknown> {
  return isObject(obj);
}

/**
 * Type guard for memory find result data
 */
export function isMemoryFindResultData(obj: unknown): obj is {
  query: unknown;
  results?: unknown[];
  metadata?: Record<string, unknown>;
  searchTime?: number;
} {
  return (
    isObject(obj) &&
    hasPropertySimple(obj, 'query')
  );
}

/**
 * Type guard for memory store result data
 */
export function isMemoryStoreResultData(obj: unknown): obj is {
  stored_items?: unknown[];
  failed_items?: unknown[];
  summary?: Record<string, unknown>;
} {
  return (
    isObject(obj) &&
    (hasPropertySimple(obj, 'stored_items') || hasPropertySimple(obj, 'failed_items'))
  );
}

/**
 * Type guard for system status data
 */
export function isSystemStatusData(obj: unknown): obj is {
  status?: string;
  components?: Record<string, unknown>;
  metrics?: Record<string, unknown>;
  version?: Record<string, unknown>;
  capabilities?: Record<string, unknown>;
} {
  return (
    isObject(obj) &&
    hasPropertySimple(obj, 'status')
  );
}

/**
 * Type guard for performance metrics
 */
export function isPerformanceMetrics(obj: unknown): obj is {
  searchTime?: number;
  totalResults?: number;
  processingTime?: number;
  cacheHitRate?: number;
} {
  return isObject(obj);
}

/**
 * Type guard for results array
 */
export function isResultsArray(obj: unknown): obj is unknown[] {
  return Array.isArray(obj);
}

// ============================================================================
// Event Handler Type Guards
// ============================================================================

/**
 * Type guard for memory stored event data
 */
export function isMemoryStoredEventData(obj: unknown): obj is {
  items?: unknown[];
  summary?: Record<string, unknown>;
} {
  return (
    isObject(obj) &&
    hasPropertySimple(obj, 'items')
  );
}

/**
 * Type guard for memory found event data
 */
export function isMemoryFoundEventData(obj: unknown): obj is {
  query?: unknown;
  resultsCount?: number;
  result?: unknown;
} {
  return (
    isObject(obj) &&
    hasPropertySimple(obj, 'query')
  );
}

/**
 * Type guard for system status event data
 */
export function isSystemStatusEventData(obj: unknown): obj is {
  status?: unknown;
  health?: unknown;
  metrics?: unknown;
} {
  return (
    isObject(obj) &&
    hasPropertySimple(obj, 'status')
  );
}

// ============================================================================
// Safe Extraction Functions
// ============================================================================

/**
 * Safe extraction of event data with proper typing
 */
export function safeExtractEventData(event: unknown): Record<string, unknown> {
  return safeObjectAccess(event, {});
}

/**
 * Safe extraction of data property from event data
 */
export function safeExtractDataProperty(eventData: unknown): Record<string, unknown> {
  if (!hasPropertySimple(eventData, 'data')) {
    return {};
  }

  return safeObjectAccess((eventData as Record<string, unknown>).data, {});
}

/**
 * Safe extraction of items array from data object
 */
export function safeExtractItemsArray(dataObj: unknown): unknown[] {
  return safeArrayPropertyAccess(dataObj, 'items', (value: unknown): value is unknown => true, []);
}

/**
 * Safe extraction of results array from data object
 */
export function safeExtractResultsArray(dataObj: unknown): unknown[] {
  return safeArrayPropertyAccess(dataObj, 'results', (value: unknown): value is unknown => true, []);
}

/**
 * Safe extraction of search time from metadata
 */
export function safeExtractSearchTime(metadata: unknown): number {
  if (!hasPropertySimple(metadata, 'searchTime')) {
    return 0;
  }

  const searchTime = (metadata as Record<string, unknown>).searchTime;
  return typeof searchTime === 'number' && isFinite(searchTime) ? searchTime : 0;
}

/**
 * Safe extraction of results count
 */
export function safeExtractResultsCount(result: unknown): number {
  if (!hasPropertySimple(result, 'data')) {
    return 0;
  }

  const data = (result as Record<string, unknown>).data;
  if (!hasPropertySimple(data, 'results')) {
    return 0;
  }

  const results = (data as Record<string, unknown>).results;
  return Array.isArray(results) ? results.length : 0;
}

// ============================================================================
// Response Building Utilities
// ============================================================================

/**
 * Type-safe content block creation
 */
export function createTextContentBlock(text: string): { type: 'text'; text: string } {
  return {
    type: 'text' as const,
    text,
  };
}

/**
 * Type-safe MCP tool response creation
 */
export function createMcpToolResponse(content: string, isError = false): {
  content: { type: 'text'; text: string }[];
  isError?: boolean;
} {
  return {
    content: [createTextContentBlock(content)],
    isError,
  };
}

/**
 * Create success response with item count
 */
export function createItemCountResponse(count: number, searchTime = 0): {
  content: { type: 'text'; text: string }[];
  isError?: boolean;
} {
  const timeText = searchTime > 0 ? ` Search took ${searchTime}ms.` : '';
  return createMcpToolResponse(`Found ${count} matching items.${timeText}`);
}

// ============================================================================
// Validation Utilities
// ============================================================================

/**
 * Validate and extract search query from args
 */
export function validateAndExtractSearchQuery(args: unknown): string {
  if (!isObject(args)) {
    return '';
  }

  const query = (args as Record<string, unknown>).query;
  return typeof query === 'string' ? query : '';
}

/**
 * Validate and extract limit from args
 */
export function validateAndExtractLimit(args: unknown): number {
  if (!isObject(args)) {
    return 10; // default limit
  }

  const limit = (args as Record<string, unknown>).limit;
  return typeof limit === 'number' && limit > 0 ? limit : 10;
}

/**
 * Validate and extract types array from args
 */
export function validateAndExtractTypes(args: unknown): string[] {
  if (!isObject(args)) {
    return [];
  }

  const types = (args as Record<string, unknown>).types;
  if (!Array.isArray(types)) {
    return [];
  }

  return types.filter((type): type is string => typeof type === 'string');
}

// ============================================================================
// Error Handling Utilities
// ============================================================================

/**
 * Type-safe error extraction from unknown
 */
export function safeExtractError(error: unknown): { message: string; code?: string | number } {
  if (error instanceof Error) {
    return {
      message: error.message,
      code: (error as any).code,
    };
  }

  if (isObject(error) && hasPropertySimple(error, 'message')) {
    const message = (error as Record<string, unknown>).message;
    return {
      message: typeof message === 'string' ? message : String(error),
      code: (error as Record<string, unknown>).code as string | number | undefined,
    };
  }

  return {
    message: String(error),
  };
}

/**
 * Create error response with proper typing
 */
export function createErrorResponse(error: unknown): {
  content: { type: 'text'; text: string }[];
  isError: true;
} {
  const errorInfo = safeExtractError(error);
  return {
    content: [createTextContentBlock(`Error: ${errorInfo.message}`)],
    isError: true,
  };
}

// ============================================================================
// Compatibility Functions (Drop-in replacements for unsafe patterns)
// ============================================================================

/**
 * Drop-in replacement for the `obj` function with type safety
 * Usage: const safeData = safeObj(unknownData, defaultValue);
 */
export function safeObj<T extends Record<string, unknown>>(value: unknown, defaultValue: T): T {
  return safeObjectAccess(value, defaultValue);
}

/**
 * Enhanced version with optional validation
 * Usage: const safeData = safeObjWithValidation(data, default, { name: isString });
 */
export function safeObjWithValidation<T extends Record<string, unknown>>(
  value: unknown,
  defaultValue: T,
  validators?: Partial<Record<keyof T, (val: unknown) => boolean>>
): T {
  return safeObjectAccessWithValidation(value, defaultValue, validators);
}

/**
 * Array-specific safe object access
 * Usage: const safeItems = safeArrayObj(itemsArray, []);
 */
export function safeArrayObj<T>(value: unknown, defaultValue: T[]): T[] {
  return Array.isArray(value) ? value as T[] : defaultValue;
}

// ============================================================================
// Type Predicate Utilities
// ============================================================================

/**
 * Create a type predicate for object with specific property
 */
export function hasPropertyOfType<T>(
  propertyName: string,
  typeGuard: (value: unknown) => value is T
) {
  return (obj: unknown): obj is Record<string, T> => {
    return hasPropertySimpleOfType(obj, propertyName, typeGuard);
  };
}

/**
 * Create a type predicate for object with multiple properties
 */
export function hasProperties<T extends Record<string, unknown>>(
  propertyMap: Array<[string, (value: unknown) => boolean]>
) {
  return (obj: unknown): obj is T => {
    if (!isObject(obj)) {
      return false;
    }

    return propertyMap.every(([key, guard]) => {
      const value = (obj as Record<string, unknown>)[key];
      return guard(value);
    });
  };
}

// ============================================================================
// Enhanced Type Guards for Complex Data Structures
// ============================================================================

/**
 * Type guard for AuditEvent objects with enhanced property checking
 */
export function isAuditEvent(obj: unknown): obj is {
  id: string;
  userId: string;
  eventType: string;
  entityType: string;
  entityId: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
} {
  return (
    isObject(obj) &&
    hasPropertySimpleOfType(obj, 'id', CommonValidators.isString) &&
    hasPropertySimpleOfType(obj, 'userId', CommonValidators.isString) &&
    hasPropertySimpleOfType(obj, 'eventType', CommonValidators.isString) &&
    hasPropertySimpleOfType(obj, 'entityType', CommonValidators.isString) &&
    hasPropertySimpleOfType(obj, 'entityId', CommonValidators.isString) &&
    hasPropertySimpleOfType(obj, 'timestamp', CommonValidators.isString)
  );
}

/**
 * Type guard for User objects with snake_case properties
 */
export function isUserObject(obj: unknown): obj is {
  id: string;
  email?: string;
  username?: string;
  password_hash: string;
  role: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
} {
  return (
    isObject(obj) &&
    hasPropertySimpleOfType(obj, 'id', CommonValidators.isString) &&
    hasPropertySimpleOfType(obj, 'password_hash', CommonValidators.isString) &&
    hasPropertySimpleOfType(obj, 'role', CommonValidators.isString) &&
    hasPropertySimpleOfType(obj, 'is_active', CommonValidators.isBoolean) &&
    hasPropertySimpleOfType(obj, 'created_at', CommonValidators.isString) &&
    hasPropertySimpleOfType(obj, 'updated_at', CommonValidators.isString)
  );
}

/**
 * Type guard for ServiceMetadata objects
 */
export function isServiceMetadata(obj: unknown): obj is {
  vector_used?: boolean;
  degraded?: boolean;
  execution_time_ms?: number;
  confidence_score?: number;
  processingTimeMs?: number;
  execution_id?: string;
} {
  return isObject(obj);
}

/**
 * Type guard for MCP Server objects with tool registration
 */
export function isMcpServerWithTools(obj: unknown): obj is {
  registerTool: (name: string, handler: unknown) => void;
} {
  return (
    isObject(obj) &&
    hasPropertySimple(obj, 'registerTool') &&
    typeof (obj as Record<string, unknown>).registerTool === 'function'
  );
}

/**
 * Type guard for ConfigService objects
 */
export function isConfigService(obj: unknown): obj is {
  getSection: (key: string) => unknown;
  set: (key: string, value: unknown) => void;
  validate: () => boolean;
} {
  return (
    isObject(obj) &&
    hasPropertySimple(obj, 'getSection') &&
    hasPropertySimple(obj, 'set') &&
    hasPropertySimple(obj, 'validate') &&
    typeof (obj as Record<string, unknown>).getSection === 'function' &&
    typeof (obj as Record<string, unknown>).set === 'function' &&
    typeof (obj as Record<string, unknown>).validate === 'function'
  );
}

/**
 * Type guard for Disposable objects
 */
export function isDisposable(obj: unknown): obj is {
  dispose: () => void | Promise<void>;
} {
  return (
    isObject(obj) &&
    hasPropertySimple(obj, 'dispose') &&
    typeof (obj as Record<string, unknown>).dispose === 'function'
  );
}

/**
 * Alias for isObject for backward compatibility
 */
export function safeIsObject(obj: unknown): obj is Record<string, unknown> {
  return isObject(obj);
}

/**
 * Safely get a property from an unknown object with a default value
 */
export function safeGetProperty<T>(
  obj: unknown,
  key: string,
  defaultValue: T
): T {
  if (isObject(obj)) {
    const record = obj as Record<string, unknown>;
    return (record[key] as T) ?? defaultValue;
  }
  return defaultValue;
}

/**
 * Type guard for DI Container configuration objects
 */
export function isDIContainerConfig(obj: unknown): obj is {
  enableCircularDependencyDetection?: boolean;
  name?: string;
} {
  return isObject(obj);
}

/**
 * Type guard for validation objects with 'must' property
 */
export function isValidationObject(obj: unknown): obj is {
  must: (condition: unknown) => unknown;
} {
  return (
    isObject(obj) &&
    hasPropertySimple(obj, 'must') &&
    typeof (obj as Record<string, unknown>).must === 'function'
  );
}

/**
 * Type guard for ResponseEnvelope objects
 */
export function isResponseEnvelope(obj: unknown): obj is {
  result?: unknown;
  message?: string;
  onSuccess?: (handler: unknown) => unknown;
  onError?: (handler: unknown) => unknown;
  onPaginated?: (handler: unknown) => unknown;
} {
  return isObject(obj);
}

/**
 * Type guard for KnowledgeItem objects
 */
export function isKnowledgeItem(obj: unknown): obj is {
  id: string;
  kind: string;
  data: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
  expiry_at?: string;
} {
  return (
    isObject(obj) &&
    hasPropertySimpleOfType(obj, 'id', CommonValidators.isString) &&
    hasPropertySimpleOfType(obj, 'kind', CommonValidators.isString) &&
    hasPropertySimpleOfType(obj, 'data', CommonValidators.isObject)
  );
}

/**
 * Type guard for MemoryFindResponse objects
 */
export function isMemoryFindResponse(obj: unknown): obj is {
  results?: unknown[];
  items?: unknown[];
  total_count?: number;
  autonomous_context?: Record<string, unknown>;
  meta?: Record<string, unknown>;
  observability?: Record<string, unknown>;
} {
  return isObject(obj);
}

/**
 * Type guard for MemoryStoreResponse objects
 */
export function isMemoryStoreResponse(obj: unknown): obj is {
  items?: unknown[];
  summary?: Record<string, unknown>;
  stored?: unknown;
  errors?: unknown;
  autonomous_context?: Record<string, unknown>;
  observability?: Record<string, unknown>;
  meta?: Record<string, unknown>;
} {
  return isObject(obj);
}

// ============================================================================
// Enhanced Safe Extraction Functions
// ============================================================================

/**
 * Safe extraction of AuditEvent properties
 */
export function safeExtractAuditEventProperties(event: unknown): {
  id: string;
  action: string;
  userId: string;
  resource: string;
  timestamp: Date;
  metadata?: Record<string, unknown>;
  category: string;
} {
  if (!isAuditEvent(event)) {
    // Return default values if event is not valid
    return {
      id: '',
      action: 'unknown',
      userId: '',
      resource: '',
      timestamp: new Date(),
      category: 'unknown'
    };
  }

  return {
    id: event.id,
    action: event.eventType,
    userId: event.userId,
    resource: `${event.entityType}:${event.entityId}`,
    timestamp: new Date(event.timestamp),
    metadata: event.metadata,
    category: event.entityType
  };
}

/**
 * Safe extraction of User properties from camelCase to snake_case
 */
export function safeExtractUserProperties(user: unknown): {
  id: string;
  email?: string;
  username?: string;
  password_hash: string;
  role: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
} {
  const defaultUser: ReturnType<typeof safeExtractUserProperties> = {
    id: '',
    password_hash: '',
    role: '',
    is_active: false,
    created_at: '',
    updated_at: ''
  };

  if (!isObject(user)) {
    return defaultUser;
  }

  const userObj = user as Record<string, unknown>;

  // Handle both camelCase and snake_case property names
  return {
    id: hasPropertySimpleOfType(userObj, 'id', CommonValidators.isString) ? userObj.id : '',
    email: hasPropertySimpleOfType(userObj, 'email', CommonValidators.isString) ? userObj.email : undefined,
    username: hasPropertySimpleOfType(userObj, 'username', CommonValidators.isString) ? userObj.username : undefined,
    password_hash: hasPropertySimpleOfType(userObj, 'password_hash', CommonValidators.isString)
      ? userObj.password_hash
      : hasPropertySimpleOfType(userObj, 'password', CommonValidators.isString)
        ? userObj.password
        : '',
    role: hasPropertySimpleOfType(userObj, 'role', CommonValidators.isString)
      ? userObj.role
      : hasPropertySimpleOfType(userObj, 'roles', CommonValidators.isArray) && Array.isArray(userObj.roles)
        ? (userObj.roles as unknown[])[0] as string
        : '',
    is_active: hasPropertySimpleOfType(userObj, 'is_active', CommonValidators.isBoolean)
      ? userObj.is_active
      : hasPropertySimpleOfType(userObj, 'isActive', CommonValidators.isBoolean)
        ? userObj.isActive
        : false,
    created_at: hasPropertySimpleOfType(userObj, 'created_at', CommonValidators.isString)
      ? userObj.created_at
      : hasPropertySimpleOfType(userObj, 'createdAt', CommonValidators.isString)
        ? userObj.createdAt
        : new Date().toISOString(),
    updated_at: hasPropertySimpleOfType(userObj, 'updated_at', CommonValidators.isString)
      ? userObj.updated_at
      : hasPropertySimpleOfType(userObj, 'updatedAt', CommonValidators.isString)
        ? userObj.updated
        : new Date().toISOString()
  };
}

/**
 * Safe extraction of ServiceMetadata properties
 */
export function safeExtractServiceMetadata(metadata: unknown): {
  vector_used: boolean;
  degraded: boolean;
  execution_time_ms: number;
  confidence_score: number;
} {
  const defaultMeta = {
    vector_used: false,
    degraded: false,
    execution_time_ms: 0,
    confidence_score: 1.0
  };

  if (!isServiceMetadata(metadata)) {
    return defaultMeta;
  }

  return {
    vector_used: typeof metadata.vector_used === 'boolean' ? metadata.vector_used : defaultMeta.vector_used,
    degraded: typeof metadata.degraded === 'boolean' ? metadata.degraded : defaultMeta.degraded,
    execution_time_ms: typeof metadata.execution_time_ms === 'number' ? metadata.execution_time_ms : defaultMeta.execution_time_ms,
    confidence_score: typeof metadata.confidence_score === 'number' ? metadata.confidence_score : defaultMeta.confidence_score
  };
}

/**
 * Safe extraction of MCP tool arguments
 */
export function safeExtractMcpArgs(args: unknown): Record<string, unknown> {
  return safeObjectAccess(args, {});
}

/**
 * Safe extraction of error details from unknown objects
 */
export function safeExtractErrorDetails(error: unknown): {
  message: string;
  code?: string | number;
  stack?: string;
  details?: unknown;
  retryable?: boolean;
  retry_after_ms?: number;
} {
  const defaultError = {
    message: 'Unknown error occurred',
    code: undefined as string | number | undefined,
    stack: undefined as string | undefined,
    details: undefined as unknown,
    retryable: false,
    retry_after_ms: undefined as number | undefined
  };

  if (error instanceof Error) {
    return {
      message: error.message,
      code: (error as any).code,
      stack: error.stack,
      details: (error as any).details,
      retryable: (error as any).retryable || false,
      retry_after_ms: (error as any).retry_after_ms
    };
  }

  if (isObject(error)) {
    const errorObj = error as Record<string, unknown>;
    return {
      message: hasPropertySimpleOfType(errorObj, 'message', CommonValidators.isString)
        ? errorObj.message
        : String(error),
      code: errorObj.code as string | number | undefined,
      stack: hasPropertySimpleOfType(errorObj, 'stack', CommonValidators.isString)
        ? errorObj.stack
        : undefined,
      details: errorObj.details,
      retryable: typeof errorObj.retryable === 'boolean' ? errorObj.retryable : false,
      retry_after_ms: typeof errorObj.retry_after_ms === 'number' ? errorObj.retry_after_ms : undefined
    };
  }

  return defaultError;
}

/**
 * Safe extraction of response envelope properties
 */
export function safeExtractResponseEnvelope(response: unknown): {
  result?: unknown;
  message?: string;
  hasResult: boolean;
  hasMessage: boolean;
  hasErrorHandlers: boolean;
  hasPaginationHandlers: boolean;
} {
  const defaultEnvelope = {
    hasResult: false,
    hasMessage: false,
    hasErrorHandlers: false,
    hasPaginationHandlers: false
  };

  if (!isResponseEnvelope(response)) {
    return defaultEnvelope;
  }

  const responseObj = response as Record<string, unknown>;
  return {
    result: responseObj.result,
    message: responseObj.message,
    hasResult: responseObj.result !== undefined,
    hasMessage: typeof responseObj.message === 'string',
    hasErrorHandlers: typeof responseObj.onError === 'function',
    hasPaginationHandlers: typeof responseObj.onPaginated === 'function'
  };
}

/**
 * Safe conversion of unknown to string or number or Date for expiry
 */
export function safeExtractExpiryValue(value: unknown): string | number | Date {
  if (typeof value === 'string' || typeof value === 'number') {
    return value;
  }

  if (value instanceof Date) {
    return value;
  }

  if (isObject(value) && hasPropertySimple(value, 'toString')) {
    const strValue = (value as Record<string, unknown>).toString;
    if (typeof strValue === 'function') {
      try {
        return strValue.call(value);
      } catch {
        // Fall back to default
      }
    }
  }

  // Default to current date + 24 hours
  return new Date(Date.now() + 24 * 60 * 60 * 1000);
}

// ============================================================================
// Enhanced Type-safe Property Access Utilities
// ============================================================================

/**
 * Safe property access with fallback for complex nested objects
 */
export function safePropertyAccessWithFallback<T>(
  obj: unknown,
  propertyPath: string[],
  fallback: T,
  typeGuard?: (value: unknown) => value is T
): T {
  let current: unknown = obj;

  for (const property of propertyPath) {
    if (!hasPropertySimple(current, property)) {
      return fallback;
    }

    current = (current as Record<string, unknown>)[property];

    if (current === null || current === undefined) {
      return fallback;
    }
  }

  // If type guard provided, use it to validate the final value
  if (typeGuard) {
    return typeGuard(current) ? current : fallback;
  }

  // If no type guard but final value matches fallback type, use it
  return (current as T) || fallback;
}

/**
 * Batch property access for multiple properties with validation
 */
export function safeBatchPropertyAccess<T extends Record<string, unknown>>(
  obj: unknown,
  propertyMap: Partial<Record<keyof T, (value: unknown) => boolean>>,
  fallback: T
): T {
  if (!isObject(obj)) {
    return fallback;
  }

  const result: Record<string, unknown> = {};
  const objRecord = obj as Record<string, unknown>;

  for (const [property, validator] of Object.entries(propertyMap)) {
    const value = objRecord[property];
    if (value !== undefined && validator(value)) {
      result[property] = value;
    } else {
      result[property] = fallback[property as keyof T];
    }
  }

  return result as T;
}

// ============================================================================
// Export Common Use Cases
// ============================================================================

/**
 * Pre-configured validators for common use cases
 */
export const CommonValidators = {
  /** Validator for string properties */
  isString: (value: unknown): value is string => typeof value === 'string',

  /** Validator for number properties */
  isNumber: (value: unknown): value is number => typeof value === 'number' && !isNaN(value),

  /** Validator for boolean properties */
  isBoolean: (value: unknown): value is boolean => typeof value === 'boolean',

  /** Validator for array properties */
  isArray: (value: unknown): value is unknown[] => Array.isArray(value),

  /** Validator for object properties */
  isObject: (value: unknown): value is Record<string, unknown> => isObject(value),

  /** Validator for optional string properties */
  isOptionalString: (value: unknown): value is string | undefined =>
    value === undefined || typeof value === 'string',

  /** Validator for optional number properties */
  isOptionalNumber: (value: unknown): value is number | undefined =>
    value === undefined || (typeof value === 'number' && !isNaN(value)),
};

/**
 * Pre-configured default values for common object types
 */
export const DefaultValues = {
  /** Default empty object */
  emptyObject: {} as Record<string, unknown>,

  /** Default empty array */
  emptyArray: [] as unknown[],

  /** Default event data */
  eventData: {} as Record<string, unknown>,

  /** Default search result */
  searchResult: {
    query: '',
    results: [],
    metadata: {},
  } as Record<string, unknown>,

  /** Default system status */
  systemStatus: {
    status: 'unknown',
    components: {},
    metrics: {},
  } as Record<string, unknown>,
};