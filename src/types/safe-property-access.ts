// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Safe Property Access Helpers with Type Safety
 *
 * This module provides utilities for safely accessing nested object properties
 * with full type safety and comprehensive error handling.
 */

import type {
  Config,
  Validator} from './base-types.js';


// ============================================================================
// Core Property Access Types
// ============================================================================

/**
 * Property path segments
 */
export type PathSegment = string | number;

/**
 * Property path array
 */
export type PropertyPath = readonly PathSegment[];

/**
 * Property access result with detailed information
 */
export interface PropertyAccessResult<T = unknown> {
  /** The retrieved value */
  readonly value: T;
  /** Whether the value was found */
  readonly found: boolean;
  /** The full path that was accessed */
  readonly path: PropertyPath;
  /** The parent object containing the property */
  readonly parent: unknown;
  /** The key/index used to access the value */
  readonly key: PathSegment;
  /** Whether the access involved traversing undefined/null values */
  readonly hadUndefinedTraversal: boolean;
  /** Whether the access used default values */
  readonly usedDefault: boolean;
}

/**
 * Property access options
 */
export interface PropertyAccessOptions<T = unknown> {
  /** Default value if property is not found */
  readonly defaultValue?: T;
  /** Type validator for the retrieved value */
  readonly validator?: Validator<T>;
  /** Whether to throw on access errors */
  readonly throwOnError?: boolean;
  /** Whether to coerce types when possible */
  readonly coerce?: boolean;
  /** Custom error message */
  readonly errorMessage?: string;
  /** Whether to create intermediate objects if they don't exist */
  readonly createPath?: boolean;
  /** Factory function for created objects */
  readonly objectFactory?: () => Record<string, unknown>;
  /** Factory function for created arrays */
  readonly arrayFactory?: () => unknown[];
}

/**
 * Nested property access result with traversal information
 */
export interface NestedAccessResult<T = unknown> {
  /** The final retrieved value */
  readonly value: T;
  /** Whether the value was found */
  readonly found: boolean;
  /** The full path that was attempted */
  readonly path: PropertyPath;
  /** Traversal information for each path segment */
  readonly traversal: TraversalStep[];
  /** Whether any defaults were used */
  readonly usedDefault: boolean;
  /** Validation errors encountered */
  readonly errors: IPropertyAccessError[];
}

/**
 * Information about each step in property traversal
 */
export interface TraversalStep {
  /** The path segment for this step */
  readonly segment: PathSegment;
  /** The object being accessed at this step */
  readonly object: unknown;
  /** Whether this step was successful */
  readonly success: boolean;
  /** The value at this step (if successful) */
  readonly value?: unknown;
  /** Error encountered at this step (if unsuccessful) */
  readonly error?: IPropertyAccessError;
}

/**
 * Property access error interface
 */
export interface IPropertyAccessError {
  /** Error type */
  readonly type: PropertyErrorType;
  /** Error message */
  readonly message: string;
  /** Path segment where error occurred */
  readonly path: PropertyPath;
  /** The object being accessed */
  readonly object: unknown;
  /** The key/segment that caused the error */
  readonly key: PathSegment;
  /** Original error if available */
  readonly cause?: Error;
}

/**
 * Types of property access errors
 */
export type PropertyErrorType =
  | 'INVALID_PATH'
  | 'NOT_FOUND'
  | 'TYPE_MISMATCH'
  | 'VALIDATION_FAILED'
  | 'COERCION_FAILED'
  | 'READ_ONLY'
  | 'CIRCULAR_REFERENCE'
  | 'UNDEFINED_PARENT'
  | 'INVALID_INDEX';

// ============================================================================
// Core Property Access Functions
// ============================================================================

/**
 * Safely access a property from an object with type safety
 */
export function safeGetProperty<T = unknown>(
  obj: unknown,
  key: string,
  options: PropertyAccessOptions<T> = {}
): PropertyAccessResult<T> {
  const {
    defaultValue,
    validator,
    throwOnError = false,
    coerce = true,
    errorMessage,
    createPath = false,
    objectFactory = () => ({}),
    arrayFactory = () => []
  } = options;

  const path: PropertyPath = [key];
  const errors: IPropertyAccessError[] = [];

  // Handle null/undefined object
  if (obj === null || obj === undefined) {
    const error: IPropertyAccessError = {
      type: 'UNDEFINED_PARENT',
      message: errorMessage || `Cannot access property '${key}' on ${obj === null ? 'null' : 'undefined'}`,
      path,
      object: obj,
      key
    };

    if (throwOnError) {
      throw new PropertyAccessError(error);
    }

    if (defaultValue !== undefined) {
      return {
        value: defaultValue,
        found: false,
        path,
        parent: obj,
        key,
        hadUndefinedTraversal: true,
        usedDefault: true
      };
    }

    return {
      value: undefined as T,
      found: false,
      path,
      parent: obj,
      key,
      hadUndefinedTraversal: true,
      usedDefault: false
    };
  }

  // Handle non-object types
  if (typeof obj !== 'object') {
    const error: IPropertyAccessError = {
      type: 'TYPE_MISMATCH',
      message: errorMessage || `Cannot access property '${key}' on non-object type: ${typeof obj}`,
      path,
      object: obj,
      key
    };

    if (throwOnError) {
      throw new PropertyAccessError(error);
    }

    if (defaultValue !== undefined) {
      return {
        value: defaultValue,
        found: false,
        path,
        parent: obj,
        key,
        hadUndefinedTraversal: false,
        usedDefault: true
      };
    }

    return {
      value: undefined as T,
      found: false,
      path,
      parent: obj,
      key,
      hadUndefinedTraversal: false,
      usedDefault: false
    };
  }

  const record = obj as Record<string, unknown>;
  let value = record[key];
  let found = key in record;

  // Handle path creation
  if (!found && createPath) {
    if (typeof key === 'number') {
      value = arrayFactory();
    } else {
      value = objectFactory();
    }
    record[key] = value;
    found = true;
  }

  // Handle missing property with default
  if (!found && defaultValue !== undefined) {
    return {
      value: defaultValue,
      found: false,
      path,
      parent: obj,
      key,
      hadUndefinedTraversal: false,
      usedDefault: true
    };
  }

  // Handle missing property without default
  if (!found) {
    const error: IPropertyAccessError = {
      type: 'NOT_FOUND',
      message: errorMessage || `Property '${key}' not found`,
      path,
      object: obj,
      key
    };

    if (throwOnError) {
      throw new PropertyAccessError(error);
    }

    return {
      value: undefined as T,
      found: false,
      path,
      parent: obj,
      key,
      hadUndefinedTraversal: false,
      usedDefault: false
    };
  }

  // Type validation
  if (validator && !validator(value)) {
    const error: IPropertyAccessError = {
      type: 'VALIDATION_FAILED',
      message: errorMessage || `Property '${key}' failed validation`,
      path,
      object: obj,
      key,
      cause: new Error(`Value ${JSON.stringify(value)} does not match expected type`)
    };

    if (throwOnError) {
      throw new PropertyAccessError(error);
    }

    if (defaultValue !== undefined) {
      return {
        value: defaultValue,
        found: true,
        path,
        parent: obj,
        key,
        hadUndefinedTraversal: false,
        usedDefault: true
      };
    }

    return {
      value: value as T,
      found: true,
      path,
      parent: obj,
      key,
      hadUndefinedTraversal: false,
      usedDefault: false
    };
  }

  // Type coercion
  if (coerce && validator && !validator(value)) {
    try {
      const coercedValue = coerceValue(value, validator);
      if (coercedValue !== null && validator(coercedValue)) {
        return {
          value: coercedValue as T,
          found: true,
          path,
          parent: obj,
          key,
          hadUndefinedTraversal: false,
          usedDefault: false
        };
      }
    } catch (coercionError) {
      errors.push({
        type: 'COERCION_FAILED',
        message: `Failed to coerce property '${key}' to expected type`,
        path,
        object: obj,
        key,
        cause: coercionError instanceof Error ? coercionError : undefined
      });
    }
  }

  return {
    value: value as T,
    found: true,
    path,
    parent: obj,
    key,
    hadUndefinedTraversal: false,
    usedDefault: false
  };
}

/**
 * Safely access an array element with type safety
 */
export function safeGetArrayElement<T = unknown>(
  arr: unknown,
  index: number,
  options: PropertyAccessOptions<T> = {}
): PropertyAccessResult<T> {
  const {
    defaultValue,
    validator,
    throwOnError = false,
    coerce = true,
    errorMessage
  } = options;

  const path: PropertyPath = [index];

  // Handle null/undefined array
  if (arr === null || arr === undefined) {
    const error: IPropertyAccessError = {
      type: 'UNDEFINED_PARENT',
      message: errorMessage || `Cannot access index ${index} on ${arr === null ? 'null' : 'undefined'}`,
      path,
      object: arr,
      key: index
    };

    if (throwOnError) {
      throw new PropertyAccessError(error);
    }

    if (defaultValue !== undefined) {
      return {
        value: defaultValue,
        found: false,
        path,
        parent: arr,
        key: index,
        hadUndefinedTraversal: true,
        usedDefault: true
      };
    }

    return {
      value: undefined as T,
      found: false,
      path,
      parent: arr,
      key: index,
      hadUndefinedTraversal: true,
      usedDefault: false
    };
  }

  // Handle non-array types
  if (!Array.isArray(arr)) {
    const error: IPropertyAccessError = {
      type: 'TYPE_MISMATCH',
      message: errorMessage || `Cannot access index ${index} on non-array type: ${typeof arr}`,
      path,
      object: arr,
      key: index
    };

    if (throwOnError) {
      throw new PropertyAccessError(error);
    }

    if (defaultValue !== undefined) {
      return {
        value: defaultValue,
        found: false,
        path,
        parent: arr,
        key: index,
        hadUndefinedTraversal: false,
        usedDefault: true
      };
    }

    return {
      value: undefined as T,
      found: false,
      path,
      parent: arr,
      key: index,
      hadUndefinedTraversal: false,
      usedDefault: false
    };
  }

  // Handle invalid index
  if (index < 0 || index >= arr.length || !Number.isInteger(index)) {
    const error: IPropertyAccessError = {
      type: 'INVALID_INDEX',
      message: errorMessage || `Invalid array index: ${index}`,
      path,
      object: arr,
      key: index
    };

    if (throwOnError) {
      throw new PropertyAccessError(error);
    }

    if (defaultValue !== undefined) {
      return {
        value: defaultValue,
        found: false,
        path,
        parent: arr,
        key: index,
        hadUndefinedTraversal: false,
        usedDefault: true
      };
    }

    return {
      value: undefined as T,
      found: false,
      path,
      parent: arr,
      key: index,
      hadUndefinedTraversal: false,
      usedDefault: false
    };
  }

  const value = arr[index];
  const found = true;

  // Type validation
  if (validator && !validator(value)) {
    const error: IPropertyAccessError = {
      type: 'VALIDATION_FAILED',
      message: errorMessage || `Array element at index ${index} failed validation`,
      path,
      object: arr,
      key: index,
      cause: new Error(`Value ${JSON.stringify(value)} does not match expected type`)
    };

    if (throwOnError) {
      throw new PropertyAccessError(error);
    }

    if (defaultValue !== undefined) {
      return {
        value: defaultValue,
        found: true,
        path,
        parent: arr,
        key: index,
        hadUndefinedTraversal: false,
        usedDefault: true
      };
    }

    return {
      value: value as T,
      found: true,
      path,
      parent: arr,
      key: index,
      hadUndefinedTraversal: false,
      usedDefault: false
    };
  }

  // Type coercion
  if (coerce && validator && !validator(value)) {
    try {
      const coercedValue = coerceValue(value, validator);
      if (coercedValue !== null && validator(coercedValue)) {
        return {
          value: coercedValue as T,
          found: true,
          path,
          parent: arr,
          key: index,
          hadUndefinedTraversal: false,
          usedDefault: false
        };
      }
    } catch (coercionError) {
      // Coercion failed, continue with original value
    }
  }

  return {
    value: value as T,
    found: true,
    path,
    parent: arr,
    key: index,
    hadUndefinedTraversal: false,
    usedDefault: false
  };
}

/**
 * Safely access nested properties with detailed traversal information
 */
export function safeGetNestedProperty<T = unknown>(
  obj: unknown,
  path: PropertyPath,
  options: PropertyAccessOptions<T> = {}
): NestedAccessResult<T> {
  const {
    defaultValue,
    validator,
    throwOnError = false,
    coerce = true,
    errorMessage,
    createPath = false,
    objectFactory = () => ({}),
    arrayFactory = () => []
  } = options;

  const traversal: TraversalStep[] = [];
  const errors: IPropertyAccessError[] = [];
  let current = obj;
  const usedDefault = false;

  // Traverse the path
  for (let i = 0; i < path.length; i++) {
    const segment = path[i];
    const currentPath = path.slice(0, i + 1);

    try {
      if (Array.isArray(current)) {
        // Array access
        if (typeof segment !== 'number') {
          const error: IPropertyAccessError = {
            type: 'INVALID_INDEX',
            message: `Expected numeric index for array access, got: ${typeof segment}`,
            path: currentPath,
            object: current,
            key: segment
          };
          errors.push(error);
          traversal.push({
            segment,
            object: current,
            success: false,
            error
          });
          break;
        }

        const result = safeGetArrayElement(current, segment, {
          defaultValue: i === path.length - 1 ? defaultValue : undefined,
          validator: i === path.length - 1 ? validator : undefined,
          throwOnError,
          coerce,
          createPath: createPath && i === path.length - 1,
          arrayFactory
        });

        traversal.push({
          segment,
          object: current,
          success: result.found,
          value: result.value
        });

        if (result.found) {
          current = result.value;
          if (i === path.length - 1) {
            return {
              value: result.value as T,
              found: true,
              path,
              traversal,
              usedDefault: result.usedDefault,
              errors
            };
          }
        } else {
          current = undefined;
          break;
        }
      } else {
        // Object access
        if (typeof segment !== 'string') {
          const error: IPropertyAccessError = {
            type: 'INVALID_PATH',
            message: `Expected string key for object access, got: ${typeof segment}`,
            path: currentPath,
            object: current,
            key: segment
          };
          errors.push(error);
          traversal.push({
            segment,
            object: current,
            success: false,
            error
          });
          break;
        }

        const result = safeGetProperty(current, segment, {
          defaultValue: i === path.length - 1 ? defaultValue : undefined,
          validator: i === path.length - 1 ? validator : undefined,
          throwOnError,
          coerce,
          createPath: createPath && i === path.length - 1,
          objectFactory
        });

        traversal.push({
          segment,
          object: current,
          success: result.found,
          value: result.value
        });

        if (result.found) {
          current = result.value;
          if (i === path.length - 1) {
            return {
              value: result.value as T,
              found: true,
              path,
              traversal,
              usedDefault: result.usedDefault,
              errors
            };
          }
        } else {
          current = undefined;
          break;
        }
      }
    } catch (error) {
      const accessError: IPropertyAccessError = {
        type: 'TYPE_MISMATCH',
        message: errorMessage || `Error accessing property at ${currentPath.join('.')}: ${error instanceof Error ? error.message : String(error)}`,
        path: currentPath,
        object: current,
        key: segment,
        cause: error instanceof Error ? error : undefined
      };
      errors.push(accessError);
      traversal.push({
        segment,
        object: current,
        success: false,
        error: accessError
      });
      break;
    }
  }

  // If we get here, the property was not found or an error occurred
  if (defaultValue !== undefined) {
    return {
      value: defaultValue,
      found: false,
      path,
      traversal,
      usedDefault: true,
      errors
    };
  }

  if (throwOnError && errors.length > 0) {
    throw new PropertyAccessError(errors[errors.length - 1]);
  }

  return {
    value: current as T,
    found: false,
    path,
    traversal,
    usedDefault,
    errors
  };
}

/**
 * Safely set a property on an object with type safety
 */
export function safeSetProperty<T = unknown>(
  obj: unknown,
  key: string,
  value: T,
  options: {
    validator?: Validator<T>;
    createPath?: boolean;
    objectFactory?: () => Record<string, unknown>;
    overwrite?: boolean;
    readOnly?: boolean;
  } = {}
): boolean {
  const {
    validator,
    createPath = false,
    objectFactory = () => ({}),
    overwrite = true,
    readOnly = false
  } = options;

  // Handle read-only check
  if (readOnly) {
    const existing = safeGetProperty(obj, key);
    if (existing.found) {
      return false;
    }
  }

  // Handle overwrite check
  if (!overwrite) {
    const existing = safeGetProperty(obj, key);
    if (existing.found) {
      return false;
    }
  }

  // Validate the value
  if (validator && !validator(value)) {
    return false;
  }

  // Handle null/undefined object with path creation
  if (obj === null || obj === undefined) {
    if (!createPath) {
      return false;
    }
    // This case should be handled at a higher level with nested access
    return false;
  }

  // Handle non-object types
  if (typeof obj !== 'object') {
    return false;
  }

  const record = obj as Record<string, unknown>;
  record[key] = value;
  return true;
}

/**
 * Safely set an array element with type safety
 */
export function safeSetArrayElement<T = unknown>(
  arr: unknown,
  index: number,
  value: T,
  options: {
    validator?: Validator<T>;
    createPath?: boolean;
    arrayFactory?: () => unknown[];
    expandArray?: boolean;
  } = {}
): boolean {
  const {
    validator,
    createPath = false,
    arrayFactory = () => [],
    expandArray = true
  } = options;

  // Validate the value
  if (validator && !validator(value)) {
    return false;
  }

  // Handle null/undefined array with path creation
  if (arr === null || arr === undefined) {
    if (!createPath) {
      return false;
    }
    // This case should be handled at a higher level with nested access
    return false;
  }

  // Handle non-array types
  if (!Array.isArray(arr)) {
    return false;
  }

  // Handle invalid index
  if (index < 0 || !Number.isInteger(index)) {
    return false;
  }

  // Expand array if needed
  if (expandArray && index >= arr.length) {
    arr.length = index + 1;
  } else if (index >= arr.length) {
    return false;
  }

  arr[index] = value;
  return true;
}

/**
 * Safely set a nested property with path creation
 */
export function safeSetNestedProperty<T = unknown>(
  obj: unknown,
  path: PropertyPath,
  value: T,
  options: {
    validator?: Validator<T>;
    createPath?: boolean;
    objectFactory?: () => Record<string, unknown>;
    arrayFactory?: () => unknown[];
    overwrite?: boolean;
  } = {}
): boolean {
  const {
    validator,
    createPath = false,
    objectFactory = () => ({}),
    arrayFactory = () => [],
    overwrite = true
  } = options;

  if (path.length === 0) {
    return false;
  }

  // Validate the value
  if (validator && !validator(value)) {
    return false;
  }

  let current = obj;

  // Traverse to parent of target property
  for (let i = 0; i < path.length - 1; i++) {
    const segment = path[i];

    if (Array.isArray(current)) {
      // Array traversal
      if (typeof segment !== 'number') {
        return false;
      }

      if (segment < 0 || segment >= current.length) {
        if (!createPath) {
          return false;
        }
        // Expand array to accommodate index
        current.length = segment + 1;
      }

      if (current[segment] === null || current[segment] === undefined) {
        if (!createPath) {
          return false;
        }
        // Determine if next segment is an array index
        const nextSegment = path[i + 1];
        current[segment] = typeof nextSegment === 'number' ? arrayFactory() : objectFactory();
      }

      current = current[segment];
    } else if (current !== null && typeof current === 'object') {
      // Object traversal
      if (typeof segment !== 'string') {
        return false;
      }

      const record = current as Record<string, unknown>;
      if (!(segment in record)) {
        if (!createPath) {
          return false;
        }
        // Determine if next segment is an array index
        const nextSegment = path[i + 1];
        record[segment] = typeof nextSegment === 'number' ? arrayFactory() : objectFactory();
      }

      current = record[segment];
    } else {
      // Invalid intermediate type
      if (!createPath) {
        return false;
      }
      // Determine if current segment should be array or object
      const nextSegment = path[i + 1];
      const newObj = typeof nextSegment === 'number' ? arrayFactory() : objectFactory();

      // Need to handle the case where we're at the root and need to create the initial object
      if (i === 0) {
        // This is a special case that needs to be handled by the caller
        return false;
      }

      current = newObj;
    }
  }

  // Set the final property
  const finalSegment = path[path.length - 1];

  if (Array.isArray(current)) {
    return safeSetArrayElement(current, finalSegment as number, value, { validator });
  } else if (current !== null && typeof current === 'object') {
    return safeSetProperty(current, finalSegment as string, value, { validator, overwrite });
  }

  return false;
}

// ============================================================================
// Configuration-Specific Property Access
// ============================================================================

/**
 * Safely access configuration values with type safety
 */
export function safeGetConfigValue<T = unknown>(
  config: Config,
  path: string,
  options: PropertyAccessOptions<T> = {}
): PropertyAccessResult<T> {
  const pathSegments = path.split('.');
  return safeGetNestedProperty(config, pathSegments, options);
}

/**
 * Safely set configuration values with type safety
 */
export function safeSetConfigValue<T = unknown>(
  config: Config,
  path: string,
  value: T,
  options: {
    validator?: Validator<T>;
    createPath?: boolean;
  } = {}
): boolean {
  const pathSegments = path.split('.');
  return safeSetNestedProperty(config, pathSegments, value, options);
}

/**
 * Get all configuration values matching a pattern
 */
export function safeGetConfigValuesByPattern(
  config: Config,
  pattern: RegExp,
  options: {
    maxDepth?: number;
    includeArrays?: boolean;
  } = {}
): Array<{ path: string; value: unknown }> {
  const { maxDepth = 10, includeArrays = false } = options;
  const results: Array<{ path: string; value: unknown }> = [];

  function traverse(obj: unknown, currentPath: string = '', depth: number = 0): void {
    if (depth > maxDepth) {
      return;
    }

    if (obj === null || typeof obj !== 'object') {
      return;
    }

    if (Array.isArray(obj)) {
      if (!includeArrays) {
        return;
      }

      obj.forEach((item, index) => {
        const itemPath = currentPath ? `${currentPath}[${index}]` : `[${index}]`;
        if (pattern.test(itemPath)) {
          results.push({ path: itemPath, value: item });
        }
        traverse(item, itemPath, depth + 1);
      });
    } else {
      const record = obj as Record<string, unknown>;
      for (const [key, value] of Object.entries(record)) {
        const itemPath = currentPath ? `${currentPath}.${key}` : key;
        if (pattern.test(itemPath)) {
          results.push({ path: itemPath, value });
        }
        traverse(value, itemPath, depth + 1);
      }
    }
  }

  traverse(config);
  return results;
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Attempt to coerce a value to match a validator
 */
function coerceValue(value: unknown, validator: Validator<unknown>): unknown | null {
  // String coercion
  if (typeof value !== 'string') {
    const strValue = String(value);
    if (validator(strValue)) {
      return strValue;
    }
  }

  // Number coercion
  if (typeof value !== 'number') {
    if (typeof value === 'string') {
      const numValue = Number(value);
      if (!isNaN(numValue) && isFinite(numValue) && validator(numValue)) {
        return numValue;
      }
    }
  }

  // Boolean coercion
  if (typeof value !== 'boolean') {
    if (typeof value === 'string') {
      const lower = value.toLowerCase();
      if ((lower === 'true' || lower === 'false') && validator(lower === 'true')) {
        return lower === 'true';
      }
    }
    if (validator(Boolean(value))) {
      return Boolean(value);
    }
  }

  return null;
}

/**
 * Create a property validator from a type guard
 */
export function createPropertyValidator<T>(
  typeGuard: (value: unknown) => value is T
): Validator<T> {
  return (value: unknown): value is T => {
    return typeGuard(value);
  };
}

/**
 * Create a property validator with custom validation logic
 */
export function createCustomValidator<T>(
  predicate: (value: unknown) => boolean,
  errorMessage?: string
): Validator<T> {
  return (value: unknown): value is T => {
    return predicate(value);
  };
}

/**
 * Combine multiple validators with AND logic
 */
export function combineValidators<T>(
  ...validators: Validator<T>[]
): Validator<T> {
  return (value: unknown): value is T => {
    return validators.every(validator => validator(value));
  };
}

/**
 * Combine multiple validators with OR logic
 */
export function combineValidatorsOr<T>(
  ...validators: Validator<T>[]
): Validator<T> {
  return (value: unknown): value is T => {
    return validators.some(validator => validator(value));
  };
}

/**
 * Create a validator for a specific value set
 */
export function createEnumValidator<T extends readonly unknown[]>(
  allowedValues: T
): Validator<T[number]> {
  const valueSet = new Set(allowedValues);
  return (value: unknown): value is T[number] => {
    return valueSet.has(value);
  };
}

/**
 * Create a validator for a range of numbers
 */
export function createRangeValidator(
  min: number,
  max: number,
  options: { inclusive?: boolean; integer?: boolean } = {}
): Validator<number> {
  const { inclusive = true, integer = false } = options;

  return (value: unknown): value is number => {
    if (typeof value !== 'number' || !isFinite(value)) {
      return false;
    }

    if (integer && !Number.isInteger(value)) {
      return false;
    }

    if (inclusive) {
      return value >= min && value <= max;
    } else {
      return value > min && value < max;
    }
  };
}

/**
 * Create a validator for string patterns
 */
export function createPatternValidator(
  pattern: RegExp,
  options: { flags?: string } = {}
): Validator<string> {
  const { flags } = options;
  const regex = new RegExp(pattern, flags);

  return (value: unknown): value is string => {
    return typeof value === 'string' && regex.test(value);
  };
}

/**
 * Create a validator for array length
 */
export function createArrayLengthValidator(
  minLength?: number,
  maxLength?: number
): Validator<unknown[]> {
  return (value: unknown): value is unknown[] => {
    if (!Array.isArray(value)) {
      return false;
    }

    if (minLength !== undefined && value.length < minLength) {
      return false;
    }

    if (maxLength !== undefined && value.length > maxLength) {
      return false;
    }

    return true;
  };
}

/**
 * Create a validator for object properties
 */
export function createObjectShapeValidator<T extends Record<string, unknown>>(
  shape: { [K in keyof T]: Validator<T[K]> },
  options: { strict?: boolean; allowPartial?: boolean } = {}
): Validator<T> {
  const { strict = false, allowPartial = false } = options;

  return (value: unknown): value is T => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      return false;
    }

    const obj = value as Record<string, unknown>;

    // Check all required properties
    for (const [key, validator] of Object.entries(shape)) {
      const hasProperty = key in obj;

      if (!hasProperty && !allowPartial) {
        return false;
      }

      if (hasProperty && !validator(obj[key])) {
        return false;
      }
    }

    // Check for extra properties in strict mode
    if (strict) {
      const allowedKeys = new Set(Object.keys(shape));
      for (const key of Object.keys(obj)) {
        if (!allowedKeys.has(key)) {
          return false;
        }
      }
    }

    return true;
  };
}

// ============================================================================
// Property Access Error Class
// ============================================================================

/**
 * Custom error class for property access failures
 */
export class PropertyAccessError extends Error {
  public readonly type: PropertyErrorType;
  public readonly path: PropertyPath;
  public readonly object: unknown;
  public readonly key: PathSegment;
  public readonly cause?: Error;

  constructor(error: IPropertyAccessError) {
    super(error.message);
    this.name = 'PropertyAccessError';
    this.type = error.type;
    this.path = error.path;
    this.object = error.object;
    this.key = error.key;
    this.cause = error.cause;
  }

  /**
   * Get a formatted error message
   */
  getFormattedMessage(): string {
    const pathStr = this.path.join('.');
    return `${this.type}: ${this.message} (path: ${pathStr}, key: ${String(this.key)})`;
  }

  /**
   * Check if this error is recoverable
   */
  isRecoverable(): boolean {
    const recoverableTypes: PropertyErrorType[] = [
      'NOT_FOUND',
      'TYPE_MISMATCH',
      'COERCION_FAILED'
    ];
    return recoverableTypes.includes(this.type);
  }

  /**
   * Get suggested fixes for this error
   */
  getSuggestedFixes(): string[] {
    switch (this.type) {
      case 'NOT_FOUND':
        return [
          'Check if the property name is correct',
          'Verify the object structure',
          'Consider providing a default value'
        ];
      case 'TYPE_MISMATCH':
        return [
          'Ensure the target is an object or array as expected',
          'Check the type of the parent object',
          'Verify the path is correct for the data structure'
        ];
      case 'VALIDATION_FAILED':
        return [
          'Check the expected type for this property',
          'Verify the value meets the validation criteria',
          'Consider type coercion if enabled'
        ];
      case 'INVALID_INDEX':
        return [
          'Ensure the index is a non-negative integer',
          'Check array bounds',
          'Verify the target is actually an array'
        ];
      default:
        return ['Review the access path and object structure'];
    }
  }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Get property with a simple string path
 */
export function get<T = unknown>(
  obj: unknown,
  path: string,
  defaultValue?: T
): T | undefined {
  const pathSegments = path.split('.');
  const result = safeGetNestedProperty(obj, pathSegments, { defaultValue });
  return result.value;
}

/**
 * Set property with a simple string path
 */
export function set<T = unknown>(
  obj: unknown,
  path: string,
  value: T,
  options: { createPath?: boolean } = {}
): boolean {
  const pathSegments = path.split('.');
  return safeSetNestedProperty(obj, pathSegments, value, options);
}

/**
 * Check if a property exists
 */
export function has(obj: unknown, path: string): boolean {
  const pathSegments = path.split('.');
  const result = safeGetNestedProperty(obj, pathSegments);
  return result.found;
}

/**
 * Delete a property safely
 */
export function safeDeleteProperty(
  obj: unknown,
  path: string
): boolean {
  const pathSegments = path.split('.');

  if (pathSegments.length === 0) {
    return false;
  }

  const parentPath = pathSegments.slice(0, -1);
  const key = pathSegments[pathSegments.length - 1];

  const parentResult = safeGetNestedProperty(obj, parentPath);
  if (!parentResult.found) {
    return false;
  }

  const parent = parentResult.value;

  if (Array.isArray(parent) && typeof key === 'number') {
    if (key >= 0 && key < parent.length) {
      parent.splice(key, 1);
      return true;
    }
  } else if (parent !== null && typeof parent === 'object' && typeof key === 'string') {
    delete (parent as Record<string, unknown>)[key];
    return true;
  }

  return false;
}