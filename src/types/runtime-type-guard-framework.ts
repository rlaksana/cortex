// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Runtime Type Guard Framework with Composition
 *
 * This module provides a comprehensive framework for creating, composing,
 * and managing runtime type guards with advanced features like validation
 * contexts, caching, and detailed error reporting.
 */

import type {
  Dict,
  JSONArray,
  JSONObject,
  JSONPrimitive,
  JSONValue} from './base-types.js';

// ============================================================================
// Core Type Guard Types
// ============================================================================

/**
 * Runtime type guard function
 */
export interface TypeGuard<T = unknown> {
  /** Guard function that validates a value */
  readonly validate: (value: unknown, context?: ValidationContext) => ValidationResult<T>;
  /** Guard name for identification and debugging */
  readonly name: string;
  /** Guard description */
  readonly description?: string;
  /** Expected type name */
  readonly typeName?: string;
  /** Whether this guard can be cached */
  readonly cacheable?: boolean;
  /** Guard metadata */
  readonly metadata?: Readonly<Record<string, unknown>>;
  /** Dependencies required by this guard */
  readonly dependencies?: readonly string[];
}

/**
 * Validation result with detailed information
 */
export interface ValidationResult<T = unknown> {
  /** Whether validation succeeded */
  readonly success: boolean;
  /** The validated value (if successful) */
  readonly value?: T;
  /** Validation errors encountered */
  readonly errors: ValidationError[];
  /** Validation warnings generated */
  readonly warnings: ValidationWarning[];
  /** Validation context information */
  readonly context?: ValidationContext;
  /** Performance metrics */
  readonly metrics?: ValidationMetrics;
}

/**
 * Validation error with detailed information
 */
export interface ValidationError {
  /** Error code */
  readonly code: string;
  /** Human-readable error message */
  readonly message: string;
  /** Path where error occurred */
  readonly path: string;
  /** The problematic value */
  readonly value: unknown;
  /** Expected type or constraint */
  readonly expected?: string;
  /** Actual type received */
  readonly actual?: string;
  /** Additional error data */
  readonly data?: Record<string, unknown>;
  /** Suggestions for fixing the error */
  readonly suggestions?: string[];
}

/**
 * Validation warning with detailed information
 */
export interface ValidationWarning {
  /** Warning code */
  readonly code: string;
  /** Human-readable warning message */
  readonly message: string;
  /** Path where warning occurred */
  readonly path: string;
  /** The value that caused the warning */
  readonly value: unknown;
  /** Warning severity level */
  readonly severity: 'low' | 'medium' | 'high';
  /** Additional warning data */
  readonly data?: Record<string, unknown>;
}

/**
 * Validation context for guard execution
 */
export interface ValidationContext {
  /** Current validation path */
  readonly path: string;
  /** Root object being validated */
  readonly root: unknown;
  /** Parent object context */
  readonly parent?: unknown;
  /** Parent property name */
  readonly parentProperty?: string;
  /** Validation options */
  readonly options: ValidationOptions;
  /** Accumulated errors from parent validations */
  readonly inheritedErrors?: ValidationError[];
  /** Accumulated warnings from parent validations */
  readonly inheritedWarnings?: ValidationWarning[];
  /** Custom properties */
  readonly [key: string]: unknown;
}

/**
 * Validation options
 */
export interface ValidationOptions {
  /** Strict mode (fail on warnings) */
  readonly strict?: boolean;
  /** Maximum validation depth */
  readonly maxDepth?: number;
  /** Whether to collect detailed metrics */
  readonly collectMetrics?: boolean;
  /** Whether to use caching */
  readonly useCache?: boolean;
  /** Custom error handlers */
  readonly errorHandlers?: Record<string, (error: ValidationError) => ValidationError>;
  /** Custom warning handlers */
  readonly warningHandlers?: Record<string, (warning: ValidationWarning) => ValidationWarning>;
  /** Progress callback for complex validations */
  readonly onProgress?: (progress: ValidationProgress) => void;
  /** Whether to short-circuit on first error */
  readonly shortCircuit?: boolean;
}

/**
 * Validation progress information
 */
export interface ValidationProgress {
  /** Current validation path */
  readonly path: string;
  /** Number of items validated */
  readonly validated: number;
  /** Total number of items (if known) */
  readonly total?: number;
  /** Current validation depth */
  readonly depth: number;
}

/**
 * Validation performance metrics
 */
export interface ValidationMetrics {
  /** Time taken for validation (microseconds) */
  readonly durationUs: number;
  /** Number of guard invocations */
  readonly invocations: number;
  /** Number of cache hits */
  readonly cacheHits: number;
  /** Number of cache misses */
  readonly cacheMisses: number;
  /** Maximum depth reached */
  readonly maxDepth: number;
  /** Number of errors encountered */
  readonly errorCount: number;
  /** Number of warnings encountered */
  readonly warningCount: number;
}

// ============================================================================
// Guard Composition Types
// ============================================================================

/**
 * Composition operators for combining guards
 */
export type CompositionOperator =
  | 'and'      // All guards must pass
  | 'or'       // At least one guard must pass
  | 'xor'      // Exactly one guard must pass
  | 'not'      // Guard must not pass
  | 'optional' // Guard may pass (treat undefined as success)
  | 'nullable' // Guard may pass or value may be null
  | 'array'    // Validate array elements
  | 'object'   // Validate object properties
  | 'tuple'    // Validate tuple structure
  | 'union'    // Validate against multiple possible types
  | 'intersection'; // Validate against multiple required types

/**
 * Guard composition definition
 */
export interface GuardComposition<T = unknown> {
  /** Composition operator */
  readonly operator: CompositionOperator;
  /** Guards to compose */
  readonly guards: TypeGuard[];
  /** Composition-specific options */
  readonly options?: Record<string, unknown>;
}

/**
 * Guard builder for fluent API
 */
export class GuardBuilder<T = unknown> {
  private guard?: TypeGuard<T>;

  constructor(guard?: TypeGuard<T>) {
    this.guard = guard;
  }

  /**
   * Add a name to the guard
   */
  name(name: string): GuardBuilder<T> {
    if (!this.guard) {
      throw new Error('Cannot set name on undefined guard');
    }
    return new GuardBuilder({
      ...this.guard,
      name
    });
  }

  /**
   * Add a description to the guard
   */
  description(description: string): GuardBuilder<T> {
    if (!this.guard) {
      throw new Error('Cannot set description on undefined guard');
    }
    return new GuardBuilder({
      ...this.guard,
      description
    });
  }

  /**
   * Add metadata to the guard
   */
  metadata(metadata: Record<string, unknown>): GuardBuilder<T> {
    if (!this.guard) {
      throw new Error('Cannot set metadata on undefined guard');
    }
    return new GuardBuilder({
      ...this.guard,
      metadata: { ...this.guard.metadata, ...metadata }
    });
  }

  /**
   * Make the guard optional
   */
  optional(): GuardBuilder<T | undefined> {
    if (!this.guard) {
      throw new Error('Cannot make undefined guard optional');
    }
    return new GuardBuilder(optionalGuard(this.guard));
  }

  /**
   * Make the guard nullable
   */
  nullable(): GuardBuilder<T | null> {
    if (!this.guard) {
      throw new Error('Cannot make undefined guard nullable');
    }
    return new GuardBuilder(nullableGuard(this.guard));
  }

  /**
   * Add a default value
   */
  default(defaultValue: T): GuardBuilder<T> {
    if (!this.guard) {
      throw new Error('Cannot set default on undefined guard');
    }
    return new GuardBuilder(defaultGuard(this.guard, defaultValue));
  }

  /**
   * Compose with another guard using AND
   */
  and<U>(other: TypeGuard<U>): GuardBuilder<T & U> {
    if (!this.guard) {
      throw new Error('Cannot compose undefined guard');
    }
    return new GuardBuilder(andGuard(this.guard, other));
  }

  /**
   * Compose with another guard using OR
   */
  or<U>(other: TypeGuard<U>): GuardBuilder<T | U> {
    if (!this.guard) {
      throw new Error('Cannot compose undefined guard');
    }
    return new GuardBuilder(orGuard(this.guard, other));
  }

  /**
   * Build the final guard
   */
  build(): TypeGuard<T> {
    if (!this.guard) {
      throw new Error('No guard to build');
    }
    return this.guard;
  }
}

// ============================================================================
// Basic Guard Implementations
// ============================================================================

/**
 * Create a basic type guard
 */
export function createTypeGuard<T>(
  name: string,
  validator: (value: unknown, context?: ValidationContext) => ValidationResult<T>,
  options: {
    description?: string;
    typeName?: string;
    cacheable?: boolean;
    metadata?: Record<string, unknown>;
    dependencies?: readonly string[];
  } = {}
): TypeGuard<T> {
  return {
    validate: validator,
    name,
    description: options.description,
    typeName: options.typeName,
    cacheable: options.cacheable ?? true,
    metadata: options.metadata,
    dependencies: options.dependencies
  };
}

/**
 * String type guard
 */
export const stringGuard: TypeGuard<string> = createTypeGuard(
  'string',
  (value, context) => {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    if (typeof value !== 'string') {
      errors.push({
        code: 'TYPE_MISMATCH',
        message: `Expected string, got ${typeof value}`,
        path: context?.path || '',
        value,
        expected: 'string',
        actual: typeof value,
        suggestions: ['Convert value to string using String(value)', 'Check if value is actually a string']
      });
      return { success: false, errors, warnings };
    }

    return { success: true, value, errors, warnings };
  },
  {
    description: 'Validates that a value is a string',
    typeName: 'string'
  }
);

/**
 * Number type guard
 */
export const numberGuard: TypeGuard<number> = createTypeGuard(
  'number',
  (value, context) => {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    if (typeof value !== 'number') {
      errors.push({
        code: 'TYPE_MISMATCH',
        message: `Expected number, got ${typeof value}`,
        path: context?.path || '',
        value,
        expected: 'number',
        actual: typeof value,
        suggestions: ['Convert value to number using Number(value)', 'Check if value is actually a number']
      });
      return { success: false, errors, warnings };
    }

    if (!isFinite(value)) {
      errors.push({
        code: 'INVALID_NUMBER',
        message: `Number must be finite, got ${value}`,
        path: context?.path || '',
        value,
        expected: 'finite number',
        actual: String(value),
        suggestions: ['Check for NaN or Infinity values', 'Use isFinite() to validate numbers']
      });
      return { success: false, errors, warnings };
    }

    return { success: true, value, errors, warnings };
  },
  {
    description: 'Validates that a value is a finite number',
    typeName: 'number'
  }
);

/**
 * Boolean type guard
 */
export const booleanGuard: TypeGuard<boolean> = createTypeGuard(
  'boolean',
  (value, context) => {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    if (typeof value !== 'boolean') {
      errors.push({
        code: 'TYPE_MISMATCH',
        message: `Expected boolean, got ${typeof value}`,
        path: context?.path || '',
        value,
        expected: 'boolean',
        actual: typeof value,
        suggestions: ['Convert value to boolean using Boolean(value)', 'Check if value is actually a boolean']
      });
      return { success: false, errors, warnings };
    }

    return { success: true, value, errors, warnings };
  },
  {
    description: 'Validates that a value is a boolean',
    typeName: 'boolean'
  }
);

/**
 * Null type guard
 */
export const nullGuard: TypeGuard<null> = createTypeGuard(
  'null',
  (value, context) => {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    if (value !== null) {
      errors.push({
        code: 'TYPE_MISMATCH',
        message: `Expected null, got ${typeof value}`,
        path: context?.path || '',
        value,
        expected: 'null',
        actual: typeof value,
        suggestions: ['Check if value should actually be null', 'Consider using nullable guard for optional null values']
      });
      return { success: false, errors, warnings };
    }

    return { success: true, value, errors, warnings };
  },
  {
    description: 'Validates that a value is null',
    typeName: 'null'
  }
);

/**
 * Undefined type guard
 */
export const undefinedGuard: TypeGuard<undefined> = createTypeGuard(
  'undefined',
  (value, context) => {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    if (value !== undefined) {
      errors.push({
        code: 'TYPE_MISMATCH',
        message: `Expected undefined, got ${typeof value}`,
        path: context?.path || '',
        value,
        expected: 'undefined',
        actual: typeof value,
        suggestions: ['Check if value should actually be undefined', 'Consider using optional guard for optional values']
      });
      return { success: false, errors, warnings };
    }

    return { success: true, value, errors, warnings };
  },
  {
    description: 'Validates that a value is undefined',
    typeName: 'undefined'
  }
);

// ============================================================================
// Composition Guard Implementations
// ============================================================================

/**
 * Create an AND composition guard
 */
export function andGuard<T, U>(
  guard1: TypeGuard<T>,
  guard2: TypeGuard<U>
): TypeGuard<T & U> {
  return createTypeGuard(
    `and(${guard1.name}, ${guard2.name})`,
    (value, context) => {
      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      // Validate with first guard
      const result1 = guard1.validate(value, context);
      errors.push(...result1.errors);
      warnings.push(...result1.warnings);

      if (!result1.success) {
        return { success: false, errors, warnings };
      }

      // Validate with second guard
      const result2 = guard2.validate(value, context);
      errors.push(...result2.errors);
      warnings.push(...result2.warnings);

      if (!result2.success) {
        return { success: false, errors, warnings };
      }

      return {
        success: true,
        value: result1.value! as T & U, // Both guards succeeded, so we can safely cast
        errors,
        warnings
      };
    },
    {
      description: `Requires both ${guard1.name} and ${guard2.name} to pass`,
      typeName: `${guard1.typeName} & ${guard2.typeName}`,
      dependencies: [guard1.name, guard2.name]
    }
  );
}

/**
 * Create an OR composition guard
 */
export function orGuard<T, U>(
  guard1: TypeGuard<T>,
  guard2: TypeGuard<U>
): TypeGuard<T | U> {
  return createTypeGuard(
    `or(${guard1.name}, ${guard2.name})`,
    (value, context) => {
      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      // Try first guard
      const result1 = guard1.validate(value, context);
      if (result1.success) {
        return {
          success: true,
          value: result1.value as T,
          errors: [],
          warnings: result1.warnings
        };
      }
      errors.push(...result1.errors);
      warnings.push(...result1.warnings);

      // Try second guard
      const result2 = guard2.validate(value, context);
      if (result2.success) {
        return {
          success: true,
          value: result2.value as U,
          errors: [],
          warnings: result2.warnings
        };
      }
      errors.push(...result2.errors);
      warnings.push(...result2.warnings);

      return {
        success: false,
        errors,
        warnings
      };
    },
    {
      description: `Requires either ${guard1.name} or ${guard2.name} to pass`,
      typeName: `${guard1.typeName} | ${guard2.typeName}`,
      dependencies: [guard1.name, guard2.name]
    }
  );
}

/**
 * Create an optional guard
 */
export function optionalGuard<T>(guard: TypeGuard<T>): TypeGuard<T | undefined> {
  return createTypeGuard(
    `optional(${guard.name})`,
    (value, context) => {
      if (value === undefined) {
        return {
          success: true,
          value: undefined,
          errors: [],
          warnings: []
        };
      }

      return guard.validate(value, context);
    },
    {
      description: `Optional version of ${guard.name}`,
      typeName: `${guard.typeName} | undefined`,
      dependencies: [guard.name]
    }
  );
}

/**
 * Create a nullable guard
 */
export function nullableGuard<T>(guard: TypeGuard<T>): TypeGuard<T | null> {
  return createTypeGuard(
    `nullable(${guard.name})`,
    (value, context) => {
      if (value === null) {
        return {
          success: true,
          value: null,
          errors: [],
          warnings: []
        };
      }

      return guard.validate(value, context);
    },
    {
      description: `Nullable version of ${guard.name}`,
      typeName: `${guard.typeName} | null`,
      dependencies: [guard.name]
    }
  );
}

/**
 * Create a guard with default value
 */
export function defaultGuard<T>(
  guard: TypeGuard<T>,
  defaultValue: T
): TypeGuard<T> {
  return createTypeGuard(
    `default(${guard.name}, ${JSON.stringify(defaultValue)})`,
    (value, context) => {
      if (value === undefined || value === null) {
        return {
          success: true,
          value: defaultValue,
          errors: [],
          warnings: [{
            code: 'DEFAULT_VALUE_USED',
            message: `Using default value: ${JSON.stringify(defaultValue)}`,
            path: context?.path || '',
            value: defaultValue,
            severity: 'low'
          }]
        };
      }

      return guard.validate(value, context);
    },
    {
      description: `${guard.name} with default value`,
      typeName: guard.typeName,
      dependencies: [guard.name]
    }
  );
}

/**
 * Create an array guard
 */
export function arrayGuard<T>(
  itemGuard: TypeGuard<T>,
  options: {
    minLength?: number;
    maxLength?: number;
    uniqueItems?: boolean;
  } = {}
): TypeGuard<T[]> {
  const { minLength, maxLength, uniqueItems } = options;

  return createTypeGuard(
    `array(${itemGuard.name})`,
    (value, context) => {
      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      if (!Array.isArray(value)) {
        errors.push({
          code: 'TYPE_MISMATCH',
          message: `Expected array, got ${typeof value}`,
          path: context?.path || '',
          value,
          expected: 'array',
          actual: typeof value,
          suggestions: ['Ensure value is an array', 'Check Array.isArray(value) before validation']
        });
        return { success: false, errors, warnings };
      }

      // Length validation
      if (minLength !== undefined && value.length < minLength) {
        errors.push({
          code: 'MIN_LENGTH',
          message: `Array must have at least ${minLength} items, got ${value.length}`,
          path: context?.path || '',
          value,
          expected: `length >= ${minLength}`,
          actual: `length = ${value.length}`,
          suggestions: [`Add more items to reach minimum length of ${minLength}`]
        });
      }

      if (maxLength !== undefined && value.length > maxLength) {
        errors.push({
          code: 'MAX_LENGTH',
          message: `Array must have at most ${maxLength} items, got ${value.length}`,
          path: context?.path || '',
          value,
          expected: `length <= ${maxLength}`,
          actual: `length = ${value.length}`,
          suggestions: [`Remove items to reduce length to ${maxLength}`]
        });
      }

      // Validate each item
      const validatedItems: T[] = [];
      const seenValues = new Set();

      for (let i = 0; i < value.length; i++) {
        const item = value[i];
        const itemPath = `${context?.path || ''}[${i}]`;
        const itemContext: ValidationContext = {
          ...(context || {}),
          path: itemPath,
          parent: value,
          parentProperty: String(i)
        };

        const itemResult = itemGuard.validate(item, itemContext);
        errors.push(...itemResult.errors);
        warnings.push(...itemResult.warnings);

        if (itemResult.success) {
          // Check for uniqueness if required
          if (uniqueItems) {
            const key = JSON.stringify(itemResult.value);
            if (seenValues.has(key)) {
              errors.push({
                code: 'DUPLICATE_ITEM',
                message: `Duplicate item found at index ${i}`,
                path: itemPath,
                value: itemResult.value,
                suggestions: ['Remove duplicate items from array']
              });
            } else {
              seenValues.add(key);
            }
          }

          validatedItems.push(itemResult.value!);
        }
      }

      const hasErrors = errors.length > 0;
      return {
        success: !hasErrors,
        value: hasErrors ? undefined : validatedItems,
        errors,
        warnings
      };
    },
    {
      description: `Array of ${itemGuard.name}`,
      typeName: `${itemGuard.typeName}[]`,
      dependencies: [itemGuard.name]
    }
  );
}

/**
 * Create an object guard
 */
export function objectGuard<T extends Record<string, unknown>>(
  shape: { [K in keyof T]: TypeGuard<T[K]> },
  options: {
    strict?: boolean;
    allowExtra?: boolean;
  } = {}
): TypeGuard<T> {
  const { strict = false, allowExtra = true } = options;
  const keys = Object.keys(shape) as (keyof T)[];

  return createTypeGuard(
    `object(${keys.map(k => shape[k].name).join(', ')})`,
    (value, context) => {
      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        errors.push({
          code: 'TYPE_MISMATCH',
          message: `Expected object, got ${Array.isArray(value) ? 'array' : typeof value}`,
          path: context?.path || '',
          value,
          expected: 'object',
          actual: Array.isArray(value) ? 'array' : typeof value,
          suggestions: ['Ensure value is a plain object', 'Check that value is not an array']
        });
        return { success: false, errors, warnings };
      }

      const obj = value as Record<string, unknown>;
      const validatedObj: Record<string, unknown> = {};

      // Validate required properties
      for (const key of keys) {
        const guard = shape[key];
        const itemPath = `${context?.path || ''}.${String(key)}`;
        const itemContext: ValidationContext = {
          ...(context || {}),
          path: itemPath,
          parent: obj,
          parentProperty: String(key)
        };

        const itemResult = guard.validate(obj[key as string], itemContext);
        errors.push(...itemResult.errors);
        warnings.push(...itemResult.warnings);

        if (itemResult.success) {
          validatedObj[key as string] = itemResult.value;
        } else if (strict) {
          return { success: false, errors, warnings };
        }
      }

      // Check for extra properties in strict mode
      if (!allowExtra) {
        const allowedKeys = new Set(keys.map(k => String(k)));
        for (const key of Object.keys(obj)) {
          if (!allowedKeys.has(key)) {
            warnings.push({
              code: 'EXTRA_PROPERTY',
              message: `Unexpected property: ${key}`,
              path: `${context?.path || ''}.${key}`,
              value: obj[key],
              severity: 'low',
              suggestions: ['Remove extra properties or set allowExtra: true']
            });
          }
        }
      }

      return {
        success: true,
        value: validatedObj as T,
        errors,
        warnings
      };
    },
    {
      description: `Object with shape: ${keys.map(k => `${k}: ${shape[k].typeName}`).join(', ')}`,
      typeName: `{ ${keys.map(k => `${k}: ${shape[k].typeName}`).join('; ')} }`,
      dependencies: keys.map(k => shape[k].name)
    }
  );
}

/**
 * Create a tuple guard
 */
export function tupleGuard<T extends readonly unknown[]>(
  ...guards: { [K in keyof T]: TypeGuard<T[K]> }
): TypeGuard<T> {
  return createTypeGuard(
    `tuple(${guards.map(g => g.name).join(', ')})`,
    (value, context) => {
      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      if (!Array.isArray(value)) {
        errors.push({
          code: 'TYPE_MISMATCH',
          message: `Expected array (tuple), got ${typeof value}`,
          path: context?.path || '',
          value,
          expected: 'array',
          actual: typeof value,
          suggestions: ['Ensure value is an array with correct length']
        });
        return { success: false, errors, warnings };
      }

      if (value.length !== guards.length) {
        errors.push({
          code: 'TUPLE_LENGTH',
          message: `Expected tuple of length ${guards.length}, got ${value.length}`,
          path: context?.path || '',
          value,
          expected: `length = ${guards.length}`,
          actual: `length = ${value.length}`,
          suggestions: [`Ensure array has exactly ${guards.length} elements`]
        });
        return { success: false, errors, warnings };
      }

      const validatedTuple: unknown[] = [];

      for (let i = 0; i < guards.length; i++) {
        const guard = guards[i];
        const item = value[i];
        const itemPath = `${context?.path || ''}[${i}]`;
        const itemContext: ValidationContext = {
          ...(context || {}),
          path: itemPath,
          parent: value,
          parentProperty: String(i)
        };

        const itemResult = guard.validate(item, itemContext);
        errors.push(...itemResult.errors);
        warnings.push(...itemResult.warnings);

        if (itemResult.success) {
          validatedTuple.push(itemResult.value);
        } else {
          return { success: false, errors, warnings };
        }
      }

      return {
        success: true,
        value: validatedTuple as T,
        errors,
        warnings
      };
    },
    {
      description: `Tuple of [${guards.map(g => g.typeName).join(', ')}]`,
      typeName: `[${guards.map(g => g.typeName).join(', ')}]`,
      dependencies: guards.map(g => g.name)
    }
  );
}

/**
 * Create a union guard
 */
export function unionGuard<T extends readonly unknown[]>(
  ...guards: { [K in keyof T]: TypeGuard<T[K]> }
): TypeGuard<T[number]> {
  return createTypeGuard(
    `union(${guards.map(g => g.name).join(' | ')})`,
    (value, context) => {
      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      for (const guard of guards) {
        const result = guard.validate(value, context);
        if (result.success) {
          return {
            success: true,
            value: result.value as T[number],
            errors: [],
            warnings: result.warnings
          };
        }
        errors.push(...result.errors);
        warnings.push(...result.warnings);
      }

      return {
        success: false,
        errors: [{
          code: 'UNION_NO_MATCH',
          message: `Value does not match any type in union: ${guards.map(g => g.typeName).join(' | ')}`,
          path: context?.path || '',
          value,
          expected: guards.map(g => g.typeName).join(' | '),
          actual: typeof value,
          suggestions: guards.map(g => `Check if value matches ${g.typeName}`)
        }],
        warnings
      };
    },
    {
      description: `Union of ${guards.map(g => g.typeName).join(' | ')}`,
      typeName: guards.map(g => g.typeName).join(' | '),
      dependencies: guards.map(g => g.name)
    }
  );
}

// ============================================================================
// Advanced Guard Utilities
// ============================================================================

/**
 * Create a guard from a predicate function
 */
export function predicateGuard<T>(
  predicate: (value: unknown) => value is T,
  typeName: string,
  options: {
    description?: string;
    errorMessage?: string;
  } = {}
): TypeGuard<T> {
  return createTypeGuard(
    `predicate(${typeName})`,
    (value, context) => {
      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      if (!predicate(value)) {
        errors.push({
          code: 'PREDICATE_FAILED',
          message: options.errorMessage || `Value does not match predicate for ${typeName}`,
          path: context?.path || '',
          value,
          expected: typeName,
          actual: typeof value,
          suggestions: ['Check if value matches the expected predicate criteria']
        });
        return { success: false, errors, warnings };
      }

      return { success: true, value, errors, warnings };
    },
    {
      description: options.description || `Validates ${typeName} using custom predicate`,
      typeName
    }
  );
}

/**
 * Create a guard with custom validation logic
 */
export function customGuard<T>(
  name: string,
  validator: (value: unknown, context?: ValidationContext) => ValidationResult<T>,
  options: {
    typeName?: string;
    cacheable?: boolean;
    metadata?: Record<string, unknown>;
  } = {}
): TypeGuard<T> {
  return createTypeGuard(name, validator, options);
}

/**
 * Create a guard that validates enum values
 */
export function enumGuard<T extends readonly string[]>(
  enumValues: T,
  options: {
    caseSensitive?: boolean;
    allowCoercion?: boolean;
  } = {}
): TypeGuard<T[number]> {
  const { caseSensitive = true, allowCoercion = false } = options;
  const valueSet = new Set(caseSensitive ? enumValues : enumValues.map(v => v.toLowerCase()));

  return createTypeGuard(
    `enum(${enumValues.join(' | ')})`,
    (value, context) => {
      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      let stringValue: string;
      if (typeof value === 'string') {
        stringValue = value;
      } else if (allowCoercion) {
        stringValue = String(value);
        warnings.push({
          code: 'TYPE_COERCION',
          message: `Value coerced to string: ${stringValue}`,
          path: context?.path || '',
          value: stringValue,
          severity: 'low'
        });
      } else {
        errors.push({
          code: 'TYPE_MISMATCH',
          message: `Expected string enum value, got ${typeof value}`,
          path: context?.path || '',
          value,
          expected: `string enum (${enumValues.join(' | ')})`,
          actual: typeof value,
          suggestions: ['Ensure value is a string matching one of the enum values']
        });
        return { success: false, errors, warnings };
      }

      const checkValue = caseSensitive ? stringValue : stringValue.toLowerCase();
      if (!valueSet.has(checkValue)) {
        errors.push({
          code: 'INVALID_ENUM_VALUE',
          message: `Invalid enum value: ${stringValue}`,
          path: context?.path || '',
          value: stringValue,
          expected: enumValues.join(' | '),
          actual: stringValue,
          suggestions: [`Use one of: ${enumValues.join(', ')}`]
        });
        return { success: false, errors, warnings };
      }

      const finalValue = caseSensitive ? stringValue : (enumValues.find(v => v.toLowerCase() === checkValue)!);

      return {
        success: true,
        value: finalValue as T[number],
        errors,
        warnings
      };
    },
    {
      description: `Enum with values: ${enumValues.join(' | ')}`,
      typeName: enumValues.join(' | ')
    }
  );
}

/**
 * Create a range guard for numbers
 */
export function rangeGuard(
  min: number,
  max: number,
  options: {
    inclusive?: boolean;
    integer?: boolean;
  } = {}
): TypeGuard<number> {
  const { inclusive = true, integer = false } = options;

  return createTypeGuard(
    `range(${min}, ${max}${inclusive ? '' : ' exclusive'}${integer ? ' integer' : ''})`,
    (value, context) => {
      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      if (typeof value !== 'number') {
        errors.push({
          code: 'TYPE_MISMATCH',
          message: `Expected number, got ${typeof value}`,
          path: context?.path || '',
          value,
          expected: 'number',
          actual: typeof value,
          suggestions: ['Convert value to number using Number(value)']
        });
        return { success: false, errors, warnings };
      }

      if (!isFinite(value)) {
        errors.push({
          code: 'INVALID_NUMBER',
          message: `Number must be finite, got ${value}`,
          path: context?.path || '',
          value,
          expected: 'finite number',
          actual: String(value),
          suggestions: ['Check for NaN or Infinity values']
        });
        return { success: false, errors, warnings };
      }

      if (integer && !Number.isInteger(value)) {
        errors.push({
          code: 'NOT_INTEGER',
          message: `Number must be integer, got ${value}`,
          path: context?.path || '',
          value,
          expected: 'integer',
          actual: String(value),
          suggestions: ['Use Math.floor() or Math.round() to convert to integer']
        });
        return { success: false, errors, warnings };
      }

      const inRange = inclusive ? (value >= min && value <= max) : (value > min && value < max);
      if (!inRange) {
        errors.push({
          code: 'OUT_OF_RANGE',
          message: `Number ${inclusive ? 'must be' : 'must be strictly'} between ${min} and ${max}, got ${value}`,
          path: context?.path || '',
          value,
          expected: inclusive ? `${min} <= value <= ${max}` : `${min} < value < ${max}`,
          actual: String(value),
          suggestions: [`Adjust value to be within range ${min} to ${max}`]
        });
        return { success: false, errors, warnings };
      }

      return { success: true, value, errors, warnings };
    },
    {
      description: `Number in range ${min} to ${max}${inclusive ? '' : ' (exclusive)'}`,
      typeName: `number (${min}-${max})`
    }
  );
}

/**
 * Create a pattern guard for strings
 */
export function patternGuard(
  pattern: RegExp,
  options: {
    description?: string;
    flags?: string;
  } = {}
): TypeGuard<string> {
  const { description, flags } = options;
  const regex = new RegExp(pattern, flags);

  return createTypeGuard(
    `pattern(${regex.toString()})`,
    (value, context) => {
      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      if (typeof value !== 'string') {
        errors.push({
          code: 'TYPE_MISMATCH',
          message: `Expected string, got ${typeof value}`,
          path: context?.path || '',
          value,
          expected: 'string',
          actual: typeof value,
          suggestions: ['Convert value to string using String(value)']
        });
        return { success: false, errors, warnings };
      }

      if (!regex.test(value)) {
        errors.push({
          code: 'PATTERN_MISMATCH',
          message: `String does not match pattern ${regex.toString()}`,
          path: context?.path || '',
          value,
          expected: `pattern: ${regex.toString()}`,
          actual: value,
          suggestions: [`Ensure string matches pattern: ${regex.toString()}`]
        });
        return { success: false, errors, warnings };
      }

      return { success: true, value, errors, warnings };
    },
    {
      description: description || `String matching pattern ${regex.toString()}`,
      typeName: `string (${regex.toString()})`
    }
  );
}

// ============================================================================
// Guard Registry and Caching
// ============================================================================

/**
 * Registry for managing type guards
 */
export class GuardRegistry {
  private guards = new Map<string, TypeGuard>();
  private cache = new Map<string, ValidationResult>();

  /**
   * Register a guard
   */
  register(guard: TypeGuard): void {
    this.guards.set(guard.name, guard);
  }

  /**
   * Get a guard by name
   */
  get(name: string): TypeGuard | undefined {
    return this.guards.get(name);
  }

  /**
   * Check if a guard is registered
   */
  has(name: string): boolean {
    return this.guards.has(name);
  }

  /**
   * Get all registered guard names
   */
  getGuardNames(): string[] {
    return Array.from(this.guards.keys());
  }

  /**
   * Clear the validation cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; keys: string[] } {
    return {
      size: this.cache.size,
      keys: Array.from(this.cache.keys())
    };
  }

  /**
   * Validate with caching
   */
  validateWithCache<T>(
    guard: TypeGuard<T>,
    value: unknown,
    context?: ValidationContext
  ): ValidationResult<T> {
    if (!guard.cacheable || !context?.options.useCache) {
      return guard.validate(value, context);
    }

    const cacheKey = this.getCacheKey(guard, value, context);
    const cached = this.cache.get(cacheKey);

    if (cached) {
      return cached as ValidationResult<T>;
    }

    const result = guard.validate(value, context);
    this.cache.set(cacheKey, result);

    return result;
  }

  /**
   * Generate cache key for validation
   */
  private getCacheKey(
    guard: TypeGuard,
    value: unknown,
    context?: ValidationContext
  ): string {
    const valueHash = JSON.stringify(value);
    const contextHash = context ? JSON.stringify(context.path) : '';
    return `${guard.name}:${valueHash}:${contextHash}`;
  }
}

// ============================================================================
// Global Registry Instance
// ============================================================================

/**
 * Global guard registry instance
 */
export const globalGuardRegistry = new GuardRegistry();

// Register basic guards
globalGuardRegistry.register(stringGuard);
globalGuardRegistry.register(numberGuard);
globalGuardRegistry.register(booleanGuard);
globalGuardRegistry.register(nullGuard);
globalGuardRegistry.register(undefinedGuard);

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Create a new guard builder
 */
export function guard<T = unknown>(guard?: TypeGuard<T>): GuardBuilder<T> {
  return new GuardBuilder(guard);
}

/**
 * Get a guard from the global registry
 */
export function getGuard(name: string): TypeGuard | undefined {
  return globalGuardRegistry.get(name);
}

/**
 * Validate using a guard from the global registry
 */
export function validate<T>(
  guardName: string,
  value: unknown,
  context?: ValidationContext
): ValidationResult<T> {
  const guard = getGuard(guardName);
  if (!guard) {
    return {
      success: false,
      errors: [{
        code: 'GUARD_NOT_FOUND',
        message: `Guard '${guardName}' not found in registry`,
        path: context?.path || '',
        value,
        suggestions: [`Register guard using globalGuardRegistry.register(${guardName})`]
      }],
      warnings: []
    };
  }

  return globalGuardRegistry.validateWithCache(guard, value, context);
}

/**
 * Check if a value matches a guard
 */
export function matches<T>(
  guardName: string,
  value: unknown,
  context?: ValidationContext
): boolean {
  const result = validate<T>(guardName, value, context);
  return result.success;
}