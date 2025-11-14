/**
 * JSONValue Conversion Utilities with Error Handling
 *
 * This module provides comprehensive utilities for converting various types
 * to JSONValue format with detailed error handling and recovery options.
 */

import type {
  Dict,
  JSONArray,
  JSONObject,
  JSONPrimitive,
  JSONValue} from './base-types.js';
import type {
  isJSONArray,
  isJSONObject,
  isJSONPrimitive,
  isJSONValue} from './type-guards-enhanced.js';

// ============================================================================
// Conversion Result Types
// ============================================================================

/**
 * Result of a JSON conversion operation
 */
export interface JSONConversionResult<T = JSONValue> {
  /** The converted JSON value */
  readonly value: T;
  /** Whether the conversion was successful */
  readonly success: boolean;
  /** The original value before conversion */
  readonly original: unknown;
  /** Warnings generated during conversion */
  readonly warnings: JSONConversionWarning[];
  /** Errors encountered during conversion */
  readonly errors: JSONConversionError[];
  /** Conversion statistics */
  readonly stats: JSONConversionStats;
}

/**
 * Warning generated during JSON conversion
 */
export interface JSONConversionWarning {
  /** Warning code */
  readonly code: JSONConversionWarningCode;
  /** Warning message */
  readonly message: string;
  /** Path where warning occurred */
  readonly path: string;
  /** The problematic value */
  readonly value: unknown;
  /** Suggested fix if available */
  readonly suggestion?: string;
}

/**
 * Error encountered during JSON conversion
 */
export interface JSONConversionError {
  /** Error code */
  readonly code: JSONConversionErrorCode;
  /** Error message */
  readonly message: string;
  /** Path where error occurred */
  readonly path: string;
  /** The problematic value */
  readonly value: unknown;
  /** Whether this error is recoverable */
  readonly recoverable: boolean;
  /** Suggested fix if available */
  readonly suggestion?: string;
  /** Original error if available */
  readonly cause?: Error;
}

/**
 * Conversion statistics
 */
export interface JSONConversionStats {
  /** Total number of values processed */
  readonly totalProcessed: number;
  /** Number of successful conversions */
  readonly successfulConversions: number;
  /** Number of failed conversions */
  readonly failedConversions: number;
  /** Number of warnings generated */
  readonly warningsGenerated: number;
  /** Number of circular references detected */
  readonly circularReferences: number;
  /** Maximum depth reached */
  readonly maxDepth: number;
  /** Conversion duration in milliseconds */
  readonly durationMs: number;
  /** Size of input in bytes (approximation) */
  readonly inputSizeBytes: number;
  /** Size of output in bytes (approximation) */
  readonly outputSizeBytes: number;
}

/**
 * Warning codes for JSON conversion
 */
export type JSONConversionWarningCode =
  | 'TYPE_COERCION'
  | 'PRECISION_LOSS'
  | 'TRUNCATION'
  | 'ESCAPE_SEQUENCES'
  | 'DATE_FORMAT'
  | 'REGEXP_LOSS'
  | 'FUNCTION_LOSS'
  | 'SYMBOL_LOSS'
  | 'CUSTOM_PROPERTY_LOSS'
  | 'DEPTH_LIMIT';

/**
 * Error codes for JSON conversion
 */
export type JSONConversionErrorCode =
  | 'CIRCULAR_REFERENCE'
  | 'MAX_DEPTH_EXCEEDED'
  | 'UNSUPPORTED_TYPE'
  | 'INVALID_SERIALIZATION'
  | 'BUFFER_TOO_LARGE'
  | 'SERIALIZATION_ERROR'
  | 'PATH_RESOLUTION_ERROR';

// ============================================================================
// Conversion Options
// ============================================================================

/**
 * Options for JSON conversion
 */
export interface JSONConversionOptions {
  /** Maximum depth to traverse (default: 100) */
  readonly maxDepth?: number;
  /** Whether to handle circular references (default: true) */
  readonly handleCircularRefs?: boolean;
  /** Strategy for handling circular references */
  readonly circularRefStrategy?: 'error' | 'ignore' | 'replace';
  /** Replacement value for circular references */
  readonly circularRefReplacement?: JSONValue;
  /** Whether to coerce types when possible (default: true) */
  readonly coerceTypes?: boolean;
  /** Whether to truncate long strings (default: false) */
  readonly truncateLongStrings?: boolean;
  /** Maximum string length before truncation */
  readonly maxStringLength?: number;
  /** Whether to preserve date objects as strings (default: true) */
  readonly preserveDates?: boolean;
  /** Date format string (default: ISO) */
  readonly dateFormat?: string;
  /** Whether to convert BigInt to string (default: true) */
  readonly convertBigInt?: boolean;
  /** Whether to convert functions to string representations (default: false) */
  readonly convertFunctions?: boolean;
  /** Whether to handle Symbol properties (default: false) */
  readonly handleSymbols?: boolean;
  /** Whether to preserve undefined values (default: false) */
  readonly preserveUndefined?: boolean;
  /** Custom type converters */
  readonly customConverters?: Map<string, TypeConverter>;
  /** Whether to collect detailed statistics (default: false) */
  readonly collectStats?: boolean;
  /** Progress callback for large conversions */
  readonly onProgress?: (progress: JSONConversionProgress) => void;
  /** Buffer size limit in bytes (default: 10MB) */
  readonly bufferSizeLimit?: number;
}

/**
 * Progress information for large conversions
 */
export interface JSONConversionProgress {
  /** Number of items processed */
  readonly processed: number;
  /** Total number of items (if known) */
  readonly total?: number;
  /** Current processing path */
  readonly currentPath: string;
  /** Percentage complete */
  readonly percentage?: number;
}

/**
 * Type converter function
 */
export type TypeConverter = (
  value: unknown,
  path: string,
  options: JSONConversionOptions
) => JSONConversionResult;

// ============================================================================
// Core JSON Conversion Engine
// ============================================================================

/**
 * Main JSON conversion engine
 */
export class JSONConverter {
  private readonly defaultOptions: Required<JSONConversionOptions> = {
    maxDepth: 100,
    handleCircularRefs: true,
    circularRefStrategy: 'replace',
    circularRefReplacement: '[Circular Reference]',
    coerceTypes: true,
    truncateLongStrings: false,
    maxStringLength: 10000,
    preserveDates: true,
    dateFormat: 'iso',
    convertBigInt: true,
    convertFunctions: false,
    handleSymbols: false,
    preserveUndefined: false,
    customConverters: new Map(),
    collectStats: false,
    onProgress: () => {},
    bufferSizeLimit: 10 * 1024 * 1024 // 10MB
  };

  /**
   * Convert any value to JSONValue with comprehensive error handling
   */
  convertToJSON(
    value: unknown,
    options: JSONConversionOptions = {}
  ): JSONConversionResult {
    const mergedOptions = { ...this.defaultOptions, ...options };
    const startTime = Date.now();

    const warnings: JSONConversionWarning[] = [];
    const errors: JSONConversionError[] = [];
    const stats: JSONConversionStats = {
      totalProcessed: 0,
      successfulConversions: 0,
      failedConversions: 0,
      warningsGenerated: 0,
      circularReferences: 0,
      maxDepth: 0,
      durationMs: 0,
      inputSizeBytes: this.estimateSize(value),
      outputSizeBytes: 0
    };

    // Track visited objects for circular reference detection
    const visited = new WeakMap<object, string>();

    try {
      const result = this.convertValue(
        value,
        '',
        visited,
        0,
        mergedOptions,
        warnings,
        errors,
        stats
      );

      // Calculate final stats
      stats.durationMs = Date.now() - startTime;
      stats.outputSizeBytes = this.estimateSize(result.value);

      return {
        value: result.value,
        success: errors.length === 0,
        original: value,
        warnings,
        errors,
        stats
      };
    } catch (error) {
      stats.durationMs = Date.now() - startTime;

      return {
        value: null,
        success: false,
        original: value,
        warnings,
        errors: [{
          code: 'SERIALIZATION_ERROR',
          message: `Conversion failed: ${error instanceof Error ? error.message : String(error)}`,
          path: '',
          value,
          recoverable: false,
          cause: error instanceof Error ? error : undefined
        }],
        stats
      };
    }
  }

  /**
   * Convert a specific value with context
   */
  private convertValue(
    value: unknown,
    path: string,
    visited: WeakMap<object, string>,
    depth: number,
    options: Required<JSONConversionOptions>,
    warnings: JSONConversionWarning[],
    errors: JSONConversionError[],
    stats: JSONConversionStats
  ): JSONConversionResult {
    stats.totalProcessed++;
    stats.maxDepth = Math.max(stats.maxDepth, depth);

    // Check depth limit
    if (depth > options.maxDepth) {
      const error: JSONConversionError = {
        code: 'MAX_DEPTH_EXCEEDED',
        message: `Maximum depth of ${options.maxDepth} exceeded at path: ${path}`,
        path,
        value,
        recoverable: true,
        suggestion: 'Consider restructuring your data or increasing maxDepth limit'
      };
      errors.push(error);
      stats.failedConversions++;
      return {
        value: null,
        success: false,
        original: value,
        warnings: [],
        errors: [error],
        stats: { ...stats, totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
      };
    }

    // Handle circular references
    if (typeof value === 'object' && value !== null) {
      const existingPath = visited.get(value);
      if (existingPath) {
        stats.circularReferences++;

        if (options.circularRefStrategy === 'error') {
          const error: JSONConversionError = {
            code: 'CIRCULAR_REFERENCE',
            message: `Circular reference detected: ${path} -> ${existingPath}`,
            path,
            value,
            recoverable: true,
            suggestion: 'Use circularRefStrategy: "replace" to handle circular references'
          };
          errors.push(error);
          stats.failedConversions++;
          return {
            value: null,
            success: false,
            original: value,
            warnings: [],
            errors: [error],
            stats: { ...stats, totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
          };
        } else if (options.circularRefStrategy === 'replace') {
          return {
            value: options.circularRefReplacement,
            success: true,
            original: value,
            warnings: [{
              code: 'CIRCULAR_REFERENCE',
              message: `Circular reference replaced: ${path} -> ${existingPath}`,
              path,
              value,
              suggestion: 'Original circular structure was replaced with placeholder'
            }],
            errors: [],
            stats: { ...stats, totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
          };
        } else {
          // Ignore strategy
          return {
            value: null,
            success: true,
            original: value,
            warnings: [{
              code: 'CIRCULAR_REFERENCE',
              message: `Circular reference ignored: ${path} -> ${existingPath}`,
              path,
              value,
              suggestion: 'Circular reference was ignored and not included in output'
            }],
            errors: [],
            stats: { ...stats, totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
          };
        }
      }

      visited.set(value, path);
    }

    // Handle null and undefined
    if (value === null) {
      stats.successfulConversions++;
      return {
        value: null,
        success: true,
        original: value,
        warnings: [],
        errors: [],
        stats: { ...stats, totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
      };
    }

    if (value === undefined) {
      if (options.preserveUndefined) {
        stats.successfulConversions++;
        return {
          value: null,
          success: true,
          original: value,
          warnings: [{
            code: 'TYPE_COERCION',
            message: `Undefined value converted to null at path: ${path}`,
            path,
            value,
            suggestion: 'Consider filtering out undefined values before conversion'
          }],
          errors: [],
          stats: { ...stats, totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
        };
      } else {
        stats.successfulConversions++;
        return {
          value: null,
          success: true,
          original: value,
          warnings: [],
          errors: [],
          stats: { ...stats, totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
        };
      }
    }

    // Handle primitives
    if (this.isJSONPrimitive(value)) {
      stats.successfulConversions++;
      return {
        value: value as JSONPrimitive,
        success: true,
        original: value,
        warnings: [],
        errors: [],
        stats: { ...stats, totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
      };
    }

    // Handle arrays
    if (Array.isArray(value)) {
      return this.convertArray(value, path, visited, depth, options, warnings, errors, stats);
    }

    // Handle objects
    if (typeof value === 'object') {
      return this.convertObject(value, path, visited, depth, options, warnings, errors, stats);
    }

    // Handle special types
    const specialResult = this.convertSpecialTypes(value, path, options);
    if (specialResult) {
      stats.successfulConversions++;
      return specialResult;
    }

    // Handle unsupported types
    const error: JSONConversionError = {
      code: 'UNSUPPORTED_TYPE',
      message: `Unsupported type ${typeof value} at path: ${path}`,
      path,
      value,
      recoverable: false,
      suggestion: 'Convert or remove unsupported values before JSON serialization'
    };
    errors.push(error);
    stats.failedConversions++;

    return {
      value: null,
      success: false,
      original: value,
      warnings: [],
      errors: [error],
      stats: { ...stats, totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
    };
  }

  /**
   * Convert array values
   */
  private convertArray(
    array: unknown[],
    path: string,
    visited: WeakMap<object, string>,
    depth: number,
    options: Required<JSONConversionOptions>,
    warnings: JSONConversionWarning[],
    errors: JSONConversionError[],
    stats: JSONConversionStats
  ): JSONConversionResult {
    const result: unknown[] = [];
    const arrayWarnings: JSONConversionWarning[] = [];
    const arrayErrors: JSONConversionError[] = [];

    for (let i = 0; i < array.length; i++) {
      const itemPath = `${path}[${i}]`;
      const itemResult = this.convertValue(
        array[i],
        itemPath,
        visited,
        depth + 1,
        options,
        arrayWarnings,
        arrayErrors,
        stats
      );

      if (itemResult.success) {
        result.push(itemResult.value);
      } else {
        result.push(null);
        arrayWarnings.push(...itemResult.warnings);
        arrayErrors.push(...itemResult.errors);
      }
    }

    warnings.push(...arrayWarnings);
    errors.push(...arrayErrors);

    return {
      value: result,
      success: arrayErrors.length === 0,
      original: array,
      warnings: arrayWarnings,
      errors: arrayErrors,
      stats: { ...stats, totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
    };
  }

  /**
   * Convert object values
   */
  private convertObject(
    obj: object,
    path: string,
    visited: WeakMap<object, string>,
    depth: number,
    options: Required<JSONConversionOptions>,
    warnings: JSONConversionWarning[],
    errors: JSONConversionError[],
    stats: JSONConversionStats
  ): JSONConversionResult {
    const result: JSONObject = {};
    const objectWarnings: JSONConversionWarning[] = [];
    const objectErrors: JSONConversionError[] = [];

    // Get all property names (including symbols if enabled)
    let propertyNames: (string | symbol)[] = Object.getOwnPropertyNames(obj);

    if (options.handleSymbols) {
      propertyNames = [...propertyNames, ...Object.getOwnPropertySymbols(obj)];
    }

    for (const propertyName of propertyNames) {
      let propertyKey: string;
      let propertyPath: string;

      if (typeof propertyName === 'symbol') {
        if (!options.handleSymbols) {
          continue;
        }
        propertyKey = propertyName.toString();
        propertyPath = `${path}[${propertyKey}]`;

        objectWarnings.push({
          code: 'SYMBOL_LOSS',
          message: `Symbol property converted to string key: ${propertyKey}`,
          path: propertyPath,
          value: propertyName,
          suggestion: 'Symbol properties will lose their unique identity'
        });
      } else {
        propertyKey = propertyName;
        propertyPath = path ? `${path}.${propertyKey}` : propertyKey;
      }

      try {
        const descriptor = Object.getOwnPropertyDescriptor(obj, propertyName);

        // Skip non-enumerable properties unless they're custom converters
        if (descriptor && !descriptor.enumerable && !options.customConverters.has(propertyKey)) {
          objectWarnings.push({
            code: 'CUSTOM_PROPERTY_LOSS',
            message: `Non-enumerable property skipped: ${propertyKey}`,
            path: propertyPath,
            value: descriptor.value,
            suggestion: 'Consider using custom converters for non-enumerable properties'
          });
          continue;
        }

        const propertyValue = obj[propertyName as keyof typeof obj];

        // Check for custom converters
        if (options.customConverters.has(propertyKey)) {
          const converter = options.customConverters.get(propertyKey)!;
          const customResult = converter(propertyValue, propertyPath, options);

          if (customResult.success) {
            result[propertyKey] = customResult.value;
            objectWarnings.push(...customResult.warnings);
            objectErrors.push(...customResult.errors);
            continue;
          }
        }

        const propertyResult = this.convertValue(
          propertyValue,
          propertyPath,
          visited,
          depth + 1,
          options,
          objectWarnings,
          objectErrors,
          stats
        );

        if (propertyResult.success) {
          result[propertyKey] = propertyResult.value;
        } else {
          result[propertyKey] = null;
          objectWarnings.push(...propertyResult.warnings);
          objectErrors.push(...propertyResult.errors);
        }
      } catch (error) {
        const conversionError: JSONConversionError = {
          code: 'PATH_RESOLUTION_ERROR',
          message: `Error accessing property ${propertyKey}: ${error instanceof Error ? error.message : String(error)}`,
          path: propertyPath,
          value: propertyName,
          recoverable: true,
          cause: error instanceof Error ? error : undefined
        };
        objectErrors.push(conversionError);
        result[propertyKey] = null;
      }
    }

    warnings.push(...objectWarnings);
    errors.push(...objectErrors);

    return {
      value: result,
      success: objectErrors.length === 0,
      original: obj,
      warnings: objectWarnings,
      errors: objectErrors,
      stats: { ...stats, totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
    };
  }

  /**
   * Convert special types (Date, BigInt, Function, etc.)
   */
  private convertSpecialTypes(
    value: unknown,
    path: string,
    options: Required<JSONConversionOptions>
  ): JSONConversionResult | null {
    // Date objects
    if (value instanceof Date) {
      if (options.preserveDates) {
        const dateString = options.dateFormat === 'iso'
          ? value.toISOString()
          : value.toString();

        return {
          value: dateString,
          success: true,
          original: value,
          warnings: [{
            code: 'DATE_FORMAT',
            message: `Date object converted to string: ${dateString}`,
            path,
            value,
            suggestion: 'Date objects are serialized as ISO strings'
          }],
          errors: [],
          stats: { totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
        };
      }
    }

    // BigInt
    if (typeof value === 'bigint') {
      if (options.convertBigInt) {
        const stringValue = value.toString();

        return {
          value: stringValue,
          success: true,
          original: value,
          warnings: [{
            code: 'PRECISION_LOSS',
            message: `BigInt converted to string: ${stringValue}`,
            path,
            value,
            suggestion: 'BigInt values lose precision when converted to strings'
          }],
          errors: [],
          stats: { totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
        };
      }
    }

    // Function
    if (typeof value === 'function') {
      if (options.convertFunctions) {
        const functionString = `[Function: ${value.name || 'anonymous'}]`;

        return {
          value: functionString,
          success: true,
          original: value,
          warnings: [{
            code: 'FUNCTION_LOSS',
            message: `Function converted to string representation`,
            path,
            value: functionString,
            suggestion: 'Functions cannot be serialized to JSON'
          }],
          errors: [],
          stats: { totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
        };
      }
    }

    // RegExp
    if (value instanceof RegExp) {
      const regexString = value.toString();

      return {
        value: regexString,
        success: true,
        original: value,
        warnings: [{
          code: 'REGEXP_LOSS',
          message: `RegExp converted to string: ${regexString}`,
          path,
          value,
          suggestion: 'RegExp objects lose their behavior when converted to strings'
        }],
        errors: [],
        stats: { totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
      };
    }

    // Buffer
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) {
      const base64String = value.toString('base64');

      return {
        value: base64String,
        success: true,
        original: value,
        warnings: [{
          code: 'TYPE_COERCION',
          message: `Buffer converted to base64 string`,
          path,
          value: base64String,
          suggestion: 'Buffer objects are serialized as base64 strings'
        }],
        errors: [],
        stats: { totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
      };
    }

    // Map
    if (value instanceof Map) {
      const obj: JSONObject = {};
      for (const [key, val] of value.entries()) {
        const stringKey = String(key);
        obj[stringKey] = val;
      }

      return {
        value: obj,
        success: true,
        original: value,
        warnings: [{
          code: 'TYPE_COERCION',
          message: `Map converted to object with string keys`,
          path,
          value: obj,
          suggestion: 'Map keys are converted to strings'
        }],
        errors: [],
        stats: { totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
      };
    }

    // Set
    if (value instanceof Set) {
      const array = Array.from(value);

      return {
        value: array,
        success: true,
        original: value,
        warnings: [{
          code: 'TYPE_COERCION',
          message: `Set converted to array`,
          path,
          value: array,
          suggestion: 'Set objects are serialized as arrays'
        }],
        errors: [],
        stats: { totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
      };
    }

    return null;
  }

  /**
   * Check if a value is a JSON primitive
   */
  private isJSONPrimitive(value: unknown): value is JSONPrimitive {
    return (
      value === null ||
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'boolean'
    );
  }

  /**
   * Estimate the size of a value in bytes
   */
  private estimateSize(value: unknown): number {
    try {
      return JSON.stringify(value).length * 2; // Rough estimate (UTF-16)
    } catch {
      // Fallback for non-serializable values
      return String(value).length * 2;
    }
  }
}

// ============================================================================
// Pre-built Type Converters
// ============================================================================

/**
 * Type converter for Date objects
 */
export const dateConverter: TypeConverter = (value, path, options) => {
  if (!(value instanceof Date)) {
    return {
      value: null,
      success: false,
      original: value,
      warnings: [],
      errors: [{
        code: 'INVALID_SERIALIZATION',
        message: `Expected Date object at ${path}, got ${typeof value}`,
        path,
        value,
        recoverable: false
      }],
      stats: { totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
    };
  }

  const dateString = options.dateFormat === 'iso' ? value.toISOString() : value.toString();

  return {
    value: dateString,
    success: true,
    original: value,
    warnings: [{
      code: 'DATE_FORMAT',
      message: `Date converted to ${options.dateFormat} format`,
      path,
      value: dateString,
      suggestion: 'Use Date.parse() to reconstruct Date objects'
    }],
    errors: [],
    stats: { totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
  };
};

/**
 * Type converter for BigInt objects
 */
export const bigIntConverter: TypeConverter = (value, path) => {
  if (typeof value !== 'bigint') {
    return {
      value: null,
      success: false,
      original: value,
      warnings: [],
      errors: [{
        code: 'INVALID_SERIALIZATION',
        message: `Expected BigInt at ${path}, got ${typeof value}`,
        path,
        value,
        recoverable: false
      }],
      stats: { totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
    };
  }

  const stringValue = value.toString();

  return {
    value: stringValue,
    success: true,
    original: value,
    warnings: [{
      code: 'PRECISION_LOSS',
      message: `BigInt converted to string with full precision`,
      path,
      value: stringValue,
      suggestion: 'Use BigInt() to reconstruct BigInt values'
    }],
    errors: [],
    stats: { totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
  };
};

/**
 * Type converter for Error objects
 */
export const errorConverter: TypeConverter = (value, path) => {
  if (!(value instanceof Error)) {
    return {
      value: null,
      success: false,
      original: value,
      warnings: [],
      errors: [{
        code: 'INVALID_SERIALIZATION',
        message: `Expected Error object at ${path}, got ${typeof value}`,
        path,
        value,
        recoverable: false
      }],
      stats: { totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
    };
  }

  const errorObj: JSONObject = {
    name: value.name,
    message: value.message,
    stack: value.stack
  };

  return {
    value: errorObj,
    success: true,
    original: value,
    warnings: [{
      code: 'TYPE_COERCION',
      message: `Error object converted to serializable representation`,
      path,
      value: errorObj,
      suggestion: 'Error objects are serialized with name, message, and stack properties'
    }],
    errors: [],
    stats: { totalProcessed: 0, successfulConversions: 0, failedConversions: 0, warningsGenerated: 0, circularReferences: 0, maxDepth: 0, durationMs: 0, inputSizeBytes: 0, outputSizeBytes: 0 }
  };
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create a JSON converter with default options
 */
export function createJSONConverter(options: JSONConversionOptions = {}): JSONConverter {
  return new JSONConverter();
}

/**
 * Convert value to JSON with sensible defaults
 */
export function toJSON(value: unknown, options: JSONConversionOptions = {}): JSONConversionResult {
  const converter = new JSONConverter();
  return converter.convertToJSON(value, options);
}

/**
 * Convert value to JSON string with error handling
 */
export function toJSONString(
  value: unknown,
  options: JSONConversionOptions & {
    /** JSON stringify options */
    space?: string | number;
    /** Replacer function */
    replacer?: (key: string, value: unknown) => unknown;
  } = {}
): { success: boolean; json: string | null; error?: string; warnings: string[] } {
  const { space, replacer, ...conversionOptions } = options;
  const converter = new JSONConverter();

  const result = converter.convertToJSON(value, conversionOptions);

  if (!result.success) {
    return {
      success: false,
      json: null,
      error: result.errors.map(e => e.message).join('; '),
      warnings: result.warnings.map(w => w.message)
    };
  }

  try {
    const jsonString = JSON.stringify(result.value, replacer, space);
    return {
      success: true,
      json: jsonString,
      warnings: result.warnings.map(w => w.message)
    };
  } catch (error) {
    return {
      success: false,
      json: null,
      error: `JSON.stringify failed: ${error instanceof Error ? error.message : String(error)}`,
      warnings: result.warnings.map(w => w.message)
    };
  }
}

/**
 * Parse JSON string with comprehensive error handling
 */
export function parseJSON(
  jsonString: string,
  options: {
    /** Allow trailing commas */
    allowTrailingCommas?: boolean;
    /** Allow comments */
    allowComments?: boolean;
    /** Custom reviver function */
    reviver?: (key: string, value: unknown) => unknown;
  } = {}
): { success: boolean; value: unknown; error?: string } {
  const { allowTrailingCommas = false, allowComments = false, reviver } = options;

  try {
    // Basic preprocessing for comments and trailing commas
    let processedJson = jsonString;

    if (allowComments) {
      // Remove single-line comments
      processedJson = processedJson.replace(/\/\/.*$/gm, '');
      // Remove multi-line comments
      processedJson = processedJson.replace(/\/\*[\s\S]*?\*\//g, '');
    }

    if (allowTrailingCommas) {
      // Remove trailing commas before closing brackets/braces
      processedJson = processedJson.replace(/,(\s*[}\]])/g, '$1');
    }

    const value = JSON.parse(processedJson, reviver);

    return { success: true, value };
  } catch (error) {
    return {
      success: false,
      value: null,
      error: `JSON.parse failed: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

/**
 * Safely clone a value using JSON serialization
 */
export function safeJSONClone<T>(
  value: T,
  options: JSONConversionOptions = {}
): { success: boolean; clone: T | null; error?: string } {
  const jsonResult = toJSON(value, options);

  if (!jsonResult.success) {
    return {
      success: false,
      clone: null,
      error: jsonResult.errors.map(e => e.message).join('; ')
    };
  }

  const parseResult = parseJSON(JSON.stringify(jsonResult.value));

  if (!parseResult.success) {
    return {
      success: false,
      clone: null,
      error: parseResult.error
    };
  }

  return {
    success: true,
    clone: parseResult.value as T
  };
}

/**
 * Validate that a value can be converted to JSON
 */
export function validateJSONConvertible(
  value: unknown,
  options: JSONConversionOptions = {}
): { valid: boolean; errors: string[]; warnings: string[] } {
  const result = toJSON(value, options);

  return {
    valid: result.success,
    errors: result.errors.map(e => e.message),
    warnings: result.warnings.map(w => w.message)
  };
}

/**
 * Format conversion result for logging
 */
export function formatConversionResult(result: JSONConversionResult): string {
  const lines = [
    `JSON Conversion ${result.success ? 'succeeded' : 'failed'}`,
    `Original type: ${typeof result.original}`,
    `Converted type: ${typeof result.value}`,
    `Stats: ${result.stats.totalProcessed} processed, ${result.stats.successfulConversions} successful, ${result.stats.failedConversions} failed`
  ];

  if (result.warnings.length > 0) {
    lines.push('Warnings:');
    result.warnings.forEach(warning => {
      lines.push(`  - ${warning.path}: ${warning.message} (${warning.code})`);
    });
  }

  if (result.errors.length > 0) {
    lines.push('Errors:');
    result.errors.forEach(error => {
      lines.push(`  - ${error.path}: ${error.message} (${error.code})`);
    });
  }

  if (result.stats.circularReferences > 0) {
    lines.push(`Circular references detected: ${result.stats.circularReferences}`);
  }

  if (result.stats.maxDepth > 0) {
    lines.push(`Maximum depth reached: ${result.stats.maxDepth}`);
  }

  lines.push(`Conversion duration: ${result.stats.durationMs}ms`);
  lines.push(`Size change: ${result.stats.inputSizeBytes} -> ${result.stats.outputSizeBytes} bytes`);

  return lines.join('\n');
}