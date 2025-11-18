/**
 * Configuration Merge Utilities with Type Safety
 *
 * This module provides comprehensive utilities for merging configuration objects
 * with type safety, conflict resolution, and detailed reporting of merge operations.
 */

import type { Config, JSONArray, JSONObject, MutableDict } from './base-types.js';
import { safeGetProperty } from './safe-property-access.js';

// Mutable version of Config for internal merge operations
type MutableConfig = MutableDict<import('./base-types.js').JSONValue>;

// ============================================================================
// Merge Configuration Types
// ============================================================================

/**
 * Merge strategy for handling conflicts
 */
export type MergeStrategy =
  | 'overwrite' // Later values overwrite earlier ones
  | 'preserve' // Keep earlier values, ignore later ones
  | 'merge' // Try to merge objects/arrays
  | 'error' // Throw error on conflicts
  | 'callback' // Use custom callback to resolve conflicts
  | 'prefer-source' // Prefer source object values
  | 'prefer-target'; // Prefer target object values

/**
 * Merge operation result
 */
export interface MergeResult {
  /** Whether merge was successful */
  readonly success: boolean;
  /** Merged configuration object */
  readonly merged: Config;
  /** Merge conflicts encountered */
  readonly conflicts: MergeConflict[];
  /** Merge warnings generated */
  readonly warnings: MergeWarning[];
  /** Merge operation statistics */
  readonly stats: MergeStats;
}

/**
 * Merge conflict information
 */
export interface MergeConflict {
  /** Conflict type */
  type: MergeConflictType;
  /** Path where conflict occurred */
  readonly path: string;
  /** Source value */
  readonly sourceValue: unknown;
  /** Target value */
  readonly targetValue: unknown;
  /** Resolved value (if conflict was resolved) */
  resolvedValue?: unknown;
  /** Resolution strategy used */
  resolution?: MergeStrategy;
  /** Custom resolution callback used */
  resolver?: ConflictResolver;
  /** Conflict description */
  description: string;
  /** Suggestions for resolving the conflict */
  readonly suggestions?: string[];
}

/**
 * Merge warning information
 */
export interface MergeWarning {
  /** Warning code */
  readonly code: MergeWarningCode;
  /** Warning message */
  readonly message: string;
  /** Path where warning occurred */
  readonly path: string;
  /** The values involved */
  readonly values: {
    readonly source?: unknown;
    readonly target?: unknown;
    readonly resolved?: unknown;
  };
  /** Warning severity level */
  readonly severity: 'low' | 'medium' | 'high';
}

/**
 * Merge operation statistics
 */
export interface MergeStats {
  /** Number of source objects merged */
  sourcesMerged: number;
  /** Number of target objects merged */
  targetsMerged: number;
  /** Number of properties processed */
  propertiesProcessed: number;
  /** Number of conflicts resolved */
  conflictsResolved: number;
  /** Number of conflicts unresolved */
  conflictsUnresolved: number;
  /** Number of warnings generated */
  warningsGenerated: number;
  /** Merge duration in milliseconds */
  durationMs: number;
  /** Size of merged configuration */
  mergedSize: number;
}

/**
 * Merge conflict types
 */
export type MergeConflictType =
  | 'TYPE_MISMATCH' // Types don't match and can't be merged
  | 'VALUE_CONFLICT' // Both have values but strategy is 'error'
  | 'STRUCTURE_MISMATCH' // Object/array structure doesn't match
  | 'READONLY_CONFLICT' // Attempting to modify read-only property
  | 'CIRCULAR_REFERENCE' // Circular reference detected during merge
  | 'DEPTH_EXCEEDED' // Maximum merge depth exceeded
  | 'INVALID_PATH' // Invalid property path
  | 'SERIALIZATION_ERROR'; // Error during value serialization

/**
 * Merge warning codes
 */
export type MergeWarningCode =
  | 'TYPE_COERCION' // Type was coerced during merge
  | 'LOSSY_MERGE' // Information was lost during merge
  | 'DEPRECATED_VALUE' // Deprecated value was used
  | 'DEFAULT_OVERRIDE' // Default value was overridden
  | 'EMPTY_MERGE' // Merged empty object/array
  | 'DUPLICATE_PROPERTY' // Property exists in multiple sources
  | 'CIRCULAR_REFERENCE'; // Circular reference detected

/**
 * Conflict resolver function
 */
export type ConflictResolver = (conflict: MergeConflict) => {
  resolved: boolean;
  value?: unknown;
  strategy?: MergeStrategy;
  message?: string;
};

/**
 * Merge options
 */
export interface MergeOptions {
  /** Default merge strategy */
  readonly defaultStrategy?: MergeStrategy;
  /** Custom conflict resolver */
  readonly conflictResolver?: ConflictResolver;
  /** Path-specific merge strategies */
  readonly pathStrategies?: Map<string, MergeStrategy>;
  /** Maximum merge depth */
  readonly maxDepth?: number;
  /** Whether to merge arrays */
  readonly mergeArrays?: boolean;
  /** Array merge strategy */
  readonly arrayStrategy?: 'append' | 'prepend' | 'replace' | 'merge' | 'intersect';
  /** Whether to handle circular references */
  readonly handleCircularRefs?: boolean;
  /** Whether to preserve read-only properties */
  readonly preserveReadOnly?: boolean;
  /** Whether to collect detailed statistics */
  readonly collectStats?: boolean;
  /** Progress callback for large merges */
  readonly onProgress?: (progress: MergeProgress) => void;
  /** Whether to clone source objects */
  readonly cloneSources?: boolean;
  /** Whether to validate merged values */
  readonly validateMerged?: boolean;
  /** Custom property transformers */
  readonly transformers?: Map<string, (value: unknown) => unknown>;
}

/**
 * Merge progress information
 */
export interface MergeProgress {
  /** Number of properties merged */
  readonly merged: number;
  /** Total number of properties (if known) */
  readonly total?: number;
  /** Current merge path */
  readonly currentPath: string;
  /** Current merge depth */
  readonly depth: number;
}

/**
 * Merge source definition
 */
export interface MergeSource {
  /** Source identifier */
  readonly id: string;
  /** Source priority (higher number = higher priority) */
  readonly priority: number;
  /** Source configuration object */
  readonly config: Config;
  /** Source metadata */
  readonly metadata?: Readonly<Record<string, unknown>>;
  /** Whether source is read-only */
  readonly readOnly?: boolean;
}

// ============================================================================
// Core Merge Engine
// ============================================================================

/**
 * Configuration merge engine
 */
export class ConfigMergeEngine {
  private readonly defaultOptions: Required<MergeOptions> = {
    defaultStrategy: 'merge',
    conflictResolver: undefined,
    pathStrategies: new Map(),
    maxDepth: 100,
    mergeArrays: true,
    arrayStrategy: 'merge',
    handleCircularRefs: true,
    preserveReadOnly: true,
    collectStats: false,
    onProgress: () => {},
    cloneSources: true,
    validateMerged: false,
    transformers: new Map(),
  };

  /**
   * Merge multiple configuration sources
   */
  merge(sources: MergeSource[], options: MergeOptions = {}): MergeResult {
    const mergedOptions = { ...this.defaultOptions, ...options };
    const startTime = Date.now();

    const conflicts: MergeConflict[] = [];
    const warnings: MergeWarning[] = [];
    const stats: MergeStats = {
      sourcesMerged: sources.length,
      targetsMerged: 0,
      propertiesProcessed: 0,
      conflictsResolved: 0,
      conflictsUnresolved: 0,
      warningsGenerated: 0,
      durationMs: 0,
      mergedSize: 0,
    };

    // Sort sources by priority (highest first)
    const sortedSources = [...sources].sort((a, b) => b.priority - a.priority);

    if (sortedSources.length === 0) {
      return {
        success: true,
        merged: {},
        conflicts: [],
        warnings: [
          {
            code: 'EMPTY_MERGE',
            message: 'No sources provided for merge',
            path: '',
            values: {},
            severity: 'low',
          },
        ],
        stats,
      };
    }

    // Start with highest priority source as base
    let merged: MutableConfig = this.cloneSource(sortedSources[0].config, mergedOptions);

    // Merge remaining sources
    for (let i = 1; i < sortedSources.length; i++) {
      const source = sortedSources[i];
      const sourceConfig = mergedOptions.cloneSources
        ? this.cloneSource(source.config, mergedOptions)
        : source.config;

      const mergeResult = this.mergeConfigs(
        merged,
        sourceConfig,
        source,
        mergedOptions,
        conflicts,
        warnings,
        stats
      );

      if (mergeResult.success) {
        merged = mergeResult.merged;
        stats.targetsMerged++;
      } else {
        // Handle merge failure
        conflicts.push(...mergeResult.conflicts);
        if (mergedOptions.defaultStrategy === 'error') {
          return {
            success: false,
            merged,
            conflicts,
            warnings,
            stats: {
              ...stats,
              durationMs: Date.now() - startTime,
            },
          };
        }
      }
    }

    // Calculate final stats
    stats.durationMs = Date.now() - startTime;
    stats.mergedSize = this.calculateSize(merged);

    return {
      success: conflicts.filter((c) => !c.resolvedValue).length === 0,
      merged,
      conflicts,
      warnings,
      stats,
    };
  }

  /**
   * Merge two configuration objects
   */
  mergeConfigs(
    target: Config,
    source: Config,
    sourceInfo: MergeSource,
    options: Required<MergeOptions>,
    conflicts: MergeConflict[],
    warnings: MergeWarning[],
    stats: MergeStats
  ): { success: boolean; merged: Config; conflicts: MergeConflict[] } {
    const newConflicts: MergeConflict[] = [];
    const merged: MutableConfig = { ...target };

    // Track visited objects for circular reference detection
    const visited = new WeakMap<object, string>();

    this.mergeValues(
      merged,
      source,
      '',
      visited,
      0,
      sourceInfo,
      options,
      newConflicts,
      warnings,
      stats
    );

    conflicts.push(...newConflicts);

    return {
      success: newConflicts.filter((c) => !c.resolvedValue).length === 0,
      merged,
      conflicts,
    };
  }

  /**
   * Merge values recursively
   */
  private mergeValues(
    target: JSONObject,
    source: JSONObject,
    path: string,
    visited: WeakMap<object, string>,
    depth: number,
    sourceInfo: MergeSource,
    options: Required<MergeOptions>,
    conflicts: MergeConflict[],
    warnings: MergeWarning[],
    stats: MergeStats
  ): void {
    if (depth > options.maxDepth) {
      conflicts.push({
        type: 'DEPTH_EXCEEDED',
        path,
        sourceValue: source,
        targetValue: target,
        description: `Maximum merge depth of ${options.maxDepth} exceeded`,
        suggestions: [`Increase maxDepth limit`, `Restructure configuration to reduce nesting`],
      });
      return;
    }

    stats.propertiesProcessed++;

    // Handle circular references
    if (typeof source === 'object' && source !== null) {
      const existingPath = visited.get(source);
      if (existingPath) {
        if (options.handleCircularRefs) {
          warnings.push({
            code: 'CIRCULAR_REFERENCE',
            message: `Circular reference detected: ${path} -> ${existingPath}`,
            path,
            values: { source, target },
            severity: 'medium',
          });
          return;
        } else {
          conflicts.push({
            type: 'CIRCULAR_REFERENCE',
            path,
            sourceValue: source,
            targetValue: target,
            description: `Circular reference detected: ${path} -> ${existingPath}`,
            suggestions: [`Enable circular reference handling`, `Restructure configuration`],
          });
          return;
        }
      }
      visited.set(source, path);
    }

    // Process each property in source
    for (const [key, sourceValue] of Object.entries(source)) {
      const currentPath = path ? `${path}.${key}` : key;
      stats.propertiesProcessed++;

      // Check if target has this property
      const targetResult = safeGetProperty(target, key);
      const targetHasProperty = targetResult.found;
      const targetValue = targetResult.value;

      // Apply path-specific strategy if available
      const pathStrategy = options.pathStrategies.get(currentPath);
      const strategy = pathStrategy || options.defaultStrategy;

      // Apply transformer if available
      const transformer = options.transformers.get(currentPath);
      const finalSourceValue = transformer ? transformer(sourceValue) : sourceValue;

      // Handle different merge strategies
      if (!targetHasProperty) {
        // Target doesn't have property - use source value
        this.setPropertySafely(target, key, finalSourceValue, options, sourceInfo);
      } else {
        // Both have property - handle conflict
        const conflict = this.handlePropertyConflict(
          currentPath,
          key,
          targetValue,
          finalSourceValue,
          strategy,
          sourceInfo,
          options
        );

        if (conflict) {
          conflicts.push(conflict);

          if (conflict.resolvedValue !== undefined) {
            this.setPropertySafely(target, key, conflict.resolvedValue, options, sourceInfo);
            stats.conflictsResolved++;
          } else {
            stats.conflictsUnresolved++;
          }
        } else {
          // No conflict, use appropriate merge strategy
          this.mergeProperty(
            target,
            key,
            targetValue,
            finalSourceValue,
            strategy,
            currentPath,
            visited,
            depth,
            sourceInfo,
            options,
            conflicts,
            warnings,
            stats
          );
        }
      }
    }
  }

  /**
   * Handle property conflict based on strategy
   */
  private handlePropertyConflict(
    path: string,
    key: string,
    targetValue: unknown,
    sourceValue: unknown,
    strategy: MergeStrategy,
    sourceInfo: MergeSource,
    options: Required<MergeOptions>
  ): MergeConflict | null {
    const conflict: MergeConflict = {
      type: this.getConflictType(targetValue, sourceValue),
      path,
      sourceValue,
      targetValue,
      description: `Conflict at ${path}: target has ${typeof targetValue}, source has ${typeof sourceValue}`,
      suggestions: this.getConflictSuggestions(targetValue, sourceValue, strategy),
    };

    switch (strategy) {
      case 'overwrite':
        conflict.resolvedValue = sourceValue;
        conflict.resolution = strategy;
        return conflict;

      case 'preserve':
        conflict.resolvedValue = targetValue;
        conflict.resolution = strategy;
        return conflict;

      case 'prefer-source':
        conflict.resolvedValue = sourceValue;
        conflict.resolution = strategy;
        return conflict;

      case 'prefer-target':
        conflict.resolvedValue = targetValue;
        conflict.resolution = strategy;
        return conflict;

      case 'error':
        conflict.resolution = strategy;
        return conflict;

      case 'callback':
        if (options.conflictResolver) {
          const result = options.conflictResolver(conflict);
          if (result.resolved) {
            conflict.resolvedValue = result.value;
            conflict.resolution = result.strategy;
            conflict.resolver = options.conflictResolver;
            if (result.message) {
              conflict.description = result.message;
            }
          }
        }
        return conflict;

      case 'merge':
        // Try to merge values
        const mergeResult = this.tryMergeValues(
          targetValue,
          sourceValue,
          path,
          sourceInfo,
          options
        );
        if (mergeResult.success) {
          conflict.resolvedValue = mergeResult.value;
          conflict.resolution = strategy;
          return conflict;
        } else {
          conflict.type = 'TYPE_MISMATCH';
          conflict.resolution = strategy;
          return conflict;
        }

      default:
        return conflict;
    }
  }

  /**
   * Merge individual properties based on strategy
   */
  private mergeProperty(
    target: JSONObject,
    key: string,
    targetValue: unknown,
    sourceValue: unknown,
    strategy: MergeStrategy,
    path: string,
    visited: WeakMap<object, string>,
    depth: number,
    sourceInfo: MergeSource,
    options: Required<MergeOptions>,
    conflicts: MergeConflict[],
    warnings: MergeWarning[],
    stats: MergeStats
  ): void {
    switch (strategy) {
      case 'overwrite':
        this.setPropertySafely(target, key, sourceValue, options, sourceInfo);
        break;

      case 'preserve':
        // Keep target value (already in target)
        break;

      case 'prefer-source':
        this.setPropertySafely(target, key, sourceValue, options, sourceInfo);
        break;

      case 'prefer-target':
        // Keep target value (already in target)
        break;

      case 'merge':
        const mergeResult = this.tryMergeValues(
          targetValue,
          sourceValue,
          path,
          sourceInfo,
          options
        );
        if (mergeResult.success) {
          this.setPropertySafely(target, key, mergeResult.value, options, sourceInfo);
        } else {
          // Fallback to overwrite if merge fails
          this.setPropertySafely(target, key, sourceValue, options, sourceInfo);
          warnings.push({
            code: 'LOSSY_MERGE',
            message: `Could not merge values at ${path}, using source value`,
            path,
            values: { source: sourceValue, target: targetValue, resolved: sourceValue },
            severity: 'medium',
          });
        }
        break;

      case 'callback':
        if (options.conflictResolver) {
          const conflict: MergeConflict = {
            type: this.getConflictType(targetValue, sourceValue),
            path,
            sourceValue,
            targetValue,
            description: `Conflict at ${path}`,
            suggestions: [],
          };

          const result = options.conflictResolver(conflict);
          if (result.resolved && result.value !== undefined) {
            this.setPropertySafely(target, key, result.value, options, sourceInfo);
          }
        }
        break;

      default:
        // Default to overwrite
        this.setPropertySafely(target, key, sourceValue, options, sourceInfo);
    }
  }

  /**
   * Try to merge two values
   */
  private tryMergeValues(
    targetValue: unknown,
    sourceValue: unknown,
    path: string,
    sourceInfo: MergeSource,
    options: Required<MergeOptions>
  ): { success: boolean; value: unknown } {
    // Handle object merging
    if (
      targetValue !== null &&
      typeof targetValue === 'object' &&
      sourceValue !== null &&
      typeof sourceValue === 'object' &&
      !Array.isArray(targetValue) &&
      !Array.isArray(sourceValue)
    ) {
      const merged: JSONObject = { ...(targetValue as JSONObject), ...(sourceValue as JSONObject) };
      return { success: true, value: merged };
    }

    // Handle array merging
    if (Array.isArray(targetValue) && Array.isArray(sourceValue) && options.mergeArrays) {
      return this.mergeArrays(targetValue, sourceValue, options.arrayStrategy);
    }

    // Types don't match or can't be merged
    return { success: false, value: undefined };
  }

  /**
   * Merge two arrays
   */
  private mergeArrays(
    target: JSONArray,
    source: JSONArray,
    strategy: 'append' | 'prepend' | 'replace' | 'merge' | 'intersect'
  ): { success: boolean; value: unknown } {
    switch (strategy) {
      case 'append':
        return { success: true, value: [...target, ...source] };

      case 'prepend':
        return { success: true, value: [...source, ...target] };

      case 'replace':
        return { success: true, value: source };

      case 'intersect':
        const intersection = target.filter((item) => source.includes(item));
        return { success: true, value: intersection };

      case 'merge':
        // Combine arrays and remove duplicates
        const combined = [...target, ...source];
        const unique = Array.from(new Set(combined));
        return { success: true, value: unique };

      default:
        return { success: false, value: undefined };
    }
  }

  /**
   * Safely set a property with read-only checks
   */
  private setPropertySafely(
    target: JSONObject,
    key: string,
    value: unknown,
    options: Required<MergeOptions>,
    sourceInfo: MergeSource
  ): void {
    if (options.preserveReadOnly && sourceInfo.readOnly) {
      return; // Don't modify read-only sources
    }

    target[key] = value as import('./base-types.js').JSONValue;
  }

  /**
   * Clone a source object
   */
  private cloneSource(source: Config, options: Required<MergeOptions>): MutableConfig {
    try {
      return JSON.parse(JSON.stringify(source));
    } catch (error) {
      // Fallback to shallow copy if deep clone fails
      return { ...source };
    }
  }

  /**
   * Get conflict type based on values
   */
  private getConflictType(targetValue: unknown, sourceValue: unknown): MergeConflictType {
    const targetType = targetValue === null ? 'null' : typeof targetValue;
    const sourceType = sourceValue === null ? 'null' : typeof sourceValue;

    if (targetType !== sourceType) {
      return 'TYPE_MISMATCH';
    }

    if (targetType === 'object' && sourceType === 'object') {
      const targetIsArray = Array.isArray(targetValue);
      const sourceIsArray = Array.isArray(sourceValue);
      if (targetIsArray !== sourceIsArray) {
        return 'STRUCTURE_MISMATCH';
      }
    }

    return 'VALUE_CONFLICT';
  }

  /**
   * Get suggestions for resolving conflicts
   */
  private getConflictSuggestions(
    targetValue: unknown,
    sourceValue: unknown,
    strategy: MergeStrategy
  ): string[] {
    const suggestions: string[] = [];

    switch (strategy) {
      case 'merge':
        if (typeof targetValue === 'object' && typeof sourceValue === 'object') {
          suggestions.push(
            'Objects will be merged, source properties will overwrite target properties'
          );
        } else {
          suggestions.push(
            'Cannot merge different types, consider using overwrite or preserve strategy'
          );
        }
        break;

      case 'error':
        suggestions.push('Provide a conflict resolver callback to handle this conflict');
        suggestions.push('Change merge strategy to avoid this conflict');
        break;

      default:
        suggestions.push(`Using ${strategy} strategy to resolve conflict`);
    }

    return suggestions;
  }

  /**
   * Calculate approximate size of configuration object
   */
  private calculateSize(config: Config): number {
    try {
      return JSON.stringify(config).length;
    } catch {
      return Object.keys(config).length;
    }
  }
}

// ============================================================================
// Pre-built Merge Strategies and Resolvers
// ============================================================================

/**
 * Create a conflict resolver that prefers newer values
 */
export function preferNewerResolver(): ConflictResolver {
  return (conflict) => {
    return {
      resolved: true,
      value: conflict.sourceValue,
      strategy: 'prefer-source',
      message: `Prefered newer value from source`,
    };
  };
}

/**
 * Create a conflict resolver that prefers older values
 */
export function preferOlderResolver(): ConflictResolver {
  return (conflict) => {
    return {
      resolved: true,
      value: conflict.targetValue,
      strategy: 'prefer-target',
      message: `Preserved existing value from target`,
    };
  };
}

/**
 * Create a conflict resolver for numeric values (uses max)
 */
export function numericMaxResolver(): ConflictResolver {
  return (conflict) => {
    const targetNum = typeof conflict.targetValue === 'number' ? conflict.targetValue : NaN;
    const sourceNum = typeof conflict.sourceValue === 'number' ? conflict.sourceValue : NaN;

    if (!isNaN(targetNum) && !isNaN(sourceNum)) {
      const maxValue = Math.max(targetNum, sourceNum);
      return {
        resolved: true,
        value: maxValue,
        message: `Used maximum value: ${maxValue}`,
      };
    }

    return {
      resolved: false,
      message: 'Cannot resolve non-numeric values',
    };
  };
}

/**
 * Create a conflict resolver for numeric values (uses min)
 */
export function numericMinResolver(): ConflictResolver {
  return (conflict) => {
    const targetNum = typeof conflict.targetValue === 'number' ? conflict.targetValue : NaN;
    const sourceNum = typeof conflict.sourceValue === 'number' ? conflict.sourceValue : NaN;

    if (!isNaN(targetNum) && !isNaN(sourceNum)) {
      const minValue = Math.min(targetNum, sourceNum);
      return {
        resolved: true,
        value: minValue,
        message: `Used minimum value: ${minValue}`,
      };
    }

    return {
      resolved: false,
      message: 'Cannot resolve non-numeric values',
    };
  };
}

/**
 * Create a conflict resolver for array values (concatenates)
 */
export function arrayConcatResolver(): ConflictResolver {
  return (conflict) => {
    if (Array.isArray(conflict.targetValue) && Array.isArray(conflict.sourceValue)) {
      const concatenated = [...conflict.targetValue, ...conflict.sourceValue];
      return {
        resolved: true,
        value: concatenated,
        message: `Concatenated arrays (${conflict.targetValue.length} + ${conflict.sourceValue.length} items)`,
      };
    }

    return {
      resolved: false,
      message: 'Cannot concatenate non-array values',
    };
  };
}

/**
 * Create a conflict resolver for string values (concatenates with separator)
 */
export function stringConcatResolver(separator: string = ', '): ConflictResolver {
  return (conflict) => {
    const targetStr =
      typeof conflict.targetValue === 'string'
        ? conflict.targetValue
        : String(conflict.targetValue);
    const sourceStr =
      typeof conflict.sourceValue === 'string'
        ? conflict.sourceValue
        : String(conflict.sourceValue);

    const concatenated = targetStr
      ? sourceStr
        ? `${targetStr}${separator}${sourceStr}`
        : targetStr
      : sourceStr;

    return {
      resolved: true,
      value: concatenated,
      message: `Concatenated strings with separator: ${separator}`,
    };
  };
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create a default merge engine
 */
export function createMergeEngine(): ConfigMergeEngine {
  return new ConfigMergeEngine();
}

/**
 * Merge configurations with sensible defaults
 */
export function mergeConfigs(sources: MergeSource[], options: MergeOptions = {}): MergeResult {
  const engine = new ConfigMergeEngine();
  return engine.merge(sources, options);
}

/**
 * Merge two configurations
 */
export function mergeTwoConfigs(
  target: Config,
  source: Config,
  options: MergeOptions = {}
): MergeResult {
  const engine = new ConfigMergeEngine();
  const sourceInfo: MergeSource = {
    id: 'source',
    priority: 10,
    config: source,
    readOnly: false,
  };

  const targetInfo: MergeSource = {
    id: 'target',
    priority: 5,
    config: target,
    readOnly: false,
  };

  return engine.merge([targetInfo, sourceInfo], options);
}

/**
 * Create a merge source
 */
export function createMergeSource(
  id: string,
  config: Config,
  priority: number = 0,
  metadata?: Record<string, unknown>,
  readOnly: boolean = false
): MergeSource {
  return {
    id,
    priority,
    config,
    metadata,
    readOnly,
  };
}

/**
 * Create merge source from environment variables
 */
export function createEnvSource(prefix: string = '', priority: number = 10): MergeSource {
  const config: MutableConfig = {};

  if (typeof process !== 'undefined' && process.env) {
    for (const [key, value] of Object.entries(process.env)) {
      if (key.startsWith(prefix)) {
        const configKey = key.substring(prefix.length).toLowerCase();
        config[configKey] = value as import('./base-types.js').JSONValue;
      }
    }
  }

  return createMergeSource('environment', config, priority, {
    source: 'environment',
    prefix,
  });
}

/**
 * Create merge source from command line arguments
 */
export function createArgSource(argv: string[] = process.argv, priority: number = 20): MergeSource {
  const config: MutableConfig = {};
  const args = argv.slice(2); // Remove node and script name

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const nextArg = args[i + 1];

      if (key.includes('=')) {
        // --key=value format
        const [k, v] = key.split('=', 2);
        config[k] = v as import('./base-types.js').JSONValue;
      } else if (nextArg && !nextArg.startsWith('--')) {
        // --key value format
        config[key] = nextArg as import('./base-types.js').JSONValue;
        i++; // Skip the next arg
      } else {
        // --key (boolean flag)
        config[key] = true as import('./base-types.js').JSONValue;
      }
    }
  }

  return createMergeSource('command-line', config, priority, {
    source: 'command-line',
  });
}

/**
 * Format merge result for logging
 */
export function formatMergeResult(result: MergeResult): string {
  const lines = [
    `Configuration merge ${result.success ? 'succeeded' : 'failed'}`,
    `Sources merged: ${result.stats.sourcesMerged}`,
    `Properties processed: ${result.stats.propertiesProcessed}`,
    `Conflicts resolved: ${result.stats.conflictsResolved}`,
    `Conflicts unresolved: ${result.stats.conflictsUnresolved}`,
    `Warnings generated: ${result.stats.warningsGenerated}`,
    `Merge duration: ${result.stats.durationMs}ms`,
    `Merged config size: ${result.stats.mergedSize} bytes`,
  ];

  if (result.conflicts.length > 0) {
    lines.push('\nConflicts:');
    result.conflicts.slice(0, 10).forEach((conflict) => {
      lines.push(`  - ${conflict.path}: ${conflict.description}`);
      if (conflict.resolution) {
        lines.push(
          `    Resolution: ${conflict.resolution} -> ${JSON.stringify(conflict.resolvedValue)}`
        );
      }
    });

    if (result.conflicts.length > 10) {
      lines.push(`  ... and ${result.conflicts.length - 10} more conflicts`);
    }
  }

  if (result.warnings.length > 0) {
    lines.push('\nWarnings:');
    result.warnings.slice(0, 10).forEach((warning) => {
      lines.push(`  - ${warning.path}: ${warning.message} (${warning.code})`);
    });

    if (result.warnings.length > 10) {
      lines.push(`  ... and ${result.warnings.length - 10} more warnings`);
    }
  }

  return lines.join('\n');
}

/**
 * Validate merge result
 */
export function validateMergeResult(result: MergeResult): {
  valid: boolean;
  errors: string[];
  warnings: string[];
} {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Check for unresolved conflicts
  if (result.stats.conflictsUnresolved > 0) {
    errors.push(`${result.stats.conflictsUnresolved} conflicts were not resolved`);
  }

  // Check for critical warnings
  const criticalWarnings = result.warnings.filter((w) => w.severity === 'high');
  if (criticalWarnings.length > 0) {
    warnings.push(`${criticalWarnings.length} high-severity warnings generated`);
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}
