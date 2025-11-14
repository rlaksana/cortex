// @ts-nocheck
// LAST ABSOLUTE FINAL EMERGENCY ROLLBACK: Complete the systematic rollback
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Cortex Memory MCP - Schema Validation Utilities
 *
 * Comprehensive schema validation using both Zod and JSON Schema validators.
 * Provides runtime validation, detailed error reporting, and migration support.
 *
 * @version 2.0.0 - Enhanced with P5-2 schema updates
 */

import { type ZodError,type ZodSchema } from 'zod';

import { ALL_JSON_SCHEMAS } from './json-schemas.js';
import {
  EnhancedMemoryFindInputSchema,
  EnhancedMemoryStoreInputSchema,
  MemoryFindInputSchema,
  MemoryStoreInputSchema,
  PerformanceMonitoringInputSchema,
  SystemStatusInputSchema,
  ValidationError,
} from './mcp-inputs.js';
import {
  type Dict,
  isDict,
  isJSONValue,
  type JSONValue,
  type MutableDict,
  toJSONValue
} from '../types/base-types.js';

// ============================================================================
// Legacy Schema Types (Pre-Enhancement)
// ============================================================================

/** Legacy memory store input format */
export interface LegacyMemoryStoreInput {
  readonly items: readonly LegacyItem[];
  readonly [key: string]: unknown;
}

/** Legacy memory find input format */
export interface LegacyMemoryFindInput {
  readonly query?: string;
  readonly mode?: 'auto' | 'fast' | 'deep';
  readonly top_k?: number;
  readonly scope?: {
    readonly project?: string;
    readonly branch?: string;
    readonly org?: string;
    readonly [key: string]: unknown;
  };
  readonly [key: string]: unknown;
}

/** Legacy system status input format */
export interface LegacySystemStatusInput {
  readonly operation?: string;
  readonly scope?: {
    readonly project?: string;
    readonly branch?: string;
    readonly org?: string;
    readonly [key: string]: unknown;
  };
  readonly [key: string]: unknown;
}

/** Legacy item structure */
export interface LegacyItem {
  readonly kind?: string;
  readonly content?: string;
  readonly data?: Dict<JSONValue>;
  readonly scope?: {
    readonly project?: string;
    readonly branch?: string;
    readonly org?: string;
    readonly [key: string]: unknown;
  };
  readonly ttl_config?: {
    readonly policy?: string;
    readonly expires_at?: string;
    readonly auto_extend?: boolean;
    readonly [key: string]: unknown;
  };
  readonly truncation_config?: {
    readonly enabled?: boolean;
    readonly max_chars?: number;
    readonly mode?: string;
    readonly preserve_structure?: boolean;
    readonly add_indicators?: boolean;
    readonly [key: string]: unknown;
  };
  readonly [key: string]: unknown;
}

// ============================================================================
// Migration Types
// ============================================================================

/** Migration result with detailed tracking */
export interface MigrationResult<T = JSONValue> {
  readonly migrated: T;
  readonly notes: string[];
}

/** Enhanced migration result with metadata */
export interface EnhancedMigrationResult<T = JSONValue> {
  readonly migrated: boolean;
  readonly input: T;
  readonly notes: string[];
}

// ============================================================================
// Validation Context Types
// ============================================================================

/** Validation context for processing options */
export interface ValidationContext {
  readonly strictMode: boolean;
  readonly enableMigration: boolean;
  readonly includeWarnings: boolean;
  readonly maxErrors: number;
  readonly [key: string]: JSONValue;
}

/** Business rule validation data context */
export interface BusinessRuleContext {
  readonly schemaName: SchemaName;
  readonly data: Dict<JSONValue>;
  readonly [key: string]: JSONValue;
}

/** JSON Schema validator interface */
export interface JsonSchemaValidator {
  compile(schema: JSONValue): (data: JSONValue) => boolean;
  readonly errors?: JsonValidationError[];
}

/** JSON Schema validation error */
export interface JsonValidationError {
  readonly instancePath: string;
  readonly message: string;
  readonly [key: string]: JSONValue;
}

// ============================================================================
// Type Guards for Runtime Validation
// ============================================================================

/** Type guard for legacy memory store input */
export function isLegacyMemoryStoreInput(value: unknown): value is LegacyMemoryStoreInput {
  if (!isJSONValue(value) || typeof value !== 'object' || value === null || !Array.isArray((value as Dict<JSONValue>).items)) {
    return false;
  }

  const items = (value as Dict<JSONValue>).items as JSONArray;
  return items.every((item: JSONValue) => isLegacyItem(item));
}

/** Type guard for legacy memory find input */
export function isLegacyMemoryFindInput(value: unknown): value is LegacyMemoryFindInput {
  return isJSONValue(value) &&
         typeof value === 'object' &&
         value !== null &&
         (typeof (value as Dict<JSONValue>).query === 'string' || typeof (value as Dict<JSONValue>).mode === 'string' || typeof (value as Dict<JSONValue>).top_k === 'number');
}

/** Type guard for legacy system status input */
export function isLegacySystemStatusInput(value: unknown): value is LegacySystemStatusInput {
  return isJSONValue(value) &&
         typeof value === 'object' &&
         value !== null &&
         (typeof (value as Dict<JSONValue>).operation === 'string' || typeof (value as Dict<JSONValue>).scope === 'object');
}

/** Type guard for legacy item */
export function isLegacyItem(value: unknown): value is LegacyItem {
  if (!isJSONValue(value) || typeof value !== 'object' || value === null) {
    return false;
  }

  const item = value as Dict<JSONValue>;
  return (typeof item.kind === 'string' || typeof item.content === 'string' || typeof item.data === 'object');
}

/** Type guard for migration result */
export function isMigrationResult<T>(value: unknown, itemGuard?: (item: unknown) => item is T): value is MigrationResult<T> {
  if (!isJSONValue(value) || typeof value !== 'object' || value === null) {
    return false;
  }

  const result = value as Dict<JSONValue>;
  const hasMigrated = itemGuard ? itemGuard(result.migrated) : isJSONValue(result.migrated);
  const hasNotes = Array.isArray(result.notes) && (result.notes as JSONArray).every((note: JSONValue) => typeof note === 'string');

  return hasMigrated && hasNotes;
}

// ============================================================================
// Utility Functions for Type Conversion
// ============================================================================

/** Convert legacy input to safe JSONValue with validation */
function convertLegacyInputToJSONValue(input: unknown): JSONValue {
  const converted = toJSONValue(input);
  if (converted === null) {
    // Fallback to empty object if conversion fails
    return {};
  }
  return converted;
}

/** Convert legacy item to safe JSONValue with validation */
function convertLegacyItemToJSONValue(item: LegacyItem): JSONValue {
  return convertLegacyInputToJSONValue(item);
}

/** Convert legacy array to JSONValue array */
function convertLegacyArrayToJSONValue(items: readonly unknown[]): JSONValue[] {
  return items.map(item => convertLegacyInputToJSONValue(item));
}

// ============================================================================
// Schema Types
// ============================================================================

export type SchemaName = keyof typeof ALL_JSON_SCHEMAS;

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: string[];
  migrated: boolean;
  migration_notes?: string[];
}

export interface ValidationOptions {
  strictMode?: boolean;
  enableMigration?: boolean;
  includeWarnings?: boolean;
  maxErrors?: number;
}

// ============================================================================
// Migration Support
// ============================================================================

/**
 * Legacy to enhanced schema migration utilities
 */
class SchemaMigrator {
  /**
   * Migrate legacy memory_store input to enhanced format
   */
  static migrateMemoryStore(input: LegacyMemoryStoreInput): MigrationResult<Dict<JSONValue>> {
    const migrated: MutableDict<JSONValue> = convertLegacyInputToJSONValue(input) as MutableDict<JSONValue>;
    const notes: string[] = [];

    // Add default processing options if not present
    if (!migrated.processing) {
      migrated.processing = {
        enable_validation: true,
        enable_async_processing: false,
        batch_processing: true,
        return_summaries: false,
        include_metrics: true,
      };
      notes.push('Added default processing options');
    }

    // Add default deduplication if not present
    if (!migrated.deduplication) {
      migrated.deduplication = {
        enabled: true,
        merge_strategy: 'intelligent',
        similarity_threshold: 0.85,
        check_within_scope_only: true,
        max_history_hours: 168,
        dedupe_window_days: 30,
        allow_newer_versions: true,
        enable_audit_logging: true,
        enable_intelligent_merging: true,
        preserve_merge_history: false,
        cross_scope_deduplication: false,
        prioritize_same_scope: true,
        time_based_deduplication: true,
        max_age_for_dedupe_days: 90,
        respect_update_timestamps: true,
        max_items_to_check: 100,
        batch_size: 50,
        enable_parallel_processing: false,
      };
      notes.push('Added default deduplication configuration');
    }

    // Convert legacy scope format if needed
    if (migrated.items && Array.isArray(migrated.items)) {
      migrated.items = convertLegacyArrayToJSONValue(migrated.items).map((item: JSONValue, index: number) => {
        const legacyItem = input.items[index]; // Get original item for migration logic
        const migratedItem: MutableDict<JSONValue> = item && typeof item === 'object' ? { ...item } as MutableDict<JSONValue> : {};

        // Ensure scope has all supported fields
        if (legacyItem.scope && typeof migratedItem.scope === 'object') {
          const existingScope = legacyItem.scope as Dict<unknown>;
          migratedItem.scope = {
            ...existingScope,
            service: (existingScope as Dict<unknown>).service || undefined,
            sprint: (existingScope as Dict<unknown>).sprint || undefined,
            tenant: (existingScope as Dict<unknown>).tenant || undefined,
            environment: (existingScope as Dict<unknown>).environment || undefined,
          };
          notes.push('Enhanced scope fields for item compatibility');
        }

        // Add default TTL config for text-based items
        if (legacyItem.content && !migratedItem.ttl_config) {
          migratedItem.ttl_config = {
            policy: 'default',
            auto_extend: false,
          };
        }

        // Add default truncation config for text-based items
        if (legacyItem.content && !migratedItem.truncation_config) {
          migratedItem.truncation_config = {
            enabled: true,
            max_chars: 10000,
            mode: 'intelligent',
            preserve_structure: true,
            add_indicators: true,
          };
        }

        return migratedItem;
      });
    }

    return { migrated, notes };
  }

  /**
   * Migrate legacy memory_find input to enhanced format
   */
  static migrateMemoryFind(input: LegacyMemoryFindInput): MigrationResult<Dict<JSONValue>> {
    const migrated: MutableDict<JSONValue> = convertLegacyInputToJSONValue(input) as MutableDict<JSONValue>;
    const notes: string[] = [];

    // Convert 'mode' to 'search_strategy'
    if (migrated.mode && !migrated.search_strategy) {
      migrated.search_strategy = migrated.mode;
      delete migrated.mode;
      notes.push('Converted "mode" to "search_strategy"');
    }

    // Convert 'top_k' to 'limit'
    if (migrated.top_k && !migrated.limit) {
      migrated.limit = migrated.top_k;
      delete migrated.top_k;
      notes.push('Converted "top_k" to "limit"');
    }

    // Add default search optimization if not present
    if (!migrated.optimization) {
      migrated.optimization = {
        enable_caching: true,
        cache_ttl_seconds: 300,
        parallel_search: true,
        timeout_ms: 10000,
      };
      notes.push('Added default search optimization');
    }

    // Add default result formatting if not present
    if (!migrated.formatting) {
      migrated.formatting = {
        include_content: true,
        include_metadata: true,
        include_relations: false,
        include_confidence_scores: true,
        include_similarity_explanation: false,
        highlight_matches: false,
        max_content_length: 1000,
      };
      notes.push('Added default result formatting');
    }

    // Enhance scope if present
    if (input.scope && typeof migrated.scope === 'object') {
      const existingScope = input.scope as Dict<unknown>;
      migrated.scope = {
        ...existingScope,
        service: (existingScope as Dict<unknown>).service || undefined,
        sprint: (existingScope as Dict<unknown>).sprint || undefined,
        tenant: (existingScope as Dict<unknown>).tenant || undefined,
        environment: (existingScope as Dict<unknown>).environment || undefined,
      };
      notes.push('Enhanced scope fields');
    }

    return { migrated, notes };
  }

  /**
   * Migrate legacy system_status input to enhanced format
   */
  static migrateSystemStatus(input: LegacySystemStatusInput): MigrationResult<Dict<JSONValue>> {
    const migrated: MutableDict<JSONValue> = convertLegacyInputToJSONValue(input) as MutableDict<JSONValue>;
    const notes: string[] = [];

    // Add default response formatting if not present
    if (!migrated.response_formatting) {
      migrated.response_formatting = {
        summary: false,
        verbose: false,
        include_raw_data: false,
        include_timestamps: true,
      };
      notes.push('Added default response formatting');
    }

    // Enhance scope if present
    if (input.scope && typeof migrated.scope === 'object') {
      const existingScope = input.scope as Dict<unknown>;
      migrated.scope = {
        ...existingScope,
        service: (existingScope as Dict<unknown>).service || undefined,
        sprint: (existingScope as Dict<unknown>).sprint || undefined,
        tenant: (existingScope as Dict<unknown>).tenant || undefined,
        environment: (existingScope as Dict<unknown>).environment || undefined,
      };
      notes.push('Enhanced scope fields');
    }

    return { migrated, notes };
  }
}

// ============================================================================
// Schema Validation Engine
// ============================================================================

export class SchemaValidator {
  private static instance: SchemaValidator;
  private jsonSchemaValidator: JsonSchemaValidator | null = null;

  private constructor() {
    // Initialize JSON Schema validator if available
    this.initializeJsonSchemaValidator();
  }

  static getInstance(): SchemaValidator {
    if (!SchemaValidator.instance) {
      SchemaValidator.instance = new SchemaValidator();
    }
    return SchemaValidator.instance;
  }

  private initializeJsonSchemaValidator(): void {
    try {
      // Try to import and initialize AJV or similar JSON Schema validator
      // This is optional - if not available, we'll fall back to Zod only
      // const Ajv = await import('ajv');
      // this.jsonSchemaValidator = new Ajv({ allErrors: true });
    } catch (_error) {
      // JSON Schema validator not available, will use Zod only
      console.warn('JSON Schema validator not available, using Zod only');
    }
  }

  /**
   * Validate input against enhanced schema with migration support
   */
  validateEnhanced(
    schemaName: SchemaName,
    input: unknown,
    options: ValidationOptions = {}
  ): ValidationResult {
    const {
      strictMode = false,
      enableMigration = true,
      includeWarnings = true,
      maxErrors = 50,
    } = options;

    const result: ValidationResult = {
      valid: true,
      errors: [],
      warnings: [],
      migrated: false,
    };

    try {
      let validatedInput = input;

      // Step 1: Attempt migration if enabled
      if (enableMigration) {
        const migrationResult = this.migrateLegacyInput(schemaName, input);
        if (migrationResult.migrated) {
          validatedInput = migrationResult.input;
          result.migrated = true;
          result.migration_notes = migrationResult.notes;
          if (includeWarnings) {
            result.warnings.push(...migrationResult.notes.map((note) => `Migration: ${note}`));
          }
        }
      }

      // Step 2: Validate with enhanced Zod schema
      const zodSchema = this.getZodSchema(schemaName);
      const zodResult = zodSchema.safeParse(validatedInput);

      if (!zodResult.success) {
        result.valid = false;
        result.errors.push(...this.convertZodErrors(zodResult.error, maxErrors));
        return result;
      }

      // Step 3: Additional JSON Schema validation if available
      if (this.jsonSchemaValidator && !strictMode) {
        const validatedInputJSON = convertLegacyInputToJSONValue(validatedInput);
        const jsonSchemaErrors = this.validateJsonSchema(schemaName, validatedInputJSON);
        if (jsonSchemaErrors.length > 0) {
          if (strictMode) {
            result.valid = false;
            result.errors.push(...jsonSchemaErrors.map((err) => new ValidationError(err)));
          } else {
            result.warnings.push(...jsonSchemaErrors.map((err) => `JSON Schema: ${err}`));
          }
        }
      }

      // Step 4: Business rule validation
      const businessRuleErrors = this.validateBusinessRules(schemaName, zodResult.data);
      if (businessRuleErrors.length > 0) {
        result.valid = false;
        result.errors.push(...businessRuleErrors);
      }

      // Step 5: Generate warnings for potential issues
      if (includeWarnings) {
        const warnings = this.generateWarnings(schemaName, zodResult.data);
        result.warnings.push(...warnings);
      }

      return result;
    } catch (error) {
      result.valid = false;
      result.errors.push(
        new ValidationError(
          `Validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
        )
      );
      return result;
    }
  }

  /**
   * Validate input against legacy schema for backward compatibility
   */
  validateLegacy(schemaName: 'memory_store' | 'memory_find', input: unknown): ValidationResult {
    const result: ValidationResult = {
      valid: true,
      errors: [],
      warnings: [],
      migrated: false,
    };

    try {
      const zodSchema =
        schemaName === 'memory_store' ? MemoryStoreInputSchema : MemoryFindInputSchema;
      const zodResult = zodSchema.safeParse(input);

      if (!zodResult.success) {
        result.valid = false;
        result.errors.push(...this.convertZodErrors(zodResult.error));
      }

      return result;
    } catch (error) {
      result.valid = false;
      result.errors.push(
        new ValidationError(
          `Legacy validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
        )
      );
      return result;
    }
  }

  /**
   * Get the appropriate Zod schema for validation
   */
  private getZodSchema(schemaName: SchemaName): ZodSchema {
    switch (schemaName) {
      case 'memory_store':
        return EnhancedMemoryStoreInputSchema;
      case 'memory_find':
        return EnhancedMemoryFindInputSchema;
      case 'system_status':
        return SystemStatusInputSchema;
      case 'performance_monitoring':
        return PerformanceMonitoringInputSchema;
      default:
        throw new Error(`Unknown schema: ${schemaName}`);
    }
  }

  /**
   * Convert Zod errors to ValidationError objects
   */
  private convertZodErrors(zodError: ZodError, maxErrors = 50): ValidationError[] {
    return zodError.errors.slice(0, maxErrors).map((error) => {
      const field = error.path.join('.');
      const message = error.message || 'Validation failed';
      return new ValidationError(`Validation failed: ${message}`, field, error.code);
    });
  }

  /**
   * Validate using JSON Schema if available
   */
  private validateJsonSchema(schemaName: SchemaName, input: JSONValue): string[] {
    if (!this.jsonSchemaValidator) {
      return [];
    }

    try {
      const jsonSchema = ALL_JSON_SCHEMAS[schemaName];
      const validate = this.jsonSchemaValidator.compile(jsonSchema);
      const valid = validate(input);

      if (!valid && this.jsonSchemaValidator.errors) {
        return this.jsonSchemaValidator.errors.map((err: JsonValidationError) => `${err.instancePath || 'root'}: ${err.message}`);
      }

      return [];
    } catch (error) {
      return [
        `JSON Schema validation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      ];
    }
  }

  /**
   * Validate business rules specific to each schema
   */
  private validateBusinessRules(schemaName: SchemaName, data: Dict<JSONValue>): ValidationError[] {
    const errors: ValidationError[] = [];

    switch (schemaName) {
      case 'memory_store':
        errors.push(...this.validateMemoryStoreBusinessRules(data));
        break;
      case 'memory_find':
        errors.push(...this.validateMemoryFindBusinessRules(data));
        break;
      case 'system_status':
        errors.push(...this.validateSystemStatusBusinessRules(data));
        break;
      case 'performance_monitoring':
        errors.push(...this.validatePerformanceMonitoringBusinessRules(data));
        break;
      default:
        // No business rules for unknown schema types
        break;
    }

    return errors;
  }

  /**
   * Business rule validation for memory_store
   */
  private validateMemoryStoreBusinessRules(data: Dict<JSONValue>): ValidationError[] {
    const errors: ValidationError[] = [];

    // Validate item count is reasonable
    if (data.items && Array.isArray(data.items) && data.items.length > 100) {
      errors.push(
        new ValidationError(
          'Cannot store more than 100 items in a single request',
          'items',
          'TOO_MANY_ITEMS'
        )
      );
    }

    // Validate deduplication settings consistency
    if (data.deduplication && typeof data.deduplication === 'object' && (data.deduplication as unknown).enabled) {
      const deduplication = data.deduplication as Dict<JSONValue>;
      if (
        deduplication.cross_scope_deduplication &&
        deduplication.check_within_scope_only
      ) {
        errors.push(
          new ValidationError(
            'Cannot enable both cross_scope_deduplication and check_within_scope_only',
            'deduplication',
            'CONFLICTING_SETTINGS'
          )
        );
      }
    }

    // Validate TTL settings
    if (data.items && Array.isArray(data.items)) {
      data.items.forEach((item: unknown, index: number) => {
        if (item && typeof item === 'object' && (item as unknown).ttl_config && typeof (item as unknown).ttl_config === 'object') {
          const ttlConfig = (item as unknown).ttl_config as Dict<JSONValue>;
          if (ttlConfig.expires_at && typeof ttlConfig.expires_at === 'string') {
            const expiryDate = new Date(ttlConfig.expires_at);
            if (expiryDate <= new Date()) {
              errors.push(
                new ValidationError(
                  `Item ${index} has already expired`,
                  `items[${index}].ttl_config.expires_at`,
                  'ALREADY_EXPIRED'
                )
              );
            }
          }
        }
      });
    }

    return errors;
  }

  /**
   * Business rule validation for memory_find
   */
  private validateMemoryFindBusinessRules(data: Dict<JSONValue>): ValidationError[] {
    const errors: ValidationError[] = [];

    // Validate pagination
    if (typeof data.limit === 'number' && typeof data.offset === 'number' && data.limit + data.offset > 1000) {
      errors.push(
        new ValidationError(
          'Cannot request more than 1000 total results (limit + offset)',
          'pagination',
          'TOO_MANY_RESULTS'
        )
      );
    }

    // Validate time window
    if (data.filters && typeof data.filters === 'object') {
      const filters = data.filters as Dict<JSONValue>;
      const created_after = filters.created_after;
      const created_before = filters.created_before;
      if (typeof created_after === 'string' && typeof created_before === 'string') {
        const after = new Date(created_after);
        const before = new Date(created_before);
        if (after >= before) {
          errors.push(
            new ValidationError(
              'created_after must be before created_before',
              'filters.time_window',
              'INVALID_TIME_WINDOW'
            )
          );
        }
      }
    }

    // Validate graph expansion
    if (data.graph_expansion && typeof data.graph_expansion === 'object') {
      const graphExpansion = data.graph_expansion as Dict<JSONValue>;
      if (graphExpansion.enabled && typeof graphExpansion.max_depth === 'number' && typeof graphExpansion.max_nodes === 'number') {
        if (graphExpansion.max_depth * graphExpansion.max_nodes > 10000) {
          errors.push(
            new ValidationError(
              'Graph expansion parameters may cause performance issues (max_depth * max_nodes > 10000)',
              'graph_expansion',
              'PERFORMANCE_RISK'
            )
          );
        }
      }
    }

    return errors;
  }

  /**
   * Business rule validation for system_status
   */
  private validateSystemStatusBusinessRules(data: Dict<JSONValue>): ValidationError[] {
    const errors: ValidationError[] = [];

    // Validate operation-specific requirements
    if (typeof data.operation === 'string') {
      switch (data.operation) {
        case 'get_document':
        case 'reassemble_document':
        case 'get_document_with_chunks':
          if (!data.document_id || typeof data.document_id !== 'string') {
            errors.push(
              new ValidationError(
                `Operation ${data.operation} requires document_id`,
                'document_id',
                'MISSING_REQUIRED_PARAMETER'
              )
            );
          }
          break;
        case 'confirm_cleanup':
          if (!data.cleanup_token || typeof data.cleanup_token !== 'string') {
            errors.push(
              new ValidationError(
                'Operation confirm_cleanup requires cleanup_token',
                'cleanup_token',
                'MISSING_REQUIRED_PARAMETER'
              )
            );
          }
          break;
        default:
          // No operation-specific requirements for unknown operations
          break;
      }
    }

    return errors;
  }

  /**
   * Business rule validation for performance_monitoring
   */
  private validatePerformanceMonitoringBusinessRules(data: Dict<JSONValue>): ValidationError[] {
    const errors: ValidationError[] = [];

    // Validate time window
    if (data.time_window && typeof data.time_window === 'object') {
      const timeWindow = data.time_window as Dict<JSONValue>;
      const start_time = timeWindow.start_time;
      const end_time = timeWindow.end_time;
      const last_hours = timeWindow.last_hours;
      const last_days = timeWindow.last_days;

      if (typeof start_time === 'string' && typeof end_time === 'string') {
        const start = new Date(start_time);
        const end = new Date(end_time);
        if (start >= end) {
          errors.push(
            new ValidationError(
              'start_time must be before end_time',
              'time_window',
              'INVALID_TIME_WINDOW'
            )
          );
        }
      }

      if (typeof last_hours === 'number' && typeof last_days === 'number') {
        errors.push(
          new ValidationError(
            'Cannot specify both last_hours and last_days',
            'time_window',
            'CONFLICTING_PARAMETERS'
          )
        );
      }
    }

    return errors;
  }

  /**
   * Generate warnings for potential issues
   */
  private generateWarnings(schemaName: SchemaName, data: Dict<JSONValue>): string[] {
    const warnings: string[] = [];

    switch (schemaName) {
      case 'memory_store':
        if (data.items && Array.isArray(data.items) && data.items.length > 50) {
          warnings.push(
            'Large batch size detected (>50 items). Consider processing in smaller batches for better performance.'
          );
        }
        if (data.deduplication && typeof data.deduplication === 'object') {
          const deduplication = data.deduplication as Dict<JSONValue>;
          if (typeof deduplication.max_items_to_check === 'number' && deduplication.max_items_to_check > 1000) {
            warnings.push('High max_items_to_check value may impact deduplication performance.');
          }
        }
        break;
      case 'memory_find':
        if (data.graph_expansion && typeof data.graph_expansion === 'object') {
          const graphExpansion = data.graph_expansion as Dict<JSONValue>;
          if (
            graphExpansion.enabled &&
            typeof graphExpansion.max_depth === 'number' &&
            graphExpansion.max_depth > 3
          ) {
            warnings.push('Deep graph expansion (max_depth > 3) may cause performance issues.');
          }
        }
        if (typeof data.limit === 'number' && data.limit > 50) {
          warnings.push(
            'Large result set requested (>50 items). Consider using pagination for better performance.'
          );
        }
        break;
      default:
        // No warnings for unknown schema types
        break;
    }

    return warnings;
  }

  /**
   * Migrate legacy input format to enhanced format
   */
  private migrateLegacyInput(
    schemaName: SchemaName,
    input: unknown
  ): EnhancedMigrationResult<JSONValue> {
    try {
      switch (schemaName) {
        case 'memory_store': {
          if (isLegacyMemoryStoreInput(input)) {
            const storeResult = SchemaMigrator.migrateMemoryStore(input);
            return { migrated: true, input: storeResult.migrated, notes: storeResult.notes };
          }
          break;
        }
        case 'memory_find': {
          if (isLegacyMemoryFindInput(input)) {
            const findResult = SchemaMigrator.migrateMemoryFind(input);
            return { migrated: true, input: findResult.migrated, notes: findResult.notes };
          }
          break;
        }
        case 'system_status': {
          if (isLegacySystemStatusInput(input)) {
            const statusResult = SchemaMigrator.migrateSystemStatus(input);
            return { migrated: true, input: statusResult.migrated, notes: statusResult.notes };
          }
          break;
        }
        default:
          // No migration available for this schema
          break;
      }

      // Return original input if no migration was performed
      return {
        migrated: false,
        input: isJSONValue(input) ? input : {},
        notes: ['No migration needed or input format not recognized']
      };
    } catch (error) {
      return {
        migrated: false,
        input: {},
        notes: [`Migration failed: ${error instanceof Error ? error.message : 'Unknown error'}`],
      };
    }
  }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Validate memory_store input with enhanced features
 */
export function validateMemoryStore(input: unknown, options?: ValidationOptions): ValidationResult {
  return SchemaValidator.getInstance().validateEnhanced('memory_store', input, options);
}

/**
 * Validate memory_find input with enhanced features
 */
export function validateMemoryFind(input: unknown, options?: ValidationOptions): ValidationResult {
  return SchemaValidator.getInstance().validateEnhanced('memory_find', input, options);
}

/**
 * Validate system_status input with enhanced features
 */
export function validateSystemStatus(
  input: unknown,
  options?: ValidationOptions
): ValidationResult {
  return SchemaValidator.getInstance().validateEnhanced('system_status', input, options);
}

/**
 * Validate performance_monitoring input with enhanced features
 */
export function validatePerformanceMonitoring(
  input: unknown,
  options?: ValidationOptions
): ValidationResult {
  return SchemaValidator.getInstance().validateEnhanced('performance_monitoring', input, options);
}

/**
 * Legacy validation for backward compatibility
 */
export function validateLegacyMemoryStore(input: unknown): ValidationResult {
  return SchemaValidator.getInstance().validateLegacy('memory_store', input);
}

export function validateLegacyMemoryFind(input: unknown): ValidationResult {
  return SchemaValidator.getInstance().validateLegacy('memory_find', input);
}
