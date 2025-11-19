// LAST ABSOLUTE FINAL EMERGENCY ROLLBACK: Complete the systematic rollback

/**
 * Validation Migration Utilities
 *
 * Provides migration utilities to transition from legacy validation systems
 * to the unified knowledge type validator. Ensures backward compatibility
 * while enabling consistent validation across all MCP tools.
 *
 * @version 2.0.0 - T20 Implementation
 */

import {
  type JSONValue,
  UnifiedKnowledgeTypeValidator,
  type ValidationErrorDetail,
  ValidationMode,
  type ValidationOptions,
  type ValidationResult
} from './unified-knowledge-validator.js';
import type {
  KnowledgeItem as IKnowledgeItem,
  StoreError,
  ValidationService as IValidationService,
} from '../types/core-interfaces.js';
import { hasStringProperty } from '../utils/type-fixes.js';

// ============================================================================
// Legacy Error Format Conversion
// ============================================================================

export interface LegacyValidationError {
  index?: number;
  field?: string;
  message: string;
  code?: string;
}

export interface LegacyValidationResult {
  valid: boolean;
  errors: LegacyValidationError[];
  warnings?: LegacyValidationError[];
}

export class ValidationErrorConverter {
  /**
   * Convert unified validation result to legacy format
   */
  static toLegacyFormat(result: ValidationResult): LegacyValidationResult {
    const legacy: LegacyValidationResult = {
      valid: result.valid,
      errors: result.errors.map((error) => ({
        field: error.field,
        message: error.message,
        code: error.code,
      })),
    };

    if (result.warnings.length > 0) {
      legacy.warnings = result.warnings.map((warning) => ({
        field: warning.field,
        message: warning.message,
        code: warning.code,
      }));
    }

    return legacy;
  }

  /**
   * Convert unified validation errors to StoreError format
   */
  static toStoreErrors(errors: ValidationErrorDetail[]): StoreError[] {
    return errors.map((error, index) => ({
      index,
      error_code: error.code,
      message: error.message,
      field: error.field,
    }));
  }

  /**
   * Convert validation result to simple error string array
   */
  static toStringArray(errors: ValidationErrorDetail[]): string[] {
    return errors.map((error) => `${error.field ? `${error.field}: ` : ''}${error.message}`);
  }
}

// ============================================================================
// Enhanced Validation Service
// ============================================================================

export class EnhancedValidationService implements IValidationService {
  private unifiedValidator: UnifiedKnowledgeTypeValidator;

  constructor() {
    this.unifiedValidator = UnifiedKnowledgeTypeValidator.getInstance();
  }

  /**
   * Validate store input with enhanced error handling
   */
  async validateStoreInput(items: unknown[]): Promise<{ valid: boolean; errors: StoreError[] }> {
    try {
      const request = { items };
      const result = await this.unifiedValidator.validateMemoryStoreRequest(request);

      if (!result.valid) {
        const errors = ValidationErrorConverter.toStoreErrors(result.errors);
        return { valid: false, errors };
      }

      return { valid: true, errors: [] };
    } catch (error) {
      return {
        valid: false,
        errors: [
          {
            index: 0,
            error_code: 'VALIDATION_SYSTEM_ERROR',
            message: error instanceof Error ? error.message : 'Unknown validation error',
          },
        ],
      };
    }
  }

  /**
   * Validate find input with enhanced error handling
   */
  async validateFindInput(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const result = await this.unifiedValidator.validateMemoryFindRequest(input);

      if (!result.valid) {
        const errors = ValidationErrorConverter.toStringArray(result.errors);
        return { valid: false, errors };
      }

      return { valid: true, errors: [] };
    } catch (error) {
      return {
        valid: false,
        errors: [error instanceof Error ? error.message : 'Unknown validation error'],
      };
    }
  }

  /**
   * Validate individual knowledge item with enhanced error handling
   */
  async validateKnowledgeItem(item: IKnowledgeItem): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const result = await this.unifiedValidator.validateKnowledgeItem(item);

      if (!result.valid) {
        const errors = ValidationErrorConverter.toStringArray(result.errors);
        return { valid: false, errors };
      }

      return { valid: true, errors: [] };
    } catch (error) {
      return {
        valid: false,
        errors: [error instanceof Error ? error.message : 'Unknown validation error'],
      };
    }
  }

  /**
   * Get detailed validation result with metadata
   */
  async getDetailedValidationResult(
    item: unknown,
    options: { mode?: ValidationMode; includeWarnings?: boolean } = {}
  ): Promise<ValidationResult> {
    return this.unifiedValidator.validateKnowledgeItem(item, options);
  }

  /**
   * Validate with custom rules
   */
  async validateWithCustomRules(
    item: unknown,
    customRules: Array<{
      name: string;
      validator: (data: JSONValue) => ValidationErrorDetail[];
      priority: number;
    }>
  ): Promise<ValidationResult> {
    return this.unifiedValidator.validateKnowledgeItem(item, {
      customRules,
    });
  }
}

// ============================================================================
// MCP Tool Integration Utilities
// ============================================================================

export class MCPValidationIntegration {
  private static enhancedService = new EnhancedValidationService();

  /**
   * Validate memory store MCP tool input
   */
  static async validateMemoryStoreTool(input: JSONValue): Promise<{
    success: boolean;
    error?: string;
    data?: JSONValue;
    warnings?: string[];
  }> {
    try {
      const result = await this.enhancedService.getDetailedValidationResult(input, {
        mode: ValidationMode.STRICT,
        includeWarnings: true,
      });

      if (!result.valid) {
        const errorMessage = result.errors.map((e) => e.message).join('; ');
        return {
          success: false,
          error: `Validation failed: ${errorMessage}`,
          warnings: result.warnings.map((w) => w.message),
        };
      }

      return {
        success: true,
        data: result.data,
        warnings: result.warnings.map((w) => w.message),
      };
    } catch (error) {
      return {
        success: false,
        error: `Validation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  /**
   * Validate memory find MCP tool input
   */
  static async validateMemoryFindTool(input: JSONValue): Promise<{
    success: boolean;
    error?: string;
    data?: JSONValue;
    warnings?: string[];
  }> {
    try {
      const result = await this.enhancedService.getDetailedValidationResult(input, {
        mode: ValidationMode.STRICT,
        includeWarnings: true,
      });

      if (!result.valid) {
        const errorMessage = result.errors.map((e) => e.message).join('; ');
        return {
          success: false,
          error: `Validation failed: ${errorMessage}`,
        };
      }

      return {
        success: true,
        data: result.data,
        warnings: result.warnings.map((w) => w.message),
      };
    } catch (error) {
      return {
        success: false,
        error: `Validation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  /**
   * Validate system status MCP tool input
   */
  static async validateSystemStatusTool(input: JSONValue): Promise<{
    success: boolean;
    error?: string;
    data?: JSONValue;
  }> {
    try {
      // Basic validation for system status operations
      const validOperations = ['get_status', 'get_health', 'get_metrics'];

      if (!hasStringProperty(input, 'operation')) {
        return {
          success: false,
          error: 'Operation is required',
        };
      }

      if (!validOperations.includes(input.operation)) {
        return {
          success: false,
          error: `Invalid operation. Must be one of: ${validOperations.join(', ')}`,
        };
      }

      return {
        success: true,
        data: input,
      };
    } catch (error) {
      return {
        success: false,
        error: `Validation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  /**
   * Format validation results for MCP responses
   */
  static formatMCPResponse(result: {
    success: boolean;
    error?: string;
    data?: JSONValue;
    warnings?: string[];
  }): JSONValue {
    const response: JSONValue = {
      success: result.success,
    };

    if (result.error) {
      response.error = {
        code: 'VALIDATION_ERROR',
        message: result.error,
      };
    }

    if (result.data) {
      response.data = result.data;
    }

    if (result.warnings && result.warnings.length > 0) {
      response.warnings = result.warnings;
    }

    return response;
  }
}

// ============================================================================
// Batch Validation Utilities
// ============================================================================

export class BatchValidationUtils {
  private static validator = UnifiedKnowledgeTypeValidator.getInstance();

  /**
   * Validate multiple knowledge items in batch
   */
  static async validateBatch(
    items: unknown[],
    options: ValidationOptions = {}
  ): Promise<{
    valid: boolean;
    results: ValidationResult[];
    summary: {
      total: number;
      valid: number;
      invalid: number;
      warnings: number;
      totalErrors: number;
    };
  }> {
    const results: ValidationResult[] = [];
    let validCount = 0;
    let warningCount = 0;
    let errorCount = 0;

    for (let i = 0; i < items.length; i++) {
      const result = await this.validator.validateKnowledgeItem(items[i], {
        ...options,
        // Add item index to error context for batch validation
        customRules: options.customRules?.map((rule) => ({
          ...rule,
          validator: (data: JSONValue) => {
            const errors = rule.validator(data);
            return errors.map((error) => ({
              ...error,
              context: {
                ...error.context,
                batchIndex: i,
              },
            }));
          },
        })),
      });

      results.push(result);

      if (result.valid) {
        validCount++;
      } else {
        errorCount += result.errors.length;
      }

      warningCount += result.warnings.length;
    }

    return {
      valid: validCount === items.length,
      results,
      summary: {
        total: items.length,
        valid: validCount,
        invalid: items.length - validCount,
        warnings: warningCount,
        totalErrors: errorCount,
      },
    };
  }

  /**
   * Validate items with parallel processing
   */
  static async validateBatchParallel(
    items: unknown[],
    options: ValidationOptions & { concurrency?: number } = {}
  ): Promise<{
    valid: boolean;
    results: ValidationResult[];
    summary: {
      total: number;
      valid: number;
      invalid: number;
      warnings: number;
      totalErrors: number;
    };
  }> {
    const concurrency = options.concurrency || 10;
    const results: ValidationResult[] = [];

    // Process items in batches
    for (let i = 0; i < items.length; i += concurrency) {
      const batch = items.slice(i, i + concurrency);
      const batchPromises = batch.map((item) =>
        this.validator.validateKnowledgeItem(item, options)
      );

      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
    }

    // Calculate summary
    const validCount = results.filter((r) => r.valid).length;
    const warningCount = results.reduce((sum, r) => sum + r.warnings.length, 0);
    const errorCount = results.reduce((sum, r) => sum + r.errors.length, 0);

    return {
      valid: validCount === items.length,
      results,
      summary: {
        total: items.length,
        valid: validCount,
        invalid: items.length - validCount,
        warnings: warningCount,
        totalErrors: errorCount,
      },
    };
  }
}

// ============================================================================
// Validation Performance Monitoring
// ============================================================================

export interface ValidationMetrics {
  totalValidations: number;
  successfulValidations: number;
  failedValidations: number;
  averageValidationTime: number;
  slowestValidation: number;
  fastestValidation: number;
  errorsByType: Record<string, number>;
  warningsByType: Record<string, number>;
}

export class ValidationPerformanceMonitor {
  private static metrics: ValidationMetrics = {
    totalValidations: 0,
    successfulValidations: 0,
    failedValidations: 0,
    averageValidationTime: 0,
    slowestValidation: 0,
    fastestValidation: Infinity,
    errorsByType: {},
    warningsByType: {},
  };

  static recordValidation(result: ValidationResult): void {
    const time = result.metadata.validationTimeMs;

    this.metrics.totalValidations++;

    if (result.valid) {
      this.metrics.successfulValidations++;
    } else {
      this.metrics.failedValidations++;
    }

    // Update timing metrics
    if (time > this.metrics.slowestValidation) {
      this.metrics.slowestValidation = time;
    }

    if (time < this.metrics.fastestValidation) {
      this.metrics.fastestValidation = time;
    }

    // Update average time
    this.metrics.averageValidationTime =
      (this.metrics.averageValidationTime * (this.metrics.totalValidations - 1) + time) /
      this.metrics.totalValidations;

    // Track errors and warnings by type
    result.errors.forEach((error) => {
      const key = `${error.category}:${error.code}`;
      this.metrics.errorsByType[key] = (this.metrics.errorsByType[key] || 0) + 1;
    });

    result.warnings.forEach((warning) => {
      const key = `${warning.category}:${warning.code}`;
      this.metrics.warningsByType[key] = (this.metrics.warningsByType[key] || 0) + 1;
    });
  }

  static getMetrics(): ValidationMetrics {
    return { ...this.metrics };
  }

  static resetMetrics(): void {
    this.metrics = {
      totalValidations: 0,
      successfulValidations: 0,
      failedValidations: 0,
      averageValidationTime: 0,
      slowestValidation: 0,
      fastestValidation: Infinity,
      errorsByType: {},
      warningsByType: {},
    };
  }
}

// ============================================================================
// Exports
// ============================================================================

export type { ValidationResult } from './unified-knowledge-validator.js';
export type { ValidationMode } from './unified-knowledge-validator.js';
export type { ValidationErrorDetail } from './unified-knowledge-validator.js';

// Singleton instance for easy access
export const enhancedValidationService = new EnhancedValidationService();
export const validationPerformanceMonitor = ValidationPerformanceMonitor;

// Legacy compatibility exports
export const convertToLegacyFormat = ValidationErrorConverter.toLegacyFormat;
export const convertToStoreErrors = ValidationErrorConverter.toStoreErrors;
export const convertToStringArray = ValidationErrorConverter.toStringArray;
