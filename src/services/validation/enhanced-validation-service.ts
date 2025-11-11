
/**
 * Enhanced Validation Service
 *
 * Production-ready validation service that replaces the legacy validation service
 * with unified validation capabilities. Provides consistent validation across
 * all MCP tools with enhanced error handling and performance monitoring.
 *
 * @version 2.0.0 - T20 Implementation
 */

import { logger } from '@/utils/logger.js';

import { ValidationMode as ValidationModeValues } from '../../schemas/unified-knowledge-validator.js';
import {
  EnhancedValidationService,
  MCPValidationIntegration,
  ValidationPerformanceMonitor,
  type ValidationResult,
} from '../../schemas/validation-migration.js';
import type {
  KnowledgeItem,
  StoreError,
  ValidationService as IValidationService,
} from '../../types/core-interfaces.js';
import { type ValidationMode } from '../../types/unified-health-interfaces.js';

/**
 * Enhanced validation service implementation with unified validation
 */
export class ValidationService implements IValidationService {
  private enhancedService: EnhancedValidationService;
  private performanceMonitoring: boolean;

  constructor(options: { enablePerformanceMonitoring?: boolean } = {}) {
    this.enhancedService = new EnhancedValidationService();
    this.performanceMonitoring = options.enablePerformanceMonitoring ?? true;
  }

  /**
   * Validate store input using unified validation
   */
  async validateStoreInput(items: unknown[]): Promise<{ valid: boolean; errors: StoreError[] }> {
    const startTime = Date.now();

    try {
      const result = await this.enhancedService.validateStoreInput(items);

      if (this.performanceMonitoring) {
        const validationTime = Date.now() - startTime;
        ValidationPerformanceMonitor.recordValidation({
          valid: result.valid,
          errors: result.errors.map((error) => ({
            code: 'VALIDATION_ERROR',
            message: error.message,
            field: error.field,
            category: 'SCHEMA' as any,
            severity: 'ERROR' as any,
          })),
          warnings: [],
          metadata: {
            validationTimeMs: validationTime,
            validatorVersion: '2.0.0',
            schemaVersion: '2.0.0',
            validationMode: ValidationModeValues.STRICT,
          },
        });
      }

      if (!result.valid) {
        logger.warn({ errors: result.errors }, 'Store input validation failed');
      }

      return result;
    } catch (error) {
      logger.error({ error }, 'Validation service error');

      const systemError: StoreError[] = [
        {
          index: 0,
          error_code: 'VALIDATION_SYSTEM_ERROR',
          message: error instanceof Error ? error.message : 'Unknown validation error',
        },
      ];

      return { valid: false, errors: systemError };
    }
  }

  /**
   * Validate find input using unified validation
   */
  async validateFindInput(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    const startTime = Date.now();

    try {
      const result = await this.enhancedService.validateFindInput(input);

      if (this.performanceMonitoring) {
        const validationTime = Date.now() - startTime;
        ValidationPerformanceMonitor.recordValidation({
          valid: result.valid,
          errors: result.errors.map((error) => ({
            code: 'VALIDATION_ERROR',
            message: error,
            category: 'SCHEMA' as any,
            severity: 'ERROR' as any,
          })),
          warnings: [],
          metadata: {
            validationTimeMs: validationTime,
            validatorVersion: '2.0.0',
            schemaVersion: '2.0.0',
            validationMode: ValidationModeValues.STRICT,
          },
        });
      }

      if (!result.valid) {
        logger.warn({ errors: result.errors }, 'Find input validation failed');
      }

      return result;
    } catch (error) {
      logger.error({ error }, 'Find validation service error');
      return {
        valid: false,
        errors: [error instanceof Error ? error.message : 'Unknown validation error'],
      };
    }
  }

  /**
   * Validate individual knowledge item using unified validation
   */
  async validateKnowledgeItem(item: KnowledgeItem): Promise<{ valid: boolean; errors: string[] }> {
    const startTime = Date.now();

    try {
      const result = await this.enhancedService.validateKnowledgeItem(item);

      if (this.performanceMonitoring) {
        const validationTime = Date.now() - startTime;
        ValidationPerformanceMonitor.recordValidation({
          valid: result.valid,
          errors: result.errors.map((error) => ({
            code: 'VALIDATION_ERROR',
            message: error,
            category: 'SCHEMA' as any,
            severity: 'ERROR' as any,
          })),
          warnings: [],
          metadata: {
            validationTimeMs: validationTime,
            validatorVersion: '2.0.0',
            schemaVersion: '2.0.0',
            validationMode: ValidationModeValues.STRICT,
          },
        });
      }

      if (!result.valid) {
        logger.warn({ errors: result.errors }, 'Knowledge item validation failed');
      }

      return result;
    } catch (error) {
      logger.error({ error }, 'Knowledge item validation service error');
      return {
        valid: false,
        errors: [error instanceof Error ? error.message : 'Unknown validation error'],
      };
    }
  }

  /**
   * Get detailed validation result with metadata (enhanced method)
   */
  async getDetailedValidationResult(
    item: unknown,
    options: { mode?: ValidationMode; includeWarnings?: boolean } = {}
  ): Promise<ValidationResult> {
    const startTime = Date.now();

    try {
      const result = await this.enhancedService.getDetailedValidationResult(item, options);

      if (this.performanceMonitoring) {
        ValidationPerformanceMonitor.recordValidation(result);
      }

      return result;
    } catch (error) {
      logger.error({ error }, 'Detailed validation service error');
      return {
        valid: false,
        errors: [
          {
            code: 'VALIDATION_SYSTEM_ERROR',
            message: error instanceof Error ? error.message : 'Unknown validation error',
            category: 'SYSTEM' as any,
            severity: 'ERROR' as any,
          },
        ],
        warnings: [],
        metadata: {
          validationTimeMs: Date.now() - startTime,
          validatorVersion: '2.0.0',
          schemaVersion: '2.0.0',
          validationMode: options.mode || ValidationModeValues.STRICT,
        },
      };
    }
  }

  /**
   * Validate with custom rules (enhanced method)
   */
  async validateWithCustomRules(
    item: unknown,
    customRules: Array<{
      name: string;
      validator: (data: any) => any[];
      priority: number;
    }>
  ): Promise<ValidationResult> {
    const startTime = Date.now();

    try {
      const result = await this.enhancedService.validateWithCustomRules(item, customRules);

      if (this.performanceMonitoring) {
        ValidationPerformanceMonitor.recordValidation(result);
      }

      return result;
    } catch (error) {
      logger.error({ error }, 'Custom rules validation service error');
      return {
        valid: false,
        errors: [
          {
            code: 'VALIDATION_SYSTEM_ERROR',
            message: error instanceof Error ? error.message : 'Unknown validation error',
            category: 'SYSTEM' as any,
            severity: 'ERROR' as any,
          },
        ],
        warnings: [],
        metadata: {
          validationTimeMs: Date.now() - startTime,
          validatorVersion: '2.0.0',
          schemaVersion: '2.0.0',
          validationMode: ValidationModeValues.STRICT,
        },
      };
    }
  }

  /**
   * Get validation performance metrics
   */
  getPerformanceMetrics() {
    return ValidationPerformanceMonitor.getMetrics();
  }

  /**
   * Reset validation performance metrics
   */
  resetPerformanceMetrics(): void {
    ValidationPerformanceMonitor.resetMetrics();
  }
}

// ============================================================================
// MCP Tool Validation Integration
// ============================================================================

/**
 * MCP tool validation wrapper for consistent error handling
 */
export class MCPToolValidator {
  private validationService: ValidationService;

  constructor(options: { enablePerformanceMonitoring?: boolean } = {}) {
    this.validationService = new ValidationService(options);
  }

  /**
   * Validate memory store MCP tool input
   */
  async validateMemoryStoreTool(input: any): Promise<{
    success: boolean;
    error?: string;
    data?: any;
    warnings?: string[];
    metadata?: any;
  }> {
    try {
      const result = await MCPValidationIntegration.validateMemoryStoreTool(input);

      return {
        ...result,
        metadata: {
          tool: 'memory_store',
          validationVersion: '2.0.0',
          timestamp: new Date().toISOString(),
        },
      };
    } catch (error) {
      logger.error({ error, tool: 'memory_store' }, 'MCP tool validation error');

      return {
        success: false,
        error: `Tool validation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        metadata: {
          tool: 'memory_store',
          validationVersion: '2.0.0',
          timestamp: new Date().toISOString(),
          error: true,
        },
      };
    }
  }

  /**
   * Validate memory find MCP tool input
   */
  async validateMemoryFindTool(input: any): Promise<{
    success: boolean;
    error?: string;
    data?: any;
    warnings?: string[];
    metadata?: any;
  }> {
    try {
      const result = await MCPValidationIntegration.validateMemoryFindTool(input);

      return {
        ...result,
        metadata: {
          tool: 'memory_find',
          validationVersion: '2.0.0',
          timestamp: new Date().toISOString(),
        },
      };
    } catch (error) {
      logger.error({ error, tool: 'memory_find' }, 'MCP tool validation error');

      return {
        success: false,
        error: `Tool validation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        metadata: {
          tool: 'memory_find',
          validationVersion: '2.0.0',
          timestamp: new Date().toISOString(),
          error: true,
        },
      };
    }
  }

  /**
   * Validate system status MCP tool input
   */
  async validateSystemStatusTool(input: any): Promise<{
    success: boolean;
    error?: string;
    data?: any;
    metadata?: any;
  }> {
    try {
      const result = await MCPValidationIntegration.validateSystemStatusTool(input);

      return {
        ...result,
        metadata: {
          tool: 'system_status',
          validationVersion: '2.0.0',
          timestamp: new Date().toISOString(),
        },
      };
    } catch (error) {
      logger.error({ error, tool: 'system_status' }, 'MCP tool validation error');

      return {
        success: false,
        error: `Tool validation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        metadata: {
          tool: 'system_status',
          validationVersion: '2.0.0',
          timestamp: new Date().toISOString(),
          error: true,
        },
      };
    }
  }

  /**
   * Format validation results for MCP responses
   */
  formatMCPResponse(result: {
    success: boolean;
    error?: string;
    data?: any;
    warnings?: string[];
    metadata?: any;
  }): any {
    return MCPValidationIntegration.formatMCPResponse(result);
  }

  /**
   * Get detailed validation result for an item
   */
  async getDetailedValidationResult(
    item: unknown,
    options: { mode?: ValidationMode; includeWarnings?: boolean } = {}
  ): Promise<ValidationResult> {
    return this.validationService.getDetailedValidationResult(item, options);
  }

  /**
   * Get validation service metrics
   */
  getMetrics() {
    return this.validationService.getPerformanceMetrics();
  }
}

// ============================================================================
// Exports
// ============================================================================

// Default instances
export const validationService = new ValidationService();
export const mcpToolValidator = new MCPToolValidator();

// Legacy compatibility exports
export type { ValidationService as IValidationService };
export type { KnowledgeItem,StoreError };
