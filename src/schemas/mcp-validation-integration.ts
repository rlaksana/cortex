/**
 * MCP Validation Integration Layer
 *
 * Provides integration utilities for MCP tools to use the unified validation system.
 * This layer ensures consistent validation across all MCP tool inputs/outputs while
 * maintaining backward compatibility with existing implementations.
 *
 * @version 2.0.0 - T20 Implementation
 */

import { logger } from '../utils/logger.js';
import { mcpToolValidator } from '../services/validation/enhanced-validation-service.js';
import { MCPValidationIntegration, ValidationErrorConverter } from './validation-migration.js';
import type { ValidationResult, ValidationErrorDetail } from './unified-knowledge-validator.js';

// ============================================================================
// MCP Input Validation Wrappers
// ============================================================================

export interface MCPValidationResult {
  success: boolean;
  data?: any;
  error?: {
    code: string;
    message: string;
    details?: ValidationErrorDetail[];
  };
  warnings?: string[];
  metadata?: {
    tool: string;
    validationVersion: string;
    timestamp: string;
    processingTimeMs?: number;
  };
}

/**
 * Validate memory store MCP tool input with enhanced error handling
 */
export async function validateMemoryStoreInput(input: any): Promise<MCPValidationResult> {
  const startTime = Date.now();

  try {
    logger.debug({ input: { itemCount: input.items?.length } }, 'Validating memory store input');

    const result = await mcpToolValidator.validateMemoryStoreTool(input);

    const validationTime = Date.now() - startTime;

    if (!result.success) {
      logger.warn({ error: result.error }, 'Memory store input validation failed');
      return {
        success: false,
        error: {
          code: 'MEMORY_STORE_VALIDATION_ERROR',
          message: result.error || 'Unknown validation error',
        },
        metadata: {
          tool: 'memory_store',
          validationVersion: '2.0.0',
          timestamp: new Date().toISOString(),
          processingTimeMs: validationTime,
        },
      };
    }

    logger.debug({ itemCount: input.items?.length }, 'Memory store input validation successful');

    return {
      success: true,
      data: result.data,
      warnings: result.warnings,
      metadata: {
        tool: 'memory_store',
        validationVersion: '2.0.0',
        timestamp: new Date().toISOString(),
        processingTimeMs: validationTime,
      },
    };
  } catch (error) {
    const validationTime = Date.now() - startTime;
    logger.error({ error }, 'Memory store validation system error');

    return {
      success: false,
      error: {
        code: 'VALIDATION_SYSTEM_ERROR',
        message: error instanceof Error ? error.message : 'Unknown validation error',
      },
      metadata: {
        tool: 'memory_store',
        validationVersion: '2.0.0',
        timestamp: new Date().toISOString(),
        processingTimeMs: validationTime,
      },
    };
  }
}

/**
 * Validate memory find MCP tool input with enhanced error handling
 */
export async function validateMemoryFindInput(input: any): Promise<MCPValidationResult> {
  const startTime = Date.now();

  try {
    logger.debug(
      { input: { query: input.query, limit: input.limit } },
      'Validating memory find input'
    );

    const result = await mcpToolValidator.validateMemoryFindTool(input);

    const validationTime = Date.now() - startTime;

    if (!result.success) {
      logger.warn({ error: result.error }, 'Memory find input validation failed');
      return {
        success: false,
        error: {
          code: 'MEMORY_FIND_VALIDATION_ERROR',
          message: result.error || 'Unknown validation error',
        },
        metadata: {
          tool: 'memory_find',
          validationVersion: '2.0.0',
          timestamp: new Date().toISOString(),
          processingTimeMs: validationTime,
        },
      };
    }

    logger.debug({ query: input.query }, 'Memory find input validation successful');

    return {
      success: true,
      data: result.data,
      warnings: result.warnings,
      metadata: {
        tool: 'memory_find',
        validationVersion: '2.0.0',
        timestamp: new Date().toISOString(),
        processingTimeMs: validationTime,
      },
    };
  } catch (error) {
    const validationTime = Date.now() - startTime;
    logger.error({ error }, 'Memory find validation system error');

    return {
      success: false,
      error: {
        code: 'VALIDATION_SYSTEM_ERROR',
        message: error instanceof Error ? error.message : 'Unknown validation error',
      },
      metadata: {
        tool: 'memory_find',
        validationVersion: '2.0.0',
        timestamp: new Date().toISOString(),
        processingTimeMs: validationTime,
      },
    };
  }
}

/**
 * Validate system status MCP tool input with enhanced error handling
 */
export async function validateSystemStatusInput(input: any): Promise<MCPValidationResult> {
  const startTime = Date.now();

  try {
    logger.debug({ input: { operation: input.operation } }, 'Validating system status input');

    const result = await mcpToolValidator.validateSystemStatusTool(input);

    const validationTime = Date.now() - startTime;

    if (!result.success) {
      logger.warn({ error: result.error }, 'System status input validation failed');
      return {
        success: false,
        error: {
          code: 'SYSTEM_STATUS_VALIDATION_ERROR',
          message: result.error || 'Unknown validation error',
        },
        metadata: {
          tool: 'system_status',
          validationVersion: '2.0.0',
          timestamp: new Date().toISOString(),
          processingTimeMs: validationTime,
        },
      };
    }

    logger.debug({ operation: input.operation }, 'System status input validation successful');

    return {
      success: true,
      data: result.data,
      metadata: {
        tool: 'system_status',
        validationVersion: '2.0.0',
        timestamp: new Date().toISOString(),
        processingTimeMs: validationTime,
      },
    };
  } catch (error) {
    const validationTime = Date.now() - startTime;
    logger.error({ error }, 'System status validation system error');

    return {
      success: false,
      error: {
        code: 'VALIDATION_SYSTEM_ERROR',
        message: error instanceof Error ? error.message : 'Unknown validation error',
      },
      metadata: {
        tool: 'system_status',
        validationVersion: '2.0.0',
        timestamp: new Date().toISOString(),
        processingTimeMs: validationTime,
      },
    };
  }
}

// ============================================================================
// Enhanced MCP Input Validation Functions
// ============================================================================

/**
 * Enhanced validateAndTransformItems function that uses unified validation
 */
export async function validateAndTransformItemsEnhanced(items: any[]): Promise<{
  items: any[];
  warnings: string[];
  metadata: any;
}> {
  const startTime = Date.now();

  try {
    logger.debug({ itemCount: items.length }, 'Validating and transforming MCP items');

    // Step 1: Validate input format using unified validator
    const validationResult = await validateMemoryStoreInput({ items });

    if (!validationResult.success) {
      const errorMessage = validationResult.error?.message || 'Unknown validation error';
      throw new Error(`MCP input validation failed: ${errorMessage}`);
    }

    // Step 2: Transform MCP input to internal format (existing logic)
    const { transformMcpInputToKnowledgeItems } = await import('../utils/mcp-transform.js');
    const transformedItems = transformMcpInputToKnowledgeItems(items);

    // Step 3: Perform additional validation on transformed items
    const detailedValidationPromises = transformedItems.map(async (item, index) => {
      const { mcpToolValidator } = await import(
        '../services/validation/enhanced-validation-service.js'
      );
      return {
        index,
        item,
        validation: await mcpToolValidator.getDetailedValidationResult(item),
      };
    });

    const detailedValidations = await Promise.all(detailedValidationPromises);

    // Step 4: Collect warnings and errors
    const allWarnings: string[] = [];
    const validationErrors: string[] = [];

    detailedValidations.forEach(({ index, validation }) => {
      if (!validation.valid) {
        const itemErrors = validation.errors.map(
          (error: any) => `Item ${index}: ${error.field ? `${error.field}: ` : ''}${error.message}`
        );
        validationErrors.push(...itemErrors);
      }

      const itemWarnings = validation.warnings.map(
        (warning: any) =>
          `Item ${index}: ${warning.field ? `${warning.field}: ` : ''}${warning.message}`
      );
      allWarnings.push(...itemWarnings);
    });

    // Step 5: Log validation results
    if (validationErrors.length > 0) {
      logger.warn({ errors: validationErrors }, 'Item validation errors detected');
    }

    if (allWarnings.length > 0) {
      logger.info({ warnings: allWarnings }, 'Item validation warnings detected');
    }

    const processingTime = Date.now() - startTime;

    const metadata = {
      validationTime: processingTime,
      itemCount: items.length,
      transformTime: processingTime,
      warnings: allWarnings.length,
      errors: validationErrors.length,
      validationVersion: '2.0.0',
      timestamp: new Date().toISOString(),
    };

    logger.debug(metadata, 'MCP items validation and transformation completed');

    return {
      items: transformedItems,
      warnings: allWarnings,
      metadata,
    };
  } catch (error) {
    const processingTime = Date.now() - startTime;
    logger.error({ error, processingTime }, 'Enhanced MCP items validation failed');

    // Fallback to original validation if unified validation fails
    try {
      logger.info('Falling back to original validation method');
      const { validateMcpInputFormat, transformMcpInputToKnowledgeItems } = await import(
        '../utils/mcp-transform.js'
      );

      const mcpValidation = validateMcpInputFormat(items);
      if (!mcpValidation.valid) {
        throw new Error(`Original validation also failed: ${mcpValidation.errors.join(', ')}`);
      }

      const transformedItems = transformMcpInputToKnowledgeItems(items);

      return {
        items: transformedItems,
        warnings: [
          `Validation fallback activated: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ],
        metadata: {
          validationTime: processingTime,
          itemCount: items.length,
          fallbackUsed: true,
          validationVersion: '2.0.0',
          timestamp: new Date().toISOString(),
        },
      };
    } catch (fallbackError) {
      logger.error({ fallbackError }, 'Fallback validation also failed');
      throw new Error(
        `Validation failed completely: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }
}

// ============================================================================
// MCP Output Validation and Formatting
// ============================================================================

/**
 * Validate and format MCP tool responses
 */
export function validateAndFormatMCPResponse(
  tool: string,
  response: any,
  validationMetadata?: any
): MCPValidationResult {
  try {
    // Basic response validation
    if (!response) {
      return {
        success: false,
        error: {
          code: 'EMPTY_RESPONSE',
          message: 'Response is empty or null',
        },
        metadata: {
          tool,
          validationVersion: '2.0.0',
          timestamp: new Date().toISOString(),
        },
      };
    }

    // Validate response structure based on tool type
    let isValid = true;
    let validationWarnings: string[] = [];

    switch (tool) {
      case 'memory_store':
        isValid = validateMemoryStoreResponse(response, validationWarnings);
        break;
      case 'memory_find':
        isValid = validateMemoryFindResponse(response, validationWarnings);
        break;
      case 'system_status':
        isValid = validateSystemStatusResponse(response, validationWarnings);
        break;
      default:
        validationWarnings.push(`Unknown tool type: ${tool}`);
    }

    return {
      success: isValid,
      data: response,
      warnings: validationWarnings.length > 0 ? validationWarnings : undefined,
      metadata: {
        tool,
        validationVersion: '2.0.0',
        timestamp: new Date().toISOString(),
        ...validationMetadata,
      },
    };
  } catch (error) {
    logger.error({ error, tool }, 'MCP response validation failed');

    return {
      success: false,
      error: {
        code: 'RESPONSE_VALIDATION_ERROR',
        message: error instanceof Error ? error.message : 'Unknown validation error',
      },
      metadata: {
        tool,
        validationVersion: '2.0.0',
        timestamp: new Date().toISOString(),
      },
    };
  }
}

/**
 * Validate memory store response structure
 */
function validateMemoryStoreResponse(response: any, warnings: string[]): boolean {
  if (typeof response !== 'object' || response === null) {
    return false;
  }

  // Check required fields
  if (response.success === undefined || typeof response.success !== 'boolean') {
    warnings.push('Missing or invalid success field');
  }

  if (response.stored !== undefined && typeof response.stored !== 'number') {
    warnings.push('Invalid stored field type, should be number');
  }

  if (response.total !== undefined && typeof response.total !== 'number') {
    warnings.push('Invalid total field type, should be number');
  }

  // Validate array fields
  if (response.stored_items !== undefined && !Array.isArray(response.stored_items)) {
    warnings.push('Invalid stored_items field type, should be array');
  }

  if (response.errors !== undefined && !Array.isArray(response.errors)) {
    warnings.push('Invalid errors field type, should be array');
  }

  return true;
}

/**
 * Validate memory find response structure
 */
function validateMemoryFindResponse(response: any, warnings: string[]): boolean {
  if (typeof response !== 'object' || response === null) {
    return false;
  }

  // Check required fields
  if (response.results === undefined && response.items === undefined) {
    warnings.push('Missing results or items field');
  }

  // Validate array fields
  if (response.results !== undefined && !Array.isArray(response.results)) {
    warnings.push('Invalid results field type, should be array');
  }

  if (response.items !== undefined && !Array.isArray(response.items)) {
    warnings.push('Invalid items field type, should be array');
  }

  if (response.total_count !== undefined && typeof response.total_count !== 'number') {
    warnings.push('Invalid total_count field type, should be number');
  }

  return true;
}

/**
 * Validate system status response structure
 */
function validateSystemStatusResponse(response: any, warnings: string[]): boolean {
  if (typeof response !== 'object' || response === null) {
    return false;
  }

  // Check required fields
  if (response.status === undefined || typeof response.status !== 'string') {
    warnings.push('Missing or invalid status field');
  }

  if (response.operation === undefined || typeof response.operation !== 'string') {
    warnings.push('Missing or invalid operation field');
  }

  return true;
}

// ============================================================================
// Validation Metrics and Monitoring
// ============================================================================

export interface MCPValidationMetrics {
  tool: string;
  totalValidations: number;
  successfulValidations: number;
  failedValidations: number;
  averageValidationTime: number;
  errorsByType: Record<string, number>;
  warningsByType: Record<string, number>;
  lastValidationTime: string;
}

class MCPValidationMonitor {
  private static metrics: Map<string, MCPValidationMetrics> = new Map();

  static recordValidation(tool: string, result: MCPValidationResult): void {
    const current = this.metrics.get(tool) || {
      tool,
      totalValidations: 0,
      successfulValidations: 0,
      failedValidations: 0,
      averageValidationTime: 0,
      errorsByType: {},
      warningsByType: {},
      lastValidationTime: new Date().toISOString(),
    };

    current.totalValidations++;

    if (result.success) {
      current.successfulValidations++;
    } else {
      current.failedValidations++;
    }

    // Update timing
    const validationTime = result.metadata?.processingTimeMs || 0;
    current.averageValidationTime =
      (current.averageValidationTime * (current.totalValidations - 1) + validationTime) /
      current.totalValidations;

    // Track errors
    if (result.error) {
      const errorType = result.error.code;
      current.errorsByType[errorType] = (current.errorsByType[errorType] || 0) + 1;
    }

    // Track warnings
    if (result.warnings) {
      result.warnings.forEach((warning) => {
        current.warningsByType[warning] = (current.warningsByType[warning] || 0) + 1;
      });
    }

    current.lastValidationTime = new Date().toISOString();
    this.metrics.set(tool, current);
  }

  static getMetrics(
    tool?: string
  ): Map<string, MCPValidationMetrics> | MCPValidationMetrics | undefined {
    if (tool) {
      return this.metrics.get(tool);
    }
    return new Map(this.metrics);
  }

  static resetMetrics(tool?: string): void {
    if (tool) {
      this.metrics.delete(tool);
    } else {
      this.metrics.clear();
    }
  }
}

// ============================================================================
// Export Functions
// ============================================================================

export {
  MCPValidationMonitor as validationMonitor,
  type ValidationResult,
  type ValidationErrorDetail,
};
