/**
 * MCP Validation Integration Layer
 *
 * Provides integration utilities for MCP tools to use the unified validation system.
 * This layer ensures consistent validation across all MCP tool inputs/outputs while
 * maintaining backward compatibility with existing implementations.
 *
 * @version 2.0.0 - Enhanced Type Safety Implementation
 */

import { logger } from '@/utils/logger.js';

import type {
  JSONValue,
  ValidationErrorDetail,
  ValidationResult,
} from './unified-knowledge-validator.js';
import { mcpToolValidator } from '../services/validation/enhanced-validation-service.js';
import type { Dict, JSONObject } from '../types/index.js';

// ============================================================================
// Typed Response Interfaces
// ============================================================================

export interface MemoryStoreResponse {
  success: boolean;
  stored?: number;
  total?: number;
  stored_items?: unknown[];
  errors?: unknown[];
  [key: string]: unknown; // Changed from JSONValue to unknown for compatibility
}

export interface MemoryFindResponse {
  results?: unknown[];
  items?: unknown[];
  total_count?: number;
  took?: number;
  facets?: Record<string, unknown>;
  [key: string]: unknown; // Changed from JSONValue to unknown for compatibility
}

export interface SystemStatusResponse {
  status: string;
  operation: string;
  timestamp?: string;
  uptime?: number;
  version?: string;
  [key: string]: unknown; // Changed from JSONValue to unknown for compatibility
}

// ============================================================================
// Type Guard Functions for JSONValue
// ============================================================================

export function isJSONObject(obj: unknown): obj is JSONObject {
  return obj !== null && typeof obj === 'object' && !Array.isArray(obj);
}

export function hasItems(obj: unknown): obj is { items: unknown[]; [key: string]: unknown } {
  if (!isJSONObject(obj)) return false;
  const o = obj as Record<string, unknown>;
  return Array.isArray(o.items);
}

export function hasQuery(obj: unknown): obj is { query: unknown; [key: string]: unknown } {
  if (!isJSONObject(obj)) return false;
  const o = obj as Record<string, unknown>;
  return typeof o.query === 'string' || typeof o.query === 'object';
}

export function isMemoryStoreResponse(obj: unknown): obj is MemoryStoreResponse {
  if (!isJSONObject(obj)) return false;

  const response = obj as Record<string, unknown>;

  // Check success field
  if (typeof response.success !== 'boolean') return false;

  // Check optional fields
  if (response.stored !== undefined && typeof response.stored !== 'number') return false;
  if (response.total !== undefined && typeof response.total !== 'number') return false;
  if (response.stored_items !== undefined && !Array.isArray(response.stored_items)) return false;
  if (response.errors !== undefined && !Array.isArray(response.errors)) return false;

  return true;
}

export function isMemoryFindResponse(obj: unknown): obj is MemoryFindResponse {
  if (!isJSONObject(obj)) return false;

  const response = obj as Record<string, unknown>;

  // Must have either results or items
  if (response.results === undefined && response.items === undefined) return false;

  // Check array fields
  if (response.results !== undefined && !Array.isArray(response.results)) return false;
  if (response.items !== undefined && !Array.isArray(response.items)) return false;
  if (response.total_count !== undefined && typeof response.total_count !== 'number') return false;
  if (response.took !== undefined && typeof response.took !== 'number') return false;

  return true;
}

export function isSystemStatusResponse(obj: unknown): obj is SystemStatusResponse {
  if (!isJSONObject(obj)) return false;

  const response = obj as Record<string, unknown>;

  // Check required fields
  if (typeof response.status !== 'string') return false;
  if (typeof response.operation !== 'string') return false;

  // Check optional fields
  if (response.timestamp !== undefined && typeof response.timestamp !== 'string') return false;
  if (response.uptime !== undefined && typeof response.uptime !== 'number') return false;
  if (response.version !== undefined && typeof response.version !== 'string') return false;

  return true;
}

export function hasOperation(obj: unknown): obj is { operation: string; [key: string]: unknown } {
  return isJSONObject(obj) && typeof obj.operation === 'string';
}

// ============================================================================
// Typed MCP Interfaces
// ============================================================================

/**
 * Base interface for MCP tool inputs
 */
export interface MCPToolInput {
  tool: string;
  parameters?: Record<string, JSONValue>;
  metadata?: Record<string, JSONValue>;
}

/**
 * Memory store specific input interface
 */
export interface MemoryStoreInput extends MCPToolInput {
  tool: 'memory_store';
  parameters: {
    items: Array<{
      kind: string;
      content: string;
      scope?: Record<string, string>;
      metadata?: Record<string, JSONValue>;
    }>;
  };
}

/**
 * Memory find specific input interface
 */
export interface MemoryFindInput extends MCPToolInput {
  tool: 'memory_find';
  parameters: {
    query?: string;
    kind?: string;
    scope?: Record<string, string>;
    limit?: number;
    filters?: Record<string, JSONValue>;
  };
}

// ============================================================================
// MCP Input Validation Wrappers
// ============================================================================

export interface MCPValidationResult<T = unknown> {
  success: boolean;
  data?: T;
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
export async function validateMemoryStoreInput(
  input: MemoryStoreInput
): Promise<MCPValidationResult> {
  const startTime = Date.now();

  try {
    // Use type guard to safely access items property
    if (!hasItems(input)) {
      throw new Error('Invalid input: missing or invalid items array');
    }

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
export async function validateMemoryFindInput(
  input: MemoryFindInput
): Promise<MCPValidationResult> {
  const startTime = Date.now();

  try {
    // Use type guard to safely access query property
    if (!hasQuery(input)) {
      throw new Error('Invalid input: missing or invalid query');
    }

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
export async function validateSystemStatusInput(
  input: Dict<JSONValue>
): Promise<MCPValidationResult> {
  const startTime = Date.now();

  try {
    // Use type guard to safely access operation property
    if (!hasOperation(input)) {
      throw new Error('Invalid input: missing or invalid operation field');
    }

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
export async function validateAndTransformItemsEnhanced(items: JSONValue[]): Promise<{
  items: JSONValue[];
  warnings: string[];
  metadata: Dict<JSONValue>;
}> {
  const startTime = Date.now();

  try {
    logger.debug({ itemCount: items.length }, 'Validating and transforming MCP items');

    // Step 1: Validate input format using unified validator
    const validationResult = await validateMemoryStoreInput({
      tool: 'memory_store',
      parameters: { items: items as Array<{ kind: string; content: string; scope?: Record<string, string>; metadata?: Record<string, JSONValue>; }> }
    });

    if (!validationResult.success) {
      const errorMessage = validationResult.error?.message || 'Unknown validation error';
      throw new Error(`MCP input validation failed: ${errorMessage}`);
    }

    // Step 2: Transform MCP input to internal format (existing logic)
    const { transformMcpInputToKnowledgeItems } = await import('../utils/mcp-transform.js');
    const transformedItems = transformMcpInputToKnowledgeItems(items as JSONValue[]);

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
          (error: ValidationErrorDetail) =>
            `Item ${index}: ${error.field ? `${error.field}: ` : ''}${error.message}`
        );
        validationErrors.push(...itemErrors);
      }

      const itemWarnings = validation.warnings.map(
        (warning: ValidationErrorDetail) =>
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
      items: transformedItems as JSONValue[],
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
        items: transformedItems as JSONValue[],
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
  response: JSONValue,
  validationMetadata?: Dict<JSONValue>
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
    const validationWarnings: string[] = [];

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
function validateMemoryStoreResponse(response: JSONValue, warnings: string[]): boolean {
  if (!isMemoryStoreResponse(response)) {
    return false;
  }

  // Check required fields
  if (response.success === undefined) {
    warnings.push('Missing success field');
  }

  return true;
}

/**
 * Validate memory find response structure
 */
function validateMemoryFindResponse(response: JSONValue, warnings: string[]): boolean {
  if (!isMemoryFindResponse(response)) {
    return false;
  }

  // Check required fields
  if (response.results === undefined && response.items === undefined) {
    warnings.push('Missing results or items field');
  }

  return true;
}

/**
 * Validate system status response structure
 */
function validateSystemStatusResponse(response: JSONValue, warnings: string[]): boolean {
  if (!isSystemStatusResponse(response)) {
    return false;
  }

  // Type guards already validate required fields
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
  type ValidationErrorDetail,
  MCPValidationMonitor as validationMonitor,
  type ValidationResult,
};
