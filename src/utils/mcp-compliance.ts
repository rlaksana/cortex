/**
 * MCP 2025 Compliance Utilities
 *
 * Standardized error handling and response formatting for Claude Code,
 * Gemini, and Codex compatibility according to MCP 2025 standards.
 */

import { logger } from './logger.js';

/**
 * Standard MCP Error Codes (2025 specification)
 */
export enum MCPErrorCode {
  // Parse errors ( -32700 to -32000 are JSON-RPC reserved)
  PARSE_ERROR = -32700,
  INVALID_REQUEST = -32600,
  METHOD_NOT_FOUND = -32601,
  INVALID_PARAMS = -32602,
  INTERNAL_ERROR = -32603,

  // MCP-specific error codes (32000-32999)
  TOOL_EXECUTION_ERROR = 32000,
  VALIDATION_ERROR = 32001,
  DATABASE_ERROR = 32002,
  AUTHENTICATION_ERROR = 32003,
  AUTHORIZATION_ERROR = 32004,
  RATE_LIMIT_ERROR = 32005,
  TIMEOUT_ERROR = 32006,
  RESOURCE_NOT_FOUND = 32007,
  CONFLICT_ERROR = 32008,
  UNAVAILABLE_ERROR = 32009
}

/**
 * MCP Error Response interface (JSON-RPC 2.0 compliant)
 */
export interface MCPErrorResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  error: {
    code: MCPErrorCode;
    message: string;
    data?: any;
  };
}

/**
 * MCP Success Response interface (JSON-RPC 2.0 compliant)
 */
export interface MCPSuccessResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result: any;
}

/**
 * Standard MCP Tool Handler Response
 */
export interface MCPToolResponse {
  content: Array<{
    type: 'text' | 'image' | 'resource';
    text?: string;
    data?: string;
    mimeType?: string;
  }>;
  isError?: boolean;
}

/**
 * Create standardized MCP error response
 */
export function createMCPError(
  code: MCPErrorCode,
  message: string,
  data?: any,
  id?: string | number | null
): MCPErrorResponse {
  const errorResponse: MCPErrorResponse = {
    jsonrpc: '2.0',
    id: id || null,
    error: {
      code,
      message,
      data
    }
  };

  logger.error({
    error_code: code,
    error_message: message,
    error_data: data,
    request_id: id
  }, `MCP Error: ${message}`);

  return errorResponse;
}

/**
 * Create standardized MCP success response
 */
export function createMCPSuccess(
  result: any,
  id?: string | number | null
): MCPSuccessResponse {
  const successResponse: MCPSuccessResponse = {
    jsonrpc: '2.0',
    id: id || null,
    result
  };

  logger.debug({
    response_type: 'success',
    request_id: id
  }, 'MCP Success response');

  return successResponse;
}

/**
 * Convert Error to MCP Error Response
 */
export function errorToMCPResponse(
  error: Error | unknown,
  id?: string | number | null
): MCPErrorResponse {
  if (error instanceof Error) {
    // Determine error code based on error type
    let code = MCPErrorCode.INTERNAL_ERROR;

    if (error.message.includes('validation')) {
      code = MCPErrorCode.VALIDATION_ERROR;
    } else if (error.message.includes('database') || error.message.includes('connection')) {
      code = MCPErrorCode.DATABASE_ERROR;
    } else if (error.message.includes('timeout')) {
      code = MCPErrorCode.TIMEOUT_ERROR;
    } else if (error.message.includes('not found')) {
      code = MCPErrorCode.RESOURCE_NOT_FOUND;
    } else if (error.message.includes('unauthorized') || error.message.includes('forbidden')) {
      code = MCPErrorCode.AUTHORIZATION_ERROR;
    }

    return createMCPError(
      code,
      error.message,
      {
        stack: error.stack,
        name: error.name,
        timestamp: new Date().toISOString()
      },
      id
    );
  }

  // Unknown error
  return createMCPError(
    MCPErrorCode.INTERNAL_ERROR,
    'Unknown internal error',
    { originalError: error },
    id
  );
}

/**
 * Validate tool input against schema
 */
export function validateToolInput(input: any, schema: any): { isValid: boolean; errors?: string[] } {
  const errors: string[] = [];

  // Basic validation logic
  if (schema.type === 'object') {
    if (schema.required && typeof input === 'object' && input !== null) {
      for (const requiredField of schema.required) {
        if (!(requiredField in input)) {
          errors.push(`Missing required field: ${requiredField}`);
        }
      }
    }

    if (schema.properties && typeof input === 'object' && input !== null) {
      for (const [fieldName, fieldSchema] of Object.entries(schema.properties)) {
        if (fieldName in input) {
          const value = input[fieldName];
          const fieldDef = fieldSchema as any;

          // Type validation
          if (fieldDef.type && typeof value !== fieldDef.type) {
            errors.push(`Field '${fieldName}' must be of type ${fieldDef.type}, got ${typeof value}`);
          }

          // Enum validation
          if (fieldDef.enum && !fieldDef.enum.includes(value)) {
            errors.push(`Field '${fieldName}' must be one of: ${fieldDef.enum.join(', ')}, got ${value}`);
          }

          // Array validation
          if (fieldDef.type === 'array' && !Array.isArray(value)) {
            errors.push(`Field '${fieldName}' must be an array`);
          }
        }
      }
    }
  }

  return errors.length === 0
    ? { isValid: true }
    : { isValid: false, errors };
}

/**
 * Create standardized tool response
 */
export function createToolResponse(
  content: string,
  isError: boolean = false,
  mimeType: string = 'text/plain'
): MCPToolResponse {
  return {
    content: [
      {
        type: 'text',
        text: content,
        ...(mimeType !== 'text/plain' && { mimeType })
      }
    ],
    isError
  };
}

/**
 * Wrap tool handlers with MCP compliance
 */
export function withMCPCompliance(
  toolName: string,
  handler: (args: any) => Promise<MCPToolResponse>
) {
  return async (args: any): Promise<MCPToolResponse> => {
    const startTime = Date.now();
    logger.info({ tool: toolName, args }, `Executing tool: ${toolName}`);

    try {
      const result = await handler(args);

      const duration = Date.now() - startTime;
      logger.info({
        tool: toolName,
        duration_ms: duration,
        success: true
      }, `Tool ${toolName} completed successfully`);

      return result;
    } catch (error) {
      const duration = Date.now() - startTime;

      logger.error({
        tool: toolName,
        duration_ms: duration,
        error: error instanceof Error ? error.message : 'Unknown error',
        success: false
      }, `Tool ${toolName} failed`);

      // Return MCP-compliant error response
      return createToolResponse(
        `Error executing ${toolName}: ${error instanceof Error ? error.message : 'Unknown error'}`,
        true
      );
    }
  };
}