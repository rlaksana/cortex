// P4 MCP INTEGRATION RESOLUTION: Fixed MCP SDK v1.22.0 compatibility

/**
 * MCP 2025 Compliance Utilities
 *
 * Standardized error handling and response formatting for Claude Code,
 * Gemini, and Codex compatibility according to MCP 2025 standards.
 * Updated for MCP SDK v1.22.0 compatibility.
 */

import type { ContentBlock } from '@modelcontextprotocol/sdk/types.js';

import { logger } from '@/utils/logger.js';

/**
 * Standard MCP Error Codes (2025 specification)
 */
export enum MCPErrorCode {
  // Parse errors ( -32700 to -32000 are JSON-RPC reserved)
  _PARSE_ERROR = -32700,
  _INVALID_REQUEST = -32600,
  _METHOD_NOT_FOUND = -32601,
  _INVALID_PARAMS = -32602,
  _INTERNAL_ERROR = -32603,

  // MCP-specific error codes (32000-32999)
  _TOOL_EXECUTION_ERROR = 32000,
  _VALIDATION_ERROR = 32001,
  _DATABASE_ERROR = 32002,
  _AUTHENTICATION_ERROR = 32003,
  _AUTHORIZATION_ERROR = 32004,
  _RATE_LIMIT_ERROR = 32005,
  _TIMEOUT_ERROR = 32006,
  _RESOURCE_NOT_FOUND = 32007,
  _CONFLICT_ERROR = 32008,
  _UNAVAILABLE_ERROR = 32009,
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
    data?: unknown;
  };
}

/**
 * MCP Success Response interface (JSON-RPC 2.0 compliant)
 */
export interface MCPSuccessResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result: unknown;
}

/**
 * Standard MCP Tool Handler Response
 */
export interface MCPToolResponse {
  content: ContentBlock[];
  isError?: boolean;
}

/**
 * Create standardized MCP error response
 */
export function createMCPError(
  code: MCPErrorCode,
  message: string,
  data?: unknown,
  id?: string | number | null
): MCPErrorResponse {
  const errorResponse: MCPErrorResponse = {
    jsonrpc: '2.0',
    id: id || null,
    error: {
      code,
      message,
      data,
    },
  };

  logger.error(
    {
      error_code: code,
      error_message: message,
      error_data: data,
      request_id: id,
    },
    `MCP Error: ${message}`
  );

  return errorResponse;
}

/**
 * Create standardized MCP success response
 */
export function createMCPSuccess(result: unknown, id?: string | number | null): MCPSuccessResponse {
  const successResponse: MCPSuccessResponse = {
    jsonrpc: '2.0',
    id: id || null,
    result,
  };

  logger.debug(
    {
      response_type: 'success',
      request_id: id,
    },
    'MCP Success response'
  );

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
    let code = MCPErrorCode._INTERNAL_ERROR;

    if (error.message.includes('validation')) {
      code = MCPErrorCode._VALIDATION_ERROR;
    } else if (error.message.includes('database') || error.message.includes('connection')) {
      code = MCPErrorCode._DATABASE_ERROR;
    } else if (error.message.includes('timeout')) {
      code = MCPErrorCode._TIMEOUT_ERROR;
    } else if (error.message.includes('not found')) {
      code = MCPErrorCode._RESOURCE_NOT_FOUND;
    } else if (error.message.includes('unauthorized') || error.message.includes('forbidden')) {
      code = MCPErrorCode._AUTHORIZATION_ERROR;
    }

    return createMCPError(
      code,
      error.message,
      {
        stack: error.stack,
        name: error.name,
        timestamp: new Date().toISOString(),
      },
      id
    );
  }

  // Unknown error
  return createMCPError(
    MCPErrorCode._INTERNAL_ERROR,
    'Unknown internal error',
    { originalError: error },
    id
  );
}

/**
 * Validate tool input against schema
 */
export function validateToolInput(
  input: unknown,
  schema: unknown
): { isValid: boolean; errors?: string[] } {
  const errors: string[] = [];

  // Validate schema structure
  if (!schema || typeof schema !== 'object') {
    errors.push('Schema must be an object');
    return { isValid: false, errors };
  }

  const schemaObj = schema as Record<string, unknown>;

  // Basic validation logic
  if (schemaObj.type === 'object') {
    if (schemaObj.required && typeof input === 'object' && input !== null) {
      const inputObj = input as Record<string, unknown>;
      for (const requiredField of schemaObj.required as string[]) {
        if (!(requiredField in inputObj)) {
          errors.push(`Missing required field: ${requiredField}`);
        }
      }
    }

    if (schemaObj.properties && typeof input === 'object' && input !== null) {
      const inputObj = input as Record<string, unknown>;
      for (const [fieldName, fieldSchema] of Object.entries(schemaObj.properties as Record<string, unknown>)) {
        if (fieldName in inputObj) {
          const value = inputObj[fieldName];
          const fieldDef = fieldSchema as Record<string, unknown>;

          // Type validation
          if (fieldDef.type && typeof value !== fieldDef.type) {
            errors.push(
              `Field '${fieldName}' must be of type ${fieldDef.type}, got ${typeof value}`
            );
          }

          // Enum validation
          if (Array.isArray(fieldDef.enum) && !fieldDef.enum.includes(value)) {
            errors.push(
              `Field '${fieldName}' must be one of: ${(fieldDef.enum as unknown[]).join(', ')}, got ${value}`
            );
          }

          // Array validation
          if (fieldDef.type === 'array' && !Array.isArray(value)) {
            errors.push(`Field '${fieldName}' must be an array`);
          }
        }
      }
    }
  }

  return errors.length === 0 ? { isValid: true } : { isValid: false, errors };
}

/**
 * Create standardized tool response
 */
export function createToolResponse(
  content: string,
  isError: boolean = false
): MCPToolResponse {
  return {
    content: [
      {
        type: 'text',
        text: content,
      },
    ],
    isError,
  };
}

/**
 * Wrap tool handlers with MCP compliance
 */
export function withMCPCompliance(
  toolName: string,
  handler: (_args: unknown) => Promise<MCPToolResponse>
) {
  return async (args: unknown): Promise<MCPToolResponse> => {
    const startTime = Date.now();
    logger.info({ tool: toolName, args }, `Executing tool: ${toolName}`);

    try {
      const result = await handler(args);

      const duration = Date.now() - startTime;
      logger.info(
        {
          tool: toolName,
          duration_ms: duration,
          success: true,
        },
        `Tool ${toolName} completed successfully`
      );

      return result;
    } catch (error) {
      const duration = Date.now() - startTime;

      logger.error(
        {
          tool: toolName,
          duration_ms: duration,
          error: error instanceof Error ? error.message : 'Unknown error',
          success: false,
        },
        `Tool ${toolName} failed`
      );

      // Return MCP-compliant error response
      return createToolResponse(
        `Error executing ${toolName}: ${error instanceof Error ? error.message : 'Unknown error'}`,
        true
      );
    }
  };
}
