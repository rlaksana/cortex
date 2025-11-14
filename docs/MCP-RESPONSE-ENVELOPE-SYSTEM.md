# MCP Response Envelope System

## Overview

The MCP Response Envelope System provides a standardized, type-safe framework for creating and handling MCP tool responses. This system eliminates the use of `any` types, ensures consistent response patterns, and provides comprehensive validation and error handling capabilities.

## Key Features

- **Type Safety**: Complete elimination of `any` usage in tool responses
- **Standardized Patterns**: Consistent response structure across all MCP tools
- **Comprehensive Validation**: Built-in validation for all response types
- **Error Handling**: Structured error responses with detailed error information
- **Pagination Support**: Built-in pagination envelope for list responses
- **Streaming Support**: Envelope for streaming/chunked responses
- **Type Guards**: Runtime type checking and safe data extraction
- **Response Builder**: Fluent API for creating typed responses

## Architecture

### Core Components

1. **Response Envelopes**: Standardized wrapper interfaces for all responses
2. **Response Data Types**: Specific data types for each MCP operation
3. **Response Builders**: Type-safe builders for creating envelopes
4. **Validators**: Comprehensive validation utilities
5. **Type Guards**: Runtime type checking and safe extraction
6. **Utilities**: Helper functions for common operations

## Response Envelope Types

### Base Envelope

All response envelopes extend the `BaseResponseEnvelope` interface:

```typescript
interface BaseResponseEnvelope<TData = unknown> {
  data: TData;                    // Response data payload
  meta: UnifiedResponseMeta;      // Standardized metadata
  timestamp: string;              // ISO 8601 timestamp
  request_id: string;             // Unique request identifier
  operation_id?: string;          // Operation identifier for tracking
  api_version: string;            // API version for compatibility
}
```

### Success Envelope

Used for successful operations:

```typescript
interface SuccessEnvelope<TData = unknown> extends BaseResponseEnvelope<TData> {
  type: 'success';
  success: true;
  message?: string;               // Optional success message
  rate_limit?: {                  // Optional rate limiting info
    allowed: boolean;
    remaining: number;
    reset_time: string;
    identifier: string;
  };
}
```

### Error Envelope

Used for failed operations:

```typescript
interface ErrorEnvelope<TErrorData = unknown> extends BaseResponseEnvelope<null> {
  type: 'error';
  success: false;
  error: {
    code: string;                 // Error code for programmatic handling
    message: string;              // Human-readable error message
    type: string;                 // Error type/category
    stack?: string;               // Stack trace (development only)
    details?: TErrorData;         // Additional error context
    retryable: boolean;           // Whether error is retryable
    retry_after_ms?: number;      // Suggested retry delay
  };
  error_id: string;               // Error correlation ID
}
```

### Paginated Envelope

Used for paginated list responses:

```typescript
interface PaginatedEnvelope<TData = unknown> extends BaseResponseEnvelope<TData[]> {
  type: 'paginated';
  success: true;
  pagination: {
    page: number;                 // Current page (1-based)
    per_page: number;             // Items per page
    total: number;                // Total items across all pages
    total_pages: number;          // Total number of pages
    has_next: boolean;            // Whether there's a next page
    has_prev: boolean;            // Whether there's a previous page
    next_cursor?: string;         // Cursor for next page (optional)
    prev_cursor?: string;         // Cursor for previous page (optional)
  };
  summary?: Record<string, unknown>; // Optional summary statistics
}
```

### Streaming Envelope

Used for streaming/chunked responses:

```typescript
interface StreamingEnvelope<TData = unknown> extends BaseResponseEnvelope<TData> {
  type: 'streaming';
  success: true;
  stream: {
    stream_id: string;            // Unique stream identifier
    chunk_number: number;         // Current chunk number
    total_chunks?: number;        // Total chunks (if known)
    is_final: boolean;            // Whether this is the final chunk
    status: 'active' | 'completed' | 'error' | 'timeout';
  };
  stream_metadata?: {            // Optional stream metadata
    content_type?: string;
    estimated_size_bytes?: number;
    progress?: number;            // Transfer progress (0-1)
  };
}
```

## Response Data Types

### Memory Store Result

```typescript
interface MemoryStoreResult {
  stored_items: Array<EnhancedContentItem | EnhancedDataItem>;
  failed_items: Array<{
    item: EnhancedContentItem | EnhancedDataItem;
    error: {
      code: string;
      message: string;
      type: string;
    };
  }>;
  summary: {
    total_attempted: number;
    total_stored: number;
    total_failed: number;
    success_rate: number;
  };
  batch_id?: string;
  autonomous_context?: {
    enabled: boolean;
    processing_applied: string[];
    statistics: Record<string, number>;
  };
}
```

### Memory Find Result

```typescript
interface MemoryFindResult {
  query: string;
  strategy: string;
  confidence: number;
  total: number;
  items: Array<EnhancedContentItem | EnhancedDataItem>;
  search_id: string;
  strategy_details: {
    type: string;
    parameters: Record<string, unknown>;
    execution: {
      vector_used: boolean;
      semantic_search: boolean;
      keyword_search: boolean;
      fuzzy_matching: boolean;
    };
  };
  expansion?: {
    type: 'relations' | 'parents' | 'children' | 'none';
    items_added: number;
    depth: number;
  };
  filters?: {
    types?: string[];
    scope?: Record<string, unknown>;
    date_range?: {
      start?: string;
      end?: string;
    };
  };
}
```

### System Status Result

```typescript
interface SystemStatusResult {
  status: 'healthy' | 'degraded' | 'unhealthy' | 'maintenance';
  components: {
    database: ComponentStatus;
    vector_store: ComponentStatus & { collection_info?: CollectionInfo };
    ai_service: ComponentStatus & { model?: string };
    memory: MemoryStatus;
  };
  metrics: {
    active_requests: number;
    avg_response_time_ms: number;
    requests_per_minute: number;
    error_rate: number;
  };
  version: {
    api_version: string;
    server_version: string;
    build_timestamp: string;
    git_commit?: string;
  };
  capabilities: {
    vector_search: boolean;
    semantic_search: boolean;
    auto_processing: boolean;
    ttl_support: boolean;
    deduplication: boolean;
  };
}
```

## Usage Examples

### Creating a Success Response

```typescript
import { createResponseEnvelopeBuilder } from '../utils/response-envelope-builder.js';

const responseBuilder = createResponseEnvelopeBuilder('memory_store', startTime)
  .setOperationId(operationId);

const successEnvelope = responseBuilder.createMemoryStoreSuccess(
  memoryStoreResult,
  'autonomous_deduplication',
  true, // vector used
  false // not degraded
);
```

### Creating an Error Response

```typescript
const errorEnvelope = responseBuilder.createErrorEnvelope(
  ErrorCode.VALIDATION_FAILED,
  'Invalid input provided',
  'ValidationError',
  { field: 'query', message: 'Query cannot be empty' },
  false // not retryable
);
```

### Creating a Paginated Response

```typescript
const paginatedEnvelope = responseBuilder.createPaginatedEnvelope(
  items,
  {
    page: 1,
    per_page: 10,
    total: 100,
    total_pages: 10,
    has_next: true,
    has_prev: false
  },
  meta
);
```

### Using Type Guards

```typescript
import {
  isMemoryStoreResponse,
  extractMemoryStoreData,
  ResponseProcessor
} from '../utils/mcp-response-guards.js';

// Check response type
if (isMemoryStoreResponse(envelope)) {
  const data = extractMemoryStoreData(envelope);
  console.log(`Stored ${data.summary.total_stored} items`);
}

// Process responses with callbacks
const result = ResponseProcessor.processMemoryStore(envelope, {
  onSuccess: (data) => handleSuccess(data),
  onError: (error) => handleError(error),
  onUnknown: (envelope) => handleUnknown(envelope)
});
```

### Using Response Matcher

```typescript
import { createResponseMatcher } from '../utils/mcp-response-guards.js';

const result = createResponseMatcher(envelope)
  .onSuccess((data) => `Success: ${data.total} items`)
  .onError((error) => `Error: ${error.message}`)
  .onPaginated((data) => `Page ${data.pagination.page} of ${data.pagination.total_pages}`)
  .otherwise(() => 'Unknown response type');
```

### Validating Responses

```typescript
import {
  validateOperationResponseOrThrow,
  ResponseEnvelopeValidator
} from '../utils/response-envelope-validator.js';

// Validate and throw if invalid
const validatedEnvelope = validateOperationResponseOrThrow(envelope, 'memory_store');

// Validate with detailed results
const validation = ResponseEnvelopeValidator.validateEnvelope(envelope);
if (!validation.valid) {
  console.error('Validation errors:', validation.errors);
}
```

## Error Codes

The system provides standardized error codes:

```typescript
enum ErrorCode {
  // Validation errors (400)
  VALIDATION_FAILED = 'VALIDATION_FAILED',
  INVALID_INPUT = 'INVALID_INPUT',
  MISSING_REQUIRED_FIELD = 'MISSING_REQUIRED_FIELD',
  INVALID_FORMAT = 'INVALID_FORMAT',

  // Authentication/Authorization errors (401/403)
  UNAUTHORIZED = 'UNAUTHORIZED',
  FORBIDDEN = 'FORBIDDEN',
  INVALID_API_KEY = 'INVALID_API_KEY',
  INSUFFICIENT_PERMISSIONS = 'INSUFFICIENT_PERMISSIONS',

  // Rate limiting errors (429)
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  QUOTA_EXCEEDED = 'QUOTA_EXCEEDED',

  // Resource errors (404/409)
  NOT_FOUND = 'NOT_FOUND',
  ALREADY_EXISTS = 'ALREADY_EXISTS',
  CONFLICT = 'CONFLICT',

  // Server errors (500)
  INTERNAL_SERVER_ERROR = 'INTERNAL_SERVER_ERROR',
  DATABASE_ERROR = 'DATABASE_ERROR',
  EXTERNAL_SERVICE_ERROR = 'EXTERNAL_SERVICE_ERROR',
  TIMEOUT = 'TIMEOUT',
  UNAVAILABLE = 'UNAVAILABLE',

  // Business logic errors
  PROCESSING_FAILED = 'PROCESSING_FAILED',
  STORAGE_LIMIT_EXCEEDED = 'STORAGE_LIMIT_EXCEEDED',
  INVALID_OPERATION = 'INVALID_OPERATION'
}
```

## Migration Guide

### From Legacy Response Format

1. **Replace `Promise<any>` return types** with typed envelope return types
2. **Use ResponseEnvelopeBuilder** instead of manual response construction
3. **Add validation** using the provided validators
4. **Update error handling** to use structured error envelopes

### Before (Legacy)

```typescript
export async function handleMemoryStore(args: any): Promise<any> {
  try {
    const response = await processItems(args.items);
    return {
      success: true,
      stored: response.stored,
      errors: response.errors,
      total: response.total
    };
  } catch (error) {
    return {
      success: false,
      error: error.message
    };
  }
}
```

### After (With Envelope System)

```typescript
export async function handleMemoryStore(args: {
  items: any[];
}): Promise<UnifiedToolResponse<SuccessEnvelope<MemoryStoreResult>>> {
  const responseBuilder = createResponseEnvelopeBuilder('memory_store', startTime)
    .setOperationId(operationId);

  try {
    const response = await processItems(args.items);
    const memoryStoreResult: MemoryStoreResult = {
      stored_items: response.stored,
      failed_items: response.errors,
      summary: {
        total_attempted: args.items.length,
        total_stored: response.stored.length,
        total_failed: response.errors.length,
        success_rate: response.stored.length / args.items.length
      }
    };

    const successEnvelope = responseBuilder.createMemoryStoreSuccess(memoryStoreResult);
    const validatedEnvelope = validateOperationResponseOrThrow(successEnvelope, 'memory_store');
    return createMcpResponse(validatedEnvelope.data);
  } catch (error) {
    const errorEnvelope = responseBuilder.createServerError(error as Error);
    return createMcpResponse(errorEnvelope.data);
  }
}
```

## Best Practices

1. **Always validate responses** before returning them
2. **Use specific error codes** instead of generic errors
3. **Include operation context** in error details
4. **Use type guards** for safe data extraction
5. **Document response shapes** for API consumers
6. **Handle retryable errors** appropriately
7. **Include correlation IDs** for debugging
8. **Use appropriate envelope types** for different response patterns

## Testing

The envelope system includes comprehensive tests covering:

- Response creation and validation
- Type guard functionality
- Error handling scenarios
- Pagination and streaming responses
- Response processing and matching

Run tests with:

```bash
npm test -- src/utils/__tests__/response-envelope.test.ts
```

## Future Enhancements

Planned improvements to the envelope system:

1. **Response Caching**: Built-in response caching support
2. **Metrics Integration**: Automatic metrics collection
3. **Response Transformation**: Utilities for response format conversion
4. **Async Validation**: Streaming validation for large responses
5. **Custom Envelopes**: Support for custom envelope types
6. **Response Compression**: Built-in compression for large payloads

## Conclusion

The MCP Response Envelope System provides a robust, type-safe foundation for handling MCP tool responses. By eliminating `any` usage and providing standardized patterns, it improves code quality, maintainability, and developer experience while ensuring consistent behavior across all MCP tools.