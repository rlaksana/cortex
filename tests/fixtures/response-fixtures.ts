/**
 * Response Test Fixtures - T22 Support
 *
 * Provides various response fixtures for comprehensive response format testing.
 * Includes success responses, error responses, batch responses, and performance data.
 *
 * @version 2.0.1
 */

import { v4 as uuidv4 } from 'uuid';

// ============================================================================
// Base Response Structure
// ============================================================================

export function createResponseMeta(overrides: any = {}) {
  return {
    requestId: uuidv4(),
    timestamp: new Date().toISOString(),
    operation: 'memory_store',
    duration: Math.floor(Math.random() * 1000) + 100,
    version: '2.0.1',
    apiVersion: '2.0.1',
    minCompatibleVersion: '2.0.0',
    ...overrides,
  };
}

export function createBaseResponse(operation: string, isError: boolean = false, overrides: any = {}) {
  return {
    content: [],
    _meta: createResponseMeta({ operation, ...overrides }),
    isError,
  };
}

// ============================================================================
// Success Response Fixtures
// ============================================================================

export function createValidToolResponse(
  operation: 'memory_store' | 'memory_find' = 'memory_store',
  options: any = {}
) {
  const baseResponse = createBaseResponse(operation, false);

  if (operation === 'memory_store') {
    baseResponse.content = [
      {
        type: 'text',
        text: options.content || 'Successfully stored 2 knowledge items in Cortex memory',
      },
      {
        type: 'json',
        text: JSON.stringify({
          storedItems: options.storedItems || 2,
          duplicatesFound: options.duplicatesFound || 0,
          operationId: uuidv4(),
        }),
      },
    ];

    baseResponse._meta = {
      ...baseResponse._meta,
      itemsProcessed: options.itemsProcessed || 2,
      duplicatesFound: options.duplicatesFound || 0,
      deduplicationEnabled: options.deduplicationEnabled !== false,
      batchSize: options.batchSize || 2,
    };
  } else if (operation === 'memory_find') {
    baseResponse.content = [
      {
        type: 'text',
        text: options.content || `Found ${options.resultCount || 5} results matching your query`,
      },
      {
        type: 'json',
        text: JSON.stringify({
          results: options.results || createMockSearchResults(options.resultCount || 5),
          totalCount: options.resultCount || 5,
          queryInfo: {
            originalQuery: options.query || 'test query',
            processedQuery: options.query || 'test query',
            searchStrategy: options.searchStrategy || 'auto',
          },
        }),
      },
    ];

    baseResponse._meta = {
      ...baseResponse._meta,
      resultCount: options.resultCount || 5,
      queryInfo: {
        originalQuery: options.query || 'test query',
        searchStrategy: options.searchStrategy || 'auto',
        processedQuery: options.query || 'test query',
      },
      resultFormat: options.resultFormat || 'detailed',
    };

    if (options.includeAnalytics) {
      baseResponse._meta.analytics = {
        searchDuration: Math.floor(Math.random() * 500) + 50,
        totalScanned: Math.floor(Math.random() * 1000) + 100,
        similarityThreshold: 0.7,
        expansionCount: Math.floor(Math.random() * 10) + 1,
      };
    }
  }

  return baseResponse;
}

export function createResponseWithMetadata(overrides: any = {}) {
  return {
    ...createValidToolResponse('memory_store'),
    _meta: {
      ...createResponseMeta({ operation: 'memory_store' }),
      ...overrides,
    },
  };
}

// ============================================================================
// Error Response Fixtures
// ============================================================================

export function createErrorResponse(errorConfig: any = {}) {
  const defaultError = {
    code: 'VALIDATION_ERROR',
    message: 'Invalid input provided',
    type: 'validation',
    field: 'items.0.kind',
    details: {
      expectedValue: 'entity|relation|observation|...',
      actualValue: 'invalid_kind',
      allowedValues: ['entity', 'relation', 'observation', 'section', 'runbook'],
    },
  };

  const error = { ...defaultError, ...errorConfig };

  return {
    content: [
      {
        type: 'text',
        text: `${error.type === 'validation' ? 'Validation error' : 'Error'}: ${error.message}`,
      },
      {
        type: 'json',
        text: JSON.stringify({
          error: {
            code: error.code,
            message: error.message,
            field: error.field,
            details: error.details,
          },
        }),
      },
    ],
    _meta: createResponseMeta({
      operation: 'memory_store',
      error,
      ...errorConfig.metaOverrides,
    }),
    isError: true,
  };
}

// ============================================================================
// Batch Response Fixtures
// ============================================================================

export function createBatchResponse(
  operation: 'memory_store' | 'memory_find',
  itemCount: number,
  options: any = {}
) {
  const successes = options.successes ?? Math.max(0, itemCount - (options.failures || 0));
  const failures = options.failures ?? Math.max(0, itemCount - successes);
  const hasFailures = failures > 0;
  const hasSuccesses = successes > 0;

  const content = [];

  if (hasSuccesses) {
    content.push({
      type: 'text',
      text: `Successfully processed ${successes} item${successes === 1 ? '' : 's'}`,
    });
  }

  if (hasFailures) {
    content.push({
      type: 'text',
      text: `Failed to process ${failures} item${failures === 1 ? '' : 's'}`,
    });
  }

  if (options.includeDetails) {
    const results = [];

    for (let i = 0; i < itemCount; i++) {
      const isSuccess = i < successes;
      results.push({
        index: i,
        success: isSuccess,
        itemId: uuidv4(),
        ...(isSuccess
          ? {
              storedId: uuidv4(),
              similarityScore: Math.random() * 0.3 + 0.7,
            }
          : {
              error: {
                code: 'VALIDATION_ERROR',
                message: `Invalid item at index ${i}`,
              },
            }),
      });
    }

    content.push({
      type: 'json',
      text: JSON.stringify({ results }),
    });
  }

  return {
    content,
    _meta: createResponseMeta({
      operation,
      batchId: uuidv4(),
      itemCount,
      processedItems: successes,
      failedItems: failures,
      ...(options.includeDetails && { results: options.results }),
      ...options.metaOverrides,
    }),
    isError: successes === 0 && failures > 0, // Complete failure = error, partial success = not error
  };
}

// ============================================================================
// Performance Response Fixtures
// ============================================================================

export function createPerformanceResponse(overrides: any = {}) {
  const baseResponse = createValidToolResponse('memory_store', overrides);

  baseResponse._meta.performance = {
    duration: Math.floor(Math.random() * 2000) + 500,
    memoryUsage: {
      used: Math.floor(Math.random() * 100 * 1024 * 1024) + 10 * 1024 * 1024, // 10-110MB
      peak: Math.floor(Math.random() * 150 * 1024 * 1024) + 20 * 1024 * 1024, // 20-170MB
      limit: 512 * 1024 * 1024, // 512MB
    },
    cpuUsage: Math.random() * 50 + 10, // 10-60%
    ...overrides.performance,
  };

  return baseResponse;
}

// ============================================================================
// Search Response Fixtures
// ============================================================================

export function createMockSearchResults(count: number) {
  const results = [];
  const kinds = ['entity', 'relation', 'observation', 'decision', 'issue'];

  for (let i = 0; i < count; i++) {
    results.push({
      id: uuidv4(),
      kind: kinds[i % kinds.length],
      content: `Mock search result ${i + 1}`,
      confidence: Math.random() * 0.3 + 0.7,
      metadata: {
        created: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
        scope: {
          project: 'test-project',
          branch: 'main',
        },
      },
    });
  }

  return results;
}

export function createSearchResponse(query: string, options: any = {}) {
  const resultCount = options.resultCount || Math.floor(Math.random() * 20) + 1;
  const results = createMockSearchResults(resultCount);

  return {
    content: [
      {
        type: 'text',
        text: `Found ${resultCount} results for query: "${query}"`,
      },
      {
        type: 'json',
        text: JSON.stringify({
          results,
          totalCount: resultCount,
          query,
          searchStrategy: options.searchStrategy || 'auto',
        }),
      },
    ],
    _meta: createResponseMeta({
      operation: 'memory_find',
      resultCount,
      query,
      searchStrategy: options.searchStrategy || 'auto',
      resultFormat: options.resultFormat || 'detailed',
      ...options.metaOverrides,
    }),
    isError: false,
  };
}

// ============================================================================
// Edge Case Response Fixtures
// ============================================================================

export function createEmptySearchResponse(query: string) {
  return {
    content: [
      {
        type: 'text',
        text: `No results found for query: "${query}"`,
      },
    ],
    _meta: createResponseMeta({
      operation: 'memory_find',
      resultCount: 0,
      query,
      searchStrategy: 'auto',
    }),
    isError: false,
  };
}

export function createLargeResponse(operation: 'memory_store' | 'memory_find') {
  if (operation === 'memory_store') {
    return createBatchResponse('memory_store', 100, {
      includeDetails: true,
      successes: 95,
      failures: 5,
    });
  } else {
    return createSearchResponse('large query test', {
      resultCount: 50,
      includeAnalytics: true,
    });
  }
}

export function createTimeoutResponse(operation: 'memory_store' | 'memory_find') {
  return {
    content: [
      {
        type: 'text',
        text: `Operation ${operation} timed out after 30 seconds`,
      },
    ],
    _meta: createResponseMeta({
      operation,
      error: {
        code: 'TIMEOUT',
        message: `Operation ${operation} timed out after 30 seconds`,
        type: 'operational',
        details: {
          timeout: 30000,
          operation,
          partialResults: operation === 'memory_find',
        },
      },
    }),
    isError: true,
  };
}

export function createRateLimitResponse() {
  return {
    content: [
      {
        type: 'text',
        text: 'Rate limit exceeded. Please try again later.',
      },
    ],
    _meta: createResponseMeta({
      operation: 'memory_store',
      error: {
        code: 'RATE_LIMITED',
        message: 'Rate limit exceeded',
        type: 'operational',
        details: {
          limit: 100,
          current: 101,
          resetTime: new Date(Date.now() + 60000).toISOString(),
          retryAfter: 60,
        },
      },
    }),
    isError: true,
  };
}

// ============================================================================
// Special Character Response Fixtures
// ============================================================================

export function createSpecialCharResponse() {
  const specialText = 'Test with special characters: 🧠 Cortex Memory, 中文测试, ñáéíóú, العربية, हिन्दी';

  return {
    content: [
      {
        type: 'text',
        text: specialText,
      },
      {
        type: 'json',
        text: JSON.stringify({
          message: specialText,
          unicode: '🧠',
          chinese: '中文测试',
          spanish: 'ñáéíóú',
          arabic: 'العربية',
          hindi: 'हिन्दी',
        }),
      },
    ],
    _meta: createResponseMeta({
      operation: 'memory_store',
      specialChars: true,
    }),
    isError: false,
  };
}

// ============================================================================
// Response Validation Fixtures
// ============================================================================

export function createInvalidResponses() {
  return [
    // Missing content
    {
      _meta: createResponseMeta(),
      isError: false,
    },

    // Missing metadata
    {
      content: [{ type: 'text', text: 'test' }],
      isError: false,
    },

    // Invalid content structure
    {
      content: 'not an array',
      _meta: createResponseMeta(),
      isError: false,
    },

    // Invalid content item
    {
      content: [{ type: 'invalid' }],
      _meta: createResponseMeta(),
      isError: false,
    },

    // Missing error flag for error response
    {
      content: [{ type: 'text', text: 'Error occurred' }],
      _meta: createResponseMeta({
        error: { code: 'TEST_ERROR', message: 'Test error' },
      }),
    },

    // Invalid metadata structure
    {
      content: [{ type: 'text', text: 'test' }],
      _meta: 'not an object',
      isError: false,
    },

    // Invalid error structure
    {
      content: [{ type: 'text', text: 'Error' }],
      _meta: createResponseMeta(),
      isError: true,
      // Missing error details in metadata
    },
  ];
}

// ============================================================================
// Performance Test Response Fixtures
// ============================================================================

export function createPerformanceTestResponses() {
  return {
    fast: createValidToolResponse('memory_find', {
      resultCount: 1,
      duration: 50,
    }),

    medium: createValidToolResponse('memory_find', {
      resultCount: 10,
      duration: 200,
    }),

    slow: createValidToolResponse('memory_find', {
      resultCount: 100,
      duration: 1000,
    }),

    memoryIntensive: createBatchResponse('memory_store', 1000, {
      successes: 1000,
      failures: 0,
      duration: 5000,
    }),

    cpuIntensive: createValidToolResponse('memory_find', {
      resultCount: 50,
      searchStrategy: 'deep',
      duration: 3000,
      includeAnalytics: true,
    }),
  };
}

// ============================================================================
// Integration Test Response Fixtures
// ============================================================================

export function createIntegrationTestResponses() {
  const requestId = uuidv4();

  return {
    storeResponse: createValidToolResponse('memory_store', {
      metaOverrides: { requestId },
      itemsProcessed: 5,
      duplicatesFound: 1,
    }),

    findResponse: createSearchResponse('test query', {
      metaOverrides: { requestId },
      resultCount: 3,
      searchStrategy: 'auto',
    }),

    batchStoreResponse: createBatchResponse('memory_store', 10, {
      metaOverrides: { requestId },
      successes: 8,
      failures: 2,
      includeDetails: true,
    }),

    emptyFindResponse: createEmptySearchResponse('nonexistent query'),
  };
}

// ============================================================================
// Backward Compatibility Response Fixtures
// ============================================================================

export function createLegacyResponseFormat() {
  // Simulate older response format (v1.x)
  return {
    success: true,
    data: {
      storedItems: 2,
      operationId: uuidv4(),
    },
    message: 'Items stored successfully',
    timestamp: new Date().toISOString(),
  };
}

export function createV2ResponseFromLegacy(legacyResponse: any) {
  // Convert legacy format to v2 format
  return {
    content: [
      {
        type: 'text',
        text: legacyResponse.message || 'Operation completed',
      },
      {
        type: 'json',
        text: JSON.stringify(legacyResponse.data || {}),
      },
    ],
    _meta: createResponseMeta({
      operation: 'memory_store',
      legacy: true,
      originalFormat: 'v1.x',
    }),
    isError: !legacyResponse.success,
  };
}