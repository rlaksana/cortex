/**
 * MCP Response Envelope System Tests
 *
 * Tests for the response envelope system to ensure type safety,
 * validation, and proper functionality.
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { describe, it, expect } from 'vitest';
import {
  createResponseEnvelopeBuilder,
  ErrorCode,
  type SuccessEnvelope,
  type ErrorEnvelope,
} from '../response-envelope-builder';
import {
  ResponseEnvelopeValidator,
  validateEnvelopeOrThrow,
  validateOperationResponseOrThrow,
} from '../response-envelope-validator';
import {
  isMemoryStoreResponse,
  isMemoryFindResponse,
  isSystemStatusResponse,
  extractMemoryStoreData,
  extractMemoryFindData,
  extractSystemStatusData,
  ResponseProcessor,
  createResponseMatcher,
} from '../mcp-response-guards';
import type { MemoryStoreResult, MemoryFindResult } from '../../types/mcp-response-data.types';

describe('ResponseEnvelopeBuilder', () => {
  it('should create a success envelope with valid structure', () => {
    const builder = createResponseEnvelopeBuilder('test_operation');
    const testData = { message: 'test data' };
    const mockMeta = {
      strategy: 'auto' as const,
      vector_used: false,
      degraded: false,
      source: 'test',
    };

    const envelope = builder.createSuccessEnvelope(testData, mockMeta, 'Success message');

    expect(envelope.type).toBe('success');
    expect(envelope.success).toBe(true);
    expect(envelope.data).toEqual(testData);
    expect(envelope.message).toBe('Success message');
    expect(envelope.timestamp).toBeDefined();
    expect(envelope.request_id).toBeDefined();
    expect(envelope.api_version).toBeDefined();
  });

  it('should create an error envelope with valid structure', () => {
    const builder = createResponseEnvelopeBuilder('test_operation');
    const error = new Error('Test error');

    const envelope = builder.createErrorEnvelope(
      ErrorCode.VALIDATION_FAILED,
      'Test error message',
      'ValidationError',
      { field: 'test' }
    );

    expect(envelope.type).toBe('error');
    expect(envelope.success).toBe(false);
    expect(envelope.data).toBe(null);
    expect(envelope.error.code).toBe(ErrorCode.VALIDATION_FAILED);
    expect(envelope.error.message).toBe('Test error message');
    expect(envelope.error.type).toBe('ValidationError');
    expect(envelope.error.details).toEqual({ field: 'test' });
    expect(envelope.error.retryable).toBe(false);
    expect(envelope.error_id).toBeDefined();
  });

  it('should create a paginated envelope with valid structure', () => {
    const builder = createResponseEnvelopeBuilder('test_operation');
    const testItems = ['item1', 'item2', 'item3'];
    const mockMeta = {
      strategy: 'auto' as const,
      vector_used: false,
      degraded: false,
      source: 'test',
    };

    const pagination = {
      page: 1,
      per_page: 10,
      total: 100,
      total_pages: 10,
      has_next: true,
      has_prev: false,
    };

    const envelope = builder.createPaginatedEnvelope(testItems, pagination, mockMeta);

    expect(envelope.type).toBe('paginated');
    expect(envelope.success).toBe(true);
    expect(envelope.data).toEqual(testItems);
    expect(envelope.pagination).toEqual(pagination);
  });

  it('should create a streaming envelope with valid structure', () => {
    const builder = createResponseEnvelopeBuilder('test_operation');
    const testData = { chunk: 'data' };
    const mockMeta = {
      strategy: 'auto' as const,
      vector_used: false,
      degraded: false,
      source: 'test',
    };

    const envelope = builder.createStreamingEnvelope(testData, 'stream123', 1, 'active', mockMeta);

    expect(envelope.type).toBe('streaming');
    expect(envelope.success).toBe(true);
    expect(envelope.data).toEqual(testData);
    expect(envelope.stream.stream_id).toBe('stream123');
    expect(envelope.stream.chunk_number).toBe(1);
    expect(envelope.stream.status).toBe('active');
    expect(envelope.stream.is_final).toBe(false);
  });
});

describe('ResponseEnvelopeValidator', () => {
  it('should validate a correct success envelope', () => {
    const builder = createResponseEnvelopeBuilder('test_operation');
    const envelope = builder.createSuccessEnvelope(
      { test: 'data' },
      {
        strategy: 'auto',
        vector_used: false,
        degraded: false,
        source: 'test',
      }
    );

    const validation = ResponseEnvelopeValidator.validateEnvelope(envelope);

    expect(validation.valid).toBe(true);
    expect(validation.errors).toHaveLength(0);
  });

  it('should detect errors in invalid envelope', () => {
    const invalidEnvelope = {
      type: 'success',
      success: true,
      // Missing required fields
    };

    const validation = ResponseEnvelopeValidator.validateEnvelope(invalidEnvelope);

    expect(validation.valid).toBe(false);
    expect(validation.errors.length).toBeGreaterThan(0);
  });

  it('should validate memory store result data', () => {
    const memoryStoreData: MemoryStoreResult = {
      stored_items: [{ id: '1', content: 'test' }],
      failed_items: [],
      summary: {
        total_attempted: 1,
        total_stored: 1,
        total_failed: 0,
        success_rate: 1.0,
      },
      batch_id: 'batch123',
    };

    const validation = ResponseEnvelopeValidator.validateMemoryStoreResult(memoryStoreData);

    expect(validation.valid).toBe(true);
  });

  it('should validate memory find result data', () => {
    const memoryFindData: MemoryFindResult = {
      query: 'test query',
      strategy: 'auto',
      confidence: 0.8,
      total: 5,
      items: [{ id: '1', content: 'result' }],
      search_id: 'search123',
      strategy_details: {
        type: 'auto',
        parameters: {},
        execution: {
          vector_used: false,
          semantic_search: false,
          keyword_search: true,
          fuzzy_matching: false,
        },
      },
    };

    const validation = ResponseEnvelopeValidator.validateMemoryFindResult(memoryFindData);

    expect(validation.valid).toBe(true);
  });
});

describe('Response Type Guards', () => {
  it('should correctly identify memory store responses', () => {
    const builder = createResponseEnvelopeBuilder('memory_store');
    const memoryStoreData: MemoryStoreResult = {
      stored_items: [{ id: '1', content: 'test' }],
      failed_items: [],
      summary: {
        total_attempted: 1,
        total_stored: 1,
        total_failed: 0,
        success_rate: 1.0,
      },
      batch_id: 'batch123',
    };

    const envelope = builder.createMemoryStoreSuccess(memoryStoreData);

    expect(isMemoryStoreResponse(envelope)).toBe(true);
    expect(extractMemoryStoreData(envelope)).toEqual(memoryStoreData);
  });

  it('should correctly identify memory find responses', () => {
    const builder = createResponseEnvelopeBuilder('memory_find');
    const memoryFindData: MemoryFindResult = {
      query: 'test query',
      strategy: 'auto',
      confidence: 0.8,
      total: 5,
      items: [{ id: '1', content: 'result' }],
      search_id: 'search123',
      strategy_details: {
        type: 'auto',
        parameters: {},
        execution: {
          vector_used: false,
          semantic_search: false,
          keyword_search: true,
          fuzzy_matching: false,
        },
      },
    };

    const envelope = builder.createMemoryFindSuccess(memoryFindData);

    expect(isMemoryFindResponse(envelope)).toBe(true);
    expect(extractMemoryFindData(envelope)).toEqual(memoryFindData);
  });

  it('should return null for non-matching responses', () => {
    const builder = createResponseEnvelopeBuilder('test_operation');
    const errorEnvelope = builder.createErrorEnvelope(
      ErrorCode.INTERNAL_SERVER_ERROR,
      'Test error'
    );

    expect(extractMemoryStoreData(errorEnvelope)).toBe(null);
    expect(extractMemoryFindData(errorEnvelope)).toBe(null);
  });
});

describe('ResponseProcessor', () => {
  it('should process success responses correctly', () => {
    const builder = createResponseEnvelopeBuilder('test_operation');
    const envelope = builder.createSuccessEnvelope(
      { result: 'success' },
      {
        strategy: 'auto',
        vector_used: false,
        degraded: false,
        source: 'test',
      }
    );

    const result = ResponseProcessor.process(envelope, {
      onSuccess: (data) => `Processed: ${data.result}`,
      onError: () => 'Error processed',
      onUnknown: () => 'Unknown processed',
    });

    expect(result).toBe('Processed: success');
  });

  it('should process error responses correctly', () => {
    const builder = createResponseEnvelopeBuilder('test_operation');
    const envelope = builder.createErrorEnvelope(ErrorCode.VALIDATION_FAILED, 'Test error');

    const result = ResponseProcessor.process(envelope, {
      onSuccess: () => 'Success processed',
      onError: (error) => `Error: ${error.message}`,
      onUnknown: () => 'Unknown processed',
    });

    expect(result).toBe('Error: Test error');
  });

  it('should process memory store responses with specialized handler', () => {
    const builder = createResponseEnvelopeBuilder('memory_store');
    const memoryStoreData: MemoryStoreResult = {
      stored_items: [{ id: '1', content: 'test' }],
      failed_items: [],
      summary: {
        total_attempted: 1,
        total_stored: 1,
        total_failed: 0,
        success_rate: 1.0,
      },
      batch_id: 'batch123',
    };

    const envelope = builder.createMemoryStoreSuccess(memoryStoreData);

    const result = ResponseProcessor.processMemoryStore(envelope, {
      onSuccess: (data) => `Stored ${data.summary.total_stored} items`,
      onError: () => 'Error processed',
      onUnknown: () => 'Unknown processed',
    });

    expect(result).toBe('Stored 1 items');
  });
});

describe('ResponseMatcher', () => {
  it('should match success case correctly', () => {
    const builder = createResponseEnvelopeBuilder('test_operation');
    const envelope = builder.createSuccessEnvelope(
      { result: 'success' },
      {
        strategy: 'auto',
        vector_used: false,
        degraded: false,
        source: 'test',
      }
    );

    const result = createResponseMatcher(envelope)
      .onSuccess((data) => `Success: ${data.result}`)
      .onError((error) => `Error: ${(error as Error).message}`)
      .otherwise(() => 'Unknown');

    expect(result).toBe('Success: success');
  });

  it('should match error case correctly', () => {
    const builder = createResponseEnvelopeBuilder('test_operation');
    const envelope = builder.createErrorEnvelope(ErrorCode.VALIDATION_FAILED, 'Test error');

    const result = createResponseMatcher(envelope)
      .onSuccess((data) => `Success: ${JSON.stringify(data)}`)
      .onError((error) => `Error: ${error.message}`)
      .otherwise(() => 'Unknown');

    expect(result).toBe('Error: Test error');
  });
});

describe('validateOperationResponseOrThrow', () => {
  it('should validate correct operation response', () => {
    const builder = createResponseEnvelopeBuilder('memory_store');
    const memoryStoreData: MemoryStoreResult = {
      stored_items: [{ id: '1', content: 'test' }],
      failed_items: [],
      summary: {
        total_attempted: 1,
        total_stored: 1,
        total_failed: 0,
        success_rate: 1.0,
      },
      batch_id: 'batch123',
    };

    const envelope = builder.createMemoryStoreSuccess(memoryStoreData);

    expect(() => {
      validateOperationResponseOrThrow(envelope, 'memory_store');
    }).not.toThrow();
  });

  it('should throw on invalid operation response', () => {
    const invalidEnvelope = {
      type: 'success',
      success: true,
      data: { invalid: 'data' }, // Missing required fields for memory store
      meta: {
        strategy: 'auto',
        vector_used: false,
        degraded: false,
        source: 'test',
      },
      timestamp: new Date().toISOString(),
      request_id: 'test',
      api_version: '1.0.0',
    };

    expect(() => {
      validateOperationResponseOrThrow(invalidEnvelope as unknown, 'memory_store');
    }).toThrow();
  });
});
