/**
 * Unit Tests for Unified Response Interface
 *
 * Tests the core functions and interfaces of the unified response format
 */

import { describe, it, expect } from 'vitest';
import {
  createResponseMeta,
  UnifiedToolResponse,
  migrateLegacyResponse,
  SearchStrategy,
  UnifiedResponseMeta,
} from '../../src/types/unified-response.interface.js';

describe('Unified Response Interface', () => {
  describe('createResponseMeta function', () => {
    it('should create meta with all required fields', () => {
      const meta = createResponseMeta({
        strategy: 'auto',
        vector_used: true,
        degraded: false,
        source: 'test_source',
      });

      expect(meta.strategy).toBe('auto');
      expect(meta.vector_used).toBe(true);
      expect(meta.degraded).toBe(false);
      expect(meta.source).toBe('test_source');
      expect(meta).not.toHaveProperty('execution_time_ms');
      expect(meta).not.toHaveProperty('confidence_score');
      expect(meta).not.toHaveProperty('ttl');
    });

    it('should include optional fields when provided', () => {
      const meta = createResponseMeta({
        strategy: 'deep',
        vector_used: false,
        degraded: true,
        source: 'another_source',
        execution_time_ms: 250,
        confidence_score: 0.87,
        ttl: '24h',
      });

      expect(meta.strategy).toBe('deep');
      expect(meta.vector_used).toBe(false);
      expect(meta.degraded).toBe(true);
      expect(meta.source).toBe('another_source');
      expect(meta.execution_time_ms).toBe(250);
      expect(meta.confidence_score).toBe(0.87);
      expect(meta.ttl).toBe('24h');
    });

    it('should merge additional metadata correctly', () => {
      const additional = {
        operation_id: 'op-123',
        user_id: 'user-456',
        request_size: 1024,
        debug_mode: true,
      };

      const meta = createResponseMeta({
        strategy: 'fast',
        vector_used: true,
        degraded: false,
        source: 'test',
        additional,
      });

      // Should have all additional properties
      expect(meta.operation_id).toBe('op-123');
      expect(meta.user_id).toBe('user-456');
      expect(meta.request_size).toBe(1024);
      expect(meta.debug_mode).toBe(true);
    });

    it('should handle empty additional metadata', () => {
      const meta = createResponseMeta({
        strategy: 'semantic',
        vector_used: true,
        degraded: false,
        source: 'test',
        additional: {},
      });

      expect(meta.strategy).toBe('semantic');
      expect(Object.keys(meta)).toEqual(['strategy', 'vector_used', 'degraded', 'source']);
    });

    it('should validate strategy types', () => {
      const validStrategies: SearchStrategy[] = [
        'fast',
        'auto',
        'deep',
        'semantic',
        'keyword',
        'hybrid',
        'fallback',
        'autonomous_deduplication',
        'system_operation',
        'error',
      ];

      validStrategies.forEach((strategy) => {
        const meta = createResponseMeta({
          strategy,
          vector_used: true,
          degraded: false,
          source: 'test',
        });

        expect(meta.strategy).toBe(strategy);
      });
    });

    it('should handle edge cases for confidence scores', () => {
      const testCases = [
        { score: 0.0, expected: 0.0 },
        { score: 1.0, expected: 1.0 },
        { score: 0.5, expected: 0.5 },
        { score: 0.999, expected: 0.999 },
      ];

      testCases.forEach(({ score, expected }) => {
        const meta = createResponseMeta({
          strategy: 'auto',
          vector_used: true,
          degraded: false,
          source: 'test',
          confidence_score: score,
        });

        expect(meta.confidence_score).toBe(expected);
      });
    });
  });

  describe('migrateLegacyResponse function', () => {
    it('should migrate legacy observability to unified meta', () => {
      const legacyResponse = {
        results: [{ id: '1', content: 'test' }],
        total: 1,
        observability: {
          source: 'legacy_source',
          strategy: 'semantic',
          vector_used: true,
          degraded: false,
          execution_time_ms: 100,
          confidence_average: 0.95,
          search_id: 'search-123',
          extra_field: 'should_be_preserved',
        },
        other_field: 'should_be_preserved',
      };

      const migrated = migrateLegacyResponse(legacyResponse);

      expect(migrated).toHaveProperty('meta');
      expect(migrated).toHaveProperty('results');
      expect(migrated).toHaveProperty('total');
      expect(migrated).toHaveProperty('other_field');

      const meta = migrated.meta;
      expect(meta.strategy).toBe('semantic');
      expect(meta.vector_used).toBe(true);
      expect(meta.degraded).toBe(false);
      expect(meta.source).toBe('legacy_source');
      expect(meta.execution_time_ms).toBe(100);
      expect(meta.confidence_score).toBe(0.95);

      // Additional fields should be preserved
      expect(meta.search_id).toBe('search-123');
      expect(meta.extra_field).toBe('should_be_preserved');
    });

    it('should use default strategy when legacy has none', () => {
      const legacyResponse = {
        results: [],
        total: 0,
        observability: {
          source: 'test',
          vector_used: false,
          degraded: true,
        },
      };

      const migrated = migrateLegacyResponse(legacyResponse, 'fast');

      expect(migrated.meta.strategy).toBe('fast');
    });

    it('should handle response without observability field', () => {
      const legacyResponse = {
        results: [],
        total: 0,
        some_field: 'value',
      };

      const migrated = migrateLegacyResponse(legacyResponse, 'auto');

      expect(migrated.meta.strategy).toBe('auto');
      expect(migrated.meta.vector_used).toBe(false);
      expect(migrated.meta.degraded).toBe(false);
      expect(migrated.meta.source).toBe('cortex_memory');
    });

    it('should prefer confidence_score over confidence_average', () => {
      const legacyResponse = {
        results: [],
        total: 0,
        observability: {
          source: 'test',
          strategy: 'keyword',
          vector_used: false,
          degraded: false,
          confidence_score: 0.75,
          confidence_average: 0.85,
        },
      };

      const migrated = migrateLegacyResponse(legacyResponse);

      expect(migrated.meta.confidence_score).toBe(0.75);
    });

    it('should use confidence_average when confidence_score is missing', () => {
      const legacyResponse = {
        results: [],
        total: 0,
        observability: {
          source: 'test',
          strategy: 'hybrid',
          vector_used: true,
          degraded: false,
          confidence_average: 0.92,
        },
      };

      const migrated = migrateLegacyResponse(legacyResponse);

      expect(migrated.meta.confidence_score).toBe(0.92);
    });
  });

  describe('Type Safety and Interface Compliance', () => {
    it('should enforce UnifiedResponseMeta interface', () => {
      const meta: UnifiedResponseMeta = {
        strategy: 'auto',
        vector_used: true,
        degraded: false,
        source: 'test',
      };

      // Should compile without errors
      expect(meta.strategy).toBeDefined();
      expect(meta.vector_used).toBeDefined();
      expect(meta.degraded).toBeDefined();
      expect(meta.source).toBeDefined();
    });

    it('should enforce UnifiedToolResponse interface', () => {
      const response: UnifiedToolResponse = {
        data: { results: [], total: 0 },
        meta: {
          strategy: 'fast',
          vector_used: false,
          degraded: true,
          source: 'error_source',
        },
      };

      // Should compile without errors
      expect(response.data).toBeDefined();
      expect(response.meta).toBeDefined();
    });

    it('should allow rate limiting in UnifiedToolResponse', () => {
      const response: UnifiedToolResponse = {
        data: { results: [] },
        meta: {
          strategy: 'auto',
          vector_used: true,
          degraded: false,
          source: 'test',
        },
        rate_limit: {
          allowed: true,
          remaining: 100,
          reset_time: '2025-01-01T00:00:00Z',
          identifier: 'test-user',
        },
      };

      expect(response.rate_limit).toBeDefined();
      expect(response.rate_limit?.allowed).toBe(true);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle null/undefined additional metadata', () => {
      const meta = createResponseMeta({
        strategy: 'auto',
        vector_used: true,
        degraded: false,
        source: 'test',
        additional: undefined,
      });

      expect(meta).not.toHaveProperty('additional');
      expect(Object.keys(meta)).toEqual(['strategy', 'vector_used', 'degraded', 'source']);
    });

    it('should handle numeric zero values correctly', () => {
      const meta = createResponseMeta({
        strategy: 'auto',
        vector_used: true,
        degraded: false,
        source: 'test',
        execution_time_ms: 0,
        confidence_score: 0,
      });

      expect(meta.execution_time_ms).toBe(0);
      expect(meta.confidence_score).toBe(0);
    });

    it('should handle empty strings', () => {
      const meta = createResponseMeta({
        strategy: '',
        vector_used: true,
        degraded: false,
        source: '',
        ttl: '',
      });

      expect(meta.strategy).toBe('');
      expect(meta.source).toBe('');
      expect(meta.ttl).toBe('');
    });

    it('should handle complex additional metadata', () => {
      const complexAdditional = {
        nested: {
          level1: {
            level2: {
              value: 'deep_value',
            },
          },
        },
        array: [1, 2, 3],
        mixed_types: {
          str: 'string',
          num: 42,
          bool: true,
          null: null,
          undefined: undefined,
        },
      };

      const meta = createResponseMeta({
        strategy: 'auto',
        vector_used: true,
        degraded: false,
        source: 'test',
        additional: complexAdditional,
      });

      expect(meta.nested.level1.level2.value).toBe('deep_value');
      expect(meta.array).toEqual([1, 2, 3]);
      expect(meta.mixed_types.str).toBe('string');
      expect(meta.mixed_types.num).toBe(42);
      expect(meta.mixed_types.bool).toBe(true);
      expect(meta.mixed_types.null).toBe(null);
      expect(meta.mixed_types.undefined).toBeUndefined();
    });
  });

  describe('Performance and Memory', () => {
    it('should handle large additional metadata efficiently', () => {
      const largeAdditional = {};

      // Create large object with 1000 properties
      for (let i = 0; i < 1000; i++) {
        largeAdditional[`prop_${i}`] = `value_${i}`;
      }

      const startTime = Date.now();
      const meta = createResponseMeta({
        strategy: 'auto',
        vector_used: true,
        degraded: false,
        source: 'test',
        additional: largeAdditional,
      });
      const endTime = Date.now();

      // Should complete quickly (less than 100ms)
      expect(endTime - startTime).toBeLessThan(100);

      // Should have all properties
      expect(meta.prop_0).toBe('value_0');
      expect(meta.prop_999).toBe('value_999');
    });

    it('should not modify original additional metadata object', () => {
      const originalAdditional = {
        test_prop: 'test_value',
        nested: {
          inner: 'inner_value',
        },
      };

      const additionalCopy = JSON.parse(JSON.stringify(originalAdditional));

      createResponseMeta({
        strategy: 'auto',
        vector_used: true,
        degraded: false,
        source: 'test',
        additional: originalAdditional,
      });

      // Original should be unchanged
      expect(originalAdditional).toEqual(additionalCopy);
    });
  });
});
