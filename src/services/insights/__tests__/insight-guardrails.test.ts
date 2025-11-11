
/**
 * Comprehensive test suite for insight generation guardrails
 * Tests token caps, deterministic templates, provenance tracking, and reproducible outputs
 */

import { beforeEach, describe, expect, it, jest } from '@jest/globals';

import type { InsightTypeUnion } from '../../../types/insight-interfaces.js';
import { insightGenerationGuardrails } from '../insight-guardrails.js';

// Mock logger to avoid console output during tests
jest.mock('../../../utils/logger.js', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

describe('Insight Generation Guardrails', () => {
  let mockInsights: InsightTypeUnion[];
  let mockInputItems: any[];

  beforeEach(() => {
    // Create mock insights for testing
    mockInsights = [
      {
        id: 'insight-1',
        type: 'patterns',
        title: 'Test Pattern Insight',
        description:
          'This is a test pattern insight with some content that should be counted for token limits',
        confidence: 0.85,
        priority: 1,
        item_ids: ['item-1', 'item-2'],
        scope: { project: 'test-project' },
        metadata: {
          generated_at: '2025-01-01T00:00:00Z',
          generated_by: 'test',
          processing_time_ms: 100,
          data_sources: ['test'],
          tags: ['test'],
        },
        actionable: false,
        category: 'pattern' as const,
        pattern_data: {
          pattern_type: 'keyword_frequency',
          frequency: 5,
          occurrences: [],
          strength: 0.7,
        },
      },
      {
        id: 'insight-2',
        type: 'connections',
        title: 'Test Connection Insight',
        description: 'This is a test connection insight',
        confidence: 0.75,
        priority: 2,
        item_ids: ['item-3', 'item-4'],
        scope: { project: 'test-project' },
        metadata: {
          generated_at: '2025-01-01T00:00:00Z',
          generated_by: 'test',
          processing_time_ms: 150,
          data_sources: ['test'],
        },
        actionable: false,
        category: 'connection' as const,
        connection_data: {
          connection_type: 'project_scope',
          source_items: ['item-3'],
          target_items: ['item-4'],
          relationship_strength: 0.8,
          connection_description: 'Test connection',
        },
      },
    ];

    // Create mock input items
    mockInputItems = [
      {
        id: 'item-1',
        kind: 'decision',
        data: { title: 'Test Decision 1', content: 'Test content 1' },
        scope: { project: 'test-project' },
      },
      {
        id: 'item-2',
        kind: 'decision',
        data: { title: 'Test Decision 2', content: 'Test content 2' },
        scope: { project: 'test-project' },
      },
    ];
  });

  describe('Token Limit Validation', () => {
    it('should validate insights within token limits', () => {
      const result = insightGenerationGuardrails.validateTokenLimits(mockInsights);

      expect(result.valid).toBe(true);
      expect(result.violations).toHaveLength(0);
      expect(result.adjusted_insights).toHaveLength(mockInsights.length);
    });

    it('should detect individual insight token violations', () => {
      // Create an insight with very long content
      const longContentInsight: InsightTypeUnion = {
        ...mockInsights[0],
        description: 'A'.repeat(2000), // Very long description
      };

      const result = insightGenerationGuardrails.validateTokenLimits([longContentInsight]);

      expect(result.valid).toBe(false);
      expect(result.violations.length).toBeGreaterThan(0);
      expect(result.violations[0].insight_index).toBe(0);
      expect(result.violations[0].limit).toBe(500); // Default maxTokensPerInsight
    });

    it('should truncate insights exceeding token limits', () => {
      const longContentInsight: InsightTypeUnion = {
        ...mockInsights[0],
        description: 'A'.repeat(2000),
      };

      const result = insightGenerationGuardrails.validateTokenLimits([longContentInsight]);

      expect(result.adjusted_insights[0].description).toContain('... [truncated]');
      expect(result.adjusted_insights[0].description.length).toBeLessThan(2000);
    });

    it('should detect batch-level token violations', () => {
      // Create multiple insights that together exceed batch limit
      const manyInsights = Array(10)
        .fill(null)
        .map((_, index) => ({
          ...mockInsights[0],
          id: `insight-${index}`,
          description: 'A'.repeat(300), // Each insight ~75 tokens
        }));

      const result = insightGenerationGuardrails.validateTokenLimits(manyInsights);

      expect(result.valid).toBe(false);
      const batchViolation = result.violations.find((v) => v.insight_index === -1);
      expect(batchViolation).toBeDefined();
      expect(batchViolation?.limit).toBe(2000); // Default maxTokensPerBatch
    });

    it('should adjust batch to fit token limits', () => {
      const manyInsights = Array(10)
        .fill(null)
        .map((_, index) => ({
          ...mockInsights[0],
          id: `insight-${index}`,
          description: 'A'.repeat(300),
        }));

      const result = insightGenerationGuardrails.validateTokenLimits(manyInsights);

      expect(result.adjusted_insights.length).toBeLessThan(manyInsights.length);
      // Should keep only insights that fit within batch limit
      const totalTokens = result.adjusted_insights.reduce(
        (sum, insight) => sum + insightGenerationGuardrails['estimateTokens'](insight),
        0
      );
      expect(totalTokens).toBeLessThanOrEqual(2000);
    });
  });

  describe('Deterministic Templates', () => {
    it('should apply deterministic templates when enabled', () => {
      const context = {
        correlation_id: 'test-correlation-123',
        session_id: 'test-session-456',
      };

      const templatedInsights = insightGenerationGuardrails.applyDeterministicTemplates(
        mockInsights,
        context
      );

      expect(templatedInsights).toHaveLength(mockInsights.length);
      expect(templatedInsights[0].metadata?.template_applied).toBeDefined();
      expect(templatedInsights[0].metadata?.correlation_id).toBe('test-correlation-123');
    });

    it('should not apply templates when disabled', () => {
      // Create guardrails instance with deterministic templates disabled
      const guardrailsNoTemplates = new (insightGenerationGuardrails.constructor as any)({
        enableDeterministicTemplates: false,
      });

      const context = { correlation_id: 'test-123' };
      const result = guardrailsNoTemplates.applyDeterministicTemplates(mockInsights, context);

      expect(result).toEqual(mockInsights); // Should return unchanged insights
    });

    it('should handle unknown insight types gracefully', () => {
      const unknownTypeInsight: InsightTypeUnion = {
        ...mockInsights[0],
        type: 'unknown_type',
      };

      const context = { correlation_id: 'test-123' };
      const result = insightGenerationGuardrails.applyDeterministicTemplates(
        [unknownTypeInsight],
        context
      );

      expect(result).toHaveLength(1);
      expect(result[0].type).toBe('unknown_type'); // Should not change unknown types
    });
  });

  describe('Provenance Tracking', () => {
    it('should track provenance for insights when enabled', () => {
      const context = {
        correlation_id: 'test-correlation-123',
        session_id: 'test-session-456',
        processing_time_ms: 250,
      };

      const provenanceRecords = insightGenerationGuardrails.trackProvenance(
        mockInsights,
        mockInputItems,
        context
      );

      expect(provenanceRecords).toHaveLength(mockInsights.length);

      const provenance = provenanceRecords[0];
      expect(provenance.insight_id).toBe(mockInsights[0].id);
      expect(provenance.generation_timestamp).toBeDefined();
      expect(provenance.input_items_hash).toBeDefined();
      expect(provenance.template_used).toBeDefined();
      expect(provenance.configuration_snapshot).toBeDefined();
      expect(provenance.processing_context.correlation_id).toBe('test-correlation-123');
      expect(provenance.processing_context.session_id).toBe('test-session-456');
      expect(provenance.performance_metrics.generation_time_ms).toBe(250);
      expect(provenance.performance_metrics.tokens_estimated).toBeGreaterThan(0);
    });

    it('should not track provenance when disabled', () => {
      const guardrailsNoProvenance = new (insightGenerationGuardrails.constructor as any)({
        enableProvenanceTracking: false,
      });

      const context = { correlation_id: 'test-123', processing_time_ms: 100 };
      const result = guardrailsNoProvenance.trackProvenance(mockInsights, mockInputItems, context);

      expect(result).toHaveLength(0);
    });

    it('should generate consistent input items hash', () => {
      const context1 = { correlation_id: 'test-1', processing_time_ms: 100 };
      const context2 = { correlation_id: 'test-2', processing_time_ms: 100 };

      const provenance1 = insightGenerationGuardrails.trackProvenance(
        mockInsights,
        mockInputItems,
        context1
      );
      const provenance2 = insightGenerationGuardrails.trackProvenance(
        mockInsights,
        mockInputItems,
        context2
      );

      // Input hash should be the same regardless of correlation ID
      expect(provenance1[0].input_items_hash).toBe(provenance2[0].input_items_hash);
    });

    it('should store provenance records for retrieval', () => {
      const context = { correlation_id: 'test-123', processing_time_ms: 100 };
      insightGenerationGuardrails.trackProvenance(mockInsights, mockInputItems, context);

      const retrievedProvenance = insightGenerationGuardrails.getProvenance(mockInsights[0].id);
      expect(retrievedProvenance).toBeDefined();
      expect(retrievedProvenance?.insight_id).toBe(mockInsights[0].id);
    });

    it('should return null for non-existent provenance', () => {
      const nonExistentProvenance = insightGenerationGuardrails.getProvenance('non-existent-id');
      expect(nonExistentProvenance).toBeNull();
    });
  });

  describe('Reproducible Outputs', () => {
    it('should ensure reproducible outputs when enabled', () => {
      const context = {
        correlation_id: 'test-correlation-123',
        input_hash: 'test-input-hash-456',
      };

      const reproducibleInsights = insightGenerationGuardrails.ensureReproducibleOutputs(
        mockInsights,
        context
      );

      expect(reproducibleInsights).toHaveLength(mockInsights.length);
      expect(reproducibleInsights[0].metadata?.reproducible).toBeDefined();
      expect(reproducibleInsights[0].metadata?.reproducible?.correlation_id).toBe(
        'test-correlation-123'
      );
      expect(reproducibleInsights[0].metadata?.reproducible?.input_hash).toBe(
        'test-input-hash-456'
      );
      expect(reproducibleInsights[0].metadata?.reproducible?.generation_id).toBeDefined();
      expect(reproducibleInsights[0].metadata?.reproducible?.generated_at).toBeDefined();
    });

    it('should not modify insights when reproducible outputs disabled', () => {
      const guardrailsNoReproducible = new (insightGenerationGuardrails.constructor as any)({
        enableReproducibleOutputs: false,
      });

      const context = { correlation_id: 'test-123', input_hash: 'test-hash' };
      const result = guardrailsNoReproducible.ensureReproducibleOutputs(mockInsights, context);

      expect(result).toEqual(mockInsights);
    });

    it('should generate deterministic reproducible IDs', () => {
      const context = {
        correlation_id: 'test-correlation-123',
        input_hash: 'test-input-hash-456',
      };

      const reproducibleInsights1 = insightGenerationGuardrails.ensureReproducibleOutputs(
        mockInsights,
        context
      );
      const reproducibleInsights2 = insightGenerationGuardrails.ensureReproducibleOutputs(
        mockInsights,
        context
      );

      // Same context should generate same reproducible ID
      expect(reproducibleInsights1[0].metadata?.reproducible?.generation_id).toBe(
        reproducibleInsights2[0].metadata?.reproducible?.generation_id
      );
    });
  });

  describe('Deterministic Cache Keys', () => {
    it('should generate deterministic cache keys when enabled', () => {
      const input = {
        items: mockInputItems,
        config: { threshold: 0.8, max_insights: 10 },
        correlation_id: 'test-correlation-123',
      };

      const cacheKey1 = insightGenerationGuardrails.generateDeterministicCacheKey(input);
      const cacheKey2 = insightGenerationGuardrails.generateDeterministicCacheKey(input);

      // Same input should generate same cache key
      expect(cacheKey1).toBe(cacheKey2);
      expect(cacheKey1).toMatch(/^[a-f0-9]{64}$/); // Should be SHA-256 hash
    });

    it('should generate different cache keys for different inputs', () => {
      const input1 = {
        items: mockInputItems,
        config: { threshold: 0.8 },
        correlation_id: 'test-1',
      };

      const input2 = {
        items: mockInputItems,
        config: { threshold: 0.9 }, // Different config
        correlation_id: 'test-1',
      };

      const cacheKey1 = insightGenerationGuardrails.generateDeterministicCacheKey(input1);
      const cacheKey2 = insightGenerationGuardrails.generateDeterministicCacheKey(input2);

      expect(cacheKey1).not.toBe(cacheKey2);
    });
  });

  describe('Provenance Cleanup', () => {
    it('should clean up old provenance records', () => {
      // Track some provenance first
      const context = { correlation_id: 'test-123', processing_time_ms: 100 };
      insightGenerationGuardrails.trackProvenance(mockInsights, mockInputItems, context);

      // Mock time to simulate old records
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 31); // 31 days ago

      // @ts-ignore - Accessing private method for testing
      insightGenerationGuardrails['provenanceStore'].forEach((_provenance, _id) => {
        _provenance.generation_timestamp = thirtyDaysAgo.toISOString();
      });

      const cleanedCount = insightGenerationGuardrails.cleanupProvenance();
      expect(cleanedCount).toBe(mockInsights.length);
    });

    it('should not clean up recent provenance records', () => {
      const context = { correlation_id: 'test-123', processing_time_ms: 100 };
      insightGenerationGuardrails.trackProvenance(mockInsights, mockInputItems, context);

      const cleanedCount = insightGenerationGuardrails.cleanupProvenance();
      expect(cleanedCount).toBe(0); // No records should be cleaned up

      // Records should still be available
      const provenance = insightGenerationGuardrails.getProvenance(mockInsights[0].id);
      expect(provenance).toBeDefined();
    });
  });

  describe('Token Estimation Methods', () => {
    it('should estimate tokens using approximate method', () => {
      const guardrailsApproximate = new (insightGenerationGuardrails.constructor as any)({
        tokenCountingMethod: 'approximate',
      });

      const insight = mockInsights[0];
      // @ts-ignore - Accessing private method for testing
      const estimatedTokens = guardrailsApproximate['estimateTokens'](insight);

      expect(estimatedTokens).toBeGreaterThan(0);
      expect(typeof estimatedTokens).toBe('number');
    });

    it('should estimate tokens using exact method', () => {
      const guardrailsExact = new (insightGenerationGuardrails.constructor as any)({
        tokenCountingMethod: 'exact',
      });

      const insight = mockInsights[0];
      // @ts-ignore - Accessing private method for testing
      const estimatedTokens = guardrailsExact['estimateTokens'](insight);

      expect(estimatedTokens).toBeGreaterThan(0);
      expect(typeof estimatedTokens).toBe('number');
    });
  });

  describe('Error Handling', () => {
    it('should handle malformed insights gracefully', () => {
      const malformedInsight = {
        ...mockInsights[0],
        description: null, // Malformed field
      };

      expect(() => {
        insightGenerationGuardrails.validateTokenLimits([malformedInsight]);
      }).not.toThrow();
    });

    it('should handle empty insight arrays', () => {
      const result = insightGenerationGuardrails.validateTokenLimits([]);
      expect(result.valid).toBe(true);
      expect(result.violations).toHaveLength(0);
      expect(result.adjusted_insights).toHaveLength(0);
    });

    it('should handle empty input items for provenance', () => {
      const context = { correlation_id: 'test-123', processing_time_ms: 100 };
      const provenance = insightGenerationGuardrails.trackProvenance(mockInsights, [], context);

      expect(provenance).toHaveLength(mockInsights.length);
      expect(provenance[0].input_items_hash).toBeDefined();
    });
  });
});
