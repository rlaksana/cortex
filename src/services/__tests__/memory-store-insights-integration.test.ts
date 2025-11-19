import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { environment } from '../../config/environment';
import type { PatternInsight } from '../../types/insight-interfaces.js';
import { insightGenerationService } from '../insights/insight-generation-service';
import { memoryStore } from '../memory-store';

// Mock dependencies
vi.mock('@/utils/logger.js');
vi.mock('../../config/environment.js');
vi.mock('../orchestrators/memory-store-orchestrator.js');
vi.mock('../truncation/truncation-service.js');
vi.mock('../insights/insight-generation-service.js');
vi.mock('../metrics/system-metrics.js');

const mockEnvironment = vi.mocked(environment);
const mockInsightService = vi.mocked(insightGenerationService);

// Mock the orchestrator to avoid database dependencies
const mockOrchestrator = {
  storeItems: vi.fn(),
};

// Mock truncation service
const mockTruncationService = {
  processContent: vi.fn(),
};

describe('Memory Store with Insights Integration', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Mock environment to enable insights in development
    mockEnvironment.isDevelopmentMode.mockReturnValue(true);
    mockEnvironment.getInsightConfig.mockReturnValue({
      enabled: true,
      environment_enabled: true,
      runtime_override: false,
      max_insights_per_item: 3,
      max_insights_per_batch: 10,
      min_confidence_threshold: 0.6,
      processing_timeout_ms: 5000,
      parallel_processing: true,
      insight_types: {
        patterns: {
          id: 'patterns',
          name: 'Pattern Recognition',
          description: 'Identify recurring patterns in knowledge items',
          enabled: true,
          confidence_threshold: 0.7,
          priority: 1,
          max_insights_per_batch: 3,
        },
        connections: {
          id: 'connections',
          name: 'Connection Analysis',
          description: 'Find relationships and connections between items',
          enabled: true,
          confidence_threshold: 0.6,
          priority: 2,
          max_insights_per_batch: 2,
        },
        recommendations: {
          id: 'recommendations',
          name: 'Action Recommendations',
          description: 'Suggest actions based on stored knowledge',
          enabled: true,
          confidence_threshold: 0.8,
          priority: 3,
          max_insights_per_batch: 2,
        },
        anomalies: {
          id: 'anomalies',
          name: 'Anomaly Detection',
          description: 'Detect unusual or unexpected patterns',
          enabled: false,
          confidence_threshold: 0.9,
          priority: 4,
          max_insights_per_batch: 1,
        },
        trends: {
          id: 'trends',
          name: 'Trend Analysis',
          description: 'Identify trends in knowledge changes over time',
          enabled: false,
          confidence_threshold: 0.7,
          priority: 5,
          max_insights_per_batch: 2,
        },
      },
      performance_impact_threshold: 5,
      enable_caching: true,
      cache_ttl_seconds: 3600,
      enable_metrics: true,
      max_insight_length: 280,
      include_metadata: true,
      filter_duplicates: true,
      prioritize_by_confidence: true,
    });

    // Mock orchestrator response
    mockOrchestrator.storeItems.mockResolvedValue({
      stored: [
        {
          id: 'item-1',
          status: 'inserted',
          kind: 'entity',
          created_at: new Date().toISOString(),
        },
        {
          id: 'item-2',
          status: 'inserted',
          kind: 'entity',
          created_at: new Date().toISOString(),
        },
      ],
      errors: [],
      autonomous_context: {
        action_performed: 'created',
        similar_items_checked: 0,
        duplicates_found: 0,
        contradictions_detected: false,
        recommendation: 'Items stored successfully',
        reasoning: 'No issues detected during storage',
        user_message_suggestion: 'Items stored successfully',
      },
      observability: {
        source: 'cortex_memory',
        strategy: 'autonomous_deduplication',
        vector_used: true,
        degraded: false,
        execution_time_ms: 100,
        confidence_score: 0.95,
      },
      items: [
        {
          input_index: 0,
          status: 'stored',
          kind: 'entity',
          content: 'Test content 1',
          id: 'item-1',
          created_at: new Date().toISOString(),
        },
        {
          input_index: 1,
          status: 'stored',
          kind: 'entity',
          content: 'Test content 2',
          id: 'item-2',
          created_at: new Date().toISOString(),
        },
      ],
      summary: {
        stored: 2,
        skipped_dedupe: 0,
        business_rule_blocked: 0,
        validation_error: 0,
        total: 2,
      },
    });

    // Mock truncation service
    mockTruncationService.processContent.mockResolvedValue({
      original: {
        content: 'Test content',
        length: 12,
        contentType: 'text',
      },
      truncated: {
        content: 'Test content',
        length: 12,
      },
      meta: {
        truncated: false,
        strategy: 'none',
      },
      metrics: {
        charsRemoved: 0,
        tokensRemoved: 0,
        processingTimeMs: 1,
      },
    });

    // Mock insight service
    mockInsightService.generateInsights.mockResolvedValue({
      insights: [
          {
            id: 'insight-1',
            type: 'patterns',
            title: 'Pattern: Test content appears frequently',
            description: 'The term "test" appears across multiple items',
            confidence: 0.8,
            priority: 1,
            item_ids: ['item-1', 'item-2'],
            scope: { project: 'test' },
            metadata: {
              generated_at: new Date().toISOString(),
              generated_by: 'insight-generation-service',
              processing_time_ms: 50,
              data_sources: ['text_content'],
              tags: ['pattern', 'keyword'],
            },
            actionable: false,
            category: 'pattern',
            pattern_data: {
              pattern_type: 'keyword_frequency',
              frequency: 2,
              occurrences: [
                { item_id: 'item-1', context: 'Test content 1', confidence: 0.8 },
                { item_id: 'item-2', context: 'Test content 2', confidence: 0.8 },
              ],
              strength: 1.0,
            },
          } as PatternInsight,
      ],
      metadata: {
        total_insights: 1,
        insights_by_type: { patterns: 1 },
        average_confidence: 0.8,
        processing_time_ms: 50,
        items_processed: 2,
        insights_generated: 1,
        performance_impact: 2.5,
        cache_hit_rate: 0.1,
      },
      errors: [],
      warnings: [],
    });

    // Reset metrics
    mockInsightService.getMetrics.mockReturnValue({
      total_insights_generated: 0,
      insights_by_type: {},
      average_confidence: 0,
      generation_success_rate: 1.0,
      processing_time_avg: 0,
      performance_impact_avg: 0,
      cache_hit_rate: 0,
      error_rate: 0,
      last_updated: new Date().toISOString(),
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Memory Store with Insights Enabled', () => {
    it('should store items and generate insights when insight option is true', async () => {
      const items = [
        {
          kind: 'entity',
          content: 'Test content about authentication system development',
          scope: { project: 'auth-service' },
          data: { content: 'Test content about authentication system development' },
        },
        {
          kind: 'entity',
          content: 'Test content for authentication module testing',
          scope: { project: 'auth-service' },
          data: { content: 'Test content for authentication module testing' },
        },
      ];

      const response = await memoryStore(items, { insight: true });

      expect(response).toBeDefined();
      expect(response.meta.insights).toBeDefined();
      expect(response.meta.insights?.enabled).toBe(true);
      expect(response.meta.insights?.total_insights).toBe(1);
      expect(response.meta.insights?.insights_by_type).toEqual({ patterns: 1 });
      expect(response.meta.insights?.average_confidence).toBe(0.8);
      expect(response.meta.insights?.processing_time_ms).toBe(50);
      expect(response.meta.insights?.performance_impact).toBe(2.5);

      // Verify orchestrator was called
      expect(mockOrchestrator.storeItems).toHaveBeenCalled();

      // Verify insight service was called
      expect(mockInsightService.generateInsights).toHaveBeenCalledWith({
        items: expect.arrayContaining([
          expect.objectContaining({
            id: 'item-1',
            kind: 'entity',
            content: 'Test content 1',
          }),
          expect.objectContaining({
            id: 'item-2',
            kind: 'entity',
            content: 'Test content 2',
          }),
        ]),
        options: {
          enabled: true,
          insight_types: ['patterns', 'connections', 'recommendations'],
          max_insights_per_item: 3,
          confidence_threshold: 0.6,
          include_metadata: true,
        },
        scope: {},
      });
    });

    it('should not generate insights when insight option is false', async () => {
      const items = [
        {
          kind: 'entity',
          content: 'Test content without insights',
          scope: { project: 'test' },
          data: { content: 'Test content without insights' },
        },
      ];

      const response = await memoryStore(items, { insight: false });

      expect(response).toBeDefined();
      expect(response.meta.insights).toBeUndefined();

      // Verify insight service was not called
      expect(mockInsightService.generateInsights).not.toHaveBeenCalled();
    });

    it('should not generate insights when option is not provided', async () => {
      const items = [
        {
          kind: 'entity',
          content: 'Test content without option',
          scope: { project: 'test' },
          data: { content: 'Test content without option' },
        },
      ];

      const response = await memoryStore(items);

      expect(response).toBeDefined();
      expect(response.meta.insights).toBeUndefined();

      // Verify insight service was not called
      expect(mockInsightService.generateInsights).not.toHaveBeenCalled();
    });

    it('should handle insight generation errors gracefully', async () => {
      // Mock insight service to throw an error
      mockInsightService.generateInsights.mockRejectedValue(new Error('Insight generation failed'));

      const items = [
        {
          kind: 'entity',
          content: 'Test content for error handling',
          scope: { project: 'test' },
          data: { content: 'Test content for error handling' },
        },
      ];

      const response = await memoryStore(items, { insight: true });

      // Should still return a valid response even if insight generation fails
      expect(response).toBeDefined();
      expect(response.meta.insights).toBeDefined();
      expect(response.meta.insights?.enabled).toBe(true);
      expect(response.meta.insights?.total_insights).toBe(0);

      // Memory store operation should still succeed
      expect(response.summary.stored).toBe(1);
    });

    it('should handle zero stored items for insights', async () => {
      // Mock orchestrator to return no stored items
      mockOrchestrator.storeItems.mockResolvedValue({
        stored: [],
        errors: [],
        autonomous_context: {
          action_performed: 'skipped',
          similar_items_checked: 0,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'No items stored',
          reasoning: 'All items were filtered out',
          user_message_suggestion: 'No items stored',
        },
        observability: {
          source: 'cortex_memory',
          strategy: 'autonomous_deduplication',
          vector_used: false,
          degraded: false,
          execution_time_ms: 50,
          confidence_score: 0,
        },
        items: [
          {
            input_index: 0,
            status: 'validation_error',
            kind: 'entity',
            content: 'Invalid item',
            error_code: 'VALIDATION_ERROR',
            reason: 'Item failed validation',
          },
        ],
        summary: {
          stored: 0,
          skipped_dedupe: 0,
          business_rule_blocked: 0,
          validation_error: 1,
          total: 1,
        },
      });

      const items = [
        {
          kind: 'entity',
          content: 'Invalid item content',
          scope: { project: 'test' },
          data: { invalid: 'structure' },
        },
      ];

      const response = await memoryStore(items, { insight: true });

      expect(response).toBeDefined();
      expect(response.meta.insights).toBeDefined();
      expect(response.meta.insights?.enabled).toBe(true);
      expect(response.meta.insights?.total_insights).toBe(0);
      expect(response.summary.stored).toBe(0);
      expect(response.summary.validation_error).toBe(1);
    });

    it('should include both truncation and insight metadata', async () => {
      // Mock truncation to occur
      mockTruncationService.processContent.mockResolvedValue({
        original: {
          content: 'Very long content that should be truncated'.repeat(100),
          length: 4500,
          contentType: 'text',
        },
        truncated: {
          content: 'Very long content that should be truncated'.repeat(50),
          length: 2250,
        },
        meta: {
          truncated: true,
          strategy: 'intelligent',
        },
        metrics: {
          charsRemoved: 2250,
          tokensRemoved: 500,
          processingTimeMs: 5,
        },
      });

      const items = [
        {
          kind: 'entity',
          content: 'Very long content that should be truncated'.repeat(100),
          scope: { project: 'test' },
          data: { content: 'Very long content that should be truncated'.repeat(100) },
        },
      ];

      const response = await memoryStore(items, { insight: true });

      expect(response).toBeDefined();
      expect(response.meta.truncated).toBe(true);
      expect(response.meta.insights).toBeDefined();
      expect(response.meta.insights?.enabled).toBe(true);

      // Should have both metadata types
      expect(response.meta.total_chars_removed).toBe(2250);
      expect(response.meta.total_tokens_removed).toBe(500);
      expect(response.meta.insights?.total_insights).toBe(1);
    });

    it('should log insight generation metrics to system metrics', async () => {
      const mockSystemMetricsService = {
        updateMetrics: vi.fn(),
      };

      // Re-mock system metrics to capture the call
      vi.doMock('../metrics/system-metrics.js', () => ({
        systemMetricsService: mockSystemMetricsService,
      }));

      const items = [
        {
          kind: 'entity',
          content: 'Test content for metrics',
          scope: { project: 'test' },
          data: { content: 'Test content for metrics' },
        },
      ];

      await memoryStore(items, { insight: true });

      // Verify system metrics were updated with insight data
      expect(mockSystemMetricsService.updateMetrics).toHaveBeenCalledWith({
        operation: 'insight_generation_summary',
        data: {
          total_insights: 1,
          insights_by_type: { patterns: 1 },
          average_confidence: 0.8,
          processing_time_ms: 50,
          performance_impact: 2.5,
        },
        duration_ms: 50,
      });
    });
  });

  describe('Insight Generation Performance', () => {
    it('should respect performance impact thresholds', async () => {
      // Mock insight service to return high performance impact
      mockInsightService.generateInsights.mockResolvedValue({
        insights: [],
        metadata: {
          total_insights: 0,
          insights_by_type: {},
          average_confidence: 0,
          processing_time_ms: 1000, // High processing time
          items_processed: 2,
          insights_generated: 0,
          performance_impact: 10, // High impact
          cache_hit_rate: 0,
        },
        errors: [],
        warnings: ['High performance impact detected'],
      });

      const items = [
        {
          kind: 'entity',
          content: 'Test content',
          scope: { project: 'test' },
          data: { content: 'Test content' },
        },
      ];

      const response = await memoryStore(items, { insight: true });

      expect(response.meta.insights).toBeDefined();
      expect(response.meta.insights?.performance_impact).toBe(10);
    });

    it('should handle insight generation timeouts', async () => {
      // Mock insight service to simulate timeout
      mockInsightService.generateInsights.mockImplementation(() => {
        return new Promise((_, reject) => {
          setTimeout(() => reject(new Error('Insight generation timeout')), 100);
        });
      });

      const items = [
        {
          kind: 'entity',
          content: 'Test content for timeout',
          scope: { project: 'test' },
          data: { content: 'Test content for timeout' },
        },
      ];

      const response = await memoryStore(items, { insight: true });

      // Should handle timeout gracefully
      expect(response).toBeDefined();
      expect(response.meta.insights).toBeDefined();
      expect(response.meta.insights?.total_insights).toBe(0);
      expect(response.summary.stored).toBe(1); // Memory store should still succeed
    });
  });
});
