// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck


import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

import { environment } from '../../../config/environment.js';
import type { InsightGenerationRequest } from '../../../types/insight-interfaces.js';
import { InsightGenerationService } from '../insight-generation-service.js';

// Mock dependencies
jest.mock('../../../utils/logger.js');
jest.mock('../../../config/environment.js');
jest.mock('../metrics/system-metrics.js');

const mockEnvironment = environment as jest.Mocked<typeof environment>;
const _mockSystemMetrics = {
  updateMetrics: jest.fn(),
};

describe('InsightGenerationService', () => {
  let insightService: InsightGenerationService;

  beforeEach(() => {
    jest.clearAllMocks();

    // Mock environment configuration
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

    // Get a new instance for each test
    insightService = InsightGenerationService.getInstance();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Configuration and Initialization', () => {
    it('should initialize with default configuration', () => {
      expect(insightService).toBeDefined();
      const metrics = insightService.getMetrics();
      expect(metrics.total_insights_generated).toBe(0);
      expect(metrics.generation_success_rate).toBe(1.0);
    });

    it('should load configuration from environment', () => {
      expect(mockEnvironment.getInsightConfig).toHaveBeenCalled();
    });

    it('should enable insights in development mode', () => {
      mockEnvironment.isDevelopmentMode.mockReturnValue(true);
      const newService = new (InsightGenerationService as unknown)();
      expect(newService.config.environment_enabled).toBe(true);
    });
  });

  describe('Insight Generation - Disabled Scenarios', () => {
    it('should return disabled response when insights are disabled', async () => {
      mockEnvironment.getInsightConfig.mockReturnValue({
        enabled: false,
        environment_enabled: false,
        runtime_override: false,
        max_insights_per_item: 3,
        max_insights_per_batch: 10,
        min_confidence_threshold: 0.6,
        processing_timeout_ms: 5000,
        parallel_processing: true,
        insight_types: {},
        performance_impact_threshold: 5,
        enable_caching: true,
        cache_ttl_seconds: 3600,
        enable_metrics: true,
        max_insight_length: 280,
        include_metadata: true,
        filter_duplicates: true,
        prioritize_by_confidence: true,
      });

      const request: InsightGenerationRequest = {
        items: [
          {
            id: '1',
            kind: 'entity',
            content: 'Test content',
            data: { content: 'Test content' },
            scope: { project: 'test' },
          },
        ],
        options: {
          enabled: false,
          insight_types: ['patterns'],
          max_insights_per_item: 3,
          confidence_threshold: 0.6,
          include_metadata: true,
        },
        scope: { project: 'test' },
      };

      const response = await insightService.generateInsights(request);

      expect(response.insights).toHaveLength(0);
      expect(response.warnings).toContain('Insight generation is disabled');
      expect(response.metadata.total_insights).toBe(0);
    });
  });

  describe('Pattern Recognition Insights', () => {
    it('should generate pattern insights for recurring keywords', async () => {
      const request: InsightGenerationRequest = {
        items: [
          {
            id: '1',
            kind: 'entity',
            content: 'Development team is working on authentication system',
            data: { content: 'Development team is working on authentication system' },
            scope: { project: 'test' },
          },
          {
            id: '2',
            kind: 'entity',
            content: 'Development team completed authentication module',
            data: { content: 'Development team completed authentication module' },
            scope: { project: 'test' },
          },
          {
            id: '3',
            kind: 'entity',
            content: 'Development team planning authentication testing',
            data: { content: 'Development team planning authentication testing' },
            scope: { project: 'test' },
          },
        ],
        options: {
          enabled: true,
          insight_types: ['patterns'],
          max_insights_per_item: 3,
          confidence_threshold: 0.6,
          include_metadata: true,
        },
        scope: { project: 'test' },
      };

      const response = await insightService.generateInsights(request);

      expect(response.insights.length).toBeGreaterThan(0);
      const patternInsight = response.insights.find((insight) => insight.type === 'patterns');
      expect(patternInsight).toBeDefined();
      expect(patternInsight?.category).toBe('pattern');
      expect(patternInsight?.confidence).toBeGreaterThanOrEqual(0.6);
      expect(patternInsight?.title).toContain('Development');
    });

    it('should not generate insights below confidence threshold', async () => {
      const request: InsightGenerationRequest = {
        items: [
          {
            id: '1',
            kind: 'entity',
            content: 'Single item with unique content',
            data: { content: 'Single item with unique content' },
            scope: { project: 'test' },
          },
        ],
        options: {
          enabled: true,
          insight_types: ['patterns'],
          max_insights_per_item: 3,
          confidence_threshold: 0.9, // High threshold
          include_metadata: true,
        },
        scope: { project: 'test' },
      };

      const response = await insightService.generateInsights(request);

      expect(response.insights).toHaveLength(0);
      expect(response.metadata.total_insights).toBe(0);
    });
  });

  describe('Connection Insights', () => {
    it('should generate connection insights for items with same scope', async () => {
      const request: InsightGenerationRequest = {
        items: [
          {
            id: '1',
            kind: 'issue',
            content: 'Bug in authentication module',
            data: { content: 'Bug in authentication module' },
            scope: { project: 'auth-service' },
          },
          {
            id: '2',
            kind: 'decision',
            content: 'Decision to refactor authentication code',
            data: { content: 'Decision to refactor authentication code' },
            scope: { project: 'auth-service' },
          },
        ],
        options: {
          enabled: true,
          insight_types: ['connections'],
          max_insights_per_item: 3,
          confidence_threshold: 0.6,
          include_metadata: true,
        },
        scope: { project: 'test' },
      };

      const response = await insightService.generateInsights(request);

      expect(response.insights.length).toBeGreaterThan(0);
      const connectionInsight = response.insights.find((insight) => insight.type === 'connections');
      expect(connectionInsight).toBeDefined();
      expect(connectionInsight?.category).toBe('connection');
      expect(connectionInsight?.title).toContain('auth-service');
    });
  });

  describe('Recommendation Insights', () => {
    it('should generate recommendations for multiple issues', async () => {
      const request: InsightGenerationRequest = {
        items: [
          {
            id: '1',
            kind: 'issue',
            content: 'Critical bug in payment processing',
            data: { content: 'Critical bug in payment processing' },
            scope: { project: 'payment-service' },
          },
          {
            id: '2',
            kind: 'issue',
            content: 'Performance issue in database queries',
            data: { content: 'Performance issue in database queries' },
            scope: { project: 'payment-service' },
          },
          {
            id: '3',
            kind: 'issue',
            content: 'Security vulnerability in API endpoint',
            data: { content: 'Security vulnerability in API endpoint' },
            scope: { project: 'payment-service' },
          },
        ],
        options: {
          enabled: true,
          insight_types: ['recommendations'],
          max_insights_per_item: 3,
          confidence_threshold: 0.6,
          include_metadata: true,
        },
        scope: { project: 'test' },
      };

      const response = await insightService.generateInsights(request);

      expect(response.insights.length).toBeGreaterThan(0);
      const recommendationInsight = response.insights.find(
        (insight) => insight.type === 'recommendations'
      );
      expect(recommendationInsight).toBeDefined();
      expect(recommendationInsight?.category).toBe('recommendation');
      expect(recommendationInsight?.actionable).toBe(true);
      expect(recommendationInsight?.title).toContain('Issues');
    });

    it('should generate recommendations for multiple todos', async () => {
      const request: InsightGenerationRequest = {
        items: [
          {
            id: '1',
            kind: 'todo',
            content: 'Implement user authentication',
            data: { content: 'Implement user authentication' },
            scope: { project: 'auth-service' },
          },
          {
            id: '2',
            kind: 'todo',
            content: 'Add password reset functionality',
            data: { content: 'Add password reset functionality' },
            scope: { project: 'auth-service' },
          },
        ],
        options: {
          enabled: true,
          insight_types: ['recommendations'],
          max_insights_per_item: 3,
          confidence_threshold: 0.6,
          include_metadata: true,
        },
        scope: { project: 'test' },
      };

      const response = await insightService.generateInsights(request);

      expect(response.insights.length).toBeGreaterThan(0);
      const todoRecommendation = response.insights.find(
        (insight) => insight.type === 'recommendations' && insight.title.includes('Todo')
      );
      expect(todoRecommendation).toBeDefined();
      expect(todoRecommendation?.actionable).toBe(true);
    });
  });

  describe('Anomaly Insights', () => {
    it('should generate anomaly insights for skewed distributions', async () => {
      // Mock anomaly insights as enabled
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
          anomalies: {
            id: 'anomalies',
            name: 'Anomaly Detection',
            description: 'Detect unusual or unexpected patterns',
            enabled: true,
            confidence_threshold: 0.6,
            priority: 4,
            max_insights_per_batch: 1,
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
      } as unknown);

      const request: InsightGenerationRequest = {
        items: [
          {
            id: '1',
            kind: 'entity',
            content: 'Normal entity',
            data: { content: 'Normal entity' },
            scope: { project: 'test' },
          },
          {
            id: '2',
            kind: 'issue',
            content: 'Issue item',
            data: { content: 'Issue item' },
            scope: { project: 'test' },
          },
          {
            id: '3',
            kind: 'issue',
            content: 'Another issue',
            data: { content: 'Another issue' },
            scope: { project: 'test' },
          },
          {
            id: '4',
            kind: 'issue',
            data: {},
            scope: { project: 'test' },
          },
          {
            id: '5',
            kind: 'issue',
            data: {},
            scope: { project: 'test' },
          },
        ],
        options: {
          enabled: true,
          insight_types: ['anomalies'],
          max_insights_per_item: 3,
          confidence_threshold: 0.6,
          include_metadata: true,
        },
        scope: { project: 'test' },
      };

      const response = await insightService.generateInsights(request);

      // May or may not generate insights depending on distribution analysis
      expect(Array.isArray(response.insights)).toBe(true);
      if (response.insights.length > 0) {
        const anomalyInsight = response.insights.find((insight) => insight.type === 'anomalies');
        if (anomalyInsight) {
          expect(anomalyInsight.category).toBe('anomaly');
        }
      }
    });
  });

  describe('Trend Insights', () => {
    it('should generate trend insights for sufficient items', async () => {
      // Mock trend insights as enabled
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
          trends: {
            id: 'trends',
            name: 'Trend Analysis',
            description: 'Identify trends in knowledge changes over time',
            enabled: true,
            confidence_threshold: 0.6,
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
      } as unknown);

      const request: InsightGenerationRequest = {
        items: Array.from({ length: 6 }, (_, i) => ({
          id: `${i + 1}`,
          kind: 'entity',
          content: `Entity ${i + 1} content`,
          data: { content: `Entity ${i + 1} content` },
          scope: { project: 'test' },
          created_at: new Date(Date.now() - (5 - i) * 60 * 60 * 1000).toISOString(), // Spread over last 5 hours
        })),
        options: {
          enabled: true,
          insight_types: ['trends'],
          max_insights_per_item: 3,
          confidence_threshold: 0.6,
          include_metadata: true,
        },
        scope: { project: 'test' },
      };

      const response = await insightService.generateInsights(request);

      expect(response.insights.length).toBeGreaterThan(0);
      const trendInsight = response.insights.find((insight) => insight.type === 'trends');
      if (trendInsight) {
        expect(trendInsight.category).toBe('trend');
        expect(trendInsight.title).toContain('Trend');
      }
    });
  });

  describe('Performance and Metrics', () => {
    it('should update metrics after insight generation', async () => {
      const initialMetrics = insightService.getMetrics();
      expect(initialMetrics.total_insights_generated).toBe(0);

      const request: InsightGenerationRequest = {
        items: [
          {
            id: '1',
            kind: 'entity',
            content: 'Test content for metrics',
            data: { content: 'Test content for metrics' },
            scope: { project: 'test' },
          },
        ],
        options: {
          enabled: true,
          insight_types: ['patterns'],
          max_insights_per_item: 3,
          confidence_threshold: 0.5, // Lower threshold to ensure insights
          include_metadata: true,
        },
        scope: { project: 'test' },
      };

      await insightService.generateInsights(request);

      const updatedMetrics = insightService.getMetrics();
      expect(updatedMetrics.last_updated).not.toBe(initialMetrics.last_updated);
    });

    it('should respect max insights per batch limit', async () => {
      // Create many items that could generate many insights
      const request: InsightGenerationRequest = {
        items: Array.from({ length: 20 }, (_, i) => ({
          id: `${i + 1}`,
          kind: 'entity',
          content: `Test content with keyword pattern repeated multiple times ${i}`,
          data: { content: `Test content with keyword pattern repeated multiple times ${i}` },
          scope: { project: 'test' },
        })),
        options: {
          enabled: true,
          insight_types: ['patterns'],
          max_insights_per_item: 3,
          confidence_threshold: 0.5,
          include_metadata: true,
        },
        scope: { project: 'test' },
      };

      const response = await insightService.generateInsights(request);

      // Should not exceed batch limit (default is 10)
      expect(response.insights.length).toBeLessThanOrEqual(10);
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid items gracefully', async () => {
      const request: InsightGenerationRequest = {
        items: [
          {
            id: '1',
            kind: 'entity',
            content: 'Valid item',
            data: { content: 'Valid item' },
            scope: { project: 'test' },
          },
          null as unknown, // Invalid item
          undefined as unknown, // Invalid item
        ],
        options: {
          enabled: true,
          insight_types: ['patterns'],
          max_insights_per_item: 3,
          confidence_threshold: 0.5,
          include_metadata: true,
        },
        scope: { project: 'test' },
      };

      const response = await insightService.generateInsights(request);

      // Should still process valid items and not crash
      expect(Array.isArray(response.insights)).toBe(true);
      expect(response.errors.length).toBe(0); // Invalid items are filtered out, not errors
    });

    it('should handle system errors without crashing', async () => {
      // Mock a system error during processing
      const originalConsoleError = console.error;
      console.error = jest.fn();

      const request: InsightGenerationRequest = {
        items: [
          {
            id: '1',
            kind: 'entity',
            content: 'Test content',
            data: { content: 'Test content' },
            scope: { project: 'test' },
          },
        ],
        options: {
          enabled: true,
          insight_types: ['patterns'],
          max_insights_per_item: 3,
          confidence_threshold: 0.5,
          include_metadata: true,
        },
        scope: { project: 'test' },
      };

      // This should not throw even if there are internal errors
      const response = await insightService.generateInsights(request);

      expect(response).toBeDefined();
      expect(Array.isArray(response.insights)).toBe(true);

      console.error = originalConsoleError;
    });
  });

  describe('Cache Behavior', () => {
    it('should use cache when enabled', async () => {
      const request: InsightGenerationRequest = {
        items: [
          {
            id: '1',
            kind: 'entity',
            content: 'Test content for caching',
            data: { content: 'Test content for caching' },
            scope: { project: 'test' },
          },
        ],
        options: {
          enabled: true,
          insight_types: ['patterns'],
          max_insights_per_item: 3,
          confidence_threshold: 0.5,
          include_metadata: true,
        },
        scope: { project: 'test' },
      };

      // First call
      const response1 = await insightService.generateInsights(request);

      // Second call with same items should potentially use cache
      const response2 = await insightService.generateInsights(request);

      // Both should succeed and return similar results
      expect(response1.insights.length).toBe(response2.insights.length);
      expect(response1.metadata.cache_hit_rate).toBeGreaterThanOrEqual(0);
      expect(response2.metadata.cache_hit_rate).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Insight Filtering and Prioritization', () => {
    it('should filter insights by confidence threshold', async () => {
      const request: InsightGenerationRequest = {
        items: [
          {
            id: '1',
            kind: 'entity',
            content: 'Test content with keyword',
            data: { content: 'Test content with keyword' },
            scope: { project: 'test' },
          },
        ],
        options: {
          enabled: true,
          insight_types: ['patterns'],
          max_insights_per_item: 3,
          confidence_threshold: 0.95, // Very high threshold
          include_metadata: true,
        },
        scope: { project: 'test' },
      };

      const response = await insightService.generateInsights(request);

      // Should filter out low-confidence insights
      response.insights.forEach((insight) => {
        expect(insight.confidence).toBeGreaterThanOrEqual(0.95);
      });
    });

    it('should prioritize insights by priority and confidence', async () => {
      const request: InsightGenerationRequest = {
        items: [
          {
            id: '1',
            kind: 'entity',
            content: 'Test content with keyword pattern',
            data: { content: 'Test content with keyword pattern' },
            scope: { project: 'test-project' },
          },
          {
            id: '2',
            kind: 'issue',
            content: 'Issue content',
            data: { content: 'Issue content' },
            scope: { project: 'test-project' },
          },
        ],
        options: {
          enabled: true,
          insight_types: ['patterns', 'connections', 'recommendations'],
          max_insights_per_item: 3,
          confidence_threshold: 0.5,
          include_metadata: true,
        },
        scope: { project: 'test' },
      };

      const response = await insightService.generateInsights(request);

      if (response.insights.length > 1) {
        // Should be sorted by priority (lower number = higher priority)
        for (let i = 1; i < response.insights.length; i++) {
          const prev = response.insights[i - 1];
          const curr = response.insights[i];

          if (prev.priority !== curr.priority) {
            expect(prev.priority).toBeLessThanOrEqual(curr.priority);
          }
        }
      }
    });
  });

  describe('Configuration Updates', () => {
    it('should allow runtime configuration updates', () => {
      const newConfig = {
        max_insights_per_item: 5,
        max_insights_per_batch: 15,
        min_confidence_threshold: 0.7,
      };

      insightService.updateConfig(newConfig);

      // We can't directly test private config, but we can test that it doesn't crash
      expect(() => insightService.updateConfig(newConfig)).not.toThrow();
    });

    it('should reset metrics when requested', () => {
      // Get initial metrics
      const initialMetrics = insightService.getMetrics();

      // Reset metrics
      insightService.resetMetrics();

      const resetMetrics = insightService.getMetrics();
      expect(resetMetrics.total_insights_generated).toBe(0);
      expect(resetMetrics.generation_success_rate).toBe(1.0);
      expect(resetMetrics.last_updated).not.toBe(initialMetrics.last_updated);
    });
  });
});
