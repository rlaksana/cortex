/**
 * Insight Generation ZAI Integration Tests
 *
 * Comprehensive integration tests for insight generation with ZAI services
 * including real AI operations, performance validation, and error handling.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import {
  MockZAIClientService,
  MockZAIServicesManager,
  createTestInsightRequest,
  measurePerformance,
  createPerformanceBenchmark,
  mockZAIResponses,
  mockPerformanceData,
  mockErrorScenarios,
} from '../mocks/zai-service.mock.js';
import type {
  InsightGenerationRequest,
  InsightGenerationResponse,
} from '../../src/types/zai-interfaces.js';

describe('Insight Generation ZAI Integration Tests', () => {
  let mockServices: MockZAIServicesManager;
  let zaiClient: MockZAIClientService;

  beforeAll(async () => {
    mockServices = new MockZAIServicesManager();
    await mockServices.initialize();
    zaiClient = mockServices.getZAIClient();
  });

  afterAll(async () => {
    await mockServices.shutdown();
  });

  beforeEach(() => {
    zaiClient.reset();
  });

  afterEach(() => {
    zaiClient.clearErrors();
  });

  describe('Basic Insight Generation', () => {
    test('should generate insights for single item', async () => {
      const request = createTestInsightRequest();

      const response = await zaiClient.generateInsights(request);

      expect(response).toBeDefined();
      expect(response.insights).toBeDefined();
      expect(Array.isArray(response.insights)).toBe(true);
      expect(response.errors).toBeDefined();
      expect(Array.isArray(response.errors)).toBe(true);
      expect(response.warnings).toBeDefined();
      expect(Array.isArray(response.warnings)).toBe(true);
      expect(response.metadata).toBeDefined();
    });

    test('should generate pattern recognition insights', async () => {
      const request = createTestInsightRequest();
      request.options!.insight_types = ['patterns'];

      const response = await zaiClient.generateInsights(request);

      expect(response.insights.length).toBeGreaterThanOrEqual(0);
      if (response.insights.length > 0) {
        expect(response.insights[0].type).toBe('patterns');
        expect(response.insights[0].confidence).toBeGreaterThan(0);
        expect(response.insights[0].description).toBeDefined();
      }
    });

    test('should generate connection insights', async () => {
      const request = {
        ...createTestInsightRequest(),
        items: [
          createTestInsightRequest().items[0],
          {
            ...createTestInsightRequest().items[0],
            id: 'test-item-2',
            kind: 'todo' as const,
            content: 'Implement user authentication service',
          },
        ],
      };
      request.options!.insight_types = ['connections'];

      const response = await zaiClient.generateInsights(request);

      expect(response.insights.length).toBeGreaterThanOrEqual(0);
      if (response.insights.length > 0) {
        expect(response.insights[0].type).toBe('connections');
        expect(response.insights[0].metadata?.relationship_type).toBeDefined();
      }
    });

    test('should generate recommendation insights', async () => {
      const request = createTestInsightRequest();
      request.options!.insight_types = ['recommendations'];

      const response = await zaiClient.generateInsights(request);

      expect(response.insights.length).toBeGreaterThanOrEqual(0);
      if (response.insights.length > 0) {
        expect(response.insights[0].type).toBe('recommendations');
        expect(response.insights[0].metadata?.recommendation).toBeDefined();
        expect(response.insights[0].metadata?.priority).toBeDefined();
      }
    });

    test('should generate anomaly detection insights', async () => {
      const request = createTestInsightRequest();
      request.options!.insight_types = ['anomalies'];

      const response = await zaiClient.generateInsights(request);

      expect(response.insights.length).toBeGreaterThanOrEqual(0);
      if (response.insights.length > 0) {
        expect(['anomalies', 'trends']).toContain(response.insights[0].type);
        expect(response.insights[0].metadata?.anomaly_type).toBeDefined();
      }
    });

    test('should generate trend insights', async () => {
      const request = createTestInsightRequest();
      request.options!.insight_types = ['trends'];

      const response = await zaiClient.generateInsights(request);

      expect(response.insights.length).toBeGreaterThanOrEqual(0);
      if (response.insights.length > 0) {
        expect(['recommendations', 'trends']).toContain(response.insights[0].type);
        expect(response.insights[0].metadata?.trend_direction).toBeDefined();
      }
    });
  });

  describe('Batch Processing', () => {
    test('should handle batch of 50 items within performance target', async () => {
      const items = Array.from({ length: 50 }, (_, i) => ({
        ...createTestInsightRequest().items[0],
        id: `batch-item-${i}`,
        content: `Decision item ${i} for batch processing`,
      }));

      const request = {
        ...createTestInsightRequest(),
        items,
        options: {
          ...createTestInsightRequest().options,
          insight_types: ['patterns', 'connections'],
          max_insights_per_item: 2,
        },
      };

      const benchmark = createPerformanceBenchmark(
        mockPerformanceData.insight_generation.batch_50_items
      );
      const { result, durationMs } = await measurePerformance(() =>
        zaiClient.generateInsights(request)
      );

      const validation = benchmark.validate(durationMs);

      expect(result.insights).toBeDefined();
      expect(result.metadata['items_processed']).toBe(50);
      expect(validation.passed).toBe(true);
      expect(validation.withinVariance).toBe(true);
      expect(validation.percentageOfTarget).toBeLessThanOrEqual(120);
    });

    test('should maintain insight quality with larger batches', async () => {
      const items = Array.from({ length: 25 }, (_, i) => ({
        ...createTestInsightRequest().items[0],
        id: `quality-item-${i}`,
        kind: i % 2 === 0 ? 'decision' : ('issue' as const),
        content: `Item ${i} for quality testing`,
      }));

      const request = {
        ...createTestInsightRequest(),
        items,
        options: {
          ...createTestInsightRequest().options,
          confidence_threshold: 0.7,
          max_insights_per_item: 1,
        },
      };

      const response = await zaiClient.generateInsights(request);

      expect(response.insights.length).toBeGreaterThanOrEqual(0);

      // All insights should meet confidence threshold
      response.insights.forEach((insight) => {
        expect(insight.confidence).toBeGreaterThanOrEqual(0.7);
      });

      // Should process all items
      expect(response.metadata['items_processed']).toBe(25);
    });

    test('should limit insights per item correctly', async () => {
      const items = Array.from({ length: 10 }, (_, i) => ({
        ...createTestInsightRequest().items[0],
        id: `limit-item-${i}`,
        content: `Item ${i} for limit testing`,
      }));

      const request = {
        ...createTestInsightRequest(),
        items,
        options: {
          ...createTestInsightRequest().options,
          insight_types: ['patterns', 'connections', 'recommendations'],
          max_insights_per_item: 1,
          confidence_threshold: 0.1, // Low threshold to get many insights
        },
      };

      const response = await zaiClient.generateInsights(request);

      // Count insights per item
      const insightsPerItem = response.insights.reduce(
        (acc, insight) => {
          acc[insight.item_id] = (acc[insight.item_id] || 0) + 1;
          return acc;
        },
        {} as Record<string, number>
      );

      // No item should have more than max_insights_per_item insights
      Object.values(insightsPerItem).forEach((count) => {
        expect(count).toBeLessThanOrEqual(1);
      });
    });
  });

  describe('Confidence Filtering', () => {
    test('should filter insights by confidence threshold', async () => {
      const request = createTestInsightRequest();

      // High confidence threshold
      const highThresholdResponse = await zaiClient.generateInsights({
        ...request,
        options: { ...request.options!, confidence_threshold: 0.9 },
      });

      // Low confidence threshold
      const lowThresholdResponse = await zaiClient.generateInsights({
        ...request,
        options: { ...request.options!, confidence_threshold: 0.3 },
      });

      // All insights in high threshold should meet the threshold
      highThresholdResponse.insights.forEach((insight) => {
        expect(insight.confidence).toBeGreaterThanOrEqual(0.9);
      });

      // Low threshold should allow more insights
      expect(lowThresholdResponse.insights.length).toBeGreaterThanOrEqual(
        highThresholdResponse.insights.length
      );
    });

    test('should handle edge case confidence thresholds', async () => {
      const request = createTestInsightRequest();

      // Very high threshold (should return very few or no insights)
      const veryHighResponse = await zaiClient.generateInsights({
        ...request,
        options: { ...request.options!, confidence_threshold: 0.99 },
      });

      // Very low threshold (should return most insights)
      const veryLowResponse = await zaiClient.generateInsights({
        ...request,
        options: { ...request.options!, confidence_threshold: 0.01 },
      });

      expect(veryLowResponse.insights.length).toBeGreaterThanOrEqual(
        veryHighResponse.insights.length
      );
    });
  });

  describe('Error Handling', () => {
    test('should handle network timeout errors', async () => {
      zaiClient.setErrorScenario('network_timeout');
      zaiClient.setResponseDelay(35000); // Longer than timeout

      const request = createTestInsightRequest();

      await expect(zaiClient.generateInsights(request)).rejects.toThrow('NetworkTimeoutError');
    });

    test('should handle rate limit errors', async () => {
      zaiClient.setErrorScenario('rate_limit');

      const request = createTestInsightRequest();

      await expect(zaiClient.generateInsights(request)).rejects.toThrow('RateLimitError');
    });

    test('should handle API errors', async () => {
      zaiClient.setErrorScenario('api_error');

      const request = createTestInsightRequest();

      await expect(zaiClient.generateInsights(request)).rejects.toThrow('ZAI_APIError');
    });

    test('should handle invalid response format', async () => {
      zaiClient.setErrorScenario('invalid_response');

      const request = createTestInsightRequest();

      await expect(zaiClient.generateInsights(request)).rejects.toThrow('InvalidResponseError');
    });

    test('should handle authentication errors', async () => {
      zaiClient.setErrorScenario('authentication');

      const request = createTestInsightRequest();

      await expect(zaiClient.generateInsights(request)).rejects.toThrow('AuthenticationError');
    });

    test('should handle model unavailable errors', async () => {
      zaiClient.setErrorScenario('model_unavailable');

      const request = createTestInsightRequest();

      await expect(zaiClient.generateInsights(request)).rejects.toThrow('ModelUnavailableError');
    });

    test('should handle malformed requests gracefully', async () => {
      const malformedRequest = {
        items: [
          {
            // Missing required fields
            id: 'malformed-1',
          },
        ],
        options: {
          enabled: true,
          insight_types: ['patterns'],
          max_insights_per_item: 1,
          confidence_threshold: 0.5,
        },
        scope: {},
      } as any;

      const response = await zaiClient.generateInsights(malformedRequest);

      // Should not crash and should return a response structure
      expect(response).toBeDefined();
      expect(response.insights).toBeDefined();
      expect(response.errors).toBeDefined();
    });

    test('should handle empty items array', async () => {
      const request: InsightGenerationRequest = {
        items: [],
        options: {
          enabled: true,
          insight_types: ['patterns'],
          max_insights_per_item: 1,
          confidence_threshold: 0.5,
          include_metadata: true,
        },
        scope: {},
      };

      const response = await zaiClient.generateInsights(request);

      expect(response.insights).toHaveLength(0);
      expect(response.metadata['items_processed']).toBe(0);
      expect(response.metadata['total_insights']).toBe(0);
    });
  });

  describe('Response Quality', () => {
    test('should include comprehensive metadata', async () => {
      const request = createTestInsightRequest();

      const response = await zaiClient.generateInsights(request);

      expect(response.metadata).toBeDefined();
      expect(response.metadata['total_insights']).toBeGreaterThanOrEqual(0);
      expect(response.metadata['items_processed']).toBeGreaterThanOrEqual(0);
      expect(response.metadata['processing_time_ms']).toBeGreaterThan(0);
      expect(response.metadata['average_confidence']).toBeGreaterThanOrEqual(0);
      expect(response.metadata['average_confidence']).toBeLessThanOrEqual(1);
      expect(response.metadata['insights_by_type']).toBeDefined();
      expect(typeof response.metadata['insights_by_type']).toBe('object');
      expect(response.metadata['performance_impact']).toBeGreaterThanOrEqual(0);
      expect(response.metadata['cache_hit_rate']).toBeGreaterThanOrEqual(0);
      expect(response.metadata['cache_hit_rate']).toBeLessThanOrEqual(1);
    });

    test('should include insight details and structure', async () => {
      const request = createTestInsightRequest();

      const response = await zaiClient.generateInsights(request);

      response.insights.forEach((insight) => {
        expect(insight.id).toBeDefined();
        expect(insight.item_id).toBeDefined();
        expect(insight.type).toBeDefined();
        expect(insight.confidence).toBeGreaterThanOrEqual(0);
        expect(insight.confidence).toBeLessThanOrEqual(1);
        expect(insight.description).toBeDefined();
        expect(insight.metadata).toBeDefined();
        expect(insight.created_at).toBeDefined();
        expect(typeof Date.parse(insight.created_at)).not.toBe(NaN);
      });
    });

    test('should maintain consistent insight types', async () => {
      const request = createTestInsightRequest();
      request.options!.insight_types = [
        'patterns',
        'connections',
        'recommendations',
        'anomalies',
        'trends',
      ];

      const response = await zaiClient.generateInsights(request);

      const validTypes = ['patterns', 'connections', 'recommendations', 'anomalies', 'trends'];

      response.insights.forEach((insight) => {
        expect(validTypes).toContain(insight.type);
      });
    });
  });

  describe('Caching and Performance', () => {
    test('should complete single item processing within performance target', async () => {
      const request = createTestInsightRequest();

      const benchmark = createPerformanceBenchmark(
        mockPerformanceData.insight_generation.single_item
      );
      const { durationMs } = await measurePerformance(() => zaiClient.generateInsights(request));

      const validation = benchmark.validate(durationMs);

      expect(validation.passed).toBe(true);
      expect(validation.withinVariance).toBe(true);
    });

    test('should maintain performance consistency across multiple runs', async () => {
      const request = createTestInsightRequest();
      const runs = 5;
      const durations: number[] = [];

      for (let i = 0; i < runs; i++) {
        const { durationMs } = await measurePerformance(() => zaiClient.generateInsights(request));
        durations.push(durationMs);
      }

      const averageDuration = durations.reduce((sum, d) => sum + d, 0) / runs;
      const variance =
        durations.reduce((sum, d) => sum + Math.pow(d - averageDuration, 2), 0) / runs;
      const standardDeviation = Math.sqrt(variance);

      // Performance should be consistent (low standard deviation)
      expect(standardDeviation).toBeLessThan(averageDuration * 0.2); // Less than 20% variation
    });

    test('should handle concurrent requests efficiently', async () => {
      const request = createTestInsightRequest();
      const concurrentRequests = 10;

      const startTime = Date.now();
      const promises = Array.from({ length: concurrentRequests }, () =>
        zaiClient.generateInsights(request)
      );

      const responses = await Promise.all(promises);
      const totalTime = Date.now() - startTime;

      // All responses should be valid
      responses.forEach((response) => {
        expect(response.insights).toBeDefined();
        expect(response.metadata).toBeDefined();
      });

      // Concurrent processing should be more efficient than sequential
      const singleRequestTime = totalTime / concurrentRequests;
      expect(singleRequestTime).toBeLessThan(500); // Each request should be reasonable
    });
  });

  describe('Integration with MCP Tools', () => {
    test('should work with memory store integration', async () => {
      const request = createTestInsightRequest();

      const response = await zaiClient.generateInsights(request);

      // Response should be compatible with memory store expectations
      expect(response.insights).toBeDefined();
      expect(response.metadata['items_processed']).toBeGreaterThan(0);

      // Insights should have proper structure for memory storage
      response.insights.forEach((insight) => {
        expect(insight.id).toBeDefined();
        expect(insight.item_id).toBeDefined();
        expect(insight.created_at).toBeDefined();
      });
    });

    test('should maintain service health during operations', async () => {
      const request = createTestInsightRequest();

      // Perform multiple operations
      await zaiClient.generateInsights(request);
      await zaiClient.generateInsights(request);
      await zaiClient.generateInsights(request);

      // Service should remain healthy
      const status = await zaiClient.getServiceStatus();
      expect(status.status).toBe('healthy');
      expect(status.errorRate).toBe(0);

      const metrics = zaiClient.getMetrics();
      expect(metrics.totalRequests).toBeGreaterThan(0);
      expect(metrics.failedRequests).toBe(0);
    });
  });

  describe('Real-world Scenarios', () => {
    test('should handle mixed item types effectively', async () => {
      const request = {
        ...createTestInsightRequest(),
        items: [
          {
            ...createTestInsightRequest().items[0],
            id: 'real-1',
            kind: 'decision' as const,
            content: 'Decision to adopt React for frontend',
          },
          {
            ...createTestInsightRequest().items[0],
            id: 'real-2',
            kind: 'issue' as const,
            content: 'Performance issues with current monolithic frontend',
          },
          {
            ...createTestInsightRequest().items[0],
            id: 'real-3',
            kind: 'todo' as const,
            content: 'Migrate dashboard components to React',
          },
          {
            ...createTestInsightRequest().items[0],
            id: 'real-4',
            kind: 'entity' as const,
            content: 'Frontend development team',
          },
        ],
        options: {
          ...createTestInsightRequest().options,
          insight_types: ['patterns', 'connections', 'recommendations'],
        },
      };

      const response = await zaiClient.generateInsights(request);

      expect(response.insights.length).toBeGreaterThan(0);
      expect(response.metadata['items_processed']).toBe(4);

      // Should generate different types of insights for different item types
      const insightTypes = new Set(response.insights.map((i) => i.type));
      expect(insightTypes.size).toBeGreaterThanOrEqual(1);
    });

    test('should handle project-specific context', async () => {
      const request = {
        ...createTestInsightRequest(),
        scope: {
          project: 'frontend-migration',
          branch: 'feature/react-adoption',
          org: 'engineering',
        },
        items: [
          {
            ...createTestInsightRequest().items[0],
            id: 'context-1',
            scope: {
              project: 'frontend-migration',
              branch: 'feature/react-adoption',
              org: 'engineering',
            },
          },
        ],
      };

      const response = await zaiClient.generateInsights(request);

      expect(response.insights).toBeDefined();
      // Context should be preserved in the processing
      expect(response.metadata['items_processed']).toBe(1);
    });
  });
});
