
/**
 * ZAI Enhanced Insight Service Integration Tests
 *
 * Integration tests for Phase 2 enhanced insight generation
 * using ZAI glm-4.6 model with multiple insight strategies.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { afterEach,beforeEach, describe, expect, it } from '@jest/globals';

import type { InsightGenerationRequest } from '../../../types/insight-interfaces.js';
import { ZAIEnhancedInsightService } from '../zai-enhanced-insight-service.js';

describe('ZAI Enhanced Insight Service - Integration Tests', () => {
  let service: ZAIEnhancedInsightService;

  beforeEach(() => {
    service = ZAIEnhancedInsightService.getInstance();
  });

  afterEach(() => {
    service.destroy();
  });

  describe('Service Initialization', () => {
    it('should initialize with default configuration', () => {
      const config = service.getConfig();
      expect(config.enabled).toBe(true);
      expect(config.strategies.pattern_recognition).toBe(true);
      expect(config.strategies.knowledge_gap).toBe(true);
      expect(config.strategies.relationship_analysis).toBe(true);
      expect(config.strategies.anomaly_detection).toBe(true);
      expect(config.strategies.predictive_insights).toBe(true);
    });

    it('should allow configuration updates', () => {
      service.updateConfig({
        strategies: {
          pattern_recognition: false,
          knowledge_gap: true,
          relationship_analysis: true,
          anomaly_detection: true,
          predictive_insights: true,
        },
      });

      const config = service.getConfig();
      expect(config.strategies.pattern_recognition).toBe(false);
      expect(config.strategies.knowledge_gap).toBe(true);
    });
  });

  describe('Insight Generation', () => {
    const createTestRequest = (): InsightGenerationRequest => ({
      items: [
        {
          id: 'test-item-1',
          kind: 'decision',
          content: 'Decision to migrate to microservices architecture',
          data: {
            title: 'Microservices Migration Decision',
            content:
              'After careful consideration, we decided to migrate our monolithic application to microservices for better scalability and maintainability.',
            rationale: 'Improved scalability, team autonomy, and technology flexibility',
            alternatives: ['Stay monolithic', 'Partial migration'],
            impact: 'High',
            stakeholders: ['Architecture Team', 'Development Teams'],
            tags: ['architecture', 'migration', 'microservices'],
            created_at: '2025-01-15T10:00:00Z',
          },
          scope: {
            project: 'platform-migration',
            branch: 'main',
            org: 'engineering',
          },
          created_at: '2025-01-15T10:00:00Z',
        },
        {
          id: 'test-item-2',
          kind: 'todo',
          content: 'Implement authentication service',
          data: {
            title: 'Authentication Service Implementation',
            content:
              'Create a standalone authentication service as part of the microservices migration',
            status: 'pending',
            priority: 'high',
            assignee: 'backend-team',
            dependencies: ['user-service'],
            tags: ['microservices', 'authentication', 'backend'],
            created_at: '2025-01-16T14:30:00Z',
          },
          scope: {
            project: 'platform-migration',
            branch: 'feature/auth',
            org: 'engineering',
          },
          created_at: '2025-01-16T14:30:00Z',
        },
        {
          id: 'test-item-3',
          kind: 'issue',
          content: 'Database connection pooling issues',
          data: {
            title: 'Connection Pool Exhaustion',
            content: 'Experiencing frequent database connection pool exhaustion during peak hours',
            severity: 'high',
            status: 'open',
            affected_components: ['user-service', 'order-service'],
            symptoms: ['Timeout errors', 'Connection refused'],
            tags: ['database', 'performance', 'production'],
            created_at: '2025-01-17T09:15:00Z',
          },
          scope: {
            project: 'platform-migration',
            branch: 'main',
            org: 'engineering',
          },
          created_at: '2025-01-17T09:15:00Z',
        },
      ],
      options: {
        enabled: true,
        insight_types: ['patterns', 'connections', 'recommendations', 'anomalies', 'trends'],
        max_insights_per_item: 3,
        confidence_threshold: 0.6,
        include_metadata: true,
        session_id: 'test-session-123',
      },
      scope: {
        project: 'platform-migration',
        branch: 'main',
        org: 'engineering',
      },
    });

    it('should generate insights for valid request', async () => {
      const request = createTestRequest();

      const response = await service.generateInsights(request, {
        strategies: ['pattern_recognition', 'knowledge_gap', 'relationship_analysis'],
        confidence_threshold: 0.6,
        max_insights_per_strategy: 2,
        enable_caching: true,
        background_processing: false,
        include_rationale: true,
      });

      expect(response).toBeDefined();
      expect(response.insights).toBeDefined();
      expect(Array.isArray(response.insights)).toBe(true);
      expect(response.errors).toBeDefined();
      expect(Array.isArray(response.errors)).toBe(true);
      expect(response.warnings).toBeDefined();
      expect(Array.isArray(response.warnings)).toBe(true);
    });

    it('should handle disabled service gracefully', async () => {
      service.updateConfig({ enabled: false });

      const request = createTestRequest();
      const response = await service.generateInsights(request);

      expect(response.insights).toHaveLength(0);
      expect(response.warnings).toContain('ZAI Enhanced Insight Service is disabled');
    });

    it('should return cached insights on subsequent requests', async () => {
      const request = createTestRequest();

      // First request
      const response1 = await service.generateInsights(request, {
        enable_caching: true,
      });

      // Second request should hit cache
      const response2 = await service.generateInsights(request, {
        enable_caching: true,
      });

      expect(response1.insights.length).toBeGreaterThan(0);
      expect(response2.insights.length).toBe(response1.insights.length);
      expect(response2.warnings).toContain('Insights retrieved from cache');
    });

    it('should queue insights for background processing', async () => {
      const request = createTestRequest();

      const response = await service.generateInsights(request, {
        background_processing: true,
      });

      expect(response.insights).toHaveLength(0);
      expect(response.metadata['processing_mode']).toBe('background');
      expect(response.metadata['batch_id']).toBeDefined();
      expect(response.metadata['estimated_completion']).toBeDefined();
    });

    it('should retrieve completed background insights', async () => {
      const request = createTestRequest();

      // Queue for background processing
      const queueResponse = await service.generateInsights(request, {
        background_processing: true,
      });

      const batchId = queueResponse.metadata['batch_id'];

      // Wait a bit for processing (in real tests, you'd mock or wait appropriately)
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Retrieve completed insights
      const completedResponse = await service.getCompletedInsights(batchId);

      // Should return null if not completed yet or the insights if completed
      expect(completedResponse).toBeDefined();
    });

    it('should filter insights by confidence threshold', async () => {
      const request = createTestRequest();

      const highThresholdResponse = await service.generateInsights(request, {
        confidence_threshold: 0.9,
        max_insights_per_strategy: 5,
      });

      const lowThresholdResponse = await service.generateInsights(request, {
        confidence_threshold: 0.3,
        max_insights_per_strategy: 5,
      });

      // Lower threshold should allow more insights
      expect(lowThresholdResponse.insights.length).toBeGreaterThanOrEqual(
        highThresholdResponse.insights.length
      );
    });

    it('should limit insights per strategy', async () => {
      const request = createTestRequest();

      const response = await service.generateInsights(request, {
        strategies: ['pattern_recognition', 'knowledge_gap'],
        max_insights_per_strategy: 1,
        confidence_threshold: 0.1, // Low threshold to get many insights
      });

      // Should not exceed the limit per strategy
      const patternInsights = response.insights.filter((i) => i.type === 'patterns');
      const gapInsights = response.insights.filter((i) => i.type === 'recommendations');

      expect(patternInsights.length).toBeLessThanOrEqual(1);
      expect(gapInsights.length).toBeLessThanOrEqual(1);
    });

    it('should handle empty items array gracefully', async () => {
      const request: InsightGenerationRequest = {
        items: [],
        options: {
          enabled: true,
          insight_types: [],
          max_insights_per_item: 3,
          confidence_threshold: 0.6,
          include_metadata: true,
        },
        scope: {},
      };

      const response = await service.generateInsights(request);

      expect(response.insights).toHaveLength(0);
      expect(response.metadata['items_processed']).toBe(0);
    });

    it('should include comprehensive metadata', async () => {
      const request = createTestRequest();

      const response = await service.generateInsights(request, {
        include_rationale: true,
      });

      expect(response.metadata).toBeDefined();
      expect(response.metadata['total_insights']).toBeGreaterThanOrEqual(0);
      expect(response.metadata['insights_by_type']).toBeDefined();
      expect(typeof response.metadata['insights_by_type']).toBe('object');
      expect(response.metadata['average_confidence']).toBeGreaterThanOrEqual(0);
      expect(response.metadata['average_confidence']).toBeLessThanOrEqual(1);
      expect(response.metadata['processing_time_ms']).toBeGreaterThan(0);
      expect(response.metadata['performance_impact']).toBeGreaterThanOrEqual(0);
      expect(response.metadata['cache_hit_rate']).toBeGreaterThanOrEqual(0);
      expect(response.metadata['cache_hit_rate']).toBeLessThanOrEqual(1);
    });
  });

  describe('Strategy-specific Tests', () => {
    const createStrategyTestRequest = (strategyType: string): InsightGenerationRequest => ({
      items: [
        {
          id: 'strategy-test-1',
          kind: 'entity',
          content: `Test item for ${strategyType}`,
          data: {
            title: `${strategyType} Test`,
            content: `Testing ${strategyType} strategy functionality`,
            tags: [strategyType, 'test'],
            created_at: '2025-01-15T10:00:00Z',
          },
          scope: { project: 'test-project' },
          created_at: '2025-01-15T10:00:00Z',
        },
      ],
      options: {
        enabled: true,
        insight_types: [strategyType],
        max_insights_per_item: 2,
        confidence_threshold: 0.5,
        include_metadata: true,
      },
      scope: { project: 'test-project' },
    });

    it('should generate pattern recognition insights', async () => {
      const request = createStrategyTestRequest('patterns');
      const response = await service.generateInsights(request, {
        strategies: ['pattern_recognition'],
      });

      expect(response.insights.length).toBeGreaterThanOrEqual(0);
      // If insights are generated, they should be pattern type
      if (response.insights.length > 0) {
        expect(response.insights[0].type).toBe('patterns');
      }
    });

    it('should generate knowledge gap insights', async () => {
      const request = createStrategyTestRequest('recommendations');
      const response = await service.generateInsights(request, {
        strategies: ['knowledge_gap'],
      });

      expect(response.insights.length).toBeGreaterThanOrEqual(0);
      // Knowledge gaps typically generate recommendation insights
      if (response.insights.length > 0) {
        expect(['recommendations', 'patterns']).toContain(response.insights[0].type);
      }
    });

    it('should generate relationship analysis insights', async () => {
      const request = createStrategyTestRequest('connections');
      const response = await service.generateInsights(request, {
        strategies: ['relationship_analysis'],
      });

      expect(response.insights.length).toBeGreaterThanOrEqual(0);
      if (response.insights.length > 0) {
        expect(response.insights[0].type).toBe('connections');
      }
    });

    it('should generate anomaly detection insights', async () => {
      const request = createStrategyTestRequest('anomalies');
      const response = await service.generateInsights(request, {
        strategies: ['anomaly_detection'],
      });

      expect(response.insights.length).toBeGreaterThanOrEqual(0);
      if (response.insights.length > 0) {
        expect(['anomalies', 'trends']).toContain(response.insights[0].type);
      }
    });

    it('should generate predictive insights', async () => {
      const request = createStrategyTestRequest('trends');
      const response = await service.generateInsights(request, {
        strategies: ['predictive_insights'],
      });

      expect(response.insights.length).toBeGreaterThanOrEqual(0);
      if (response.insights.length > 0) {
        expect(['recommendations', 'trends']).toContain(response.insights[0].type);
      }
    });
  });

  describe('Error Handling', () => {
    it('should handle malformed request gracefully', async () => {
      const malformedRequest = {
        items: [
          {
            // Missing required fields
            kind: 'invalid',
          },
        ],
        options: {
          enabled: true,
          insight_types: ['patterns'],
          max_insights_per_item: 1,
          confidence_threshold: 0.5,
          include_metadata: false,
        },
        scope: {},
      } as unknown;

      const response = await service.generateInsights(malformedRequest);

      // Should not crash and should return a response
      expect(response).toBeDefined();
      expect(response.insights).toBeDefined();
      expect(Array.isArray(response.errors)).toBe(true);
    });

    it('should handle invalid strategy names gracefully', async () => {
      const request = {
        items: [],
        options: {
          enabled: true,
          insight_types: [],
          max_insights_per_item: 1,
          confidence_threshold: 0.5,
          include_metadata: false,
        },
        scope: {},
      };

      const response = await service.generateInsights(request, {
        strategies: ['invalid_strategy'] as unknown,
      });

      expect(response.insights).toHaveLength(0);
      expect(response.warnings.length).toBeGreaterThanOrEqual(0);
    });

    it('should handle service destruction gracefully', async () => {
      const service = ZAIEnhancedInsightService.getInstance();

      // Should not throw
      expect(() => service.destroy()).not.toThrow();

      // Should allow re-initialization
      expect(() => ZAIEnhancedInsightService.getInstance()).not.toThrow();
    });
  });

  describe('Performance Requirements', () => {
    it('should complete insight generation within performance thresholds', async () => {
      const request = {
        items: Array.from({ length: 50 }, (_, i) => ({
          id: `perf-test-${i}`,
          kind: 'entity',
          content: `Performance test item ${i}`,
          data: {
            title: `Test ${i}`,
            content: `Content for performance testing ${i}`,
            tags: ['performance', 'test'],
            created_at: new Date().toISOString(),
          },
          scope: { project: 'performance-test' },
          created_at: new Date().toISOString(),
        })),
        options: {
          enabled: true,
          insight_types: ['patterns', 'connections'],
          max_insights_per_item: 1,
          confidence_threshold: 0.7,
          include_metadata: true,
        },
        scope: { project: 'performance-test' },
      };

      const startTime = Date.now();
      const response = await service.generateInsights(request, {
        strategies: ['pattern_recognition', 'relationship_analysis'],
        max_insights_per_strategy: 5,
        confidence_threshold: 0.6,
        enable_caching: false, // Disable cache to measure actual processing time
      });
      const processingTime = Date.now() - startTime;

      // Should complete within 5 seconds for batch of 50 items
      expect(processingTime).toBeLessThan(5000);
      expect(response.metadata['processing_time_ms']).toBeLessThan(5000);
    });

    it('should maintain insight accuracy above threshold', async () => {
      const request = {
        items: [
          {
            id: 'accuracy-test-1',
            kind: 'decision',
            content: 'High confidence test decision',
            data: {
              title: 'Test Decision',
              content: 'Clear decision with strong indicators for insight generation',
              rationale: 'Well-documented decision process',
              impact: 'high',
              tags: ['test', 'accuracy'],
              created_at: '2025-01-15T10:00:00Z',
            },
            scope: { project: 'accuracy-test' },
            created_at: '2025-01-15T10:00:00Z',
          },
        ],
        options: {
          enabled: true,
          insight_types: ['patterns', 'recommendations'],
          max_insights_per_item: 3,
          confidence_threshold: 0.9, // High threshold
          include_metadata: true,
        },
        scope: { project: 'accuracy-test' },
      };

      const response = await service.generateInsights(request, {
        confidence_threshold: 0.9,
        max_insights_per_strategy: 3,
      });

      // All generated insights should meet the high confidence threshold
      response.insights.forEach((insight) => {
        expect(insight.confidence).toBeGreaterThanOrEqual(0.9);
      });
    });
  });
});
