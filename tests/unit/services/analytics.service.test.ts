/**
 * Comprehensive Unit Tests for Analytics Service
 *
 * Tests advanced analytics service functionality including:
 * - Knowledge base analytics and metrics calculation
 * - Relationship analytics and graph metrics
 * - Performance analytics and bottleneck detection
 * - User behavior analytics and engagement tracking
 * - Predictive analytics and trend forecasting
 * - Report generation and data visualization
 * - Caching mechanisms and performance optimization
 * - Error handling and data validation
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { AnalyticsService } from '../../../src/services/analytics/analytics.service';
import type {
  KnowledgeAnalytics,
  RelationshipAnalytics,
  PerformanceAnalytics,
  UserBehaviorAnalytics,
  PredictiveAnalytics,
  AnalyticsReport,
  AnalyticsQuery,
  AnalyticsFilter
} from '../../../src/types/core-interfaces';

// Mock dependencies
vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn()
  }
}));

vi.mock('../../../src/db/qdrant', () => ({
  getQdrantClient: () => mockQdrantClient
}));

// Mock Qdrant client with comprehensive analytics data
const mockQdrantClient = {
  section: {
    findMany: vi.fn(),
    count: vi.fn()
  },
  adrDecision: {
    findMany: vi.fn(),
    count: vi.fn()
  },
  issueLog: {
    findMany: vi.fn(),
    count: vi.fn()
  },
  todoLog: {
    findMany: vi.fn(),
    count: vi.fn()
  },
  runbook: {
    findMany: vi.fn(),
    count: vi.fn()
  },
  changeLog: {
    findMany: vi.fn(),
    count: vi.fn()
  },
  releaseNote: {
    findMany: vi.fn(),
    count: vi.fn()
  },
  ddlHistory: {
    findMany: vi.fn(),
    count: vi.fn()
  },
  prContext: {
    findMany: vi.fn(),
    count: vi.fn()
  },
  knowledgeEntity: {
    findMany: vi.fn(),
    count: vi.fn()
  },
  knowledgeRelation: {
    findMany: vi.fn(),
    count: vi.fn()
  },
  knowledgeObservation: {
    findMany: vi.fn(),
    count: vi.fn()
  },
  incidentLog: {
    findMany: vi.fn(),
    count: vi.fn()
  },
  releaseLog: {
    findMany: vi.fn(),
    count: vi.fn()
  },
  riskLog: {
    findMany: vi.fn(),
    count: vi.fn()
  },
  assumptionLog: {
    findMany: vi.fn(),
    count: vi.fn()
  }
};

describe('AnalyticsService - Comprehensive Analytics Functionality', () => {
  let analyticsService: AnalyticsService;

  beforeEach(() => {
    analyticsService = new AnalyticsService();

    // Reset all mocks
    vi.clearAllMocks();

    // Setup default mock responses
    Object.values(mockQdrantClient).forEach((model: any) => {
      if (model.findMany) model.findMany.mockResolvedValue([]);
      if (model.count) model.count.mockResolvedValue(0);
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. Knowledge Analytics Tests
  describe('Knowledge Analytics', () => {
    it('should calculate comprehensive knowledge base metrics', async () => {
      // Mock comprehensive knowledge data
      const mockKnowledgeData = {
        entities: 150,
        relations: 280,
        observations: 420,
        sections: 75,
        decisions: 95,
        issues: 60,
        todos: 85,
        runbooks: 45,
        changes: 110,
        releaseNotes: 35,
        ddlHistory: 25,
        prContexts: 55,
        incidents: 20,
        releases: 15,
        risks: 40,
        assumptions: 30
      };

      // Setup mock counts for each knowledge type
      mockQdrantClient.knowledgeEntity.count.mockResolvedValue(mockKnowledgeData.entities);
      mockQdrantClient.knowledgeRelation.count.mockResolvedValue(mockKnowledgeData.relations);
      mockQdrantClient.knowledgeObservation.count.mockResolvedValue(mockKnowledgeData.observations);
      mockQdrantClient.section.count.mockResolvedValue(mockKnowledgeData.sections);
      mockQdrantClient.adrDecision.count.mockResolvedValue(mockKnowledgeData.decisions);
      mockQdrantClient.issueLog.count.mockResolvedValue(mockKnowledgeData.issues);
      mockQdrantClient.todoLog.count.mockResolvedValue(mockKnowledgeData.todos);
      mockQdrantClient.runbook.count.mockResolvedValue(mockKnowledgeData.runbooks);
      mockQdrantClient.changeLog.count.mockResolvedValue(mockKnowledgeData.changes);
      mockQdrantClient.releaseNote.count.mockResolvedValue(mockKnowledgeData.releaseNotes);
      mockQdrantClient.ddlHistory.count.mockResolvedValue(mockKnowledgeData.ddlHistory);
      mockQdrantClient.prContext.count.mockResolvedValue(mockKnowledgeData.prContexts);
      mockQdrantClient.incidentLog.count.mockResolvedValue(mockKnowledgeData.incidents);
      mockQdrantClient.releaseLog.count.mockResolvedValue(mockKnowledgeData.releases);
      mockQdrantClient.riskLog.count.mockResolvedValue(mockKnowledgeData.risks);
      mockQdrantClient.assumptionLog.count.mockResolvedValue(mockKnowledgeData.assumptions);

      const analytics = await analyticsService.getKnowledgeBaseMetrics();

      expect(analytics.totalEntities).toBe(mockKnowledgeData.entities);
      expect(analytics.totalRelations).toBe(mockKnowledgeData.relations);
      expect(analytics.totalObservations).toBe(mockKnowledgeData.observations);
      expect(analytics.knowledgeTypeDistribution).toBeDefined();
      expect(analytics.knowledgeTypeDistribution['entity']).toBe(mockKnowledgeData.entities);
      expect(analytics.knowledgeTypeDistribution['decision']).toBe(mockKnowledgeData.decisions);
      expect(analytics.growthMetrics).toBeDefined();
      expect(analytics.contentMetrics).toBeDefined();
      expect(analytics.scopeDistribution).toBeDefined();
    });

    it('should calculate growth trends with different time aggregations', async () => {
      const aggregation = {
        interval: 'day' as const,
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-01-07')
      };

      // Mock time-based data
      mockQdrantClient.section.findMany.mockImplementation(({ where }) => {
        const items = [];
        const startDate = new Date(where.created_at.gte);
        const endDate = new Date(where.created_at.lte);

        // Generate mock data for each day
        for (let d = new Date(startDate); d <= endDate; d.setDate(d.getDate() + 1)) {
          items.push({
            id: `item-${d.getTime()}`,
            kind: 'section',
            data: { title: `Section from ${d.toDateString()}` },
            tags: { project: 'test-project' },
            created_at: new Date(d)
          });
        }

        return Promise.resolve(items);
      });

      const trends = await analyticsService.getGrowthTrends(aggregation);

      expect(trends).toHaveLength(7); // 7 days
      trends.forEach((trend, index) => {
        expect(trend.timestamp).toBeInstanceOf(Date);
        expect(trend.totalKnowledge).toBeGreaterThanOrEqual(0);
        expect(trend.newEntities).toBeGreaterThanOrEqual(0);
        expect(trend.activeScopes).toBeGreaterThanOrEqual(0);
      });
    });

    it('should analyze usage patterns and interactions', async () => {
      const filter: AnalyticsFilter = {
        scope: { project: 'test-project' },
        dateRange: {
          startDate: new Date('2024-01-01'),
          endDate: new Date('2024-01-31')
        }
      };

      const usageAnalytics = await analyticsService.getUsageAnalytics(filter);

      expect(usageAnalytics.searchQueries).toBeGreaterThanOrEqual(0);
      expect(usageAnalytics.knowledgeRetrieval).toBeGreaterThanOrEqual(0);
      expect(usageAnalytics.knowledgeStorage).toBeGreaterThanOrEqual(0);
      expect(usageAnalytics.peakUsageHours).toBeInstanceOf(Array);
      expect(usageAnalytics.averageQueryComplexity).toBeGreaterThanOrEqual(0);
      expect(usageAnalytics.mostAccessedTypes).toBeDefined();
    });

    it('should handle knowledge analytics with comprehensive filters', async () => {
      const complexFilter: AnalyticsFilter = {
        scope: {
          project: 'complex-project',
          org: 'test-org',
          branch: 'main'
        },
        dateRange: {
          startDate: new Date('2024-01-01'),
          endDate: new Date('2024-12-31')
        },
        types: ['entity', 'relation', 'decision', 'issue'],
        tags: { category: 'critical', priority: 'high' }
      };

      mockQdrantClient.knowledgeEntity.count.mockResolvedValue(85);
      mockQdrantClient.knowledgeRelation.count.mockResolvedValue(120);
      mockQdrantClient.adrDecision.count.mockResolvedValue(45);
      mockQdrantClient.issueLog.count.mockResolvedValue(30);

      const analytics = await analyticsService.getKnowledgeBaseMetrics(complexFilter);

      expect(analytics.knowledgeTypeDistribution).toBeDefined();
      expect(Object.keys(analytics.knowledgeTypeDistribution)).toContain('entity');
      expect(Object.keys(analytics.knowledgeTypeDistribution)).toContain('relation');

      // Verify that the where clause was constructed correctly
      expect(mockQdrantClient.knowledgeEntity.count).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            tags: expect.objectContaining({
              project: 'complex-project',
              org: 'test-org',
              branch: 'main'
            }),
            created_at: expect.objectContaining({
              gte: complexFilter.dateRange?.startDate,
              lte: complexFilter.dateRange?.endDate
            })
          })
        })
      );
    });

    it('should calculate content complexity and distribution metrics', async () => {
      mockQdrantClient.knowledgeEntity.findMany.mockResolvedValue([
        {
          id: 'entity-1',
          data: { title: 'Simple Entity', content: 'Short content' },
          created_at: new Date('2024-01-01')
        },
        {
          id: 'entity-2',
          data: {
            title: 'Complex Entity',
            content: 'This is a much longer and more complex content piece that would be classified as having higher complexity due to its length and structure.',
            details: { sections: ['intro', 'body', 'conclusion'], complexity: 'high' }
          },
          created_at: new Date('2024-01-02')
        }
      ]);

      const analytics = await analyticsService.getKnowledgeBaseMetrics();

      expect(analytics.contentMetrics).toBeDefined();
      expect(analytics.contentMetrics.averageContentLength).toBeGreaterThan(0);
      expect(analytics.contentMetrics.totalContentLength).toBeGreaterThan(0);
      expect(['low', 'medium', 'high']).toContain(analytics.contentMetrics.contentComplexity);
    });

    it('should handle knowledge analytics errors gracefully', async () => {
      // Mock database error
      mockQdrantClient.knowledgeEntity.count.mockRejectedValue(new Error('Database connection failed'));

      await expect(analyticsService.getKnowledgeBaseMetrics()).rejects.toThrow('Failed to retrieve knowledge metrics');
    });
  });

  // 2. Relationship Analytics Tests
  describe('Relationship Analytics', () => {
    it('should calculate comprehensive relationship analytics', async () => {
      const mockRelations = [
        {
          id: 'rel-1',
          relation_type: 'depends_on',
          source_entity_id: 'entity-1',
          target_entity_id: 'entity-2'
        },
        {
          id: 'rel-2',
          relation_type: 'implements',
          source_entity_id: 'entity-2',
          target_entity_id: 'entity-3'
        },
        {
          id: 'rel-3',
          relation_type: 'relates_to',
          source_entity_id: 'entity-1',
          target_entity_id: 'entity-3'
        },
        {
          id: 'rel-4',
          relation_type: 'depends_on',
          source_entity_id: 'entity-4',
          target_entity_id: 'entity-1'
        }
      ];

      mockQdrantClient.knowledgeRelation.findMany.mockResolvedValue(mockRelations);

      const analytics = await analyticsService.getRelationshipAnalytics();

      expect(analytics.totalRelations).toBe(mockRelations.length);
      expect(analytics.relationTypeDistribution).toBeDefined();
      expect(analytics.relationTypeDistribution['depends_on']).toBe(2);
      expect(analytics.relationTypeDistribution['implements']).toBe(1);
      expect(analytics.relationTypeDistribution['relates_to']).toBe(1);
      expect(analytics.graphDensity).toBeGreaterThan(0);
      expect(analytics.averageDegree).toBeGreaterThan(0);
      expect(analytics.centralityMeasures).toBeDefined();
    });

    it('should identify network insights and patterns', async () => {
      const filter: AnalyticsFilter = {
        scope: { project: 'network-analysis' }
      };

      const insights = await analyticsService.getNetworkInsights(filter);

      expect(insights.stronglyConnectedComponents).toBeGreaterThan(0);
      expect(insights.networkCommunities).toBeInstanceOf(Array);
      expect(insights.keyInfluencers).toBeInstanceOf(Array);
      expect(insights.bridges).toBeInstanceOf(Array);
      expect(insights.networkEvolution).toBeInstanceOf(Array);

      // Verify key influencers have expected structure
      insights.keyInfluencers.forEach(influencer => {
        expect(influencer).toHaveProperty('id');
        expect(influencer).toHaveProperty('influenceScore');
        expect(influencer).toHaveProperty('type');
        expect(influencer.influenceScore).toBeGreaterThanOrEqual(0);
        expect(influencer.influenceScore).toBeLessThanOrEqual(1);
      });
    });

    it('should calculate centrality measures correctly', async () => {
      const mockRelations = [
        { relation_type: 'connects', source_entity_id: 'central', target_entity_id: 'node-1' },
        { relation_type: 'connects', source_entity_id: 'central', target_entity_id: 'node-2' },
        { relation_type: 'connects', source_entity_id: 'central', target_entity_id: 'node-3' },
        { relation_type: 'connects', source_entity_id: 'node-1', target_entity_id: 'node-2' },
        { relation_type: 'connects', source_entity_id: 'node-2', target_entity_id: 'node-3' }
      ];

      mockQdrantClient.knowledgeRelation.findMany.mockResolvedValue(mockRelations);

      const analytics = await analyticsService.getRelationshipAnalytics();

      expect(analytics.centralityMeasures.betweenness).toBeDefined();
      expect(analytics.centralityMeasures.closeness).toBeDefined();
      expect(analytics.centralityMeasures.eigenvector).toBeDefined();
      expect(analytics.clusteringCoefficients).toBeDefined();
      expect(analytics.pathLengths).toBeDefined();
      expect(analytics.pathLengths.averageShortestPath).toBeGreaterThanOrEqual(0);
      expect(analytics.pathLengths.diameter).toBeGreaterThanOrEqual(0);
    });

    it('should handle sparse relationship graphs', async () => {
      // Mock sparse graph with minimal relationships
      const sparseRelations = [
        { relation_type: 'relates_to', source_entity_id: 'entity-1', target_entity_id: 'entity-2' }
      ];

      mockQdrantClient.knowledgeRelation.findMany.mockResolvedValue(sparseRelations);

      const analytics = await analyticsService.getRelationshipAnalytics();

      expect(analytics.totalRelations).toBe(1);
      expect(analytics.graphDensity).toBeGreaterThan(0);
      expect(analytics.averageDegree).toBeGreaterThan(0);
      expect(Object.keys(analytics.relationTypeDistribution)).toContain('relates_to');
    });

    it('should handle relationship analytics with filters', async () => {
      const filter: AnalyticsFilter = {
        scope: { project: 'filtered-project' },
        dateRange: {
          startDate: new Date('2024-01-01'),
          endDate: new Date('2024-06-30')
        }
      };

      const mockRelations = [
        {
          id: 'filtered-rel-1',
          relation_type: 'implements',
          source_entity_id: 'src-1',
          target_entity_id: 'tgt-1',
          tags: { project: 'filtered-project' },
          created_at: new Date('2024-03-15')
        }
      ];

      mockQdrantClient.knowledgeRelation.findMany.mockResolvedValue(mockRelations);

      const analytics = await analyticsService.getRelationshipAnalytics(filter);

      expect(mockQdrantClient.knowledgeRelation.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            tags: expect.objectContaining({ project: 'filtered-project' })
          })
        })
      );
    });
  });

  // 3. Performance Analytics Tests
  describe('Performance Analytics', () => {
    it('should analyze query performance metrics', async () => {
      const filter: AnalyticsFilter = {
        dateRange: {
          startDate: new Date('2024-01-01'),
          endDate: new Date('2024-01-31')
        }
      };

      const analytics = await analyticsService.getPerformanceAnalytics(filter);

      expect(analytics.queryPerformance).toBeDefined();
      expect(analytics.queryPerformance.averageResponseTime).toBeGreaterThanOrEqual(0);
      expect(analytics.queryPerformance.p95ResponseTime).toBeGreaterThanOrEqual(0);
      expect(analytics.queryPerformance.p99ResponseTime).toBeGreaterThanOrEqual(0);
      expect(analytics.queryPerformance.throughput).toBeGreaterThanOrEqual(0);
      expect(analytics.queryPerformance.errorRate).toBeGreaterThanOrEqual(0);
      expect(analytics.queryPerformance.errorRate).toBeLessThanOrEqual(1);
    });

    it('should calculate storage utilization analytics', async () => {
      const analytics = await analyticsService.getPerformanceAnalytics();

      expect(analytics.storageUtilization).toBeDefined();
      expect(analytics.storageUtilization.totalStorageUsed).toBeGreaterThan(0);
      expect(analytics.storageUtilization.storageByType).toBeDefined();
      expect(analytics.storageUtilization.growthRate).toBeGreaterThanOrEqual(0);

      // Verify storage by type structure
      Object.entries(analytics.storageUtilization.storageByType).forEach(([type, usage]) => {
        expect(typeof type).toBe('string');
        expect(usage).toBeGreaterThanOrEqual(0);
      });
    });

    it('should identify performance bottlenecks', async () => {
      const analytics = await analyticsService.getPerformanceAnalytics();

      expect(analytics.bottlenecks).toBeInstanceOf(Array);
      analytics.bottlenecks.forEach(bottleneck => {
        expect(bottleneck).toHaveProperty('type');
        expect(bottleneck).toHaveProperty('severity');
        expect(bottleneck).toHaveProperty('description');
        expect(bottleneck).toHaveProperty('recommendation');
        expect(['low', 'medium', 'high', 'critical']).toContain(bottleneck.severity);
      });

      expect(analytics.optimizationSuggestions).toBeInstanceOf(Array);
      analytics.optimizationSuggestions.forEach(suggestion => {
        expect(typeof suggestion).toBe('string');
        expect(suggestion.length).toBeGreaterThan(0);
      });
    });

    it('should provide system metrics monitoring', async () => {
      const analytics = await analyticsService.getPerformanceAnalytics();

      expect(analytics.systemMetrics).toBeDefined();
      expect(analytics.systemMetrics.cpuUsage).toBeGreaterThanOrEqual(0);
      expect(analytics.systemMetrics.memoryUsage).toBeGreaterThanOrEqual(0);
      expect(analytics.systemMetrics.diskIO).toBeGreaterThanOrEqual(0);
      expect(analytics.systemMetrics.networkIO).toBeGreaterThanOrEqual(0);
    });

    it('should handle performance analytics with real-time monitoring', async () => {
      const realTimeConfig = {
        enableRealTimeAnalytics: true,
        enableCaching: false
      };

      const realTimeService = new AnalyticsService(realTimeConfig);
      const analytics = await realTimeService.getPerformanceAnalytics();

      expect(analytics).toBeDefined();
      expect(analytics.queryPerformance).toBeDefined();
      expect(realTimeService.getConfig().enableRealTimeAnalytics).toBe(true);
    });

    it('should generate optimization recommendations based on metrics', async () => {
      const analytics = await analyticsService.getPerformanceAnalytics();

      // Should provide suggestions when performance issues are detected
      if (analytics.queryPerformance.averageResponseTime > 1000) {
        expect(analytics.optimizationSuggestions.length).toBeGreaterThan(0);
        expect(analytics.optimizationSuggestions.some(s =>
          s.toLowerCase().includes('cache')
        )).toBe(true);
      }

      if (analytics.storageUtilization.growthRate > 0.2) {
        expect(analytics.optimizationSuggestions.some(s =>
          s.toLowerCase().includes('storage') || s.toLowerCase().includes('archiving')
        )).toBe(true);
      }
    });

    it('should handle performance analytics errors gracefully', async () => {
      // Mock performance monitoring service error
      const originalGetRecentQueryPerformance = analyticsService['getRecentQueryPerformance'];
      analyticsService['getRecentQueryPerformance'] = vi.fn().mockRejectedValue(new Error('Performance monitoring service unavailable'));

      await expect(analyticsService.getPerformanceAnalytics()).rejects.toThrow('Failed to retrieve performance analytics');

      // Restore original method
      analyticsService['getRecentQueryPerformance'] = originalGetRecentQueryPerformance;
    });
  });

  // 4. User Behavior Analytics Tests
  describe('User Behavior Analytics', () => {
    it('should analyze comprehensive search patterns', async () => {
      const filter: AnalyticsFilter = {
        dateRange: {
          startDate: new Date('2024-01-01'),
          endDate: new Date('2024-01-31')
        }
      };

      const analytics = await analyticsService.getUserBehaviorAnalytics(filter);

      expect(analytics.searchPatterns).toBeDefined();
      expect(analytics.searchPatterns.commonQueries).toBeInstanceOf(Array);
      expect(analytics.searchPatterns.queryComplexity).toBeDefined();
      expect(analytics.searchPatterns.queryComplexity.simple).toBeGreaterThanOrEqual(0);
      expect(analytics.searchPatterns.queryComplexity.medium).toBeGreaterThanOrEqual(0);
      expect(analytics.searchPatterns.queryComplexity.complex).toBeGreaterThanOrEqual(0);
      expect(analytics.searchPatterns.filtersUsage).toBeDefined();

      // Verify common queries structure
      analytics.searchPatterns.commonQueries.forEach(query => {
        expect(query).toHaveProperty('query');
        expect(query).toHaveProperty('frequency');
        expect(query.frequency).toBeGreaterThan(0);
        expect(typeof query.query).toBe('string');
      });
    });

    it('should analyze content interaction patterns', async () => {
      const analytics = await analyticsService.getUserBehaviorAnalytics();

      expect(analytics.contentInteraction).toBeDefined();
      expect(analytics.contentInteraction.mostViewedTypes).toBeDefined();
      expect(analytics.contentInteraction.averageSessionDuration).toBeGreaterThan(0);
      expect(analytics.contentInteraction.bounceRate).toBeGreaterThanOrEqual(0);
      expect(analytics.contentInteraction.bounceRate).toBeLessThanOrEqual(1);

      // Verify most viewed types structure
      Object.entries(analytics.contentInteraction.mostViewedTypes).forEach(([type, views]) => {
        expect(typeof type).toBe('string');
        expect(views).toBeGreaterThan(0);
      });
    });

    it('should calculate usage trends and adoption metrics', async () => {
      const analytics = await analyticsService.getUserBehaviorAnalytics();

      expect(analytics.usageTrends).toBeDefined();
      expect(analytics.usageTrends.dailyActiveUsers).toBeGreaterThan(0);
      expect(analytics.usageTrends.retentionRate).toBeGreaterThanOrEqual(0);
      expect(analytics.usageTrends.retentionRate).toBeLessThanOrEqual(1);
      expect(analytics.usageTrends.featureAdoption).toBeDefined();

      // Verify feature adoption structure
      Object.entries(analytics.usageTrends.featureAdoption).forEach(([feature, adoption]) => {
        expect(typeof feature).toBe('string');
        expect(adoption).toBeGreaterThanOrEqual(0);
        expect(adoption).toBeLessThanOrEqual(1);
      });
    });

    it('should calculate engagement metrics', async () => {
      const analytics = await analyticsService.getUserBehaviorAnalytics();

      expect(analytics.engagementMetrics).toBeDefined();
      expect(analytics.engagementMetrics.totalInteractions).toBeGreaterThanOrEqual(0);
      expect(analytics.engagementMetrics.averageInteractionsPerSession).toBeGreaterThanOrEqual(0);
      expect(analytics.engagementMetrics.peakActivityHours).toBeInstanceOf(Array);

      // Verify peak activity hours
      analytics.engagementMetrics.peakActivityHours.forEach(hour => {
        expect(hour).toBeGreaterThanOrEqual(0);
        expect(hour).toBeLessThan(24);
      });
    });

    it('should identify user behavior patterns across different scopes', async () => {
      const filter: AnalyticsFilter = {
        scope: { project: 'user-behavior-study' },
        dateRange: {
          startDate: new Date('2024-01-01'),
          endDate: new Date('2024-03-31')
        }
      };

      const analytics = await analyticsService.getUserBehaviorAnalytics(filter);

      expect(analytics.searchPatterns).toBeDefined();
      expect(analytics.contentInteraction).toBeDefined();
      expect(analytics.usageTrends).toBeDefined();
      expect(analytics.engagementMetrics).toBeDefined();
    });

    it('should handle user behavior analytics with demographic filters', async () => {
      const filter: AnalyticsFilter = {
        tags: {
          user_type: 'power_user',
          department: 'engineering'
        }
      };

      const analytics = await analyticsService.getUserBehaviorAnalytics(filter);

      expect(analytics).toBeDefined();
      expect(analytics.searchPatterns).toBeDefined();
      expect(analytics.contentInteraction).toBeDefined();
    });
  });

  // 5. Predictive Analytics Tests
  describe('Predictive Analytics', () => {
    it('should generate growth predictions', async () => {
      const analyticsServiceWithPrediction = new AnalyticsService({
        enablePredictiveAnalytics: true
      });

      const analytics = await analyticsServiceWithPrediction.getPredictiveAnalytics();

      expect(analytics.growthPredictions).toBeDefined();
      expect(analytics.growthPredictions.nextMonth).toBeDefined();
      expect(analytics.growthPredictions.nextQuarter).toBeDefined();
      expect(analytics.growthPredictions.nextYear).toBeDefined();

      // Verify prediction structure
      ['nextMonth', 'nextQuarter', 'nextYear'].forEach(period => {
        const prediction = analytics.growthPredictions[period as keyof typeof analytics.growthPredictions];
        expect(prediction.entities).toBeGreaterThan(0);
        expect(prediction.relations).toBeGreaterThan(0);
        expect(prediction.observations).toBeGreaterThan(0);
      });
    });

    it('should predict knowledge trends and patterns', async () => {
      const analyticsServiceWithPrediction = new AnalyticsService({
        enablePredictiveAnalytics: true
      });

      const analytics = await analyticsServiceWithPrediction.getPredictiveAnalytics();

      expect(analytics.trendPredictions).toBeDefined();
      expect(analytics.trendPredictions.knowledgeTypes).toBeDefined();
      expect(analytics.trendPredictions.scopes).toBeDefined();
      expect(['increasing', 'decreasing', 'stable']).toContain(analytics.trendPredictions.contentComplexity);

      // Verify trend predictions structure
      Object.entries(analytics.trendPredictions.knowledgeTypes).forEach(([type, prediction]) => {
        expect(typeof type).toBe('string');
        expect(prediction).toHaveProperty('trend');
        expect(prediction).toHaveProperty('confidence');
        expect(['increasing', 'decreasing', 'stable']).toContain(prediction.trend);
        expect(prediction.confidence).toBeGreaterThanOrEqual(0);
        expect(prediction.confidence).toBeLessThanOrEqual(1);
      });
    });

    it('should detect anomalies and unusual patterns', async () => {
      const analyticsServiceWithPrediction = new AnalyticsService({
        enablePredictiveAnalytics: true
      });

      const analytics = await analyticsServiceWithPrediction.getPredictiveAnalytics();

      expect(analytics.anomalyDetection).toBeDefined();
      expect(analytics.anomalyDetection.detectedAnomalies).toBeInstanceOf(Array);
      expect(analytics.anomalyDetection.confidenceScores).toBeDefined();
      expect(analytics.anomalyDetection.recommendedActions).toBeInstanceOf(Array);

      // Verify anomaly detection structure
      analytics.anomalyDetection.detectedAnomalies.forEach(anomaly => {
        expect(anomaly).toHaveProperty('type');
        expect(anomaly).toHaveProperty('timestamp');
        expect(anomaly).toHaveProperty('severity');
        expect(anomaly).toHaveProperty('description');
        expect(['low', 'medium', 'high', 'critical']).toContain(anomaly.severity);
      });

      // Verify confidence scores
      Object.entries(analytics.anomalyDetection.confidenceScores).forEach(([anomaly, score]) => {
        expect(typeof anomaly).toBe('string');
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(1);
      });
    });

    it('should generate predictive insights and recommendations', async () => {
      const analyticsServiceWithPrediction = new AnalyticsService({
        enablePredictiveAnalytics: true
      });

      const analytics = await analyticsServiceWithPrediction.getPredictiveAnalytics();

      expect(analytics.insights).toBeDefined();
      expect(analytics.insights.keyInsights).toBeInstanceOf(Array);
      expect(analytics.insights.recommendations).toBeInstanceOf(Array);
      expect(analytics.insights.riskFactors).toBeInstanceOf(Array);

      // Verify insights structure
      analytics.insights.keyInsights.forEach(insight => {
        expect(typeof insight).toBe('string');
        expect(insight.length).toBeGreaterThan(0);
      });

      analytics.insights.recommendations.forEach(recommendation => {
        expect(typeof recommendation).toBe('string');
        expect(recommendation.length).toBeGreaterThan(0);
      });

      analytics.insights.riskFactors.forEach(risk => {
        expect(typeof risk).toBe('string');
        expect(risk.length).toBeGreaterThan(0);
      });
    });

    it('should handle predictive analytics with filters', async () => {
      const analyticsServiceWithPrediction = new AnalyticsService({
        enablePredictiveAnalytics: true
      });

      const filter: AnalyticsFilter = {
        scope: { project: 'prediction-study' },
        dateRange: {
          startDate: new Date('2024-01-01'),
          endDate: new Date('2024-12-31')
        }
      };

      const analytics = await analyticsServiceWithPrediction.getPredictiveAnalytics(filter);

      expect(analytics.growthPredictions).toBeDefined();
      expect(analytics.trendPredictions).toBeDefined();
      expect(analytics.anomalyDetection).toBeDefined();
      expect(analytics.insights).toBeDefined();
    });

    it('should throw error when predictive analytics is disabled', async () => {
      const analyticsServiceWithoutPrediction = new AnalyticsService({
        enablePredictiveAnalytics: false
      });

      await expect(analyticsServiceWithoutPrediction.getPredictiveAnalytics()).rejects.toThrow('Predictive analytics is disabled in configuration');
    });

    it('should handle prediction calculation errors gracefully', async () => {
      const analyticsServiceWithPrediction = new AnalyticsService({
        enablePredictiveAnalytics: true
      });

      // Mock prediction method to throw error
      const originalPredictGrowth = analyticsServiceWithPrediction['predictGrowth'];
      analyticsServiceWithPrediction['predictGrowth'] = vi.fn().mockRejectedValue(new Error('Prediction calculation failed'));

      await expect(analyticsServiceWithPrediction.getPredictiveAnalytics()).rejects.toThrow('Failed to retrieve predictive analytics');

      // Restore original method
      analyticsServiceWithPrediction['predictGrowth'] = originalPredictGrowth;
    });
  });

  // 6. Report Generation and Visualization Tests
  describe('Report Generation and Visualization', () => {
    it('should generate comprehensive analytics reports', async () => {
      const query: AnalyticsQuery = {
        type: 'knowledge',
        title: 'Knowledge Base Analytics Report',
        timeRange: {
          startDate: new Date('2024-01-01'),
          endDate: new Date('2024-01-31')
        },
        filters: {
          scope: { project: 'report-project' }
        }
      };

      const report = await analyticsService.generateReport(query);

      expect(report.id).toBeDefined();
      expect(report.title).toBe(query.title);
      expect(report.generatedAt).toBeInstanceOf(Date);
      expect(report.timeRange).toEqual(query.timeRange);
      expect(report.filters).toEqual(query.filters);
      expect(report.data).toBeDefined();
      expect(report.visualizations).toBeInstanceOf(Array);
      expect(report.summary).toBeDefined();
      expect(report.metadata).toBeDefined();

      // Verify metadata structure
      expect(report.metadata.totalDataPoints).toBeGreaterThan(0);
      expect(report.metadata.processingTimeMs).toBeGreaterThan(0);
      expect(typeof report.metadata.cacheHit).toBe('boolean');
    });

    it('should generate different types of analytics reports', async () => {
      const reportTypes: AnalyticsQuery['type'][] = ['knowledge', 'relationships', 'performance', 'user_behavior', 'predictive'];

      for (const type of reportTypes) {
        const query: AnalyticsQuery = {
          type,
          title: `${type.charAt(0).toUpperCase() + type.slice(1)} Analytics Report`
        };

        if (type === 'predictive') {
          // Enable predictive analytics for predictive reports
          analyticsService.updateConfig({ enablePredictiveAnalytics: true });
        }

        const report = await analyticsService.generateReport(query);

        expect(report.data).toBeDefined();
        expect(report.visualizations.length).toBeGreaterThan(0);
        expect(report.summary.length).toBeGreaterThan(0);

        if (type === 'predictive') {
          // Disable predictive analytics after test
          analyticsService.updateConfig({ enablePredictiveAnalytics: false });
        }
      }
    });

    it('should generate appropriate visualizations for report data', async () => {
      const query: AnalyticsQuery = {
        type: 'knowledge',
        title: 'Visualization Test Report'
      };

      const report = await analyticsService.generateReport(query);

      expect(report.visualizations.length).toBeGreaterThan(0);

      report.visualizations.forEach(viz => {
        expect(viz).toHaveProperty('type');
        expect(viz).toHaveProperty('title');
        expect(viz).toHaveProperty('data');
        expect(typeof viz.type).toBe('string');
        expect(typeof viz.title).toBe('string');
        expect(viz.data).toBeDefined();
      });
    });

    it('should export reports in different formats', async () => {
      const query: AnalyticsQuery = {
        type: 'knowledge',
        title: 'Export Test Report'
      };

      const report = await analyticsService.generateReport(query);

      // Test JSON export
      const jsonExport = await analyticsService.exportReport(report.id, 'json');
      expect(jsonExport).toBeInstanceOf(Buffer);
      const jsonContent = JSON.parse(jsonExport.toString());
      expect(jsonContent.id).toBe(report.id);
      expect(jsonContent.title).toBe(report.title);

      // Test CSV export
      const csvExport = await analyticsService.exportReport(report.id, 'csv');
      expect(csvExport).toBeInstanceOf(Buffer);
      const csvContent = csvExport.toString();
      expect(csvContent).toContain('Metric,Value,Type');
      expect(csvContent.length).toBeGreaterThan(0);
    });

    it('should handle PDF export request appropriately', async () => {
      const query: AnalyticsQuery = {
        type: 'knowledge',
        title: 'PDF Test Report'
      };

      const report = await analyticsService.generateReport(query);

      await expect(analyticsService.exportReport(report.id, 'pdf')).rejects.toThrow('PDF export not yet implemented');
    });

    it('should handle report export errors gracefully', async () => {
      await expect(analyticsService.exportReport('non-existent-report', 'json')).rejects.toThrow('Report not found: non-existent-report');

      await expect(analyticsService.exportReport('test-report', 'unsupported' as any)).rejects.toThrow('Unsupported export format: unsupported');
    });

    it('should cache reports for performance', async () => {
      const query: AnalyticsQuery = {
        type: 'knowledge',
        title: 'Cache Test Report'
      };

      // Generate first report
      const report1 = await analyticsService.generateReport(query);

      // Generate same report again (should hit cache)
      const report2 = await analyticsService.generateReport(query);

      expect(report1.id).toBe(report2.id);
      expect(report1.data).toEqual(report2.data);
      expect(report1.metadata.cacheHit).toBe(false); // First call
      expect(report2.metadata.cacheHit).toBe(true); // Second call
    });

    it('should handle complex report queries with aggregations', async () => {
      const complexQuery: AnalyticsQuery = {
        type: 'performance',
        title: 'Complex Performance Report',
        timeRange: {
          startDate: new Date('2024-01-01'),
          endDate: new Date('2024-12-31')
        },
        filters: {
          scope: { project: 'complex-project' },
          types: ['entity', 'relation']
        },
        aggregations: [
          {
            field: 'response_time',
            operation: 'average'
          },
          {
            field: 'storage_usage',
            operation: 'sum',
            groupBy: 'type'
          }
        ],
        limit: 1000
      };

      const report = await analyticsService.generateReport(complexQuery);

      expect(report.data).toBeDefined();
      expect(report.visualizations.length).toBeGreaterThan(0);
      expect(report.metadata.totalDataPoints).toBeLessThanOrEqual(1000);
    });
  });

  // 7. Caching and Performance Tests
  describe('Caching and Performance', () => {
    it('should cache analytics results correctly', async () => {
      const filter: AnalyticsFilter = {
        scope: { project: 'cache-test' }
      };

      // First call should hit database
      const analytics1 = await analyticsService.getKnowledgeBaseMetrics(filter);
      expect(mockQdrantClient.knowledgeEntity.count).toHaveBeenCalledTimes(1);

      // Second call should hit cache
      const analytics2 = await analyticsService.getKnowledgeBaseMetrics(filter);
      expect(mockQdrantClient.knowledgeEntity.count).toHaveBeenCalledTimes(1); // Still only called once

      expect(analytics1).toEqual(analytics2);
    });

    it('should respect cache timeout', async () => {
      const shortTimeoutConfig = {
        enableCaching: true,
        cacheTimeoutMs: 100 // 100ms timeout
      };

      const shortTimeoutService = new AnalyticsService(shortTimeoutConfig);
      const filter: AnalyticsFilter = {
        scope: { project: 'timeout-test' }
      };

      // First call
      await shortTimeoutService.getKnowledgeBaseMetrics(filter);

      // Wait for cache to expire
      await new Promise(resolve => setTimeout(resolve, 150));

      // Second call should hit database again
      await shortTimeoutService.getKnowledgeBaseMetrics(filter);
      expect(mockQdrantClient.knowledgeEntity.count).toHaveBeenCalledTimes(2);
    });

    it('should handle cache size limits', async () => {
      // Generate many different requests to exceed cache limit
      const promises = [];
      for (let i = 0; i < 1100; i++) {
        const filter: AnalyticsFilter = {
          scope: { project: `cache-test-${i}` }
        };
        promises.push(analyticsService.getKnowledgeBaseMetrics(filter));
      }

      await Promise.all(promises);

      // Cache should still be functional
      const finalAnalytics = await analyticsService.getKnowledgeBaseMetrics({
        scope: { project: 'cache-test-1099' }
      });

      expect(finalAnalytics).toBeDefined();
    });

    it('should provide cache statistics', async () => {
      const stats = analyticsService.getCacheStats();

      expect(stats).toHaveProperty('size');
      expect(stats).toHaveProperty('maxSize');
      expect(stats).toHaveProperty('memoryUsage');
      expect(typeof stats.size).toBe('number');
      expect(typeof stats.maxSize).toBe('number');
      expect(typeof stats.memoryUsage).toBe('number');
    });

    it('should clear cache on demand', async () => {
      const filter: AnalyticsFilter = {
        scope: { project: 'clear-cache-test' }
      };

      // Generate cached result
      await analyticsService.getKnowledgeBaseMetrics(filter);
      expect(analyticsService.getCacheStats().size).toBeGreaterThan(0);

      // Clear cache
      analyticsService.clearCache();
      expect(analyticsService.getCacheStats().size).toBe(0);
    });

    it('should work with caching disabled', async () => {
      const noCacheConfig = {
        enableCaching: false
      };

      const noCacheService = new AnalyticsService(noCacheConfig);
      const filter: AnalyticsFilter = {
        scope: { project: 'no-cache-test' }
      };

      // Multiple calls should always hit database
      await noCacheService.getKnowledgeBaseMetrics(filter);
      await noCacheService.getKnowledgeBaseMetrics(filter);

      expect(mockQdrantClient.knowledgeEntity.count).toHaveBeenCalledTimes(2);
    });
  });

  // 8. Configuration and Utility Tests
  describe('Configuration and Utilities', () => {
    it('should accept custom configuration', () => {
      const customConfig = {
        enableCaching: false,
        cacheTimeoutMs: 600000,
        maxReportItems: 20000,
        enablePredictiveAnalytics: false,
        enableRealTimeAnalytics: false
      };

      const customService = new AnalyticsService(customConfig);
      const config = customService.getConfig();

      expect(config.enableCaching).toBe(false);
      expect(config.cacheTimeoutMs).toBe(600000);
      expect(config.maxReportItems).toBe(20000);
      expect(config.enablePredictiveAnalytics).toBe(false);
      expect(config.enableRealTimeAnalytics).toBe(false);
    });

    it('should update configuration dynamically', () => {
      const initialConfig = analyticsService.getConfig();
      expect(initialConfig.enablePredictiveAnalytics).toBe(true);

      analyticsService.updateConfig({
        enablePredictiveAnalytics: false,
        cacheTimeoutMs: 600000
      });

      const updatedConfig = analyticsService.getConfig();
      expect(updatedConfig.enablePredictiveAnalytics).toBe(false);
      expect(updatedConfig.cacheTimeoutMs).toBe(600000);
      expect(updatedConfig.enableCaching).toBe(initialConfig.enableCaching); // Should preserve other settings
    });

    it('should handle table name mapping correctly', () => {
      const testCases = [
        { kind: 'entity', expected: 'knowledgeEntity' },
        { kind: 'relation', expected: 'knowledgeRelation' },
        { kind: 'decision', expected: 'adrDecision' },
        { kind: 'observation', expected: 'knowledgeObservation' },
        { kind: 'unknown', expected: 'unknown' }
      ];

      testCases.forEach(({ kind, expected }) => {
        const tableName = analyticsService['getTableNameForKind'](kind);
        expect(tableName).toBe(expected);
      });
    });

    it('should build where clauses correctly', () => {
      const testCases = [
        {
          filter: undefined,
          expected: {}
        },
        {
          filter: { scope: { project: 'test' } },
          expected: { tags: { project: 'test' } }
        },
        {
          filter: {
            scope: { project: 'test', org: 'org', branch: 'main' },
            types: ['entity', 'relation']
          },
          expected: {
            tags: { project: 'test', org: 'org', branch: 'main' },
            kind: { in: ['entity', 'relation'] }
          }
        },
        {
          filter: {
            dateRange: {
              startDate: new Date('2024-01-01'),
              endDate: new Date('2024-12-31')
            }
          },
          expected: {
            created_at: {
              gte: new Date('2024-01-01'),
              lte: new Date('2024-12-31')
            }
          }
        }
      ];

      testCases.forEach(({ filter, expected }) => {
        const whereClause = analyticsService['buildWhereClause'](filter);
        expect(whereClause).toEqual(expected);
      });
    });

    it('should generate time slots correctly', () => {
      const testCases = [
        {
          aggregation: {
            interval: 'day' as const,
            startDate: new Date('2024-01-01'),
            endDate: new Date('2024-01-03')
          },
          expectedSlots: 3
        },
        {
          aggregation: {
            interval: 'hour' as const,
            startDate: new Date('2024-01-01T00:00:00'),
            endDate: new Date('2024-01-01T02:00:00')
          },
          expectedSlots: 2
        },
        {
          aggregation: {
            interval: 'month' as const,
            startDate: new Date('2024-01-01'),
            endDate: new Date('2024-03-01')
          },
          expectedSlots: 2
        }
      ];

      testCases.forEach(({ aggregation, expectedSlots }) => {
        const timeSlots = analyticsService['generateTimeSlots'](aggregation);
        expect(timeSlots).toHaveLength(expectedSlots);

        timeSlots.forEach((slot, index) => {
          expect(slot.start).toBeInstanceOf(Date);
          expect(slot.end).toBeInstanceOf(Date);
          expect(slot.start < slot.end).toBe(true);

          if (index > 0) {
            expect(slot.start >= timeSlots[index - 1].end).toBe(true);
          }
        });
      });
    });

    it('should calculate percentiles correctly', () => {
      const values = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];

      const p50 = analyticsService['calculatePercentile'](values, 50);
      const p95 = analyticsService['calculatePercentile'](values, 95);
      const p99 = analyticsService['calculatePercentile'](values, 99);

      expect(p50).toBe(50); // Median
      expect(p95).toBe(95); // 95th percentile
      expect(p99).toBe(100); // 99th percentile (should be max value)
    });

    it('should handle empty values array for percentile calculation', () => {
      const emptyValues: number[] = [];
      const p95 = analyticsService['calculatePercentile'](emptyValues, 95);
      expect(p95).toBe(0); // Should return 0 for empty array
    });

    it('should calculate entity degrees correctly', () => {
      const relations = [
        { source_entity_id: 'entity-1', target_entity_id: 'entity-2' },
        { source_entity_id: 'entity-1', target_entity_id: 'entity-3' },
        { source_entity_id: 'entity-2', target_entity_id: 'entity-3' },
        { source_entity_id: 'entity-3', target_entity_id: 'entity-1' }
      ];

      const degrees = analyticsService['calculateEntityDegrees'](relations);

      expect(degrees['entity-1']).toBe(3); // Connected to entity-2, entity-3, and receives from entity-3
      expect(degrees['entity-2']).toBe(2); // Connected to entity-1 and entity-3
      expect(degrees['entity-3']).toBe(3); // Connected to entity-1, entity-2, and connects to entity-1
    });

    it('should generate proper cache keys', async () => {
      const filter1: AnalyticsFilter = {
        scope: { project: 'test' }
      };

      const filter2: AnalyticsFilter = {
        scope: { project: 'test' },
        dateRange: {
          startDate: new Date('2024-01-01')
        }
      };

      const filter3: AnalyticsFilter = {
        scope: { project: 'test' },
        dateRange: {
          startDate: new Date('2024-01-01')
        }
      };

      // Different filters should generate different cache keys
      await analyticsService.getKnowledgeBaseMetrics(filter1);
      await analyticsService.getKnowledgeBaseMetrics(filter2);
      await analyticsService.getKnowledgeBaseMetrics(filter3);

      const stats = analyticsService.getCacheStats();
      expect(stats.size).toBe(2); // filter2 and filter3 should be the same, filter1 different
    });
  });

  // 9. Error Handling and Edge Cases Tests
  describe('Error Handling and Edge Cases', () => {
    it('should handle database connection errors', async () => {
      // Mock database connection failure
      mockQdrantClient.knowledgeEntity.count.mockRejectedValue(new Error('Connection timeout'));

      await expect(analyticsService.getKnowledgeBaseMetrics()).rejects.toThrow('Failed to retrieve knowledge metrics');
    });

    it('should handle malformed filter objects', async () => {
      const malformedFilter = {
        scope: {
          project: null,
          org: undefined,
          branch: ''
        },
        dateRange: {
          startDate: 'invalid-date',
          endDate: new Date('invalid-date')
        },
        types: 'not-an-array',
        tags: { '': 'empty-key' }
      } as any;

      // Should handle gracefully or throw appropriate error
      try {
        await analyticsService.getKnowledgeBaseMetrics(malformedFilter);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }
    });

    it('should handle empty knowledge base', async () => {
      // Mock empty knowledge base
      Object.values(mockQdrantClient).forEach((model: any) => {
        if (model.count) model.count.mockResolvedValue(0);
        if (model.findMany) model.findMany.mockResolvedValue([]);
      });

      const analytics = await analyticsService.getKnowledgeBaseMetrics();

      expect(analytics.totalEntities).toBe(0);
      expect(analytics.totalRelations).toBe(0);
      expect(analytics.totalObservations).toBe(0);
      expect(Object.keys(analytics.knowledgeTypeDistribution)).toHaveLength(0);
    });

    it('should handle very large knowledge bases', async () => {
      // Mock very large counts
      Object.values(mockQdrantClient).forEach((model: any) => {
        if (model.count) model.count.mockResolvedValue(1000000);
      });

      const analytics = await analyticsService.getKnowledgeBaseMetrics();

      expect(analytics.totalEntities).toBe(1000000);
      expect(analytics).toBeDefined();
    });

    it('should handle concurrent analytics requests', async () => {
      const concurrentRequests = Array.from({ length: 10 }, (_, i) =>
        analyticsService.getKnowledgeBaseMetrics({
          scope: { project: `concurrent-test-${i}` }
        })
      );

      const results = await Promise.all(concurrentRequests);

      expect(results).toHaveLength(10);
      results.forEach(result => {
        expect(result).toBeDefined();
        expect(result.totalEntities).toBeGreaterThanOrEqual(0);
      });
    });

    it('should handle memory pressure scenarios', async () => {
      // Simulate memory pressure by creating many analytics service instances
      const services = Array.from({ length: 100 }, () => new AnalyticsService());

      // All services should be functional
      const promises = services.map(service => service.getKnowledgeBaseMetrics());
      const results = await Promise.all(promises);

      expect(results).toHaveLength(100);
      results.forEach(result => {
        expect(result).toBeDefined();
      });
    });

    it('should handle invalid report queries', async () => {
      const invalidQueries = [
        { type: 'invalid-type' as any },
        { type: 'knowledge', timeRange: { startDate: 'invalid' } as any },
        { type: 'performance', filters: { invalidFilter: 'value' } as any }
      ];

      for (const query of invalidQueries) {
        try {
          await analyticsService.generateReport(query as any);
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should handle analytics service initialization failures', () => {
      expect(() => new AnalyticsService()).not.toThrow();
      expect(() => new AnalyticsService({})).not.toThrow();
      expect(() => new AnalyticsService({ enableCaching: false })).not.toThrow();
    });

    it('should handle edge case time aggregations', async () => {
      const edgeCases = [
        {
          interval: 'day' as const,
          startDate: new Date('2024-01-01'),
          endDate: new Date('2024-01-01') // Same day
        },
        {
          interval: 'hour' as const,
          startDate: new Date('2024-01-01T00:00:00'),
          endDate: new Date('2024-01-01T00:59:59') // Less than one hour
        },
        {
          interval: 'month' as const,
          startDate: new Date('2024-01-31'),
          endDate: new Date('2024-02-01') // Cross month boundary
        }
      ];

      for (const aggregation of edgeCases) {
        const trends = await analyticsService.getGrowthTrends(aggregation);
        expect(trends).toBeDefined();
        expect(Array.isArray(trends)).toBe(true);
      }
    });

    it('should handle null and undefined values gracefully', async () => {
      const nullFilter: AnalyticsFilter = {
        scope: { project: null as any },
        dateRange: { startDate: null as any, endDate: undefined as any },
        types: null as any,
        tags: null as any
      };

      try {
        const analytics = await analyticsService.getKnowledgeBaseMetrics(nullFilter);
        expect(analytics).toBeDefined();
      } catch (error) {
        // Should handle gracefully
        expect(error).toBeInstanceOf(Error);
      }
    });
  });

  // 10. Integration Tests
  describe('Integration Tests', () => {
    it('should integrate all analytics components', async () => {
      // Enable all features
      analyticsService.updateConfig({
        enableCaching: true,
        enablePredictiveAnalytics: true,
        enableRealTimeAnalytics: true
      });

      const filter: AnalyticsFilter = {
        scope: { project: 'integration-test' },
        dateRange: {
          startDate: new Date('2024-01-01'),
          endDate: new Date('2024-01-31')
        }
      };

      // Get all types of analytics
      const knowledgeAnalytics = await analyticsService.getKnowledgeBaseMetrics(filter);
      const relationshipAnalytics = await analyticsService.getRelationshipAnalytics(filter);
      const performanceAnalytics = await analyticsService.getPerformanceAnalytics(filter);
      const userBehaviorAnalytics = await analyticsService.getUserBehaviorAnalytics(filter);
      const predictiveAnalytics = await analyticsService.getPredictiveAnalytics(filter);

      // All analytics should be consistent
      expect(knowledgeAnalytics).toBeDefined();
      expect(relationshipAnalytics).toBeDefined();
      expect(performanceAnalytics).toBeDefined();
      expect(userBehaviorAnalytics).toBeDefined();
      expect(predictiveAnalytics).toBeDefined();

      // Generate comprehensive report
      const reportQuery: AnalyticsQuery = {
        type: 'knowledge',
        title: 'Integration Test Report',
        timeRange: filter.dateRange,
        filters: filter
      };

      const report = await analyticsService.generateReport(reportQuery);
      expect(report).toBeDefined();
      expect(report.visualizations.length).toBeGreaterThan(0);

      // Export report
      const exportBuffer = await analyticsService.exportReport(report.id, 'json');
      expect(exportBuffer).toBeInstanceOf(Buffer);
      expect(exportBuffer.length).toBeGreaterThan(0);
    });

    it('should handle real-world analytics workflow', async () => {
      // Step 1: Analyze current state
      const currentState = await analyticsService.getKnowledgeBaseMetrics();
      expect(currentState).toBeDefined();

      // Step 2: Analyze performance
      const performance = await analyticsService.getPerformanceAnalytics();
      expect(performance).toBeDefined();

      // Step 3: Check for optimization opportunities
      if (performance.queryPerformance.averageResponseTime > 500) {
        expect(performance.optimizationSuggestions.length).toBeGreaterThan(0);
      }

      // Step 4: Generate insights report
      const insightsReport = await analyticsService.generateReport({
        type: 'performance',
        title: 'Performance Insights Report'
      });

      expect(insightsReport.summary.length).toBeGreaterThan(0);
      expect(insightsReport.visualizations.length).toBeGreaterThan(0);

      // Step 5: Export for external analysis
      const csvExport = await analyticsService.exportReport(insightsReport.id, 'csv');
      expect(csvExport.toString().split('\n').length).toBeGreaterThan(1);
    });
  });
});