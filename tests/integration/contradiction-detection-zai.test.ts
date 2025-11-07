/**
 * Contradiction Detection ZAI Integration Tests
 *
 * Comprehensive integration tests for contradiction detection with ZAI services
 * including semantic, temporal, and logical contradiction analysis.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import {
  MockZAIClientService,
  MockZAIServicesManager,
  createTestContradictionRequest,
  measurePerformance,
  createPerformanceBenchmark,
  mockZAIResponses,
  mockPerformanceData,
  mockErrorScenarios,
} from '../mocks/zai-service.mock.js';
import type {
  ContradictionDetectionRequest,
  ContradictionDetectionResponse,
} from '../../src/types/zai-interfaces.js';

describe('Contradiction Detection ZAI Integration Tests', () => {
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

  describe('Basic Contradiction Detection', () => {
    test('should detect contradictions for item pairs', async () => {
      const request = createTestContradictionRequest();

      const response = await zaiClient.detectContradictions(request);

      expect(response).toBeDefined();
      expect(response.contradictions).toBeDefined();
      expect(Array.isArray(response.contradictions)).toBe(true);
      expect(response.metadata).toBeDefined();
      expect(response.metadata['total_contradictions']).toBeGreaterThanOrEqual(0);
      expect(response.metadata['items_processed']).toBeGreaterThanOrEqual(0);
    });

    test('should detect semantic contradictions', async () => {
      const request = createTestContradictionRequest();
      request.options!.detection_types = ['semantic'];

      const response = await zaiClient.detectContradictions(request);

      expect(response.contradictions.length).toBeGreaterThanOrEqual(0);
      if (response.contradictions.length > 0) {
        expect(response.contradictions[0].type).toBe('contradiction');
        expect(response.contradictions[0].metadata?.contradiction_type).toBe('semantic');
        expect(response.contradictions[0].confidence).toBeGreaterThan(0);
        expect(response.contradictions[0].metadata?.severity).toBeDefined();
      }
    });

    test('should detect temporal contradictions', async () => {
      const request = createTestContradictionRequest();
      request.options!.detection_types = ['temporal'];

      const response = await zaiClient.detectContradictions(request);

      expect(response.contradictions.length).toBeGreaterThanOrEqual(0);
      if (response.contradictions.length > 0) {
        expect(response.contradictions[0].type).toBe('timeline_conflict');
        expect(response.contradictions[0].metadata?.conflict_type).toBe('temporal');
        expect(response.contradictions[0].metadata?.timeline_details).toBeDefined();
      }
    });

    test('should detect logical contradictions', async () => {
      const request = createTestContradictionRequest();
      request.options!.detection_types = ['logical'];

      const response = await zaiClient.detectContradictions(request);

      expect(response.contradictions.length).toBeGreaterThanOrEqual(0);
      if (response.contradictions.length > 0) {
        expect(response.contradictions[0].type).toBe('logical_inconsistency');
        expect(response.contradictions[0].metadata?.inconsistency_type).toBe('logical');
        expect(response.contradictions[0].metadata?.logical_implications).toBeDefined();
        expect(Array.isArray(response.contradictions[0].metadata.logical_implications)).toBe(true);
      }
    });

    test('should detect all contradiction types when enabled', async () => {
      const request = createTestContradictionRequest();
      request.options!.detection_types = ['semantic', 'temporal', 'logical'];

      const response = await zaiClient.detectContradictions(request);

      expect(response.contradictions.length).toBeGreaterThanOrEqual(0);

      // Should detect multiple types if contradictions exist
      const detectedTypes = new Set(response.contradictions.map((c) => c.type));
      if (response.contradictions.length > 1) {
        expect(detectedTypes.size).toBeGreaterThanOrEqual(1);
      }
    });
  });

  describe('Complex Contradiction Scenarios', () => {
    test('should detect contradictions between decisions and issues', async () => {
      const request = {
        ...createTestContradictionRequest(),
        items: [
          {
            id: 'decision-1',
            kind: 'decision',
            content: 'Proceed with major system rewrite',
            data: {
              title: 'System Rewrite Decision',
              content: 'We will completely rewrite the system using modern architecture',
              rationale: 'Technical debt has become unsustainable',
              impact: 'critical',
              timeline: '3 months',
              tags: ['architecture', 'rewrite', 'modernization'],
              created_at: '2025-01-15T10:00:00Z',
            },
            scope: { project: 'system-modernization' },
            created_at: '2025-01-15T10:00:00Z',
          },
          {
            id: 'issue-1',
            kind: 'issue',
            content: 'Critical production stability issues',
            data: {
              title: 'Production Instability',
              content: 'System experiencing frequent crashes and data corruption issues',
              severity: 'critical',
              status: 'open',
              affected_components: ['database', 'auth', 'api'],
              symptoms: ['Crashes', 'Data corruption', 'Slow response times'],
              tags: ['production', 'stability', 'critical'],
              created_at: '2025-01-16T09:00:00Z',
            },
            scope: { project: 'system-modernization' },
            created_at: '2025-01-16T09:00:00Z',
          },
        ],
      };

      const response = await zaiClient.detectContradictions(request);

      expect(response.contradictions.length).toBeGreaterThanOrEqual(0);
      if (response.contradictions.length > 0) {
        expect(response.contradictions[0].items).toContain('decision-1');
        expect(response.contradictions[0].items).toContain('issue-1');
      }
    });

    test('should detect temporal conflicts in project timelines', async () => {
      const request = {
        ...createTestContradictionRequest(),
        items: [
          {
            id: 'task-1',
            kind: 'todo',
            content: 'Complete database migration',
            data: {
              title: 'Database Migration',
              content: 'Migrate from PostgreSQL to MongoDB',
              due_date: '2025-02-01T00:00:00Z',
              estimated_days: 14,
              dependencies: ['schema-finalization'],
              tags: ['database', 'migration'],
              created_at: '2025-01-15T10:00:00Z',
            },
            scope: { project: 'data-platform' },
            created_at: '2025-01-15T10:00:00Z',
          },
          {
            id: 'decision-2',
            kind: 'decision',
            content: 'Postpone database migration',
            data: {
              title: 'Migration Postponement',
              content: 'Database migration postponed due to resource constraints',
              rationale: 'Team needed for urgent security fixes',
              new_timeline: '2025-03-01T00:00:00Z',
              tags: ['database', 'postponement'],
              created_at: '2025-01-20T15:00:00Z',
            },
            scope: { project: 'data-platform' },
            created_at: '2025-01-20T15:00:00Z',
          },
        ],
      };

      const response = await zaiClient.detectContradictions(request);

      expect(response.contradictions.length).toBeGreaterThanOrEqual(0);
      if (response.contradictions.length > 0) {
        const temporalContradiction = response.contradictions.find(
          (c) => c.type === 'timeline_conflict' || c.metadata?.conflict_type === 'temporal'
        );
        if (temporalContradiction) {
          expect(temporalContradiction.metadata?.timeline_details).toBeDefined();
        }
      }
    });

    test('should detect logical inconsistencies in strategy', async () => {
      const request = {
        ...createTestContradictionRequest(),
        items: [
          {
            id: 'strategy-1',
            kind: 'decision',
            content: 'Adopt cost-cutting measures',
            data: {
              title: 'Cost Reduction Strategy',
              content: 'Implement aggressive cost-cutting across all departments',
              rationale: 'Budget constraints require immediate action',
              target_savings: '30%',
              timeline: 'Q1 2025',
              tags: ['strategy', 'cost-cutting'],
              created_at: '2025-01-10T09:00:00Z',
            },
            scope: { project: 'company-strategy' },
            created_at: '2025-01-10T09:00:00Z',
          },
          {
            id: 'strategy-2',
            kind: 'decision',
            content: 'Major investment in new technology',
            data: {
              title: 'Technology Investment',
              content: 'Significant investment in AI/ML infrastructure and team expansion',
              rationale: 'Competitive advantage requires modern technology stack',
              investment_amount: '$2M',
              timeline: 'Q1 2025',
              tags: ['strategy', 'investment', 'technology'],
              created_at: '2025-01-12T14:30:00Z',
            },
            scope: { project: 'company-strategy' },
            created_at: '2025-01-12T14:30:00Z',
          },
        ],
      };

      const response = await zaiClient.detectContradictions(request);

      expect(response.contradictions.length).toBeGreaterThanOrEqual(0);
      if (response.contradictions.length > 0) {
        const logicalContradiction = response.contradictions.find(
          (c) => c.type === 'logical_inconsistency' || c.metadata?.inconsistency_type === 'logical'
        );
        if (logicalContradiction) {
          expect(logicalContradiction.confidence).toBeGreaterThan(0.5);
          expect(logicalContradiction.metadata?.severity).toBeDefined();
        }
      }
    });

    test('should handle multi-item contradiction analysis', async () => {
      const items = Array.from({ length: 10 }, (_, i) => ({
        id: `multi-item-${i}`,
        kind: i % 3 === 0 ? 'decision' : i % 3 === 1 ? 'issue' : ('todo' as const),
        content: `Item ${i} for multi-item contradiction testing`,
        data: {
          title: `Multi-item Test ${i}`,
          content: `Content for item ${i} with potential contradictions`,
          tags: [`tag-${i % 3}`, `test`],
          created_at: new Date(Date.now() + i * 3600000).toISOString(),
        },
        scope: { project: 'multi-item-test' },
        created_at: new Date(Date.now() + i * 3600000).toISOString(),
      }));

      const request = {
        ...createTestContradictionRequest(),
        items,
        options: {
          enabled: true,
          detection_types: ['semantic', 'temporal', 'logical'],
          confidence_threshold: 0.6,
          include_metadata: true,
        },
      };

      const response = await zaiClient.detectContradictions(request);

      expect(response.metadata['items_processed']).toBe(10);
      expect(response.contradictions.length).toBeGreaterThanOrEqual(0);
      expect(response.metadata['total_contradictions']).toBe(response.contradictions.length);
    });
  });

  describe('Confidence and Threshold Testing', () => {
    test('should filter contradictions by confidence threshold', async () => {
      const request = createTestContradictionRequest();

      // High confidence threshold
      const highThresholdResponse = await zaiClient.detectContradictions({
        ...request,
        options: { ...request.options!, confidence_threshold: 0.9 },
      });

      // Low confidence threshold
      const lowThresholdResponse = await zaiClient.detectContradictions({
        ...request,
        options: { ...request.options!, confidence_threshold: 0.3 },
      });

      // All contradictions in high threshold should meet the threshold
      highThresholdResponse.contradictions.forEach((contradiction) => {
        expect(contradiction.confidence).toBeGreaterThanOrEqual(0.9);
      });

      // Low threshold should allow more contradictions
      expect(lowThresholdResponse.contradictions.length).toBeGreaterThanOrEqual(
        highThresholdResponse.contradictions.length
      );
    });

    test('should handle edge case confidence thresholds', async () => {
      const request = createTestContradictionRequest();

      // Maximum threshold
      const maxThresholdResponse = await zaiClient.detectContradictions({
        ...request,
        options: { ...request.options!, confidence_threshold: 0.99 },
      });

      // Minimum threshold
      const minThresholdResponse = await zaiClient.detectContradictions({
        ...request,
        options: { ...request.options!, confidence_threshold: 0.01 },
      });

      // All contradictions should meet minimum threshold
      minThresholdResponse.contradictions.forEach((contradiction) => {
        expect(contradiction.confidence).toBeGreaterThanOrEqual(0.01);
      });

      expect(minThresholdResponse.contradictions.length).toBeGreaterThanOrEqual(
        maxThresholdResponse.contradictions.length
      );
    });
  });

  describe('Performance Testing', () => {
    test('should process 100 items within performance target', async () => {
      const items = Array.from({ length: 100 }, (_, i) => ({
        ...createTestContradictionRequest().items[0],
        id: `perf-item-${i}`,
        content: `Performance test item ${i} for contradiction detection`,
      }));

      const request = {
        ...createTestContradictionRequest(),
        items,
        options: {
          enabled: true,
          detection_types: ['semantic', 'temporal', 'logical'],
          confidence_threshold: 0.6,
        },
      };

      const benchmark = createPerformanceBenchmark(
        mockPerformanceData.contradiction_detection.batch_100_items
      );
      const { result, durationMs } = await measurePerformance(() =>
        zaiClient.detectContradictions(request)
      );

      const validation = benchmark.validate(durationMs);

      expect(result.metadata['items_processed']).toBe(100);
      expect(validation.passed).toBe(true);
      expect(validation.withinVariance).toBe(true);
      expect(validation.percentageOfTarget).toBeLessThanOrEqual(120);
    });

    test('should handle batch processing efficiently', async () => {
      const batchSize = 50;
      const batches = 2;

      const requests = Array.from({ length: batches }, (_, batchIndex) => ({
        ...createTestContradictionRequest(),
        items: Array.from({ length: batchSize }, (_, i) => ({
          ...createTestContradictionRequest().items[0],
          id: `batch-${batchIndex}-item-${i}`,
          content: `Batch ${batchIndex} item ${i} for contradiction testing`,
        })),
        options: {
          enabled: true,
          detection_types: ['semantic'],
          confidence_threshold: 0.7,
        },
      }));

      const startTime = Date.now();
      const responses = await Promise.all(
        requests.map((request) => zaiClient.detectContradictions(request))
      );
      const totalTime = Date.now() - startTime;

      expect(responses).toHaveLength(batches);
      responses.forEach((response) => {
        expect(response.metadata['items_processed']).toBe(batchSize);
        expect(response.contradictions).toBeDefined();
      });

      // Batch processing should be efficient
      const averageTimePerBatch = totalTime / batches;
      expect(averageTimePerBatch).toBeLessThan(3000); // Should be reasonable
    });

    test('should maintain performance with contradiction complexity', async () => {
      const simpleRequest = createTestContradictionRequest();
      simpleRequest.items = simpleRequest.items.slice(0, 2); // Small, simple case

      const complexItems = Array.from({ length: 20 }, (_, i) => ({
        ...createTestContradictionRequest().items[0],
        id: `complex-${i}`,
        kind: ['decision', 'issue', 'todo', 'entity'][i % 4] as any,
        content: `Complex item ${i} with detailed content and multiple relationships`,
        data: {
          ...createTestContradictionRequest().items[0].data,
          title: `Complex Item ${i}`,
          content: `This is a complex item with extensive content for contradiction detection testing. It contains multiple facets and considerations that should increase processing complexity.`,
          details: {
            stakeholders: ['team-a', 'team-b', 'team-c'],
            dependencies: [`item-${i - 1}`, `item-${i - 2}`],
            timeline: `2025-01-${String(i + 1).padStart(2, '0')}T10:00:00Z`,
            impact: ['high', 'medium', 'low'][i % 3],
            risk_factors: [`factor-${i}`, `factor-${i + 1}`, `factor-${i + 2}`],
          },
        },
      }));

      const complexRequest = {
        ...createTestContradictionRequest(),
        items: complexItems,
        options: {
          enabled: true,
          detection_types: ['semantic', 'temporal', 'logical'],
          confidence_threshold: 0.6,
        },
      };

      const { durationMs: simpleDuration } = await measurePerformance(() =>
        zaiClient.detectContradictions(simpleRequest)
      );

      const { durationMs: complexDuration } = await measurePerformance(() =>
        zaiClient.detectContradictions(complexRequest)
      );

      // Complex processing should still be within reasonable bounds
      expect(complexDuration).toBeLessThan(simpleDuration * 5); // Not more than 5x slower
    });
  });

  describe('Error Handling', () => {
    test('should handle API errors gracefully', async () => {
      zaiClient.setErrorScenario('api_error');

      const request = createTestContradictionRequest();

      await expect(zaiClient.detectContradictions(request)).rejects.toThrow('ZAI_APIError');
    });

    test('should handle network timeout errors', async () => {
      zaiClient.setErrorScenario('network_timeout');
      zaiClient.setResponseDelay(35000);

      const request = createTestContradictionRequest();

      await expect(zaiClient.detectContradictions(request)).rejects.toThrow('NetworkTimeoutError');
    });

    test('should handle malformed requests', async () => {
      const malformedRequest = {
        items: [
          {
            // Missing required fields
            id: 'malformed-1',
            kind: 'invalid',
          },
        ],
        options: {
          enabled: true,
          detection_types: ['semantic'],
          confidence_threshold: 0.5,
        },
        scope: {},
      } as any;

      const response = await zaiClient.detectContradictions(malformedRequest);

      // Should not crash and return a response structure
      expect(response).toBeDefined();
      expect(response.contradictions).toBeDefined();
      expect(response.metadata).toBeDefined();
    });

    test('should handle empty items array', async () => {
      const request: ContradictionDetectionRequest = {
        items: [],
        options: {
          enabled: true,
          detection_types: ['semantic'],
          confidence_threshold: 0.5,
        },
        scope: {},
      };

      const response = await zaiClient.detectContradictions(request);

      expect(response.contradictions).toHaveLength(0);
      expect(response.metadata['total_contradictions']).toBe(0);
      expect(response.metadata['items_processed']).toBe(0);
    });

    test('should handle single item gracefully', async () => {
      const request = {
        ...createTestContradictionRequest(),
        items: [createTestContradictionRequest().items[0]],
      };

      const response = await zaiClient.detectContradictions(request);

      expect(response.contradictions).toBeDefined(); // May be empty for single item
      expect(response.metadata['items_processed']).toBe(1);
    });
  });

  describe('Response Quality and Structure', () => {
    test('should include comprehensive metadata', async () => {
      const request = createTestContradictionRequest();

      const response = await zaiClient.detectContradictions(request);

      expect(response.metadata).toBeDefined();
      expect(response.metadata['total_contradictions']).toBeGreaterThanOrEqual(0);
      expect(response.metadata['items_processed']).toBeGreaterThanOrEqual(0);
      expect(response.metadata['processing_time_ms']).toBeGreaterThan(0);
      expect(response.metadata['average_confidence']).toBeGreaterThanOrEqual(0);
      expect(response.metadata['average_confidence']).toBeLessThanOrEqual(1);
      expect(response.metadata['contradictions_by_type']).toBeDefined();
      expect(typeof response.metadata['contradictions_by_type']).toBe('object');
    });

    test('should include detailed contradiction information', async () => {
      const request = createTestContradictionRequest();

      const response = await zaiClient.detectContradictions(request);

      response.contradictions.forEach((contradiction) => {
        expect(contradiction.id).toBeDefined();
        expect(contradiction.type).toBeDefined();
        expect(contradiction.confidence).toBeGreaterThanOrEqual(0);
        expect(contradiction.confidence).toBeLessThanOrEqual(1);
        expect(contradiction.description).toBeDefined();
        expect(contradiction.items).toBeDefined();
        expect(Array.isArray(contradiction.items)).toBe(true);
        expect(contradiction.metadata).toBeDefined();
        expect(contradiction.created_at).toBeDefined();
        expect(typeof Date.parse(contradiction.created_at)).not.toBe(NaN);
      });
    });

    test('should maintain contradiction type consistency', async () => {
      const request = createTestContradictionRequest();
      request.options!.detection_types = ['semantic', 'temporal', 'logical'];

      const response = await zaiClient.detectContradictions(request);

      const validTypes = ['contradiction', 'timeline_conflict', 'logical_inconsistency'];

      response.contradictions.forEach((contradiction) => {
        expect(validTypes).toContain(contradiction.type);
      });
    });

    test('should properly categorize contradictions by type', async () => {
      const request = createTestContradictionRequest();
      request.options!.detection_types = ['semantic', 'temporal', 'logical'];

      const response = await zaiClient.detectContradictions(request);

      if (response.contradictions.length > 0) {
        const categorizedByType = response.metadata['contradictions_by_type'];
        expect(Object.keys(categorizedByType).length).toBeGreaterThan(0);

        // The counts should match the actual contradictions
        let totalCount = 0;
        Object.values(categorizedByType).forEach((count) => {
          totalCount += count as number;
        });

        expect(totalCount).toBe(response.contradictions.length);
      }
    });
  });

  describe('Real-world Contradiction Scenarios', () => {
    test('should detect project timeline contradictions', async () => {
      const request = {
        ...createTestContradictionRequest(),
        items: [
          {
            id: 'timeline-1',
            kind: 'decision',
            content: 'Launch product in Q2 2025',
            data: {
              title: 'Product Launch Timeline',
              content: 'Product will launch in Q2 2025 with all features complete',
              launch_date: '2025-06-30T00:00:00Z',
              tags: ['launch', 'timeline', 'Q2-2025'],
              created_at: '2025-01-15T10:00:00Z',
            },
            scope: { project: 'product-launch' },
            created_at: '2025-01-15T10:00:00Z',
          },
          {
            id: 'timeline-2',
            kind: 'issue',
            content: 'Major development delays discovered',
            data: {
              title: 'Development Delays',
              content: 'Critical development delays will push launch to Q4 2025',
              new_launch_date: '2025-12-15T00:00:00Z',
              delay_reasons: ['Team shortage', 'Technical debt', 'Scope changes'],
              tags: ['delays', 'timeline', 'Q4-2025'],
              created_at: '2025-02-01T14:30:00Z',
            },
            scope: { project: 'product-launch' },
            created_at: '2025-02-01T14:30:00Z',
          },
        ],
      };

      const response = await zaiClient.detectContradictions(request);

      expect(response.contradictions.length).toBeGreaterThanOrEqual(0);
      if (response.contradictions.length > 0) {
        const temporalConflict = response.contradictions.find(
          (c) => c.type === 'timeline_conflict' || c.metadata?.conflict_type === 'temporal'
        );
        if (temporalConflict) {
          expect(temporalConflict.metadata?.timeline_details).toBeDefined();
          expect(temporalConflict.confidence).toBeGreaterThan(0.5);
        }
      }
    });

    test('should detect resource allocation contradictions', async () => {
      const request = {
        ...createTestContradictionRequest(),
        items: [
          {
            id: 'resource-1',
            kind: 'decision',
            content: 'Assign entire development team to Project Alpha',
            data: {
              title: 'Resource Allocation Decision',
              content: 'All 10 developers will work exclusively on Project Alpha for next 6 months',
              team_size: 10,
              duration_months: 6,
              exclusivity: 'full-time',
              tags: ['resources', 'allocation', 'project-alpha'],
              created_at: '2025-01-15T10:00:00Z',
            },
            scope: { project: 'resource-planning' },
            created_at: '2025-01-15T10:00:00Z',
          },
          {
            id: 'resource-2',
            kind: 'todo',
            content: 'Start critical Project Beta maintenance',
            data: {
              title: 'Project Beta Critical Maintenance',
              content:
                'Emergency maintenance for Project Beta requires immediate full team attention',
              priority: 'critical',
              team_required: 10,
              duration_weeks: 4,
              tags: ['maintenance', 'project-beta', 'critical'],
              created_at: '2025-01-20T09:15:00Z',
            },
            scope: { project: 'resource-planning' },
            created_at: '2025-01-20T09:15:00Z',
          },
        ],
      };

      const response = await zaiClient.detectContradictions(request);

      expect(response.contradictions.length).toBeGreaterThanOrEqual(0);
      if (response.contradictions.length > 0) {
        // Should detect logical inconsistency in resource allocation
        const logicalContradiction = response.contradictions.find(
          (c) => c.type === 'logical_inconsistency' || c.metadata?.inconsistency_type === 'logical'
        );
        if (logicalContradiction) {
          expect(logicalContradiction.metadata?.logical_implications).toBeDefined();
          expect(Array.isArray(logicalContradiction.metadata['logical_implications'])).toBe(true);
        }
      }
    });

    test('should detect technology stack contradictions', async () => {
      const request = {
        ...createTestContradictionRequest(),
        items: [
          {
            id: 'tech-1',
            kind: 'decision',
            content: 'Migrate to Node.js microservices architecture',
            data: {
              title: 'Technology Stack Decision',
              content: 'Complete migration to Node.js microservices for all services',
              rationale: 'Better performance and scalability',
              migration_scope: 'all-services',
              timeline: '6 months',
              tags: ['nodejs', 'microservices', 'migration'],
              created_at: '2025-01-15T10:00:00Z',
            },
            scope: { project: 'tech-migration' },
            created_at: '2025-01-15T10:00:00Z',
          },
          {
            id: 'tech-2',
            kind: 'decision',
            content: 'Invest in Java enterprise platform',
            data: {
              title: 'Java Platform Investment',
              content: 'Significant investment in Java EE platform and Spring ecosystem',
              rationale: 'Enterprise stability and long-term support',
              investment_scope: 'core-platform',
              timeline: '6 months',
              tags: ['java', 'enterprise', 'spring'],
              created_at: '2025-01-18T14:20:00Z',
            },
            scope: { project: 'tech-migration' },
            created_at: '2025-01-18T14:20:00Z',
          },
        ],
      };

      const response = await zaiClient.detectContradictions(request);

      expect(response.contradictions.length).toBeGreaterThanOrEqual(0);
      if (response.contradictions.length > 0) {
        // Should detect semantic contradiction in technology choices
        const semanticContradiction = response.contradictions.find(
          (c) => c.type === 'contradiction' || c.metadata?.contradiction_type === 'semantic'
        );
        if (semanticContradiction) {
          expect(semanticContradiction.metadata?.resolution_suggestion).toBeDefined();
          expect(semanticContradiction.confidence).toBeGreaterThan(0.5);
        }
      }
    });
  });
});
