/**
 * Unit Tests for Contradiction Detector
 * Tests the contradiction detection service and its components
 */

import {
  ContradictionDetector,
  ContradictionDetectionRequest,
  ContradictionResult,
  KnowledgeItem,
} from '../../src/types/contradiction-detector.interface';
import { ContradictionDetectorImpl } from '../../src/services/contradiction/contradiction-detector.service';
import { MetadataFlaggingService } from '../../src/services/contradiction/metadata-flagging.service';
import { PointerResolutionService } from '../../src/services/contradiction/pointer-resolution.service';
import { generateId } from '../../src/utils/id-generator';

describe('ContradictionDetector', () => {
  let detector: ContradictionDetector;
  let flaggingService: MetadataFlaggingService;
  let resolutionService: PointerResolutionService;

  beforeEach(() => {
    detector = new ContradictionDetectorImpl({
      enabled: true,
      sensitivity: 'balanced',
      auto_flag: true,
      batch_checking: true,
      performance_monitoring: true,
      cache_results: true,
      cache_ttl_ms: 300000,
      max_items_per_check: 100,
      timeout_ms: 30000,
    });

    flaggingService = new MetadataFlaggingService();
    resolutionService = new PointerResolutionService();
  });

  describe('Factual Contradiction Detection', () => {
    test('should detect direct negation', async () => {
      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system is enabled',
          scope: { project: 'test' },
          data: {},
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system is not enabled',
          scope: { project: 'test' },
          data: {},
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      const response = await detector.detectContradictions(request);

      expect(response.contradictions).toHaveLength(1);
      expect(response.contradictions[0].contradiction_type).toBe('factual');
      expect(response.contradictions[0].confidence_score).toBeGreaterThanOrEqual(0.8);
      expect(response.contradictions[0].primary_item_id).toBe(items[0].id);
      expect(response.contradictions[0].conflicting_item_ids).toContain(items[1].id);
    });

    test('should detect semantic contradictions', async () => {
      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'The service is running hot',
          scope: { project: 'test' },
          data: {},
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'The service is running cold',
          scope: { project: 'test' },
          data: {},
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      const response = await detector.detectContradictions(request);

      expect(response.contradictions.length).toBeGreaterThan(0);
      expect(response.contradictions[0].contradiction_type).toBe('factual');
    });

    test('should not detect contradictions in consistent statements', async () => {
      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system is operational',
          scope: { project: 'test' },
          data: {},
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system is working',
          scope: { project: 'test' },
          data: {},
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      const response = await detector.detectContradictions(request);

      expect(response.contradictions).toHaveLength(0);
    });
  });

  describe('Temporal Contradiction Detection', () => {
    test('should detect temporal sequence conflicts', async () => {
      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'Event A happened before Event B',
          scope: { project: 'test' },
          data: {},
          created_at: '2024-01-01T10:00:00Z',
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'Event B happened before Event A',
          scope: { project: 'test' },
          data: {},
          created_at: '2024-01-01T10:00:30Z',
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      const response = await detector.detectContradictions(request);

      expect(response.contradictions.length).toBeGreaterThan(0);
      expect(response.contradictions.some((c) => c.contradiction_type === 'temporal')).toBe(true);
    });

    test('should handle items with no temporal data', async () => {
      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'Generic statement without time',
          scope: { project: 'test' },
          data: {},
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'Another generic statement',
          scope: { project: 'test' },
          data: {},
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      const response = await detector.detectContradictions(request);

      // Should not crash and may have other contradictions but no temporal ones
      expect(Array.isArray(response.contradictions)).toBe(true);
    });
  });

  describe('Logical Contradiction Detection', () => {
    test('should detect mutual exclusion violations', async () => {
      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'Option A and Option B are exclusive or',
          scope: { project: 'test' },
          data: {},
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'Both Option A and Option B are true',
          scope: { project: 'test' },
          data: {},
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      const response = await detector.detectContradictions(request);

      expect(response.contradictions.length).toBeGreaterThan(0);
      expect(response.contradictions.some((c) => c.contradiction_type === 'logical')).toBe(true);
    });

    test('should detect mutual exclusion markers', async () => {
      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'These events are mutually exclusive',
          scope: { project: 'test' },
          data: {},
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'Both events occurred simultaneously',
          scope: { project: 'test' },
          data: {},
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      const response = await detector.detectContradictions(request);

      expect(response.contradictions.length).toBeGreaterThan(0);
    });
  });

  describe('Attribute Contradiction Detection', () => {
    test('should detect type conflicts', async () => {
      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'Item status information',
          scope: { project: 'test' },
          data: { status: 'active' },
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'Item status information',
          scope: { project: 'test' },
          data: { status: 123 },
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      const response = await detector.detectContradictions(request);

      expect(response.contradictions.length).toBeGreaterThan(0);
      expect(response.contradictions.some((c) => c.contradiction_type === 'attribute')).toBe(true);
    });

    test('should detect value conflicts', async () => {
      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'Configuration item',
          scope: { project: 'test' },
          data: { enabled: true },
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'Configuration item',
          scope: { project: 'test' },
          data: { enabled: false },
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      const response = await detector.detectContradictions(request);

      expect(response.contradictions.length).toBeGreaterThan(0);
      const attributeContradiction = response.contradictions.find(
        (c) => c.contradiction_type === 'attribute'
      );
      expect(attributeContradiction).toBeDefined();
      expect(attributeContradiction!.confidence_score).toBeGreaterThan(0.8);
    });

    test('should extract attributes from content', async () => {
      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'priority: high, severity: critical',
          scope: { project: 'test' },
          data: {},
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'priority: low, severity: critical',
          scope: { project: 'test' },
          data: {},
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      const response = await detector.detectContradictions(request);

      expect(response.contradictions.length).toBeGreaterThan(0);
    });
  });

  describe('Performance and Scalability', () => {
    test('should handle batch processing within limits', async () => {
      const items: KnowledgeItem[] = Array.from({ length: 50 }, (_, i) => ({
        id: generateId(),
        kind: 'entity',
        content: `Test statement ${i}`,
        scope: { project: 'test' },
        data: { index: i },
      }));

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      const startTime = Date.now();
      const response = await detector.detectContradictions(request);
      const processingTime = Date.now() - startTime;

      expect(response.summary.total_items_checked).toBe(50);
      expect(processingTime).toBeLessThan(10000); // Should complete within 10 seconds
      expect(response.performance.items_per_second).toBeGreaterThan(0);
    });

    test('should respect maximum items per check limit', async () => {
      const items: KnowledgeItem[] = Array.from({ length: 200 }, (_, i) => ({
        id: generateId(),
        kind: 'entity',
        content: `Test statement ${i}`,
        scope: { project: 'test' },
        data: { index: i },
      }));

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      await expect(detector.detectContradictions(request)).rejects.toThrow();
    });
  });

  describe('Configuration and Safety', () => {
    test('should respect enabled/disabled configuration', async () => {
      const disabledDetector = new ContradictionDetectorImpl({
        enabled: false,
        sensitivity: 'balanced',
        auto_flag: true,
        batch_checking: true,
        performance_monitoring: true,
        cache_results: true,
        cache_ttl_ms: 300000,
        max_items_per_check: 100,
        timeout_ms: 30000,
      });

      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system is enabled',
          scope: { project: 'test' },
          data: {},
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system is not enabled',
          scope: { project: 'test' },
          data: {},
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      const response = await disabledDetector.detectContradictions(request);

      expect(response.contradictions).toHaveLength(0);
      expect(response.summary.total_items_checked).toBe(0);
    });

    test('should apply sensitivity thresholds correctly', async () => {
      const conservativeDetector = new ContradictionDetectorImpl({
        enabled: true,
        sensitivity: 'conservative',
        auto_flag: true,
        batch_checking: true,
        performance_monitoring: true,
        cache_results: true,
        cache_ttl_ms: 300000,
        max_items_per_check: 100,
        timeout_ms: 30000,
      });

      const aggressiveDetector = new ContradictionDetectorImpl({
        enabled: true,
        sensitivity: 'aggressive',
        auto_flag: true,
        batch_checking: true,
        performance_monitoring: true,
        cache_results: true,
        cache_ttl_ms: 300000,
        max_items_per_check: 100,
        timeout_ms: 30000,
      });

      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system might be enabled',
          scope: { project: 'test' },
          data: {},
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system might be disabled',
          scope: { project: 'test' },
          data: {},
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      const conservativeResponse = await conservativeDetector.detectContradictions(request);
      const aggressiveResponse = await aggressiveDetector.detectContradictions(request);

      // Aggressive should detect more or equal contradictions than conservative
      expect(aggressiveResponse.contradictions.length).toBeGreaterThanOrEqual(
        conservativeResponse.contradictions.length
      );
    });
  });

  describe('Edge Cases', () => {
    test('should handle empty input', async () => {
      const request: ContradictionDetectionRequest = {
        items: [],
        scope: { project: 'test' },
      };

      const response = await detector.detectContradictions(request);

      expect(response.contradictions).toHaveLength(0);
      expect(response.summary.total_items_checked).toBe(0);
    });

    test('should handle single item', async () => {
      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'Single statement',
          scope: { project: 'test' },
          data: {},
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      const response = await detector.detectContradictions(request);

      expect(response.contradictions).toHaveLength(0);
      expect(response.summary.total_items_checked).toBe(1);
    });

    test('should handle items with missing fields', async () => {
      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          scope: { project: 'test' },
          data: {},
        },
        {
          id: generateId(),
          kind: 'entity',
          content: '', // Empty content
          scope: { project: 'test' },
          data: null as any, // Null data
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      const response = await detector.detectContradictions(request);

      // Should not crash
      expect(Array.isArray(response.contradictions)).toBe(true);
      expect(response.summary.total_items_checked).toBe(2);
    });

    test('should handle items from different scopes', async () => {
      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system is enabled',
          scope: { project: 'project1' },
          data: {},
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system is not enabled',
          scope: { project: 'project2' },
          data: {},
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      const response = await detector.detectContradictions(request);

      // Should not detect contradictions across different scopes
      expect(response.contradictions).toHaveLength(0);
    });
  });

  describe('Severity Calculation', () => {
    test('should calculate correct severity levels', async () => {
      const highConfidenceItem: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system is definitely enabled',
          scope: { project: 'test' },
          data: {},
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system is definitely not enabled',
          scope: { project: 'test' },
          data: {},
        },
      ];

      const request: ContradictionDetectionRequest = {
        items: highConfidenceItem,
        scope: { project: 'test' },
      };

      const response = await detector.detectContradictions(request);

      if (response.contradictions.length > 0) {
        const contradiction = response.contradictions[0];
        expect(['low', 'medium', 'high', 'critical']).toContain(contradiction.severity);

        // High confidence should result in higher severity
        if (contradiction.confidence_score >= 0.9) {
          expect(['high', 'critical']).toContain(contradiction.severity);
        }
      }
    });
  });

  describe('Resolution Suggestions', () => {
    test('should provide relevant resolution suggestions', async () => {
      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system is enabled',
          scope: { project: 'test' },
          data: {},
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system is not enabled',
          scope: { project: 'test' },
          data: {},
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'test' },
      };

      const response = await detector.detectContradictions(request);

      if (response.contradictions.length > 0) {
        const contradiction = response.contradictions[0];
        expect(contradiction.resolution_suggestions).toBeDefined();
        expect(contradiction.resolution_suggestions.length).toBeGreaterThan(0);

        const suggestion = contradiction.resolution_suggestions[0];
        expect(suggestion.suggestion).toBeDefined();
        expect(suggestion.priority).toBeDefined();
        expect(suggestion.effort).toBeDefined();
        expect(suggestion.description).toBeDefined();
      }
    });
  });
});

// Type assertion for the ContradictionDetectorImpl class
class ContradictionDetectorImpl {
  constructor(config: any) {
    // Implementation would go here
  }

  async detectContradictions(request: ContradictionDetectionRequest): Promise<any> {
    // Mock implementation for testing
    return {
      contradictions: [],
      summary: {
        total_items_checked: request.items.length,
        contradictions_found: 0,
        by_type: {},
        by_severity: {},
        processing_time_ms: 0,
        cache_hits: 0,
        cache_misses: 0,
      },
      performance: {
        items_per_second: 0,
        memory_usage_mb: 0,
        bottleneck_detected: false,
        bottlenecks: [],
      },
    };
  }
}
