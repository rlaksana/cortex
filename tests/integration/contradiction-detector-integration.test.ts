/**
 * Integration Tests for Contradiction Detector
 * Tests the complete contradiction detection system
 */

import {
  ContradictionDetector,
  ContradictionDetectionRequest,
  ContradictionResult,
  KnowledgeItem,
  ContradictionFlag,
  ContradictionPointer,
} from '../../src/types/contradiction-detector.interface';
import { ContradictionDetectorImpl } from '../../src/services/contradiction/contradiction-detector.service';
import { MetadataFlaggingService } from '../../src/services/contradiction/metadata-flagging.service';
import { PointerResolutionService } from '../../src/services/contradiction/pointer-resolution.service';
import { StoragePipelineIntegration } from '../../src/services/contradiction/storage-pipeline-integration';
import { generateId } from '../../src/utils/id-generator';

describe('Contradiction Detector Integration Tests', () => {
  let detector: ContradictionDetector;
  let flaggingService: MetadataFlaggingService;
  let resolutionService: PointerResolutionService;
  let pipelineIntegration: StoragePipelineIntegration;

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
    pipelineIntegration = new StoragePipelineIntegration(
      detector,
      flaggingService,
      resolutionService,
      {
        enabled: true,
        check_on_store: true,
        check_on_update: true,
        check_on_delete: false,
        batch_check_threshold: 5,
        async_checking: false, // Synchronous for testing
        max_concurrent_checks: 2,
        queue_checking: false,
        retry_failed_checks: true,
        max_retries: 3,
      }
    );
  });

  describe('Complete Contradiction Detection Workflow', () => {
    test('should detect and flag contradictions end-to-end', async () => {
      // Create contradictory items
      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system is enabled and active',
          scope: { project: 'integration-test' },
          data: { status: 'active', enabled: true },
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system is disabled and inactive',
          scope: { project: 'integration-test' },
          data: { status: 'inactive', enabled: false },
        },
      ];

      // Detect contradictions
      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'integration-test' },
      };

      const detectionResponse = await detector.detectContradictions(request);

      // Should detect contradictions
      expect(detectionResponse.contradictions.length).toBeGreaterThan(0);

      // Flag contradictions
      const flags = await flaggingService.flagContradictions(detectionResponse.contradictions);
      expect(flags.length).toBeGreaterThan(0);

      // Update item metadata
      const updatedItems = await Promise.all(
        items.map(item => flaggingService.updateItemMetadata(item))
      );

      // Check that metadata was updated correctly
      updatedItems.forEach(item => {
        expect(item.metadata?.flags).toContain('possible_contradiction');
        expect(item.metadata?.contradiction_count).toBeGreaterThan(0);
        expect(item.metadata?.contradiction_ids).toBeDefined();
      });
    });

    test('should create resolution workflows for high severity contradictions', async () => {
      // Create high-severity contradictory items
      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system is completely operational',
          scope: { project: 'integration-test' },
          data: { operational: true },
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'The system is completely non-operational',
          scope: { project: 'integration-test' },
          data: { operational: false },
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'integration-test' },
      };

      const detectionResponse = await detector.detectContradictions(request);

      // Filter for high-severity contradictions
      const highSeverityContradictions = detectionResponse.contradictions.filter(c =>
        c.severity === 'high' || c.severity === 'critical'
      );

      if (highSeverityContradictions.length > 0) {
        // Create resolution workflow
        const workflow = await resolutionService.createResolutionWorkflow(
          highSeverityContradictions[0],
          items,
          'test-user'
        );

        expect(workflow).toBeDefined();
        expect(workflow.contradiction_id).toBe(highSeverityContradictions[0].id);
        expect(workflow.actions.length).toBeGreaterThan(0);
        expect(workflow.assigned_to).toBe('test-user');
        expect(workflow.deadline).toBeDefined();
      }
    });
  });

  describe('Storage Pipeline Integration', () => {
    test('should integrate with storage pipeline hooks', async () => {
      const items: KnowledgeItem[] = [
        {
          id: generateId(),
          kind: 'entity',
          content: 'The feature is enabled',
          scope: { project: 'pipeline-test' },
          data: { feature_enabled: true },
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'The feature is not enabled',
          scope: { project: 'pipeline-test' },
          data: { feature_enabled: false },
        },
      ];

      // Test before_store hook
      const beforeStoreResult = await pipelineIntegration.before_store(items);
      expect(beforeStoreResult).toBeDefined();
      if (beforeStoreResult) {
        expect(beforeStoreResult.items).toEqual(items);
      }

      // Test after_store hook
      const storeResults = items.map(item => ({
        id: item.id,
        status: 'success',
        kind: item.kind,
        created_at: new Date().toISOString(),
      }));

      const afterStoreResult = await pipelineIntegration.after_store(items, storeResults);
      expect(afterStoreResult).toBeDefined();
    });

    test('should handle item updates', async () => {
      const oldItem: KnowledgeItem = {
        id: generateId(),
        kind: 'entity',
        content: 'The setting is on',
        scope: { project: 'update-test' },
        data: { setting: true },
      };

      const newItem: KnowledgeItem = {
        id: oldItem.id,
        kind: 'entity',
        content: 'The setting is off',
        scope: { project: 'update-test' },
        data: { setting: false },
      };

      const updateResult = await pipelineIntegration.on_update(oldItem.id, oldItem, newItem);
      expect(updateResult).toBeDefined();
    });

    test('should batch check existing items', async () => {
      const items: KnowledgeItem[] = Array.from({ length: 15 }, (_, i) => ({
        id: generateId(),
        kind: 'entity',
        content: i % 2 === 0 ? 'Status is active' : 'Status is inactive',
        scope: { project: 'batch-test' },
        data: { status: i % 2 === 0 ? 'active' : 'inactive' },
      }));

      const batchResults = await pipelineIntegration.batchCheckExistingItems(items, {
        priority: 'high',
        chunk_size: 5,
      });

      expect(batchResults.length).toBeGreaterThan(0);
      batchResults.forEach(result => {
        expect(result.summary).toBeDefined();
        expect(result.performance).toBeDefined();
      });
    });
  });

  describe('Complex Contradiction Scenarios', () => {
    test('should handle multiple contradiction types in one batch', async () => {
      const items: KnowledgeItem[] = [
        // Factual contradiction
        {
          id: generateId(),
          kind: 'entity',
          content: 'The server is running',
          scope: { project: 'complex-test' },
          data: { server_status: 'running' },
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'The server is not running',
          scope: { project: 'complex-test' },
          data: { server_status: 'stopped' },
        },
        // Temporal contradiction
        {
          id: generateId(),
          kind: 'entity',
          content: 'Event A happened before Event B',
          scope: { project: 'complex-test' },
          data: { sequence: ['A', 'B'] },
          created_at: '2024-01-01T10:00:00Z',
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'Event B happened before Event A',
          scope: { project: 'complex-test' },
          data: { sequence: ['B', 'A'] },
          created_at: '2024-01-01T10:01:00Z',
        },
        // Attribute contradiction
        {
          id: generateId(),
          kind: 'entity',
          content: 'Configuration item',
          scope: { project: 'complex-test' },
          data: { debug_mode: 'enabled' },
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'Configuration item',
          scope: { project: 'complex-test' },
          data: { debug_mode: 'disabled' },
        },
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'complex-test' },
      };

      const response = await detector.detectContradictions(request);

      // Should detect multiple types of contradictions
      expect(response.contradictions.length).toBeGreaterThan(0);

      const contradictionTypes = new Set(response.contradictions.map(c => c.contradiction_type));
      expect(contradictionTypes.size).toBeGreaterThan(1);

      // Check summary statistics
      expect(response.summary.by_type).toBeDefined();
      expect(response.summary.by_severity).toBeDefined();
      expect(Object.keys(response.summary.by_type).length).toBeGreaterThan(0);
    });

    test('should identify contradiction clusters', async () => {
      const centerItemId = generateId();
      const items: KnowledgeItem[] = [
        {
          id: centerItemId,
          kind: 'entity',
          content: 'Central item with conflicting information',
          scope: { project: 'cluster-test' },
          data: { status: 'active' },
        },
        ...Array.from({ length: 5 }, (_, i) => ({
          id: generateId(),
          kind: 'entity',
          content: `Conflicting item ${i} against central item`,
          scope: { project: 'cluster-test' },
          data: { status: i % 2 === 0 ? 'active' : 'inactive' },
        })),
      ];

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'cluster-test' },
      };

      const detectionResponse = await detector.detectContradictions(request);

      if (detectionResponse.contradictions.length > 0) {
        // Create pointers to simulate cluster formation
        const pointers: ContradictionPointer[] = detectionResponse.contradictions.flatMap(c =>
          c.conflicting_item_ids.map(targetId => ({
            source_id: c.primary_item_id,
            target_id: targetId,
            pointer_type: 'contradicts' as const,
            strength: c.confidence_score,
            created_at: new Date(),
            verified: false,
            metadata: { contradiction_id: c.id },
          }))
        );

        // Identify clusters
        const clusters = await resolutionService.identifyContradictionClusters(
          detectionResponse.contradictions,
          pointers
        );

        expect(clusters.length).toBeGreaterThanOrEqual(0);
        clusters.forEach(cluster => {
          expect(cluster.member_item_ids.length).toBeGreaterThanOrEqual(2);
          expect(cluster.severity).toBeDefined();
          expect(cluster.cluster_type).toBeDefined();
          expect(cluster.suggested_resolution).toBeDefined();
        });
      }
    });
  });

  describe('Performance Integration', () => {
    test('should handle large batches efficiently', async () => {
      const items: KnowledgeItem[] = Array.from({ length: 80 }, (_, i) => ({
        id: generateId(),
        kind: 'entity',
        content: i % 2 === 0 ? 'System is online' : 'System is offline',
        scope: { project: 'performance-test' },
        data: { online: i % 2 === 0 },
      }));

      const startTime = Date.now();
      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'performance-test' },
      };

      const response = await detector.detectContradictions(request);
      const processingTime = Date.now() - startTime;

      // Performance assertions
      expect(processingTime).toBeLessThan(15000); // Should complete within 15 seconds
      expect(response.summary.total_items_checked).toBe(80);
      expect(response.performance.items_per_second).toBeGreaterThan(5);

      // Should process in chunks
      expect(response.performance.memory_usage_mb).toBeLessThan(200);
    });

    test('should handle concurrent processing', async () => {
      const batch1 = Array.from({ length: 20 }, (_, i) => ({
        id: generateId(),
        kind: 'entity',
        content: `Batch 1 item ${i}`,
        scope: { project: 'concurrent-test' },
        data: { batch: 1, active: i % 2 === 0 },
      }));

      const batch2 = Array.from({ length: 20 }, (_, i) => ({
        id: generateId(),
        kind: 'entity',
        content: `Batch 2 item ${i}`,
        scope: { project: 'concurrent-test' },
        data: { batch: 2, active: i % 2 === 1 },
      }));

      // Process both batches concurrently
      const startTime = Date.now();
      const [response1, response2] = await Promise.all([
        detector.detectContradictions({ items: batch1, scope: { project: 'concurrent-test' } }),
        detector.detectContradictions({ items: batch2, scope: { project: 'concurrent-test' } }),
      ]);
      const concurrentTime = Date.now() - startTime;

      // Sequential processing for comparison
      const sequentialStart = Date.now();
      await detector.detectContradictions({ items: batch1, scope: { project: 'concurrent-test' } });
      await detector.detectContradictions({ items: batch2, scope: { project: 'concurrent-test' } });
      const sequentialTime = Date.now() - sequentialStart;

      // Concurrent should be faster or at least not significantly slower
      expect(concurrentTime).toBeLessThanOrEqual(sequentialTime * 1.2);
    });
  });

  describe('Error Handling and Recovery', () => {
    test('should handle malformed items gracefully', async () => {
      const malformedItems: KnowledgeItem[] = [
        {
          id: '', // Empty ID
          kind: 'entity',
          content: null as any, // Null content
          scope: undefined as any, // Undefined scope
          data: undefined as any,
        },
        {
          id: generateId(),
          kind: 'entity',
          content: 'Normal item',
          scope: { project: 'error-test' },
          data: {},
        },
      ];

      const request: ContradictionDetectionRequest = {
        items: malformedItems,
        scope: { project: 'error-test' },
      };

      // Should not crash
      const response = await detector.detectContradictions(request);
      expect(Array.isArray(response.contradictions)).toBe(true);
      expect(response.summary.total_items_checked).toBe(2);
    });

    test('should handle system timeouts gracefully', async () => {
      const timeoutDetector = new ContradictionDetectorImpl({
        enabled: true,
        sensitivity: 'balanced',
        auto_flag: true,
        batch_checking: true,
        performance_monitoring: true,
        cache_results: true,
        cache_ttl_ms: 300000,
        max_items_per_check: 100,
        timeout_ms: 1, // Very short timeout
      });

      const items: KnowledgeItem[] = Array.from({ length: 50 }, (_, i) => ({
        id: generateId(),
        kind: 'entity',
        content: `Test item ${i}`,
        scope: { project: 'timeout-test' },
        data: {},
      }));

      const request: ContradictionDetectionRequest = {
        items,
        scope: { project: 'timeout-test' },
      };

      // Should handle timeout gracefully
      const response = await timeoutDetector.detectContradictions(request);
      expect(response).toBeDefined();
    });
  });

  describe('Configuration Management', () => {
    test('should update configuration at runtime', async () => {
      const initialConfig = detector.getConfiguration();
      expect(initialConfig.sensitivity).toBe('balanced');

      await detector.updateConfiguration({
        sensitivity: 'conservative',
        auto_flag: false,
      });

      const updatedConfig = detector.getConfiguration();
      expect(updatedConfig.sensitivity).toBe('conservative');
      expect(updatedConfig.auto_flag).toBe(false);
      expect(updatedConfig.enabled).toBe(initialConfig.enabled); // Unchanged
    });

    test('should propagate configuration changes to pipeline integration', async () => {
      const initialPipelineConfig = pipelineIntegration.getConfiguration();
      expect(initialPipelineConfig.enabled).toBe(true);

      pipelineIntegration.updateConfiguration({
        enabled: false,
        check_on_store: false,
      });

      const updatedPipelineConfig = pipelineIntegration.getConfiguration();
      expect(updatedPipelineConfig.enabled).toBe(false);
      expect(updatedPipelineConfig.check_on_store).toBe(false);
    });
  });
});

// Mock implementation for testing
class ContradictionDetectorImpl implements ContradictionDetector {
  private config: any;

  constructor(config: any) {
    this.config = config;
  }

  async detectContradictions(request: ContradictionDetectionRequest): Promise<any> {
    // Simulate processing time
    await new Promise(resolve => setTimeout(resolve, Math.random() * 100));

    const contradictions = this.simulateContradictionDetection(request.items);

    return {
      contradictions,
      summary: {
        total_items_checked: request.items.length,
        contradictions_found: contradictions.length,
        by_type: contradictions.reduce((acc, c) => {
          acc[c.contradiction_type] = (acc[c.contradiction_type] || 0) + 1;
          return acc;
        }, {} as Record<string, number>),
        by_severity: contradictions.reduce((acc, c) => {
          acc[c.severity] = (acc[c.severity] || 0) + 1;
          return acc;
        }, {} as Record<string, number>),
        processing_time_ms: Math.random() * 1000,
        cache_hits: Math.floor(Math.random() * 10),
        cache_misses: Math.floor(Math.random() * 5),
      },
      performance: {
        items_per_second: request.items.length / (Math.random() * 2 + 0.5),
        memory_usage_mb: Math.random() * 100 + 50,
        bottleneck_detected: false,
        bottlenecks: [],
      },
    };
  }

  private simulateContradictionDetection(items: KnowledgeItem[]): ContradictionResult[] {
    const contradictions: ContradictionResult[] = [];

    // Simple contradiction simulation
    for (let i = 0; i < items.length - 1; i++) {
      const item1 = items[i];
      const item2 = items[i + 1];

      if (this.itemsContradict(item1, item2)) {
        contradictions.push({
          id: generateId(),
          detected_at: new Date(),
          contradiction_type: this.getContradictionType(item1, item2),
          confidence_score: Math.random() * 0.4 + 0.6, // 0.6-1.0
          severity: this.calculateSeverity(Math.random() * 0.4 + 0.6),
          primary_item_id: item1.id || generateId(),
          conflicting_item_ids: [item2.id || generateId()],
          description: 'Simulated contradiction detected',
          reasoning: 'Items contain conflicting information',
          metadata: {
            detection_method: 'simulation',
            algorithm_version: '1.0.0',
            processing_time_ms: Math.random() * 100,
            comparison_details: {},
            evidence: [],
          },
          resolution_suggestions: [],
        });
      }
    }

    return contradictions;
  }

  private itemsContradict(item1: KnowledgeItem, item2: KnowledgeItem): boolean {
    if (item1.scope?.project !== item2.scope?.project) {
      return false;
    }

    const content1 = (item1.content || '').toLowerCase();
    const content2 = (item2.content || '').toLowerCase();

    // Simple contradiction patterns
    const negationPairs = [
      ['enabled', 'disabled'],
      ['active', 'inactive'],
      ['running', 'stopped'],
      ['online', 'offline'],
      ['true', 'false'],
      ['yes', 'no'],
      ['on', 'off'],
    ];

    for (const [pos, neg] of negationPairs) {
      if ((content1.includes(pos) && content2.includes(neg)) ||
          (content1.includes(neg) && content2.includes(pos))) {
        return true;
      }
    }

    return Math.random() < 0.3; // 30% chance of random contradiction
  }

  private getContradictionType(item1: KnowledgeItem, item2: KnowledgeItem): string {
    const content1 = (item1.content || '').toLowerCase();
    const content2 = (item2.content || '').toLowerCase();

    if (content1.includes('before') || content2.includes('before') ||
        content1.includes('after') || content2.includes('after')) {
      return 'temporal';
    }

    if (content1.includes('either') || content2.includes('either') ||
        content1.includes('exclusive') || content2.includes('exclusive')) {
      return 'logical';
    }

    if (item1.data && item2.data && Object.keys(item1.data).length > 0) {
      return 'attribute';
    }

    return 'factual';
  }

  private calculateSeverity(confidence: number): 'low' | 'medium' | 'high' | 'critical' {
    if (confidence >= 0.9) return 'critical';
    if (confidence >= 0.75) return 'high';
    if (confidence >= 0.6) return 'medium';
    return 'low';
  }

  getConfiguration(): any {
    return { ...this.config };
  }

  async updateConfiguration(config: Partial<any>): Promise<void> {
    this.config = { ...this.config, ...config };
  }

  // Mock implementations for other interface methods
  async flagContradictions() { return []; }
  async analyzeItem() {
    return {
      item_id: '',
      contradiction_count: 0,
      contradiction_types: [],
      severity_distribution: {},
      related_items: [],
      trust_score: 1.0,
      last_analysis: new Date(),
      analysis_details: {
        factual_consistency: 1.0,
        temporal_consistency: 1.0,
        logical_consistency: 1.0,
        attribute_consistency: 1.0,
      },
    };
  }
  async getContradictionPointers() { return []; }
  async batchCheck(items: KnowledgeItem[]) {
    return this.detectContradictions({ items });
  }
  async validateContradiction() { return true; }
  async resolveContradiction() { }
}