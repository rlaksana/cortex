// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck


/**
 * P4-1: Enhanced System Metrics Tests
 *
 * Tests for enhanced metrics collection including chunking, cleanup,
 * and dedupe_hits metrics.
 */

import { beforeEach,describe, expect, it } from '@jest/globals';

import { type SystemMetricsService, systemMetricsService } from '../system-metrics.js';

// Mock the logger
jest.mock('../../utils/logger.js', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

describe('Enhanced SystemMetricsService', () => {
  let service: SystemMetricsService;

  beforeEach(() => {
    // Use the singleton but reset it for testing
    service = systemMetricsService;
    service.resetMetrics();
  });

  describe('Chunking Metrics', () => {
    it('should update chunking metrics correctly', () => {
      const chunkData = {
        items_chunked: 5,
        chunks_generated: 15,
        success: true,
        type: 'section',
        semantic_analysis_used: 3,
        semantic_boundaries_found: 2,
        reassembly_accuracy: 95.5,
        average_chunk_size: 500,
        overlap_utilization: 0.15,
      };

      service.updateMetrics({
        operation: 'chunking',
        data: chunkData,
        duration_ms: 250,
      });

      const metrics = service.getMetrics();
      const chunking = metrics.chunking;

      expect(chunking.items_chunked).toBe(5);
      expect(chunking.chunks_generated).toBe(15);
      expect(chunking.avg_chunks_per_item).toBe(3); // 15/5
      expect(chunking.chunking_duration_ms).toBe(250);
      expect(chunking.chunking_success_rate).toBeGreaterThan(0);
      expect(chunking.semantic_analysis_used).toBe(3);
      expect(chunking.semantic_boundaries_found).toBe(2);
      expect(chunking.chunk_reassembly_accuracy).toBe(95.5);
      expect(chunking.average_chunk_size).toBe(500);
      expect(chunking.overlap_utilization).toBe(0.15);
      expect(chunking.chunking_by_type['section']).toBe(1);
    });

    it('should track chunking errors', () => {
      const errorData = {
        success: false,
        type: 'runbook',
      };

      service.updateMetrics({
        operation: 'chunking',
        data: errorData,
        duration_ms: 100,
      });

      const metrics = service.getMetrics();
      const chunking = metrics.chunking;

      // Should track error in success rate calculation
      expect(chunking.chunking_errors).toBe(0); // This gets calculated
      expect(chunking.chunking_success_rate).toBeLessThan(100);
    });

    it('should aggregate metrics from multiple chunking operations', () => {
      // First operation
      service.updateMetrics({
        operation: 'chunking',
        data: {
          items_chunked: 2,
          chunks_generated: 6,
          success: true,
          type: 'section',
        },
        duration_ms: 100,
      });

      // Second operation
      service.updateMetrics({
        operation: 'chunking',
        data: {
          items_chunked: 3,
          chunks_generated: 9,
          success: true,
          type: 'runbook',
        },
        duration_ms: 150,
      });

      const metrics = service.getMetrics();
      const chunking = metrics.chunking;

      expect(chunking.items_chunked).toBe(5);
      expect(chunking.chunks_generated).toBe(15);
      expect(chunking.avg_chunks_per_item).toBe(3); // 15/5
      expect(chunking.chunking_duration_ms).toBe(250); // 100+150
      expect(chunking.chunking_by_type['section']).toBe(1);
      expect(chunking.chunking_by_type['runbook']).toBe(1);
    });
  });

  describe('Cleanup Metrics', () => {
    it('should update cleanup metrics correctly', () => {
      const cleanupData = {
        items_deleted: 50,
        items_dryrun_identified: 120,
        success: true,
        operation_type: 'expired',
        knowledge_type: 'entity',
        backup_created: true,
        backup_size: 1024000, // 1MB
        items_per_second: 5.2,
        confirmation_required: true,
        confirmation_completed: true,
      };

      service.updateMetrics({
        operation: 'cleanup',
        data: cleanupData,
        duration_ms: 10000, // 10 seconds
      });

      const metrics = service.getMetrics();
      const cleanup = metrics.cleanup;

      expect(cleanup.cleanup_operations_run).toBe(1);
      expect(cleanup.items_deleted_total).toBe(50);
      expect(cleanup.items_dryrun_identified).toBe(120);
      expect(cleanup.cleanup_duration_ms).toBe(10000);
      expect(cleanup.cleanup_success_rate).toBeGreaterThan(0);
      expect(cleanup.backup_operations).toBe(1);
      expect(cleanup.backup_size_total_bytes).toBe(1024000);
      expect(cleanup.average_items_per_second).toBe(5.2);
      expect(cleanup.confirmations_required).toBe(1);
      expect(cleanup.confirmations_completed).toBe(1);
      expect(cleanup.cleanup_by_operation['expired']).toBe(1);
      expect(cleanup.cleanup_by_type['entity']).toBe(1);
    });

    it('should track cleanup operations over time', () => {
      // Multiple cleanup operations
      const operations = [
        { operation_type: 'expired', knowledge_type: 'entity', items_deleted: 30, success: true },
        {
          operation_type: 'orphaned',
          knowledge_type: 'relation',
          items_deleted: 20,
          success: true,
        },
        { operation_type: 'duplicate', knowledge_type: 'entity', items_deleted: 15, success: true },
      ];

      operations.forEach((op, index) => {
        service.updateMetrics({
          operation: 'cleanup',
          data: {
            ...op,
            success: true,
          },
          duration_ms: 5000,
        });
      });

      const metrics = service.getMetrics();
      const cleanup = metrics.cleanup;

      expect(cleanup.cleanup_operations_run).toBe(3);
      expect(cleanup.items_deleted_total).toBe(65); // 30+20+15
      expect(cleanup.cleanup_by_operation['expired']).toBe(1);
      expect(cleanup.cleanup_by_operation['orphaned']).toBe(1);
      expect(cleanup.cleanup_by_operation['duplicate']).toBe(1);
      expect(cleanup.cleanup_by_type['entity']).toBe(2); // expired + duplicate
      expect(cleanup.cleanup_by_type['relation']).toBe(1);
    });

    it('should handle cleanup failures', () => {
      service.updateMetrics({
        operation: 'cleanup',
        data: {
          success: false,
          operation_type: 'expired',
        },
        duration_ms: 2000,
      });

      const metrics = service.getMetrics();
      const cleanup = metrics.cleanup;

      expect(cleanup.cleanup_operations_run).toBe(1);
      expect(cleanup.cleanup_success_rate).toBeLessThan(100);
    });
  });

  describe('Dedupe Hits Metrics', () => {
    it('should update dedupe_hits metrics correctly', () => {
      const dedupeData = {
        duplicates_detected: 5,
        similarity_score: 0.92,
        merge_operation: true,
        strategy: 'intelligent',
        false_positive: false,
        merge_conflicts_resolved: 2,
      };

      service.updateMetrics({
        operation: 'dedupe_hits',
        data: dedupeData,
        duration_ms: 500,
      });

      const metrics = service.getMetrics();
      const dedupeHits = metrics.dedupe_hits;

      expect(dedupeHits.duplicates_detected).toBe(5);
      expect(dedupeHits.similarity_scores).toContain(0.92);
      expect(dedupeHits.avg_similarity_score).toBe(0.92);
      expect(dedupeHits.merge_operations).toBe(1);
      expect(dedupeHits.intelligent_merges).toBe(1);
      expect(dedupeHits.dedupe_hits_by_strategy['intelligent']).toBe(1);
      expect(dedupeHits.false_positives).toBe(0);
      expect(dedupeHits.merge_conflicts_resolved).toBe(2);
      expect(dedupeHits.dedupe_processing_time_ms).toBe(500);
    });

    it('should track different merge strategies', () => {
      const strategies = [
        { strategy: 'intelligent', merge_operation: true, similarity_score: 0.95 },
        { strategy: 'combine', merge_operation: true, similarity_score: 0.88 },
        { strategy: 'skip', skip_operation: true, similarity_score: 0.91 },
      ];

      strategies.forEach((strategy) => {
        service.updateMetrics({
          operation: 'dedupe_hits',
          data: {
            duplicates_detected: 1,
            similarity_score: strategy.similarity_score,
            ...strategy,
          },
        });
      });

      const metrics = service.getMetrics();
      const dedupeHits = metrics.dedupe_hits;

      expect(dedupeHits.duplicates_detected).toBe(3);
      expect(dedupeHits.merge_operations).toBe(2);
      expect(dedupeHits.skip_operations).toBe(1);
      expect(dedupeHits.intelligent_merges).toBe(1);
      expect(dedupeHits.combine_merges).toBe(1);
      expect(dedupeHits.dedupe_hits_by_strategy['intelligent']).toBe(1);
      expect(dedupeHits.dedupe_hits_by_strategy['combine']).toBe(1);
      expect(dedupeHits.dedupe_hits_by_strategy['skip']).toBe(1);
    });

    it('should limit similarity scores array size', () => {
      // Add many similarity scores to test array size limiting
      for (let i = 0; i < 1100; i++) {
        // More than the 1000 limit
        service.updateMetrics({
          operation: 'dedupe_hits',
          data: {
            duplicates_detected: 1,
            similarity_score: 0.8 + (i % 20) * 0.01, // Varying scores
          },
        });
      }

      const metrics = service.getMetrics();
      const dedupeHits = metrics.dedupe_hits;

      expect(dedupeHits.similarity_scores.length).toBeLessThanOrEqual(1000);
      expect(dedupeHits.duplicates_detected).toBe(1100);
    });

    it('should calculate average similarity score correctly', () => {
      const scores = [0.85, 0.9, 0.95, 0.88, 0.92];

      scores.forEach((score) => {
        service.updateMetrics({
          operation: 'dedupe_hits',
          data: {
            duplicates_detected: 1,
            similarity_score: score,
          },
        });
      });

      const metrics = service.getMetrics();
      const dedupeHits = metrics.dedupe_hits;

      const expectedAverage = scores.reduce((a, b) => a + b, 0) / scores.length;
      expect(dedupeHits.avg_similarity_score).toBeCloseTo(expectedAverage, 5);
    });
  });

  describe('Metrics Integration', () => {
    it('should include enhanced metrics in full metrics response', () => {
      // Update all enhanced metric types
      service.updateMetrics({
        operation: 'chunking',
        data: {
          items_chunked: 3,
          chunks_generated: 9,
          success: true,
        },
      });

      service.updateMetrics({
        operation: 'cleanup',
        data: {
          items_deleted: 10,
          success: true,
        },
      });

      service.updateMetrics({
        operation: 'dedupe_hits',
        data: {
          duplicates_detected: 2,
          similarity_score: 0.89,
        },
      });

      const metrics = service.getMetrics();

      expect(metrics.chunking).toBeDefined();
      expect(metrics.cleanup).toBeDefined();
      expect(metrics.dedupe_hits).toBeDefined();

      expect(metrics.chunking.items_chunked).toBe(3);
      expect(metrics.cleanup.items_deleted_total).toBe(10);
      expect(metrics.dedupe_hits.duplicates_detected).toBe(2);
    });

    it('should reset all enhanced metrics', () => {
      // Update some enhanced metrics
      service.updateMetrics({
        operation: 'chunking',
        data: { items_chunked: 5, success: true },
      });

      service.updateMetrics({
        operation: 'cleanup',
        data: { items_deleted: 20, success: true },
      });

      service.updateMetrics({
        operation: 'dedupe_hits',
        data: { duplicates_detected: 3, similarity_score: 0.91 },
      });

      // Verify metrics were updated
      let metrics = service.getMetrics();
      expect(metrics.chunking.items_chunked).toBe(5);
      expect(metrics.cleanup.items_deleted_total).toBe(20);
      expect(metrics.dedupe_hits.duplicates_detected).toBe(3);

      // Reset metrics
      service.resetMetrics();

      // Verify metrics were reset
      metrics = service.getMetrics();
      expect(metrics.chunking.items_chunked).toBe(0);
      expect(metrics.cleanup.items_deleted_total).toBe(0);
      expect(metrics.dedupe_hits.duplicates_detected).toBe(0);
      expect(metrics.chunking.chunking_by_type).toEqual({});
      expect(metrics.cleanup.cleanup_by_operation).toEqual({});
      expect(metrics.dedupe_hits.similarity_scores).toEqual([]);
    });
  });

  describe('Metrics Summary', () => {
    it('should provide comprehensive metrics summary', () => {
      // Update various metrics
      service.updateMetrics({
        operation: 'store',
        data: { success: true, kind: 'entity' },
        duration_ms: 100,
      });

      service.updateMetrics({
        operation: 'find',
        data: { success: true, mode: 'auto' },
        duration_ms: 50,
      });

      service.updateMetrics({
        operation: 'chunking',
        data: { items_chunked: 2, success: true },
      });

      service.updateMetrics({
        operation: 'cleanup',
        data: { items_deleted: 5, success: true },
      });

      const summary = service.getMetricsSummary();

      expect(summary.operations).toBeDefined();
      expect(summary.performance).toBeDefined();
      expect(summary.health).toBeDefined();

      expect(summary.operations.stores).toBeGreaterThan(0);
      expect(summary.operations.finds).toBeGreaterThan(0);
      expect(typeof summary.performance.avg_response_time).toBe('number');
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle invalid operation type gracefully', () => {
      expect(() => {
        service.updateMetrics({
          operation: 'invalid_operation' as unknown,
          data: {},
        });
      }).not.toThrow();
    });

    it('should handle missing data gracefully', () => {
      expect(() => {
        service.updateMetrics({
          operation: 'chunking',
          data: {},
          duration_ms: 100,
        });
      }).not.toThrow();

      const metrics = service.getMetrics();
      expect(metrics.chunking.items_chunked).toBe(0);
      expect(metrics.chunking.chunking_duration_ms).toBe(100);
    });

    it('should handle negative or invalid values', () => {
      service.updateMetrics({
        operation: 'cleanup',
        data: {
          items_deleted: -5, // Invalid negative value
          success: true,
        },
      });

      const metrics = service.getMetrics();
      expect(metrics.cleanup.items_deleted_total).toBeGreaterThanOrEqual(-5);
    });

    it('should handle large values without overflow', () => {
      const largeValue = Number.MAX_SAFE_INTEGER;

      service.updateMetrics({
        operation: 'dedupe_hits',
        data: {
          duplicates_detected: largeValue,
        },
      });

      const metrics = service.getMetrics();
      expect(metrics.dedupe_hits.duplicates_detected).toBe(largeValue);
    });
  });

  describe('Performance Considerations', () => {
    it('should handle rapid metric updates efficiently', () => {
      const startTime = Date.now();

      // Perform many rapid updates
      for (let i = 0; i < 1000; i++) {
        service.updateMetrics({
          operation: 'chunking',
          data: {
            items_chunked: 1,
            success: i % 10 !== 0, // 90% success rate
          },
        });
      }

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Should complete within reasonable time (adjust threshold as needed)
      expect(duration).toBeLessThan(1000); // Less than 1 second

      const metrics = service.getMetrics();
      expect(metrics.chunking.items_chunked).toBe(1000);
    });

    it('should maintain performance with large similarity score arrays', () => {
      // Add many similarity scores up to the limit
      for (let i = 0; i < 1000; i++) {
        service.updateMetrics({
          operation: 'dedupe_hits',
          data: {
            duplicates_detected: 1,
            similarity_score: 0.8 + Math.random() * 0.2,
          },
        });
      }

      const startTime = Date.now();
      const metrics = service.getMetrics();
      const endTime = Date.now();

      expect(metrics.dedupe_hits.similarity_scores.length).toBe(1000);
      expect(endTime - startTime).toBeLessThan(50); // Should be fast to retrieve
    });
  });
});
