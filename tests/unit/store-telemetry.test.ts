import { StoreTelemetryService } from '../../src/services/telemetry/store-telemetry-service';
import { KnowledgeItem } from '../../src/types/core-interfaces';

describe('StoreTelemetryService', () => {
  let service: StoreTelemetryService;

  beforeEach(() => {
    service = new StoreTelemetryService();
  });

  describe('truncation tracking', () => {
    it('should track when content is truncated at 8000 chars', async () => {
      const longContent = 'a'.repeat(10000);
      const item: KnowledgeItem = {
        kind: 'observation',
        scope: { project: 'test' },
        data: { content: longContent }
      };

      await service.recordStoreAttempt(item, 10000, 8000);

      const metrics = service.getTruncationMetrics();
      expect(metrics.total_stores).toBe(1);
      expect(metrics.truncated_stores).toBe(1);
      expect(metrics.truncated_ratio).toBe(1.0);
      expect(metrics.avg_truncated_len).toBe(8000);
    });

    it('should not count truncation when content is under limit', async () => {
      const shortContent = 'a'.repeat(1000);
      const item: KnowledgeItem = {
        kind: 'observation',
        scope: { project: 'test' },
        data: { content: shortContent }
      };

      await service.recordStoreAttempt(item, 1000, 1000);

      const metrics = service.getTruncationMetrics();
      expect(metrics.total_stores).toBe(1);
      expect(metrics.truncated_stores).toBe(0);
      expect(metrics.truncated_ratio).toBe(0.0);
    });

    it('should calculate average truncated length correctly', async () => {
      // First item: 10000 -> 8000 (truncated)
      const item1: KnowledgeItem = {
        kind: 'observation',
        scope: { project: 'test' },
        data: { content: 'a'.repeat(10000) }
      };

      // Second item: 12000 -> 8000 (truncated)
      const item2: KnowledgeItem = {
        kind: 'decision',
        scope: { project: 'test' },
        data: { content: 'b'.repeat(12000) }
      };

      await service.recordStoreAttempt(item1, 10000, 8000);
      await service.recordStoreAttempt(item2, 12000, 8000);

      const metrics = service.getTruncationMetrics();
      expect(metrics.total_stores).toBe(2);
      expect(metrics.truncated_stores).toBe(2);
      expect(metrics.truncated_ratio).toBe(1.0);
      expect(metrics.avg_truncated_len).toBe(8000); // Both truncated to 8000
    });
  });

  describe('per-kind success tracking', () => {
    it('should track successful stores by kind', async () => {
      const observation: KnowledgeItem = {
        kind: 'observation',
        scope: { project: 'test' },
        data: { content: 'test observation' }
      };

      const decision: KnowledgeItem = {
        kind: 'decision',
        scope: { project: 'test' },
        data: { title: 'test decision', rationale: 'test rationale' }
      };

      await service.recordSuccessfulStore(observation);
      await service.recordSuccessfulStore(decision);
      await service.recordSkippedDedupe('observation');

      const metrics = service.getPerKindMetrics();
      expect(metrics.observation.stored).toBe(1);
      expect(metrics.observation.skipped_dedupe).toBe(1);
      expect(metrics.decision.stored).toBe(1);
      expect(metrics.decision.skipped_dedupe).toBe(0);
    });
  });

  describe('deduplication distribution', () => {
    it('should track deduplication hits with similarity scores', async () => {
      await service.recordDedupeHit(0.92, 'test-source-1');
      await service.recordDedupeHit(0.88, 'test-source-2');
      await service.recordDedupeHit(0.95, 'test-source-1');

      const metrics = service.getDeduplicationMetrics();
      expect(metrics.dedupe_hits).toBe(3);
      expect(metrics.avg_similarity_of_hits).toBeCloseTo(0.917, 2);
      expect(metrics.top_offenders['test-source-1']).toBe(2);
      expect(metrics.top_offenders['test-source-2']).toBe(1);
    });
  });

  describe('embedding failure tracking', () => {
    it('should track embedding success and failure rates', async () => {
      await service.recordEmbeddingAttempt(true);
      await service.recordEmbeddingAttempt(true);
      await service.recordEmbeddingAttempt(false);
      await service.recordStoreWithoutVector();

      const metrics = service.getEmbeddingMetrics();
      expect(metrics.embedding_calls).toBe(3);
      expect(metrics.embedding_failures).toBe(1);
      expect(metrics.stored_without_vector).toBe(1);
      expect(metrics.embedding_success_rate).toBeCloseTo(0.667, 2);
    });
  });

  describe('language distribution tracking', () => {
    it('should track detected language distribution', async () => {
      await service.recordLanguageDetection('en');
      await service.recordLanguageDetection('id');
      await service.recordLanguageDetection('en');
      await service.recordLanguageDetection('mixed');

      const metrics = service.getLanguageMetrics();
      expect(metrics.total_stores).toBe(4);
      expect(metrics.lang_distribution.en).toBe(2);
      expect(metrics.lang_distribution.id).toBe(1);
      expect(metrics.lang_distribution.mixed).toBe(1);
    });
  });
});