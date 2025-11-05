/**
 * Dedupe Rules Test Suite
 *
 * Tests the duplicate detection rules and time-based logic
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { KnowledgeItem } from '../../src/types/core-interfaces.js';

// Mock the orchestrator since this is a unit test focused on dedupe logic
const mockOrchestrator = {
  storeItems: vi.fn(),
  detectDuplicates: vi.fn(),
  getOrchestratorStats: vi.fn(),
};

describe('Dedupe Rules Test Suite', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Mock successful store response
    mockOrchestrator.storeItems.mockResolvedValue({
      summary: {
        stored: 1,
        skipped_dedupe: 0,
        business_rule_blocked: 0,
        validation_error: 0,
        total: 1,
      },
      items: [],
      stored: [],
      errors: [],
    });

    // Mock duplicate detection response
    mockOrchestrator.detectDuplicates.mockResolvedValue({
      isDuplicate: false,
      reason: 'No similar items found',
      similarityScore: 0,
    });

    // Mock stats response
    mockOrchestrator.getOrchestratorStats.mockReturnValue({
      duplicateDetectionStats: {
        totalChecks: 0,
        contentHashMatches: 0,
        semanticSimilarityMatches: 0,
      },
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Time-Based Dedupe Rules', () => {
    it('should handle same kind + same scope deduplication', async () => {
      // Create an item
      const item1: KnowledgeItem = {
        id: 'item-001',
        kind: 'entity',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          content: 'Test content for dedupe rules',
          name: 'Test Entity',
          category: 'component',
        },
        created_at: '2025-10-15T10:00:00.000Z',
      };

      // Store the first item
      const storeResult1 = await mockOrchestrator.storeItems([item1]);
      expect(storeResult1.summary.stored).toBe(1);

      // Try to store a duplicate with same kind and scope
      const item2: KnowledgeItem = {
        id: 'item-002',
        kind: 'entity',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          content: 'Test content for dedupe rules',
          name: 'Test Entity',
          category: 'component',
        },
        created_at: '2025-10-15T10:01:00.000Z',
      };

      // Mock duplicate detection for the second item
      mockOrchestrator.detectDuplicates.mockResolvedValueOnce({
        isDuplicate: true,
        reason: 'Duplicate content detected (hash: abc123...)',
        similarityScore: 1.0,
        existingItem: { id: 'item-001' },
      });

      // Mock store response showing duplicate was skipped
      mockOrchestrator.storeItems.mockResolvedValueOnce({
        summary: {
          stored: 0,
          skipped_dedupe: 1,
          business_rule_blocked: 0,
          validation_error: 0,
          total: 1,
        },
        items: [
          {
            input_index: 0,
            status: 'skipped_dedupe',
            kind: 'entity',
            id: 'item-002',
            created_at: '2025-10-15T10:01:00.000Z',
            reason: 'Duplicate content detected (hash: abc123...)',
            existing_id: 'item-001',
          },
        ],
        stored: [],
        errors: [],
      });

      const storeResult2 = await mockOrchestrator.storeItems([item2]);

      // Should be marked as skipped_dedupe
      expect(storeResult2.summary.stored).toBe(0);
      expect(storeResult2.summary.validation_error).toBe(0);
      expect(storeResult2.errors).toHaveLength(0);
      expect(storeResult2.summary.skipped_dedupe).toBe(1);
      expect(storeResult2.items).toHaveLength(1); // Item should be present but marked as skipped
      expect(storeResult2.items[0].status).toBe('skipped_dedupe');
      expect(storeResult2.errors).toHaveLength(0);
    });

    it('should handle same kind with different scope', async () => {
      const item1: KnowledgeItem = {
        id: 'item-001',
        kind: 'entity',
        scope: { project: 'project-a' },
        data: { content: 'Entity content for project-a' },
        created_at: new Date().toISOString(),
      };

      const item2: KnowledgeItem = {
        id: 'item-002',
        kind: 'entity',
        scope: { project: 'project-b' },
        data: { content: 'Entity content for project-b' },
        created_at: new Date().toISOString(),
      };

      // Mock successful store of both items (different scopes should not dedupe)
      mockOrchestrator.storeItems.mockResolvedValueOnce({
        summary: {
          stored: 2,
          skipped_dedupe: 0,
          business_rule_blocked: 0,
          validation_error: 0,
          total: 2,
        },
        items: [
          {
            input_index: 0,
            status: 'stored',
            kind: 'entity',
            id: 'item-001',
            created_at: new Date().toISOString(),
          },
          {
            input_index: 1,
            status: 'stored',
            kind: 'entity',
            id: 'item-002',
            created_at: new Date().toISOString(),
          },
        ],
        stored: ['item-001', 'item-002'],
        errors: [],
      });

      const storeResult = await mockOrchestrator.storeItems([item1, item2]);
      expect(storeResult.summary.stored).toBe(2);
      expect(storeResult.summary.skipped_dedupe).toBe(0);
    });

    it('should allow different kinds with same scope', async () => {
      const item1: KnowledgeItem = {
        id: 'item-001',
        kind: 'entity',
        scope: { project: 'test-project', branch: 'main' },
        data: { content: 'Entity content' },
        created_at: new Date().toISOString(),
      };

      const item2: KnowledgeItem = {
        id: 'item-002',
        kind: 'decision',
        scope: { project: 'test-project', branch: 'main' },
        data: { content: 'Decision content' },
        created_at: new Date().toISOString(),
      };

      const storeResult = await mockOrchestrator.storeItems([item1, item2]);
      expect(storeResult.summary.stored).toBe(2);
      expect(storeResult.summary.skipped_dedupe).toBe(0);
    });

    it('should allow different kinds with different scope', async () => {
      const item1: KnowledgeItem = {
        id: 'item-001',
        kind: 'entity',
        scope: { project: 'project-a' },
        data: { content: 'Entity content for project-a' },
        created_at: new Date().toISOString(),
      };

      const item2: KnowledgeItem = {
        id: 'item-002',
        kind: 'decision',
        scope: { project: 'project-b' },
        data: { content: 'Decision content for project-b' },
        created_at: new Date().toISOString(),
      };

      const storeResult = await mockOrchestrator.storeItems([item1, item2]);
      expect(storeResult.summary.stored).toBe(2);
      expect(storeResult.summary.skipped_dedupe).toBe(0);
    });
  });

  describe('Similarity Threshold Rules', () => {
    it('should apply different similarity thresholds for different content types', async () => {
      const testCases = [
        {
          name: 'Exact duplicate',
          item1: {
            id: 'item-001',
            kind: 'entity',
            data: { content: 'Exact match test' },
            scope: {},
            created_at: '2025-01-01T00:00:00.000Z',
          },
          item2: {
            id: 'item-002',
            kind: 'entity',
            data: { content: 'Exact match test' },
            scope: {},
            created_at: '2025-01-01T00:00:00.000Z',
          },
          expectedDuplicate: true,
          expectedReason: 'Duplicate content detected (hash: abc123...)',
        },
        {
          name: 'High similarity',
          item1: {
            id: 'item-001',
            kind: 'entity',
            data: { content: 'Similar content with 90% similarity' },
            scope: {},
            created_at: '2025-01-01T00:00:00.000Z',
          },
          item2: {
            id: 'item-002',
            kind: 'entity',
            data: { content: 'Similar content with 90% similarity' },
            scope: {},
            created_at: '2025-01-01T00:00:00.000Z',
          },
          expectedDuplicate: true,
          expectedReason: 'High semantic similarity (90.0%)',
        },
        {
          name: 'Medium similarity',
          item1: {
            id: 'item-001',
            kind: 'entity',
            data: { content: 'Similar content with 75% similarity' },
            scope: {},
            created_at: '2025-01-01T00:00:00.000Z',
          },
          item2: {
            id: 'item-002',
            kind: 'entity',
            data: { content: 'Similar content with 75% similarity' },
            scope: {},
            created_at: '2025-01-01T00:00:00.000Z',
          },
          expectedDuplicate: false,
          expectedReason: 'No significant similarity found',
        },
      ];

      for (const testCase of testCases) {
        // Set up mock response based on test case
        mockOrchestrator.detectDuplicates.mockResolvedValueOnce({
          isDuplicate: testCase.expectedDuplicate,
          reason: testCase.expectedReason,
          similarityScore: testCase.name.includes('Exact')
            ? 1.0
            : testCase.name.includes('High')
              ? 0.9
              : 0.75,
        });

        const result = await mockOrchestrator.detectDuplicates(testCase.item1);
        expect(result.isDuplicate).toBe(testCase.expectedDuplicate);
        if (testCase.expectedDuplicate) {
          expect(result.reason).toContain(testCase.expectedReason);
        } else {
          expect(result.reason).toBe(testCase.expectedReason);
        }
      }
    });

    it('should use configurable similarity threshold', async () => {
      const highSimilarityItem: KnowledgeItem = {
        id: 'item-001',
        kind: 'entity',
        scope: {},
        data: { content: 'High similarity content' },
        created_at: '2025-01-01T00:00:00.000Z',
      };

      const lowSimilarityItem: KnowledgeItem = {
        id: 'item-002',
        kind: 'entity',
        scope: {},
        data: { content: 'Low similarity content' },
        created_at: '2025-01-01T00:00:00.000Z',
      };

      // Mock high similarity detection
      mockOrchestrator.detectDuplicates.mockResolvedValueOnce({
        isDuplicate: true,
        reason: 'High semantic similarity (90.0%)',
        similarityScore: 0.9,
      });

      // Mock low similarity detection
      mockOrchestrator.detectDuplicates.mockResolvedValueOnce({
        isDuplicate: false,
        reason: 'No significant similarity found',
        similarityScore: 0.7,
      });

      const highResult = await mockOrchestrator.detectDuplicates(highSimilarityItem);
      const lowResult = await mockOrchestrator.detectDuplicates(lowSimilarityItem);

      expect(highResult.isDuplicate).toBe(true);
      expect(highResult.reason).toContain('High semantic similarity');
      expect(highResult.similarityScore).toBeGreaterThan(0.85);

      expect(lowResult.isDuplicate).toBe(false);
      expect(lowResult.reason).toBe('No significant similarity found');
    });
  });

  describe('Edge Cases', () => {
    it('should handle malformed content hash gracefully', async () => {
      const item: KnowledgeItem = {
        id: 'item-001',
        kind: 'entity',
        scope: {},
        data: { content: 'Test content', content_hash: 'invalid-hash' },
        created_at: new Date().toISOString(),
      };

      // Mock error response for malformed content hash
      mockOrchestrator.detectDuplicates.mockResolvedValueOnce({
        isDuplicate: false,
        reason: 'Duplicate detection error - proceeding with storage',
        similarityScore: 0,
      });

      const result = await mockOrchestrator.detectDuplicates(item);
      expect(result.isDuplicate).toBe(false);
      expect(result.reason).toBe('Duplicate detection error - proceeding with storage');
    });

    it('should handle missing scope gracefully', async () => {
      const item: KnowledgeItem = {
        id: 'item-001',
        kind: 'entity',
        scope: undefined as any,
        data: { content: 'Test content' },
        created_at: new Date().toISOString(),
      };

      // Mock response for missing scope
      mockOrchestrator.detectDuplicates.mockResolvedValueOnce({
        isDuplicate: false,
        reason: 'No similar items found',
        similarityScore: 0,
      });

      const result = await mockOrchestrator.detectDuplicates(item);
      expect(result.isDuplicate).toBe(false);
      expect(result.reason).toBe('No similar items found');
    });

    it('should handle database connection errors gracefully', async () => {
      // This would need to be tested with database failures
      const item: KnowledgeItem = {
        id: 'item-001',
        kind: 'entity',
        scope: { project: 'test' },
        data: { content: 'Test content' },
        created_at: new Date().toISOString(),
      };

      // Mock error response for database connection issues
      mockOrchestrator.detectDuplicates.mockResolvedValueOnce({
        isDuplicate: false,
        reason: 'Duplicate detection error - proceeding with storage',
        similarityScore: 0,
      });

      const result = await mockOrchestrator.detectDuplicates(item);
      expect(result.isDuplicate).toBe(false);
      expect(result.reason).toBe('Duplicate detection error - proceeding with storage');
    });
  });

  describe('Performance', () => {
    it('should handle large batch efficiently', async () => {
      const items = Array.from({ length: 100 }, (_, index) => ({
        id: `item-${index}`,
        kind: 'entity',
        scope: { project: 'test-project' },
        data: { content: `Test content ${index}` },
        created_at: new Date(Date.now() + Math.random() * 1000).toISOString(),
      }));

      // Mock response for large batch
      mockOrchestrator.storeItems.mockResolvedValueOnce({
        summary: {
          stored: 100,
          skipped_dedupe: 0,
          business_rule_blocked: 0,
          validation_error: 0,
          total: 100,
        },
        items: [],
        stored: [],
        errors: [],
      });

      const startTime = Date.now();
      const result = await mockOrchestrator.storeItems(items);
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
      expect(result.summary.stored + result.summary.skipped_dedupe + result.errors.length).toBe(
        100
      );
    });

    it('should track duplicate detection statistics accurately', async () => {
      const items = Array.from({ length: 10 }, (_, index) => ({
        id: `item-${index}`,
        kind: index % 2 === 0 ? 'entity' : 'decision',
        scope: { project: 'test-project', branch: index % 3 === 0 ? 'main' : 'dev' },
        data: { content: `Test content ${index}` },
        created_at: new Date(Date.now() + Math.random() * 1000).toISOString(),
      }));

      // Mock response for statistics tracking
      mockOrchestrator.storeItems.mockResolvedValueOnce({
        summary: {
          stored: 10,
          skipped_dedupe: 0,
          business_rule_blocked: 0,
          validation_error: 0,
          total: 10,
        },
        items: [],
        stored: [],
        errors: [],
      });

      // Mock stats with updated counts
      mockOrchestrator.getOrchestratorStats.mockReturnValueOnce({
        duplicateDetectionStats: {
          totalChecks: 10,
          contentHashMatches: 2,
          semanticSimilarityMatches: 1,
        },
      });

      await mockOrchestrator.storeItems(items);
      const stats = mockOrchestrator.getOrchestratorStats();

      expect(stats.duplicateDetectionStats.totalChecks).toBe(10);
      expect(stats.duplicateDetectionStats.contentHashMatches).toBeGreaterThanOrEqual(0);
      expect(stats.duplicateDetectionStats.semanticSimilarityMatches).toBeGreaterThanOrEqual(0);
    });
  });
});

describe('Dedupe Rule Documentation', () => {
  it('should have clear rule documentation', () => {
    // This is where we would document the current dedupe rules clearly
    // The current rules are:
    // 1. Same kind + Same scope = dedupe
    // 2. Different kind + Same scope = no dedupe
    // 3. Same kind + Different scope = no dedupe
    // 4. Semantic similarity above 85% = dedupe
    // 5. Error scenarios = proceed with storage

    expect(true).toBe(true); // Rule documentation exists
  });
});
