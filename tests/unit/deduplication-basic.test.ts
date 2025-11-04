/**
 * Basic deduplication strategy tests
 * Simple tests to verify the core functionality works
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { SkipStrategy, PreferExistingStrategy, PreferNewerStrategy, CombineStrategy, IntelligentStrategy } from '../../src/services/deduplication/strategies/index.js';

// Test data factory
const createTestItem = (overrides: any = {}) => ({
  id: `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
  kind: 'entity',
  scope: { project: 'test-project' },
  data: { content: 'Test content' },
  metadata: {},
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  ...overrides
});

describe('Basic Deduplication Strategy Tests', () => {
  describe('Skip Strategy', () => {
    let strategy: SkipStrategy;

    beforeEach(() => {
      strategy = new SkipStrategy();
    });

    it('should return all items as unique', async () => {
      const items = [
        createTestItem({ data: { content: 'Same content' } }),
        createTestItem({ data: { content: 'Same content' } }),
        createTestItem({ data: { content: 'Different content' } })
      ];

      const result = await strategy.detectDuplicates(items);

      expect(result.duplicates.length).toBe(0);
      expect(result.unique.length).toBe(3);
      expect(result.metrics.totalItems).toBe(3);
    });

    it('should handle empty array', async () => {
      const result = await strategy.detectDuplicates([]);

      expect(result.duplicates.length).toBe(0);
      expect(result.unique.length).toBe(0);
    });
  });

  describe('Prefer Existing Strategy', () => {
    let strategy: PreferExistingStrategy;

    beforeEach(() => {
      strategy = new PreferExistingStrategy({
        similarityThreshold: 0.8 // Lower threshold for testing
      });
    });

    it('should detect exact duplicates', async () => {
      const items = [
        createTestItem({
          data: { content: 'Identical content' },
          id: 'item1'
        }),
        createTestItem({
          data: { content: 'Identical content' },
          id: 'item2'
        })
      ];

      const result = await strategy.detectDuplicates(items);

      expect(result.duplicates.length).toBe(1);
      expect(result.unique.length).toBe(1);
      expect(result.duplicates[0].items.length).toBe(2);
    });

    it('should not deduplicate different content', async () => {
      const items = [
        createTestItem({ data: { content: 'Content A' } }),
        createTestItem({ data: { content: 'Content B' } })
      ];

      const result = await strategy.detectDuplicates(items);

      expect(result.duplicates.length).toBe(0);
      expect(result.unique.length).toBe(2);
    });
  });

  describe('Prefer Newer Strategy', () => {
    let strategy: PreferNewerStrategy;

    beforeEach(() => {
      strategy = new PreferNewerStrategy({
        similarityThreshold: 0.8
      });
    });

    it('should prefer newer item when timestamps differ', async () => {
      const olderItem = createTestItem({
        data: { content: 'Same content' },
        created_at: '2024-01-01T00:00:00.000Z'
      });
      const newerItem = createTestItem({
        data: { content: 'Same content' },
        created_at: '2024-01-02T00:00:00.000Z'
      });

      const result = await strategy.detectDuplicates([olderItem, newerItem]);

      expect(result.duplicates.length).toBe(1);
      expect(result.unique.length).toBe(1);
    });
  });

  describe('Combine Strategy', () => {
    let strategy: CombineStrategy;

    beforeEach(() => {
      strategy = new CombineStrategy({
        similarityThreshold: 0.8
      });
    });

    it('should combine duplicate items', async () => {
      const items = [
        createTestItem({
          data: { content: 'First part' },
          metadata: { source: 'doc1' }
        }),
        createTestItem({
          data: { content: 'First part' },
          metadata: { source: 'doc2' }
        })
      ];

      const result = await strategy.detectDuplicates(items);

      expect(result.duplicates.length).toBe(1);
      expect(result.unique.length).toBe(1);
      expect(result.unique[0].metadata).toBeDefined();
    });
  });

  describe('Intelligent Strategy', () => {
    let strategy: IntelligentStrategy;

    beforeEach(() => {
      strategy = new IntelligentStrategy({
        thresholds: {
          overall: 0.6 // Lower threshold for testing
        }
      });
    });

    it('should analyze items without errors', async () => {
      const items = [
        createTestItem({ data: { content: 'Machine learning algorithms' } }),
        createTestItem({ data: { content: 'AI algorithms for learning' } })
      ];

      const result = await strategy.detectDuplicates(items);

      expect(result.duplicates).toBeDefined();
      expect(result.unique).toBeDefined();
      expect(result.metrics.totalItems).toBe(2);
    });

    it('should handle empty input', async () => {
      const result = await strategy.detectDuplicates([]);

      expect(result.duplicates.length).toBe(0);
      expect(result.unique.length).toBe(0);
    });
  });
});