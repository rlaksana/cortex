/**
 * Test for P1-T1.4: Expose dedupe threshold in autonomous_context.dedupe_threshold_used
 *
 * This test validates that the deduplication threshold and method information
 * are properly exposed in the autonomous context response.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../src/index';

// Mock Qdrant client for testing
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor() {
      this.getCollections = vi.fn().mockResolvedValue({
        collections: [{ name: 'test-collection' }],
      });
      this.createCollection = vi.fn().mockResolvedValue(undefined);
      this.upsert = vi.fn().mockResolvedValue(undefined);
      this.search = vi.fn().mockResolvedValue([]);
      this.getCollection = vi.fn().mockResolvedValue({
        points_count: 0,
        status: 'green',
      });
      this.delete = vi.fn().mockResolvedValue({ status: 'completed' });
      this.count = vi.fn().mockResolvedValue({ count: 0 });
      this.healthCheck = vi.fn().mockResolvedValue(true);
    }
  },
}));

describe('P1-T1.4: Dedupe Threshold Exposure', () => {
  let vectorDb: VectorDatabase;

  beforeEach(() => {
    vectorDb = new VectorDatabase();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Dedupe threshold exposure in autonomous context', () => {
    it('should expose dedupe_threshold_used field in autonomous context', async () => {
      // Test items that will trigger deduplication
      const items = [
        {
          kind: 'entity',
          content: 'Test entity 1',
          data: { name: 'Entity 1' },
          scope: { project: 'test-project', branch: 'main' },
        },
        {
          kind: 'entity',
          content: 'duplicate-content test item',
          data: { name: 'Duplicate Entity' },
          scope: { project: 'test-project', branch: 'main' },
        },
      ];

      const result = await vectorDb.storeItems(items);

      // Verify P1-T1.4: dedupe_threshold_used field is present
      expect(result.autonomous_context).toHaveProperty('dedupe_threshold_used');
      expect(typeof result.autonomous_context.dedupe_threshold_used).toBe('number');
      expect(result.autonomous_context.dedupe_threshold_used).toBe(0.85);
    });

    it('should expose dedupe_method field in autonomous context', async () => {
      // Test items with duplicates to ensure combined method is used
      const items = [
        {
          kind: 'entity',
          content: 'Test entity 1',
          data: { name: 'Entity 1' },
          scope: { project: 'test-project', branch: 'main' },
        },
        {
          kind: 'entity',
          content: 'duplicate-content test item',
          data: { name: 'Duplicate Entity' },
          scope: { project: 'test-project', branch: 'main' },
        },
      ];

      const result = await vectorDb.storeItems(items);

      // Verify P1-T1.4: dedupe_method field is present
      expect(result.autonomous_context).toHaveProperty('dedupe_method');
      expect(typeof result.autonomous_context.dedupe_method).toBe('string');
      expect(['content_hash', 'semantic_similarity', 'combined', 'none']).toContain(
        result.autonomous_context.dedupe_method
      );
    });

    it('should expose dedupe_enabled field in autonomous context', async () => {
      const items = [
        {
          kind: 'entity',
          content: 'Test entity',
          data: { name: 'Entity' },
          scope: { project: 'test-project', branch: 'main' },
        },
      ];

      const result = await vectorDb.storeItems(items);

      // Verify P1-T1.4: dedupe_enabled field is present
      expect(result.autonomous_context).toHaveProperty('dedupe_enabled');
      expect(typeof result.autonomous_context.dedupe_enabled).toBe('boolean');
      expect(result.autonomous_context.dedupe_enabled).toBe(true);
    });

    it('should show combined method when duplicates are found', async () => {
      // Test with items that will result in duplicates
      const items = [
        {
          kind: 'entity',
          content: 'New item',
          data: { name: 'New Entity' },
          scope: { project: 'test-project', branch: 'main' },
        },
        {
          kind: 'entity',
          content: 'duplicate-content test item',
          data: { name: 'Duplicate Entity' },
          scope: { project: 'test-project', branch: 'main' },
        },
        {
          kind: 'decision',
          content: 'Use OAuth 2.0 for authentication',
          data: { title: 'Auth Decision' },
          scope: { project: 'test-project', branch: 'main' },
        },
      ];

      const result = await vectorDb.storeItems(items);

      // When duplicates are found, method should be 'combined'
      expect(result.autonomous_context.dedupe_method).toBe('combined');
      expect(result.autonomous_context.dedupe_threshold_used).toBe(0.85);
      expect(result.autonomous_context.dedupe_enabled).toBe(true);
    });

    it('should show content_hash method when no duplicates are found', async () => {
      // Test with items that won't result in duplicates
      const items = [
        {
          kind: 'entity',
          content: 'Unique test entity',
          data: { name: 'Unique Entity' },
          scope: { project: 'test-project', branch: 'main' },
        },
        {
          kind: 'decision',
          content: 'Unique test decision',
          data: { title: 'Unique Decision' },
          scope: { project: 'test-project', branch: 'main' },
        },
      ];

      const result = await vectorDb.storeItems(items);

      // When no duplicates are found, method should be 'content_hash'
      expect(result.autonomous_context.dedupe_method).toBe('content_hash');
      expect(result.autonomous_context.dedupe_threshold_used).toBe(0.85);
      expect(result.autonomous_context.dedupe_enabled).toBe(true);
    });

    it('should maintain backward compatibility with existing autonomous_context fields', async () => {
      const items = [
        {
          kind: 'entity',
          content: 'Test entity',
          data: { name: 'Entity' },
          scope: { project: 'test-project', branch: 'main' },
        },
      ];

      const result = await vectorDb.storeItems(items);

      // Verify all existing fields are still present
      expect(result.autonomous_context).toHaveProperty('action_performed');
      expect(result.autonomous_context).toHaveProperty('similar_items_checked');
      expect(result.autonomous_context).toHaveProperty('duplicates_found');
      expect(result.autonomous_context).toHaveProperty('contradictions_detected');
      expect(result.autonomous_context).toHaveProperty('recommendation');
      expect(result.autonomous_context).toHaveProperty('reasoning');
      expect(result.autonomous_context).toHaveProperty('user_message_suggestion');

      // Verify new P1-T1.4 fields are present
      expect(result.autonomous_context).toHaveProperty('dedupe_threshold_used');
      expect(result.autonomous_context).toHaveProperty('dedupe_method');
      expect(result.autonomous_context).toHaveProperty('dedupe_enabled');
    });

    it('should handle empty input gracefully', async () => {
      const result = await vectorDb.storeItems([]);

      // Should still expose dedupe fields even with no items
      expect(result.autonomous_context).toHaveProperty('dedupe_threshold_used');
      expect(result.autonomous_context).toHaveProperty('dedupe_method');
      expect(result.autonomous_context).toHaveProperty('dedupe_enabled');
      expect(result.autonomous_context.dedupe_enabled).toBe(false);
    });
  });

  describe('Threshold value validation', () => {
    it('should use the correct threshold value (0.85)', async () => {
      const items = [
        {
          kind: 'entity',
          content: 'Test entity',
          data: { name: 'Entity' },
          scope: { project: 'test-project', branch: 'main' },
        },
      ];

      const result = await vectorDb.storeItems(items);

      // Verify the specific threshold value
      expect(result.autonomous_context.dedupe_threshold_used).toBe(0.85);
    });
  });
});
