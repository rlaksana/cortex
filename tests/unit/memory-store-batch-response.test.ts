/**
 * Failing Test for Enhanced Memory Store Batch Response
 *
 * This test demonstrates the need for improved response shape for memory_store batch operations.
 * Following TDD approach, this test should FAIL initially and pass after implementing the feature.
 *
 * Expected enhancements:
 * 1. Individual item status tracking with input_index mapping
 * 2. Detailed reason information for skipped/blocked items
 * 3. Summary statistics for quick batch overview
 * 4. business_rule_blocked status for validation failures
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../src/index';
import { ImmutabilityViolationError } from '../../src/utils/immutability';

// Mock Qdrant client with enhanced behavior for testing different scenarios
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor() {
      this.getCollections = vi.fn().mockResolvedValue({
        collections: [{ name: 'test-collection' }]
      });
      this.createCollection = vi.fn().mockResolvedValue(undefined);
      this.upsert = vi.fn().mockResolvedValue(undefined);
      this.search = vi.fn().mockResolvedValue([]);
      this.getCollection = vi.fn().mockResolvedValue({
        points_count: 0,
        status: 'green'
      });
      this.delete = vi.fn().mockResolvedValue({ status: 'completed' });
      this.count = vi.fn().mockResolvedValue({ count: 0 });
      this.healthCheck = vi.fn().mockResolvedValue(true);

      // Mock existing data for deduplication testing
      this.existingHashes = new Set(['duplicate-content-hash']);
      this.existingDecisions = new Map([
        ['existing-decision-id', {
          id: 'existing-decision-id',
          status: 'accepted',
          component: 'Authentication',
          title: 'Use OAuth 2.0',
          rationale: 'Industry standard',
          alternativesConsidered: ['Basic Auth', 'JWT']
        }]
      ]);
    }

    // Simulate finding existing items by content hash
    async findByHash(contentHash) {
      if (this.existingHashes.has(contentHash)) {
        return [{
          id: 'existing-item-id',
          content_hash: contentHash,
          created_at: '2024-01-01T00:00:00Z'
        }];
      }
      return [];
    }

    // Simulate finding existing decisions
    async findUnique(collection, where) {
      if (collection === 'adrDecision' && this.existingDecisions.has(where.id)) {
        return this.existingDecisions.get(where.id);
      }
      return null;
    }
  }
}));

describe('VectorDatabase - Enhanced memory_store batch response', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    db = new VectorDatabase();
    mockQdrant = (db as any).client;
  });

  describe('P1-T1.2: Enhanced batch response with mixed results', () => {
    it('should return detailed status for each item in batch with mixed results', async () => {
      // Arrange: Create test items covering different scenarios
      const items = [
        {
          kind: 'entity',
          content: 'New component: User Service',
          metadata: {
            component: 'User Service',
            status: 'active',
            created_by: 'test-user'
          },
          scope: {
            project: 'test-project',
            branch: 'main'
          }
        },
        {
          kind: 'decision',
          content: 'Use OAuth 2.0 for authentication', // This will be a duplicate
          metadata: {
            component: 'Authentication',
            status: 'accepted',
            title: 'Use OAuth 2.0',
            rationale: 'Industry standard',
            alternatives_considered: ['Basic Auth', 'JWT']
          },
          scope: {
            project: 'test-project',
            branch: 'main'
          }
        },
        {
          kind: 'decision',
          content: 'Update existing accepted ADR', // This will violate business rules
          metadata: {
            id: 'existing-decision-id', // References existing accepted decision
            component: 'Authentication',
            status: 'accepted',
            title: 'Use OAuth 2.0',
            rationale: 'Modified rationale - this should fail',
            alternatives_considered: ['Basic Auth']
          },
          scope: {
            project: 'test-project',
            branch: 'main'
          }
        }
      ];

      // Act: Call memory_store with batch items
      const result = await db.storeItems(items);

      // Assert: Expected enhanced response shape (this will fail with current implementation)

      // 1. Response should have items array with detailed status for each input item
      expect(result).toHaveProperty('items');
      expect(result.items).toHaveLength(3);

      // 2. Each item should have input_index to map back to original request
      expect(result.items[0]).toHaveProperty('input_index', 0);
      expect(result.items[1]).toHaveProperty('input_index', 1);
      expect(result.items[2]).toHaveProperty('input_index', 2);

      // 3. First item should be stored successfully
      expect(result.items[0]).toMatchObject({
        input_index: 0,
        status: 'stored',
        kind: 'entity',
        content: 'New component: User Service'
      });
      expect(result.items[0]).toHaveProperty('id'); // Should have generated UUID

      // 4. Second item should be skipped due to deduplication
      expect(result.items[1]).toMatchObject({
        input_index: 1,
        status: 'skipped_dedupe',
        reason: 'Duplicate content',
        kind: 'decision',
        content: 'Use OAuth 2.0 for authentication'
      });
      expect(result.items[1]).toHaveProperty('existing_id'); // Should reference existing item

      // 5. Third item should be blocked due to business rule violation
      expect(result.items[2]).toMatchObject({
        input_index: 2,
        status: 'business_rule_blocked',
        reason: 'Cannot modify accepted ADR "Use OAuth 2.0". Create a new ADR with supersedes reference instead.',
        kind: 'decision',
        content: 'Update existing accepted ADR'
      });
      expect(result.items[2]).toHaveProperty('error_code', 'IMMUTABILITY_VIOLATION');

      // 6. Response should include summary statistics
      expect(result).toHaveProperty('summary');
      expect(result.summary).toMatchObject({
        stored: 1,
        skipped_dedupe: 1,
        business_rule_blocked: 1,
        total: 3
      });

      // 7. Legacy compatibility fields should still exist
      expect(result).toHaveProperty('stored');
      expect(result).toHaveProperty('errors');
      expect(result).toHaveProperty('autonomous_context');

      // 8. Legacy stored array should contain successful items
      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].kind).toBe('entity');

      // 9. Legacy errors array should be empty (business rule violations are handled in items array)
      expect(result.errors).toHaveLength(0);

      // 10. Autonomous context should reflect mixed results
      expect(result.autonomous_context.action_performed).toBe('batch');
      expect(result.autonomous_context.duplicates_found).toBe(1);
      expect(result.autonomous_context.user_message_suggestion).toContain('Processed');
    });

    it('should handle all stored successfully scenario', async () => {
      // Arrange: All valid, unique items
      const items = [
        {
          kind: 'entity',
          content: 'New service: Payment API',
          metadata: { component: 'Payment API' }
        },
        {
          kind: 'observation',
          content: 'System performance metrics collected',
          metadata: { cpu: 45, memory: 62 }
        }
      ];

      // Act
      const result = await db.storeItems(items);

      // Assert: All items should be stored
      expect(result.items).toHaveLength(2);
      expect(result.items[0]).toMatchObject({
        input_index: 0,
        status: 'stored',
        kind: 'entity'
      });
      expect(result.items[1]).toMatchObject({
        input_index: 1,
        status: 'stored',
        kind: 'observation'
      });

      expect(result.summary).toMatchObject({
        stored: 2,
        skipped_dedupe: 0,
        business_rule_blocked: 0,
        total: 2
      });
    });

    it('should handle all duplicates scenario', async () => {
      // Arrange: All items are duplicates of existing content
      const items = [
        {
          kind: 'entity',
          content: 'Duplicate content 1', // Pre-configured as duplicate in mock
          metadata: { duplicate: true }
        },
        {
          kind: 'section',
          content: 'Duplicate content 1', // Same content hash
          metadata: { duplicate: true }
        }
      ];

      // Act
      const result = await db.storeItems(items);

      // Assert: All items should be skipped
      expect(result.items).toHaveLength(2);
      expect(result.items[0]).toMatchObject({
        input_index: 0,
        status: 'skipped_dedupe',
        reason: 'Duplicate content'
      });
      expect(result.items[1]).toMatchObject({
        input_index: 1,
        status: 'skipped_dedupe',
        reason: 'Duplicate content'
      });

      expect(result.summary).toMatchObject({
        stored: 0,
        skipped_dedupe: 2,
        business_rule_blocked: 0,
        total: 2
      });
    });

    it('should maintain backward compatibility with existing response shape', async () => {
      // Arrange: Simple valid item
      const items = [{
        kind: 'entity',
        content: 'Test entity for backward compatibility'
      }];

      // Act
      const result = await db.storeItems(items);

      // Assert: Both new and old response formats should be present
      // New format
      expect(result).toHaveProperty('items');
      expect(result).toHaveProperty('summary');

      // Old format (for backward compatibility)
      expect(result).toHaveProperty('stored');
      expect(result).toHaveProperty('errors');
      expect(result).toHaveProperty('autonomous_context');

      // Both formats should contain consistent data
      expect(result.stored).toHaveLength(1);
      expect(result.items).toHaveLength(1);
      expect(result.items[0].status).toBe('stored');
      expect(result.stored[0].id).toBe(result.items[0].id);
    });

    it('should handle validation errors in new format', async () => {
      // Arrange: Items with validation errors
      const items = [
        {
          kind: 'entity',
          content: 'Valid item'
        },
        {
          kind: 'invalid-kind', // Invalid knowledge type
          content: 'Invalid item'
        },
        null, // Completely invalid
        undefined // Also invalid
      ];

      // Act
      const result = await db.storeItems(items as any);

      // Assert: Validation errors should be in items array
      expect(result.items).toHaveLength(4);

      // First item should be valid
      expect(result.items[0]).toMatchObject({
        input_index: 0,
        status: 'stored'
      });

      // Invalid items should have validation errors
      expect(result.items[1]).toMatchObject({
        input_index: 1,
        status: 'validation_error',
        reason: expect.stringContaining('Invalid knowledge type')
      });

      expect(result.items[2]).toMatchObject({
        input_index: 2,
        status: 'validation_error',
        reason: expect.stringContaining('required')
      });

      expect(result.items[3]).toMatchObject({
        input_index: 3,
        status: 'validation_error',
        reason: expect.stringContaining('required')
      });

      expect(result.summary).toMatchObject({
        stored: 1,
        validation_error: 3,
        total: 4
      });
    });
  });
});