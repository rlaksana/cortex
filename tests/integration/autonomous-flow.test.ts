/**
 * Integration tests for autonomous collaboration flows
 * Tests the complete cycle: store → find → autonomous decision-making
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
// PostgreSQL import removed - now using Qdrant;
import { memoryStore } from '../services/memory-store.ts';
import { memoryFind } from '../services/memory-find.ts';
import { loadEnv } from '../config/environment.ts';

loadEnv();

describe('Autonomous Collaboration Flows', () => {
  const testScope = { project: 'test-autonomous', branch: 'test-branch' };

  beforeAll(async () => {
    // PostgreSQL setup removed - Qdrant only
    // Test data cleanup will be handled by Qdrant operations
  });

  describe('Scenario 1: Store New Information', () => {
    it('should provide autonomous context for new item creation', async () => {
      const result = await memoryStore([
        {
          kind: 'section',
          scope: testScope,
          data: {
            title: 'Database Setup',
            body_md: 'Using PostgreSQL 18 for persistence',
          },
        },
      ]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].status).toBe('inserted');
      expect(result.autonomous_context).toBeDefined();
      expect(result.autonomous_context.action_performed).toBe('created');
      expect(result.autonomous_context.user_message_suggestion).toContain('Saved');
      expect(result.autonomous_context.recommendation).toContain('Inform user');
    });
  });

  describe('Scenario 2: Duplicate Detection', () => {
    it('should skip exact duplicates and provide context', async () => {
      // Store first time
      const first = await memoryStore([
        {
          kind: 'section',
          scope: testScope,
          data: {
            title: 'Auth Flow Test',
            body_md: 'OAuth 2.0 implementation with RS256',
          },
        },
      ]);

      expect(first.stored[0].status).toBe('inserted');

      // Store again (exact duplicate)
      const second = await memoryStore([
        {
          kind: 'section',
          scope: testScope,
          data: {
            title: 'Auth Flow Test',
            body_md: 'OAuth 2.0 implementation with RS256',
          },
        },
      ]);

      expect(second.stored[0].status).toBe('skipped_dedupe');
      expect(second.autonomous_context.action_performed).toBe('skipped');
      expect(second.autonomous_context.duplicates_found).toBeGreaterThan(0);
      expect(second.autonomous_context.user_message_suggestion).toContain('Already in memory');
    });
  });

  describe('Scenario 3: Search with Autonomous Metadata', () => {
    it('should return confidence scores for autonomous retry decisions', async () => {
      // Store some test data
      await memoryStore([
        {
          kind: 'section',
          scope: testScope,
          data: {
            title: 'Authentication Guide',
            body_md: 'Complete guide to OAuth 2.0 authentication',
          },
        },
      ]);

      // Search with good keywords
      const goodSearch = await memoryFind({
        query: 'OAuth authentication',
        scope: testScope,
        mode: 'auto',
      });

      expect(goodSearch.autonomous_metadata).toBeDefined();
      expect(goodSearch.autonomous_metadata.confidence).toMatch(/high|medium|low/);
      expect(goodSearch.autonomous_metadata.user_message_suggestion).toBeDefined();
      expect(goodSearch.autonomous_metadata.recommendation).toBeDefined();
    });

    it('should provide low confidence for poor matches', async () => {
      // Search for something that doesn't exist
      const poorSearch = await memoryFind({
        query: 'kubernetes deployment strategies',
        scope: testScope,
        mode: 'auto',
      });

      expect(poorSearch.autonomous_metadata.confidence).toBe('low');
      expect(poorSearch.autonomous_metadata.recommendation).toContain('broader keywords');
    });
  });

  describe('Scenario 4: Delete Operations', () => {
    it('should provide autonomous context for deletions', async () => {
      // Create item first
      const created = await memoryStore([
        {
          kind: 'section',
          scope: testScope,
          data: {
            title: 'Temporary Doc',
            body_md: 'This will be deleted',
          },
        },
      ]);

      const itemId = created.stored[0].id;

      // Delete it
      const deleted = await memoryStore([
        {
          operation: 'delete',
          kind: 'section',
          id: itemId,
        },
      ]);

      expect(deleted.stored[0].status).toBe('updated'); // Status for deletion
      expect(deleted.autonomous_context.action_performed).toBe('deleted');
      expect(deleted.autonomous_context.user_message_suggestion).toContain('Deleted');
    });
  });

  describe('Scenario 5: Batch Operations', () => {
    it('should provide batch context for multiple operations', async () => {
      const result = await memoryStore([
        {
          kind: 'section',
          scope: testScope,
          data: { title: 'Doc 1', body_md: 'Content 1' },
        },
        {
          kind: 'section',
          scope: testScope,
          data: { title: 'Doc 2', body_md: 'Content 2' },
        },
        {
          kind: 'section',
          scope: testScope,
          data: { title: 'Doc 3', body_md: 'Content 3' },
        },
      ]);

      expect(result.stored).toHaveLength(3);
      expect(result.autonomous_context.action_performed).toBe('batch');
      expect(result.autonomous_context.reasoning).toContain('Batch operation');
    });
  });
});
