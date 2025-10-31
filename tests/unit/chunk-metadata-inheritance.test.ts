/**
 * Tests for Chunk Metadata Inheritance
 *
 * Tests that chunks properly inherit scope and TTL from parent items,
 * and that parent-child relationships are created correctly.
 *
 * @module tests/unit/chunk-metadata-inheritance.test.ts
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { ChunkingService } from '../../src/services/chunking/chunking-service';
import { getDefaultTTLPolicy, inheritTTLFromParent, TTL_DURATIONS } from '../../src/utils/tl-utils';
import type { KnowledgeItem } from '../../src/types/core-interfaces';

describe('Chunk Metadata Inheritance', () => {
  let chunkingService: ChunkingService;

  beforeEach(() => {
    chunkingService = new ChunkingService(1000, 200); // Smaller chunks for testing
  });

  describe('Scope Inheritance', () => {
    it('should inherit scope from parent to child chunks', () => {
      const parentItem: KnowledgeItem = {
        id: 'parent-id',
        kind: 'section',
        scope: {
          project: 'test-project',
          branch: 'main',
          org: 'test-org',
        },
        data: {
          title: 'Test Section',
          body_text: 'A'.repeat(3000), // Long content to trigger chunking
        },
      };

      const chunkedItems = chunkingService.createChunkedItems(parentItem);

      // Should have parent + chunks
      expect(chunkedItems.length).toBeGreaterThan(1);

      // All chunks should inherit scope from parent
      chunkedItems.forEach(item => {
        expect(item.scope).toEqual(parentItem.scope);
      });
    });

    it('should handle missing scope gracefully', () => {
      const parentItem: KnowledgeItem = {
        id: 'parent-id',
        kind: 'runbook',
        data: {
          title: 'Test Runbook',
          steps: [{ step_number: 1, description: 'Step 1' }],
          description: 'A'.repeat(3000),
        },
      };

      const chunkedItems = chunkingService.createChunkedItems(parentItem);

      // Should set empty scope object if not provided
      chunkedItems.forEach(item => {
        expect(item.scope).toEqual({});
      });
    });

    it('should preserve partial scope information', () => {
      const parentItem: KnowledgeItem = {
        id: 'parent-id',
        kind: 'incident',
        scope: {
          project: 'test-project',
          // branch and org are missing
        },
        data: {
          title: 'Test Incident',
          impact: 'Test impact',
          severity: 'medium',
          resolution_status: 'investigating',
          description: 'A'.repeat(3000),
        },
      };

      const chunkedItems = chunkingService.createChunkedItems(parentItem);

      chunkedItems.forEach(item => {
        expect(item.scope).toEqual({ project: 'test-project' });
      });
    });
  });

  describe('TTL Inheritance', () => {
    it('should inherit TTL policy from parent to child chunks', () => {
      const parentItem: KnowledgeItem = {
        id: 'parent-id',
        kind: 'pr_context',
        scope: { project: 'test' },
        data: {
          pr_number: 123,
          title: 'Test PR',
          ttl_policy: 'short',
          description: 'A'.repeat(3000),
        },
      };

      const chunkedItems = chunkingService.createChunkedItems(parentItem);

      // All chunks should inherit TTL policy from parent
      chunkedItems.forEach(item => {
        expect(item.data.ttl_policy).toBe('short');
        expect(item.data.expires_at).toBeDefined();
      });
    });

    it('should use default TTL policy for knowledge type when not specified', () => {
      const parentItem: KnowledgeItem = {
        id: 'parent-id',
        kind: 'section',
        scope: { project: 'test' },
        data: {
          title: 'Test Section',
          body_text: 'A'.repeat(3000),
        },
      };

      const chunkedItems = chunkingService.createChunkedItems(parentItem);

      chunkedItems.forEach(item => {
        expect(item.data.ttl_policy).toBe('long'); // Default for sections
        expect(item.data.expires_at).toBeDefined();
      });
    });

    it('should inherit explicit expires_at from parent', () => {
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days from now
      const parentItem: KnowledgeItem = {
        id: 'parent-id',
        kind: 'entity',
        scope: { project: 'test' },
        data: {
          entity_type: 'test',
          name: 'Test Entity',
          expires_at: expiresAt.toISOString(),
          content: 'A'.repeat(3000),
        },
      };

      const chunkedItems = chunkingService.createChunkedItems(parentItem);

      chunkedItems.forEach(item => {
        expect(item.data.expires_at).toBe(expiresAt.toISOString());
      });
    });
  });

  describe('Chunk Metadata', () => {
    it('should create proper parent-child metadata', () => {
      const parentItem: KnowledgeItem = {
        id: 'parent-id',
        kind: 'section',
        scope: { project: 'test' },
        data: {
          title: 'Test Section',
          body_text: 'A'.repeat(3000),
        },
      };

      const chunkedItems = chunkingService.createChunkedItems(parentItem);

      // Find parent and children
      const parents = chunkedItems.filter(item =>
        item.data.is_chunk === false &&
        item.metadata?.chunking_info?.is_parent === true
      );
      const children = chunkedItems.filter(item =>
        item.data.is_chunk === true &&
        item.metadata?.chunking_info?.is_child === true
      );

      // Should have exactly one parent
      expect(parents).toHaveLength(1);
      expect(children.length).toBeGreaterThan(0);

      const parent = parents[0];

      // Parent should have correct metadata
      expect(parent.data.total_chunks).toBe(children.length); // Total chunks includes children only
      expect(parent.data.chunk_index).toBe(0);
      expect(parent.data.is_chunk).toBe(false);
      expect(parent.metadata?.chunking_info).toMatchObject({
        was_chunked: true,
        is_parent: true,
        total_chunks: children.length,
      });

      // Children should have correct metadata
      children.forEach((child, index) => {
        expect(child.data.parent_id).toBe(parent.id);
        expect(child.data.chunk_index).toBe(index);
        expect(child.data.total_chunks).toBe(children.length);
        expect(child.data.is_chunk).toBe(true);
        expect(child.metadata?.chunking_info).toMatchObject({
          was_chunked: true,
          is_child: true,
          parent_id: parent.id,
          chunk_index: index,
          total_chunks: children.length,
        });
      });
    });

    it('should add chunking metadata to non-chunked items', () => {
      const shortItem: KnowledgeItem = {
        id: 'short-id',
        kind: 'runbook',
        scope: { project: 'test' },
        data: {
          title: 'Short Runbook',
          steps: [{ step_number: 1, description: 'Single step' }],
        },
      };

      const processedItems = chunkingService.processItemsForStorage([shortItem]);

      expect(processedItems).toHaveLength(1);
      const item = processedItems[0];

      expect(item.metadata?.chunking_info).toMatchObject({
        was_chunked: false,
        total_chunks: 1,
      });
      expect(item.data.is_chunk).toBe(false);
      expect(item.data.total_chunks).toBe(1);
      expect(item.data.chunk_index).toBe(0);
    });
  });

  describe('Content Handling', () => {
    it('should handle different content field types', () => {
      const testCases = [
        {
          name: 'body_text',
          data: { title: 'Test', body_text: 'A'.repeat(3000) },
        },
        {
          name: 'body_md',
          data: { title: 'Test', body_md: 'A'.repeat(3000) },
        },
        {
          name: 'description',
          data: { title: 'Test', description: 'A'.repeat(3000) },
        },
        {
          name: 'rationale',
          data: { title: 'Test', rationale: 'A'.repeat(3000) },
        },
      ];

      testCases.forEach(({ name, data }) => {
        const item: KnowledgeItem = {
          id: `test-${name}`,
          kind: 'section',
          scope: { project: 'test' },
          data,
        };

        const chunkedItems = chunkingService.createChunkedItems(item);
        expect(chunkedItems.length).toBeGreaterThan(1);

        // All chunks should have content
        chunkedItems.forEach(chunk => {
          expect(chunk.data.content).toBeDefined();
          expect(typeof chunk.data.content).toBe('string');
        });
      });
    });

    it('should combine multiple string fields when no primary content field', () => {
      const item: KnowledgeItem = {
        id: 'test-multi',
        kind: 'incident',
        scope: { project: 'test' },
        data: {
          title: 'Test Incident',
          impact: 'A'.repeat(1500),
          timeline: 'B'.repeat(1500),
        },
      };

      const chunkedItems = chunkingService.createChunkedItems(item);
      expect(chunkedItems.length).toBeGreaterThan(1);

      // Should combine fields for content
      const parent = chunkedItems.find(item => item.data.is_chunk === false);
      expect(parent?.data.content).toContain('chunks created');
    });
  });
});

describe('TTL Utilities', () => {
  describe('getDefaultTTLPolicy', () => {
    it('should return correct default TTL policies', () => {
      expect(getDefaultTTLPolicy('pr_context')).toBe('short');
      expect(getDefaultTTLPolicy('entity')).toBe('long');
      expect(getDefaultTTLPolicy('decision')).toBe('long');
      expect(getDefaultTTLPolicy('section')).toBe('long');
      expect(getDefaultTTLPolicy('runbook')).toBe('default');
      expect(getDefaultTTLPolicy('unknown')).toBe('default');
    });
  });

  describe('inheritTTLFromParent', () => {
    it('should inherit TTL policy from parent with explicit ttl_policy', () => {
      const parent: KnowledgeItem = {
        id: 'parent',
        kind: 'test',
        data: { ttl_policy: 'short' },
      };

      const inherited = inheritTTLFromParent(parent);

      expect(inherited.ttl_policy).toBe('short');
      expect(inherited.expires_at).toBeDefined();
    });

    it('should calculate expiration date correctly', () => {
      const parent: KnowledgeItem = {
        id: 'parent',
        kind: 'test',
        data: { ttl_policy: 'short' },
      };

      const inherited = inheritTTLFromParent(parent);
      const expiresAt = new Date(inherited.expires_at!);
      const expectedTime = Date.now() + TTL_DURATIONS.short;

      // Allow 1 second tolerance
      expect(Math.abs(expiresAt.getTime() - expectedTime)).toBeLessThan(1000);
    });

    it('should return no expires_at for permanent TTL', () => {
      const parent: KnowledgeItem = {
        id: 'parent',
        kind: 'test',
        data: { ttl_policy: 'permanent' },
      };

      const inherited = inheritTTLFromParent(parent);

      expect(inherited.ttl_policy).toBe('permanent');
      expect(inherited.expires_at).toBeUndefined();
    });
  });
});