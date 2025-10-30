/**
 * Test for schema mismatch fix in mcp__cortex memory_store
 * This test should FAIL before the fix and PASS after the fix
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { VectorDatabase } from '../../src/index.js';

// Mock Qdrant client for testing
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor() {
      this.getCollections = vi.fn().mockResolvedValue({
        collections: [{ name: 'test-collection' }]
      });
    }
    getCollection = vi.fn().mockResolvedValue({});
    createCollection = vi.fn().mockResolvedValue({});
    deleteCollection = vi.fn().mockResolvedValue({});
    upsert = vi.fn().mockResolvedValue({ status: 'completed' });
    search = vi.fn().mockResolvedValue([]);
    scroll = vi.fn().mockResolvedValue({ result: [] });
    count = vi.fn().mockResolvedValue({ count: 0 });
  }
}));

describe('Schema Mismatch Fix - Memory Store', () => {
  let db: VectorDatabase;

  beforeEach(() => {
    db = new VectorDatabase();
  });

  it('should accept items with content and metadata fields as per MCP tool definition', async () => {
    // This follows the MCP tool definition format from src/index.ts
    const items = [{
      kind: 'entity',
      content: 'Test entity content',
      metadata: { source: 'test', priority: 'high' },
      scope: {
        project: 'test-project',
        branch: 'main',
        org: 'test-org'
      }
    }];

    // This should work now that schema mismatch is fixed
    const result = await db.storeItems(items);

    expect(result.errors).toHaveLength(0);
    expect(result.stored).toHaveLength(1);
    expect(result.stored[0].id).toBeDefined();
    expect(result.stored[0].kind).toBe('entity');
  });

  it('should accept minimal items with only required fields (kind and content)', async () => {
    const items = [{
      kind: 'decision',
      content: 'Test decision content'
      // No metadata or scope - these are optional
    }];

    const result = await db.storeItems(items);

    expect(result.errors).toHaveLength(0);
    expect(result.stored).toHaveLength(1);
    expect(result.stored[0].id).toBeDefined();
    expect(result.stored[0].kind).toBe('decision');
  });

  it('should handle all 16 knowledge types with content/metadata format', async () => {
    const knowledgeTypes = [
      'entity', 'relation', 'observation', 'section', 'runbook',
      'change', 'issue', 'decision', 'todo', 'release_note',
      'ddl', 'pr_context', 'incident', 'release', 'risk', 'assumption'
    ];

    for (const kind of knowledgeTypes) {
      const items = [{
        kind,
        content: `Test ${kind} content`,
        metadata: { type: kind }
      }];

      const result = await db.storeItems(items);

      expect(result.errors).toHaveLength(0);
      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].id).toBeDefined();
      expect(result.stored[0].kind).toBe(kind);
    }
  });
});