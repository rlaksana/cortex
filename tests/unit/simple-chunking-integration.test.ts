import { ChunkingService } from '../../src/services/chunking/chunking-service';
import { KnowledgeItem } from '../../src/types/core-interfaces';

describe('Simple Chunking Integration Test', () => {
  let service: ChunkingService;

  beforeEach(() => {
    service = new ChunkingService(1200, 200); // Small chunk size for testing
  });

  it('should correctly add parent_id, chunk_index, and total_chunks to chunk metadata', () => {
    const largeContent = 'a'.repeat(3000); // Enough to trigger chunking

    const baseItem: KnowledgeItem = {
      id: 'test-parent-id',
      kind: 'section',
      scope: { project: 'test', branch: 'main' },
      data: {
        title: 'Test Section',
        body_text: largeContent,
      },
    };

    const chunkedItems = service.createChunkedItems(baseItem);

    // Should have parent + children
    expect(chunkedItems.length).toBeGreaterThan(1);

    // Find parent and children
    const parentItem = chunkedItems.find((item) => !item['data.is_chunk']);
    const childItems = chunkedItems.filter((item) => item['data.is_chunk']);

    expect(parentItem).toBeDefined();
    expect(childItems.length).toBeGreaterThan(0);

    // Verify parent item has correct metadata
    expect(parentItem!.data['is_chunk']).toBe(false);
    expect(parentItem!.data['parent_id']).toBeUndefined();
    expect(parentItem!.data['chunk_index']).toBe(0);
    expect(parentItem!.data['total_chunks']).toBe(childItems.length);
    expect(parentItem!.data.original_length).toBe(largeContent.length);
    expect(parentItem!.data.chunk_overlap).toBe(200);

    // Verify child items have correct metadata
    childItems.forEach((child, index) => {
      expect(child['data.is_chunk']).toBe(true);
      expect(child['data.parent_id']).toBe('test-parent-id');
      expect(child['data.chunk_index']).toBe(index);
      expect(child['data.total_chunks']).toBe(childItems.length);
      expect(child['data.original_length']).toBe(largeContent.length);
      expect(child['data.chunk_overlap']).toBe(200);
    });

    // Verify chunk_index is sequential
    const chunkIndexes = childItems.map((child) => child['data.chunk_index']).sort((a, b) => a - b);
    expect(chunkIndexes[0]).toBe(0);
    for (let i = 0; i < chunkIndexes.length; i++) {
      expect(chunkIndexes[i]).toBe(i);
    }
  });

  it('should preserve metadata structure across chunks', () => {
    const largeContent = 'a'.repeat(3000);

    const baseItem: KnowledgeItem = {
      id: 'test-with-metadata',
      kind: 'runbook',
      scope: { project: 'test', branch: 'main', org: 'test-org' },
      metadata: { author: 'test-author', version: '1.0' },
      data: {
        title: 'Test Runbook',
        body_text: largeContent,
        category: 'test',
      },
    };

    const chunkedItems = service.createChunkedItems(baseItem);
    const childItems = chunkedItems.filter((item) => item['data.is_chunk']);

    // Verify metadata is preserved
    childItems.forEach((child) => {
      expect(child.kind).toBe('runbook');
      expect(child.scope).toEqual({ project: 'test', branch: 'main', org: 'test-org' });
      expect(child.metadata['author']).toBe('test-author');
      expect(child.metadata['version']).toBe('1.0');
      expect(child['data.title']).toBe('Test Runbook');
      expect(child['data.category']).toBe('test');
    });
  });

  it('should not chunk content below threshold', () => {
    const smallContent = 'a'.repeat(1000); // Below chunking threshold

    const baseItem: KnowledgeItem = {
      kind: 'section',
      scope: { project: 'test', branch: 'main' },
      data: {
        title: 'Small Section',
        body_text: smallContent,
      },
    };

    const chunkedItems = service.createChunkedItems(baseItem);

    // Should have only one item
    expect(chunkedItems).toHaveLength(1);
    expect(chunkedItems[0].data['is_chunk']).toBe(false);
    expect(chunkedItems[0].data['total_chunks']).toBe(1);
    expect(chunkedItems[0].data['chunk_index']).toBe(0);
    expect(chunkedItems[0].data.original_length).toBe(smallContent.length);
    expect(chunkedItems[0].data.chunk_overlap).toBe(0);
  });
});
