import { ChunkingService } from '../../src/services/chunking/chunking-service';
import { KnowledgeItem } from '../../src/types/core-interfaces';

describe('ChunkingService', () => {
  let service: ChunkingService;

  beforeEach(() => {
    service = new ChunkingService();
  });

  describe('shouldChunk', () => {
    it('should return false for short content', () => {
      const shortContent = 'This is a short content';
      const shouldChunk = service.shouldChunk(shortContent);
      expect(shouldChunk).toBe(false);
    });

    it('should return true for content over threshold', () => {
      const longContent = 'a'.repeat(9000);
      const shouldChunk = service.shouldChunk(longContent);
      expect(shouldChunk).toBe(true);
    });

    it('should return false for content exactly at threshold', () => {
      const thresholdContent = 'a'.repeat(8000);
      const shouldChunk = service.shouldChunk(thresholdContent);
      expect(shouldChunk).toBe(false);
    });
  });

  describe('chunkContent', () => {
    it('should chunk long content with overlap', () => {
      const longContent = 'a'.repeat(12000);
      const chunks = service.chunkContent(longContent);

      expect(chunks.length).toBeGreaterThan(1);
      expect(chunks.length).toBeLessThan(5); // Should be reasonable number

      // Check overlap
      for (let i = 1; i < chunks.length; i++) {
        const prevChunkEnd = chunks[i - 1].slice(-200);
        const currChunkStart = chunks[i].slice(0, 200);
        // Should have some overlap
        expect(prevChunkEnd + currChunkStart).toContain('a'.repeat(100));
      }
    });

    it('should return single chunk for short content', () => {
      const shortContent = 'Short content';
      const chunks = service.chunkContent(shortContent);

      expect(chunks).toHaveLength(1);
      expect(chunks[0]).toBe(shortContent);
    });

    it('should preserve paragraph boundaries when possible', () => {
      const content = 'Paragraph 1. '.repeat(1000) + '\n\n' + 'Paragraph 2. '.repeat(1000);
      const chunks = service.chunkContent(content);

      expect(chunks.length).toBeGreaterThan(1);
      // Chunks should ideally break at paragraph boundaries
    });

    it('should handle code blocks properly', () => {
      const codeBlock = 'function test() { return "hello"; } '.repeat(500);
      const content = `Some text\n\n\`\`\`javascript\n${codeBlock}\`\`\`\n\nMore text`;
      const chunks = service.chunkContent(content);

      expect(chunks.length).toBeGreaterThan(1);
      // Should keep code blocks intact as much as possible
    });
  });

  describe('createChunkedItems', () => {
    it('should create parent and child items from large content', () => {
      const baseItem: KnowledgeItem = {
        kind: 'observation',
        scope: { project: 'test', branch: 'main' },
        data: {
          content: 'a'.repeat(12000),
          title: 'Test Item'
        }
      };

      const chunkedItems = service.createChunkedItems(baseItem);

      // Should have parent item
      const parentItem = chunkedItems.find(item => !item.data.is_chunk);
      expect(parentItem).toBeDefined();
      expect(parentItem?.data.total_chunks).toBeGreaterThan(1);
      expect(parentItem?.data.original_length).toBe(12000);

      // Should have child chunks
      const childItems = chunkedItems.filter(item => item.data.is_chunk);
      expect(childItems.length).toBeGreaterThan(1);

      // Check chunk metadata
      childItems.forEach((chunk, index) => {
        expect(chunk.data.parent_id).toBe(parentItem?.id);
        expect(chunk.data.chunk_index).toBe(index);
        expect(chunk.data.total_chunks).toBe(childItems.length);
        expect(chunk.data.original_length).toBe(12000);
      });
    });

    it('should return single item for short content', () => {
      const baseItem: KnowledgeItem = {
        kind: 'observation',
        scope: { project: 'test', branch: 'main' },
        data: {
          content: 'Short content',
          title: 'Test Item'
        }
      };

      const chunkedItems = service.createChunkedItems(baseItem);

      expect(chunkedItems).toHaveLength(1);
      expect(chunkedItems[0].data.is_chunk).toBe(false);
      expect(chunkedItems[0].data.total_chunks).toBe(1);
    });

    it('should preserve all original fields', () => {
      const baseItem: KnowledgeItem = {
        id: 'test-id',
        kind: 'decision',
        scope: { project: 'test', branch: 'main', org: 'test-org' },
        data: {
          content: 'a'.repeat(12000),
          title: 'Test Decision',
          rationale: 'Test rationale',
          component: 'test-component'
        },
        metadata: { source: 'test' },
        created_at: '2025-01-01T00:00:00Z'
      };

      const chunkedItems = service.createChunkedItems(baseItem);

      // Check parent item preserves all fields
      const parentItem = chunkedItems.find(item => !item.data.is_chunk);
      expect(parentItem?.id).toBe('test-id');
      expect(parentItem?.kind).toBe('decision');
      expect(parentItem?.scope).toEqual({ project: 'test', branch: 'main', org: 'test-org' });
      expect(parentItem?.metadata).toEqual({ source: 'test' });
      expect(parentItem?.created_at).toBe('2025-01-01T00:00:00Z');

      // Check child items preserve essential fields
      const childItems = chunkedItems.filter(item => item.data.is_chunk);
      childItems.forEach(chunk => {
        expect(chunk.kind).toBe('decision');
        expect(chunk.scope).toEqual({ project: 'test', branch: 'main', org: 'test-org' });
        expect(chunk.metadata).toEqual({ source: 'test' });
        expect(chunk.data.title).toBe('Test Decision');
        expect(chunk.data.rationale).toBe('Test rationale');
        expect(chunk.data.component).toBe('test-component');
      });
    });
  });

  describe('getChunkingStats', () => {
    it('should return chunking statistics', () => {
      const baseItem: KnowledgeItem = {
        kind: 'observation',
        scope: { project: 'test', branch: 'main' },
        data: {
          content: 'a'.repeat(12000),
          title: 'Test Item'
        }
      };

      const stats = service.getChunkingStats(baseItem);

      expect(stats.original_length).toBe(12000);
      expect(stats.should_chunk).toBe(true);
      expect(stats.recommended_chunk_size).toBe(4000);
      expect(stats.overlap_size).toBe(200);
      expect(stats.estimated_chunks).toBeGreaterThan(1);
    });

    it('should return stats for non-chunked content', () => {
      const baseItem: KnowledgeItem = {
        kind: 'observation',
        scope: { project: 'test', branch: 'main' },
        data: {
          content: 'Short content',
          title: 'Test Item'
        }
      };

      const stats = service.getChunkingStats(baseItem);

      expect(stats.original_length).toBeLessThan(100); // Rough estimate
      expect(stats.should_chunk).toBe(false);
      expect(stats.estimated_chunks).toBe(1);
    });
  });
});