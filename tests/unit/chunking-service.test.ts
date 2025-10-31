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
      const thresholdContent = 'a'.repeat(2400); // New threshold
      const shouldChunk = service.shouldChunk(thresholdContent);
      expect(shouldChunk).toBe(false);
    });
  });

  describe('chunkContent', () => {
    it('should chunk long content with overlap', () => {
      const longContent = 'a'.repeat(12000);
      const chunks = service.chunkContent(longContent);

      expect(chunks.length).toBeGreaterThan(1);
      expect(chunks.length).toBeLessThan(15); // Should be reasonable number with smaller chunks

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
      expect(parentItem?.metadata.source).toBe('test');
      expect(parentItem?.metadata.chunking_info).toBeDefined();
      expect(parentItem?.created_at).toBe('2025-01-01T00:00:00Z');

      // Check child items preserve essential fields
      const childItems = chunkedItems.filter(item => item.data.is_chunk);
      childItems.forEach(chunk => {
        expect(chunk.kind).toBe('decision');
        expect(chunk.scope).toEqual({ project: 'test', branch: 'main', org: 'test-org' });
        expect(chunk.metadata.source).toBe('test');
        expect(chunk.metadata.chunking_info).toBeDefined();
        expect(chunk.data.title).toBe('Test Decision');
        expect(chunk.data.rationale).toBe('Test rationale');
        expect(chunk.data.component).toBe('test-component');
      });
    });

    it('should correctly set chunk metadata linking fields', () => {
      const baseItem: KnowledgeItem = {
        id: 'test-parent-id',
        kind: 'section',
        scope: { project: 'test', branch: 'main' },
        data: {
          content: 'a'.repeat(12000),
          title: 'Test Section'
        }
      };

      const chunkedItems = service.createChunkedItems(baseItem);

      // Check parent item metadata
      const parentItem = chunkedItems.find(item => !item.data.is_chunk);
      expect(parentItem).toBeDefined();
      expect(parentItem?.data.parent_id).toBeUndefined(); // Parent has no parent_id
      expect(parentItem?.data.chunk_index).toBe(0);
      expect(parentItem?.data.total_chunks).toBeGreaterThan(1);
      expect(parentItem?.data.original_length).toBe(12000);
      expect(parentItem?.data.chunk_overlap).toBe(200);
      expect(parentItem?.data.is_chunk).toBe(false);

      // Check child items metadata
      const childItems = chunkedItems.filter(item => item.data.is_chunk);
      expect(childItems.length).toBe(parentItem?.data.total_chunks);

      childItems.forEach((chunk, index) => {
        expect(chunk.data.parent_id).toBe('test-parent-id'); // Should reference parent
        expect(chunk.data.chunk_index).toBe(index); // Sequential indexing
        expect(chunk.data.total_chunks).toBe(childItems.length); // Same total for all
        expect(chunk.data.original_length).toBe(12000); // Same original length
        expect(chunk.data.chunk_overlap).toBe(200); // Same overlap
        expect(chunk.data.is_chunk).toBe(true);

        // Check metadata chunking_info matches data fields
        expect(chunk.metadata.chunking_info.parent_id).toBe('test-parent-id');
        expect(chunk.metadata.chunking_info.chunk_index).toBe(index);
        expect(chunk.metadata.chunking_info.total_chunks).toBe(childItems.length);
        expect(chunk.metadata.chunking_info.is_child).toBe(true);
      });

      // Check metadata chunking_info for parent
      expect(parentItem?.metadata.chunking_info.is_parent).toBe(true);
      expect(parentItem?.metadata.chunking_info.total_chunks).toBe(childItems.length);
      expect(parentItem?.metadata.chunking_info.chunk_size).toBe(1200);
      expect(parentItem?.metadata.chunking_info.overlap_size).toBe(200);
    });

    it('should ensure chunk_index is sequential starting from 0', () => {
      const baseItem: KnowledgeItem = {
        id: 'sequential-test',
        kind: 'runbook',
        scope: { project: 'test', branch: 'main' },
        data: {
          content: 'a'.repeat(12000),
          title: 'Sequential Test'
        }
      };

      const chunkedItems = service.createChunkedItems(baseItem);
      const childItems = chunkedItems.filter(item => item.data.is_chunk);

      // Extract chunk_index values and sort them
      const chunkIndexes = childItems.map(chunk => chunk.data.chunk_index).sort((a, b) => a - b);

      // Should start from 0
      expect(chunkIndexes[0]).toBe(0);

      // Should be sequential with no gaps
      for (let i = 0; i < chunkIndexes.length; i++) {
        expect(chunkIndexes[i]).toBe(i);
      }

      // Should match total count
      expect(Math.max(...chunkIndexes) + 1).toBe(childItems.length);
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
      expect(stats.recommended_chunk_size).toBe(1200); // Updated chunk size
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

  describe('shouldChunkItem (Type-Based Filtering)', () => {
    const largeContent = 'a'.repeat(12000); // Over chunking threshold

    describe('Chunkable Types (should chunk when content is large)', () => {
      it('should chunk section type with large content', () => {
        const sectionItem: KnowledgeItem = {
          kind: 'section',
          scope: { project: 'test', branch: 'main' },
          data: {
            content: largeContent,
            title: 'Large Section'
          }
        };

        expect(service.shouldChunkItem(sectionItem)).toBe(true);
      });

      it('should chunk runbook type with large content', () => {
        const runbookItem: KnowledgeItem = {
          kind: 'runbook',
          scope: { project: 'test', branch: 'main' },
          data: {
            content: largeContent,
            title: 'Large Runbook'
          }
        };

        expect(service.shouldChunkItem(runbookItem)).toBe(true);
      });

      it('should chunk incident type with large content', () => {
        const incidentItem: KnowledgeItem = {
          kind: 'incident',
          scope: { project: 'test', branch: 'main' },
          data: {
            content: largeContent,
            title: 'Large Incident'
          }
        };

        expect(service.shouldChunkItem(incidentItem)).toBe(true);
      });

      it('should not chunk chunkable types with small content', () => {
        const smallContent = 'a'.repeat(1000); // Below chunking threshold

        const sectionItem: KnowledgeItem = {
          kind: 'section',
          scope: { project: 'test', branch: 'main' },
          data: { content: smallContent, title: 'Small Section' }
        };

        const runbookItem: KnowledgeItem = {
          kind: 'runbook',
          scope: { project: 'test', branch: 'main' },
          data: { content: smallContent, title: 'Small Runbook' }
        };

        const incidentItem: KnowledgeItem = {
          kind: 'incident',
          scope: { project: 'test', branch: 'main' },
          data: { content: smallContent, title: 'Small Incident' }
        };

        expect(service.shouldChunkItem(sectionItem)).toBe(false);
        expect(service.shouldChunkItem(runbookItem)).toBe(false);
        expect(service.shouldChunkItem(incidentItem)).toBe(false);
      });
    });

    describe('Non-Chunkable Types (should never chunk regardless of size)', () => {
      const nonChunkableTypes = [
        'entity', 'relation', 'observation', 'decision', 'todo',
        'release_note', 'ddl', 'pr_context', 'assumption', 'change',
        'release', 'risk', 'issue'
      ];

      nonChunkableTypes.forEach(type => {
        it(`should not chunk ${type} type even with large content`, () => {
          const item: KnowledgeItem = {
            kind: type as any,
            scope: { project: 'test', branch: 'main' },
            data: {
              content: largeContent,
              title: `Large ${type}`
            }
          };

          expect(service.shouldChunkItem(item)).toBe(false);
        });
      });
    });
  });

  describe('processItemsForStorage (Selective Type Processing)', () => {
    it('should only chunk chunkable types and leave others unchanged', () => {
      const largeContent = 'a'.repeat(12000);
      const smallContent = 'a'.repeat(1000);

      const items: KnowledgeItem[] = [
        // Chunkable types with large content (should be chunked)
        {
          kind: 'section',
          scope: { project: 'test', branch: 'main' },
          data: { content: largeContent, title: 'Large Section' }
        },
        {
          kind: 'runbook',
          scope: { project: 'test', branch: 'main' },
          data: { content: largeContent, title: 'Large Runbook' }
        },
        {
          kind: 'incident',
          scope: { project: 'test', branch: 'main' },
          data: { content: largeContent, title: 'Large Incident' }
        },
        // Chunkable types with small content (should not be chunked)
        {
          kind: 'section',
          scope: { project: 'test', branch: 'main' },
          data: { content: smallContent, title: 'Small Section' }
        },
        // Non-chunkable types with large content (should not be chunked)
        {
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: { content: largeContent, title: 'Large Decision' }
        },
        {
          kind: 'observation',
          scope: { project: 'test', branch: 'main' },
          data: { content: largeContent, title: 'Large Observation' }
        },
        {
          kind: 'todo',
          scope: { project: 'test', branch: 'main' },
          data: { content: largeContent, title: 'Large Todo' }
        }
      ];

      const processedItems = service.processItemsForStorage(items);

      // Should have more items due to chunking of the 3 large chunkable items
      expect(processedItems.length).toBeGreaterThan(items.length);

      // Count chunked vs non-chunked items
      const chunkedItems = processedItems.filter(item => item.data.is_chunk);
      const nonChunkedItems = processedItems.filter(item => !item.data.is_chunk);

      // Should have chunk items for the large chunkable types
      expect(chunkedItems.length).toBeGreaterThan(0);
      chunkedItems.forEach(chunk => {
        expect(['section', 'runbook', 'incident']).toContain(chunk.kind);
        expect(chunk.data.is_chunk).toBe(true);
      });

      // Should have parent items for chunked content
      const parentItems = nonChunkedItems.filter(item => item.data.total_chunks > 1);
      expect(parentItems).toHaveLength(3);
      parentItems.forEach(parent => {
        expect(['section', 'runbook', 'incident']).toContain(parent.kind);
        expect(parent.data.total_chunks).toBeGreaterThan(1);
        expect(parent.data.original_length).toBe(largeContent.length);
      });

      // Should have single items for small chunkable types and all non-chunkable types
      const singleItems = nonChunkedItems.filter(item => item.data.total_chunks === 1);
      expect(singleItems.length).toBe(4); // 1 small section + 3 large non-chunkable types
      singleItems.forEach(item => {
        expect(item.data.total_chunks).toBe(1);
        expect(item.data.original_length).toBeDefined();
      });
    });
  });
});