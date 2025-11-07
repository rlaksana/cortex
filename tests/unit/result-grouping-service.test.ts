import { ResultGroupingService } from '../../src/services/search/result-grouping-service';
import { SearchResult } from '../../src/types/core-interfaces';

describe('ResultGroupingService', () => {
  let service: ResultGroupingService;

  beforeEach(() => {
    service = new ResultGroupingService();
  });

  describe('groupResultsByParent', () => {
    it('should group chunked results by parent_id', () => {
      const searchResults: SearchResult[] = [
        {
          id: 'parent-1',
          kind: 'observation',
          scope: { project: 'test' },
          data: { is_chunk: false, total_chunks: 3 },
          created_at: '2025-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic',
        },
        {
          id: 'chunk-1-1',
          kind: 'observation',
          scope: { project: 'test' },
          data: {
            is_chunk: true,
            parent_id: 'parent-1',
            chunk_index: 0,
            total_chunks: 3,
            content: 'First chunk content',
          },
          created_at: '2025-01-01T00:00:00Z',
          confidence_score: 0.85,
          match_type: 'semantic',
        },
        {
          id: 'chunk-1-2',
          kind: 'observation',
          scope: { project: 'test' },
          data: {
            is_chunk: true,
            parent_id: 'parent-1',
            chunk_index: 1,
            total_chunks: 3,
            content: 'Second chunk content',
          },
          created_at: '2025-01-01T00:00:00Z',
          confidence_score: 0.8,
          match_type: 'semantic',
        },
      ];

      const grouped = service.groupResultsByParent(searchResults);

      expect(grouped).toHaveLength(1); // One parent group
      expect(grouped[0].parent_id).toBe('parent-1');
      expect(grouped[0].chunks).toHaveLength(2);
      expect(grouped[0].chunks[0].chunk_index).toBe(0);
      expect(grouped[0].chunks[1].chunk_index).toBe(1);
      expect(grouped[0].parent_score).toBe(0.9); // Parent item score
    });

    it('should handle non-chunked results', () => {
      const searchResults: SearchResult[] = [
        {
          id: 'regular-1',
          kind: 'decision',
          scope: { project: 'test' },
          data: { title: 'Regular item' },
          created_at: '2025-01-01T00:00:00Z',
          confidence_score: 0.7,
          match_type: 'semantic',
        },
        {
          id: 'regular-2',
          kind: 'entity',
          scope: { project: 'test' },
          data: { name: 'Another item' },
          created_at: '2025-01-01T00:00:00Z',
          confidence_score: 0.6,
          match_type: 'fuzzy',
        },
      ];

      const grouped = service.groupResultsByParent(searchResults);

      expect(grouped).toHaveLength(2);
      expect(grouped[0].parent_id).toBe('regular-1');
      expect(grouped[0].chunks).toHaveLength(0);
      expect(grouped[0].is_single_item).toBe(true);
      expect(grouped[1].parent_id).toBe('regular-2');
      expect(grouped[1].chunks).toHaveLength(0);
    });

    it('should sort chunks by chunk_index', () => {
      const searchResults: SearchResult[] = [
        {
          id: 'parent-1',
          kind: 'observation',
          scope: { project: 'test' },
          data: { is_chunk: false, total_chunks: 3 },
          created_at: '2025-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic',
        },
        {
          id: 'chunk-2', // Second chunk but first in array
          kind: 'observation',
          scope: { project: 'test' },
          data: {
            is_chunk: true,
            parent_id: 'parent-1',
            chunk_index: 1,
            total_chunks: 3,
          },
          created_at: '2025-01-01T00:00:00Z',
          confidence_score: 0.8,
          match_type: 'semantic',
        },
        {
          id: 'chunk-1', // First chunk but second in array
          kind: 'observation',
          scope: { project: 'test' },
          data: {
            is_chunk: true,
            parent_id: 'parent-1',
            chunk_index: 0,
            total_chunks: 3,
          },
          created_at: '2025-01-01T00:00:00Z',
          confidence_score: 0.85,
          match_type: 'semantic',
        },
      ];

      const grouped = service.groupResultsByParent(searchResults);

      expect(grouped[0].chunks).toHaveLength(2);
      expect(grouped[0].chunks[0].chunk_index).toBe(0);
      expect(grouped[0].chunks[1].chunk_index).toBe(1);
    });
  });

  describe('reconstructGroupedContent', () => {
    it('should reconstruct content from grouped chunks', () => {
      const groupedResult = {
        parent_id: 'parent-1',
        parent_score: 0.9,
        is_single_item: false,
        chunks: [
          {
            id: 'chunk-1',
            chunk_index: 0,
            total_chunks: 3,
            confidence_score: 0.85,
            data: { content: 'First part' },
            kind: 'observation',
            scope: { project: 'test' },
            created_at: '2025-01-01T00:00:00Z',
            match_type: 'semantic',
          },
          {
            id: 'chunk-2',
            chunk_index: 1,
            total_chunks: 3,
            confidence_score: 0.8,
            data: { content: 'Second part' },
            kind: 'observation',
            scope: { project: 'test' },
            created_at: '2025-01-01T00:00:00Z',
            match_type: 'semantic',
          },
        ],
      };

      const reconstructed = service.reconstructGroupedContent(groupedResult);

      expect(reconstructed.content).toBe('First part\n\nSecond part');
      expect(reconstructed['total_chunks']).toBe(3);
      expect(reconstructed.found_chunks).toBe(2);
      expect(reconstructed.confidence_score).toBeCloseTo(0.825, 2); // Average of chunks
    });

    it('should handle single items gracefully', () => {
      const singleItemResult = {
        parent_id: 'regular-1',
        parent_score: 0.7,
        is_single_item: true,
        chunks: [],
      };

      const reconstructed = service.reconstructGroupedContent(singleItemResult);

      expect(reconstructed['total_chunks']).toBe(1);
      expect(reconstructed.found_chunks).toBe(1);
      expect(reconstructed.confidence_score).toBe(0.7);
    });
  });

  describe('groupAndSortResults', () => {
    it('should group and sort results by parent score', () => {
      const searchResults: SearchResult[] = [
        {
          id: 'parent-2',
          kind: 'decision',
          scope: { project: 'test' },
          data: { title: 'Lower score parent' },
          created_at: '2025-01-01T00:00:00Z',
          confidence_score: 0.6,
          match_type: 'semantic',
        },
        {
          id: 'parent-1',
          kind: 'observation',
          scope: { project: 'test' },
          data: { is_chunk: false, total_chunks: 2 },
          created_at: '2025-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic',
        },
        {
          id: 'chunk-1-1',
          kind: 'observation',
          scope: { project: 'test' },
          data: {
            is_chunk: true,
            parent_id: 'parent-1',
            chunk_index: 0,
            total_chunks: 2,
          },
          created_at: '2025-01-01T00:00:00Z',
          confidence_score: 0.85,
          match_type: 'semantic',
        },
      ];

      const grouped = service.groupAndSortResults(searchResults);

      expect(grouped).toHaveLength(2);
      expect(grouped[0].parent_id).toBe('parent-1'); // Higher score first
      expect(grouped[1].parent_id).toBe('parent-2');
    });
  });

  describe('calculateGroupingStats', () => {
    it('should provide grouping statistics', () => {
      const searchResults: SearchResult[] = [
        { id: 'parent-1', data: { is_chunk: false, total_chunks: 3 } },
        { id: 'chunk-1-1', data: { is_chunk: true, parent_id: 'parent-1' } },
        { id: 'chunk-1-2', data: { is_chunk: true, parent_id: 'parent-1' } },
        { id: 'regular-1', data: { title: 'Regular' } },
        { id: 'regular-2', data: { name: 'Another' } },
      ];

      const stats = service.calculateGroupingStats(searchResults);

      expect(stats.total_results).toBe(5);
      expect(stats.grouped_results).toBe(1); // One parent with chunks
      expect(stats.single_item_results).toBe(2); // Two regular items
      expect(stats['total_chunks']_found).toBe(2);
      expect(stats.chunk_coverage_ratio).toBeCloseTo(0.48, 0.01); // 2/3 chunks found but parent item missing
    });
  });
});
