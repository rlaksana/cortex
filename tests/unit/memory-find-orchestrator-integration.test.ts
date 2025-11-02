import { MemoryFindOrchestratorQdrant } from '../../src/services/orchestrators/memory-find-orchestrator-qdrant';
import { SearchResult } from '../../src/types/core-interfaces';
import type { IDatabase } from '../../src/db/database-interface';
import { vi } from 'vitest';

// Mock database for testing
const mockDatabase: IDatabase = {
  findItems: vi.fn().mockResolvedValue({
    hits: [],
    total: 0,
    search_time: 0,
    strategy_used: 'semantic',
  }),
  storeItems: vi.fn(),
  deleteItems: vi.fn(),
  getStats: vi.fn(),
  healthCheck: vi.fn().mockResolvedValue({ status: 'healthy' }),
  close: vi.fn(),
} as any;

describe('MemoryFindOrchestratorQdrant Integration', () => {
  let orchestrator: MemoryFindOrchestratorQdrant;

  beforeEach(() => {
    orchestrator = new MemoryFindOrchestratorQdrant(mockDatabase);
    vi.clearAllMocks();
  });

  describe('Result Grouping Service Integration', () => {
    it('should provide access to result grouping service', () => {
      const groupingService = orchestrator.getResultGroupingService();
      expect(groupingService).toBeDefined();
      expect(typeof groupingService.groupResultsByParent).toBe('function');
      expect(typeof groupingService.reconstructGroupedContent).toBe('function');
      expect(typeof groupingService.groupAndSortResults).toBe('function');
    });

    it('should group chunked search results correctly', () => {
      const groupingService = orchestrator.getResultGroupingService();

      const mockSearchResults: SearchResult[] = [
        {
          id: 'parent-1',
          kind: 'observation',
          scope: { project: 'test', branch: 'main' },
          data: { is_chunk: false, total_chunks: 3 },
          created_at: '2025-01-01T00:00:00Z',
          confidence_score: 0.9,
          match_type: 'semantic',
        },
        {
          id: 'chunk-1',
          kind: 'observation',
          scope: { project: 'test', branch: 'main' },
          data: {
            is_chunk: true,
            parent_id: 'parent-1',
            chunk_index: 0,
            total_chunks: 3,
            content: 'First part',
          },
          created_at: '2025-01-01T00:00:00Z',
          confidence_score: 0.85,
          match_type: 'semantic',
        },
        {
          id: 'chunk-2',
          kind: 'observation',
          scope: { project: 'test', branch: 'main' },
          data: {
            is_chunk: true,
            parent_id: 'parent-1',
            chunk_index: 1,
            total_chunks: 3,
            content: 'Second part',
          },
          created_at: '2025-01-01T00:00:00Z',
          confidence_score: 0.8,
          match_type: 'semantic',
        },
      ];

      const grouped = groupingService.groupResultsByParent(mockSearchResults);

      expect(grouped).toHaveLength(1);
      expect(grouped[0].parent_id).toBe('parent-1');
      expect(grouped[0].chunks).toHaveLength(2);

      const reconstructed = groupingService.reconstructGroupedContent(grouped[0]);
      expect(reconstructed.content).toContain('First part');
      expect(reconstructed.content).toContain('Second part');
      expect(reconstructed.found_chunks).toBe(2);
      expect(reconstructed.total_chunks).toBe(3);
    });

    it('should handle mixed chunked and non-chunked results', () => {
      const groupingService = orchestrator.getResultGroupingService();

      const mockResults: SearchResult[] = [
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
          id: 'chunk-1',
          kind: 'observation',
          scope: { project: 'test' },
          data: {
            is_chunk: true,
            parent_id: 'parent-1',
            chunk_index: 0,
            total_chunks: 2,
            content: 'Chunk content',
          },
          created_at: '2025-01-01T00:00:00Z',
          confidence_score: 0.85,
          match_type: 'semantic',
        },
        {
          id: 'regular-1',
          kind: 'decision',
          scope: { project: 'test' },
          data: { title: 'Regular item' },
          created_at: '2025-01-01T00:00:00Z',
          confidence_score: 0.7,
          match_type: 'keyword',
        },
      ];

      const grouped = groupingService.groupAndSortResults(mockResults);

      expect(grouped).toHaveLength(2);
      expect(grouped[0].parent_id).toBe('parent-1'); // Higher score first
      expect(grouped[1].parent_id).toBe('regular-1');
    });
  });

  describe('Orchestrator Capabilities', () => {
    it('should include result grouping in capabilities', async () => {
      const stats = await orchestrator.getOrchestratorStats();

      expect(stats.capabilities).toContain('result_grouping');
      expect(stats.supportedStrategies).toContain('semantic');
      expect(stats.supportedStrategies).toContain('keyword');
    });
  });
});
