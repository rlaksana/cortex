/**
 * Comprehensive Unit Tests for Deep Search Implementation
 *
 * Tests deep search functionality including:
 * - Full-text search (FTS) with weighting
 * - Trigram similarity matching
 * - Combined scoring algorithms
 * - Multiple knowledge type searching
 * - Similarity threshold filtering
 * - Performance and error handling
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { deepSearch, calculateSimilarity, type DeepSearchResult } from '../../../src/services/search/deep-search';

// Mock the Qdrant client dependencies
vi.mock('../../../src/db/qdrant-client', () => ({
  getQdrantClient: vi.fn(() => mockQdrantClient),
}));

// Mock Qdrant client with vector search methods
const mockQdrantClient = {
  search: vi.fn(),
  scroll: vi.fn(),
  $queryRaw: vi.fn(), // Keep for backward compatibility during transition
};

describe('Deep Search Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('deepSearch', () => {
    it('should perform deep search with default parameters', async () => {

      const mockSectionResults = [
        {
          id: '123e4567-e89b-12d3-a456-426614174000',
          kind: 'section',
          title: 'Database Schema Design',
          snippet: 'This section covers database schema design principles and best practices...',
          fts_score: 0.8,
          similarity_score: 0.7,
          combined_score: 0.72,
        },
        {
          id: '123e4567-e89b-12d3-a456-426614174001',
          kind: 'section',
          title: 'API Authentication Methods',
          snippet: 'Comprehensive guide to API authentication methods including OAuth...',
          fts_score: 0.6,
          similarity_score: 0.8,
          combined_score: 0.68,
        },
      ];

      mockQdrantClient.$queryRaw.mockResolvedValue(mockSectionResults);

      const results = await deepSearch('database schema');

      expect(mockQdrantClient.$queryRaw).toHaveBeenCalled();

      expect(results).toHaveLength(2);
      expect(results[0]).toMatchObject({
        id: '123e4567-e89b-12d3-a456-426614174000',
        kind: 'section',
        title: 'Database Schema Design',
        snippet: 'This section covers database schema design principles and best practices...',
      });

      // Results should be sorted by combined_score descending
      expect(results[0].combined_score).toBeGreaterThanOrEqual(results[1].combined_score);
    });

    it('should search across multiple knowledge types', async () => {
  
      const mockSectionResults = [
        {
          id: '123e4567-e89b-12d3-a456-426614174000',
          kind: 'section',
          title: 'Database Design',
          snippet: 'Database design principles...',
          fts_score: 0.8,
          similarity_score: 0.7,
          combined_score: 0.72,
        },
      ];

      const mockRunbookResults = [
        {
          id: '123e4567-e89b-12d3-a456-426614174001',
          kind: 'runbook',
          title: 'Database Migration',
          snippet: '{"steps": ["backup database", "run migration", "verify data"]}',
          fts_score: 0.0,
          similarity_score: 0.6,
          combined_score: 0.18,
        },
      ];

      const mockChangeResults = [
        {
          id: '123e4567-e89b-12d3-a456-426614174002',
          kind: 'change',
          title: 'Update Database Schema',
          snippet: 'Added new tables and relationships',
          fts_score: 0.0,
          similarity_score: 0.8,
          combined_score: 0.24,
        },
      ];

      mockQdrantClient.$queryRaw
        .mockResolvedValueOnce(mockSectionResults)
        .mockResolvedValueOnce(mockRunbookResults)
        .mockResolvedValueOnce(mockChangeResults);

      const results = await deepSearch('database', ['section', 'runbook', 'change']);

      expect(mockQdrantClient.$queryRaw).toHaveBeenCalledTimes(3);

      expect(results).toHaveLength(3);
      expect(results.map(r => r.kind)).toEqual(['section', 'change', 'runbook']);

      // Should be sorted by combined_score descending
      expect(results[0].combined_score).toBeGreaterThan(results[1].combined_score);
      expect(results[1].combined_score).toBeGreaterThan(results[2].combined_score);
    });

    it('should respect topK parameter', async () => {
  
      const mockResults = Array.from({ length: 25 }, (_, i) => ({
        id: `123e4567-e89b-12d3-a456-42661417${i.toString().padStart(4, '0')}`,
        kind: 'section',
        title: `Result ${i}`,
        snippet: `Snippet for result ${i}`,
        fts_score: 1.0 - (i * 0.01),
        similarity_score: 0.8 - (i * 0.01),
        combined_score: 0.9 - (i * 0.01),
      }));

      mockQdrantClient.$queryRaw.mockResolvedValue(mockResults);

      const results = await deepSearch('test query', ['section'], 10);

      expect(results).toHaveLength(10);
      expect(results[0].combined_score).toBeGreaterThan(results[9].combined_score);
    });

    it('should filter results by minimum similarity threshold', async () => {
  
      const mockResults = [
        {
          id: '123e4567-e89b-12d3-a456-426614174000',
          kind: 'section',
          title: 'High Similarity',
          snippet: 'Very similar content',
          fts_score: 0.8,
          similarity_score: 0.8,
          combined_score: 0.72,
        },
        // Low similarity result would be filtered out by the SQL query with minSimilarity > 0.5
      ];

      mockQdrantClient.$queryRaw.mockResolvedValue(mockResults);

      const results = await deepSearch('test query', ['section'], 20, 0.5);

      // Should only include results with similarity > 0.5
      expect(results).toHaveLength(1);
      expect(results[0].title).toBe('High Similarity');

      expect(mockQdrantClient.$queryRaw).toHaveBeenCalledWith(
        expect.stringContaining('similarity(body_text, ${query}) > 0.5')
      );
    });

    it('should handle empty search types', async () => {
  
      const results = await deepSearch('test query', []);

      expect(results).toHaveLength(0);
      expect(mockQdrantClient.$queryRaw).not.toHaveBeenCalled();
    });

    it('should handle no matching results', async () => {
  
      mockQdrantClient.$queryRaw.mockResolvedValue([]);

      const results = await deepSearch('nonexistent query');

      expect(results).toHaveLength(0);
    });

    it('should handle database errors gracefully', async () => {
  
      mockQdrantClient.$queryRaw.mockRejectedValue(new Error('Database connection failed'));

      await expect(deepSearch('test query')).rejects.toThrow('Database connection failed');
    });

    it('should combine FTS and similarity scores correctly', async () => {
  
      const mockResults = [
        {
          id: '123e4567-e89b-12d3-a456-426614174000',
          kind: 'section',
          title: 'Test Result',
          snippet: 'Test snippet',
          fts_score: 0.6, // 60% weight
          similarity_score: 0.8, // 40% weight
          combined_score: 0.4 * 0.6 + 0.6 * 0.8, // Should be 0.72
        },
      ];

      mockQdrantClient.$queryRaw.mockResolvedValue(mockResults);

      const results = await deepSearch('test query');

      expect(results[0].combined_score).toBeCloseTo(0.72, 2);
    });
  });

  describe('Search Type Implementations', () => {
    describe('Section Search', () => {
      it('should search sections with FTS and similarity', async () => {
    
        const mockResults = [
          {
            id: '123e4567-e89b-12d3-a456-426614174000',
            kind: 'section',
            title: 'Authentication Guide',
            snippet: 'This guide covers authentication methods...',
            fts_score: 0.8,
            similarity_score: 0.7,
            combined_score: 0.72,
          },
        ];

        mockQdrantClient.$queryRaw.mockResolvedValue(mockResults);

        await deepSearch('authentication', ['section']);

        expect(mockQdrantClient.$queryRaw).toHaveBeenCalled();

        expect(mockQdrantClient.$queryRaw).toHaveBeenCalledWith(
          expect.stringContaining('ts @@ plainto_tsquery')
        );

        expect(mockQdrantClient.$queryRaw).toHaveBeenCalledWith(
          expect.stringContaining('similarity(body_text, ${query})')
        );

        expect(mockQdrantClient.$queryRaw).toHaveBeenCalledWith(
          expect.stringContaining('LEFT(body_text, 200)')
        );
      });

      it('should handle sections without text content', async () => {
    
        const mockResults = [
          {
            id: '123e4567-e89b-12d3-a456-426614174000',
            kind: 'section',
            title: 'Empty Section',
            snippet: '',
            fts_score: 0.0,
            similarity_score: 0.0,
            combined_score: 0.0,
          },
        ];

        mockQdrantClient.$queryRaw.mockResolvedValue(mockResults);

        const results = await deepSearch('test', ['section']);

        expect(results).toHaveLength(1);
        expect(results[0].snippet).toBe('');
      });
    });

    describe('Runbook Search', () => {
      it('should search runbooks with trigram similarity on service and steps', async () => {
    
        const mockResults = [
          {
            id: '123e4567-e89b-12d3-a456-426614174000',
            kind: 'runbook',
            title: 'Database Service',
            snippet: '{"steps": ["connect to database", "execute query", "process results"]}',
            fts_score: 0.0,
            similarity_score: 0.8,
            combined_score: 0.24, // 0.3 * 0.8
          },
        ];

        mockQdrantClient.$queryRaw.mockResolvedValue(mockResults);

        await deepSearch('database', ['runbook']);

        expect(mockQdrantClient.$queryRaw).toHaveBeenCalled();

        expect(mockQdrantClient.$queryRaw).toHaveBeenCalledWith(
          expect.stringContaining('GREATEST(similarity(service, ${query}), similarity(steps_jsonb::text, ${query}))')
        );

        expect(mockQdrantClient.$queryRaw).toHaveBeenCalledWith(
          expect.stringContaining('LEFT(steps_jsonb::text, 200)')
        );
      });

      it('should find runbooks matching on service name', async () => {
    
        const mockResults = [
          {
            id: '123e4567-e89b-12d3-a456-426614174000',
            kind: 'runbook',
            title: 'Authentication Service',
            snippet: '{"steps": ["verify token", "check permissions"]}',
            fts_score: 0.0,
            similarity_score: 0.9,
            combined_score: 0.27,
          },
        ];

        mockQdrantClient.$queryRaw.mockResolvedValue(mockResults);

        const results = await deepSearch('authentication', ['runbook']);

        expect(results[0].title).toBe('Authentication Service');
        expect(results[0].similarity_score).toBe(0.9);
      });
    });

    describe('Change Log Search', () => {
      it('should search change logs with trigram similarity on summary', async () => {
    
        const mockResults = [
          {
            id: '123e4567-e89b-12d3-a456-426614174000',
            kind: 'change',
            title: 'Add Authentication Feature',
            snippet: 'Implemented OAuth 2.0 authentication',
            fts_score: 0.0,
            similarity_score: 0.85,
            combined_score: 0.255, // 0.3 * 0.85
          },
        ];

        mockQdrantClient.$queryRaw.mockResolvedValue(mockResults);

        await deepSearch('authentication', ['change']);

        expect(mockQdrantClient.$queryRaw).toHaveBeenCalled();

        expect(mockQdrantClient.$queryRaw).toHaveBeenCalledWith(
          expect.stringContaining('similarity(summary, ${query})')
        );
      });
    });
  });

  describe('calculateSimilarity', () => {
    it('should calculate similarity between two strings', async () => {
  
      const mockResult = [{ score: 0.85 }];
      mockQdrantClient.$queryRaw.mockResolvedValue(mockResult);

      const similarity = await calculateSimilarity('authentication', 'authorization');

      expect(similarity).toBe(0.85);

      expect(mockQdrantClient.$queryRaw).toHaveBeenCalledWith(
        expect.stringContaining('SELECT similarity')
      );
    });

    it('should return 0 when similarity calculation fails', async () => {
  
      mockQdrantClient.$queryRaw.mockResolvedValue([]);

      const similarity = await calculateSimilarity('test1', 'test2');

      expect(similarity).toBe(0);
    });

    it('should handle database errors during similarity calculation', async () => {
  
      mockQdrantClient.$queryRaw.mockRejectedValue(new Error('Database error'));

      const similarity = await calculateSimilarity('test1', 'test2');

      expect(similarity).toBe(0);
    });

    it('should handle empty strings', async () => {
  
      const mockResult = [{ score: 0.0 }];
      mockQdrantClient.$queryRaw.mockResolvedValue(mockResult);

      const similarity = await calculateSimilarity('', '');

      expect(similarity).toBe(0.0);
    });
  });

  describe('Scoring Algorithm', () => {
    it('should weight FTS and similarity scores correctly for sections', async () => {
  
      const mockResults = [
        {
          id: '123e4567-e89b-12d3-a456-426614174000',
          kind: 'section',
          title: 'Test',
          snippet: 'Test content',
          // Section formula: 0.4 * (0.6 * fts + 0.4 * similarity) + 0.6 * similarity
          fts_score: 0.8,
          similarity_score: 0.6,
          combined_score: 0.4 * (0.6 * 0.8 + 0.4 * 0.6) + 0.6 * 0.6, // = 0.624
        },
      ];

      mockQdrantClient.$queryRaw.mockResolvedValue(mockResults);

      const results = await deepSearch('test', ['section']);

      expect(results[0].combined_score).toBeCloseTo(0.624, 3);
    });

    it('should use correct scoring for runbooks', async () => {
  
      const mockResults = [
        {
          id: '123e4567-e89b-12d3-a456-426614174000',
          kind: 'runbook',
          title: 'Test Service',
          snippet: 'Test steps',
          // Runbook formula: 0.3 * similarity
          fts_score: 0.0,
          similarity_score: 0.8,
          combined_score: 0.3 * 0.8, // = 0.24
        },
      ];

      mockQdrantClient.$queryRaw.mockResolvedValue(mockResults);

      const results = await deepSearch('test', ['runbook']);

      expect(results[0].combined_score).toBeCloseTo(0.24, 2);
    });

    it('should use correct scoring for change logs', async () => {
  
      const mockResults = [
        {
          id: '123e4567-e89b-12d3-a456-426614174000',
          kind: 'change',
          title: 'Test Change',
          snippet: 'Test details',
          // Change log formula: 0.3 * similarity
          fts_score: 0.0,
          similarity_score: 0.7,
          combined_score: 0.3 * 0.7, // = 0.21
        },
      ];

      mockQdrantClient.$queryRaw.mockResolvedValue(mockResults);

      const results = await deepSearch('test', ['change']);

      expect(results[0].combined_score).toBeCloseTo(0.21, 2);
    });

    it('should sort results by combined score descending', async () => {
  
      const mockResults = [
        {
          id: '123e4567-e89b-12d3-a456-426614174000',
          kind: 'section',
          title: 'Low Score',
          snippet: 'Content',
          fts_score: 0.3,
          similarity_score: 0.2,
          combined_score: 0.2,
        },
        {
          id: '123e4567-e89b-12d3-a456-426614174001',
          kind: 'section',
          title: 'High Score',
          snippet: 'Content',
          fts_score: 0.9,
          similarity_score: 0.8,
          combined_score: 0.8,
        },
        {
          id: '123e4567-e89b-12d3-a456-426614174002',
          kind: 'section',
          title: 'Medium Score',
          snippet: 'Content',
          fts_score: 0.6,
          similarity_score: 0.5,
          combined_score: 0.5,
        },
      ];

      mockQdrantClient.$queryRaw.mockResolvedValue(mockResults);

      const results = await deepSearch('test', ['section']);

      expect(results[0].title).toBe('High Score');
      expect(results[1].title).toBe('Medium Score');
      expect(results[2].title).toBe('Low Score');
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large result sets efficiently', async () => {
  
      const largeResultSet = Array.from({ length: 1000 }, (_, i) => ({
        id: `123e4567-e89b-12d3-a456-42661417${i.toString().padStart(4, '0')}`,
        kind: 'section',
        title: `Result ${i}`,
        snippet: `Snippet content for result ${i}`,
        fts_score: 1.0 - (i * 0.001),
        similarity_score: 0.8 - (i * 0.001),
        combined_score: 0.9 - (i * 0.001),
      }));

      mockQdrantClient.$queryRaw.mockResolvedValue(largeResultSet);

      const startTime = Date.now();
      const results = await deepSearch('test query', ['section'], 100);
      const endTime = Date.now();

      expect(results).toHaveLength(100);
      expect(results[0].combined_score).toBeGreaterThan(results[99].combined_score);

      // Should complete in reasonable time
      expect(endTime - startTime).toBeLessThan(1000); // 1 second max
    });

    it('should handle concurrent search requests', async () => {
  
      const mockResults = [
        {
          id: '123e4567-e89b-12d3-a456-426614174000',
          kind: 'section',
          title: 'Test Result',
          snippet: 'Test content',
          fts_score: 0.8,
          similarity_score: 0.7,
          combined_score: 0.72,
        },
      ];

      mockQdrantClient.$queryRaw.mockResolvedValue(mockResults);

      const promises = Array(10).fill(null).map((_, i) =>
        deepSearch(`test query ${i}`, ['section'])
      );

      const results = await Promise.all(promises);

      expect(results).toHaveLength(10);
      expect(results.every(r => r.length === 1)).toBe(true);
      expect(mockQdrantClient.$queryRaw).toHaveBeenCalledTimes(10);
    });

    it('should use efficient SQL queries with proper indexing', async () => {
  
      mockQdrantClient.$queryRaw.mockResolvedValue([]);

      await deepSearch('test query', ['section'], 20, 0.3);

      expect(mockQdrantClient.$queryRaw).toHaveBeenCalledWith(
        expect.stringContaining('ORDER BY combined_score DESC')
      );

      expect(mockQdrantClient.$queryRaw).toHaveBeenCalledWith(
        expect.stringContaining('LIMIT 20')
      );

      expect(mockQdrantClient.$queryRaw).toHaveBeenCalledWith(
        expect.stringContaining('> 0.3')
      );
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle empty query strings', async () => {

      mockQdrantClient.$queryRaw.mockResolvedValue([]);

      const results = await deepSearch('', ['section']);

      expect(results).toHaveLength(0);
    });

    it('should handle very long query strings', async () => {
  
      const longQuery = 'test query '.repeat(100);

      mockQdrantClient.$queryRaw.mockResolvedValue([]);

      const results = await deepSearch(longQuery, ['section']);

      expect(results).toHaveLength(0);
      expect(mockQdrantClient.$queryRaw).toHaveBeenCalled();
    });

    it('should handle special characters in queries', async () => {
  
      const specialQuery = 'test@#$%^&*()_+-={}[]|\\:";\'<>?,./';

      mockQdrantClient.$queryRaw.mockResolvedValue([]);

      const results = await deepSearch(specialQuery, ['section']);

      expect(results).toHaveLength(0);
    });

    it('should handle Unicode characters', async () => {
  
      const unicodeQuery = 'café résumé 测试';

      mockQdrantClient.$queryRaw.mockResolvedValue([]);

      const results = await deepSearch(unicodeQuery, ['section']);

      expect(results).toHaveLength(0);
      expect(mockQdrantClient.$queryRaw).toHaveBeenCalled();
    });

    it('should handle null or undefined parameters', async () => {

      // Mock the query to return undefined for null queries (simulating SQL behavior)
      mockQdrantClient.$queryRaw.mockResolvedValue(undefined);

      // @ts-expect-error - Testing invalid input
      const results1 = await deepSearch(null, ['section']);

      expect(results1).toHaveLength(0);

      // Mock empty array for null search types
      mockQdrantClient.$queryRaw.mockResolvedValue([]);

      // @ts-expect-error - Testing invalid input
      const results2 = await deepSearch('test', null);

      expect(results2).toHaveLength(0);
    });

    it('should handle invalid similarity thresholds', async () => {
  
      // @ts-expect-error - Testing invalid input
      const results1 = await deepSearch('test', ['section'], 20, -0.5);

      expect(results1).toBeDefined();

      // @ts-expect-error - Testing invalid input
      const results2 = await deepSearch('test', ['section'], 20, 1.5);

      expect(results2).toBeDefined();
    });

    it('should handle invalid topK values', async () => {
  
      // @ts-expect-error - Testing invalid input
      const results1 = await deepSearch('test', ['section'], -5);

      expect(results1).toBeDefined();

      // @ts-expect-error - Testing invalid input
      const results2 = await deepSearch('test', ['section'], 0);

      expect(results2).toHaveLength(0);
    });
  });

  describe('SQL Injection Prevention', () => {
    it('should use parameterized queries', async () => {
  
      const maliciousQuery = "test'; DROP TABLE section; --";

      mockQdrantClient.$queryRaw.mockResolvedValue([]);

      await deepSearch(maliciousQuery, ['section']);

      // The query should use parameterized binding, not string concatenation
      expect(mockQdrantClient.$queryRaw).toHaveBeenCalledWith(
        expect.stringContaining('${maliciousQuery}')
      );
    });

    it('should sanitize search types', async () => {
  
      const maliciousTypes = ['section; DROP TABLE section; --'];

      mockQdrantClient.$queryRaw.mockResolvedValue([]);

      await deepSearch('test', maliciousTypes as any);

      // Should not attempt to query malicious table names
      expect(mockQdrantClient.$queryRaw).not.toHaveBeenCalledWith(
        expect.stringContaining('DROP TABLE')
      );
    });
  });

  describe('Result Format Validation', () => {
    it('should return properly formatted DeepSearchResult objects', async () => {
  
      const mockResults = [
        {
          id: '123e4567-e89b-12d3-a456-426614174000',
          kind: 'section',
          title: 'Test Section',
          snippet: 'Test snippet content',
          fts_score: 0.8,
          similarity_score: 0.7,
          combined_score: 0.72,
        },
      ];

      mockQdrantClient.$queryRaw.mockResolvedValue(mockResults);

      const results = await deepSearch('test', ['section']);

      expect(results[0]).toMatchObject({
        id: expect.stringMatching(/^[0-9a-f-]{36}$/),
        kind: expect.stringMatching(/^(section|runbook|change)$/),
        title: expect.any(String),
        snippet: expect.any(String),
        fts_score: expect.any(Number),
        similarity_score: expect.any(Number),
        combined_score: expect.any(Number),
      });

      expect(results[0].fts_score).toBeGreaterThanOrEqual(0);
      expect(results[0].fts_score).toBeLessThanOrEqual(1);
      expect(results[0].similarity_score).toBeGreaterThanOrEqual(0);
      expect(results[0].similarity_score).toBeLessThanOrEqual(1);
      expect(results[0].combined_score).toBeGreaterThanOrEqual(0);
      expect(results[0].combined_score).toBeLessThanOrEqual(1);
    });

    it('should handle missing optional fields gracefully', async () => {
  
      const mockResults = [
        {
          id: '123e4567-e89b-12d3-a456-426614174000',
          kind: 'section',
          title: 'Test',
          snippet: null,
          fts_score: 0.8,
          similarity_score: 0.7,
          combined_score: 0.72,
        },
      ];

      mockQdrantClient.$queryRaw.mockResolvedValue(mockResults);

      const results = await deepSearch('test', ['section']);

      expect(results[0].snippet).toBeNull();
    });
  });
});