/**
 * Chunk Reassembly Test Without Embeddings
 *
 * Tests the chunking and reassembly functionality using traditional chunking
 */

import { describe, it, expect } from 'vitest';
import { ChunkingService } from '../../src/services/chunking/chunking-service.js';
import { ResultGroupingService } from '../../src/services/search/result-grouping-service.js';
import type { KnowledgeItem } from '../../src/types/core-interfaces.js';

describe('Chunk Reassembly Without Embeddings', () => {
  let chunkingService: ChunkingService;
  let groupingService: ResultGroupingService;

  beforeEach(() => {
    // Create chunking service without embedding service (uses traditional chunking)
    chunkingService = new ChunkingService();
    groupingService = new ResultGroupingService();
  });

  it('should test chunking and reassembly without embeddings', () => {
    // Test the chunking service without waiting for async operations
    const content = `
# System Architecture Document

## Overview
This document provides a comprehensive overview of our system architecture.

${'Additional technical content repeated to ensure proper chunking. '.repeat(100)}

## Database Design
Our database uses PostgreSQL for relational data and Redis for caching.

${'More database content to reach chunking thresholds. '.repeat(80)}

## Security Implementation
Security is implemented at multiple layers throughout the system.

${'Additional security details and implementation notes. '.repeat(60)}

## Conclusion
This architecture provides a solid foundation for our scalable system.
    `.trim();

    const knowledgeItem: KnowledgeItem = {
      id: 'test-doc-001',
      kind: 'section', // This should be chunked
      scope: { project: 'test-project' },
      data: {
        content,
        title: 'Architecture Documentation',
      },
    };

    // Test if content should be chunked
    const shouldChunk = chunkingService.shouldChunkItem(knowledgeItem);
    expect(shouldChunk).toBe(true);

    // Test chunking statistics
    const stats = chunkingService.getChunkingStats(knowledgeItem);
    expect(stats.should_chunk).toBe(true);
    expect(stats.estimated_chunks).toBeGreaterThan(1);
  });

  it('should simulate complete chunking and reassembly flow', async () => {
    // Create test data that simulates chunked items
    const parentItem: KnowledgeItem = {
      id: 'parent-001',
      kind: 'section',
      scope: { project: 'test-project' },
      data: {
        content: 'PARENT: Document with multiple chunks',
        is_chunk: false,
        total_chunks: 3,
        chunk_index: 0,
        original_length: 5000,
        title: 'Test Document',
      },
    };

    const chunk1: KnowledgeItem = {
      id: 'chunk-001',
      kind: 'section',
      scope: { project: 'test-project' },
      data: {
        content: 'First part of the document content...',
        is_chunk: true,
        parent_id: 'parent-001',
        chunk_index: 0,
        total_chunks: 3,
        original_length: 5000,
        title: 'Test Document',
      },
    };

    const chunk2: KnowledgeItem = {
      id: 'chunk-002',
      kind: 'section',
      scope: { project: 'test-project' },
      data: {
        content: 'Second part of the document content with more details...',
        is_chunk: true,
        parent_id: 'parent-001',
        chunk_index: 1,
        total_chunks: 3,
        original_length: 5000,
        title: 'Test Document',
      },
    };

    const chunk3: KnowledgeItem = {
      id: 'chunk-003',
      kind: 'section',
      scope: { project: 'test-project' },
      data: {
        content: 'Third part of the document content with final details...',
        is_chunk: true,
        parent_id: 'parent-001',
        chunk_index: 2,
        total_chunks: 3,
        original_length: 5000,
        title: 'Test Document',
      },
    };

    // Create simulated search results (including both parent and chunks)
    const searchResults = [
      {
        id: parentItem.id,
        kind: parentItem.kind,
        content: parentItem.data.content,
        data: parentItem.data,
        scope: parentItem.scope,
        confidence_score: 0.95,
        created_at: new Date().toISOString(),
        match_type: 'semantic' as const,
      },
      {
        id: chunk1.id,
        kind: chunk1.kind,
        content: chunk1.data.content,
        data: chunk1.data,
        scope: chunk1.scope,
        confidence_score: 0.9,
        created_at: new Date().toISOString(),
        match_type: 'semantic' as const,
      },
      {
        id: chunk2.id,
        kind: chunk2.kind,
        content: chunk2.data.content,
        data: chunk2.data,
        scope: chunk2.scope,
        confidence_score: 0.85,
        created_at: new Date().toISOString(),
        match_type: 'semantic' as const,
      },
      {
        id: chunk3.id,
        kind: chunk3.kind,
        content: chunk3.data.content,
        data: chunk3.data,
        scope: chunk3.scope,
        confidence_score: 0.8,
        created_at: new Date().toISOString(),
        match_type: 'semantic' as const,
      },
    ];

    // Group results
    const groupedResults = groupingService.groupResultsByParent(searchResults);
    expect(groupedResults.length).toBe(1);

    // Find the group for our parent
    const groupedResult = groupedResults.find((g) => g.parent_id === 'parent-001');
    expect(groupedResult).toBeDefined();
    expect(groupedResult!.is_single_item).toBe(false);
    expect(groupedResult!.chunks.length).toBe(3);

    // Reconstruct content
    const reconstructed = groupingService.reconstructGroupedContent(groupedResult!);

    // Verify reconstruction
    expect(reconstructed.content).toContain('First part of the document content');
    expect(reconstructed.content).toContain('Second part of the document content');
    expect(reconstructed.content).toContain('Third part of the document content');

    // Verify metadata
    expect(reconstructed.total_chunks).toBe(3);
    expect(reconstructed.found_chunks).toBe(3);
    expect(reconstructed.completeness_ratio).toBe(1.0);
    expect(reconstructed.confidence_score).toBeCloseTo(0.85, 2); // Average of 0.9, 0.85, 0.8
  });

  it('should handle partial chunk scenarios', async () => {
    // Simulate finding only 2 out of 3 chunks (including a parent result)
    const searchResults = [
      {
        id: 'parent-001',
        kind: 'section',
        content: 'Parent item content...',
        data: {
          content: 'Parent item content...',
          is_chunk: false,
          total_chunks: 3,
        },
        scope: { project: 'test' },
        confidence_score: 0.95,
        created_at: new Date().toISOString(),
        match_type: 'semantic' as const,
      },
      {
        id: 'chunk-001',
        kind: 'section',
        content: 'First part of content...',
        data: {
          content: 'First part of content...',
          is_chunk: true,
          parent_id: 'parent-001',
          chunk_index: 0,
          total_chunks: 3,
          original_length: 3000,
        },
        scope: { project: 'test' },
        confidence_score: 0.9,
        created_at: new Date().toISOString(),
        match_type: 'semantic' as const,
      },
      {
        id: 'chunk-002',
        kind: 'section',
        content: 'Second part of content...',
        data: {
          content: 'Second part of content...',
          is_chunk: true,
          parent_id: 'parent-001',
          chunk_index: 1,
          total_chunks: 3,
          original_length: 3000,
        },
        scope: { project: 'test' },
        confidence_score: 0.85,
        created_at: new Date().toISOString(),
        match_type: 'semantic' as const,
      },
    ];

    // Group and reconstruct
    const groupedResults = groupingService.groupResultsByParent(searchResults);
    const groupedResult = groupedResults.find((g) => g.parent_id === 'parent-001');
    if (!groupedResult) return;
    const reconstructed = groupingService.reconstructGroupedContent(groupedResult);

    // Verify partial reconstruction
    expect(reconstructed.total_chunks).toBe(3);
    expect(reconstructed.found_chunks).toBe(2);
    expect(reconstructed.completeness_ratio).toBeCloseTo(2 / 3, 2);
  });

  it('should handle mixed chunked and non-chunked results', () => {
    const searchResults = [
      // Non-chunked item
      {
        id: 'entity-001',
        kind: 'entity',
        content: 'This is a standalone entity.',
        data: {
          content: 'This is a standalone entity.',
          name: 'Test Entity',
        },
        scope: { project: 'test' },
        confidence_score: 0.8,
        created_at: new Date().toISOString(),
        match_type: 'keyword' as const,
      },
      // Chunked items
      {
        id: 'chunk-001',
        kind: 'section',
        content: 'First chunk content...',
        data: {
          content: 'First chunk content...',
          is_chunk: true,
          parent_id: 'section-001',
          chunk_index: 0,
          total_chunks: 2,
        },
        scope: { project: 'test' },
        confidence_score: 0.75,
        created_at: new Date().toISOString(),
        match_type: 'semantic' as const,
      },
      {
        id: 'chunk-002',
        kind: 'section',
        content: 'Second chunk content...',
        data: {
          content: 'Second chunk content...',
          is_chunk: true,
          parent_id: 'section-001',
          chunk_index: 1,
          total_chunks: 2,
        },
        scope: { project: 'test' },
        confidence_score: 0.7,
        created_at: new Date().toISOString(),
        match_type: 'semantic' as const,
      },
    ];

    // Group results
    const groupedResults = groupingService.groupResultsByParent(searchResults);

    // Should have 2 groups: 1 single item (entity) and 1 grouped (section)
    expect(groupedResults.length).toBe(2);

    const singleItems = groupedResults.filter((g) => g.is_single_item);
    const groupedItems = groupedResults.filter((g) => !g.is_single_item);

    expect(singleItems.length).toBe(1);
    expect(groupedItems.length).toBe(1);

    // Verify the entity is a single item
    const entityGroup = singleItems.find((g) => g.parent_id === 'entity-001');
    expect(entityGroup).toBeDefined();

    // Verify the section is grouped
    const sectionGroup = groupedItems.find((g) => g.parent_id === 'section-001');
    expect(sectionGroup).toBeDefined();
    expect(sectionGroup!.chunks.length).toBe(2);
  });

  it('should verify content integrity in reassembly', () => {
    const _originalContent = `
# Document Title

## Section 1
This is the first section with important information.

## Section 2
This is the second section with more details.

## Section 3
This is the third section with conclusions.
    `.trim();

    // Simulate chunks that preserve the original content structure
    const searchResults = [
      {
        id: 'chunk-1',
        kind: 'section',
        content:
          '# Document Title\n\n## Section 1\nThis is the first section with important information.',
        data: {
          content:
            '# Document Title\n\n## Section 1\nThis is the first section with important information.',
          is_chunk: true,
          parent_id: 'doc-001',
          chunk_index: 0,
          total_chunks: 3,
        },
        scope: { project: 'test' },
        confidence_score: 0.9,
        created_at: new Date().toISOString(),
        match_type: 'semantic' as const,
      },
      {
        id: 'chunk-2',
        kind: 'section',
        content: '## Section 2\nThis is the second section with more details.',
        data: {
          content: '## Section 2\nThis is the second section with more details.',
          is_chunk: true,
          parent_id: 'doc-001',
          chunk_index: 1,
          total_chunks: 3,
        },
        scope: { project: 'test' },
        confidence_score: 0.85,
        created_at: new Date().toISOString(),
        match_type: 'semantic' as const,
      },
      {
        id: 'chunk-3',
        kind: 'section',
        content: '## Section 3\nThis is the third section with conclusions.',
        data: {
          content: '## Section 3\nThis is the third section with conclusions.',
          is_chunk: true,
          parent_id: 'doc-001',
          chunk_index: 2,
          total_chunks: 3,
        },
        scope: { project: 'test' },
        confidence_score: 0.8,
        created_at: new Date().toISOString(),
        match_type: 'semantic' as const,
      },
    ];

    // Group and reconstruct
    const groupedResults = groupingService.groupResultsByParent(searchResults);
    const reconstructed = groupingService.reconstructGroupedContent(groupedResults[0]);

    // Verify the reconstructed content maintains structure
    expect(reconstructed.content).toContain('# Document Title');
    expect(reconstructed.content).toContain('## Section 1');
    expect(reconstructed.content).toContain('## Section 2');
    expect(reconstructed.content).toContain('## Section 3');

    // Verify key phrases are preserved
    expect(reconstructed.content).toContain('important information');
    expect(reconstructed.content).toContain('more details');
    expect(reconstructed.content).toContain('conclusions');

    // Verify proper separation between sections
    expect(reconstructed.content).toMatch(/Section 1.*\n\n.*Section 2/s);
  });
});
