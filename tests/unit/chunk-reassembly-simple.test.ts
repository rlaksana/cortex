/**
 * Simple Chunk Reassembly Test
 *
 * Focused test to verify the core chunking and reassembly functionality
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { ChunkingService } from '../../src/services/chunking/chunking-service.js';
import { ResultGroupingService } from '../../src/services/search/result-grouping-service.js';
import { MockEmbeddingService } from '../utils/mock-embedding-service.js';
import { createMockSemanticAnalyzer } from '../utils/mock-semantic-analyzer.js';
import type { KnowledgeItem } from '../../src/types/core-interfaces.js';

describe('Chunk Reassembly Simple Test', () => {
  let chunkingService: ChunkingService;
  let embeddingService: MockEmbeddingService;
  let groupingService: ResultGroupingService;

  beforeEach(() => {
    // Create mock embedding service with explicit configuration to prevent failures
    embeddingService = new MockEmbeddingService({
      shouldFail: false,
      failMethod: 'both',
      latency: 0
    });

    chunkingService = new ChunkingService(undefined, undefined, embeddingService as any);

    // Replace the semantic analyzer with our mock - ensure it's properly set
    const mockSemanticAnalyzer = createMockSemanticAnalyzer(embeddingService as any, {
      shouldFail: false
    });
    (chunkingService as any).semanticAnalyzer = mockSemanticAnalyzer;

    groupingService = new ResultGroupingService();
  });

  it('should chunk and reassemble basic content', async () => {
    // Create content that should be chunked (over 2400 chars, will trigger semantic analysis)
    const content = `
# Large Technical Document

## Introduction
This is a comprehensive technical document that covers multiple aspects of our system architecture and implementation details.

${'This is repeated content to ensure we have enough text for chunking. '.repeat(100)}

## Database Architecture
Our database architecture consists of multiple layers designed for scalability and performance.

${'Additional database content to reach the chunking threshold. '.repeat(50)}

## Security Implementation
Security is implemented at multiple layers throughout the system architecture.

${'Security details and implementation notes. '.repeat(30)}

## Conclusion
This document provides a comprehensive overview of our technical architecture.
    `.trim();

    const knowledgeItem: KnowledgeItem = {
      id: 'test-doc-001',
      kind: 'section', // This should be chunked
      scope: { project: 'test-project' },
      data: {
        content,
        title: 'Technical Documentation'
      }
    };

    // Apply chunking
    const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);

    // Verify we have multiple items (parent + chunks)
    expect(chunkedItems.length).toBeGreaterThan(1);

    // Find parent and chunks
    const parentItem = chunkedItems.find(item => !item.data.is_chunk);
    const childChunks = chunkedItems.filter(item => item.data.is_chunk);

    expect(parentItem).toBeDefined();
    expect(childChunks.length).toBeGreaterThan(0);
    expect(parentItem?.data.total_chunks).toBe(childChunks.length);

    // Simulate search results from both parent and chunks
    const searchResults = [
      // Add parent result
      {
        id: parentItem!.id,
        kind: parentItem!.kind,
        content: parentItem!.data.content,
        data: parentItem!.data,
        scope: parentItem!.scope,
        confidence_score: 0.9,
        created_at: parentItem!.created_at!,
        match_type: 'semantic' as const
      },
      // Add chunk results
      ...childChunks.map(chunk => ({
        id: chunk.id,
        kind: chunk.kind,
        content: chunk.data.content,
        data: chunk.data,
        scope: chunk.scope,
        confidence_score: 0.8,
        created_at: chunk.created_at!,
        match_type: 'semantic' as const
      }))
    ];

    // Group results
    const groupedResults = groupingService.groupResultsByParent(searchResults);
    expect(groupedResults.length).toBeGreaterThan(0);

    // Find the group for our parent
    const groupedResult = groupedResults.find(g => g.parent_id === parentItem!.id);
    expect(groupedResult).toBeDefined();

    // Reconstruct content
    const reconstructed = groupingService.reconstructGroupedContent(groupedResult!);

    // Verify reconstruction
    expect(reconstructed.content).toContain('Large Technical Document');
    expect(reconstructed.content).toContain('Introduction');
    expect(reconstructed.content).toContain('Database Architecture');
    expect(reconstructed.content).toContain('Security Implementation');
    expect(reconstructed.content).toContain('Conclusion');

    // Verify metadata
    expect(reconstructed.total_chunks).toBe(childChunks.length);
    expect(reconstructed.found_chunks).toBe(childChunks.length);
    expect(reconstructed.completeness_ratio).toBe(1.0);
    expect(reconstructed.confidence_score).toBeGreaterThan(0);
  });

  it('should handle mixed chunked and non-chunked results', async () => {
    // Create items - one chunked, one not
    const chunkableItem: KnowledgeItem = {
      id: 'chunkable-001',
      kind: 'section',
      scope: { project: 'test' },
      data: {
        content: 'A'.repeat(3000), // Long content
        title: 'Chunkable Item'
      }
    };

    const nonChunkableItem: KnowledgeItem = {
      id: 'non-chunkable-001',
      kind: 'entity', // This type is not chunked
      scope: { project: 'test' },
      data: {
        content: 'This is a short entity that will not be chunked.',
        name: 'Test Entity'
      }
    };

    // Process both items
    const processedItems = await chunkingService.processItemsForStorage([chunkableItem, nonChunkableItem]);

    // Create simulated search results
    const searchResults = processedItems.map(item => ({
      id: item.id,
      kind: item.kind,
      content: item.data.content,
      data: item.data,
      scope: item.scope,
      confidence_score: 0.7 + Math.random() * 0.3,
      created_at: item.created_at || new Date().toISOString(),
      match_type: 'semantic' as const
    }));

    // Group results
    const groupedResults = groupingService.groupResultsByParent(searchResults);

    // Should have both single items and grouped items
    const singleItems = groupedResults.filter(g => g.is_single_item);
    const groupedItems = groupedResults.filter(g => !g.is_single_item);

    expect(singleItems.length).toBeGreaterThan(0);
    expect(groupedItems.length).toBeGreaterThan(0);

    // Verify the entity is single item
    const entityGroup = singleItems.find(g => g.parent_id === 'non-chunkable-001');
    expect(entityGroup).toBeDefined();

    // Verify the section is grouped
    const sectionGroup = groupedItems.find(g => g.parent_id === 'chunkable-001');
    expect(sectionGroup).toBeDefined();
  });
});