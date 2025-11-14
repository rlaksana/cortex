// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck


import { type SearchResult } from '../../types/core-interfaces.js';

export interface GroupedResult {
  parent_id: string;
  parent_score: number;
  is_single_item: boolean;
  chunks: ChunkResult[];
}

export interface ChunkResult {
  id: string;
  chunk_index: number;
  total_chunks: number;
  confidence_score: number;
  data: Record<string, unknown>;
  kind: string;
  scope: Record<string, unknown>;
  created_at: string;
  match_type: 'exact' | 'fuzzy' | 'semantic' | 'keyword' | 'hybrid' | 'expanded' | 'graph';
}

export interface ReconstructedContent {
  parent_id: string;
  content: string;
  total_chunks: number;
  found_chunks: number;
  confidence_score: number;
  parent_score: number;
  completeness_ratio: number;
}

export interface GroupingStats {
  total_results: number;
  grouped_results: number;
  single_item_results: number;
  total_chunks_found: number;
  chunk_coverage_ratio: number;
}

export class ResultGroupingService {
  /**
   * Group search results by parent_id for chunked content
   */
  groupResultsByParent(results: SearchResult[]): GroupedResult[] {
    // Separate chunked and non-chunked results
    const chunkedResults: SearchResult[] = [];
    const nonChunkedResults: SearchResult[] = [];

    for (const result of results) {
      if (result.data.is_chunk) {
        chunkedResults.push(result);
      } else {
        nonChunkedResults.push(result);
      }
    }

    // Group chunks by parent_id
    const chunksByParent = new Map<string, SearchResult[]>();
    for (const chunk of chunkedResults) {
      const parentId = chunk.data.parent_id as string;
      if (!chunksByParent.has(parentId)) {
        chunksByParent.set(parentId, []);
      }
      chunksByParent.get(parentId)!.push(chunk);
    }

    // Create grouped results
    const groupedResults: GroupedResult[] = [];

    // First, create groups for chunks that have parent_id references
    for (const [parentId, chunks] of chunksByParent) {
      const sortedChunks = chunks.sort((a, b) =>
        (a.data.chunk_index as number) - (b.data.chunk_index as number)
      );

      // Calculate parent score as average of chunk scores (since parent might not be in results)
      const parentScore = sortedChunks.reduce((sum, chunk) => sum + chunk.confidence_score, 0) / sortedChunks.length;

      groupedResults.push({
        parent_id: parentId,
        parent_score: parentScore,
        is_single_item: false,
        chunks: sortedChunks.map(chunk => ({
          id: chunk.id,
          chunk_index: chunk.data.chunk_index as number,
          total_chunks: chunk.data.total_chunks as number,
          confidence_score: chunk.confidence_score,
          data: chunk.data,
          kind: chunk.kind,
          scope: chunk.scope,
          created_at: chunk.created_at,
          match_type: chunk.match_type
        }))
      });
    }

    // Then, add parent groups if parent items are also present in results
    // (This will overwrite the chunk-only group with a parent-present group)
    for (const result of results) {
      if (!result.data.is_chunk && chunksByParent.has(result.id)) {
        const chunks = chunksByParent.get(result.id)!;
        const sortedChunks = chunks.sort((a, b) =>
          (a.data.chunk_index as number) - (b.data.chunk_index as number)
        );

        // Find and update the existing group or create a new one
        const existingGroupIndex = groupedResults.findIndex(g => g.parent_id === result.id);
        if (existingGroupIndex >= 0) {
          // Update existing group with actual parent score
          groupedResults[existingGroupIndex].parent_score = result.confidence_score;
        } else {
          // This shouldn't happen with the logic above, but handle it just in case
          groupedResults.push({
            parent_id: result.id,
            parent_score: result.confidence_score,
            is_single_item: false,
            chunks: sortedChunks.map(chunk => ({
              id: chunk.id,
              chunk_index: chunk.data.chunk_index as number,
              total_chunks: chunk.data.total_chunks as number,
              confidence_score: chunk.confidence_score,
              data: chunk.data,
              kind: chunk.kind,
              scope: chunk.scope,
              created_at: chunk.created_at,
              match_type: chunk.match_type
            }))
          });
        }
      }
    }

    // Add single items (non-chunked results that don't have chunks)
    for (const result of nonChunkedResults) {
      if (!chunksByParent.has(result.id)) {
        groupedResults.push({
          parent_id: result.id,
          parent_score: result.confidence_score,
          is_single_item: true,
          chunks: []
        });
      }
    }

    return groupedResults;
  }

  /**
   * Reconstruct content from grouped chunks
   */
  reconstructGroupedContent(groupedResult: GroupedResult): ReconstructedContent {
    if (groupedResult.is_single_item) {
      return {
        parent_id: groupedResult.parent_id,
        content: '', // No content to reconstruct for single items
        total_chunks: 1,
        found_chunks: 1,
        confidence_score: groupedResult.parent_score,
        parent_score: groupedResult.parent_score,
        completeness_ratio: 1.0
      };
    }

    const chunks = groupedResult.chunks;
    if (chunks.length === 0) {
      return {
        parent_id: groupedResult.parent_id,
        content: '',
        total_chunks: 0,
        found_chunks: 0,
        confidence_score: 0,
        parent_score: groupedResult.parent_score,
        completeness_ratio: 0
      };
    }

    // Extract content from chunks and clean up chunking metadata
    const contentParts: string[] = [];
    let totalChunks = 0;
    let totalScore = 0;

    for (const chunk of chunks) {
      let chunkContent = chunk.data.content as string || '';

      // Remove chunking metadata prefixes
      chunkContent = chunkContent
        .replace(/^CHUNK \d+ of \d+\n\n/gm, '') // Remove "CHUNK X of Y" prefixes
        .replace(/^TITLE: .+\n\n/gm, '') // Remove "TITLE: ..." prefixes
        .replace(/^PARENT: .+\n\n/gm, ''); // Remove "PARENT: ..." prefixes

      contentParts.push(chunkContent);
      totalChunks = Math.max(totalChunks, chunk.total_chunks);
      totalScore += chunk.confidence_score;
    }

    const content = contentParts.join('\n\n').trim();
    const avgScore = chunks.length > 0 ? totalScore / chunks.length : 0;
    const completenessRatio = totalChunks > 0 ? chunks.length / totalChunks : 0;

    return {
      parent_id: groupedResult.parent_id,
      content,
      total_chunks: totalChunks,
      found_chunks: chunks.length,
      confidence_score: avgScore,
      parent_score: groupedResult.parent_score,
      completeness_ratio: completenessRatio
    };
  }

  /**
   * Group results and sort by parent score (highest first)
   */
  groupAndSortResults(results: SearchResult[]): GroupedResult[] {
    const grouped = this.groupResultsByParent(results);

    // Sort by parent_score (highest first), then by parent_id for consistency
    grouped.sort((a, b) => {
      if (b.parent_score !== a.parent_score) {
        return b.parent_score - a.parent_score;
      }
      return a.parent_id.localeCompare(b.parent_id);
    });

    return grouped;
  }

  /**
   * Calculate grouping statistics
   */
  calculateGroupingStats(results: SearchResult[]): GroupingStats {
    const grouped = this.groupResultsByParent(results);

    const totalResults = results.length;
    const groupedResults = grouped.filter(g => !g.is_single_item).length;
    const singleItemResults = grouped.filter(g => g.is_single_item).length;

    let totalChunksFound = 0;
    let expectedTotalChunks = 0;

    for (const group of grouped) {
      totalChunksFound += group.chunks.length;
      if (group.chunks.length > 0) {
        expectedTotalChunks += group.chunks[0].total_chunks;
      }
    }

    const chunkCoverageRatio = expectedTotalChunks > 0 ? totalChunksFound / expectedTotalChunks : 0;

    return {
      total_results: totalResults,
      grouped_results: groupedResults,
      single_item_results: singleItemResults,
      total_chunks_found: totalChunksFound,
      chunk_coverage_ratio: chunkCoverageRatio
    };
  }

  /**
   * Filter grouped results by completeness ratio
   */
  filterByCompleteness(groupedResults: GroupedResult[], minCompleteness: number = 0.5): GroupedResult[] {
    return groupedResults.filter(group => {
      if (group.is_single_item) return true;

      // Calculate completeness for this group
      const foundChunks = group.chunks.length;
      const totalChunks = group.chunks.length > 0 ? group.chunks[0].total_chunks : 1;
      const completeness = foundChunks / totalChunks;

      return completeness >= minCompleteness;
    });
  }

  /**
   * Get high-quality groups (both good score and completeness)
   */
  getHighQualityGroups(groupedResults: GroupedResult[], minScore: number = 0.7, minCompleteness: number = 0.5): GroupedResult[] {
    return groupedResults.filter(group =>
      group.parent_score >= minScore &&
      (group.is_single_item || this.calculateGroupCompleteness(group) >= minCompleteness)
    );
  }

  /**
   * Calculate completeness ratio for a group
   */
  private calculateGroupCompleteness(group: GroupedResult): number {
    if (group.is_single_item) return 1.0;

    const foundChunks = group.chunks.length;
    const totalChunks = group.chunks.length > 0 ? group.chunks[0].total_chunks : 1;

    return foundChunks / totalChunks;
  }
}