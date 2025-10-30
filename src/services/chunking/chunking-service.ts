import { randomUUID } from 'node:crypto';
import { KnowledgeItem } from '../../types/core-interfaces';

export interface ChunkingStats {
  original_length: number;
  should_chunk: boolean;
  recommended_chunk_size: number;
  overlap_size: number;
  estimated_chunks: number;
}

export class ChunkingService {
  private readonly CHUNK_SIZE = 4000; // Target characters per chunk
  private readonly OVERLAP_SIZE = 200; // Characters overlap between chunks
  private readonly CHUNKING_THRESHOLD = 8000; // Minimum length to trigger chunking

  /**
   * Determine if content should be chunked
   */
  shouldChunk(content: string): boolean {
    return content.length > this.CHUNKING_THRESHOLD;
  }

  /**
   * Get chunking statistics for content
   */
  getChunkingStats(item: KnowledgeItem): ChunkingStats {
    const content = this.extractContent(item);
    const shouldChunk = this.shouldChunk(content);

    let estimatedChunks = 1;
    if (shouldChunk) {
      estimatedChunks = Math.ceil(
        (content.length - this.OVERLAP_SIZE) / (this.CHUNK_SIZE - this.OVERLAP_SIZE)
      );
    }

    return {
      original_length: content.length,
      should_chunk: shouldChunk,
      recommended_chunk_size: this.CHUNK_SIZE,
      overlap_size: this.OVERLAP_SIZE,
      estimated_chunks: estimatedChunks,
    };
  }

  /**
   * Split content into chunks with overlap
   */
  chunkContent(content: string): string[] {
    if (!this.shouldChunk(content)) {
      return [content];
    }

    const chunks: string[] = [];
    let start = 0;

    while (start < content.length) {
      let end = start + this.CHUNK_SIZE;

      // Try to break at natural boundaries (paragraphs, code blocks)
      if (end < content.length) {
        end = this.findNaturalBreakPoint(content, start, end);
      }

      const chunk = content.substring(start, end);
      chunks.push(chunk);

      // Calculate next start position with overlap
      start = Math.max(start + 1, end - this.OVERLAP_SIZE);
    }

    return chunks;
  }

  /**
   * Create chunked knowledge items from a base item
   */
  createChunkedItems(item: KnowledgeItem): KnowledgeItem[] {
    const content = this.extractContent(item);

    if (!this.shouldChunk(content)) {
      // Return single item with chunking metadata
      return [
        {
          ...item,
          data: {
            ...item.data,
            is_chunk: false,
            total_chunks: 1,
            chunk_index: 0,
            original_length: content.length,
            chunk_overlap: 0,
          },
        },
      ];
    }

    const chunks = this.chunkContent(content);
    const parentItem: KnowledgeItem = {
      ...item,
      data: {
        ...item.data,
        is_chunk: false,
        total_chunks: chunks.length,
        original_length: content.length,
        chunk_overlap: this.OVERLAP_SIZE,
        content: `PARENT: ${chunks.length} chunks created from ${content.length} characters`,
      },
      metadata: item.metadata || {},
    };

    const childItems: KnowledgeItem[] = chunks.map((chunk, index) => ({
      id: randomUUID(),
      kind: item.kind,
      scope: item.scope,
      data: {
        ...item.data,
        is_chunk: true,
        parent_id: parentItem.id,
        chunk_index: index,
        total_chunks: chunks.length,
        original_length: content.length,
        chunk_overlap: this.OVERLAP_SIZE,
        content: chunk,
      },
      metadata: item.metadata || {},
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    }));

    return [parentItem, ...childItems];
  }

  /**
   * Extract content from knowledge item for chunking
   */
  private extractContent(item: KnowledgeItem): string {
    // Try different content fields
    if (item.data.content) {
      return item.data.content;
    }

    // Try other common content fields
    const contentFields = ['body_text', 'body_md', 'description', 'rationale', 'summary'];
    for (const field of contentFields) {
      if (item.data[field] && typeof item.data[field] === 'string') {
        return item.data[field];
      }
    }

    // Fallback: combine all string fields
    const contentParts: string[] = [];
    for (const [_key, value] of Object.entries(item.data)) {
      if (typeof value === 'string' && value.length > 0) {
        contentParts.push(value);
      }
    }

    return contentParts.join('\n\n');
  }

  /**
   * Find natural break points in content to avoid splitting in awkward places
   */
  private findNaturalBreakPoint(content: string, start: number, end: number): number {
    const maxEnd = Math.min(end, content.length);
    const minStart = Math.max(start, maxEnd - 500); // Look back 500 chars for break point

    // Priority order for break points:
    // 1. Double newlines (paragraphs)
    // 2. Single newlines (lines)
    // 3. Sentence endings (., !, ?)
    // 4. Code block boundaries
    // 5. Spaces

    const searchArea = content.substring(minStart, maxEnd);

    // Look for double newlines first (paragraphs)
    let match = searchArea.match(/\n\n[^\n]*$/);
    if (match && match.index !== undefined) {
      return minStart + match.index! + 2;
    }

    // Look for single newlines
    match = searchArea.match(/\n[^\n]*$/);
    if (match && match.index !== undefined) {
      return minStart + match.index! + 1;
    }

    // Look for sentence endings
    match = searchArea.match(/[.!?]\s+[A-Z][^.!?]*$/);
    if (match && match.index !== undefined) {
      return minStart + match.index! + 1;
    }

    // Look for code block endings
    match = searchArea.match(/```\s*[^\n]*$/);
    if (match && match.index !== undefined) {
      return minStart + match.index! + 3;
    }

    // Look for spaces as last resort
    match = searchArea.match(/\s+[^\s]*$/);
    if (match && match.index !== undefined) {
      return minStart + match.index! + 1;
    }

    // No good break point found, return the original end
    return maxEnd;
  }
}
