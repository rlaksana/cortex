import { randomUUID, createHash } from 'node:crypto';
import { KnowledgeItem } from '../../types/core-interfaces.js';
import { inheritTTLFromParent } from '../../utils/tl-utils.js';
import { SemanticAnalyzer, type SemanticAnalysisResult } from './semantic-analyzer.js';
import { EmbeddingService } from '../embeddings/embedding-service.js';
import { logger } from '../../utils/logger.js';

export interface ChunkingStats {
  original_length: number;
  should_chunk: boolean;
  recommended_chunk_size: number;
  overlap_size: number;
  estimated_chunks: number;
  semantic_analysis_enabled: boolean;
  semantic_boundaries_found: number;
}

export class ChunkingService {
  private readonly CHUNK_SIZE = 1200; // Target characters per chunk
  private readonly OVERLAP_SIZE = 200; // Characters overlap between chunks
  private readonly CHUNKING_THRESHOLD = 2400; // Minimum length to trigger chunking (2x chunk size)

  // Types that should be chunked
  private readonly CHUNKABLE_TYPES = ['section', 'runbook', 'incident'];

  // Semantic analysis components
  private semanticAnalyzer?: SemanticAnalyzer;
  private readonly SEMANTIC_ANALYSIS_THRESHOLD = 3600; // Enable semantic analysis for longer content

  constructor(chunkSize?: number, overlapSize?: number, embeddingService?: EmbeddingService) {
    // Allow configuration for testing
    if (chunkSize) {
      (this as any).CHUNK_SIZE = chunkSize;
    }
    if (overlapSize) {
      (this as any).OVERLAP_SIZE = overlapSize;
    }

    // Initialize semantic analyzer if embedding service is available
    if (embeddingService) {
      this.semanticAnalyzer = new SemanticAnalyzer(embeddingService, {
        strong_boundary_threshold: 0.3,
        medium_boundary_threshold: 0.5,
        weak_boundary_threshold: 0.7,
        window_size: 3,
        min_chunk_sentences: 2,
        max_chunk_sentences: 15,
        enable_caching: true,
        cache_ttl: 3600000,
      });
    }
  }

  /**
   * Determine if item type and content should be chunked
   */
  shouldChunkItem(item: KnowledgeItem): boolean {
    return this.CHUNKABLE_TYPES.includes(item.kind) && this.shouldChunk(this.extractContent(item));
  }

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
    const semanticEnabled = this.shouldUseSemanticAnalysis(content);

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
      semantic_analysis_enabled: semanticEnabled,
      semantic_boundaries_found: 0, // Will be updated after analysis
    };
  }

  /**
   * Split content into chunks with overlap (enhanced with semantic analysis)
   */
  async chunkContent(content: string): Promise<string[]> {
    if (!this.shouldChunk(content)) {
      return [content];
    }

    // Use semantic chunking if available and content is long enough
    if (this.shouldUseSemanticAnalysis(content) && this.semanticAnalyzer) {
      try {
        return await this.chunkContentSemantically(content);
      } catch (error) {
        // Fallback to traditional chunking if semantic analysis fails
        logger.warn(
          { error, contentLength: content.length },
          'Semantic chunking failed, falling back to traditional method'
        );
      }
    }

    // Traditional chunking as fallback
    return this.chunkContentTraditionally(content);
  }

  /**
   * Determine if semantic analysis should be used
   */
  private shouldUseSemanticAnalysis(content: string): boolean {
    return (
      this.semanticAnalyzer !== undefined && content.length >= this.SEMANTIC_ANALYSIS_THRESHOLD
    );
  }

  /**
   * Chunk content using semantic boundary detection
   */
  private async chunkContentSemantically(content: string): Promise<string[]> {
    if (!this.semanticAnalyzer) {
      throw new Error('Semantic analyzer not available');
    }

    // Perform semantic analysis
    const analysis = await this.semanticAnalyzer.analyzeSemanticBoundaries(content);

    if (analysis.boundaries.length === 0) {
      // No semantic boundaries found, use traditional chunking
      logger.info(
        { contentLength: content.length },
        'No semantic boundaries found, using traditional chunking'
      );
      return this.chunkContentTraditionally(content);
    }

    // Create chunks based on semantic boundaries
    return this.createChunksFromBoundaries(analysis);
  }

  /**
   * Create chunks from semantic boundaries with size constraints
   */
  private createChunksFromBoundaries(analysis: SemanticAnalysisResult): string[] {
    const chunks: string[] = [];
    const boundaries = analysis.boundaries.sort((a, b) => a.index - b.index);

    let startIndex = 0;
    let currentChunkSize = 0;

    for (let i = 0; i < analysis.sentences.length; i++) {
      const sentence = analysis.sentences[i];
      const sentenceLength = sentence.length;

      // Check if adding this sentence would exceed chunk size
      if (
        currentChunkSize + sentenceLength > this.CHUNK_SIZE &&
        currentChunkSize > this.CHUNK_SIZE * 0.6
      ) {
        // Create chunk from current range
        const chunkContent = analysis.sentences.slice(startIndex, i).join(' ');
        chunks.push(chunkContent);
        startIndex = i;
        currentChunkSize = 0;
      }

      currentChunkSize += sentenceLength;

      // Check if there's a strong semantic boundary at this position
      const boundary = boundaries.find((b) => b.index === i);
      if (boundary && (boundary.type === 'strong' || boundary.type === 'medium')) {
        // Check if we have enough content for a meaningful chunk
        if (i - startIndex >= 2) {
          // At least 2 sentences
          const chunkContent = analysis.sentences.slice(startIndex, i + 1).join(' ');
          chunks.push(chunkContent);
          startIndex = i + 1;
          currentChunkSize = 0;
        }
      }
    }

    // Add remaining content as final chunk
    if (startIndex < analysis.sentences.length) {
      const finalChunk = analysis.sentences.slice(startIndex).join(' ');
      if (finalChunk.trim().length > 0) {
        chunks.push(finalChunk);
      }
    }

    // Post-process chunks to ensure they meet size requirements
    return this.postProcessChunks(chunks);
  }

  /**
   * Post-process chunks to ensure quality and size constraints
   */
  private postProcessChunks(chunks: string[]): string[] {
    const processedChunks: string[] = [];

    for (const chunk of chunks) {
      const trimmed = chunk.trim();

      // Skip very short chunks
      if (trimmed.length < 50) {
        continue;
      }

      // Split overly long chunks
      if (trimmed.length > this.CHUNK_SIZE * 1.5) {
        const subChunks = this.chunkContentTraditionally(trimmed);
        processedChunks.push(...subChunks);
      } else {
        processedChunks.push(trimmed);
      }
    }

    return processedChunks.length > 0 ? processedChunks : [chunks.join(' ')];
  }

  /**
   * Traditional chunking method (original implementation)
   */
  private chunkContentTraditionally(content: string): string[] {
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
   * Process knowledge items and apply chunking where appropriate
   * Returns array of items (may be larger than input due to chunking)
   */
  async processItemsForStorage(items: KnowledgeItem[]): Promise<KnowledgeItem[]> {
    const processedItems: KnowledgeItem[] = [];

    for (const item of items) {
      if (this.shouldChunkItem(item)) {
        const chunkedItems = await this.createChunkedItems(item);
        processedItems.push(...chunkedItems);
      } else {
        // Item doesn't need chunking, but add chunking metadata for consistency
        const content = this.extractContent(item);

        processedItems.push({
          ...item,
          // Ensure scope inheritance even for non-chunked items
          scope: item.scope || {},
          data: {
            ...item.data,
            is_chunk: false,
            total_chunks: 1,
            chunk_index: 0,
            original_length: content.length,
            chunk_overlap: 0,
            // Inherit TTL policy for consistency
            ...inheritTTLFromParent(item),
          },
          metadata: {
            ...item.metadata,
            chunking_info: {
              was_chunked: false,
              total_chunks: 1,
              processing_timestamp: new Date().toISOString(),
            },
          },
        });
      }
    }

    return processedItems;
  }

  /**
   * Create chunked knowledge items from a base item
   */
  async createChunkedItems(item: KnowledgeItem): Promise<KnowledgeItem[]> {
    const content = this.extractContent(item);
    const extractedTitle = this.extractTitle(item);

    if (!this.shouldChunk(content)) {
      // Return single item with chunking metadata and TTL inheritance
      const ttlInfo = inheritTTLFromParent(item);
      return [
        {
          ...item,
          // Ensure scope inheritance
          scope: item.scope || {},
          data: {
            ...item.data,
            is_chunk: false,
            total_chunks: 1,
            chunk_index: 0,
            original_length: content.length,
            chunk_overlap: 0,
            extracted_title: extractedTitle,
            // Inherit TTL policy
            ...ttlInfo,
          },
          metadata: {
            ...item.metadata,
            chunking_info: {
              was_chunked: false,
              total_chunks: 1,
              processing_timestamp: new Date().toISOString(),
              title_carried: extractedTitle !== '',
            },
          },
        },
      ];
    }

    const chunks = await this.chunkContent(content);
    const ttlInfo = inheritTTLFromParent(item);
    const semanticAnalysisEnabled = this.shouldUseSemanticAnalysis(content);

    // Calculate original content hash for deduplication purposes
    const originalContentHash = createHash('sha256').update(content).digest('hex');

    // Create parent item with enhanced metadata
    const parentItem: KnowledgeItem = {
      ...item,
      // Ensure parent has an ID for child chunks to reference
      id: item.id || randomUUID(),
      // Ensure scope inheritance
      scope: item.scope || {},
      data: {
        ...item.data,
        is_chunk: false,
        chunk_index: 0,
        total_chunks: chunks.length,
        original_length: content.length,
        chunk_overlap: this.OVERLAP_SIZE,
        content: `PARENT: ${chunks.length} chunks created from ${content.length} characters`,
        extracted_title: extractedTitle,
        // Inherit TTL policy
        ...ttlInfo,
      },
      metadata: {
        ...item.metadata,
        chunking_info: {
          was_chunked: true,
          is_parent: true,
          total_chunks: chunks.length,
          chunk_size: this.CHUNK_SIZE,
          overlap_size: this.OVERLAP_SIZE,
          processing_timestamp: new Date().toISOString(),
          original_content_hash: originalContentHash,
          semantic_analysis_enabled: semanticAnalysisEnabled,
          title_carried: extractedTitle !== '',
          average_chunk_size: Math.round(chunks.reduce((sum, chunk) => sum + chunk.length, 0) / chunks.length),
        },
      },
    };

    // Create child items with enhanced metadata and proper inheritance
    const childItems: KnowledgeItem[] = chunks.map((chunk, index) => {
      const chunkWithContext = this.addContextToChunk(chunk, extractedTitle, index, chunks.length);
      const chunkLength = chunk.length;
      const positionRatio = index / (chunks.length - 1); // 0.0 to 1.0

      return {
        id: randomUUID(),
        kind: item.kind,
        // Ensure scope inheritance from parent
        scope: item.scope || {},
        data: {
          ...item.data,
          is_chunk: true,
          parent_id: parentItem.id,
          chunk_index: index,
          total_chunks: chunks.length,
          original_length: content.length,
          chunk_overlap: this.OVERLAP_SIZE,
          content: chunkWithContext,
          extracted_title: extractedTitle,
          chunk_length: chunkLength,
          position_ratio: positionRatio,
          // Inherit TTL policy from parent
          ...ttlInfo,
        },
        metadata: {
          ...item.metadata,
          chunking_info: {
            was_chunked: true,
            is_child: true,
            parent_id: parentItem.id,
            chunk_index: index,
            total_chunks: chunks.length,
            chunk_size: this.CHUNK_SIZE,
            overlap_size: this.OVERLAP_SIZE,
            processing_timestamp: new Date().toISOString(),
            semantic_analysis_enabled: semanticAnalysisEnabled,
            title_carried: extractedTitle !== '',
            has_context: chunkWithContext !== chunk,
            size_ratio: chunkLength / content.length,
          },
        },
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
    });

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

  /**
   * Extract title from knowledge item for context carrying
   */
  private extractTitle(item: KnowledgeItem): string {
    // Try different title fields
    const titleFields = ['title', 'name', 'subject', 'headline', 'label'];
    for (const field of titleFields) {
      if (item.data[field] && typeof item.data[field] === 'string') {
        return item.data[field].trim();
      }
    }

    // Try metadata fields
    if (item.metadata?.title && typeof item.metadata.title === 'string') {
      return item.metadata.title.trim();
    }

    // Generate title from first line of content if available
    const content = this.extractContent(item);
    const firstLine = content.split('\n')[0].trim();
    if (firstLine.length > 0 && firstLine.length < 200) {
      return firstLine;
    }

    return '';
  }

  /**
   * Add context to chunk (title carry and position info)
   */
  private addContextToChunk(chunk: string, title: string, index: number, totalChunks: number): string {
    let contextualizedChunk = chunk;

    // Add title prefix if available
    if (title && title.trim()) {
      const titlePrefix = `TITLE: ${title}\n\n`;
      if (!contextualizedChunk.includes(titlePrefix)) {
        contextualizedChunk = titlePrefix + contextualizedChunk;
      }
    }

    // Add position context for better reconstruction
    const positionInfo = `CHUNK ${index + 1} of ${totalChunks}\n\n`;
    if (!contextualizedChunk.includes('CHUNK')) {
      contextualizedChunk = positionInfo + contextualizedChunk;
    }

    return contextualizedChunk;
  }
}
