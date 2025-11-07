import { randomUUID, createHash } from 'crypto';
import { KnowledgeItem } from '../../types/core-interfaces.js';
import { inheritTTLFromParent } from '../../utils/tl-utils.js';
import { SemanticAnalyzer, type SemanticAnalysisResult } from './semantic-analyzer.js';
import { EmbeddingService } from '../embeddings/embedding-service.js';
import { logger } from '@/utils/logger.js';
import { environment } from '../../config/environment.js';

export interface ChunkingStats {
  original_length: number;
  should_chunk: boolean;
  recommended_chunk_size: number;
  overlap_size: number;
  estimated_chunks: number;
  semantic_analysis_enabled: boolean;
  semantic_boundaries_found: number;
  chunk_fallback_used: boolean;
}

export class ChunkingService {
  private readonly CHUNK_SIZE: number; // Target characters per chunk
  private readonly OVERLAP_SIZE: number; // Characters overlap between chunks
  private readonly CHUNKING_THRESHOLD: number; // Minimum length to trigger chunking
  private readonly CONTENT_TRUNCATION_LIMIT: number; // Fallback truncation limit

  // Types that should be chunked
  private readonly CHUNKABLE_TYPES = ['section', 'runbook', 'incident'];

  // Semantic analysis components
  private semanticAnalyzer?: SemanticAnalyzer;
  private readonly SEMANTIC_ANALYSIS_THRESHOLD = 3600; // Enable semantic analysis for longer content

  // Circuit breaker for semantic analysis
  private circuitBreaker = {
    failures: 0,
    lastFailureTime: 0,
    state: 'CLOSED' as 'CLOSED' | 'OPEN' | 'HALF_OPEN',
    threshold: 3, // Max failures before opening
    timeout: 60000, // 1 minute timeout before trying again
  };

  constructor(chunkSize?: number, overlapSize?: number, embeddingService?: EmbeddingService) {
    // Initialize from environment configuration
    const chunkingConfig = environment.getChunkingConfig();
    this.CHUNK_SIZE = chunkSize || chunkingConfig.maxCharsPerChunk;
    this.OVERLAP_SIZE = overlapSize || chunkingConfig.chunkOverlapSize;
    this.CHUNKING_THRESHOLD = chunkingConfig.chunkingThreshold;
    this.CONTENT_TRUNCATION_LIMIT = chunkingConfig.contentTruncationLimit;

    // Initialize semantic analyzer if embedding service is available
    // This is completely optional - the service works fine without it
    if (embeddingService) {
      try {
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
        logger.info('Semantic analyzer initialized successfully');
      } catch (error) {
        logger.warn(
          { error },
          'Failed to initialize semantic analyzer, using traditional chunking only'
        );
        // Continue without semantic analyzer - service still works perfectly
      }
    } else {
      logger.info('No embedding service provided, using traditional chunking only');
    }
  }

  /**
   * Check if semantic analysis is available through circuit breaker
   */
  private isSemanticAnalysisAvailable(): boolean {
    const now = Date.now();

    switch (this.circuitBreaker.state) {
      case 'CLOSED':
        return true;
      case 'OPEN':
        if (now - this.circuitBreaker.lastFailureTime > this.circuitBreaker.timeout) {
          this.circuitBreaker.state = 'HALF_OPEN';
          logger.info('Circuit breaker moving to HALF_OPEN state');
          return true;
        }
        return false;
      case 'HALF_OPEN':
        return true;
      default:
        return false;
    }
  }

  /**
   * Record semantic analysis failure
   */
  private recordSemanticAnalysisFailure(error: Error): void {
    this.circuitBreaker.failures++;
    this.circuitBreaker.lastFailureTime = Date.now();

    if (this.circuitBreaker.failures >= this.circuitBreaker.threshold) {
      this.circuitBreaker.state = 'OPEN';
      logger.warn(
        {
          failures: this.circuitBreaker.failures,
          error: error.message,
        },
        'Circuit breaker opened due to repeated semantic analysis failures'
      );
    }
  }

  /**
   * Record semantic analysis success
   */
  private recordSemanticAnalysisSuccess(): void {
    if (this.circuitBreaker.state === 'HALF_OPEN') {
      this.circuitBreaker.state = 'CLOSED';
      this.circuitBreaker.failures = 0;
      logger.info('Circuit breaker closed after successful semantic analysis');
    }
  }

  /**
   * Perform semantic analysis with circuit breaker protection
   */
  private async performSemanticAnalysis(
    content: string,
    _existingChunks?: string[]
  ): Promise<SemanticAnalysisResult | null> {
    if (!this.semanticAnalyzer || !this.isSemanticAnalysisAvailable()) {
      return null;
    }

    try {
      const result = await this.semanticAnalyzer.analyzeSemanticBoundaries(content);
      this.recordSemanticAnalysisSuccess();
      return result;
    } catch (error) {
      this.recordSemanticAnalysisFailure(
        error instanceof Error ? error : new Error('Unknown error')
      );
      logger.warn(
        {
          error: error instanceof Error ? error.message : 'Unknown error',
          circuitState: this.circuitBreaker.state,
        },
        'Semantic analysis failed, falling back to traditional chunking'
      );
      return null;
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

    // Determine if fallback would be used based on circuit breaker state and semantic analyzer availability
    const chunk_fallback_used = semanticEnabled && !this.isSemanticAnalysisAvailable();

    return {
      original_length: content.length,
      should_chunk: shouldChunk,
      recommended_chunk_size: this.CHUNK_SIZE,
      overlap_size: this.OVERLAP_SIZE,
      estimated_chunks: estimatedChunks,
      semantic_analysis_enabled: semanticEnabled,
      semantic_boundaries_found: 0, // Will be updated after analysis
      chunk_fallback_used,
    };
  }

  /**
   * Split content into chunks with overlap (enhanced with semantic analysis)
   */
  async chunkContent(content: string): Promise<{ chunks: string[]; fallback_used: boolean }> {
    if (!this.shouldChunk(content)) {
      return { chunks: [content], fallback_used: false };
    }

    let fallback_used = false;

    // Use semantic chunking if available and content is long enough
    if (
      this.shouldUseSemanticAnalysis(content) &&
      this.semanticAnalyzer &&
      this.isSemanticAnalysisAvailable()
    ) {
      try {
        const chunks = await this.chunkContentSemantically(content);

        // Validate semantic chunks before returning
        if (this.validateChunks(chunks, content)) {
          return { chunks, fallback_used: false };
        } else {
          logger.warn(
            { chunkCount: chunks.length, contentLength: content.length },
            'Semantic chunks validation failed, falling back to traditional method'
          );
          fallback_used = true;
        }
      } catch (error) {
        // Fallback to traditional chunking if semantic analysis fails
        logger.warn(
          { error, contentLength: content.length },
          'Semantic chunking failed, falling back to traditional method'
        );
        this.recordSemanticAnalysisFailure(error as Error);
        fallback_used = true;
      }
    } else if (this.shouldUseSemanticAnalysis(content) && !this.isSemanticAnalysisAvailable()) {
      // Circuit breaker is open, fallback to traditional
      logger.info(
        { contentLength: content.length, circuitBreakerState: this.circuitBreaker.state },
        'Semantic analysis unavailable (circuit breaker open), using traditional chunking'
      );
      fallback_used = true;
    }

    // Traditional chunking as guaranteed fallback
    const chunks = this.chunkContentTraditionally(content);
    return { chunks, fallback_used };
  }

  /**
   * Determine if semantic analysis should be used
   */
  private shouldUseSemanticAnalysis(content: string): boolean {
    // Check if semantic chunking is disabled by environment variable
    if (environment.getFeatureFlag('semantic-chunking-optional')) {
      logger.debug('Semantic chunking disabled by SEMANTIC_CHUNKING_OPTIONAL=true');
      return false;
    }

    return (
      this.semanticAnalyzer !== undefined && content.length >= this.SEMANTIC_ANALYSIS_THRESHOLD
    );
  }

  /**
   * Chunk content using semantic boundary detection
   */
  private async chunkContentSemantically(content: string): Promise<string[]> {
    if (!this.semanticAnalyzer) {
      logger.debug('Semantic analyzer not available, using traditional chunking');
      return this.chunkContentTraditionally(content);
    }

    // Perform semantic analysis with circuit breaker protection
    const analysis = await this.performSemanticAnalysis(content);

    if (!analysis || analysis.boundaries.length === 0) {
      // No semantic boundaries found or analysis failed, use traditional chunking
      logger.info(
        { contentLength: content.length, hasAnalysis: !!analysis },
        'No semantic boundaries found or analysis failed, using traditional chunking'
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
   * REFACTORED: Simplified orchestration with extracted helper methods
   */
  async createChunkedItems(item: KnowledgeItem): Promise<KnowledgeItem[]> {
    const content = this.extractContent(item);
    const extractedTitle = this.extractTitle(item);

    // Check if chunking is needed
    if (!this.shouldChunk(content)) {
      return this.createSingleChunkedItem(item, content, extractedTitle);
    }

    // Perform chunking
    const chunkResult = await this.performChunking(content);

    // Create parent and child items
    return this.createChunkedItemHierarchy(item, content, extractedTitle, chunkResult);
  }

  /**
   * Create a single non-chunked item with metadata
   */
  private createSingleChunkedItem(
    item: KnowledgeItem,
    content: string,
    extractedTitle: string
  ): KnowledgeItem[] {
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

  /**
   * Perform the actual chunking operation
   */
  private async performChunking(content: string): Promise<{
    chunks: string[];
    fallback_used: boolean;
    semanticAnalysisEnabled: boolean;
    originalContentHash: string;
  }> {
    const chunkResult = await this.chunkContent(content);
    const semanticAnalysisEnabled = this.shouldUseSemanticAnalysis(content);

    // Calculate original content hash for deduplication purposes
    const originalContentHash = createHash('sha256').update(content).digest('hex');

    return {
      chunks: chunkResult.chunks,
      fallback_used: chunkResult.fallback_used,
      semanticAnalysisEnabled,
      originalContentHash,
    };
  }

  /**
   * Create parent and child chunked items with proper hierarchy
   */
  private createChunkedItemHierarchy(
    item: KnowledgeItem,
    content: string,
    extractedTitle: string,
    chunkResult: {
      chunks: string[];
      fallback_used: boolean;
      semanticAnalysisEnabled: boolean;
      originalContentHash: string;
    }
  ): KnowledgeItem[] {
    const { chunks, fallback_used, semanticAnalysisEnabled, originalContentHash } = chunkResult;
    const ttlInfo = inheritTTLFromParent(item);

    // Create parent item
    const parentItem = this.createParentChunkedItem(
      item,
      content,
      extractedTitle,
      chunks,
      ttlInfo,
      semanticAnalysisEnabled,
      fallback_used,
      originalContentHash
    );

    // Create child items
    const childItems = this.createChildChunkedItems(
      item,
      parentItem,
      extractedTitle,
      chunks,
      ttlInfo,
      semanticAnalysisEnabled,
      fallback_used,
      content
    );

    return [parentItem, ...childItems];
  }

  /**
   * Create the parent chunked item with enhanced metadata
   */
  private createParentChunkedItem(
    item: KnowledgeItem,
    content: string,
    extractedTitle: string,
    chunks: string[],
    ttlInfo: any,
    semanticAnalysisEnabled: boolean,
    fallback_used: boolean,
    originalContentHash: string
  ): KnowledgeItem {
    return {
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
          chunk_fallback_used: fallback_used,
          title_carried: extractedTitle !== '',
          average_chunk_size: Math.round(
            chunks.reduce((sum, chunk) => sum + chunk.length, 0) / chunks.length
          ),
        },
      },
    };
  }

  /**
   * Create child chunked items with proper inheritance and metadata
   * ENHANCED: Added deterministic links and reassembly metadata
   */
  private createChildChunkedItems(
    item: KnowledgeItem,
    parentItem: KnowledgeItem,
    extractedTitle: string,
    chunks: string[],
    ttlInfo: any,
    semanticAnalysisEnabled: boolean,
    fallback_used: boolean,
    originalContent: string
  ): KnowledgeItem[] {
    return chunks.map((chunk, index) => {
      const chunkWithContext = this.addContextToChunk(chunk, extractedTitle, index, chunks.length);
      const chunkLength = chunk.length;
      const positionRatio = index / (chunks.length - 1); // 0.0 to 1.0

      // Calculate chunk boundaries for deterministic reassembly
      const chunkBoundaries = this.calculateChunkBoundaries(originalContent, chunks, index);
      const chunkHash = createHash('sha256').update(chunk).digest('hex');
      const reassemblyKey = this.generateReassemblyKey(
        parentItem.id || 'unknown',
        index,
        chunkHash
      );

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
          original_length: originalContent.length,
          chunk_overlap: this.OVERLAP_SIZE,
          content: chunkWithContext,
          extracted_title: extractedTitle,
          chunk_length: chunkLength,
          position_ratio: positionRatio,
          // ENHANCED: Deterministic reassembly metadata
          chunk_hash: chunkHash,
          reassembly_key: reassemblyKey,
          chunk_start_pos: chunkBoundaries.start,
          chunk_end_pos: chunkBoundaries.end,
          chunk_prefix: chunkBoundaries.prefix,
          chunk_suffix: chunkBoundaries.suffix,
          reassembly_order: index,
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
            chunk_fallback_used: fallback_used,
            title_carried: extractedTitle !== '',
            has_context: chunkWithContext !== chunk,
            size_ratio: chunkLength / originalContent.length,
            // ENHANCED: Reassembly metadata
            chunk_hash: chunkHash,
            reassembly_key: reassemblyKey,
            deterministic_order: true,
            reassembly_validation: {
              start_boundary: chunkBoundaries.start,
              end_boundary: chunkBoundaries.end,
              prefix_hash: createHash('sha256').update(chunkBoundaries.prefix).digest('hex'),
              suffix_hash: createHash('sha256').update(chunkBoundaries.suffix).digest('hex'),
            },
          },
        },
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
    });
  }

  /**
   * Extract content from knowledge item for chunking
   */
  private extractContent(item: KnowledgeItem): string {
    let content = '';

    // Try different content fields
    if (item.data.content) {
      content = item.data.content;
    } else {
      // Try other common content fields
      const contentFields = ['body_text', 'body_md', 'description', 'rationale', 'summary'];
      let found = false;
      for (const field of contentFields) {
        if (item.data[field] && typeof item.data[field] === 'string') {
          content = item.data[field];
          found = true;
          break;
        }
      }

      if (!found) {
        // Fallback: combine all string fields
        const contentParts: string[] = [];
        for (const [_key, value] of Object.entries(item.data)) {
          if (typeof value === 'string' && value.length > 0) {
            contentParts.push(value);
          }
        }
        content = contentParts.join('\n\n');
      }
    }

    // Apply truncation limit if needed (this should be rare with proper chunking)
    return this.applyContentTruncation(content || '');
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
  private addContextToChunk(
    chunk: string,
    title: string,
    index: number,
    totalChunks: number
  ): string {
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

  /**
   * Apply content truncation limit with logging when triggered
   */
  private applyContentTruncation(content: string): string {
    if (content.length <= this.CONTENT_TRUNCATION_LIMIT) {
      return content;
    }

    const originalLength = content.length;
    const truncatedContent = content.substring(0, this.CONTENT_TRUNCATION_LIMIT);

    logger.warn(
      {
        original_length: originalLength,
        truncated_length: truncatedContent.length,
        truncation_limit: this.CONTENT_TRUNCATION_LIMIT,
        characters_removed: originalLength - truncatedContent.length,
        removal_percentage: (
          ((originalLength - truncatedContent.length) / originalLength) *
          100
        ).toFixed(1),
      },
      'Content truncated due to length limit - chunking should normally prevent this'
    );

    return truncatedContent;
  }

  /**
   * Calculate chunk boundaries for deterministic reassembly
   */
  private calculateChunkBoundaries(
    originalContent: string,
    chunks: string[],
    chunkIndex: number
  ): { start: number; end: number; prefix: string; suffix: string } {
    // Find approximate boundaries in original content
    const chunkContent = chunks[chunkIndex];
    const chunkLength = chunkContent.length;

    // For more accurate boundary detection, we would need to track positions during chunking
    // For now, calculate approximate boundaries based on chunk size and overlap
    const approxStart = Math.max(0, chunkIndex * (this.CHUNK_SIZE - this.OVERLAP_SIZE));
    const approxEnd = Math.min(originalContent.length, approxStart + chunkLength);

    // Extract prefix and suffix for validation
    const prefix = originalContent.substring(
      approxStart,
      Math.min(approxStart + 100, originalContent.length)
    );
    const suffix = originalContent.substring(
      Math.max(0, approxEnd - 100),
      Math.min(approxEnd, originalContent.length)
    );

    return {
      start: approxStart,
      end: approxEnd,
      prefix,
      suffix,
    };
  }

  /**
   * Generate deterministic reassembly key
   */
  private generateReassemblyKey(parentId: string, chunkIndex: number, chunkHash: string): string {
    const keyData = `${parentId}:${chunkIndex}:${chunkHash}`;
    return createHash('sha256').update(keyData).digest('hex').substring(0, 16);
  }

  /**
   * Validate chunks to ensure they meet quality standards
   * ENHANCED: Added deterministic validation
   */
  private validateChunks(chunks: string[], originalContent: string): boolean {
    // Basic validation checks
    if (!chunks || chunks.length === 0) {
      logger.warn('Chunk validation failed: No chunks generated');
      return false;
    }

    // Check if we have reasonable number of chunks
    const expectedMaxChunks = Math.ceil(originalContent.length / (this.CHUNK_SIZE * 0.5));
    if (chunks.length > expectedMaxChunks * 2) {
      logger.warn(
        { chunkCount: chunks.length, expectedMax: expectedMaxChunks * 2 },
        'Chunk validation failed: Too many chunks generated'
      );
      return false;
    }

    // Check if chunks preserve content integrity
    const combinedContent = chunks.join(' ').replace(/\s+/g, ' ').trim();
    const normalizedOriginal = originalContent.replace(/\s+/g, ' ').trim();

    // Allow for some differences due to preprocessing, but content should be substantially similar
    const similarityRatio =
      Math.min(combinedContent.length, normalizedOriginal.length) /
      Math.max(combinedContent.length, normalizedOriginal.length);

    if (similarityRatio < 0.8) {
      logger.warn(
        {
          similarityRatio,
          originalLength: normalizedOriginal.length,
          combinedLength: combinedContent.length,
        },
        'Chunk validation failed: Content integrity compromised'
      );
      return false;
    }

    // Check chunk size distribution
    const chunkSizes = chunks.map((chunk) => chunk.length);
    const avgChunkSize = chunkSizes.reduce((sum, size) => sum + size, 0) / chunkSizes.length;

    // Average chunk size should be reasonable
    if (avgChunkSize < this.CHUNK_SIZE * 0.3 || avgChunkSize > this.CHUNK_SIZE * 2.0) {
      logger.warn(
        { avgChunkSize, targetSize: this.CHUNK_SIZE },
        'Chunk validation failed: Average chunk size outside acceptable range'
      );
      return false;
    }

    // Check for extremely small or large chunks
    const extremelySmallChunks = chunkSizes.filter((size) => size < 50).length;
    const extremelyLargeChunks = chunkSizes.filter((size) => size > this.CHUNK_SIZE * 2.5).length;

    if (extremelySmallChunks > chunks.length * 0.2) {
      logger.warn(
        { extremelySmallChunks, totalChunks: chunks.length },
        'Chunk validation failed: Too many extremely small chunks'
      );
      return false;
    }

    if (extremelyLargeChunks > chunks.length * 0.1) {
      logger.warn(
        { extremelyLargeChunks, totalChunks: chunks.length },
        'Chunk validation failed: Too many extremely large chunks'
      );
      return false;
    }

    logger.info(
      { chunkCount: chunks.length, avgChunkSize, similarityRatio },
      'Chunk validation passed'
    );

    return true;
  }
}
