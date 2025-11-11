
/**
 * Semantic Analyzer for Chunking
 *
 * Provides semantic boundary detection using embeddings to create more meaningful
 * chunks that preserve context coherence and improve search relevance.
 *
 * Features:
 * - Sentence-level semantic similarity analysis
 * - Topic boundary detection using embedding clusters
 * - Paragraph coherence scoring
 * - Sliding window semantic analysis
 * - Configurable similarity thresholds
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { logger } from '@/utils/logger.js';

import { EmbeddingService } from '../embeddings/embedding-service.js';

export interface SemanticBoundary {
  index: number;
  score: number;
  type: 'strong' | 'medium' | 'weak';
  context_before: string;
  context_after: string;
  reason: string;
}

export interface SemanticChunkingConfig {
  // Similarity thresholds (0-1, higher = more similar)
  strong_boundary_threshold: number; // Below this = strong boundary
  medium_boundary_threshold: number; // Below this = medium boundary
  weak_boundary_threshold: number; // Below this = weak boundary

  // Analysis parameters
  window_size: number; // Sentences to analyze for boundary detection
  min_chunk_sentences: number; // Minimum sentences per chunk
  max_chunk_sentences: number; // Maximum sentences per chunk

  // Performance parameters
  enable_caching: boolean; // Cache embeddings for reuse
  cache_ttl: number; // Cache TTL in milliseconds
}

export interface SemanticAnalysisResult {
  boundaries: SemanticBoundary[];
  sentences: string[];
  topic_shifts: number[];
  coherence_scores: number[];
  analysis_metadata: {
    total_sentences: number;
    processing_time: number;
    cache_hits: number;
    embedding_calls: number;
  };
}

export class SemanticAnalyzer {
  private embeddingService: EmbeddingService;
  private config: SemanticChunkingConfig;
  private embeddingCache: Map<string, { embedding: number[]; timestamp: number }> = new Map();
  private consecutiveFailures = 0;
  private lastFailureTime = 0;
  private readonly CIRCUIT_BREAKER_THRESHOLD = 5; // Fail 5 times before opening circuit
  private readonly CIRCUIT_BREAKER_TIMEOUT = 60000; // 1 minute timeout

  constructor(embeddingService: EmbeddingService, config?: Partial<SemanticChunkingConfig>) {
    this.embeddingService = embeddingService;
    this.config = {
      strong_boundary_threshold: 0.3, // Very low similarity = strong boundary
      medium_boundary_threshold: 0.5, // Low similarity = medium boundary
      weak_boundary_threshold: 0.7, // Medium similarity = weak boundary
      window_size: 3, // Analyze 3 sentences before/after
      min_chunk_sentences: 2, // At least 2 sentences per chunk
      max_chunk_sentences: 15, // No more than 15 sentences per chunk
      enable_caching: true,
      cache_ttl: 3600000, // 1 hour
      ...config,
    };
  }

  /**
   * Analyze content for semantic boundaries
   */
  async analyzeSemanticBoundaries(content: string): Promise<SemanticAnalysisResult> {
    const startTime = Date.now();
    // Performance tracking variables
    const cache_hits = 0;
    let embedding_calls = 0;

    try {
      // Step 1: Split content into sentences
      const sentences = this.splitIntoSentences(content);
      if (sentences.length <= this.config.min_chunk_sentences) {
        // Content too short for semantic analysis
        return {
          boundaries: [],
          sentences,
          topic_shifts: [],
          coherence_scores: [],
          analysis_metadata: {
            total_sentences: sentences.length,
            processing_time: Date.now() - startTime,
            cache_hits,
            embedding_calls,
          },
        };
      }

      // Step 2: Generate embeddings for sentences
      const embeddings = await this.getEmbeddingsForSentences(sentences);
      embedding_calls = sentences.length;

      // Step 3: Calculate semantic similarity between consecutive sentences
      const similarities = this.calculateSimilarities(embeddings);

      // Step 4: Identify semantic boundaries
      const boundaries = this.identifyBoundaries(sentences, similarities);

      // Step 5: Analyze topic shifts
      const topicShifts = this.identifyTopicShifts(similarities);

      // Step 6: Calculate coherence scores for potential chunks
      const coherenceScores = this.calculateCoherenceScores(embeddings);

      // Step 7: Clean up expired cache entries
      this.cleanupCache();

      return {
        boundaries,
        sentences,
        topic_shifts: topicShifts,
        coherence_scores: coherenceScores,
        analysis_metadata: {
          total_sentences: sentences.length,
          processing_time: Date.now() - startTime,
          cache_hits,
          embedding_calls,
        },
      };
    } catch (error) {
      logger.error({ error, contentLength: content.length }, 'Semantic boundary analysis failed');
      throw error;
    }
  }

  /**
   * Split content into sentences while preserving structure and handling edge cases
   */
  private splitIntoSentences(content: string): string[] {
    // Normalize whitespace but preserve important structure
    const normalized = content.replace(/[ \t]+/g, ' ').trim();

    // Enhanced sentence splitting with better edge case handling
    const sentences = this.extractSentencesWithEdgeCaseHandling(normalized);

    // Filter and clean sentences
    return this.filterAndCleanSentences(sentences);
  }

  /**
   * Extract sentences with comprehensive edge case handling
   */
  private extractSentencesWithEdgeCaseHandling(content: string): string[] {
    const sentences: string[] = [];
    let currentPosition = 0;

    // Common abbreviations and patterns that should NOT end sentences
    const abbreviations = [
      'Mr',
      'Mrs',
      'Ms',
      'Dr',
      'Prof',
      'Sr',
      'Jr',
      'St',
      'Mt',
      'Ave',
      'Blvd',
      'Rd',
      'etc',
      'e.g',
      'i.e',
      'vs',
      'al',
      'et',
      'cf',
      'viz',
      'ff',
      'p',
      'pp',
      'vol',
      'fig',
      'figs',
      'tab',
      'tabs',
      'eq',
      'eqs',
      'ref',
      'refs',
    ];

    const abbreviationPattern = new RegExp(`\\b(?:${abbreviations.join('|')})[.!?]\\s`, 'gi');

    while (currentPosition < content.length) {
      // Find next potential sentence ending
      const nextEnd = this.findNextSentenceEnd(content, currentPosition, abbreviationPattern);

      if (nextEnd === -1 || nextEnd === content.length) {
        // No more sentence endings, add remaining content
        const remaining = content.substring(currentPosition).trim();
        if (remaining.length > 0) {
          sentences.push(remaining);
        }
        break;
      }

      // Extract sentence
      let sentence = content.substring(currentPosition, nextEnd + 1).trim();

      // Handle special cases
      sentence = this.handleSpecialSentenceCases(sentence);

      if (sentence.length > 0) {
        sentences.push(sentence);
      }

      currentPosition = nextEnd + 1;

      // Skip whitespace between sentences
      while (currentPosition < content.length && /\s/.test(content[currentPosition])) {
        currentPosition++;
      }
    }

    return sentences;
  }

  /**
   * Find the next sentence ending position
   */
  private findNextSentenceEnd(
    content: string,
    startPos: number,
    abbreviationPattern: RegExp
  ): number {
    let position = startPos;

    while (position < content.length) {
      // Look for sentence ending punctuation
      const punctuationMatch = content.slice(position).match(/[.!?]/);
      if (!punctuationMatch) {
        return content.length;
      }

      const punctuationPos = position + punctuationMatch.index!;

      // Check if this is within an abbreviation
      const beforePunctuation = content.slice(Math.max(0, punctuationPos - 10), punctuationPos);
      if (abbreviationPattern.test(beforePunctuation + content[punctuationPos] + ' ')) {
        position = punctuationPos + 1;
        continue;
      }

      // Check if followed by appropriate context (space, newline, or end)
      const afterPunctuation = content.slice(punctuationPos + 1);
      if (afterPunctuation.match(/^\s/) || afterPunctuation.length === 0) {
        // Additional checks to avoid splitting inappropriately
        if (this.isValidSentenceEnding(content, punctuationPos)) {
          return punctuationPos;
        }
      }

      position = punctuationPos + 1;
    }

    return content.length;
  }

  /**
   * Validate that a punctuation mark is a valid sentence ending
   */
  private isValidSentenceEnding(content: string, punctuationPos: number): boolean {
    const beforePunctuation = content.slice(Math.max(0, punctuationPos - 20), punctuationPos);
    const afterPunctuation = content.slice(
      punctuationPos + 1,
      Math.min(content.length, punctuationPos + 10)
    );

    // Don't split after single letters (like in "A. B. C.")
    if (beforePunctuation.match(/\b[A-Za-z]\s*$/)) {
      return false;
    }

    // Don't split within numbers or decimals
    if (beforePunctuation.match(/\d+$/) && afterPunctuation.match(/^\d/)) {
      return false;
    }

    // Don't split within URLs or email addresses
    if (beforePunctuation.match(/https?:\/\//) || beforePunctuation.match(/[\w.-]+@[\w.-]/)) {
      return false;
    }

    // Don't split within file paths
    if (beforePunctuation.match(/[\/\\][\w.-]*$/)) {
      return false;
    }

    return true;
  }

  /**
   * Handle special cases in sentence processing
   */
  private handleSpecialSentenceCases(sentence: string): string {
    // Remove artificial line breaks within sentences
    sentence = sentence.replace(/([a-zA-Z])\n([a-zA-Z])/g, '$1 $2');

    // Preserve important formatting in code blocks
    if (sentence.includes('```')) {
      return sentence;
    }

    // Handle bullet points and numbered lists
    if (sentence.match(/^\s*[-*+•]\s/) || sentence.match(/^\s*\d+\.\s/)) {
      return sentence;
    }

    // Clean up extra whitespace but preserve single spaces
    sentence = sentence.replace(/\s{2,}/g, ' ').trim();

    return sentence;
  }

  /**
   * Filter and clean sentences to ensure quality
   */
  private filterAndCleanSentences(sentences: string[]): string[] {
    const filtered: string[] = [];

    for (const sentence of sentences) {
      const cleaned = sentence.trim();

      // Skip very short fragments
      if (cleaned.length < 5) {
        continue;
      }

      // Skip sentences that are just punctuation or whitespace
      if (/^[^\w]*$/.test(cleaned)) {
        continue;
      }

      // Skip duplicate sentences (case-insensitive)
      const normalized = cleaned.toLowerCase();
      const isDuplicate = filtered.some((existing) => existing.toLowerCase() === normalized);

      if (!isDuplicate) {
        filtered.push(cleaned);
      }
    }

    return filtered;
  }

  /**
   * Get embeddings for sentences with caching
   */
  private async getEmbeddingsForSentences(sentences: string[]): Promise<number[][]> {
    const embeddings: number[][] = [];

    for (const sentence of sentences) {
      // Check cache first
      if (this.config.enable_caching) {
        const cached = this.getCachedEmbedding(sentence);
        if (cached) {
          embeddings.push(cached);
          continue;
        }
      }

      // Check circuit breaker
      if (this.isCircuitBreakerOpen()) {
        logger.warn('Circuit breaker is open, using fallback embeddings');
        embeddings.push(new Array(1536).fill(0)); // Default embedding size
        continue;
      }

      // Generate embedding
      try {
        const result = await this.embeddingService.generateEmbedding(sentence);
        embeddings.push(result.vector);

        // Reset failure count on success
        this.consecutiveFailures = 0;

        // Cache the result
        if (this.config.enable_caching) {
          this.setCachedEmbedding(sentence, result.vector);
        }
      } catch (error) {
        this.consecutiveFailures++;
        this.lastFailureTime = Date.now();

        logger.warn(
          {
            error,
            sentence: sentence.substring(0, 50),
            consecutiveFailures: this.consecutiveFailures,
          },
          'Failed to generate embedding for sentence'
        );

        // Use a zero vector as fallback
        embeddings.push(new Array(1536).fill(0)); // Default embedding size
      }
    }

    return embeddings;
  }

  /**
   * Calculate semantic similarities between consecutive sentences
   */
  private calculateSimilarities(embeddings: number[][]): number[] {
    const similarities: number[] = [];

    for (let i = 0; i < embeddings.length - 1; i++) {
      const similarity = EmbeddingService.calculateSimilarity(embeddings[i], embeddings[i + 1]);
      similarities.push(similarity);
    }

    return similarities;
  }

  /**
   * Identify semantic boundaries based on similarity patterns with enhanced detection
   */
  private identifyBoundaries(sentences: string[], similarities: number[]): SemanticBoundary[] {
    const boundaries: SemanticBoundary[] = [];

    // Apply multiple detection strategies
    const similarityBoundaries = this.detectSimilarityBoundaries(sentences, similarities);
    const structuralBoundaries = this.detectStructuralBoundaries(sentences);
    const topicBoundaries = this.detectTopicBoundaries(sentences, similarities);

    // Combine and score boundaries
    const combinedBoundaries = this.combineBoundaries(
      similarityBoundaries,
      structuralBoundaries,
      topicBoundaries,
      sentences
    );

    // Apply final filtering to ensure quality boundaries
    return this.filterQualityBoundaries(combinedBoundaries, sentences, similarities);
  }

  /**
   * Detect boundaries based on semantic similarity patterns
   */
  private detectSimilarityBoundaries(
    sentences: string[],
    similarities: number[]
  ): SemanticBoundary[] {
    const boundaries: SemanticBoundary[] = [];

    for (let i = 0; i < similarities.length; i++) {
      const similarity = similarities[i];
      let boundaryType: 'strong' | 'medium' | 'weak';
      let reason: string;

      if (similarity < this.config.strong_boundary_threshold) {
        boundaryType = 'strong';
        reason = `Low semantic similarity (${(similarity * 100).toFixed(1)}%) indicates topic change`;
      } else if (similarity < this.config.medium_boundary_threshold) {
        boundaryType = 'medium';
        reason = `Medium semantic similarity (${(similarity * 100).toFixed(1)}%) suggests topic shift`;
      } else if (similarity < this.config.weak_boundary_threshold) {
        boundaryType = 'weak';
        reason = `Reduced semantic similarity (${(similarity * 100).toFixed(1)}%) indicates possible boundary`;
      } else {
        continue; // No significant boundary
      }

      // Apply enhanced sliding window analysis
      if (this.confirmBoundaryWithWindow(similarities, i)) {
        boundaries.push({
          index: i + 1, // Boundary is after this sentence
          score: similarity,
          type: boundaryType,
          context_before: sentences[i],
          context_after: sentences[i + 1],
          reason,
        });
      }
    }

    return boundaries;
  }

  /**
   * Detect boundaries based on structural cues (headings, lists, code blocks)
   */
  private detectStructuralBoundaries(sentences: string[]): SemanticBoundary[] {
    const boundaries: SemanticBoundary[] = [];

    for (let i = 0; i < sentences.length; i++) {
      const sentence = sentences[i];
      let boundaryType: 'strong' | 'medium' | 'weak';
      let reason = '';
      let score = 0.5;

      // Check for heading patterns
      if (this.isHeading(sentence)) {
        boundaryType = 'strong';
        score = 0.2; // Very low similarity indicates strong boundary
        reason = 'Structural boundary: heading detected';
      }
      // Check for list item patterns
      else if (this.isListItem(sentence)) {
        boundaryType = 'medium';
        score = 0.4;
        reason = 'Structural boundary: list item detected';
      }
      // Check for code block markers
      else if (this.isCodeBlock(sentence)) {
        boundaryType = 'strong';
        score = 0.2;
        reason = 'Structural boundary: code block detected';
      }
      // Check for paragraph breaks (empty or very short sentences)
      else if (this.isParagraphBreak(sentence)) {
        boundaryType = 'weak';
        score = 0.6;
        reason = 'Structural boundary: paragraph break detected';
      } else {
        continue;
      }

      boundaries.push({
        index: i,
        score,
        type: boundaryType,
        context_before: i > 0 ? sentences[i - 1] : '',
        context_after: i < sentences.length - 1 ? sentences[i + 1] : '',
        reason,
      });
    }

    return boundaries;
  }

  /**
   * Detect boundaries based on topic clustering and shifts
   */
  private detectTopicBoundaries(sentences: string[], similarities: number[]): SemanticBoundary[] {
    const boundaries: SemanticBoundary[] = [];

    // Look for significant similarity drops that indicate topic shifts
    for (let i = 1; i < similarities.length - 1; i++) {
      const prev = similarities[i - 1];
      const current = similarities[i];
      const next = similarities[i + 1];

      // A topic shift is indicated by a significant drop followed by recovery
      const dropRatio = prev > 0 ? (prev - current) / prev : 0;
      const recoveryRatio = next > current ? (next - current) / current : 0;

      if (dropRatio > 0.4 && recoveryRatio > 0.2) {
        boundaries.push({
          index: i + 1, // Shift occurs after sentence i
          score: current,
          type: 'medium',
          context_before: sentences[i],
          context_after: sentences[i + 1],
          reason: `Topic shift detected: ${Math.round(dropRatio * 100)}% drop with recovery`,
        });
      }
    }

    return boundaries;
  }

  /**
   * Combine boundaries from different detection methods
   */
  private combineBoundaries(
    similarityBoundaries: SemanticBoundary[],
    structuralBoundaries: SemanticBoundary[],
    topicBoundaries: SemanticBoundary[],
    sentences: string[]
  ): SemanticBoundary[] {
    const combinedBoundaries: Map<number, SemanticBoundary> = new Map();

    // Add all boundaries with their indices
    [...similarityBoundaries, ...structuralBoundaries, ...topicBoundaries].forEach((boundary) => {
      const existing = combinedBoundaries.get(boundary.index);

      if (!existing) {
        combinedBoundaries.set(boundary.index, boundary);
      } else {
        // Combine boundary evidence
        const combinedType = this.combineBoundaryTypes(existing.type, boundary.type);
        const combinedScore = Math.min(existing.score, boundary.score); // Lower score = stronger boundary
        const combinedReason = `${existing.reason}; ${boundary.reason}`;

        combinedBoundaries.set(boundary.index, {
          ...existing,
          type: combinedType,
          score: combinedScore,
          reason: combinedReason,
        });
      }
    });

    return Array.from(combinedBoundaries.values());
  }

  /**
   * Filter boundaries to ensure quality and prevent over-chunking
   */
  private filterQualityBoundaries(
    boundaries: SemanticBoundary[],
    sentences: string[],
    similarities: number[]
  ): SemanticBoundary[] {
    if (boundaries.length === 0) return boundaries;

    // Sort by index
    boundaries.sort((a, b) => a.index - b.index);

    const filtered: SemanticBoundary[] = [];
    let lastBoundaryIndex = -1;

    for (const boundary of boundaries) {
      // Ensure minimum distance between boundaries
      const minDistance = Math.max(2, Math.floor(sentences.length * 0.05)); // At least 5% of content

      if (boundary.index - lastBoundaryIndex < minDistance) {
        // Too close to previous boundary, skip or merge
        continue;
      }

      // Ensure we have enough content after boundary for meaningful chunk
      const remainingSentences = sentences.length - boundary.index;
      if (remainingSentences < this.config.min_chunk_sentences) {
        continue;
      }

      // Validate boundary quality
      if (this.validateBoundaryQuality(boundary, sentences, similarities)) {
        filtered.push(boundary);
        lastBoundaryIndex = boundary.index;
      }
    }

    return filtered;
  }

  /**
   * Combine boundary types when multiple detection methods agree
   */
  private combineBoundaryTypes(
    type1: 'strong' | 'medium' | 'weak',
    type2: 'strong' | 'medium' | 'weak'
  ): 'strong' | 'medium' | 'weak' {
    const typeStrength = { strong: 3, medium: 2, weak: 1 };
    const strength1 = typeStrength[type1];
    const strength2 = typeStrength[type2];

    const combinedStrength = Math.max(strength1, strength2);

    switch (combinedStrength) {
      case 3:
        return 'strong';
      case 2:
        return 'medium';
      case 1:
        return 'weak';
      default:
        return 'weak';
    }
  }

  /**
   * Validate boundary quality using multiple criteria
   */
  private validateBoundaryQuality(
    boundary: SemanticBoundary,
    sentences: string[],
    similarities: number[]
  ): boolean {
    const index = boundary.index;

    // Check if we're at document boundaries
    if (index <= 0 || index >= sentences.length - 1) {
      return false;
    }

    // Validate context quality
    const beforeText = boundary.context_before.trim();
    const afterText = boundary.context_after.trim();

    if (beforeText.length < 10 || afterText.length < 10) {
      return false;
    }

    // Check semantic consistency
    if (index > 0 && index < similarities.length) {
      const surroundingSimilarities = similarities.slice(
        Math.max(0, index - 2),
        Math.min(similarities.length, index + 2)
      );

      const avgSimilarity =
        surroundingSimilarities.reduce((a, b) => a + b, 0) / surroundingSimilarities.length;

      // If surrounding area has very high similarity, this might not be a good boundary
      if (avgSimilarity > 0.9 && boundary.type === 'weak') {
        return false;
      }
    }

    return true;
  }

  /**
   * Check if sentence is a heading
   */
  private isHeading(sentence: string): boolean {
    const trimmed = sentence.trim();

    // Markdown headings
    if (trimmed.startsWith('#')) return true;

    // All caps or title case followed by colon
    if (/^[A-Z][A-Z\s]*:/.test(trimmed)) return true;

    // Short, capitalized phrases (likely section headers)
    if (trimmed.length < 50 && /^[A-Z]/.test(trimmed) && !trimmed.includes('.')) return true;

    return false;
  }

  /**
   * Check if sentence is a list item
   */
  private isListItem(sentence: string): boolean {
    const trimmed = sentence.trim();

    // Numbered list items
    if (/^\d+\.\s/.test(trimmed)) return true;

    // Bulleted list items
    if (/^[•\-\*]\s/.test(trimmed)) return true;

    // Lettered list items
    if (/^[a-zA-Z]\.\s/.test(trimmed)) return true;

    return false;
  }

  /**
   * Check if sentence is a code block marker
   */
  private isCodeBlock(sentence: string): boolean {
    const trimmed = sentence.trim();

    // Code block markers
    if (trimmed.startsWith('```')) return true;

    // Code-like patterns
    if (/^\s*(function|class|const|let|var|import|export|def|if|for|while)\s/.test(trimmed))
      return true;

    return false;
  }

  /**
   * Check if sentence represents a paragraph break
   */
  private isParagraphBreak(sentence: string): boolean {
    const trimmed = sentence.trim();

    // Very short fragments or single words
    if (trimmed.length < 10 && !trimmed.includes(' ')) return true;

    // Punctuation-only fragments
    if (/^[^\w\s]*$/.test(trimmed)) return true;

    return false;
  }

  /**
   * Confirm boundary using sliding window analysis
   */
  private confirmBoundaryWithWindow(similarities: number[], index: number): boolean {
    const halfWindow = Math.floor(this.config.window_size / 2);
    const start = Math.max(0, index - halfWindow);
    const end = Math.min(similarities.length - 1, index + halfWindow);

    // Calculate average similarity before and after the potential boundary
    const beforeSimilarities = similarities.slice(start, index);
    const afterSimilarities = similarities.slice(index + 1, end + 1);

    if (beforeSimilarities.length === 0 || afterSimilarities.length === 0) {
      return true; // Not enough context, accept boundary
    }

    const avgBefore =
      beforeSimilarities.reduce((sum, val) => sum + val, 0) / beforeSimilarities.length;

    // Boundary is confirmed if there's a significant drop in similarity
    const dropRatio = (avgBefore - similarities[index]) / avgBefore;
    return dropRatio > 0.3; // 30% drop or more confirms boundary
  }

  /**
   * Identify topic shifts based on similarity patterns
   */
  private identifyTopicShifts(similarities: number[]): number[] {
    const topicShifts: number[] = [];

    // Look for significant drops in similarity
    for (let i = 1; i < similarities.length - 1; i++) {
      const prev = similarities[i - 1];
      const current = similarities[i];
      const next = similarities[i + 1];

      // A topic shift is indicated by a significant drop followed by recovery
      const dropRatio = (prev - current) / prev;
      const recoveryRatio = next > current ? (next - current) / current : 0;

      if (dropRatio > 0.4 && recoveryRatio > 0.2) {
        topicShifts.push(i + 1); // Shift occurs after sentence i
      }
    }

    return topicShifts;
  }

  /**
   * Calculate coherence scores for potential chunks
   */
  private calculateCoherenceScores(embeddings: number[][]): number[] {
    const scores: number[] = [];

    // Calculate coherence for different chunk sizes
    for (
      let size = this.config.min_chunk_sentences;
      size <= this.config.max_chunk_sentences;
      size++
    ) {
      const chunkScores: number[] = [];

      for (let start = 0; start <= embeddings.length - size; start++) {
        const chunkEmbeddings = embeddings.slice(start, start + size);
        const coherence = this.calculateChunkCoherence(chunkEmbeddings);
        chunkScores.push(coherence);
      }

      // Average coherence for this chunk size
      const avgCoherence = chunkScores.reduce((sum, score) => sum + score, 0) / chunkScores.length;
      scores.push(avgCoherence);
    }

    return scores;
  }

  /**
   * Calculate coherence score for a chunk of embeddings
   */
  private calculateChunkCoherence(chunkEmbeddings: number[][]): number {
    if (chunkEmbeddings.length <= 1) {
      return 1.0;
    }

    let totalSimilarity = 0;
    let comparisons = 0;

    // Calculate pairwise similarities within the chunk
    for (let i = 0; i < chunkEmbeddings.length - 1; i++) {
      for (let j = i + 1; j < chunkEmbeddings.length; j++) {
        const similarity = EmbeddingService.calculateSimilarity(
          chunkEmbeddings[i],
          chunkEmbeddings[j]
        );
        totalSimilarity += similarity;
        comparisons++;
      }
    }

    return comparisons > 0 ? totalSimilarity / comparisons : 0;
  }

  /**
   * Get cached embedding if available and not expired
   */
  private getCachedEmbedding(text: string): number[] | null {
    if (!this.config.enable_caching) {
      return null;
    }

    const cached = this.embeddingCache.get(text);
    if (!cached) {
      return null;
    }

    const now = Date.now();
    if (now - cached.timestamp > this.config.cache_ttl) {
      this.embeddingCache.delete(text);
      return null;
    }

    return cached.embedding;
  }

  /**
   * Cache embedding with timestamp
   */
  private setCachedEmbedding(text: string, embedding: number[]): void {
    if (!this.config.enable_caching) {
      return;
    }

    this.embeddingCache.set(text, {
      embedding,
      timestamp: Date.now(),
    });
  }

  /**
   * Check if circuit breaker is open
   */
  private isCircuitBreakerOpen(): boolean {
    if (this.consecutiveFailures < this.CIRCUIT_BREAKER_THRESHOLD) {
      return false;
    }

    const now = Date.now();
    if (now - this.lastFailureTime > this.CIRCUIT_BREAKER_TIMEOUT) {
      // Reset circuit breaker after timeout
      this.consecutiveFailures = 0;
      this.lastFailureTime = 0;
      return false;
    }

    return true;
  }

  /**
   * Clean up expired cache entries
   */
  private cleanupCache(): void {
    if (!this.config.enable_caching) {
      return;
    }

    const now = Date.now();
    const expiredKeys: string[] = [];

    for (const [key, entry] of this.embeddingCache.entries()) {
      if (now - entry.timestamp > this.config.cache_ttl) {
        expiredKeys.push(key);
      }
    }

    expiredKeys.forEach((key) => this.embeddingCache.delete(key));
  }

  /**
   * Get analysis statistics
   */
  getStats(): {
    cache_size: number;
    config: SemanticChunkingConfig;
  } {
    return {
      cache_size: this.embeddingCache.size,
      config: { ...this.config },
    };
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.embeddingCache.clear();
    logger.info('Semantic analyzer cache cleared');
  }
}
