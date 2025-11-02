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

import { logger } from '../../utils/logger.js';
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
   * Split content into sentences while preserving structure
   */
  private splitIntoSentences(content: string): string[] {
    // Normalize whitespace first
    const normalized = content.replace(/\s+/g, ' ').trim();

    // Split by sentence boundaries, but preserve abbreviations and common patterns
    const sentencePatterns = [
      // End of sentence markers (., !, ?) followed by space and uppercase letter
      /([.!?])\s+([A-Z])/g,
      // Line breaks that indicate sentence separation
      /\n\s*\n/g,
      // List item separators
      /[;]\s+/g,
    ];

    let sentences: string[] = [normalized];

    // Apply each pattern progressively
    for (const pattern of sentencePatterns) {
      const newSentences: string[] = [];
      for (const sentence of sentences) {
        const parts = sentence.split(pattern);
        newSentences.push(...parts.map((part) => part.trim()).filter((part) => part.length > 0));
      }
      sentences = newSentences;
    }

    // Filter out very short fragments and clean up
    return sentences
      .filter((sentence) => sentence.length > 10) // Minimum 10 characters
      .map((sentence) => sentence.replace(/^\s+|\s+$/g, '')) // Trim whitespace
      .filter((sentence) => sentence.length > 0); // Remove empty strings
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
   * Identify semantic boundaries based on similarity patterns
   */
  private identifyBoundaries(sentences: string[], similarities: number[]): SemanticBoundary[] {
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

      // Apply sliding window analysis to confirm boundary
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
