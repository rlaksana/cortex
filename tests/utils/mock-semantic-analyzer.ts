/**
 * Mock Semantic Analyzer for Testing
 *
 * Provides deterministic semantic boundary detection for testing without requiring real embedding operations
 */

import type {
  SemanticBoundary,
  SemanticChunkingConfig,
  SemanticAnalysisResult,
} from '../../src/services/chunking/semantic-analyzer.js';
import type { EmbeddingService } from '../../src/services/embeddings/embedding-service.js';

export interface MockSemanticAnalyzerConfig {
  shouldFail?: boolean;
  boundaryPositions?: number[]; // Specific sentence indices to create boundaries at
  strongBoundaryThreshold?: number;
  mediumBoundaryThreshold?: number;
  weakBoundaryThreshold?: number;
}

export class MockSemanticAnalyzer {
  private config: Required<MockSemanticAnalyzerConfig>;
  private embeddingService: EmbeddingService;

  constructor(embeddingService: EmbeddingService, config: SemanticChunkingConfig) {
    this.embeddingService = embeddingService;
    this.config = {
      shouldFail: false,
      boundaryPositions: [], // Will be calculated automatically if not provided
      strongBoundaryThreshold: config.strong_boundary_threshold || 0.3,
      mediumBoundaryThreshold: config.medium_boundary_threshold || 0.5,
      weakBoundaryThreshold: config.weak_boundary_threshold || 0.7,
    };
  }

  /**
   * Analyze semantic boundaries in text
   */
  async analyzeSemanticBoundaries(content: string): Promise<SemanticAnalysisResult> {
    if (this.config.shouldFail) {
      throw new Error('Mock semantic analyzer failed');
    }

    // Split content into sentences
    const sentences = this.splitIntoSentences(content);

    if (sentences.length < 3) {
      // Not enough sentences for meaningful semantic analysis
      return {
        boundaries: [],
        sentences,
        topic_shifts: [],
        coherence_scores: [],
        analysis_metadata: {
          total_sentences: sentences.length,
          processing_time: 5, // Mock processing time for short content
          cache_hits: 0,
          embedding_calls: 0,
        },
      };
    }

    // Generate boundaries deterministically based on content structure
    const boundaries = this.generateDeterministicBoundaries(sentences);
    const topic_shifts = boundaries.length;
    const coherence_scores = this.generateCoherenceScores(sentences);

    return {
      boundaries,
      sentences,
      topic_shifts,
      coherence_scores,
      analysis_metadata: {
        total_sentences: sentences.length,
        processing_time: 10, // Mock processing time
        cache_hits: 0,
        embedding_calls: sentences.length,
      },
    };
  }

  /**
   * Split content into sentences
   */
  private splitIntoSentences(content: string): string[] {
    // Simple sentence splitting - can be enhanced for testing edge cases
    return content
      .split(/[.!?]+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0)
      .map((s) => s + (s.endsWith('.') ? '' : '.')); // Add period back if missing
  }

  /**
   * Generate deterministic boundaries based on sentence content and structure
   */
  private generateDeterministicBoundaries(sentences: string[]): SemanticBoundary[] {
    const boundaries: SemanticBoundary[] = [];

    // Use provided boundary positions or calculate them
    const positions =
      this.config.boundaryPositions.length > 0
        ? this.config.boundaryPositions
        : this.calculateBoundaryPositions(sentences);

    for (const position of positions) {
      if (position > 0 && position < sentences.length - 1) {
        const boundary = this.createBoundaryAtPosition(sentences, position);
        if (boundary) {
          boundaries.push(boundary);
        }
      }
    }

    return boundaries;
  }

  /**
   * Calculate logical boundary positions based on content structure
   */
  private calculateBoundaryPositions(sentences: string[]): number[] {
    const positions: number[] = [];

    // Look for structural indicators
    for (let i = 1; i < sentences.length - 1; i++) {
      const sentence = sentences[i];
      const prevSentence = sentences[i - 1];

      // Boundary indicators
      const hasHeader = /^#+ |^## |^### /.test(sentence);
      const hasListStart = /^[-*+] |^\d+\. /.test(sentence);
      const hasCodeBlock = sentence.includes('```') || sentence.includes('`');
      const hasTransition =
        /however|therefore|moreover|furthermore|consequently|in conclusion/.test(
          sentence.toLowerCase()
        );
      const hasQuestion = sentence.includes('?');
      const lengthChange =
        Math.abs(sentence.length - prevSentence.length) > prevSentence.length * 0.5;

      // Score the boundary strength
      let score = 0;
      if (hasHeader) score += 0.4;
      if (hasListStart) score += 0.3;
      if (hasCodeBlock) score += 0.3;
      if (hasTransition) score += 0.2;
      if (hasQuestion) score += 0.2;
      if (lengthChange) score += 0.1;

      // Determine boundary type based on score
      if (score >= this.config.strongBoundaryThreshold) {
        positions.push(i);
      } else if (score >= this.config.mediumBoundaryThreshold && i % 3 === 0) {
        positions.push(i); // Add some medium boundaries at regular intervals
      }
    }

    // Ensure we have some boundaries for longer content - this is key for testing
    if (positions.length === 0 && sentences.length > 6) {
      // Add boundaries at logical points
      const thirdPoint = Math.floor(sentences.length / 3);
      const twoThirdsPoint = Math.floor((sentences.length * 2) / 3);
      positions.push(thirdPoint, twoThirdsPoint);
    }

    // For very long content, ensure we have boundaries to create chunks
    if (sentences.length > 20 && positions.length < 3) {
      // Force boundaries for testing
      const interval = Math.floor(sentences.length / 5);
      for (let i = interval; i < sentences.length - 1; i += interval) {
        if (!positions.includes(i)) {
          positions.push(i);
        }
      }
    }

    return positions;
  }

  /**
   * Create a semantic boundary at the given position
   */
  private createBoundaryAtPosition(sentences: string[], position: number): SemanticBoundary | null {
    if (position <= 0 || position >= sentences.length - 1) {
      return null;
    }

    const context_before = sentences.slice(Math.max(0, position - 2), position).join(' ');
    const context_after = sentences
      .slice(position, Math.min(sentences.length, position + 3))
      .join(' ');

    // Calculate boundary strength based on context changes
    const lengthRatio = sentences[position].length / (sentences[position - 1].length || 1);
    const hasStructuralChange = this.hasStructuralChange(
      sentences[position - 1],
      sentences[position]
    );

    let score = 0.5; // Base score
    if (hasStructuralChange) score += 0.3;
    if (lengthRatio < 0.5 || lengthRatio > 2.0) score += 0.2;

    // Determine boundary type
    let type: 'strong' | 'medium' | 'weak';
    if (score <= this.config.strongBoundaryThreshold) {
      type = 'strong';
    } else if (score <= this.config.mediumBoundaryThreshold) {
      type = 'medium';
    } else {
      type = 'weak';
    }

    return {
      index: position,
      score,
      type,
      context_before: context_before.trim(),
      context_after: context_after.trim(),
      reason: this.generateBoundaryReason(sentences[position - 1], sentences[position], type),
    };
  }

  /**
   * Check if there's a structural change between sentences
   */
  private hasStructuralChange(prevSentence: string, currSentence: string): boolean {
    const prevHasHeader = /^#+ |^## |^### /.test(prevSentence);
    const currHasHeader = /^#+ |^## |^### /.test(currSentence);
    const prevHasList = /^[-*+] |^\d+\. /.test(prevSentence);
    const currHasList = /^[-*+] |^\d+\. /.test(currSentence);
    const prevHasCode = prevSentence.includes('```') || prevSentence.includes('`');
    const currHasCode = currSentence.includes('```') || currSentence.includes('`');

    return (
      prevHasHeader !== currHasHeader || prevHasList !== currHasList || prevHasCode !== currHasCode
    );
  }

  /**
   * Generate a human-readable reason for the boundary
   */
  private generateBoundaryReason(
    prevSentence: string,
    currSentence: string,
    type: 'strong' | 'medium' | 'weak'
  ): string {
    if (currSentence.match(/^#+ /)) {
      return 'New section header detected';
    }
    if (currSentence.match(/^[-*+] |^\d+\. /)) {
      return 'List item boundary';
    }
    if (currSentence.includes('```')) {
      return 'Code block boundary';
    }
    if (currSentence.includes('?')) {
      return 'Question boundary';
    }
    if (
      /however|therefore|moreover|furthermore|consequently|in conclusion/.test(
        currSentence.toLowerCase()
      )
    ) {
      return 'Transition phrase detected';
    }
    if (type === 'strong') {
      return 'Strong semantic shift detected';
    } else if (type === 'medium') {
      return 'Medium semantic shift detected';
    } else {
      return 'Weak semantic boundary detected';
    }
  }

  /**
   * Generate coherence scores for sentences
   */
  private generateCoherenceScores(sentences: string[]): number[] {
    const scores: number[] = [];

    for (let i = 0; i < sentences.length; i++) {
      if (i === 0) {
        scores.push(1.0); // First sentence has full coherence with itself
      } else {
        // Calculate coherence based on length similarity and content overlap
        const lengthRatio =
          Math.min(sentences[i].length, sentences[i - 1].length) /
          Math.max(sentences[i].length, sentences[i - 1].length);
        const contentOverlap = this.calculateContentOverlap(sentences[i - 1], sentences[i]);

        const coherence = lengthRatio * 0.3 + contentOverlap * 0.7;
        scores.push(Math.min(1.0, Math.max(0.0, coherence)));
      }
    }

    return scores;
  }

  /**
   * Calculate simple content overlap between sentences
   */
  private calculateContentOverlap(sentence1: string, sentence2: string): number {
    const words1 = new Set(
      sentence1
        .toLowerCase()
        .split(/\s+/)
        .filter((w) => w.length > 3)
    );
    const words2 = new Set(
      sentence2
        .toLowerCase()
        .split(/\s+/)
        .filter((w) => w.length > 3)
    );

    if (words1.size === 0 || words2.size === 0) {
      return 0.0;
    }

    const intersection = new Set([...words1].filter((w) => words2.has(w)));
    const union = new Set([...words1, ...words2]);

    return intersection.size / union.size;
  }
}

/**
 * Helper function to create a mock semantic analyzer
 */
export function createMockSemanticAnalyzer(
  embeddingService: EmbeddingService,
  config: MockSemanticAnalyzerConfig = {}
): MockSemanticAnalyzer {
  const mockConfig: SemanticChunkingConfig = {
    strong_boundary_threshold: config.strongBoundaryThreshold || 0.3,
    medium_boundary_threshold: config.mediumBoundaryThreshold || 0.5,
    weak_boundary_threshold: config.weakBoundaryThreshold || 0.7,
    window_size: 3,
    min_chunk_sentences: 2,
    max_chunk_sentences: 15,
    enable_caching: true,
    cache_ttl: 3600000,
  };

  const analyzer = new MockSemanticAnalyzer(embeddingService, mockConfig);

  // Apply config overrides
  if (config.shouldFail !== undefined) {
    (analyzer as any).config.shouldFail = config.shouldFail;
  }
  if (config.boundaryPositions !== undefined) {
    (analyzer as any).config.boundaryPositions = config.boundaryPositions;
  }

  return analyzer;
}
