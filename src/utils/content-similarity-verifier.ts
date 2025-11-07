/**
 * Content Similarity Verifier
 *
 * Provides comprehensive content similarity analysis for validating
 * document reassembly accuracy with multiple metrics and algorithms.
 */

import { logger } from '@/utils/logger.js';
import { createHash } from 'crypto';

export interface SimilarityMetrics {
  overall_similarity: number; // 0-1 scale
  character_similarity: number;
  word_similarity: number;
  semantic_similarity: number;
  structural_similarity: number;
  sequence_similarity: number;
}

export interface InputSimilarityMetrics {
  character_similarity: number;
  word_similarity: number;
  semantic_similarity: number;
  structural_similarity: number;
  sequence_similarity: number;
}

export interface SimilarityAnalysis {
  metrics: SimilarityMetrics;
  is_acceptable: boolean;
  confidence_level: number;
  details: {
    missing_phrases: string[];
    extra_phrases: string[];
    reordered_sections: string[];
    quality_score: number;
    recommendations: string[];
  };
}

export interface VerificationOptions {
  target_similarity?: number; // Default: 0.995 (99.5%)
  enable_semantic_analysis?: boolean;
  enable_structural_analysis?: boolean;
  min_phrase_length?: number;
  ignore_whitespace?: boolean;
  case_sensitive?: boolean;
}

/**
 * Comprehensive content similarity verification
 */
export class ContentSimilarityVerifier {
  private readonly DEFAULT_TARGET_SIMILARITY = 0.995;
  private readonly MIN_PHRASE_LENGTH = 10;

  /**
   * Verify similarity between original and reassembled content
   */
  async verifyContentSimilarity(
    originalContent: string,
    reassembledContent: string,
    options: VerificationOptions = {}
  ): Promise<SimilarityAnalysis> {
    const opts = {
      target_similarity: options.target_similarity ?? this.DEFAULT_TARGET_SIMILARITY,
      enable_semantic_analysis: options.enable_semantic_analysis ?? true,
      enable_structural_analysis: options.enable_structural_analysis ?? true,
      min_phrase_length: options.min_phrase_length ?? this.MIN_PHRASE_LENGTH,
      ignore_whitespace: options.ignore_whitespace ?? true,
      case_sensitive: options.case_sensitive ?? false,
      ...options,
    };

    logger.debug(
      {
        originalLength: originalContent.length,
        reassembledLength: reassembledContent.length,
        targetSimilarity: opts.target_similarity,
      },
      'Starting content similarity verification'
    );

    // Preprocess content
    const processedOriginal = this.preprocessContent(originalContent, opts);
    const processedReassembled = this.preprocessContent(reassembledContent, opts);

    // Calculate various similarity metrics
    const characterSimilarity = this.calculateCharacterSimilarity(
      processedOriginal,
      processedReassembled
    );
    const wordSimilarity = this.calculateWordSimilarity(
      processedOriginal,
      processedReassembled,
      opts
    );
    const semanticSimilarity = opts.enable_semantic_analysis
      ? await this.calculateSemanticSimilarity(processedOriginal, processedReassembled)
      : 0.5; // Neutral score if semantic analysis disabled
    const structuralSimilarity = opts.enable_structural_analysis
      ? this.calculateStructuralSimilarity(originalContent, reassembledContent)
      : 0.5;
    const sequenceSimilarity = this.calculateSequenceSimilarity(
      processedOriginal,
      processedReassembled
    );

    // Calculate overall similarity (weighted average)
    const overallSimilarity = this.calculateOverallSimilarity({
      character_similarity: characterSimilarity,
      word_similarity: wordSimilarity,
      semantic_similarity: semanticSimilarity,
      structural_similarity: structuralSimilarity,
      sequence_similarity: sequenceSimilarity,
    });

    // Analyze differences
    const details = await this.analyzeDifferences(processedOriginal, processedReassembled, opts);

    // Determine if similarity is acceptable
    const isAcceptable = overallSimilarity >= opts.target_similarity;
    const confidenceLevel = this.calculateConfidenceLevel(overallSimilarity, details.quality_score);

    const analysis: SimilarityAnalysis = {
      metrics: {
        overall_similarity: overallSimilarity,
        character_similarity: characterSimilarity,
        word_similarity: wordSimilarity,
        semantic_similarity: semanticSimilarity,
        structural_similarity: structuralSimilarity,
        sequence_similarity: sequenceSimilarity,
      },
      is_acceptable: isAcceptable,
      confidence_level: confidenceLevel,
      details,
    };

    logger.info(
      {
        overallSimilarity: overallSimilarity,
        targetSimilarity: opts.target_similarity,
        isAcceptable,
        confidenceLevel,
      },
      'Content similarity verification completed'
    );

    return analysis;
  }

  /**
   * Preprocess content for comparison
   */
  private preprocessContent(content: string, options: VerificationOptions): string {
    let processed = content;

    // Normalize whitespace if enabled
    if (options.ignore_whitespace) {
      processed = processed.replace(/\s+/g, ' ').trim();
    }

    // Normalize case if enabled
    if (!options.case_sensitive) {
      processed = processed.toLowerCase();
    }

    return processed;
  }

  /**
   * Calculate character-level similarity using Levenshtein distance
   */
  private calculateCharacterSimilarity(text1: string, text2: string): number {
    const longer = text1.length > text2.length ? text1 : text2;
    const shorter = text1.length > text2.length ? text2 : text1;

    if (longer.length === 0) return 1.0;

    const editDistance = this.calculateLevenshteinDistance(longer, shorter);
    return (longer.length - editDistance) / longer.length;
  }

  /**
   * Calculate word-level similarity using Jaccard similarity
   */
  private calculateWordSimilarity(
    text1: string,
    text2: string,
    options: VerificationOptions
  ): number {
    const words1 = this.extractWords(text1, options.min_phrase_length || this.MIN_PHRASE_LENGTH);
    const words2 = this.extractWords(text2, options.min_phrase_length || this.MIN_PHRASE_LENGTH);

    if (words1.length === 0 && words2.length === 0) return 1.0;
    if (words1.length === 0 || words2.length === 0) return 0.0;

    // Calculate Jaccard similarity for words
    const set1 = new Set(words1);
    const set2 = new Set(words2);

    const intersection = new Set([...set1].filter((x) => set2.has(x)));
    const union = new Set([...set1, ...set2]);

    const wordJaccard = intersection.size / union.size;

    // Calculate phrase-level similarity
    const phrases1 = this.extractPhrases(
      text1,
      options.min_phrase_length || this.MIN_PHRASE_LENGTH
    );
    const phrases2 = this.extractPhrases(
      text2,
      options.min_phrase_length || this.MIN_PHRASE_LENGTH
    );

    const phraseSimilarity = this.calculatePhraseSimilarity(phrases1, phrases2);

    // Weighted average (phrases more important than individual words)
    return wordJaccard * 0.4 + phraseSimilarity * 0.6;
  }

  /**
   * Calculate semantic similarity using n-gram analysis
   */
  private async calculateSemanticSimilarity(text1: string, text2: string): Promise<number> {
    // Extract n-grams for semantic analysis
    const ngrams1 = this.extractNGrams(text1, 3); // Trigrams
    const ngrams2 = this.extractNGrams(text2, 3);

    if (ngrams1.length === 0 && ngrams2.length === 0) return 1.0;
    if (ngrams1.length === 0 || ngrams2.length === 0) return 0.0;

    // Calculate cosine similarity between n-gram vectors
    const vector1 = this.createNgramVector(ngrams1);
    const vector2 = this.createNgramVector(ngrams2);

    return this.calculateCosineSimilarity(vector1, vector2);
  }

  /**
   * Calculate structural similarity (headings, lists, code blocks)
   */
  private calculateStructuralSimilarity(text1: string, text2: string): number {
    const structure1 = this.analyzeStructure(text1);
    const structure2 = this.analyzeStructure(text2);

    let similarityScore = 0;
    let totalElements = 0;

    // Compare heading structures
    const headingSimilarity = this.compareHeadingLevels(structure1.headings, structure2.headings);
    similarityScore += headingSimilarity * 2; // Weight headings more heavily
    totalElements += 2;

    // Compare list structures
    const listSimilarity = this.compareListStructures(structure1.lists, structure2.lists);
    similarityScore += listSimilarity;
    totalElements += 1;

    // Compare code block structures
    const codeSimilarity = this.compareCodeStructures(structure1.codeBlocks, structure2.codeBlocks);
    similarityScore += codeSimilarity;
    totalElements += 1;

    // Compare paragraph structure
    const paragraphSimilarity = this.compareParagraphStructures(
      structure1.paragraphs,
      structure2.paragraphs
    );
    similarityScore += paragraphSimilarity;
    totalElements += 1;

    return totalElements > 0 ? similarityScore / totalElements : 1.0;
  }

  /**
   * Calculate sequence similarity (order of content)
   */
  private calculateSequenceSimilarity(text1: string, text2: string): number {
    const sentences1 = this.extractSentences(text1);
    const sentences2 = this.extractSentences(text2);

    if (sentences1.length === 0 && sentences2.length === 0) return 1.0;
    if (sentences1.length === 0 || sentences2.length === 0) return 0.0;

    // Calculate longest common subsequence length
    const lcsLength = this.calculateLongestCommonSubsequence(sentences1, sentences2);
    const maxLength = Math.max(sentences1.length, sentences2.length);

    return maxLength > 0 ? lcsLength / maxLength : 1.0;
  }

  /**
   * Calculate overall similarity as weighted average
   */
  private calculateOverallSimilarity(metrics: InputSimilarityMetrics): number {
    // Weights based on importance for document reassembly
    const weights = {
      character_similarity: 0.15,
      word_similarity: 0.25,
      semantic_similarity: 0.3,
      structural_similarity: 0.2,
      sequence_similarity: 0.1,
    };

    return (
      metrics.character_similarity * weights.character_similarity +
      metrics.word_similarity * weights.word_similarity +
      metrics.semantic_similarity * weights.semantic_similarity +
      metrics.structural_similarity * weights.structural_similarity +
      metrics.sequence_similarity * weights.sequence_similarity
    );
  }

  /**
   * Analyze differences between original and reassembled content
   */
  private async analyzeDifferences(
    original: string,
    reassembled: string,
    options: VerificationOptions
  ): Promise<SimilarityAnalysis['details']> {
    const originalPhrases = this.extractPhrases(
      original,
      options.min_phrase_length || this.MIN_PHRASE_LENGTH
    );
    const reassembledPhrases = this.extractPhrases(
      reassembled,
      options.min_phrase_length || this.MIN_PHRASE_LENGTH
    );

    const originalSet = new Set(originalPhrases);
    const reassembledSet = new Set(reassembledPhrases);

    // Find missing phrases
    const missingPhrases = originalPhrases.filter((phrase) => !reassembledSet.has(phrase));

    // Find extra phrases
    const extraPhrases = reassembledPhrases.filter((phrase) => !originalSet.has(phrase));

    // Find reordered sections (simple implementation)
    const reorderedSections = this.findReorderedSections(original, reassembled);

    // Calculate quality score
    const totalPhrases = originalPhrases.length;
    const foundPhrases = totalPhrases - missingPhrases.length;
    const phraseRetentionRate = totalPhrases > 0 ? foundPhrases / totalPhrases : 1.0;

    const qualityScore = Math.min(1.0, phraseRetentionRate * (1 - missingPhrases.length * 0.01));

    // Generate recommendations
    const recommendations = this.generateRecommendations(
      missingPhrases,
      extraPhrases,
      qualityScore
    );

    return {
      missing_phrases: missingPhrases.slice(0, 10), // Limit to first 10 for readability
      extra_phrases: extraPhrases.slice(0, 10),
      reordered_sections: reorderedSections,
      quality_score: qualityScore,
      recommendations,
    };
  }

  /**
   * Calculate confidence level based on similarity and quality scores
   */
  private calculateConfidenceLevel(similarity: number, qualityScore: number): number {
    // Combine similarity and quality for confidence
    const baseConfidence = (similarity + qualityScore) / 2;

    // Adjust based on similarity ranges
    if (similarity >= 0.99) {
      return Math.min(1.0, baseConfidence + 0.05);
    } else if (similarity >= 0.95) {
      return baseConfidence;
    } else if (similarity >= 0.9) {
      return Math.max(0.5, baseConfidence - 0.1);
    } else {
      return Math.max(0.1, baseConfidence - 0.2);
    }
  }

  /**
   * Extract meaningful words from text
   */
  private extractWords(text: string, minLength: number): string[] {
    return text
      .toLowerCase()
      .split(/\s+/)
      .filter((word) => word.length >= minLength && /^[a-zA-Z0-9]+$/.test(word));
  }

  /**
   * Extract meaningful phrases from text
   */
  private extractPhrases(text: string, minLength: number): string[] {
    const phrases: string[] = [];
    const sentences = this.extractSentences(text);

    for (const sentence of sentences) {
      // Extract n-grams from each sentence
      const words = sentence.split(/\s+/).filter((w) => w.length > 0);

      for (let n = 2; n <= Math.min(5, words.length); n++) {
        for (let i = 0; i <= words.length - n; i++) {
          const phrase = words.slice(i, i + n).join(' ');
          if (phrase.length >= minLength) {
            phrases.push(phrase);
          }
        }
      }
    }

    return [...new Set(phrases)]; // Remove duplicates
  }

  /**
   * Extract n-grams from text
   */
  private extractNGrams(text: string, n: number): string[] {
    const words = text
      .toLowerCase()
      .split(/\s+/)
      .filter((w) => w.length > 0);
    const ngrams: string[] = [];

    for (let i = 0; i <= words.length - n; i++) {
      ngrams.push(words.slice(i, i + n).join(' '));
    }

    return [...new Set(ngrams)];
  }

  /**
   * Create n-gram vector for similarity calculation
   */
  private createNgramVector(ngrams: string[]): Map<string, number> {
    const vector = new Map<string, number>();
    const total = ngrams.length;

    for (const ngram of ngrams) {
      vector.set(ngram, (vector.get(ngram) || 0) + 1);
    }

    // Normalize by total count
    for (const [key, value] of vector.entries()) {
      vector.set(key, value / total);
    }

    return vector;
  }

  /**
   * Calculate cosine similarity between two vectors
   */
  private calculateCosineSimilarity(
    vector1: Map<string, number>,
    vector2: Map<string, number>
  ): number {
    let dotProduct = 0;
    let magnitude1 = 0;
    let magnitude2 = 0;

    const allKeys = new Set([...vector1.keys(), ...vector2.keys()]);

    for (const key of allKeys) {
      const value1 = vector1.get(key) || 0;
      const value2 = vector2.get(key) || 0;

      dotProduct += value1 * value2;
      magnitude1 += value1 * value1;
      magnitude2 += value2 * value2;
    }

    magnitude1 = Math.sqrt(magnitude1);
    magnitude2 = Math.sqrt(magnitude2);

    if (magnitude1 === 0 || magnitude2 === 0) return 0;

    return dotProduct / (magnitude1 * magnitude2);
  }

  /**
   * Analyze document structure
   */
  private analyzeStructure(text: string) {
    const lines = text.split('\n');
    const structure = {
      headings: [] as string[],
      lists: [] as string[],
      codeBlocks: [] as string[],
      paragraphs: [] as string[],
    };

    let inCodeBlock = false;
    let currentParagraph = '';

    for (const line of lines) {
      const trimmed = line.trim();

      // Code blocks
      if (trimmed.startsWith('```')) {
        inCodeBlock = !inCodeBlock;
        structure.codeBlocks.push(trimmed);
        continue;
      }

      if (inCodeBlock) {
        structure.codeBlocks.push(trimmed);
        continue;
      }

      // Headings
      if (trimmed.startsWith('#')) {
        structure.headings.push(trimmed);
        if (currentParagraph) {
          structure.paragraphs.push(currentParagraph.trim());
          currentParagraph = '';
        }
        continue;
      }

      // Lists
      if (/^\s*[-*+]\s/.test(trimmed) || /^\s*\d+\.\s/.test(trimmed)) {
        structure.lists.push(trimmed);
        if (currentParagraph) {
          structure.paragraphs.push(currentParagraph.trim());
          currentParagraph = '';
        }
        continue;
      }

      // Paragraphs
      if (trimmed) {
        currentParagraph += (currentParagraph ? ' ' : '') + trimmed;
      } else if (currentParagraph) {
        structure.paragraphs.push(currentParagraph.trim());
        currentParagraph = '';
      }
    }

    // Add final paragraph if exists
    if (currentParagraph) {
      structure.paragraphs.push(currentParagraph.trim());
    }

    return structure;
  }

  /**
   * Compare heading structures
   */
  private compareHeadingLevels(headings1: string[], headings2: string[]): number {
    if (headings1.length === 0 && headings2.length === 0) return 1.0;
    if (headings1.length === 0 || headings2.length === 0) return 0.0;

    const levels1 = headings1.map((h) => this.getHeadingLevel(h));
    const levels2 = headings2.map((h) => this.getHeadingLevel(h));

    const commonLength = Math.min(levels1.length, levels2.length);
    let matches = 0;

    for (let i = 0; i < commonLength; i++) {
      if (levels1[i] === levels2[i]) {
        matches++;
      }
    }

    return commonLength > 0 ? matches / Math.max(levels1.length, levels2.length) : 0;
  }

  /**
   * Get heading level from markdown heading
   */
  private getHeadingLevel(heading: string): number {
    const match = heading.match(/^(#+)/);
    return match ? match[1].length : 0;
  }

  /**
   * Compare list structures
   */
  private compareListStructures(lists1: string[], lists2: string[]): number {
    if (lists1.length === 0 && lists2.length === 0) return 1.0;
    if (lists1.length === 0 || lists2.length === 0) return 0.0;

    // Simple comparison based on list patterns
    const patterns1 = lists1.map((l) => this.getListPattern(l));
    const patterns2 = lists2.map((l) => this.getListPattern(l));

    const set1 = new Set(patterns1);
    const set2 = new Set(patterns2);

    const intersection = new Set([...set1].filter((x) => set2.has(x)));
    const union = new Set([...set1, ...set2]);

    return union.size > 0 ? intersection.size / union.size : 1.0;
  }

  /**
   * Get list pattern (numbered vs bulleted)
   */
  private getListPattern(listItem: string): string {
    if (/^\s*\d+\./.test(listItem)) return 'numbered';
    if (/^\s*[-*+]/.test(listItem)) return 'bulleted';
    return 'unknown';
  }

  /**
   * Compare code block structures
   */
  private compareCodeStructures(code1: string[], code2: string[]): number {
    if (code1.length === 0 && code2.length === 0) return 1.0;
    if (code1.length === 0 || code2.length === 0) return 0.0;

    // Compare code block markers and content
    const markers1 = code1.filter((c) => c.startsWith('```')).length;
    const markers2 = code2.filter((c) => c.startsWith('```')).length;

    const markerSimilarity =
      markers1 === markers2 ? 1.0 : Math.min(markers1, markers2) / Math.max(markers1, markers2);

    // Compare code content length
    const content1 = code1.filter((c) => !c.startsWith('```')).join(' ').length;
    const content2 = code2.filter((c) => !c.startsWith('```')).join(' ').length;

    const contentSimilarity =
      content1 === 0 && content2 === 0
        ? 1.0
        : content1 === 0 || content2 === 0
          ? 0.0
          : Math.min(content1, content2) / Math.max(content1, content2);

    return (markerSimilarity + contentSimilarity) / 2;
  }

  /**
   * Compare paragraph structures
   */
  private compareParagraphStructures(paragraphs1: string[], paragraphs2: string[]): number {
    if (paragraphs1.length === 0 && paragraphs2.length === 0) return 1.0;
    if (paragraphs1.length === 0 || paragraphs2.length === 0) return 0.0;

    const avgLength1 = paragraphs1.reduce((sum, p) => sum + p.length, 0) / paragraphs1.length;
    const avgLength2 = paragraphs2.reduce((sum, p) => sum + p.length, 0) / paragraphs2.length;

    const lengthSimilarity =
      avgLength1 === 0 && avgLength2 === 0
        ? 1.0
        : avgLength1 === 0 || avgLength2 === 0
          ? 0.0
          : Math.min(avgLength1, avgLength2) / Math.max(avgLength1, avgLength2);

    const countSimilarity =
      Math.min(paragraphs1.length, paragraphs2.length) /
      Math.max(paragraphs1.length, paragraphs2.length);

    return (lengthSimilarity + countSimilarity) / 2;
  }

  /**
   * Extract sentences from text
   */
  private extractSentences(text: string): string[] {
    return text
      .split(/[.!?]+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  }

  /**
   * Calculate Levenshtein distance between two strings
   */
  private calculateLevenshteinDistance(str1: string, str2: string): number {
    const matrix = [];

    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1, // insertion
            matrix[i - 1][j] + 1 // deletion
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  /**
   * Calculate phrase similarity using longest common subsequence
   */
  private calculatePhraseSimilarity(phrases1: string[], phrases2: string[]): number {
    if (phrases1.length === 0 && phrases2.length === 0) return 1.0;
    if (phrases1.length === 0 || phrases2.length === 0) return 0.0;

    const set1 = new Set(phrases1);
    const set2 = new Set(phrases2);

    const intersection = new Set([...set1].filter((x) => set2.has(x)));
    const union = new Set([...set1, ...set2]);

    return union.size > 0 ? intersection.size / union.size : 1.0;
  }

  /**
   * Calculate longest common subsequence
   */
  private calculateLongestCommonSubsequence(seq1: string[], seq2: string[]): number {
    const dp: number[][] = Array(seq1.length + 1)
      .fill(null)
      .map(() => Array(seq2.length + 1).fill(0));

    for (let i = 1; i <= seq1.length; i++) {
      for (let j = 1; j <= seq2.length; j++) {
        if (seq1[i - 1] === seq2[j - 1]) {
          dp[i][j] = dp[i - 1][j - 1] + 1;
        } else {
          dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
        }
      }
    }

    return dp[seq1.length][seq2.length];
  }

  /**
   * Find reordered sections in text
   */
  private findReorderedSections(original: string, reassembled: string): string[] {
    const originalSections = this.extractSections(original);
    const reassembledSections = this.extractSections(reassembled);

    const reordered: string[] = [];

    for (let i = 0; i < originalSections.length; i++) {
      const originalSection = originalSections[i];
      const reassembledIndex = reassembledSections.findIndex(
        (s) => this.calculateSectionSimilarity(originalSection, s) > 0.8
      );

      if (reassembledIndex !== -1 && Math.abs(i - reassembledIndex) > 1) {
        reordered.push(
          `Section "${originalSection.substring(0, 30)}..." moved from position ${i} to ${reassembledIndex}`
        );
      }
    }

    return reordered;
  }

  /**
   * Extract major sections from text
   */
  private extractSections(text: string): string[] {
    const sections: string[] = [];
    const lines = text.split('\n');
    let currentSection = '';

    for (const line of lines) {
      if (line.startsWith('#')) {
        if (currentSection) {
          sections.push(currentSection.trim());
        }
        currentSection = line;
      } else {
        currentSection += '\n' + line;
      }
    }

    if (currentSection) {
      sections.push(currentSection.trim());
    }

    return sections;
  }

  /**
   * Calculate similarity between two sections
   */
  private calculateSectionSimilarity(section1: string, section2: string): number {
    const words1 = new Set(section1.toLowerCase().split(/\s+/));
    const words2 = new Set(section2.toLowerCase().split(/\s+/));

    const intersection = new Set([...words1].filter((x) => words2.has(x)));
    const union = new Set([...words1, ...words2]);

    return union.size > 0 ? intersection.size / union.size : 1.0;
  }

  /**
   * Generate recommendations based on analysis
   */
  private generateRecommendations(
    missingPhrases: string[],
    extraPhrases: string[],
    qualityScore: number
  ): string[] {
    const recommendations: string[] = [];

    if (missingPhrases.length > 0) {
      recommendations.push(
        `${missingPhrases.length} phrases missing from reassembled content - check chunk boundaries`
      );
    }

    if (extraPhrases.length > 0) {
      recommendations.push(
        `${extraPhrases.length} extra phrases found - possible duplication during reassembly`
      );
    }

    if (qualityScore < 0.95) {
      recommendations.push('Quality score below 95% - review chunking algorithm');
    }

    if (missingPhrases.length > 5) {
      recommendations.push('Consider reducing chunk overlap to prevent content loss');
    }

    if (qualityScore > 0.99) {
      recommendations.push('Excellent reassembly quality - current parameters optimal');
    }

    return recommendations;
  }
}

/**
 * Export singleton instance
 */
export const contentSimilarityVerifier = new ContentSimilarityVerifier();

/**
 * Convenience function for quick verification
 */
export async function verifyContentSimilarity(
  originalContent: string,
  reassembledContent: string,
  options?: VerificationOptions
): Promise<SimilarityAnalysis> {
  return contentSimilarityVerifier.verifyContentSimilarity(
    originalContent,
    reassembledContent,
    options
  );
}
