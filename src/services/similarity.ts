/**
 * Similarity Detection Service (Legacy Interface)
 *
 * Legacy interface that delegates to UnifiedSimilarityService for backward compatibility.
 * Uses advanced hybrid similarity analysis combining semantic and lexical analysis.
 *
 * @module services/similarity
 * @deprecated Use UnifiedSimilarityService directly for new code
 */

import crypto from 'crypto';
import { UnifiedSimilarityService } from './similarity/unified-similarity-service.js';
import { logger } from '../utils/logger.js';
import type { KnowledgeItem } from '../types/core-interfaces.js';

export interface SimilarItem {
  id: string;
  kind: string;
  title: string;
  snippet: string;
  similarity_score: number;
  similarity_type: 'exact_duplicate' | 'high_similarity' | 'medium_similarity';
  content_hash?: string;
}

export interface SimilarityResult {
  has_duplicates: boolean;
  has_similar: boolean;
  has_contradictions: boolean;
  similar_items: SimilarItem[];
  recommendation: 'add' | 'update' | 'skip' | 'delete_and_add';
  reasoning: string;
}

// Global unified similarity service instance
let similarityService: UnifiedSimilarityService | null = null;

/**
 * Get or initialize the unified similarity service
 */
function getSimilarityService(): UnifiedSimilarityService {
  if (!similarityService) {
    similarityService = new UnifiedSimilarityService();
  }
  return similarityService;
}

/**
 * Find similar content for a new item being stored
 *
 * @param kind - Knowledge type (section, decision, etc.)
 * @param title - Item title
 * @param content - Item content (body_md, rationale, etc.)
 * @returns Similarity analysis result
 */
export async function findSimilar(
  kind: string,
  title: string,
  content: string
): Promise<SimilarityResult> {
  try {
    const service = getSimilarityService();

    // Create a knowledge item for similarity checking
    const queryItem: KnowledgeItem = {
      id: `temp-${Date.now()}`,
      kind,
      title,
      content,
      timestamp: new Date().toISOString(),
      scope: 'global' // Default scope for legacy compatibility
    };

    // Find similar items using the unified service
    const similarItems = await service.findSimilar(queryItem, {
      threshold: 0.6, // Slightly lower threshold for legacy compatibility
      maxResults: 10
    });

    // Convert unified results to legacy format
    const legacyItems: SimilarItem[] = similarItems.map(result => ({
      id: result.item.id || 'unknown',
      kind: result.item.kind || kind,
      title: result.item.title || 'Untitled',
      snippet: (result.item.content || '').substring(0, 200),
      similarity_score: result.score,
      similarity_type: result.score >= 0.9 ? 'exact_duplicate' :
                     result.score >= 0.7 ? 'high_similarity' : 'medium_similarity',
      content_hash: result.item.id ? computeContentHash(result.item.content || '') : undefined
    }));

    // Analyze results and provide recommendation
    return analyzeLegacyResults(legacyItems);

  } catch (error) {
    logger.error({ error, kind, title }, 'Legacy similarity check failed');

    // Fallback to safe default
    return {
      has_duplicates: false,
      has_similar: false,
      has_contradictions: false,
      similar_items: [],
      recommendation: 'add',
      reasoning: `Similarity check failed: ${(error as Error).message}. Defaulting to add.`,
    };
  }
}

// Helper function to compute content hash
function computeContentHash(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Analyze legacy similarity results and provide recommendation
 */
function analyzeLegacyResults(similarItems: SimilarItem[]): SimilarityResult {
  if (similarItems.length === 0) {
    return {
      has_duplicates: false,
      has_similar: false,
      has_contradictions: false,
      similar_items: [],
      recommendation: 'add',
      reasoning: 'No similar content found. Safe to add as new item.',
    };
  }

  const highestSim = similarItems[0];
  const hasDuplicates = similarItems.some(item => item.similarity_type === 'exact_duplicate');
  const hasHighSimilarity = similarItems.some(item => item.similarity_type === 'high_similarity');

  if (hasDuplicates) {
    return {
      has_duplicates: true,
      has_similar: true,
      has_contradictions: false,
      similar_items: similarItems,
      recommendation: 'skip',
      reasoning: `Exact duplicate(s) found. Skipping to avoid redundancy.`,
    };
  }

  if (highestSim.similarity_score >= 0.8) {
    return {
      has_duplicates: false,
      has_similar: true,
      has_contradictions: false,
      similar_items: similarItems,
      recommendation: 'update',
      reasoning: `High similarity (${(highestSim.similarity_score * 100).toFixed(0)}%) with "${highestSim.title}". Recommend updating existing item instead of creating duplicate.`,
    };
  }

  return {
    has_duplicates: false,
    has_similar: hasHighSimilarity,
    has_contradictions: false,
    similar_items: similarItems,
    recommendation: 'add',
    reasoning: hasHighSimilarity ?
      `Medium similarity found but not high enough to suggest update. Different enough to add as new item.` :
      'Low similarity. Safe to add as new item.',
  };
}

/**
 * Detect if new content contradicts existing content
 *
 * This is a simple heuristic - looks for negation words and opposing values
 *
 * @param existingContent - Existing content
 * @param newContent - New content being added
 * @returns True if likely contradiction detected
 */
export function detectContradiction(existingContent: string, newContent: string): boolean {
  const existing = existingContent.toLowerCase();
  const newText = newContent.toLowerCase();

  // Check for version number contradictions (e.g., "qdrant 17" vs "qdrant 18")
  const versionRegex = /(\w+)\s+(\d+(?:\.\d+)?)/g;
  const existingVersions = [...existing.matchAll(versionRegex)];
  const newVersions = [...newText.matchAll(versionRegex)];

  for (const match1 of existingVersions) {
    const name1 = match1[1];
    const ver1 = match1[2];
    for (const match2 of newVersions) {
      const name2 = match2[1];
      const ver2 = match2[2];
      if (name1 === name2 && ver1 !== ver2) {
        return true; // Same software, different versions = contradiction
      }
    }
  }

  // Check for boolean contradictions
  const negationPairs = [
    ['use', "don't use"],
    ['enable', 'disable'],
    ['true', 'false'],
    ['yes', 'no'],
    ['allowed', 'forbidden'],
    ['required', 'optional'],
  ];

  for (const [positive, negative] of negationPairs) {
    if (
      (existing.includes(positive) && newText.includes(negative)) ||
      (existing.includes(negative) && newText.includes(positive))
    ) {
      return true;
    }
  }

  return false;
}
