// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck


/**
 * Calculate confidence score for search results
 *
 * Confidence indicates how well results match the query:
 * - 0.9-1.0: Exact match (e.g., ID lookup, exact phrase)
 * - 0.7-0.9: High confidence (strong FTS rank)
 * - 0.5-0.7: Medium confidence (fuzzy/trigram match)
 * - 0.3-0.5: Low confidence (weak match)
 * - 0.0-0.3: Very low confidence (fallback results)
 */

export interface ConfidenceFactors {
  ftsScore: number;
  similarityScore?: number;
  isExactMatch: boolean;
  hitCount: number;
  queryLength: number;
}

/**
 * Calculate confidence score based on multiple factors
 *
 * @param factors - Factors influencing confidence
 * @returns Confidence score between 0.0 and 1.0
 */
export function calculateConfidence(factors: ConfidenceFactors): number {
  const { ftsScore, similarityScore, isExactMatch, hitCount, queryLength } = factors;

  // Exact match (e.g., external_id, UUID lookup)
  if (isExactMatch) {
    return 0.95;
  }

  // High FTS rank indicates strong match
  if (ftsScore > 0.5) {
    return 0.85;
  }

  // Medium FTS rank
  if (ftsScore > 0.2) {
    return 0.7;
  }

  // Fuzzy/trigram match (if available)
  if (similarityScore && similarityScore > 0.5) {
    return 0.65;
  }

  if (similarityScore && similarityScore > 0.3) {
    return 0.55;
  }

  // Low recall penalty
  if (hitCount < 3) {
    return 0.3;
  }

  // Very short queries tend to have lower precision
  if (queryLength < 3) {
    return 0.4;
  }

  // Default medium-low confidence
  return 0.5;
}

/**
 * Classify confidence level for display
 */
export function getConfidenceLevel(
  score: number
): 'very_high' | 'high' | 'medium' | 'low' | 'very_low' {
  if (score >= 0.9) return 'very_high';
  if (score >= 0.7) return 'high';
  if (score >= 0.5) return 'medium';
  if (score >= 0.3) return 'low';
  return 'very_low';
}

/**
 * Determine if exact match based on query patterns
 *
 * Exact match indicators:
 * - UUID format (8-4-4-4-12 hex pattern)
 * - Issue ID (GH-123, JIRA-456)
 * - Quoted exact phrase
 * - Hash/commit SHA
 */
export function isExactMatchQuery(query: string): boolean {
  // UUID pattern
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(query)) {
    return true;
  }

  // Issue ID pattern (e.g., GH-123, JIRA-456)
  if (/^[A-Z]+-\d+$/.test(query)) {
    return true;
  }

  // Quoted exact phrase
  if (query.startsWith('"') && query.endsWith('"')) {
    return true;
  }

  // Git commit SHA (7-40 hex chars)
  if (/^[0-9a-f]{7,40}$/i.test(query)) {
    return true;
  }

  return false;
}

/**
 * Adjust confidence based on result consistency
 *
 * If top results have very similar scores, confidence increases
 * If scores vary widely, confidence decreases (ambiguous query)
 */
export function adjustConfidenceByConsistency(baseConfidence: number, topScores: number[]): number {
  if (topScores.length < 2) {
    return baseConfidence;
  }

  // Calculate coefficient of variation
  const mean = topScores.reduce((a, b) => a + b, 0) / topScores.length;
  const variance =
    topScores.reduce((sum, score) => sum + Math.pow(score - mean, 2), 0) / topScores.length;
  const stdDev = Math.sqrt(variance);
  const cv = mean > 0 ? stdDev / mean : 1.0;

  // Low variation (cv < 0.2) = consistent results = boost confidence
  if (cv < 0.2) {
    return Math.min(1.0, baseConfidence + 0.05);
  }

  // High variation (cv > 0.5) = inconsistent = reduce confidence
  if (cv > 0.5) {
    return Math.max(0.0, baseConfidence - 0.1);
  }

  return baseConfidence;
}
