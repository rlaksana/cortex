// @ts-nocheck
import { qdrant } from '../../db/qdrant-client.js';

export interface Suggestion {
  type: 'spelling' | 'filter' | 'broader' | 'alternative';
  text: string;
  reason?: string;
}

/**
 * Generate search suggestions when results are poor or empty
 *
 * Suggestions include:
 * - Spelling corrections (using pg_trgm)
 * - Filter removal hints
 * - Broader search terms
 * - Alternative query formats
 *
 * @param pool - Database connection pool
 * @param query - Original search query
 * @param hitCount - Number of results found
 * @param hasFilters - Whether scope/type filters were applied
 * @returns Array of actionable suggestions
 */
export async function generateSuggestions(
  query: string,
  hitCount: number,
  hasFilters: boolean = false
): Promise<Suggestion[]> {
  const suggestions: Suggestion[] = [];

  // Low or no results - provide helpful suggestions
  if (hitCount < 3) {
    // Suggest removing filters if applied
    if (hasFilters) {
      suggestions.push({
        type: 'filter',
        text: 'Try removing scope or type filters',
        reason: 'Filters may be too restrictive',
      });
    }

    // Suggest broader terms
    if (query.split(' ').length > 3) {
      suggestions.push({
        type: 'broader',
        text: 'Try using fewer, more general keywords',
        reason: 'Long queries may be too specific',
      });
    }

    // Check for potential spelling errors using trigram similarity
    const spellingCheck = await checkSpelling(query);
    if (spellingCheck.length > 0) {
      suggestions.push({
        type: 'spelling',
        text: `Did you mean: ${spellingCheck.join(', ')}?`,
        reason: 'Possible typo detected',
      });
    }

    // Suggest alternative formats for structured queries
    if (/^[A-Z]+-\d+$/.test(query)) {
      // Looks like issue ID (e.g., "GH-123")
      suggestions.push({
        type: 'alternative',
        text: 'Try searching without the prefix (e.g., just the number)',
        reason: 'Issue ID format detected',
      });
    }

    // Generic helpful suggestions
    if (suggestions.length === 0) {
      suggestions.push(
        {
          type: 'broader',
          text: 'Try different keywords or synonyms',
        },
        {
          type: 'broader',
          text: 'Check for typos in your search',
        }
      );
    }
  }

  return suggestions.slice(0, 3); // Max 3 suggestions
}

/**
 * Check for spelling errors using trigram similarity against existing content
 *
 * @param pool - Database connection pool
 * @param query - Search query to check
 * @returns Array of potential correct spellings
 */
async function checkSpelling(query: string): Promise<string[]> {
  const words = query
    .toLowerCase()
    .split(/\s+/)
    .filter((w) => w.length > 3);

  if (words.length === 0) {
    return [];
  }

  const corrections: string[] = [];

  for (const word of words) {
    try {
      // Find similar words in section titles and content using Qdrant
      const sections = await qdrant.getClient().section.findMany({
        select: {
          title: true,
          content: true,
        },
        take: 1000, // Limit for performance
      });

      // Extract words from sections and find similar ones
      const sectionWords = new Set<string>();
      for (const section of sections) {
        if (section.title) {
          section.title.toLowerCase().split(/\s+/).forEach((w: string) => {
            if (w.length > 3) sectionWords.add(w);
          });
        }
        if (section.content) {
          section.content.toLowerCase().split(/\s+/).forEach((w: string) => {
            if (w.length > 3) sectionWords.add(w);
          });
        }
      }

      // Find similar words using simple string similarity
      const similarWords = Array.from(sectionWords)
        .filter(w => w !== word && calculateSimilarity(word, w) > 0.6)
        .sort((a, b) => calculateSimilarity(word, b) - calculateSimilarity(word, a))
        .slice(0, 2);

      corrections.push(...similarWords);
    } catch {
      // Ignore spelling check errors
      continue;
    }
  }

  return [...new Set(corrections)].slice(0, 3);
}

// Simple similarity calculation for spelling suggestions
function calculateSimilarity(str1: string, str2: string): number {
  const longer = str1.length > str2.length ? str1 : str2;
  const shorter = str1.length > str2.length ? str2 : str1;

  if (longer.length === 0) return 1.0;

  const editDistance = levenshteinDistance(longer, shorter);
  return (longer.length - editDistance) / longer.length;
}

// Levenshtein distance calculation
function levenshteinDistance(str1: string, str2: string): number {
  const matrix = Array(str2.length + 1).fill(null).map(() => Array(str1.length + 1).fill(null));

  for (let i = 0; i <= str1.length; i++) matrix[0][i] = i;
  for (let j = 0; j <= str2.length; j++) matrix[j][0] = j;

  for (let j = 1; j <= str2.length; j++) {
    for (let i = 1; i <= str1.length; i++) {
      const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j][i - 1] + 1, // deletion
        matrix[j - 1][i] + 1, // insertion
        matrix[j - 1][i - 1] + indicator, // substitution
      );
    }
  }

  return matrix[str2.length][str1.length];
}

/**
 * Simplify query by removing common stop words and special characters
 */
export function simplifyQuery(query: string): string {
  const stopWords = new Set(['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for']);

  return query
    .toLowerCase()
    .split(/\s+/)
    .filter((word) => !stopWords.has(word) && word.length > 2)
    .join(' ');
}
