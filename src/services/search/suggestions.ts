import { Pool } from 'pg';

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
  pool: Pool,
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
    const spellingCheck = await checkSpelling(pool, query);
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
async function checkSpelling(pool: Pool, query: string): Promise<string[]> {
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
      // Find similar words in section headings/body_text
      const result = await pool.query(
        `
        SELECT DISTINCT word
        FROM (
          SELECT unnest(string_to_array(lower(heading), ' ')) AS word FROM section
          UNION ALL
          SELECT unnest(string_to_array(lower(body_text), ' ')) AS word FROM section LIMIT 1000
        ) words
        WHERE
          length(word) > 3
          AND similarity(word, $1) > 0.6
          AND word != $1
        ORDER BY similarity(word, $1) DESC
        LIMIT 2
      `,
        [word]
      );

      if (result.rows.length > 0) {
        corrections.push(...result.rows.map((r) => r.word));
      }
    } catch (error) {
      // Ignore spelling check errors
      continue;
    }
  }

  return [...new Set(corrections)].slice(0, 3);
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
