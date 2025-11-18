// PHASE 2.2A RECOVERY: Snippet utility synchronization complete
// Recovery Date: 2025-11-14T18:00:00+07:00 (Asia/Jakarta)
// Recovery Method: Sequential file-by-file approach with quality gates
// Dependencies: Text snippet generation for search results

import { logger } from './logger.js';

/**
 * Generate highlighted snippet from text using simple text matching
 *
 * Note: This is a simplified implementation that replaces PostgreSQL ts_headline
 * functionality since we're now using Qdrant vector database instead of PostgreSQL.
 *
 * @param bodyText - Full text content to extract snippet from
 * @param query - Search query string
 * @param options - Snippet generation options
 * @returns Highlighted excerpt with <b>...</b> tags around matches
 */
export async function generateSnippet(
  bodyText: string,
  query: string,
  options: {
    maxWords?: number;
    minWords?: number;
    shortWord?: number;
    highlightAll?: boolean;
    maxFragments?: number;
    fragmentDelimiter?: string;
  } = {}
): Promise<string> {
  const { maxWords = 30, minWords = 15, shortWord = 3, highlightAll = false } = options;

  try {
    // Simple text-based snippet generation for vector database context
    const queryWords = query
      .toLowerCase()
      .split(/\s+/)
      .filter((word) => word.length >= shortWord);

    if (queryWords.length === 0) {
      return extractPlainSnippet(bodyText, maxWords * 5);
    }

    // Find the best matching fragment
    const words = bodyText.split(/\s+/);
    const bodyTextLower = bodyText.toLowerCase();

    let bestMatch: { index: number; score: number } = { index: 0, score: 0 };

    // Find the best fragment containing query terms
    for (let i = 0; i <= words.length - minWords; i++) {
      let score = 0;
      const fragmentStart = words.slice(0, i).join(' ').length;
      const fragmentEnd = words.slice(0, i + minWords + (maxWords - minWords)).join(' ').length;
      const fragment = bodyTextLower.substring(fragmentStart, fragmentEnd);

      // Score based on query term matches
      for (const queryWord of queryWords) {
        const matches = (fragment.match(new RegExp(queryWord, 'g')) || []).length;
        score += matches;
      }

      // Prefer fragments that start earlier
      score -= i * 0.01;

      if (score > bestMatch.score) {
        bestMatch = { index: i, score };
      }
    }

    // Extract the fragment around the best match
    const fragmentWords = Math.min(maxWords, words.length - bestMatch.index);
    let snippet = words.slice(bestMatch.index, bestMatch.index + fragmentWords).join(' ');

    // Highlight matches
    if (highlightAll || queryWords.length > 0) {
      for (const queryWord of queryWords) {
        const regex = new RegExp(`(${queryWord})`, 'gi');
        snippet = snippet.replace(regex, '<b>$1</b>');
      }
    }

    // Add ellipsis if we're in the middle of the text
    if (bestMatch.index > 0) {
      snippet = `... ${snippet}`;
    }
    if (bestMatch.index + fragmentWords < words.length) {
      snippet = `${snippet} ...`;
    }

    return snippet || extractPlainSnippet(bodyText, maxWords * 5);
  } catch (error) {
    logger.error({ error, query: query.substring(0, 100) }, 'Failed to generate snippet');
    // Fallback to simple truncation if highlighting fails
    return extractPlainSnippet(bodyText, maxWords * 5);
  }
}

/**
 * Extract plain text snippet without highlighting (for preview)
 */
export function extractPlainSnippet(text: string, maxLength: number = 150): string {
  if (text.length <= maxLength) {
    return text;
  }

  // Try to break at word boundary
  const truncated = text.substring(0, maxLength);
  const lastSpace = truncated.lastIndexOf(' ');

  return lastSpace > maxLength * 0.8
    ? `${truncated.substring(0, lastSpace)}...`
    : `${truncated}...`;
}
