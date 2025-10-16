import { Pool } from 'pg';

/**
 * Generate highlighted snippet from text using PostgreSQL ts_headline
 *
 * @param pool - Database connection pool
 * @param bodyText - Full text content to extract snippet from
 * @param query - Search query string
 * @param options - ts_headline options
 * @returns Highlighted excerpt with <b>...</b> tags around matches
 */
export async function generateSnippet(
  pool: Pool,
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
  const {
    maxWords = 30,
    minWords = 15,
    shortWord = 3,
    highlightAll = false,
    maxFragments = 1,
    fragmentDelimiter = ' ... ',
  } = options;

  // Build ts_headline options string
  const hlOptions = [
    `MaxWords=${maxWords}`,
    `MinWords=${minWords}`,
    `ShortWord=${shortWord}`,
    `HighlightAll=${highlightAll}`,
    `MaxFragments=${maxFragments}`,
    `FragmentDelimiter=${fragmentDelimiter}`,
  ].join(', ');

  try {
    const result = await pool.query<{ snippet: string }>(
      `SELECT ts_headline('english', $1, plainto_tsquery('english', $2), $3) AS snippet`,
      [bodyText, query, hlOptions]
    );

    return result.rows[0]?.snippet ?? bodyText.substring(0, maxWords * 5);
  } catch (_error) {
    // Fallback to simple truncation if ts_headline fails
    return `${bodyText.substring(0, maxWords * 5)  }...`;
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
    ? `${truncated.substring(0, lastSpace)  }...`
    : `${truncated  }...`;
}
