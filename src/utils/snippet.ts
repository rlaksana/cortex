import { getPrismaClient } from '../db/prisma.js';

/**
 * Generate highlighted snippet from text using PostgreSQL ts_headline
 *
 * @param bodyText - Full text content to extract snippet from
 * @param query - Search query string
 * @param options - ts_headline options
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
  const prisma = getPrismaClient();
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
    const result = await prisma.$queryRaw<Array<{ snippet: string }>>`
      SELECT ts_headline('english', ${bodyText}, plainto_tsquery('english', ${query}), ${hlOptions}) AS snippet
    `;

    return result[0]?.snippet ?? bodyText.substring(0, maxWords * 5);
  } catch {
    // Fallback to simple truncation if ts_headline fails
    return `${bodyText.substring(0, maxWords * 5)}...`;
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
