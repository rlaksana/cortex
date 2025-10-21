import { getPrismaClient } from '../../db/prisma.js';

export interface DeepSearchResult {
  id: string;
  kind: string;
  title: string;
  snippet: string;
  fts_score: number;
  similarity_score: number;
  combined_score: number;
}

/**
 * Perform deep search using both FTS and pg_trgm trigram similarity
 *
 * Deep mode combines:
 * - Full-text search (weighted match) - 60% weight
 * - Trigram similarity - 40% weight
 *
 * Use when:
 * - Fast mode returns poor results
 * - User explicitly requests deep mode
 * - Query contains typos or fuzzy terms
 *
 * @param pool - Database connection pool
 * @param query - Search query string
 * @param searchTypes - Knowledge types to search
 * @param topK - Maximum results to return
 * @param minSimilarity - Minimum trigram similarity threshold (0.0-1.0)
 * @returns Array of search results with combined scoring
 */
export async function deepSearch(
  query: string,
  searchTypes: string[] = ['section'],
  topK: number = 20,
  minSimilarity: number = 0.3
): Promise<DeepSearchResult[]> {
  const prisma = getPrismaClient();
  const results: DeepSearchResult[] = [];

  // Search sections with FTS + trigram similarity
  if (searchTypes.includes('section')) {
    const sectionResult = await prisma.$queryRaw<Array<DeepSearchResult>>`
      SELECT
        id,
        'section' AS kind,
        heading AS title,
        LEFT(body_text, 200) AS snippet,
        (0.6 * CASE WHEN ts @@ plainto_tsquery('english', ${query}) THEN 1.0 ELSE 0.0 END +
         0.4 * similarity(COALESCE(heading, ''), ${query})) AS fts_score,
        similarity(body_text, ${query}) AS similarity_score,
        (0.4 * (0.6 * CASE WHEN ts @@ plainto_tsquery('english', ${query}) THEN 1.0 ELSE 0.0 END + 0.4 * similarity(COALESCE(heading, ''), ${query})) +
         0.6 * similarity(body_text, ${query})) AS combined_score
      FROM section
      WHERE
        ts @@ plainto_tsquery('english', ${query})
        OR similarity(body_text, ${query}) > ${minSimilarity}
      ORDER BY combined_score DESC
      LIMIT ${topK}
    `;
    if (sectionResult.length > 0) {
      results.push(...(sectionResult as unknown as DeepSearchResult[]));
    }
  }

  // Search runbook with trigram on service name + steps
  if (searchTypes.includes('runbook')) {
    const runbookResult = await prisma.$queryRaw<Array<DeepSearchResult>>`
      SELECT
        id,
        'runbook' AS kind,
        service AS title,
        LEFT(steps_jsonb::text, 200) AS snippet,
        0.0 AS fts_score,
        GREATEST(similarity(service, ${query}), similarity(steps_jsonb::text, ${query})) AS similarity_score,
        (0.3 * GREATEST(similarity(service, ${query}), similarity(steps_jsonb::text, ${query}))) AS combined_score
      FROM runbook
      WHERE
        similarity(service, ${query}) > ${minSimilarity}
        OR similarity(steps_jsonb::text, ${query}) > ${minSimilarity}
      ORDER BY combined_score DESC
      LIMIT ${topK}
    `;
    if (runbookResult.length > 0) {
      results.push(...(runbookResult as unknown as DeepSearchResult[]));
    }
  }

  // Search change_log with trigram on summary
  if (searchTypes.includes('change')) {
    const changeResult = await prisma.$queryRaw<Array<DeepSearchResult>>`
      SELECT
        id,
        'change' AS kind,
        summary AS title,
        details AS snippet,
        0.0 AS fts_score,
        similarity(summary, ${query}) AS similarity_score,
        (0.3 * similarity(summary, ${query})) AS combined_score
      FROM change_log
      WHERE similarity(summary, ${query}) > ${minSimilarity}
      ORDER BY combined_score DESC
      LIMIT ${topK}
    `;
    if (changeResult.length > 0) {
      results.push(...(changeResult as unknown as DeepSearchResult[]));
    }
  }

  // Sort all results by combined_score descending
  results.sort((a, b) => b.combined_score - a.combined_score);

  return results.slice(0, topK);
}

/**
 * Calculate fuzzy match score for a single string
 * Uses pg_trgm similarity without database query
 */
export async function calculateSimilarity(
  text1: string,
  text2: string
): Promise<number> {
  const prisma = getPrismaClient();
  const result = await prisma.$queryRaw<Array<{ score: number }>>`
    SELECT similarity(${text1}, ${text2}) AS score
  `;
  if (result.length > 0) {
    return Number((result as unknown as Array<{ score: number }>)[0].score);
  }
  return 0;
}
