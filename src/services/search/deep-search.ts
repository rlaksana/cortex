import { Pool } from 'pg';

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
 * - Full-text search (ts_rank) - 70% weight
 * - Trigram similarity - 30% weight
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
  pool: Pool,
  query: string,
  searchTypes: string[] = ['section'],
  topK: number = 20,
  minSimilarity: number = 0.3
): Promise<DeepSearchResult[]> {
  const results: DeepSearchResult[] = [];

  // Search sections with FTS + trigram similarity
  if (searchTypes.includes('section')) {
    const sectionQuery = `
      SELECT
        id,
        'section' AS kind,
        heading AS title,
        LEFT(body_text, 200) AS snippet,
        ts_rank(ts, plainto_tsquery('english', $1)) AS fts_score,
        similarity(body_text, $1) AS similarity_score,
        (0.7 * ts_rank(ts, plainto_tsquery('english', $1)) + 0.3 * similarity(body_text, $1)) AS combined_score
      FROM section
      WHERE
        ts @@ plainto_tsquery('english', $1)
        OR similarity(body_text, $1) > $2
      ORDER BY combined_score DESC
      LIMIT $3
    `;

    const sectionResult = await pool.query(sectionQuery, [query, minSimilarity, topK]);
    results.push(...sectionResult.rows);
  }

  // Search runbook with trigram on service name + steps
  if (searchTypes.includes('runbook')) {
    const runbookQuery = `
      SELECT
        id,
        'runbook' AS kind,
        service AS title,
        LEFT(steps_jsonb::text, 200) AS snippet,
        0.0 AS fts_score,
        GREATEST(similarity(service, $1), similarity(steps_jsonb::text, $1)) AS similarity_score,
        (0.3 * GREATEST(similarity(service, $1), similarity(steps_jsonb::text, $1))) AS combined_score
      FROM runbook
      WHERE
        similarity(service, $1) > $2
        OR similarity(steps_jsonb::text, $1) > $2
      ORDER BY combined_score DESC
      LIMIT $3
    `;

    const runbookResult = await pool.query(runbookQuery, [query, minSimilarity, topK]);
    results.push(...runbookResult.rows);
  }

  // Search change_log with trigram on summary
  if (searchTypes.includes('change')) {
    const changeQuery = `
      SELECT
        id,
        'change' AS kind,
        summary AS title,
        details AS snippet,
        0.0 AS fts_score,
        similarity(summary, $1) AS similarity_score,
        (0.3 * similarity(summary, $1)) AS combined_score
      FROM change_log
      WHERE similarity(summary, $1) > $2
      ORDER BY combined_score DESC
      LIMIT $3
    `;

    const changeResult = await pool.query(changeQuery, [query, minSimilarity, topK]);
    results.push(...changeResult.rows);
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
  pool: Pool,
  text1: string,
  text2: string
): Promise<number> {
  const result = await pool.query('SELECT similarity($1, $2) AS score', [text1, text2]);
  return result.rows[0]?.score || 0;
}
