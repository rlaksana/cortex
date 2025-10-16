/**
 * Similarity Detection Service
 *
 * Detects duplicate and contradicting content to enable autonomous decision-making.
 * Uses PostgreSQL trigram similarity and content hashing.
 *
 * @module services/similarity
 */

import type { Pool } from 'pg';
import { computeContentHash } from '../utils/hash.js';

interface QueryRow {
  id: string;
  title: string;
  snippet: string;
  content_hash?: string;
  sim_score?: string;
}

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

/**
 * Find similar content for a new item being stored
 *
 * @param pool - PostgreSQL connection pool
 * @param kind - Knowledge type (section, decision, etc.)
 * @param title - Item title
 * @param content - Item content (body_md, rationale, etc.)
 * @returns Similarity analysis result
 */
export async function findSimilar(
  pool: Pool,
  kind: string,
  title: string,
  content: string
): Promise<SimilarityResult> {
  const similarItems: SimilarItem[] = [];

  // Compute content hash for exact duplicate detection
  const contentHash = computeContentHash(JSON.stringify({ title, content }));

  // Table mapping for different knowledge types
  const tableMap: Record<string, { table: string; titleCol: string; contentCol: string }> = {
    section: { table: 'section', titleCol: 'heading', contentCol: 'body_text' },
    decision: { table: 'adr_decision', titleCol: 'title', contentCol: 'rationale' },
    issue: { table: 'issue_log', titleCol: 'title', contentCol: 'description' },
    runbook: { table: 'runbook', titleCol: 'service', contentCol: 'steps_jsonb::text' },
    todo: { table: 'todo_log', titleCol: 'scope', contentCol: 'text' },
  };

  const mapping = tableMap[kind];
  if (!mapping) {
    // Unknown kind, can't check similarity
    return {
      has_duplicates: false,
      has_similar: false,
      has_contradictions: false,
      similar_items: [],
      recommendation: 'add',
      reasoning: 'Unknown kind, proceeding with add',
    };
  }

  try {
    // Check for exact duplicate by content hash
    const exactDupe = await pool.query<QueryRow>(
      `SELECT id, ${mapping.titleCol} as title, ${mapping.contentCol} as snippet, content_hash
       FROM ${mapping.table}
       WHERE content_hash = $1
       LIMIT 1`,
      [contentHash]
    );

    if (exactDupe.rows.length > 0) {
      const row = exactDupe.rows[0] as unknown as Record<string, unknown>;
      similarItems.push({
        id: String(row.id),
        kind,
        title: String(row.title),
        snippet: String(row.snippet).substring(0, 200),
        similarity_score: 1.0,
        similarity_type: 'exact_duplicate',
        content_hash: String(row.content_hash ?? ''),
      });

      const dupRow = exactDupe.rows[0] as unknown as Record<string, unknown>;
      return {
        has_duplicates: true,
        has_similar: true,
        has_contradictions: false,
        similar_items: similarItems,
        recommendation: 'skip',
        reasoning: `Exact duplicate found (id: ${dupRow.id}). Content hash matches.`,
      };
    }

    // Check for high similarity using trigram matching on title
    const similar = await pool.query<QueryRow>(
      `SELECT id, ${mapping.titleCol} as title, ${mapping.contentCol} as snippet,
              similarity(${mapping.titleCol}, $1) as sim_score
       FROM ${mapping.table}
       WHERE similarity(${mapping.titleCol}, $1) > 0.3
       ORDER BY sim_score DESC
       LIMIT 5`,
      [title]
    );

    for (const row of similar.rows) {
      const simScore = row.sim_score ? parseFloat(row.sim_score) : 0;
      const simType: 'high_similarity' | 'medium_similarity' | null =
        simScore > 0.8 ? 'high_similarity' : simScore > 0.5 ? 'medium_similarity' : null;

      if (simType) {
        similarItems.push({
          id: row.id,
          kind,
          title: row.title,
          snippet: String(row.snippet).substring(0, 200),
          similarity_score: simScore,
          similarity_type: simType,
        });
      }
    }

    // Analyze results and make recommendation
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

    if (highestSim.similarity_score > 0.8) {
      // Very similar - likely updating same topic
      return {
        has_duplicates: false,
        has_similar: true,
        has_contradictions: false,
        similar_items: similarItems,
        recommendation: 'update',
        reasoning: `High similarity (${(highestSim.similarity_score * 100).toFixed(0)}%) with "${highestSim.title}". Recommend updating existing item instead of creating duplicate.`,
      };
    } else {
      // Medium similarity - related but different
      return {
        has_duplicates: false,
        has_similar: true,
        has_contradictions: false,
        similar_items: similarItems,
        recommendation: 'add',
        reasoning: `Medium similarity found but not high enough to suggest update. Different enough to add as new item.`,
      };
    }
  } catch (err) {
    // Error in similarity check - default to safe add
    return {
      has_duplicates: false,
      has_similar: false,
      has_contradictions: false,
      similar_items: [],
      recommendation: 'add',
      reasoning: `Similarity check failed: ${(err as Error).message}. Defaulting to add.`,
    };
  }
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

  // Check for version number contradictions (e.g., "PostgreSQL 17" vs "PostgreSQL 18")
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
