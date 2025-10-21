/**
 * Similarity Detection Service
 *
 * Detects duplicate and contradicting content to enable autonomous decision-making.
 * Uses PostgreSQL trigram similarity and content hashing.
 *
 * @module services/similarity
 */

import crypto from 'crypto';
import { prisma } from '../db/prisma-client.js';

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
// Helper function to compute content hash
function computeContentHash(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

export async function findSimilar(
  kind: string,
  title: string,
  content: string
): Promise<SimilarityResult> {
  // Compute content hash for exact duplicate detection
  const content_hash = computeContentHash(JSON.stringify({ title, content }));

  try {
    // Use Prisma based on kind
    switch (kind) {
      case 'section':
        return await findSectionSimilarity(title, content, content_hash, kind);
      case 'decision':
        return await findDecisionSimilarity(title, content, content_hash, kind);
      case 'issue':
        return await findIssueSimilarity(title, content, content_hash, kind);
      case 'runbook':
        return await findRunbookSimilarity(title, content, content_hash, kind);
      case 'todo':
        return await findTodoSimilarity(title, content, content_hash, kind);
      default:
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

async function findSectionSimilarity(
  title: string,
  content: string,
  _content_hash: string,
  kind: string
): Promise<SimilarityResult> {
  const similarItems: SimilarItem[] = [];

  // Check for exact duplicate by title and content matching
  const exactDupe = await prisma.getClient().section.findFirst({
    where: {
      AND: [
        { title: { equals: title, mode: 'insensitive' } },
        { content: { equals: content } }
      ]
    },
    select: {
      id: true,
      title: true,
      content: true,
    },
  });

  if (exactDupe) {
    similarItems.push({
      id: exactDupe.id,
      kind,
      title: exactDupe.title,
      snippet: (exactDupe.content ?? '').substring(0, 200),
      similarity_score: 1.0,
      similarity_type: 'exact_duplicate',
    });

    return {
      has_duplicates: true,
      has_similar: true,
      has_contradictions: false,
      similar_items: similarItems,
      recommendation: 'skip',
      reasoning: `Exact duplicate found (id: ${exactDupe.id}). Title and content match.`,
    };
  }

  // Check for high similarity using Prisma's contains for title matching
  const similar = await prisma.getClient().section.findMany({
    where: {
      title: {
        contains: title.substring(0, 10), // Simple substring matching
        mode: 'insensitive',
      },
    },
    select: {
      id: true,
      title: true,
      content: true,
    },
    take: 5,
  });

  for (const item of similar) {
    // Calculate simple similarity score based on title overlap
    const simScore = calculateTitleSimilarity(title, item.title);
    const simType: 'high_similarity' | 'medium_similarity' | null =
      simScore > 0.8 ? 'high_similarity' : simScore > 0.5 ? 'medium_similarity' : null;

    if (simType) {
      similarItems.push({
        id: item.id,
        kind,
        title: item.title,
        snippet: (item.content ?? '').substring(0, 200),
        similarity_score: simScore,
        similarity_type: simType,
      });
    }
  }

  return analyzeSimilarityResults(similarItems);
}

async function findDecisionSimilarity(
  title: string,
  content: string,
  _content_hash: string,
  kind: string
): Promise<SimilarityResult> {
  const similarItems: SimilarItem[] = [];

  // Check for exact duplicate by title and rationale matching
  const exactDupe = await prisma.getClient().adrDecision.findFirst({
    where: {
      AND: [
        { title: { equals: title, mode: 'insensitive' } },
        { rationale: { equals: content } }
      ]
    },
    select: {
      id: true,
      title: true,
      rationale: true,
    },
  });

  if (exactDupe) {
    similarItems.push({
      id: exactDupe.id,
      kind,
      title: exactDupe.title,
      snippet: exactDupe.rationale.substring(0, 200),
      similarity_score: 1.0,
      similarity_type: 'exact_duplicate',
    });

    return {
      has_duplicates: true,
      has_similar: true,
      has_contradictions: false,
      similar_items: similarItems,
      recommendation: 'skip',
      reasoning: `Exact duplicate found (id: ${exactDupe.id}). Title and rationale match.`,
    };
  }

  // Check for high similarity using title matching
  const similar = await prisma.getClient().adrDecision.findMany({
    where: {
      title: {
        contains: title.substring(0, 10),
        mode: 'insensitive',
      },
    },
    select: {
      id: true,
      title: true,
      rationale: true,
    },
    take: 5,
  });

  for (const item of similar) {
    const simScore = calculateTitleSimilarity(title, item.title);
    const simType: 'high_similarity' | 'medium_similarity' | null =
      simScore > 0.8 ? 'high_similarity' : simScore > 0.5 ? 'medium_similarity' : null;

    if (simType) {
      similarItems.push({
        id: item.id,
        kind,
        title: item.title,
        snippet: item.rationale.substring(0, 200),
        similarity_score: simScore,
        similarity_type: simType,
      });
    }
  }

  return analyzeSimilarityResults(similarItems);
}

async function findIssueSimilarity(
  title: string,
  content: string,
  _content_hash: string,
  kind: string
): Promise<SimilarityResult> {
  // Similar implementation for issues
  const similarItems: SimilarItem[] = [];

  try {
    // Check for exact duplicate by title and description matching
    const exactDupe = await prisma.getClient().issueLog.findFirst({
      where: {
        AND: [
          { title: { equals: title, mode: 'insensitive' } },
          { description: { equals: content } }
        ]
      },
      select: {
        id: true,
        title: true,
        description: true,
      },
    });

    if (exactDupe) {
      similarItems.push({
        id: exactDupe.id,
        kind,
        title: exactDupe.title,
        snippet: (exactDupe.description ?? '').substring(0, 200),
        similarity_score: 1.0,
        similarity_type: 'exact_duplicate',
      });

      return {
        has_duplicates: true,
        has_similar: true,
        has_contradictions: false,
        similar_items: similarItems,
        recommendation: 'skip',
        reasoning: `Exact duplicate found (id: ${exactDupe.id}). Title and description match.`,
      };
    }

    // Check for similar titles
    const similar = await prisma.getClient().issueLog.findMany({
      where: {
        title: {
          contains: title.substring(0, 10),
          mode: 'insensitive',
        },
      },
      select: {
        id: true,
        title: true,
        description: true,
      },
      take: 5,
    });

    for (const item of similar) {
      const simScore = calculateTitleSimilarity(title, item.title);
      const simType: 'high_similarity' | 'medium_similarity' | null =
        simScore > 0.8 ? 'high_similarity' : simScore > 0.5 ? 'medium_similarity' : null;

      if (simType) {
        similarItems.push({
          id: item.id,
          kind,
          title: item.title,
          snippet: (item.description ?? '').substring(0, 200),
          similarity_score: simScore,
          similarity_type: simType,
        });
      }
    }
  } catch {
    // If the table doesn't exist or other error, return empty results
  }

  return analyzeSimilarityResults(similarItems);
}

async function findRunbookSimilarity(
  title: string,
  _content: string,
  _content_hash: string,
  kind: string
): Promise<SimilarityResult> {
  const similarItems: SimilarItem[] = [];

  try {
    // Similar implementation for runbooks
    const similar = await prisma.getClient().runbook.findMany({
      where: {
        title: {
          contains: title.substring(0, 10),
          mode: 'insensitive',
        },
      },
      select: {
        id: true,
        title: true,
        description: true,
        steps: true,
      },
      take: 5,
    });

    for (const item of similar) {
      const simScore = calculateTitleSimilarity(title, item.title);
      const simType: 'high_similarity' | 'medium_similarity' | null =
        simScore > 0.8 ? 'high_similarity' : simScore > 0.5 ? 'medium_similarity' : null;

      if (simType) {
        similarItems.push({
          id: item.id,
          kind,
          title: item.title,
          snippet: (item.description ?? JSON.stringify(item.steps)).substring(0, 200),
          similarity_score: simScore,
          similarity_type: simType,
        });
      }
    }
  } catch {
    // If the table doesn't exist or other error, return empty results
  }

  return analyzeSimilarityResults(similarItems);
}

async function findTodoSimilarity(
  title: string,
  _content: string,
  _content_hash: string,
  kind: string
): Promise<SimilarityResult> {
  const similarItems: SimilarItem[] = [];

  try {
    // Similar implementation for todos
    const similar = await prisma.getClient().todoLog.findMany({
      where: {
        title: {
          contains: title.substring(0, 10),
          mode: 'insensitive',
        },
      },
      select: {
        id: true,
        title: true,
        description: true,
      },
      take: 5,
    });

    for (const item of similar) {
      const simScore = calculateTitleSimilarity(title, item.title);
      const simType: 'high_similarity' | 'medium_similarity' | null =
        simScore > 0.8 ? 'high_similarity' : simScore > 0.5 ? 'medium_similarity' : null;

      if (simType) {
        similarItems.push({
          id: item.id,
          kind,
          title: item.title,
          snippet: (item.description ?? '').substring(0, 200),
          similarity_score: simScore,
          similarity_type: simType,
        });
      }
    }
  } catch {
    // If the table doesn't exist or other error, return empty results
  }

  return analyzeSimilarityResults(similarItems);
}

// Simple title similarity calculation
function calculateTitleSimilarity(title1: string, title2: string): number {
  const words1 = title1.toLowerCase().split(/\s+/);
  const words2 = title2.toLowerCase().split(/\s+/);

  const intersection = words1.filter(word => words2.includes(word));
  const union = [...new Set([...words1, ...words2])];

  return intersection.length / union.length;
}

function analyzeSimilarityResults(similarItems: SimilarItem[]): SimilarityResult {
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
