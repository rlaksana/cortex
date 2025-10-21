import { prisma } from '../db/prisma-client.js';
import { logger } from '../utils/logger.js';
import { traverseGraph, enrichGraphNodes, type TraversalOptions } from './graph-traversal.js';
import { checkAndPurge } from './auto-purge.js';

// Helper function to create properly typed scope conditions for Prisma JSON filtering
function createScopeConditions(scope: Record<string, unknown>): Record<string, any>[] {
  return Object.entries(scope).map(([key, value]) => ({
    tags: {
      path: [key], // Prisma expects path as array of segments
      equals: value
    }
  }));
}

interface FindHit {
  kind: string;
  id: string;
  title: string;
  snippet: string;
  score: number;
  scope?: Record<string, unknown>;
  updated_at?: string;
  route_used: string;
  confidence: number;
}

interface AutonomousMetadata {
  strategy_used: 'fast' | 'deep' | 'fast_then_deep_fallback';
  mode_requested: string;
  mode_executed: string;
  confidence: 'high' | 'medium' | 'low';
  total_results: number;
  avg_score: number;
  fallback_attempted: boolean;
  recommendation: string;
  user_message_suggestion: string;
}

/**
 * Constitutional ranking formula: 0.4×FTS + 0.3×recency + 0.2×proximity + 0.1×citations
 */
function computeRankingScore(
  ftsScore: number,
  recencyScore: number,
  proximityScore: number,
  citationScore: number
): number {
  return (
    ((0.4 * ftsScore + 0.3 * recencyScore + 0.2 * proximityScore + 0.1 * citationScore) as 0.4) *
      ftsScore +
    0.3 * recencyScore +
    0.2 * proximityScore +
    0.1 * citationScore
  );
}

/**
 * Calculate Jaccard similarity between two tag objects for proximity scoring
 */
function calculateProximity(
  queryScope: Record<string, unknown> | undefined,
  resultTags: Record<string, unknown>
): number {
  if (!queryScope || Object.keys(queryScope).length === 0) return 0.5; // neutral

  const queryKeys = new Set(Object.keys(queryScope));
  const resultKeys = new Set(Object.keys(resultTags));

  const intersection = [...queryKeys].filter(
    (k) => resultKeys.has(k as string) && queryScope[k] === resultTags[k as string]
  ).length;
  const union = new Set([...queryKeys, ...resultKeys]).size;

  return union === 0 ? 0 : intersection / union;
}

/**
 * Normalize recency: newer is better, using exponential decay
 */
function calculateRecency(updated_at: Date | string | null): number {
  if (!updated_at) return 0.3; // default for missing timestamps

  const now = Date.now();
  const updated = new Date(updated_at).getTime();
  const ageMs = now - updated;
  const ageDays = ageMs / (1000 * 60 * 60 * 24);

  // Exponential decay: score = e^(-age/30) (30-day half-life)
  return Math.exp(-ageDays / 30);
}

/**
 * Normalize citation count using log scale
 */
// function calculateCitationScore(count: number): number {
//   if (count <= 0) return 0;
//   return Math.log10(count + 1) / Math.log10(100); // normalize to [0, 1] assuming max 100 citations
// }

export async function memoryFind(params: {
  query: string;
  scope?: Record<string, unknown>;
  types?: string[];
  top_k?: number;
  mode?: 'auto' | 'fast' | 'deep';
  traverse?: TraversalOptions & {
    start_entity_type?: string;
    start_entity_id?: string;
  };
}): Promise<{
  hits: FindHit[];
  suggestions: string[];
  autonomous_metadata: AutonomousMetadata;
  debug?: Record<string, unknown>;
  graph?: {
    nodes: Array<{
      entity_type: string;
      entity_id: string;
      depth: number;
      data?: Record<string, unknown>;
    }>;
    edges: Array<{
      from_entity_type: string;
      from_entity_id: string;
      to_entity_type: string;
      to_entity_id: string;
      relation_type: string;
      metadata?: Record<string, unknown>;
    }>;
  };
}> {
  
  // ✨ AUTO-MAINTENANCE: Check purge thresholds (< 1ms overhead)
  await checkAndPurge('memory.find');

  const startTime = Date.now();

  // Input validation - prevent undefined/null errors
  if (!params.query || typeof params.query !== 'string') {
    throw new Error('Query parameter is required and must be a string');
  }

  if (params.scope && typeof params.scope !== 'object') {
    throw new Error('Scope parameter must be an object if provided');
  }

  // Mode routing logic
  const queryWords = params.query.trim().split(/\s+/).length;
  const hasScope = params.scope && Object.keys(params.scope).length > 0;
  let mode = params.mode ?? 'auto';

  if (mode === 'auto') {
    mode = queryWords < 3 && !hasScope ? 'fast' : 'deep';
  }

  const topK = params.top_k ?? (mode === 'fast' ? 10 : 20);
  const searchTypes =
    params.types ??
    (mode === 'fast'
      ? ['section']
      : [
          'section',
          'runbook',
          'change',
          'issue',
          'decision',
          'todo',
          'release_note',
          'pr_context',
          'ddl',
          'entity',
          'incident',
          'release',
          'risk',
          'assumption',
        ]);

  // These variables are no longer needed with Prisma Client

  const allHits: FindHit[] = [];
  let totalCandidates = 0;

  // Search section table using Prisma
  if (searchTypes.includes('section')) {
    const searchQuery = params.query.toLowerCase();
    let sectionResults: any[];

    if (params.scope && Object.keys(params.scope).length > 0) {
      // Search with scope filter - use Prisma's JSON operations with correct syntax
      const scopeConditions = createScopeConditions(params.scope);

      sectionResults = await prisma.getClient().section.findMany({
        where: {
          AND: [
            {
              OR: [
                { title: { contains: searchQuery, mode: 'insensitive' } },
                { content: { contains: searchQuery, mode: 'insensitive' } },
              ],
            },
            ...scopeConditions,
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    } else {
      // Search without scope filter
      sectionResults = await prisma.getClient().section.findMany({
        where: {
          OR: [
            { title: { contains: searchQuery, mode: 'insensitive' } },
            { content: { contains: searchQuery, mode: 'insensitive' } },
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    }

    totalCandidates += sectionResults.length;

    for (const section of sectionResults) {
      // Calculate a simple FTS-like score based on exact matches and position
      const titleMatch = section.title.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const contentMatch = section.content?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const ftsScore = 0.6 * Math.max(titleMatch, contentMatch) + 0.4 * (titleMatch > 0 ? 1.0 : 0.0);

      const recencyScore = calculateRecency(section.updated_at);
      const proximityScore = calculateProximity(params.scope, section.tags as Record<string, unknown> ?? {});
      const citationScore = section.citation_count ? section.citation_count / 10 : 0; // Scale citation count

      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, citationScore);

      // Use content for snippet
      const snippetContent = section.content || '';

      allHits.push({
        kind: 'section',
        id: section.id,
        title: section.title ?? 'Untitled',
        snippet: `${snippetContent.substring(0, 150)}...`,
        score: finalScore,
        scope: section.tags as Record<string, unknown>,
        updated_at: section.updated_at?.toISOString(),
        route_used: mode,
        confidence: ftsScore > 0.3 ? 0.85 : 0.65,
      });
    }
  }

  // Search runbook table using Prisma
  if (searchTypes.includes('runbook')) {
    const searchQuery = params.query.toLowerCase();
    let runbookResults: any[];

    if (params.scope && Object.keys(params.scope).length > 0) {
      // Search with scope filter
      const scopeConditions = createScopeConditions(params.scope);

      runbookResults = await prisma.getClient().runbook.findMany({
        where: {
          AND: [
            {
              OR: [
                { title: { contains: searchQuery, mode: 'insensitive' } },
                { description: { contains: searchQuery, mode: 'insensitive' } },
              ],
            },
            ...scopeConditions,
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    } else {
      // Search without scope filter
      runbookResults = await prisma.getClient().runbook.findMany({
        where: {
          OR: [
            { title: { contains: searchQuery, mode: 'insensitive' } },
            { description: { contains: searchQuery, mode: 'insensitive' } },
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    }

    totalCandidates += runbookResults.length;

    for (const runbook of runbookResults) {
      const titleMatch = runbook.title.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const descriptionMatch = runbook.description?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const ftsScore = 0.7 * Math.max(titleMatch, descriptionMatch) + 0.3 * (titleMatch > 0 ? 1.0 : 0.0);

      const recencyScore = calculateRecency(runbook.updated_at);
      const proximityScore = calculateProximity(params.scope, runbook.tags as Record<string, unknown> ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      // Create snippet from steps_jsonb or description
      const stepsSnippet = runbook.steps_jsonb ? JSON.stringify(runbook.steps_jsonb).substring(0, 150) : '';
      const descriptionSnippet = runbook.description?.substring(0, 150) ?? '';
      const snippet = stepsSnippet || descriptionSnippet || `Service: ${runbook.service}`;

      allHits.push({
        kind: 'runbook',
        id: runbook.id,
        title: runbook.title ?? 'Untitled Runbook',
        snippet: `${snippet}...`,
        score: finalScore,
        scope: runbook.tags as Record<string, unknown>,
        updated_at: runbook.updated_at?.toISOString(),
        route_used: mode,
        confidence: 0.7,
      });
    }
  }

  // Search change_log table using Prisma
  if (searchTypes.includes('change')) {
    const searchQuery = params.query.toLowerCase();
    let changeResults: any[];

    if (params.scope && Object.keys(params.scope).length > 0) {
      // Search with scope filter
      const scopeConditions = createScopeConditions(params.scope);

      changeResults = await prisma.getClient().changeLog.findMany({
        where: {
          AND: [
            {
              OR: [
                { subject_ref: { contains: searchQuery, mode: 'insensitive' } },
                { summary: { contains: searchQuery, mode: 'insensitive' } },
              ],
            },
            ...scopeConditions,
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    } else {
      // Search without scope filter
      changeResults = await prisma.getClient().changeLog.findMany({
        where: {
          OR: [
            { subject_ref: { contains: searchQuery, mode: 'insensitive' } },
            { summary: { contains: searchQuery, mode: 'insensitive' } },
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    }

    totalCandidates += changeResults.length;

    for (const change of changeResults) {
      const subjectMatch = change.subject_ref.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const summaryMatch = change.summary?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const ftsScore = 0.7 * Math.max(subjectMatch, summaryMatch) + 0.3 * (subjectMatch > 0 ? 1.0 : 0.0);

      const recencyScore = calculateRecency(change.updated_at);
      const proximityScore = calculateProximity(params.scope, change.tags as Record<string, unknown> ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'change',
        id: change.id,
        title: change.subject_ref ?? 'Untitled Change',
        snippet: `${(change.summary ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: change.tags as Record<string, unknown>,
        updated_at: change.updated_at?.toISOString(),
        route_used: mode,
        confidence: 0.7,
      });
    }
  }

  // Search issue_log table using Prisma
  if (searchTypes.includes('issue')) {
    const searchQuery = params.query.toLowerCase();
    let issueResults: any[];

    if (params.scope && Object.keys(params.scope).length > 0) {
      const scopeConditions = createScopeConditions(params.scope);

      issueResults = await prisma.getClient().issueLog.findMany({
        where: {
          AND: [
            {
              OR: [
                { title: { contains: searchQuery, mode: 'insensitive' } },
                { description: { contains: searchQuery, mode: 'insensitive' } },
              ],
            },
            ...scopeConditions,
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    } else {
      issueResults = await prisma.getClient().issueLog.findMany({
        where: {
          OR: [
            { title: { contains: searchQuery, mode: 'insensitive' } },
            { description: { contains: searchQuery, mode: 'insensitive' } },
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    }

    totalCandidates += issueResults.length;

    for (const issue of issueResults) {
      const titleMatch = issue.title.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const descriptionMatch = issue.description?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const ftsScore = 0.6 * Math.max(titleMatch, descriptionMatch) + 0.4 * (titleMatch > 0 ? 1.0 : 0.0);

      const recencyScore = calculateRecency(issue.updated_at);
      const proximityScore = calculateProximity(params.scope, issue.tags as Record<string, unknown> ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'issue',
        id: issue.id,
        title: issue.title,
        snippet: `${(issue.description ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: issue.tags as Record<string, unknown>,
        updated_at: issue.updated_at?.toISOString(),
        route_used: mode,
        confidence: 0.7,
      });
    }
  }

  // Search adr_decision table using Prisma
  if (searchTypes.includes('decision')) {
    const searchQuery = params.query.toLowerCase();
    let decisionResults: any[];

    if (params.scope && Object.keys(params.scope).length > 0) {
      const scopeConditions = createScopeConditions(params.scope);

      decisionResults = await prisma.getClient().adrDecision.findMany({
        where: {
          AND: [
            {
              OR: [
                { title: { contains: searchQuery, mode: 'insensitive' } },
                { rationale: { contains: searchQuery, mode: 'insensitive' } },
                { component: { contains: searchQuery, mode: 'insensitive' } },
              ],
            },
            ...scopeConditions,
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    } else {
      decisionResults = await prisma.getClient().adrDecision.findMany({
        where: {
          OR: [
            { title: { contains: searchQuery, mode: 'insensitive' } },
            { rationale: { contains: searchQuery, mode: 'insensitive' } },
            { component: { contains: searchQuery, mode: 'insensitive' } },
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    }

    totalCandidates += decisionResults.length;

    for (const decision of decisionResults) {
      const titleMatch = decision.title.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const rationaleMatch = decision.rationale?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const componentMatch = decision.component?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const ftsScore = 0.8 * Math.max(titleMatch, rationaleMatch, componentMatch) + 0.2 * (titleMatch > 0 ? 1.0 : 0.0);

      const recencyScore = calculateRecency(decision.updated_at);
      const proximityScore = calculateProximity(params.scope, decision.tags as Record<string, unknown> ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'decision',
        id: decision.id,
        title: `ADR: ${decision.component} - ${decision.title}`,
        snippet: `${(decision.rationale ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: decision.tags as Record<string, unknown>,
        updated_at: decision.updated_at?.toISOString(),
        route_used: mode,
        confidence: 0.8,
      });
    }
  }

  // Search todo_log table using Prisma
  if (searchTypes.includes('todo')) {
    const searchQuery = params.query.toLowerCase();
    let todoResults: any[];

    if (params.scope && Object.keys(params.scope).length > 0) {
      const scopeConditions = createScopeConditions(params.scope);

      todoResults = await prisma.getClient().todoLog.findMany({
        where: {
          AND: [
            {
              OR: [
                { title: { contains: searchQuery, mode: 'insensitive' } },
                { description: { contains: searchQuery, mode: 'insensitive' } },
                { priority: { contains: searchQuery, mode: 'insensitive' } },
              ],
            },
            ...scopeConditions,
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    } else {
      todoResults = await prisma.getClient().todoLog.findMany({
        where: {
          OR: [
            { title: { contains: searchQuery, mode: 'insensitive' } },
            { description: { contains: searchQuery, mode: 'insensitive' } },
            { priority: { contains: searchQuery, mode: 'insensitive' } },
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    }

    totalCandidates += todoResults.length;

    for (const todo of todoResults) {
      const titleMatch = todo.title.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const descriptionMatch = todo.description?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const priorityMatch = todo.priority?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const ftsScore = 0.6 * Math.max(titleMatch, descriptionMatch, priorityMatch) + 0.4 * (titleMatch > 0 ? 1.0 : 0.0);

      const recencyScore = calculateRecency(todo.updated_at);
      const proximityScore = calculateProximity(params.scope, todo.tags as Record<string, unknown> ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      const snippetText = todo.description ?? todo.title ?? 'No description';

      allHits.push({
        kind: 'todo',
        id: todo.id,
        title: `${todo.status.toUpperCase()}: ${todo.title}`,
        snippet: `${snippetText.substring(0, 150)}...`,
        score: finalScore,
        scope: todo.tags as Record<string, unknown>,
        updated_at: todo.updated_at?.toISOString(),
        route_used: mode,
        confidence: 0.65,
      });
    }
  }

  // Search release_note table using Prisma
  if (searchTypes.includes('release_note')) {
    const searchQuery = params.query.toLowerCase();
    let releaseResults: any[];

    if (params.scope && Object.keys(params.scope).length > 0) {
      const scopeConditions = createScopeConditions(params.scope);

      releaseResults = await prisma.getClient().releaseNote.findMany({
        where: {
          AND: [
            {
              OR: [
                { version: { contains: searchQuery, mode: 'insensitive' } },
                { summary: { contains: searchQuery, mode: 'insensitive' } },
              ],
            },
            ...scopeConditions,
          ],
        },
        orderBy: { created_at: 'desc' },
        take: topK,
      });
    } else {
      releaseResults = await prisma.getClient().releaseNote.findMany({
        where: {
          OR: [
            { version: { contains: searchQuery, mode: 'insensitive' } },
            { summary: { contains: searchQuery, mode: 'insensitive' } },
          ],
        },
        orderBy: { created_at: 'desc' },
        take: topK,
      });
    }

    totalCandidates += releaseResults.length;

    for (const release of releaseResults) {
      const versionMatch = release.version.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const summaryMatch = release.summary?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const ftsScore = 0.7 * Math.max(versionMatch, summaryMatch) + 0.3 * (versionMatch > 0 ? 1.0 : 0.0);

      const recencyScore = calculateRecency(release.updated_at);
      const proximityScore = calculateProximity(params.scope, release.tags as Record<string, unknown> ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'release_note',
        id: release.id,
        title: `Release ${release.version}`,
        snippet: `${(release.summary ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: release.tags as Record<string, unknown>,
        updated_at: release.updated_at?.toISOString(),
        route_used: mode,
        confidence: 0.75,
      });
    }
  }

  // Search pr_context table using Prisma
  if (searchTypes.includes('pr_context')) {
    const searchQuery = params.query.toLowerCase();
    let prResults: any[];

    if (params.scope && Object.keys(params.scope).length > 0) {
      const scopeConditions = createScopeConditions(params.scope);

      prResults = await prisma.getClient().prContext.findMany({
        where: {
          AND: [
            {
              OR: [
                { title: { contains: searchQuery, mode: 'insensitive' } },
                { description: { contains: searchQuery, mode: 'insensitive' } },
                { author: { contains: searchQuery, mode: 'insensitive' } },
              ],
            },
            ...scopeConditions,
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    } else {
      prResults = await prisma.getClient().prContext.findMany({
        where: {
          OR: [
            { title: { contains: searchQuery, mode: 'insensitive' } },
            { description: { contains: searchQuery, mode: 'insensitive' } },
            { author: { contains: searchQuery, mode: 'insensitive' } },
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    }

    totalCandidates += prResults.length;

    for (const pr of prResults) {
      const titleMatch = pr.title.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const descriptionMatch = pr.description?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const authorMatch = pr.author?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const ftsScore = 0.7 * Math.max(titleMatch, descriptionMatch, authorMatch) + 0.3 * (titleMatch > 0 ? 1.0 : 0.0);

      const recencyScore = calculateRecency(pr.updated_at);
      const proximityScore = calculateProximity(params.scope, pr.tags as Record<string, unknown> ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'pr_context',
        id: pr.id,
        title: `PR #${pr.pr_number}: ${pr.title}`,
        snippet: `${(pr.description ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: pr.tags as Record<string, unknown>,
        updated_at: pr.updated_at?.toISOString(),
        route_used: mode,
        confidence: 0.7,
      });
    }
  }

  // Search ddl_log table using Prisma (unified model)
  if (searchTypes.includes('ddl')) {
    const searchQuery = params.query.toLowerCase();

    const ddlResults = await prisma.getClient().ddlHistory.findMany({
      where: {
        OR: [
          { migration_id: { contains: searchQuery, mode: 'insensitive' } },
          { description: { contains: searchQuery, mode: 'insensitive' } },
          { ddl_text: { contains: searchQuery, mode: 'insensitive' } },
        ],
      },
      orderBy: { applied_at: 'desc' },
      take: topK,
    });

    totalCandidates += ddlResults.length;

    for (const ddl of ddlResults) {
      const migrationMatch = ddl.migration_id.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const descriptionMatch = ddl.description?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const ddlMatch = ddl.ddl_text?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const ftsScore = 0.5 * Math.max(migrationMatch, descriptionMatch, ddlMatch) + 0.5 * (migrationMatch > 0 ? 1.0 : 0.0);

      const recencyScore = calculateRecency(ddl.applied_at);
      const finalScore = computeRankingScore(ftsScore, recencyScore, 0, 0);

      allHits.push({
        kind: 'ddl',
        id: ddl.id,
        title: ddl.migration_id ?? 'Untitled Migration',
        snippet: `${(ddl.description ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: {},
        updated_at: ddl.applied_at?.toISOString(),
        route_used: mode,
        confidence: 0.6,
      });
    }
  }

  // Search knowledge_entity table (flexible entities) using Prisma
  if (searchTypes.includes('entity')) {
    const searchQuery = params.query.toLowerCase();
    let entityResults: any[];

    if (params.scope && Object.keys(params.scope).length > 0) {
      const scopeConditions = createScopeConditions(params.scope);

      entityResults = await prisma.getClient().knowledgeEntity.findMany({
        where: {
          AND: [
            {
              OR: [
                { name: { contains: searchQuery, mode: 'insensitive' } },
                { entity_type: { contains: searchQuery, mode: 'insensitive' } },
              ],
            },
            ...scopeConditions,
            {
              deleted_at: null,
            },
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    } else {
      entityResults = await prisma.getClient().knowledgeEntity.findMany({
        where: {
          AND: [
            {
              OR: [
                { name: { contains: searchQuery, mode: 'insensitive' } },
                { entity_type: { contains: searchQuery, mode: 'insensitive' } },
              ],
            },
            {
              deleted_at: null,
            },
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    }

    totalCandidates += entityResults.length;

    for (const entity of entityResults) {
      const nameMatch = entity.name.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const typeMatch = entity.entity_type.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const ftsScore = 0.6 * Math.max(nameMatch, typeMatch) + 0.4 * (nameMatch > 0 ? 1.0 : 0.0);

      const recencyScore = calculateRecency(entity.updated_at);
      const proximityScore = calculateProximity(params.scope, entity.tags as Record<string, unknown> ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      // Create snippet from entity data
      const dataSnippet = JSON.stringify(entity.data).substring(0, 100);

      allHits.push({
        kind: 'entity',
        id: entity.id,
        title: `${entity.entity_type}: ${entity.name}`,
        snippet: `${dataSnippet}...`,
        score: finalScore,
        scope: entity.tags as Record<string, unknown>,
        updated_at: entity.updated_at?.toISOString(),
        route_used: mode,
        confidence: 0.7,
      });
    }
  }

  // Search incident_log table (8-LOG SYSTEM) using Prisma
  if (searchTypes.includes('incident')) {
    const searchQuery = params.query.toLowerCase();
    let incidentResults: any[];

    if (params.scope && Object.keys(params.scope).length > 0) {
      const scopeConditions = createScopeConditions(params.scope);

      incidentResults = await prisma.getClient().incidentLog.findMany({
        where: {
          AND: [
            {
              OR: [
                { title: { contains: searchQuery, mode: 'insensitive' } },
                { impact: { contains: searchQuery, mode: 'insensitive' } },
                { severity: { contains: searchQuery, mode: 'insensitive' } },
              ],
            },
            ...scopeConditions,
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    } else {
      incidentResults = await prisma.getClient().incidentLog.findMany({
        where: {
          OR: [
            { title: { contains: searchQuery, mode: 'insensitive' } },
            { impact: { contains: searchQuery, mode: 'insensitive' } },
            { severity: { contains: searchQuery, mode: 'insensitive' } },
            { resolution: { contains: searchQuery, mode: 'insensitive' } },
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    }

    totalCandidates += incidentResults.length;

    for (const incident of incidentResults) {
      const titleMatch = incident.title.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const impactMatch = incident.impact?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const severityMatch = incident.severity?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const ftsScore = 0.8 * Math.max(titleMatch, impactMatch, severityMatch) + 0.2 * (titleMatch > 0 ? 1.0 : 0.0);

      const recencyScore = calculateRecency(incident.updated_at);
      const proximityScore = calculateProximity(params.scope, incident.tags as Record<string, unknown> ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'incident',
        id: incident.id,
        title: `INCIDENT: ${incident.title} (${incident.severity})`,
        snippet: `${(incident.impact ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: incident.tags as Record<string, unknown>,
        updated_at: incident.updated_at?.toISOString(),
        route_used: mode,
        confidence: 0.85,
      });
    }
  }

  // Search release_log table (8-LOG SYSTEM) using Prisma
  if (searchTypes.includes('release')) {
    const searchQuery = params.query.toLowerCase();
    let releaseResults: any[];

    if (params.scope && Object.keys(params.scope).length > 0) {
      const scopeConditions = createScopeConditions(params.scope);

      releaseResults = await prisma.getClient().releaseLog.findMany({
        where: {
          AND: [
            {
              OR: [
                { version: { contains: searchQuery, mode: 'insensitive' } },
                { scope: { contains: searchQuery, mode: 'insensitive' } },
              ],
            },
            ...scopeConditions,
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    } else {
      releaseResults = await prisma.getClient().releaseLog.findMany({
        where: {
          OR: [
            { version: { contains: searchQuery, mode: 'insensitive' } },
            { scope: { contains: searchQuery, mode: 'insensitive' } },
            { release_type: { contains: searchQuery, mode: 'insensitive' } },
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    }

    totalCandidates += releaseResults.length;

    for (const release of releaseResults) {
      const versionMatch = release.version.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const scopeMatch = release.scope?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const ftsScore = 0.8 * Math.max(versionMatch, scopeMatch) + 0.2 * (versionMatch > 0 ? 1.0 : 0.0);

      const recencyScore = calculateRecency(release.updated_at);
      const proximityScore = calculateProximity(params.scope, release.tags as Record<string, unknown> ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'release',
        id: release.id,
        title: `RELEASE: ${release.version}`,
        snippet: `${(release.scope ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: release.tags as Record<string, unknown>,
        updated_at: release.updated_at?.toISOString(),
        route_used: mode,
        confidence: 0.8,
      });
    }
  }

  // Search risk_log table (8-LOG SYSTEM) using Prisma
  if (searchTypes.includes('risk')) {
    const searchQuery = params.query.toLowerCase();
    let riskResults: any[];

    if (params.scope && Object.keys(params.scope).length > 0) {
      const scopeConditions = createScopeConditions(params.scope);

      riskResults = await prisma.getClient().riskLog.findMany({
        where: {
          AND: [
            {
              OR: [
                { title: { contains: searchQuery, mode: 'insensitive' } },
                { impact_description: { contains: searchQuery, mode: 'insensitive' } },
                { category: { contains: searchQuery, mode: 'insensitive' } },
              ],
            },
            ...scopeConditions,
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    } else {
      riskResults = await prisma.getClient().riskLog.findMany({
        where: {
          OR: [
            { title: { contains: searchQuery, mode: 'insensitive' } },
            { impact_description: { contains: searchQuery, mode: 'insensitive' } },
            { risk_level: { contains: searchQuery, mode: 'insensitive' } },
            { category: { contains: searchQuery, mode: 'insensitive' } },
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    }

    totalCandidates += riskResults.length;

    for (const risk of riskResults) {
      const titleMatch = risk.title.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const impactMatch = risk.impact_description?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const categoryMatch = risk.category?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const ftsScore = 0.75 * Math.max(titleMatch, impactMatch, categoryMatch) + 0.25 * (titleMatch > 0 ? 1.0 : 0.0);

      const recencyScore = calculateRecency(risk.updated_at);
      const proximityScore = calculateProximity(params.scope, risk.tags as Record<string, unknown> ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'risk',
        id: risk.id,
        title: `RISK: ${risk.title}`,
        snippet: `${(risk.impact_description ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: risk.tags as Record<string, unknown>,
        updated_at: risk.updated_at?.toISOString(),
        route_used: mode,
        confidence: 0.8,
      });
    }
  }

  // Search assumption_log table (8-LOG SYSTEM) using Prisma
  if (searchTypes.includes('assumption')) {
    const searchQuery = params.query.toLowerCase();
    let assumptionResults: any[];

    if (params.scope && Object.keys(params.scope).length > 0) {
      const scopeConditions = createScopeConditions(params.scope);

      assumptionResults = await prisma.getClient().assumptionLog.findMany({
        where: {
          AND: [
            {
              OR: [
                { title: { contains: searchQuery, mode: 'insensitive' } },
                { description: { contains: searchQuery, mode: 'insensitive' } },
                { impact_if_invalid: { contains: searchQuery, mode: 'insensitive' } },
                { category: { contains: searchQuery, mode: 'insensitive' } },
              ],
            },
            ...scopeConditions,
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    } else {
      assumptionResults = await prisma.getClient().assumptionLog.findMany({
        where: {
          OR: [
            { title: { contains: searchQuery, mode: 'insensitive' } },
            { description: { contains: searchQuery, mode: 'insensitive' } },
            { impact_if_invalid: { contains: searchQuery, mode: 'insensitive' } },
            { category: { contains: searchQuery, mode: 'insensitive' } },
          ],
        },
        orderBy: { updated_at: 'desc' },
        take: topK,
      });
    }

    totalCandidates += assumptionResults.length;

    for (const assumption of assumptionResults) {
      const titleMatch = assumption.title.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const descriptionMatch = assumption.description?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const impactMatch = assumption.impact_if_invalid?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const categoryMatch = assumption.category?.toLowerCase().includes(searchQuery) ? 1.0 : 0.0;
      const ftsScore = 0.6 * Math.max(titleMatch, descriptionMatch, impactMatch, categoryMatch) + 0.4 * (titleMatch > 0 ? 1.0 : 0.0);

      const recencyScore = calculateRecency(assumption.updated_at);
      const proximityScore = calculateProximity(params.scope, assumption.tags as Record<string, unknown> ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'assumption',
        id: assumption.id,
        title: `ASSUMPTION: ${assumption.title} (${assumption.validation_status})`,
        snippet: `${(assumption.description ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: assumption.tags as Record<string, unknown>,
        updated_at: assumption.updated_at?.toISOString(),
        route_used: mode,
        confidence: 0.75,
      });
    }
  }

  // Sort by final score and apply limit
  allHits.sort((a, b) => b.score - a.score);
  const topHits = allHits.slice(0, topK);

  // Graph traversal (if requested)
  let graphResult;
  if (params.traverse) {
    const startEntityType = params.traverse.start_entity_type ?? topHits[0]?.kind;
    const startEntityId = params.traverse.start_entity_id ?? topHits[0]?.id;

    if (startEntityType && startEntityId) {
      try {
        const traversalResult = await traverseGraph(startEntityType, startEntityId, {
          depth: params.traverse.depth ?? 3,
          relation_types: params.traverse.relation_types ?? [],
          direction: params.traverse.direction ?? ('both' as const),
        });

        // Enrich nodes with entity data
        const enrichedNodes = await enrichGraphNodes(traversalResult.nodes);

        graphResult = {
          nodes: enrichedNodes,
          edges: traversalResult.edges,
        };

        logger.info(
          {
            start_entity: `${startEntityType}:${startEntityId}`,
            nodes_found: enrichedNodes.length,
            edges_found: traversalResult.edges.length,
            max_depth: traversalResult.max_depth_reached,
          },
          'Graph traversal completed'
        );
      } catch (err: unknown) {
        logger.error(
          { err, start_entity: `${startEntityType}:${startEntityId}` },
          'Graph traversal failed'
        );
      }
    }
  }

  const duration = Date.now() - startTime;
  // Build autonomous metadata for Claude Code decision-making
  const avgScore =
    topHits.length > 0 ? topHits.reduce((sum, h) => sum + h.score, 0) / topHits.length : 0;

  const confidence: 'high' | 'medium' | 'low' =
    topHits.length >= 3 && avgScore > 0.7
      ? 'high'
      : topHits.length >= 1 && avgScore > 0.4
        ? 'medium'
        : 'low';

  const autonomousMetadata: AutonomousMetadata = {
    strategy_used:
      params.mode === 'fast' ? 'fast' : params.mode === 'deep' ? 'deep' : 'fast_then_deep_fallback',
    mode_requested: params.mode ?? 'auto',
    mode_executed: mode,
    confidence,
    total_results: topHits.length,
    avg_score: avgScore,
    fallback_attempted: params.mode === 'auto' && mode === 'deep',
    recommendation:
      confidence === 'high'
        ? 'Results sufficient, use top results.'
        : confidence === 'medium'
          ? 'Results acceptable. Consider refining query if needed.'
          : 'Low confidence. Recommend broader keywords or deep mode.',
    user_message_suggestion:
      topHits.length === 0
        ? 'No results found'
        : topHits.length === 1
          ? `Found 1 result`
          : `Found ${topHits.length} results`,
  };

  logger.info(
    {
      query: params.query,
      mode,
      hits: topHits.length,
      candidates: totalCandidates,
      duration_ms: duration,
      graph_traversal: !!graphResult,
      confidence,
    },
    'memory.find completed'
  );

  return {
    hits: topHits,
    suggestions: topHits.length < 3 ? ['Try broader terms', 'Check spelling', 'Use deep mode'] : [],
    autonomous_metadata: autonomousMetadata,
    debug: {
      query_duration_ms: duration,
      total_candidates: totalCandidates,
      mode_used: mode,
      tables_searched: searchTypes.length,
      graph_nodes: graphResult?.nodes.length ?? 0,
      graph_edges: graphResult?.edges.length ?? 0,
    },
    graph: graphResult,
  };
}
