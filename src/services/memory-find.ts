import { getPool } from '../db/pool.js';
import { logger } from '../utils/logger.js';
import { traverseGraph, enrichGraphNodes, type TraversalOptions } from './graph-traversal.js';
import { checkAndPurge } from './auto-purge.js';

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
function calculateRecency(updatedAt: Date | string | null): number {
  if (!updatedAt) return 0.3; // default for missing timestamps

  const now = Date.now();
  const updated = new Date(updatedAt).getTime();
  const ageMs = now - updated;
  const ageDays = ageMs / (1000 * 60 * 60 * 24);

  // Exponential decay: score = e^(-age/30) (30-day half-life)
  return Math.exp(-ageDays / 30);
}

/**
 * Normalize citation count using log scale
 */
function calculateCitationScore(count: number): number {
  if (count <= 0) return 0;
  return Math.log10(count + 1) / Math.log10(100); // normalize to [0, 1] assuming max 100 citations
}

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
  const pool = getPool();

  // ✨ AUTO-MAINTENANCE: Check purge thresholds (< 1ms overhead)
  await checkAndPurge(pool, 'memory.find');

  const startTime = Date.now();

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

  // Build scope filter SQL
  const scopeFilter = params.scope ? `AND tags @> $2::jsonb` : '';
  const scopeParam = params.scope ? JSON.stringify(params.scope) : null;

  const likePattern = `%${params.query}%`;

  const allHits: FindHit[] = [];
  let totalCandidates = 0;

  // Search section table (has FTS)
  if (searchTypes.includes('section')) {
    const sectionQuery = scopeFilter
      ? `SELECT id, heading, body_jsonb,
                (0.6 * CASE WHEN ts @@ plainto_tsquery('english', $1) THEN 1.0 ELSE 0.0 END +
                 0.4 * similarity(COALESCE(heading, ''), $1)) as fts_score,
                tags, updated_at, citation_count
         FROM section
         WHERE ts @@ plainto_tsquery('english', $1) ${scopeFilter}
         ORDER BY fts_score DESC
         LIMIT $3`
      : `SELECT id, heading, body_jsonb,
                (0.6 * CASE WHEN ts @@ plainto_tsquery('english', $1) THEN 1.0 ELSE 0.0 END +
                 0.4 * similarity(COALESCE(heading, ''), $1)) as fts_score,
                tags, updated_at, citation_count
         FROM section
         WHERE ts @@ plainto_tsquery('english', $1)
         ORDER BY fts_score DESC
         LIMIT $2`;

    const sectionParams = scopeFilter ? [params.query, scopeParam, topK] : [params.query, topK];
    const sectionResult = await pool.query(sectionQuery, sectionParams);
    totalCandidates += sectionResult.rows.length;

    for (const row of sectionResult.rows) {
      const ftsScore = parseFloat(row.fts_score) ?? 0;
      const recencyScore = calculateRecency(row.updated_at);
      const proximityScore = calculateProximity(params.scope, row.tags ?? {});
      const citationScore = calculateCitationScore(row.citation_count ?? 0);

      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, citationScore);

      allHits.push({
        kind: 'section',
        id: row.id,
        title: row.heading ?? 'Untitled',
        snippet: `${(row.body_jsonb?.text ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: row.tags,
        updated_at: row.updated_at,
        route_used: mode,
        confidence: ftsScore > 0.3 ? 0.85 : 0.65,
      });
    }
  }

  // Search runbook table
  if (searchTypes.includes('runbook')) {
    const runbookQuery = scopeFilter
      ? `SELECT id, service, steps_jsonb, tags, updated_at
         FROM runbook
         WHERE (service ILIKE $1 OR steps_jsonb::text ILIKE $1) ${scopeFilter}
         LIMIT $3`
      : `SELECT id, service, steps_jsonb, tags, updated_at
         FROM runbook
         WHERE service ILIKE $1 OR steps_jsonb::text ILIKE $1
         LIMIT $2`;

    const runbookParams = scopeFilter ? [likePattern, scopeParam, topK] : [likePattern, topK];
    const runbookResult = await pool.query(runbookQuery, runbookParams);
    totalCandidates += runbookResult.rows.length;

    for (const row of runbookResult.rows) {
      const ftsScore = 0.5; // basic text match
      const recencyScore = calculateRecency(row.updated_at);
      const proximityScore = calculateProximity(params.scope, row.tags ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'runbook',
        id: row.id,
        title: row.service ?? 'Untitled Runbook',
        snippet: `${JSON.stringify(row.steps_jsonb).substring(0, 150)}...`,
        score: finalScore,
        scope: row.tags,
        updated_at: row.updated_at,
        route_used: mode,
        confidence: 0.7,
      });
    }
  }

  // Search change_log table
  if (searchTypes.includes('change')) {
    const changeQuery = scopeFilter
      ? `SELECT id, subject_ref, summary, details, tags, updated_at
         FROM change_log
         WHERE (subject_ref ILIKE $1 OR summary ILIKE $1 OR details ILIKE $1) ${scopeFilter}
         LIMIT $3`
      : `SELECT id, subject_ref, summary, details, tags, updated_at
         FROM change_log
         WHERE subject_ref ILIKE $1 OR summary ILIKE $1 OR details ILIKE $1
         LIMIT $2`;

    const changeParams = scopeFilter ? [likePattern, scopeParam, topK] : [likePattern, topK];
    const changeResult = await pool.query(changeQuery, changeParams);
    totalCandidates += changeResult.rows.length;

    for (const row of changeResult.rows) {
      const ftsScore = 0.5;
      const recencyScore = calculateRecency(row.updated_at);
      const proximityScore = calculateProximity(params.scope, row.tags ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'change',
        id: row.id,
        title: row.subject_ref ?? 'Untitled Change',
        snippet: `${(row.summary ?? row.details ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: row.tags,
        updated_at: row.updated_at,
        route_used: mode,
        confidence: 0.7,
      });
    }
  }

  // Search issue_log table
  if (searchTypes.includes('issue')) {
    const issueQuery = scopeFilter
      ? `SELECT id, title, description, tags, updated_at
         FROM issue_log
         WHERE (title ILIKE $1 OR description ILIKE $1) ${scopeFilter}
         LIMIT $3`
      : `SELECT id, title, description, tags, updated_at
         FROM issue_log
         WHERE title ILIKE $1 OR description ILIKE $1
         LIMIT $2`;

    const issueParams = scopeFilter ? [likePattern, scopeParam, topK] : [likePattern, topK];
    const issueResult = await pool.query(issueQuery, issueParams);
    totalCandidates += issueResult.rows.length;

    for (const row of issueResult.rows) {
      const ftsScore = 0.5;
      const recencyScore = calculateRecency(row.updated_at);
      const proximityScore = calculateProximity(params.scope, row.tags ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'issue',
        id: row.id,
        title: row.title ?? 'Untitled Issue',
        snippet: `${(row.description ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: row.tags,
        updated_at: row.updated_at,
        route_used: mode,
        confidence: 0.7,
      });
    }
  }

  // Search adr_decision table
  if (searchTypes.includes('decision')) {
    const adrQuery = scopeFilter
      ? `SELECT id, title, rationale, component, tags, updated_at
         FROM adr_decision
         WHERE (title ILIKE $1 OR rationale ILIKE $1 OR component ILIKE $1) ${scopeFilter}
         LIMIT $3`
      : `SELECT id, title, rationale, component, tags, updated_at
         FROM adr_decision
         WHERE title ILIKE $1 OR rationale ILIKE $1 OR component ILIKE $1
         LIMIT $2`;

    const adrParams = scopeFilter ? [likePattern, scopeParam, topK] : [likePattern, topK];
    const adrResult = await pool.query(adrQuery, adrParams);
    totalCandidates += adrResult.rows.length;

    for (const row of adrResult.rows) {
      const ftsScore = 0.6; // ADRs are high-value
      const recencyScore = calculateRecency(row.updated_at);
      const proximityScore = calculateProximity(params.scope, row.tags ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'decision',
        id: row.id,
        title: row.title ?? 'Untitled ADR',
        snippet: `${(row.rationale ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: row.tags,
        updated_at: row.updated_at,
        route_used: mode,
        confidence: 0.8,
      });
    }
  }

  // Search todo_log table
  if (searchTypes.includes('todo')) {
    const todoQuery = scopeFilter
      ? `SELECT id, text, scope, tags, updated_at
         FROM todo_log
         WHERE (text ILIKE $1 OR scope ILIKE $1) ${scopeFilter}
         LIMIT $3`
      : `SELECT id, text, scope, tags, updated_at
         FROM todo_log
         WHERE text ILIKE $1 OR scope ILIKE $1
         LIMIT $2`;

    const todoParams = scopeFilter ? [likePattern, scopeParam, topK] : [likePattern, topK];
    const todoResult = await pool.query(todoQuery, todoParams);
    totalCandidates += todoResult.rows.length;

    for (const row of todoResult.rows) {
      const ftsScore = 0.5;
      const recencyScore = calculateRecency(row.updated_at);
      const proximityScore = calculateProximity(params.scope, row.tags ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'todo',
        id: row.id,
        title: (row.text ?? 'Untitled TODO').substring(0, 50),
        snippet: `${(row.text ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: row.tags,
        updated_at: row.updated_at,
        route_used: mode,
        confidence: 0.65,
      });
    }
  }

  // Search release_note table
  if (searchTypes.includes('release_note')) {
    const releaseQuery = scopeFilter
      ? `SELECT id, version, summary, tags, created_at
         FROM release_note
         WHERE (version ILIKE $1 OR summary ILIKE $1) ${scopeFilter}
         LIMIT $3`
      : `SELECT id, version, summary, tags, created_at
         FROM release_note
         WHERE version ILIKE $1 OR summary ILIKE $1
         LIMIT $2`;

    const releaseParams = scopeFilter ? [likePattern, scopeParam, topK] : [likePattern, topK];
    const releaseResult = await pool.query(releaseQuery, releaseParams);
    totalCandidates += releaseResult.rows.length;

    for (const row of releaseResult.rows) {
      const ftsScore = 0.5;
      const recencyScore = calculateRecency(row.created_at);
      const proximityScore = calculateProximity(params.scope, row.tags ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'release_note',
        id: row.id,
        title: `Release ${row.version}`,
        snippet: `${(row.summary ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: row.tags,
        updated_at: row.created_at,
        route_used: mode,
        confidence: 0.75,
      });
    }
  }

  // Search pr_context table
  if (searchTypes.includes('pr_context')) {
    const prQuery = scopeFilter
      ? `SELECT id, title, description, pr_number, tags, updated_at
         FROM pr_context
         WHERE (title ILIKE $1 OR description ILIKE $1) ${scopeFilter}
         LIMIT $3`
      : `SELECT id, title, description, pr_number, tags, updated_at
         FROM pr_context
         WHERE title ILIKE $1 OR description ILIKE $1
         LIMIT $2`;

    const prParams = scopeFilter ? [likePattern, scopeParam, topK] : [likePattern, topK];
    const prResult = await pool.query(prQuery, prParams);
    totalCandidates += prResult.rows.length;

    for (const row of prResult.rows) {
      const ftsScore = 0.5;
      const recencyScore = calculateRecency(row.updated_at);
      const proximityScore = calculateProximity(params.scope, row.tags ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'pr_context',
        id: row.id,
        title: row.title ?? `PR #${row.pr_number}`,
        snippet: `${(row.description ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: row.tags,
        updated_at: row.updated_at,
        route_used: mode,
        confidence: 0.7,
      });
    }
  }

  // Search ddl_history table
  if (searchTypes.includes('ddl')) {
    const ddlQuery = `SELECT id, migration_id, description, applied_at
         FROM ddl_history
         WHERE migration_id ILIKE $1 OR description ILIKE $1
         LIMIT $2`;

    const ddlResult = await pool.query(ddlQuery, [likePattern, topK]);
    totalCandidates += ddlResult.rows.length;

    for (const row of ddlResult.rows) {
      const ftsScore = 0.4;
      const recencyScore = calculateRecency(row.applied_at);
      const finalScore = computeRankingScore(ftsScore, recencyScore, 0, 0);

      allHits.push({
        kind: 'ddl',
        id: row.id,
        title: row.migration_id ?? 'Untitled Migration',
        snippet: `${(row.description ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: {},
        updated_at: row.applied_at,
        route_used: mode,
        confidence: 0.6,
      });
    }
  }

  // Search knowledge_entity table (flexible entities)
  if (searchTypes.includes('entity')) {
    const entityQuery = scopeFilter
      ? `SELECT id, entity_type, name, data, tags, updated_at
         FROM knowledge_entity
         WHERE (name ILIKE $1 OR entity_type ILIKE $1 OR data::text ILIKE $1)
         AND deleted_at IS NULL ${scopeFilter}
         LIMIT $3`
      : `SELECT id, entity_type, name, data, tags, updated_at
         FROM knowledge_entity
         WHERE (name ILIKE $1 OR entity_type ILIKE $1 OR data::text ILIKE $1)
         AND deleted_at IS NULL
         LIMIT $2`;

    const entityParams = scopeFilter ? [likePattern, scopeParam, topK] : [likePattern, topK];
    const entityResult = await pool.query(entityQuery, entityParams);
    totalCandidates += entityResult.rows.length;

    for (const row of entityResult.rows) {
      const ftsScore = 0.5; // basic text match
      const recencyScore = calculateRecency(row.updated_at);
      const proximityScore = calculateProximity(params.scope, row.tags ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      // Create snippet from entity data
      const dataSnippet = JSON.stringify(row.data).substring(0, 100);

      allHits.push({
        kind: 'entity',
        id: row.id,
        title: `${row.entity_type}: ${row.name}`,
        snippet: `${dataSnippet}...`,
        score: finalScore,
        scope: row.tags,
        updated_at: row.updated_at,
        route_used: mode,
        confidence: 0.7,
      });
    }
  }

  // Search incident_log table (8-LOG SYSTEM)
  if (searchTypes.includes('incident')) {
    const incidentQuery = scopeFilter
      ? `SELECT id, title, severity, impact, resolution_status, tags, updated_at
         FROM incident_log
         WHERE (title ILIKE $1 OR impact ILIKE $1 OR root_cause_analysis ILIKE $1) ${scopeFilter}
         LIMIT $3`
      : `SELECT id, title, severity, impact, resolution_status, tags, updated_at
         FROM incident_log
         WHERE (title ILIKE $1 OR impact ILIKE $1 OR root_cause_analysis ILIKE $1)
         LIMIT $2`;

    const incidentParams = scopeFilter ? [likePattern, scopeParam, topK] : [likePattern, topK];
    const incidentResult = await pool.query(incidentQuery, incidentParams);
    totalCandidates += incidentResult.rows.length;

    for (const row of incidentResult.rows) {
      const ftsScore = 0.8; // Incidents are high-value
      const recencyScore = calculateRecency(row.updated_at);
      const proximityScore = calculateProximity(params.scope, row.tags ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'incident',
        id: row.id,
        title: `INCIDENT: ${row.title} (${row.severity})`,
        snippet: `${(row.impact ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: row.tags,
        updated_at: row.updated_at,
        route_used: mode,
        confidence: 0.85,
      });
    }
  }

  // Search release_log table (8-LOG SYSTEM)
  if (searchTypes.includes('release')) {
    const releaseQuery = scopeFilter
      ? `SELECT id, version, release_type, scope, status, tags, updated_at
         FROM release_log
         WHERE (version ILIKE $1 OR scope ILIKE $1 OR release_notes ILIKE $1) ${scopeFilter}
         LIMIT $3`
      : `SELECT id, version, release_type, scope, status, tags, updated_at
         FROM release_log
         WHERE (version ILIKE $1 OR scope ILIKE $1 OR release_notes ILIKE $1)
         LIMIT $2`;

    const releaseParams = scopeFilter ? [likePattern, scopeParam, topK] : [likePattern, topK];
    const releaseResult = await pool.query(releaseQuery, releaseParams);
    totalCandidates += releaseResult.rows.length;

    for (const row of releaseResult.rows) {
      const ftsScore = 0.7; // Releases are high-value
      const recencyScore = calculateRecency(row.updated_at);
      const proximityScore = calculateProximity(params.scope, row.tags ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'release',
        id: row.id,
        title: `RELEASE: ${row.version} (${row.release_type})`,
        snippet: `${(row.scope ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: row.tags,
        updated_at: row.updated_at,
        route_used: mode,
        confidence: 0.8,
      });
    }
  }

  // Search risk_log table (8-LOG SYSTEM)
  if (searchTypes.includes('risk')) {
    const riskQuery = scopeFilter
      ? `SELECT id, title, category, risk_level, impact_description, tags, updated_at
         FROM risk_log
         WHERE (title ILIKE $1 OR impact_description ILIKE $1 OR mitigation_strategies::text ILIKE $1) ${scopeFilter}
         LIMIT $3`
      : `SELECT id, title, category, risk_level, impact_description, tags, updated_at
         FROM risk_log
         WHERE (title ILIKE $1 OR impact_description ILIKE $1 OR mitigation_strategies::text ILIKE $1)
         LIMIT $2`;

    const riskParams = scopeFilter ? [likePattern, scopeParam, topK] : [likePattern, topK];
    const riskResult = await pool.query(riskQuery, riskParams);
    totalCandidates += riskResult.rows.length;

    for (const row of riskResult.rows) {
      const ftsScore = 0.75; // Risks are high-value
      const recencyScore = calculateRecency(row.updated_at);
      const proximityScore = calculateProximity(params.scope, row.tags ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'risk',
        id: row.id,
        title: `RISK: ${row.title} (${row.risk_level})`,
        snippet: `${(row.impact_description ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: row.tags,
        updated_at: row.updated_at,
        route_used: mode,
        confidence: 0.8,
      });
    }
  }

  // Search assumption_log table (8-LOG SYSTEM)
  if (searchTypes.includes('assumption')) {
    const assumptionQuery = scopeFilter
      ? `SELECT id, title, description, category, validation_status, tags, updated_at
         FROM assumption_log
         WHERE (title ILIKE $1 OR description ILIKE $1 OR impact_if_invalid ILIKE $1) ${scopeFilter}
         LIMIT $3`
      : `SELECT id, title, description, category, validation_status, tags, updated_at
         FROM assumption_log
         WHERE (title ILIKE $1 OR description ILIKE $1 OR impact_if_invalid ILIKE $1)
         LIMIT $2`;

    const assumptionParams = scopeFilter ? [likePattern, scopeParam, topK] : [likePattern, topK];
    const assumptionResult = await pool.query(assumptionQuery, assumptionParams);
    totalCandidates += assumptionResult.rows.length;

    for (const row of assumptionResult.rows) {
      const ftsScore = 0.6; // Assumptions are moderate value
      const recencyScore = calculateRecency(row.updated_at);
      const proximityScore = calculateProximity(params.scope, row.tags ?? {});
      const finalScore = computeRankingScore(ftsScore, recencyScore, proximityScore, 0);

      allHits.push({
        kind: 'assumption',
        id: row.id,
        title: `ASSUMPTION: ${row.title} (${row.validation_status})`,
        snippet: `${(row.description ?? '').substring(0, 150)}...`,
        score: finalScore,
        scope: row.tags,
        updated_at: row.updated_at,
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
        const traversalResult = await traverseGraph(pool, startEntityType, startEntityId, {
          depth: params.traverse.depth ?? 3,
          relation_types: params.traverse.relation_types ?? [],
          direction: params.traverse.direction ?? ('both' as const),
        });

        // Enrich nodes with entity data
        const enrichedNodes = await enrichGraphNodes(pool, traversalResult.nodes);

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
