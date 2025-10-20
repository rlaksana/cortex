/**
 * 8-LOG SYSTEM Service - Session Persistence
 *
 * Manages the four session log types:
 * - INCIDENTLOG: Incident management with RCA and recovery
 * - RELEASELOG: Release management with deployment tracking
 * - RISK/ASSUMPTION LOG: Risk and assumption management
 *
 * Provides comprehensive CRUD operations for session persistence.
 */

import { Pool } from 'pg';
import { logger } from '../../utils/logger.js';

/**
 * Generate UUID using PostgreSQL gen_random_uuid()
 */
async function generateUUID(pool: Pool): Promise<string> {
  const result = await pool.query('SELECT gen_random_uuid() as uuid');
  return (result.rows[0] as { uuid: string }).uuid;
}

// ============================================================================
// INCIDENT LOG OPERATIONS
// ============================================================================

export interface IncidentData {
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  impact: string;
  timeline?: Array<{ timestamp: string; event: string; actor?: string }>;
  root_cause_analysis?: string;
  resolution_status: 'open' | 'investigating' | 'resolved' | 'closed';
  affected_services?: string[];
  business_impact?: string;
  recovery_actions?: string[];
  follow_up_required?: boolean;
  incident_commander?: string;
}

export async function storeIncident(
  pool: Pool,
  data: IncidentData,
  scope: Record<string, unknown> = {}
): Promise<string> {
  const id = await generateUUID(pool);

  await pool.query<{ id: string }>(
    `INSERT INTO incident_log (
      id, title, severity, impact, timeline, root_cause_analysis, resolution_status,
      affected_services, business_impact, recovery_actions, follow_up_required,
      incident_commander, tags, metadata
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
    [
      id,
      data.title,
      data.severity,
      data.impact,
      JSON.stringify(data.timeline ?? []),
      data.root_cause_analysis ?? null,
      data.resolution_status,
      data.affected_services ?? [],
      data.business_impact ?? null,
      data.recovery_actions ?? [],
      data.follow_up_required ?? false,
      data.incident_commander ?? null,
      JSON.stringify(scope),
      JSON.stringify({}),
    ]
  );

  logger.info({ incidentId: id, severity: data.severity }, 'Incident stored successfully');
  return id;
}

export async function updateIncident(
  pool: Pool,
  id: string,
  data: Partial<IncidentData>
): Promise<void> {
  const updates: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  const updateFields = [
    'title',
    'severity',
    'impact',
    'timeline',
    'root_cause_analysis',
    'resolution_status',
    'affected_services',
    'business_impact',
    'recovery_actions',
    'follow_up_required',
    'incident_commander',
  ] as const;

  for (const field of updateFields) {
    if (data[field] !== undefined) {
      updates.push(`${field} = $${paramIndex++}`);
      if (field === 'timeline') {
        values.push(JSON.stringify(data[field]));
      } else {
        values.push(data[field]);
      }
    }
  }

  if (updates.length === 0) {
    return;
  }

  updates.push(`updated_at = CURRENT_TIMESTAMP`);
  values.push(id);

  await pool.query(
    `UPDATE incident_log SET ${updates.join(', ')} WHERE id = $${paramIndex}`,
    values
  );
  logger.info({ incidentId: id, updates: updates.length }, 'Incident updated successfully');
}

export async function findIncidents(
  pool: Pool,
  criteria: {
    severity?: string;
    status?: string;
    limit?: number;
    offset?: number;
  }
): Promise<
  Array<{
    id: string;
    title: string;
    severity: string;
    impact: string;
    resolution_status: string;
    created_at: Date;
    updated_at: Date;
  }>
> {
  const conditions: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  if (criteria.severity) {
    conditions.push(`severity = $${paramIndex++}`);
    values.push(criteria.severity);
  }
  if (criteria.status) {
    conditions.push(`resolution_status = $${paramIndex++}`);
    values.push(criteria.status);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const limitClause = criteria.limit ? `LIMIT $${paramIndex++}` : '';
  const offsetClause = criteria.offset ? `OFFSET $${paramIndex++}` : '';

  if (criteria.limit) values.push(criteria.limit);
  if (criteria.offset) values.push(criteria.offset);

  const result = await pool.query<{
    id: string;
    title: string;
    severity: string;
    impact: string;
    resolution_status: string;
    created_at: Date;
    updated_at: Date;
  }>(
    `SELECT id, title, severity, impact, resolution_status, created_at, updated_at
     FROM incident_log ${whereClause}
     ORDER BY created_at DESC ${limitClause} ${offsetClause}`,
    values
  );

  return result.rows;
}

// ============================================================================
// RELEASE LOG OPERATIONS
// ============================================================================

export interface ReleaseData {
  version: string;
  release_type: 'major' | 'minor' | 'patch' | 'hotfix';
  scope: string;
  release_date?: string;
  status: 'planned' | 'in_progress' | 'completed' | 'rolled_back';
  ticket_references?: string[];
  included_changes?: string[];
  deployment_strategy?: string;
  rollback_plan?: string;
  testing_status?: string;
  approvers?: string[];
  release_notes?: string;
  post_release_actions?: string[];
}

export async function storeRelease(
  pool: Pool,
  data: ReleaseData,
  scope: Record<string, unknown> = {}
): Promise<string> {
  const id = await generateUUID(pool);

  await pool.query<{ id: string }>(
    `INSERT INTO release_log (
      id, version, release_type, scope, release_date, status, ticket_references,
      included_changes, deployment_strategy, rollback_plan, testing_status,
      approvers, release_notes, post_release_actions, tags, metadata
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
    [
      id,
      data.version,
      data.release_type,
      data.scope,
      data.release_date ?? null,
      data.status,
      data.ticket_references ?? [],
      data.included_changes ?? [],
      data.deployment_strategy ?? null,
      data.rollback_plan ?? null,
      data.testing_status ?? null,
      data.approvers ?? [],
      data.release_notes ?? null,
      data.post_release_actions ?? [],
      JSON.stringify(scope),
      JSON.stringify({}),
    ]
  );

  logger.info({ releaseId: id, version: data.version }, 'Release stored successfully');
  return id;
}

export async function updateRelease(
  pool: Pool,
  id: string,
  data: Partial<ReleaseData>
): Promise<void> {
  const updates: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  const updateFields = [
    'version',
    'release_type',
    'scope',
    'release_date',
    'status',
    'ticket_references',
    'included_changes',
    'deployment_strategy',
    'rollback_plan',
    'testing_status',
    'approvers',
    'release_notes',
    'post_release_actions',
  ] as const;

  for (const field of updateFields) {
    if (data[field] !== undefined) {
      if (Array.isArray(data[field])) {
        updates.push(`${field} = $${paramIndex++}`);
        values.push(data[field]);
      } else {
        updates.push(`${field} = $${paramIndex++}`);
        values.push(data[field]);
      }
    }
  }

  if (updates.length === 0) {
    return;
  }

  updates.push(`updated_at = CURRENT_TIMESTAMP`);
  values.push(id);

  await pool.query(
    `UPDATE release_log SET ${updates.join(', ')} WHERE id = $${paramIndex}`,
    values
  );
  logger.info({ releaseId: id, updates: updates.length }, 'Release updated successfully');
}

export async function findReleases(
  pool: Pool,
  criteria: {
    version?: string;
    status?: string;
    limit?: number;
    offset?: number;
  }
): Promise<
  Array<{
    id: string;
    version: string;
    release_type: string;
    scope: string;
    release_date: Date;
    status: string;
    created_at: Date;
    updated_at: Date;
  }>
> {
  const conditions: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  if (criteria.version) {
    conditions.push(`version ILIKE $${paramIndex}`);
    values.push(`%${criteria.version}%`);
  }
  if (criteria.status) {
    conditions.push(`status = $${paramIndex++}`);
    values.push(criteria.status);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const limitClause = criteria.limit ? `LIMIT $${paramIndex++}` : '';
  const offsetClause = criteria.offset ? `OFFSET $${paramIndex++}` : '';

  if (criteria.limit) values.push(criteria.limit);
  if (criteria.offset) values.push(criteria.offset);

  const result = await pool.query<{
    id: string;
    version: string;
    release_type: string;
    scope: string;
    release_date: Date;
    status: string;
    created_at: Date;
    updated_at: Date;
  }>(
    `SELECT id, version, release_type, scope, release_date, status, created_at, updated_at
     FROM release_log ${whereClause}
     ORDER BY release_date DESC ${limitClause} ${offsetClause}`,
    values
  );

  return result.rows;
}

// ============================================================================
// RISK LOG OPERATIONS
// ============================================================================

export interface RiskData {
  title: string;
  category: 'technical' | 'business' | 'operational' | 'security' | 'compliance';
  risk_level: 'critical' | 'high' | 'medium' | 'low';
  probability: 'very_likely' | 'likely' | 'possible' | 'unlikely' | 'very_unlikely';
  impact_description: string;
  trigger_events?: string[];
  mitigation_strategies?: string[];
  owner?: string;
  review_date?: string;
  status: 'active' | 'mitigated' | 'accepted' | 'closed';
  related_decisions?: string[];
  monitoring_indicators?: string[];
  contingency_plans?: string;
}

export async function storeRisk(
  pool: Pool,
  data: RiskData,
  scope: Record<string, unknown> = {}
): Promise<string> {
  const id = await generateUUID(pool);

  await pool.query<{ id: string }>(
    `INSERT INTO risk_log (
      id, title, category, risk_level, probability, impact_description,
      trigger_events, mitigation_strategies, owner, review_date, status,
      related_decisions, monitoring_indicators, contingency_plans, tags, metadata
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
    [
      id,
      data.title,
      data.category,
      data.risk_level,
      data.probability,
      data.impact_description,
      data.trigger_events ?? [],
      data.mitigation_strategies ?? [],
      data.owner ?? null,
      data.review_date ?? null,
      data.status,
      data.related_decisions ?? [],
      data.monitoring_indicators ?? [],
      data.contingency_plans ?? null,
      JSON.stringify(scope),
      JSON.stringify({}),
    ]
  );

  logger.info({ riskId: id, level: data.risk_level }, 'Risk stored successfully');
  return id;
}

export async function updateRisk(pool: Pool, id: string, data: Partial<RiskData>): Promise<void> {
  const updates: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  const updateFields = [
    'title',
    'category',
    'risk_level',
    'probability',
    'impact_description',
    'trigger_events',
    'mitigation_strategies',
    'owner',
    'review_date',
    'status',
    'related_decisions',
    'monitoring_indicators',
    'contingency_plans',
  ] as const;

  for (const field of updateFields) {
    if (data[field] !== undefined) {
      if (Array.isArray(data[field])) {
        updates.push(`${field} = $${paramIndex++}`);
        values.push(data[field]);
      } else {
        updates.push(`${field} = $${paramIndex++}`);
        values.push(data[field]);
      }
    }
  }

  if (updates.length === 0) {
    return;
  }

  updates.push(`updated_at = CURRENT_TIMESTAMP`);
  values.push(id);

  await pool.query(`UPDATE risk_log SET ${updates.join(', ')} WHERE id = $${paramIndex}`, values);
  logger.info({ riskId: id, updates: updates.length }, 'Risk updated successfully');
}

export async function findRisks(
  pool: Pool,
  criteria: {
    category?: string;
    level?: string;
    status?: string;
    limit?: number;
    offset?: number;
  }
): Promise<
  Array<{
    id: string;
    title: string;
    category: string;
    risk_level: string;
    probability: string;
    status: string;
    created_at: Date;
    updated_at: Date;
  }>
> {
  const conditions: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  if (criteria.category) {
    conditions.push(`category = $${paramIndex++}`);
    values.push(criteria.category);
  }
  if (criteria.level) {
    conditions.push(`risk_level = $${paramIndex++}`);
    values.push(criteria.level);
  }
  if (criteria.status) {
    conditions.push(`status = $${paramIndex++}`);
    values.push(criteria.status);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const limitClause = criteria.limit ? `LIMIT $${paramIndex++}` : '';
  const offsetClause = criteria.offset ? `OFFSET $${paramIndex++}` : '';

  if (criteria.limit) values.push(criteria.limit);
  if (criteria.offset) values.push(criteria.offset);

  const result = await pool.query<{
    id: string;
    title: string;
    category: string;
    risk_level: string;
    probability: string;
    status: string;
    created_at: Date;
    updated_at: Date;
  }>(
    `SELECT id, title, category, risk_level, probability, status, created_at, updated_at
     FROM risk_log ${whereClause}
     ORDER BY updated_at DESC ${limitClause} ${offsetClause}`,
    values
  );

  return result.rows;
}

// ============================================================================
// ASSUMPTION LOG OPERATIONS
// ============================================================================

export interface AssumptionData {
  title: string;
  description: string;
  category: 'technical' | 'business' | 'user' | 'market' | 'resource';
  validation_status: 'validated' | 'assumed' | 'invalidated' | 'needs_validation';
  impact_if_invalid: string;
  validation_criteria?: string[];
  validation_date?: string;
  owner?: string;
  related_assumptions?: string[];
  dependencies?: string[];
  monitoring_approach?: string;
  review_frequency?: 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'as_needed';
}

export async function storeAssumption(
  pool: Pool,
  data: AssumptionData,
  scope: Record<string, unknown> = {}
): Promise<string> {
  const id = await generateUUID(pool);

  await pool.query<{ id: string }>(
    `INSERT INTO assumption_log (
      id, title, description, category, validation_status, impact_if_invalid,
      validation_criteria, validation_date, owner, related_assumptions,
      dependencies, monitoring_approach, review_frequency, tags, metadata
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
    [
      id,
      data.title,
      data.description,
      data.category,
      data.validation_status,
      data.impact_if_invalid,
      data.validation_criteria ?? [],
      data.validation_date ?? null,
      data.owner ?? null,
      data.related_assumptions ?? [],
      data.dependencies ?? [],
      data.monitoring_approach ?? null,
      data.review_frequency ?? null,
      JSON.stringify(scope),
      JSON.stringify({}),
    ]
  );

  logger.info(
    { assumptionId: id, status: data.validation_status },
    'Assumption stored successfully'
  );
  return id;
}

export async function updateAssumption(
  pool: Pool,
  id: string,
  data: Partial<AssumptionData>
): Promise<void> {
  const updates: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  const updateFields = [
    'title',
    'description',
    'category',
    'validation_status',
    'impact_if_invalid',
    'validation_criteria',
    'validation_date',
    'owner',
    'related_assumptions',
    'dependencies',
    'monitoring_approach',
    'review_frequency',
  ] as const;

  for (const field of updateFields) {
    if (data[field] !== undefined) {
      if (Array.isArray(data[field])) {
        updates.push(`${field} = $${paramIndex++}`);
        values.push(data[field]);
      } else {
        updates.push(`${field} = $${paramIndex++}`);
        values.push(data[field]);
      }
    }
  }

  if (updates.length === 0) {
    return;
  }

  updates.push(`updated_at = CURRENT_TIMESTAMP`);
  values.push(id);

  await pool.query(
    `UPDATE assumption_log SET ${updates.join(', ')} WHERE id = $${paramIndex}`,
    values
  );
  logger.info({ assumptionId: id, updates: updates.length }, 'Assumption updated successfully');
}

export async function findAssumptions(
  pool: Pool,
  criteria: {
    category?: string;
    status?: string;
    limit?: number;
    offset?: number;
  }
): Promise<
  Array<{
    id: string;
    title: string;
    description: string;
    category: string;
    validation_status: string;
    created_at: Date;
    updated_at: Date;
  }>
> {
  const conditions: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  if (criteria.category) {
    conditions.push(`category = $${paramIndex++}`);
    values.push(criteria.category);
  }
  if (criteria.status) {
    conditions.push(`validation_status = $${paramIndex++}`);
    values.push(criteria.status);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const limitClause = criteria.limit ? `LIMIT $${paramIndex++}` : '';
  const offsetClause = criteria.offset ? `OFFSET $${paramIndex++}` : '';

  if (criteria.limit) values.push(criteria.limit);
  if (criteria.offset) values.push(criteria.offset);

  const result = await pool.query<{
    id: string;
    title: string;
    description: string;
    category: string;
    validation_status: string;
    created_at: Date;
    updated_at: Date;
  }>(
    `SELECT id, title, description, category, validation_status, created_at, updated_at
     FROM assumption_log ${whereClause}
     ORDER BY updated_at DESC ${limitClause} ${offsetClause}`,
    values
  );

  return result.rows;
}

// ============================================================================
// SESSION LOG DASHBOARD - Combined view of all 8-LOG SYSTEM entries
// ============================================================================

export interface SessionLogEntry {
  type: 'incident' | 'release' | 'risk' | 'assumption';
  id: string;
  title: string;
  status: string;
  created_at: Date;
  updated_at: Date;
  tags: Record<string, unknown>;
}

export async function getSessionLogDashboard(
  pool: Pool,
  criteria: {
    type?: string;
    limit?: number;
    offset?: number;
  } = {}
): Promise<SessionLogEntry[]> {
  const conditions: string[] = [];
  const values: unknown[] = [];
  let paramIndex = 1;

  if (criteria.type) {
    conditions.push(`log_type = $${paramIndex++}`);
    values.push(criteria.type);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const limitClause = criteria.limit ? `LIMIT $${paramIndex++}` : '';
  const offsetClause = criteria.offset ? `OFFSET $${paramIndex++}` : '';

  if (criteria.limit) values.push(criteria.limit);
  if (criteria.offset) values.push(criteria.offset);

  const result = await pool.query(
    `SELECT log_type, id, title, status, created_at, updated_at, tags
     FROM (
       SELECT 'incident' as log_type, id, title, resolution_status as status, created_at, updated_at, tags FROM incident_log
       UNION ALL
       SELECT 'release' as log_type, id, version as title, status, created_at, updated_at, tags FROM release_log
       UNION ALL
       SELECT 'risk' as log_type, id, title, status, created_at, updated_at, tags FROM risk_log
       UNION ALL
       SELECT 'assumption' as log_type, id, title, validation_status as status, created_at, updated_at, tags FROM assumption_log
     ) as combined_logs
     ${whereClause}
     ORDER BY updated_at DESC ${limitClause} ${offsetClause}`,
    values
  );

  return result.rows.map((row) => ({
    type: row.log_type,
    id: row.id,
    title: row.title,
    status: row.status,
    created_at: row.created_at,
    updated_at: row.updated_at,
    tags: row.tags,
  }));
}
