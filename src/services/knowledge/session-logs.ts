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

// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import { logger } from '../../utils/logger.js';

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
    data: IncidentData,
  scope: Record<string, unknown> = {}
): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const result = await qdrant.incidentLog.create({
    data: {
      title: data.title,
      severity: data.severity,
      impact: data.impact,
      resolution_status: data.resolution_status,
      tags: {
        ...scope,
        timeline: data.timeline ?? [],
        root_cause_analysis: data.root_cause_analysis,
        affected_services: data.affected_services ?? [],
        business_impact: data.business_impact,
        recovery_actions: data.recovery_actions ?? [],
        follow_up_required: data.follow_up_required ?? false,
        incident_commander: data.incident_commander
      }
    }
  });

  logger.info({ incidentId: result.id, severity: data.severity }, 'Incident stored successfully');
  return result.id;
}

export async function updateIncident(
    id: string,
  data: Partial<IncidentData>
): Promise<void> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const updateData: any = {};

  if (data.title !== undefined) {
    updateData.title = data.title;
  }
  if (data.severity !== undefined) {
    updateData.severity = data.severity;
  }
  if (data.impact !== undefined) {
    updateData.impact = data.impact;
  }
  if (data.resolution_status !== undefined) {
    updateData.resolution_status = data.resolution_status;
  }

  // Note: Other fields are stored in tags due to schema limitations
  const tagUpdates: any = {};
  if (data.timeline !== undefined) {
    tagUpdates.timeline = data.timeline;
  }
  if (data.root_cause_analysis !== undefined) {
    tagUpdates.root_cause_analysis = data.root_cause_analysis;
  }
  if (data.affected_services !== undefined) {
    tagUpdates.affected_services = data.affected_services;
  }
  if (data.business_impact !== undefined) {
    tagUpdates.business_impact = data.business_impact;
  }
  if (data.recovery_actions !== undefined) {
    tagUpdates.recovery_actions = data.recovery_actions;
  }
  if (data.follow_up_required !== undefined) {
    tagUpdates.follow_up_required = data.follow_up_required;
  }
  if (data.incident_commander !== undefined) {
    tagUpdates.incident_commander = data.incident_commander;
  }

  if (Object.keys(updateData).length === 0 && Object.keys(tagUpdates).length === 0) {
    return;
  }

  if (Object.keys(tagUpdates).length > 0) {
    updateData.tags = tagUpdates;
  }

  await db.update('incidentLog', { id }, updateData
  );
  logger.info({ incidentId: id, updates: Object.keys(updateData).length }, 'Incident updated successfully');
}

export async function findIncidents(
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
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const whereClause: any = {};

  if (criteria.severity) {
    whereClause.severity = criteria.severity;
  }
  if (criteria.status) {
    whereClause.resolution_status = criteria.status;
  }

  const result = return await db.find('incidentLog', {
    where: whereClause,
    orderBy: { created_at: 'desc' },
    take: criteria.limit,
    skip: criteria.offset,
    select: {
      id: true,
      title: true,
      severity: true,
      impact: true,
      resolution_status: true,
      created_at: true,
      updated_at: true
    }
  });

  return result.map(incident => ({
    id: incident.id,
    title: incident.title,
    severity: incident.severity,
    impact: incident.impact,
    resolution_status: incident.resolution_status,
    created_at: incident.created_at,
    updated_at: incident.updated_at
  }));
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
    data: ReleaseData,
  scope: Record<string, unknown> = {}
): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const result = await qdrant.releaseLog.create({
    data: {
      version: data.version,
      release_type: data.release_type,
      scope: data.scope,
      status: data.status,
      tags: {
        ...scope,
        release_date: data.release_date,
        ticket_references: data.ticket_references ?? [],
        included_changes: data.included_changes ?? [],
        deployment_strategy: data.deployment_strategy,
        rollback_plan: data.rollback_plan,
        testing_status: data.testing_status,
        approvers: data.approvers ?? [],
        release_notes: data.release_notes,
        post_release_actions: data.post_release_actions ?? []
      }
    }
  });

  logger.info({ releaseId: result.id, version: data.version }, 'Release stored successfully');
  return result.id;
}

export async function updateRelease(
    id: string,
  data: Partial<ReleaseData>
): Promise<void> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const updateData: any = {};
  const tagUpdates: any = {};

  // Handle direct fields (those that exist in the schema)
  if (data.version !== undefined) {
    updateData.version = data.version;
  }
  if (data.release_type !== undefined) {
    updateData.release_type = data.release_type;
  }
  if (data.scope !== undefined) {
    updateData.scope = data.scope;
  }
  if (data.status !== undefined) {
    updateData.status = data.status;
  }

  // Handle fields stored in tags JSON
  const tagFields = [
    'release_date',
    'ticket_references',
    'included_changes',
    'deployment_strategy',
    'rollback_plan',
    'testing_status',
    'approvers',
    'release_notes',
    'post_release_actions',
  ] as const;

  for (const field of tagFields) {
    if (data[field] !== undefined) {
      tagUpdates[field] = data[field];
    }
  }

  if (Object.keys(updateData).length === 0 && Object.keys(tagUpdates).length === 0) {
    return;
  }

  if (Object.keys(tagUpdates).length > 0) {
    updateData.tags = tagUpdates;
  }

  await db.update('releaseLog', { id }, updateData
  );
  logger.info({ releaseId: id, updates: Object.keys(updateData).length }, 'Release updated successfully');
}

export async function findReleases(
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
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const whereClause: any = {};

  if (criteria.version) {
    whereClause.version = {
      contains: criteria.version,
      mode: 'insensitive'
    };
  }
  if (criteria.status) {
    whereClause.status = criteria.status;
  }

  const result = return await db.find('releaseLog', {
    where: whereClause,
    orderBy: { created_at: 'desc' },
    take: criteria.limit,
    skip: criteria.offset,
    select: {
      id: true,
      version: true,
      release_type: true,
      scope: true,
      status: true,
      created_at: true,
      updated_at: true,
      tags: true
    }
  });

  return result.map(release => ({
    id: release.id,
    version: release.version,
    release_type: release.release_type,
    scope: release.scope,
    release_date: (release.tags as any)?.release_date ? new Date((release.tags as any).release_date) : release.created_at,
    status: release.status,
    created_at: release.created_at,
    updated_at: release.updated_at
  }));
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
    data: RiskData,
  scope: Record<string, unknown> = {}
): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const result = await qdrant.riskLog.create({
    data: {
      title: data.title,
      category: data.category,
      risk_level: data.risk_level,
      impact_description: data.impact_description,
      status: data.status,
      tags: {
        ...scope,
        probability: data.probability,
        trigger_events: data.trigger_events ?? [],
        mitigation_strategies: data.mitigation_strategies ?? [],
        owner: data.owner ?? null,
        review_date: data.review_date ?? null,
        related_decisions: data.related_decisions ?? [],
        monitoring_indicators: data.monitoring_indicators ?? [],
        contingency_plans: data.contingency_plans ?? null
      }
    }
  });

  logger.info({ riskId: result.id, level: data.risk_level }, 'Risk stored successfully');
  return result.id;
}

export async function updateRisk(id: string, data: Partial<RiskData>): Promise<void> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const updateData: any = {};
  const tagUpdates: any = {};

  // Handle direct fields (those that exist in the schema)
  if (data.title !== undefined) {
    updateData.title = data.title;
  }
  if (data.category !== undefined) {
    updateData.category = data.category;
  }
  if (data.risk_level !== undefined) {
    updateData.risk_level = data.risk_level;
  }
  if (data.impact_description !== undefined) {
    updateData.impact_description = data.impact_description;
  }
  if (data.status !== undefined) {
    updateData.status = data.status;
  }

  // Handle fields stored in tags JSON
  const tagFields = [
    'probability',
    'trigger_events',
    'mitigation_strategies',
    'owner',
    'review_date',
    'related_decisions',
    'monitoring_indicators',
    'contingency_plans',
  ] as const;

  for (const field of tagFields) {
    if (data[field] !== undefined) {
      tagUpdates[field] = data[field];
    }
  }

  if (Object.keys(updateData).length === 0 && Object.keys(tagUpdates).length === 0) {
    return;
  }

  if (Object.keys(tagUpdates).length > 0) {
    updateData.tags = tagUpdates;
  }

  await db.update('riskLog', { id }, updateData
  );
  logger.info({ riskId: id, updates: Object.keys(updateData).length }, 'Risk updated successfully');
}

export async function findRisks(
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
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const whereClause: any = {};

  if (criteria.category) {
    whereClause.category = criteria.category;
  }
  if (criteria.level) {
    whereClause.risk_level = criteria.level;
  }
  if (criteria.status) {
    whereClause.status = criteria.status;
  }

  const result = return await db.find('riskLog', {
    where: whereClause,
    orderBy: { updated_at: 'desc' },
    take: criteria.limit,
    skip: criteria.offset,
    select: {
      id: true,
      title: true,
      category: true,
      risk_level: true,
      status: true,
      created_at: true,
      updated_at: true,
      tags: true
    }
  });

  return result.map(risk => ({
    id: risk.id,
    title: risk.title,
    category: risk.category,
    risk_level: risk.risk_level,
    probability: (risk.tags as any)?.probability || 'unknown',
    status: risk.status,
    created_at: risk.created_at,
    updated_at: risk.updated_at
  }));
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
    data: AssumptionData,
  scope: Record<string, unknown> = {}
): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const result = await qdrant.assumptionLog.create({
    data: {
      title: data.title,
      description: data.description,
      category: data.category,
      validation_status: data.validation_status,
      impact_if_invalid: data.impact_if_invalid,
      tags: {
        ...scope,
        validation_criteria: data.validation_criteria ?? [],
        validation_date: data.validation_date ?? null,
        owner: data.owner ?? null,
        related_assumptions: data.related_assumptions ?? [],
        dependencies: data.dependencies ?? [],
        monitoring_approach: data.monitoring_approach ?? null,
        review_frequency: data.review_frequency ?? null
      }
    }
  });

  logger.info(
    { assumptionId: result.id, status: data.validation_status },
    'Assumption stored successfully'
  );
  return result.id;
}

export async function updateAssumption(
    id: string,
  data: Partial<AssumptionData>
): Promise<void> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const updateData: any = {};
  const tagUpdates: any = {};

  // Handle direct fields (those that exist in the schema)
  if (data.title !== undefined) {
    updateData.title = data.title;
  }
  if (data.description !== undefined) {
    updateData.description = data.description;
  }
  if (data.category !== undefined) {
    updateData.category = data.category;
  }
  if (data.validation_status !== undefined) {
    updateData.validation_status = data.validation_status;
  }
  if (data.impact_if_invalid !== undefined) {
    updateData.impact_if_invalid = data.impact_if_invalid;
  }

  // Handle fields stored in tags JSON
  const tagFields = [
    'validation_criteria',
    'validation_date',
    'owner',
    'related_assumptions',
    'dependencies',
    'monitoring_approach',
    'review_frequency',
  ] as const;

  for (const field of tagFields) {
    if (data[field] !== undefined) {
      tagUpdates[field] = data[field];
    }
  }

  if (Object.keys(updateData).length === 0 && Object.keys(tagUpdates).length === 0) {
    return;
  }

  if (Object.keys(tagUpdates).length > 0) {
    updateData.tags = tagUpdates;
  }

  await db.update('assumptionLog', { id }, updateData
  );
  logger.info({ assumptionId: id, updates: Object.keys(updateData).length }, 'Assumption updated successfully');
}

export async function findAssumptions(
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
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const whereClause: any = {};

  if (criteria.category) {
    whereClause.category = criteria.category;
  }
  if (criteria.status) {
    whereClause.validation_status = criteria.status;
  }

  const result = return await db.find('assumptionLog', {
    where: whereClause,
    orderBy: { updated_at: 'desc' },
    take: criteria.limit,
    skip: criteria.offset,
    select: {
      id: true,
      title: true,
      description: true,
      category: true,
      validation_status: true,
      created_at: true,
      updated_at: true
    }
  });

  return result.map(assumption => ({
    id: assumption.id,
    title: assumption.title,
    description: assumption.description,
    category: assumption.category,
    validation_status: assumption.validation_status,
    created_at: assumption.created_at,
    updated_at: assumption.updated_at
  }));
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
    criteria: {
    type?: string;
    limit?: number;
    offset?: number;
  } = {}
): Promise<SessionLogEntry[]> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  // Since we can't easily replicate the UNION ALL with Qdrant queries,
  // we'll use $queryRawUnsafe with proper template literal
  const limitClause = criteria.limit ? `LIMIT ${criteria.limit}` : '';
  const offsetClause = criteria.offset ? `OFFSET ${criteria.offset}` : '';
  const whereClause = criteria.type ? `WHERE log_type = '${criteria.type}'` : '';

  const result = await qdrant.$queryRawUnsafe<Array<{
    log_type: string;
    id: string;
    title: string;
    status: string;
    created_at: Date;
    updated_at: Date;
    tags: Record<string, unknown>;
  }>>(
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
     ORDER BY updated_at DESC ${limitClause} ${offsetClause}`
  );

  return result.map((row) => ({
    type: row.log_type as 'incident' | 'release' | 'risk' | 'assumption',
    id: row.id,
    title: row.title,
    status: row.status,
    created_at: row.created_at,
    updated_at: row.updated_at,
    tags: row.tags,
  }));
}
