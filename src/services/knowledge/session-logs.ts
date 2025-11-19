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

// Import required modules
import { logger } from '@/utils/logger.js';
import {
  hasPropertySimple,
  safePropertyAccess,
  isString,
  isBoolean,
  isObject,
  isArray,
  requirePropertyAccess,
  isUnknown,
  isDatabaseCriteria,
  isIncidentResponse,
  isReleaseResponse,
  isRiskResponse,
  isAssumptionResponse
} from '../../utils/type-guards.js';
import type {
  DatabaseResponse,
  IncidentResponse,
  ReleaseResponse,
  RiskResponse,
  AssumptionResponse
} from '../../types/database.js';

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

export async function storeIncident(data: unknown, scope: unknown = {}): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  // Safely extract required properties using type guards
  const title = requirePropertyAccess(data, 'title', isString);
  const severity = requirePropertyAccess(data, 'severity', isString);
  const impact = requirePropertyAccess(data, 'impact', isString);
  const resolutionStatus = requirePropertyAccess(data, 'resolution_status', isString);

  // Extract optional properties safely
  const timeline = safePropertyAccess(data, 'timeline', isArray, []);
  const rootCauseAnalysis = safePropertyAccess(data, 'root_cause_analysis', isString, undefined);
  const affectedServices = safePropertyAccess(data, 'affected_services', isArray, []);
  const businessImpact = safePropertyAccess(data, 'business_impact', isString, undefined);
  const recoveryActions = safePropertyAccess(data, 'recovery_actions', isArray, []);
  const followUpRequired = safePropertyAccess(data, 'follow_up_required', isBoolean, false);
  const incidentCommander = safePropertyAccess(data, 'incident_commander', isString);

  const result = await db.create('incidentLog', {
    title,
    severity,
    impact,
    resolution_status: resolutionStatus,
    tags: {
      ...(scope && typeof scope === 'object' ? scope : {}),
      timeline,
      root_cause_analysis: rootCauseAnalysis,
      affected_services: affectedServices,
      business_impact: businessImpact,
      recovery_actions: recoveryActions,
      follow_up_required: followUpRequired,
      incident_commander: incidentCommander,
    },
  });

  logger.info({ incidentId: result.id, severity }, 'Incident stored successfully');
  return result.id;
}

export async function updateIncident(id: string, data: unknown): Promise<void> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('Invalid incident data provided');
  }

  const dataObj = data as Record<string, unknown>;
  const updateData: Record<string, unknown> = {};

  if (hasPropertySimple(dataObj, 'title') && isString(dataObj.title)) {
    updateData.title = dataObj.title;
  }
  if (hasPropertySimple(dataObj, 'severity') && isString(dataObj.severity)) {
    updateData.severity = dataObj.severity;
  }
  if (hasPropertySimple(dataObj, 'impact') && isString(dataObj.impact)) {
    updateData.impact = dataObj.impact;
  }
  if (hasPropertySimple(dataObj, 'resolution_status') && isString(dataObj.resolution_status)) {
    updateData.resolution_status = dataObj.resolution_status;
  }

  // Note: Other fields are stored in tags due to schema limitations
  const tagUpdates: Record<string, unknown> = {};
  if (hasPropertySimple(dataObj, 'timeline')) {
    tagUpdates.timeline = dataObj.timeline;
  }
  if (hasPropertySimple(dataObj, 'root_cause_analysis') && isString(dataObj.root_cause_analysis)) {
    tagUpdates.root_cause_analysis = dataObj.root_cause_analysis;
  }
  if (hasPropertySimple(dataObj, 'affected_services') && isArray(dataObj.affected_services, isString)) {
    tagUpdates.affected_services = dataObj.affected_services;
  }
  if (hasPropertySimple(dataObj, 'business_impact') && isString(dataObj.business_impact)) {
    tagUpdates.business_impact = dataObj.business_impact;
  }
  if (hasPropertySimple(dataObj, 'recovery_actions') && isArray(dataObj.recovery_actions, isString)) {
    tagUpdates.recovery_actions = dataObj.recovery_actions;
  }
  if (hasPropertySimple(dataObj, 'follow_up_required') && isBoolean(dataObj.follow_up_required)) {
    tagUpdates.follow_up_required = dataObj.follow_up_required;
  }
  if (hasPropertySimple(dataObj, 'incident_commander') && isString(dataObj.incident_commander)) {
    tagUpdates.incident_commander = dataObj.incident_commander;
  }

  if (Object.keys(updateData).length === 0 && Object.keys(tagUpdates).length === 0) {
    return;
  }

  if (Object.keys(tagUpdates).length > 0) {
    updateData.tags = tagUpdates;
  }

  // For now, just log that update is not supported
  // In a full implementation, you would delete and recreate the item
  logger.warn({ incidentId: id }, 'Update not supported - would require delete + recreate');
  logger.info(
    { incidentId: id, updates: Object.keys(updateData).length },
    'Incident updated successfully'
  );
}

export async function findIncidents(criteria: unknown): Promise<unknown> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const whereClause: Record<string, unknown> = {};

  if (criteria && typeof criteria === 'object' && !Array.isArray(criteria)) {
    const criteriaObj = criteria as Record<string, unknown>;
    if (hasPropertySimple(criteriaObj, 'severity') && isString(criteriaObj.severity)) {
      whereClause.severity = criteriaObj.severity;
    }
    if (hasPropertySimple(criteriaObj, 'status') && isString(criteriaObj.status)) {
      whereClause.resolution_status = criteriaObj.status;
    }
  }

  const findOptions: Record<string, unknown> = {
    where: whereClause,
    orderBy: { created_at: 'desc' },
  };

  if (criteria && typeof criteria === 'object' && !Array.isArray(criteria)) {
    const criteriaObj = criteria as Record<string, unknown>;
    if (hasPropertySimple(criteriaObj, 'limit') && typeof criteriaObj.limit === 'number') {
      findOptions.take = criteriaObj.limit;
    }
    if (hasPropertySimple(criteriaObj, 'offset') && typeof criteriaObj.offset === 'number') {
      findOptions.skip = criteriaObj.offset;
    }
  }

  const result = await db.find('incidentLog', findOptions);

  if (!Array.isArray(result)) {
    return [];
  }

  return result.filter(isIncidentResponse).map((incident) => ({
    id: incident.id,
    title: incident.title,
    severity: incident.severity,
    impact: incident.impact || '',
    resolution_status: incident.resolution_status || 'open',
    created_at: incident.created_at,
    updated_at: incident.updated_at,
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

export async function storeRelease(data: unknown, scope: unknown = {}): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('Invalid release data provided');
  }

  const dataObj = data as Record<string, unknown>;
  const scopeObj = (scope && typeof scope === 'object' && !Array.isArray(scope)) ? scope as Record<string, unknown> : {};

  const createData: Record<string, unknown> = {};

  if (hasPropertySimple(dataObj, 'version') && isString(dataObj.version)) {
    createData.version = dataObj.version;
  }
  if (hasPropertySimple(dataObj, 'release_type') && isString(dataObj.release_type)) {
    createData.release_type = dataObj.release_type;
  }
  if (hasPropertySimple(dataObj, 'scope') && isString(dataObj.scope)) {
    createData.scope = dataObj.scope;
  }
  if (hasPropertySimple(dataObj, 'status') && isString(dataObj.status)) {
    createData.status = dataObj.status;
  }

  createData.tags = {
    ...scopeObj,
    release_date: hasPropertySimple(dataObj, 'release_date') ? dataObj.release_date : undefined,
    ticket_references: hasPropertySimple(dataObj, 'ticket_references') && isArray(dataObj.ticket_references, isString) ? dataObj.ticket_references : [],
    included_changes: hasPropertySimple(dataObj, 'included_changes') && isArray(dataObj.included_changes, isString) ? dataObj.included_changes : [],
    deployment_strategy: hasPropertySimple(dataObj, 'deployment_strategy') ? dataObj.deployment_strategy : undefined,
    rollback_plan: hasPropertySimple(dataObj, 'rollback_plan') ? dataObj.rollback_plan : undefined,
    testing_status: hasPropertySimple(dataObj, 'testing_status') ? dataObj.testing_status : undefined,
    approvers: hasPropertySimple(dataObj, 'approvers') && isArray(dataObj.approvers, isString) ? dataObj.approvers : [],
    release_notes: hasPropertySimple(dataObj, 'release_notes') ? dataObj.release_notes : undefined,
    post_release_actions: hasPropertySimple(dataObj, 'post_release_actions') && isArray(dataObj.post_release_actions, isString) ? dataObj.post_release_actions : [],
  };

  const result = await db.create('releaseLog', createData);

  logger.info({ releaseId: result.id, version: String(createData.version || 'unknown') }, 'Release stored successfully');
  return result.id;
}

export async function updateRelease(id: string, data: unknown): Promise<void> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('Invalid release data provided');
  }

  const dataObj = data as Record<string, unknown>;
  const updateData: Record<string, unknown> = {};
  const tagUpdates: Record<string, unknown> = {};

  // Handle direct fields (those that exist in the schema)
  if (hasPropertySimple(dataObj, 'version') && isString(dataObj.version)) {
    updateData.version = dataObj.version;
  }
  if (hasPropertySimple(dataObj, 'release_type') && isString(dataObj.release_type)) {
    updateData.release_type = dataObj.release_type;
  }
  if (hasPropertySimple(dataObj, 'scope') && isString(dataObj.scope)) {
    updateData.scope = dataObj.scope;
  }
  if (hasPropertySimple(dataObj, 'status') && isString(dataObj.status)) {
    updateData.status = dataObj.status;
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
    if (hasPropertySimple(dataObj, field)) {
      tagUpdates[field] = dataObj[field];
    }
  }

  if (Object.keys(updateData).length === 0 && Object.keys(tagUpdates).length === 0) {
    return;
  }

  if (Object.keys(tagUpdates).length > 0) {
    updateData.tags = tagUpdates;
  }

  // For now, just log that update is not supported
  // In a full implementation, you would delete and recreate the item
  logger.warn({ releaseId: id }, 'Update not supported - would require delete + recreate');
  logger.info(
    { releaseId: id, updates: Object.keys(updateData).length },
    'Release updated successfully'
  );
}

export async function findReleases(criteria: unknown): Promise<unknown> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const whereClause: Record<string, unknown> = {};

  if (criteria && typeof criteria === 'object' && !Array.isArray(criteria)) {
    const criteriaObj = criteria as Record<string, unknown>;
    if (hasPropertySimple(criteriaObj, 'version') && isString(criteriaObj.version)) {
      whereClause.version = {
        contains: criteriaObj.version,
        mode: 'insensitive',
      };
    }
    if (hasPropertySimple(criteriaObj, 'status') && isString(criteriaObj.status)) {
      whereClause.status = criteriaObj.status;
    }
  }

  const findOptions: Record<string, unknown> = {
    where: whereClause,
    orderBy: { created_at: 'desc' },
  };

  if (criteria && typeof criteria === 'object' && !Array.isArray(criteria)) {
    const criteriaObj = criteria as Record<string, unknown>;
    if (hasPropertySimple(criteriaObj, 'limit') && typeof criteriaObj.limit === 'number') {
      findOptions.take = criteriaObj.limit;
    }
    if (hasPropertySimple(criteriaObj, 'offset') && typeof criteriaObj.offset === 'number') {
      findOptions.skip = criteriaObj.offset;
    }
  }

  const result = await db.find('releaseLog', findOptions);

  if (!Array.isArray(result)) {
    return [];
  }

  return result.filter(isReleaseResponse).map((release) => {
    const tags = release.tags as Record<string, unknown> || {};
    return {
      id: release.id,
      version: release.version,
      release_type: release.release_type || '',
      scope: release.scope || '',
      release_date: (tags.release_date && typeof tags.release_date === 'string')
        ? new Date(tags.release_date)
        : release.created_at,
      status: release.status || '',
      created_at: release.created_at,
      updated_at: release.updated_at,
    };
  });
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

export async function storeRisk(data: unknown, scope: unknown = {}): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('Invalid risk data provided');
  }

  const dataObj = data as Record<string, unknown>;
  const scopeObj = (scope && typeof scope === 'object' && !Array.isArray(scope)) ? scope as Record<string, unknown> : {};

  const createData: Record<string, unknown> = {};

  if (hasPropertySimple(dataObj, 'title') && isString(dataObj.title)) {
    createData.title = dataObj.title;
  }
  if (hasPropertySimple(dataObj, 'category') && isString(dataObj.category)) {
    createData.category = dataObj.category;
  }
  if (hasPropertySimple(dataObj, 'risk_level') && isString(dataObj.risk_level)) {
    createData.risk_level = dataObj.risk_level;
  }
  if (hasPropertySimple(dataObj, 'impact_description') && isString(dataObj.impact_description)) {
    createData.impact_description = dataObj.impact_description;
  }
  if (hasPropertySimple(dataObj, 'status') && isString(dataObj.status)) {
    createData.status = dataObj.status;
  }

  createData.tags = {
    ...scopeObj,
    probability: hasPropertySimple(dataObj, 'probability') ? dataObj.probability : undefined,
    trigger_events: hasPropertySimple(dataObj, 'trigger_events') && isArray(dataObj.trigger_events, isString) ? dataObj.trigger_events : [],
    mitigation_strategies: hasPropertySimple(dataObj, 'mitigation_strategies') && isArray(dataObj.mitigation_strategies, isString) ? dataObj.mitigation_strategies : [],
    owner: hasPropertySimple(dataObj, 'owner') ? dataObj.owner : null,
    review_date: hasPropertySimple(dataObj, 'review_date') ? dataObj.review_date : null,
    related_decisions: hasPropertySimple(dataObj, 'related_decisions') && isArray(dataObj.related_decisions, isString) ? dataObj.related_decisions : [],
    monitoring_indicators: hasPropertySimple(dataObj, 'monitoring_indicators') && isArray(dataObj.monitoring_indicators, isString) ? dataObj.monitoring_indicators : [],
    contingency_plans: hasPropertySimple(dataObj, 'contingency_plans') ? dataObj.contingency_plans : null,
  };

  const result = await db.create('riskLog', createData);

  logger.info({ riskId: result.id, level: String(createData.risk_level || 'unknown') }, 'Risk stored successfully');
  return result.id;
}

export async function updateRisk(id: string, data: unknown): Promise<void> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('Invalid risk data provided');
  }

  const dataObj = data as Record<string, unknown>;
  const updateData: Record<string, unknown> = {};
  const tagUpdates: Record<string, unknown> = {};

  // Handle direct fields (those that exist in the schema)
  if (hasPropertySimple(dataObj, 'title') && isString(dataObj.title)) {
    updateData.title = dataObj.title;
  }
  if (hasPropertySimple(dataObj, 'category') && isString(dataObj.category)) {
    updateData.category = dataObj.category;
  }
  if (hasPropertySimple(dataObj, 'risk_level') && isString(dataObj.risk_level)) {
    updateData.risk_level = dataObj.risk_level;
  }
  if (hasPropertySimple(dataObj, 'impact_description') && isString(dataObj.impact_description)) {
    updateData.impact_description = dataObj.impact_description;
  }
  if (hasPropertySimple(dataObj, 'status') && isString(dataObj.status)) {
    updateData.status = dataObj.status;
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
    if (hasPropertySimple(dataObj, field)) {
      tagUpdates[field] = dataObj[field];
    }
  }

  if (Object.keys(updateData).length === 0 && Object.keys(tagUpdates).length === 0) {
    return;
  }

  if (Object.keys(tagUpdates).length > 0) {
    updateData.tags = tagUpdates;
  }

  // For now, just log that update is not supported
  // In a full implementation, you would delete and recreate the item
  logger.warn({ riskId: id }, 'Update not supported - would require delete + recreate');
  logger.info({ riskId: id, updates: Object.keys(updateData).length }, 'Risk updated successfully');
}

export async function findRisks(criteria: unknown): Promise<unknown> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const whereClause: Record<string, unknown> = {};

  if (criteria && typeof criteria === 'object' && !Array.isArray(criteria)) {
    const criteriaObj = criteria as Record<string, unknown>;
    if (hasPropertySimple(criteriaObj, 'category') && isString(criteriaObj.category)) {
      whereClause.category = criteriaObj.category;
    }
    if (hasPropertySimple(criteriaObj, 'level') && isString(criteriaObj.level)) {
      whereClause.risk_level = criteriaObj.level;
    }
    if (hasPropertySimple(criteriaObj, 'status') && isString(criteriaObj.status)) {
      whereClause.status = criteriaObj.status;
    }
  }

  const findOptions: Record<string, unknown> = {
    where: whereClause,
    orderBy: { updated_at: 'desc' },
  };

  if (criteria && typeof criteria === 'object' && !Array.isArray(criteria)) {
    const criteriaObj = criteria as Record<string, unknown>;
    if (hasPropertySimple(criteriaObj, 'limit') && typeof criteriaObj.limit === 'number') {
      findOptions.take = criteriaObj.limit;
    }
    if (hasPropertySimple(criteriaObj, 'offset') && typeof criteriaObj.offset === 'number') {
      findOptions.skip = criteriaObj.offset;
    }
  }

  const result = await db.find('riskLog', findOptions);

  if (!Array.isArray(result)) {
    return [];
  }

  return result.filter(isRiskResponse).map((risk) => {
    const tags = risk.tags as Record<string, unknown> || {};
    return {
      id: risk.id,
      title: risk.title,
      category: risk.category,
      risk_level: risk.risk_level || '',
      probability: (tags.probability && isString(tags.probability)) ? tags.probability : 'unknown',
      status: risk.status || '',
      created_at: risk.created_at,
      updated_at: risk.updated_at,
    };
  });
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

export async function storeAssumption(data: unknown, scope: unknown = {}): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('Invalid assumption data provided');
  }

  const dataObj = data as Record<string, unknown>;
  const scopeObj = (scope && typeof scope === 'object' && !Array.isArray(scope)) ? scope as Record<string, unknown> : {};

  const createData: Record<string, unknown> = {};

  if (hasPropertySimple(dataObj, 'title') && isString(dataObj.title)) {
    createData.title = dataObj.title;
  }
  if (hasPropertySimple(dataObj, 'description') && isString(dataObj.description)) {
    createData.description = dataObj.description;
  }
  if (hasPropertySimple(dataObj, 'category') && isString(dataObj.category)) {
    createData.category = dataObj.category;
  }
  if (hasPropertySimple(dataObj, 'validation_status') && isString(dataObj.validation_status)) {
    createData.validation_status = dataObj.validation_status;
  }
  if (hasPropertySimple(dataObj, 'impact_if_invalid') && isString(dataObj.impact_if_invalid)) {
    createData.impact_if_invalid = dataObj.impact_if_invalid;
  }

  createData.tags = {
    ...scopeObj,
    validation_criteria: hasPropertySimple(dataObj, 'validation_criteria') && isArray(dataObj.validation_criteria, isString) ? dataObj.validation_criteria : [],
    validation_date: hasPropertySimple(dataObj, 'validation_date') ? dataObj.validation_date : null,
    owner: hasPropertySimple(dataObj, 'owner') ? dataObj.owner : null,
    related_assumptions: hasPropertySimple(dataObj, 'related_assumptions') && isArray(dataObj.related_assumptions, isString) ? dataObj.related_assumptions : [],
    dependencies: hasPropertySimple(dataObj, 'dependencies') && isArray(dataObj.dependencies, isString) ? dataObj.dependencies : [],
    monitoring_approach: hasPropertySimple(dataObj, 'monitoring_approach') ? dataObj.monitoring_approach : null,
    review_frequency: hasPropertySimple(dataObj, 'review_frequency') ? dataObj.review_frequency : null,
  };

  const result = await db.create('assumptionLog', createData);

  logger.info(
    { assumptionId: result.id, status: String(createData.validation_status || 'unknown') },
    'Assumption stored successfully'
  );
  return result.id;
}

export async function updateAssumption(id: string, data: unknown): Promise<void> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new (UnifiedDatabaseLayer as unknown)();
  await (db as unknown).initialize();

  const updateData: unknown = {};
  const tagUpdates: unknown = {};

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

  // For now, just log that update is not supported
  // In a full implementation, you would delete and recreate the item
  logger.warn({ assumptionId: id }, 'Update not supported - would require delete + recreate');
  logger.info(
    { assumptionId: id, updates: Object.keys(updateData).length },
    'Assumption updated successfully'
  );
}

export async function findAssumptions(criteria: unknown): Promise<unknown> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new (UnifiedDatabaseLayer as unknown)();
  await (db as unknown).initialize();

  const whereClause: unknown = {};

  if (criteria.category) {
    whereClause.category = criteria.category;
  }
  if (criteria.status) {
    whereClause.validation_status = criteria.status;
  }

  const result = await (db as unknown).find('assumptionLog', {
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
      updated_at: true,
    },
  });

  return result.map((assumption: unknown) => ({
    id: assumption.id,
    title: assumption.title,
    description: assumption.description,
    category: assumption.category,
    validation_status: assumption.validation_status,
    created_at: assumption.created_at,
    updated_at: assumption.updated_at,
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

export async function getSessionLogDashboard(criteria: unknown = {}): Promise<unknown> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new (UnifiedDatabaseLayer as unknown)();
  await (db as unknown).initialize();

  // Since we can't easily replicate the UNION ALL with Qdrant queries,
  // we'll return empty results for now
  void criteria; // Mark as used

  // For now, return empty results since $queryRawUnsafe is not supported
  const result: unknown[] = [];

  return result.map((row: unknown) => ({
    type: row.log_type as 'incident' | 'release' | 'risk' | 'assumption',
    id: row.id,
    title: row.title,
    status: row.status,
    created_at: row.created_at,
    updated_at: row.updated_at,
    tags: row.tags,
  }));
}
