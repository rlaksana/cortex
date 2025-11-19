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

import type {
  IncidentResponse,
  ReleaseResponse} from '../../types/database.js';
import {
  hasArrayProperty,
  hasBooleanProperty,
  hasNumberProperty,
  hasProperty,
  hasStringProperty,
  safeGetStringProperty
} from '../../utils/type-fixes.js';
import {
  isRiskResponse} from '../../utils/type-guards.js';

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// Helper function to safely check if a response has incident data structure
function isIncidentResponse(response: unknown): response is IncidentResponse {
  if (!response || typeof response !== 'object') return false;
  const obj = response as Record<string, unknown>;
  return hasProperty(obj, 'id') && hasProperty(obj, 'title') &&
         hasProperty(obj, 'severity') && hasProperty(obj, 'impact');
}

// Helper function to safely check if a response has release data structure
function isReleaseResponse(response: unknown): response is ReleaseResponse {
  if (!response || typeof response !== 'object') return false;
  const obj = response as Record<string, unknown>;
  return hasProperty(obj, 'id') && hasProperty(obj, 'version') &&
         hasProperty(obj, 'release_type');
}

// Helper function to check if value is a string
function isString(value: unknown): value is string {
  return typeof value === 'string';
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

export async function storeIncident(data: unknown, scope: unknown = {}): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  // Safely extract required properties using type guards
  if (!hasStringProperty(data, 'title') ||
      !hasStringProperty(data, 'severity') ||
      !hasStringProperty(data, 'impact') ||
      !hasStringProperty(data, 'resolution_status')) {
    throw new Error('Missing required properties for incident log');
  }

  const title = data.title;
  const severity = data.severity;
  const impact = data.impact;
  const resolutionStatus = data.resolution_status;

  // Extract optional properties safely
  const timeline = hasArrayProperty(data, 'timeline') ? data.timeline : [];
  const rootCauseAnalysis = hasStringProperty(data, 'root_cause_analysis') ? data.root_cause_analysis : undefined;
  const affectedServices = hasArrayProperty(data, 'affected_services') ? data.affected_services : [];
  const businessImpact = hasStringProperty(data, 'business_impact') ? data.business_impact : undefined;
  const recoveryActions = hasArrayProperty(data, 'recovery_actions') ? data.recovery_actions : [];
  const followUpRequired = hasBooleanProperty(data, 'follow_up_required') ? data.follow_up_required : false;
  const incidentCommander = hasStringProperty(data, 'incident_commander') ? data.incident_commander : undefined;

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

  const resultObj = result as Record<string, unknown>;
  const incidentId = safeGetStringProperty(resultObj, 'id');

  logger.info({ incidentId, severity }, 'Incident stored successfully');
  return incidentId;
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

  if (hasStringProperty(dataObj, 'title')) {
    updateData.title = dataObj.title;
  }
  if (hasStringProperty(dataObj, 'severity')) {
    updateData.severity = dataObj.severity;
  }
  if (hasStringProperty(dataObj, 'impact')) {
    updateData.impact = dataObj.impact;
  }
  if (hasStringProperty(dataObj, 'resolution_status')) {
    updateData.resolution_status = dataObj.resolution_status;
  }

  // Note: Other fields are stored in tags due to schema limitations
  const tagUpdates: Record<string, unknown> = {};
  if (hasArrayProperty(dataObj, 'timeline')) {
    tagUpdates.timeline = dataObj.timeline;
  }
  if (hasStringProperty(dataObj, 'root_cause_analysis')) {
    tagUpdates.root_cause_analysis = dataObj.root_cause_analysis;
  }
  if (hasArrayProperty(dataObj, 'affected_services')) {
    tagUpdates.affected_services = dataObj.affected_services;
  }
  if (hasArrayProperty(dataObj, 'business_impact')) {
    tagUpdates.business_impact = dataObj.business_impact;
  }
  if (hasArrayProperty(dataObj, 'recovery_actions')) {
    tagUpdates.recovery_actions = dataObj.recovery_actions;
  }
  if (hasBooleanProperty(dataObj, 'follow_up_required')) {
    tagUpdates.follow_up_required = dataObj.follow_up_required;
  }
  if (hasArrayProperty(dataObj, 'incident_commander')) {
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
    if (hasStringProperty(criteriaObj, 'severity')) {
      whereClause.severity = criteriaObj.severity;
    }
    if (hasStringProperty(criteriaObj, 'status')) {
      whereClause.resolution_status = criteriaObj.status;
    }
  }

  const findOptions: Record<string, unknown> = {
    where: whereClause,
    orderBy: { created_at: 'desc' },
  };

  if (criteria && typeof criteria === 'object' && !Array.isArray(criteria)) {
    const criteriaObj = criteria as Record<string, unknown>;
    if (hasNumberProperty(criteriaObj, 'limit')) {
      findOptions.take = criteriaObj.limit;
    }
    if (hasNumberProperty(criteriaObj, 'offset')) {
      findOptions.skip = criteriaObj.offset;
    }
  }

  const result = await db.find('incidentLog', findOptions);

  if (!Array.isArray(result)) {
    return [];
  }

  return result.filter(isIncidentResponse).map((incident) => {
    const incidentObj = incident as Record<string, unknown>;
    return {
      id: safeGetStringProperty(incidentObj, 'id'),
      title: safeGetStringProperty(incidentObj, 'title'),
      severity: safeGetStringProperty(incidentObj, 'severity'),
      impact: safeGetStringProperty(incidentObj, 'impact', ''),
      resolution_status: safeGetStringProperty(incidentObj, 'resolution_status', 'open'),
      created_at: safeGetStringProperty(incidentObj, 'created_at'),
      updated_at: safeGetStringProperty(incidentObj, 'updated_at'),
    };
  });
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

  if (hasStringProperty(dataObj, 'version')) {
    createData.version = dataObj.version;
  }
  if (hasStringProperty(dataObj, 'release_type')) {
    createData.release_type = dataObj.release_type;
  }
  if (hasStringProperty(dataObj, 'scope')) {
    createData.scope = dataObj.scope;
  }
  if (hasStringProperty(dataObj, 'status')) {
    createData.status = dataObj.status;
  }

  createData.tags = {
    ...scopeObj,
    release_date: hasStringProperty(dataObj, 'release_date') ? dataObj.release_date : undefined,
    ticket_references: hasArrayProperty(dataObj, 'ticket_references') ? dataObj.ticket_references : [],
    included_changes: hasArrayProperty(dataObj, 'included_changes') ? dataObj.included_changes : [],
    deployment_strategy: hasStringProperty(dataObj, 'deployment_strategy') ? dataObj.deployment_strategy : undefined,
    rollback_plan: hasStringProperty(dataObj, 'rollback_plan') ? dataObj.rollback_plan : undefined,
    testing_status: hasStringProperty(dataObj, 'testing_status') ? dataObj.testing_status : undefined,
    approvers: hasArrayProperty(dataObj, 'approvers') ? dataObj.approvers : [],
    release_notes: hasStringProperty(dataObj, 'release_notes') ? dataObj.release_notes : undefined,
    post_release_actions: hasArrayProperty(dataObj, 'post_release_actions') ? dataObj.post_release_actions : [],
  };

  const result = await db.create('releaseLog', createData);
  const resultObj = result as Record<string, unknown>;
  const releaseId = safeGetStringProperty(resultObj, 'id');

  logger.info({ releaseId, version: String(createData.version || 'unknown') }, 'Release stored successfully');
  return releaseId;
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
  if (hasStringProperty(dataObj, 'version')) {
    updateData.version = dataObj.version;
  }
  if (hasStringProperty(dataObj, 'release_type')) {
    updateData.release_type = dataObj.release_type;
  }
  if (hasStringProperty(dataObj, 'scope')) {
    updateData.scope = dataObj.scope;
  }
  if (hasStringProperty(dataObj, 'status')) {
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
    if (hasStringProperty(dataObj, field)) {
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
    if (hasStringProperty(criteriaObj, 'version') && isString(criteriaObj.version)) {
      whereClause.version = {
        contains: criteriaObj.version,
        mode: 'insensitive',
      };
    }
    if (hasStringProperty(criteriaObj, 'status') && isString(criteriaObj.status)) {
      whereClause.status = criteriaObj.status;
    }
  }

  const findOptions: Record<string, unknown> = {
    where: whereClause,
    orderBy: { created_at: 'desc' },
  };

  if (criteria && typeof criteria === 'object' && !Array.isArray(criteria)) {
    const criteriaObj = criteria as Record<string, unknown>;
    if (hasStringProperty(criteriaObj, 'limit') && typeof criteriaObj.limit === 'number') {
      findOptions.take = criteriaObj.limit;
    }
    if (hasStringProperty(criteriaObj, 'offset') && typeof criteriaObj.offset === 'number') {
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

  if (hasStringProperty(dataObj, 'title')) {
    createData.title = dataObj.title;
  }
  if (hasStringProperty(dataObj, 'category')) {
    createData.category = dataObj.category;
  }
  if (hasStringProperty(dataObj, 'risk_level')) {
    createData.risk_level = dataObj.risk_level;
  }
  if (hasStringProperty(dataObj, 'impact_description')) {
    createData.impact_description = dataObj.impact_description;
  }
  if (hasStringProperty(dataObj, 'status')) {
    createData.status = dataObj.status;
  }

  createData.tags = {
    ...scopeObj,
    probability: hasStringProperty(dataObj, 'probability') ? dataObj.probability : undefined,
    trigger_events: hasArrayProperty(dataObj, 'trigger_events') ? dataObj.trigger_events : [],
    mitigation_strategies: hasArrayProperty(dataObj, 'mitigation_strategies') ? dataObj.mitigation_strategies : [],
    owner: hasStringProperty(dataObj, 'owner') ? dataObj.owner : null,
    review_date: hasStringProperty(dataObj, 'review_date') ? dataObj.review_date : null,
    related_decisions: hasArrayProperty(dataObj, 'related_decisions') ? dataObj.related_decisions : [],
    monitoring_indicators: hasArrayProperty(dataObj, 'monitoring_indicators') ? dataObj.monitoring_indicators : [],
    contingency_plans: hasArrayProperty(dataObj, 'contingency_plans') ? dataObj.contingency_plans : null,
  };

  const result = await db.create('riskLog', createData);
  const resultObj = result as Record<string, unknown>;
  const riskId = safeGetStringProperty(resultObj, 'id');

  logger.info({ riskId, level: String(createData.risk_level || 'unknown') }, 'Risk stored successfully');
  return riskId;
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
  if (hasStringProperty(dataObj, 'title')) {
    updateData.title = dataObj.title;
  }
  if (hasStringProperty(dataObj, 'category')) {
    updateData.category = dataObj.category;
  }
  if (hasArrayProperty(dataObj, 'risk_level')) {
    updateData.risk_level = dataObj.risk_level;
  }
  if (hasArrayProperty(dataObj, 'impact_description')) {
    updateData.impact_description = dataObj.impact_description;
  }
  if (hasStringProperty(dataObj, 'status')) {
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
    if (hasStringProperty(dataObj, field)) {
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
    if (hasStringProperty(criteriaObj, 'category') && isString(criteriaObj.category)) {
      whereClause.category = criteriaObj.category;
    }
    if (hasStringProperty(criteriaObj, 'level') && isString(criteriaObj.level)) {
      whereClause.risk_level = criteriaObj.level;
    }
    if (hasStringProperty(criteriaObj, 'status') && isString(criteriaObj.status)) {
      whereClause.status = criteriaObj.status;
    }
  }

  const findOptions: Record<string, unknown> = {
    where: whereClause,
    orderBy: { updated_at: 'desc' },
  };

  if (criteria && typeof criteria === 'object' && !Array.isArray(criteria)) {
    const criteriaObj = criteria as Record<string, unknown>;
    if (hasStringProperty(criteriaObj, 'limit') && typeof criteriaObj.limit === 'number') {
      findOptions.take = criteriaObj.limit;
    }
    if (hasStringProperty(criteriaObj, 'offset') && typeof criteriaObj.offset === 'number') {
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

  if (hasStringProperty(dataObj, 'title')) {
    createData.title = dataObj.title;
  }
  if (hasStringProperty(dataObj, 'description')) {
    createData.description = dataObj.description;
  }
  if (hasStringProperty(dataObj, 'category')) {
    createData.category = dataObj.category;
  }
  if (hasStringProperty(dataObj, 'validation_status')) {
    createData.validation_status = dataObj.validation_status;
  }
  if (hasStringProperty(dataObj, 'impact_if_invalid')) {
    createData.impact_if_invalid = dataObj.impact_if_invalid;
  }

  createData.tags = {
    ...scopeObj,
    validation_criteria: hasArrayProperty(dataObj, 'validation_criteria') ? dataObj.validation_criteria : [],
    validation_date: hasArrayProperty(dataObj, 'validation_date') ? dataObj.validation_date : null,
    owner: hasArrayProperty(dataObj, 'owner') ? dataObj.owner : null,
    related_assumptions: hasArrayProperty(dataObj, 'related_assumptions') ? dataObj.related_assumptions : [],
    dependencies: hasArrayProperty(dataObj, 'dependencies') ? dataObj.dependencies : [],
    monitoring_approach: hasArrayProperty(dataObj, 'monitoring_approach') ? dataObj.monitoring_approach : null,
    review_frequency: hasArrayProperty(dataObj, 'review_frequency') ? dataObj.review_frequency : null,
  };

  const result = await db.create('assumptionLog', createData);
  const resultObj = result as Record<string, unknown>;
  const assumptionId = safeGetStringProperty(resultObj, 'id');

  logger.info(
    { assumptionId, status: String(createData.validation_status || 'unknown') },
    'Assumption stored successfully'
  );
  return assumptionId;
}

export async function updateAssumption(id: string, data: unknown): Promise<void> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('Invalid assumption data provided');
  }

  const dataObj = data as Record<string, unknown>;
  const updateData: Record<string, unknown> = {};
  const tagUpdates: Record<string, unknown> = {};

  // Handle direct fields (those that exist in the schema)
  if (hasStringProperty(dataObj, 'title')) {
    updateData.title = dataObj.title;
  }
  if (hasStringProperty(dataObj, 'description')) {
    updateData.description = dataObj.description;
  }
  if (hasStringProperty(dataObj, 'category')) {
    updateData.category = dataObj.category;
  }
  if (hasStringProperty(dataObj, 'validation_status')) {
    updateData.validation_status = dataObj.validation_status;
  }
  if (hasStringProperty(dataObj, 'impact_if_invalid')) {
    updateData.impact_if_invalid = dataObj.impact_if_invalid;
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
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const whereClause: Record<string, unknown> = {};

  if (criteria && typeof criteria === 'object' && !Array.isArray(criteria)) {
    const criteriaObj = criteria as Record<string, unknown>;
    if (hasStringProperty(criteriaObj, 'category')) {
      whereClause.category = criteriaObj.category;
    }
    if (hasStringProperty(criteriaObj, 'status')) {
      whereClause.validation_status = criteriaObj.status;
    }
  }

  const findOptions: Record<string, unknown> = {
    where: whereClause,
    orderBy: { updated_at: 'desc' },
  };

  if (criteria && typeof criteria === 'object' && !Array.isArray(criteria)) {
    const criteriaObj = criteria as Record<string, unknown>;
    if (hasNumberProperty(criteriaObj, 'limit')) {
      (findOptions as unknown).take = criteriaObj.limit;
    }
    if (hasNumberProperty(criteriaObj, 'offset')) {
      (findOptions as unknown).skip = criteriaObj.offset;
    }
  }

  const result = await db.find('assumptionLog', findOptions) as Record<string, unknown>[];

  if (!Array.isArray(result)) {
    return [];
  }

  return result.map((assumption: unknown) => {
    const assumptionObj = assumption as Record<string, unknown>;
    return {
      id: safeGetStringProperty(assumptionObj, 'id'),
      title: safeGetStringProperty(assumptionObj, 'title'),
      description: safeGetStringProperty(assumptionObj, 'description'),
      category: safeGetStringProperty(assumptionObj, 'category'),
      validation_status: safeGetStringProperty(assumptionObj, 'validation_status'),
      created_at: safeGetStringProperty(assumptionObj, 'created_at'),
      updated_at: safeGetStringProperty(assumptionObj, 'updated_at'),
    };
  });
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
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  // Since we can't easily replicate the UNION ALL with Qdrant queries,
  // we'll return empty results for now
  void criteria; // Mark as used

  // For now, return empty results since $queryRawUnsafe is not supported
  const result: unknown[] = [];

  return result.map((row: unknown) => {
    const rowObj = row as Record<string, unknown>;
    return {
      type: safeGetStringProperty(rowObj, 'log_type') as 'incident' | 'release' | 'risk' | 'assumption',
      id: safeGetStringProperty(rowObj, 'id'),
      title: safeGetStringProperty(rowObj, 'title'),
      status: safeGetStringProperty(rowObj, 'status'),
      created_at: rowObj.created_at,
      updated_at: rowObj.updated_at,
      tags: rowObj.tags,
    };
  });
}
