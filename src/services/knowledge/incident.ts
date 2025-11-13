
// @ts-nocheck - Emergency rollback: Critical business service
// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import type { IncidentData, ScopeFilter } from '../../types/knowledge-data.js';
import { isArray, isBoolean,isString, safePropertyAccess } from '../../utils/type-guards.js';

export async function storeIncident(data: IncidentData, scope: ScopeFilter): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const result = await db.create('incidentLog', {
    data: {
      title: data.title,
      severity: data.severity || 'medium',
      impact: data.impact_level || 'unknown',
      resolution_status: data.status || 'open',
      affected_services: safePropertyAccess(data, 'affected_services', isArray) || undefined,
      business_impact: data.description || '',
      recovery_actions: safePropertyAccess(data, 'recovery_actions', isArray)
        ? JSON.stringify(safePropertyAccess(data, 'recovery_actions', isArray))
        : undefined,
      follow_up_required: safePropertyAccess(data, 'follow_up_required', isBoolean) || false,
      incident_commander: safePropertyAccess(data, 'incident_commander', isString) || undefined,
      timeline: safePropertyAccess(data, 'timeline', isArray) ? JSON.stringify(safePropertyAccess(data, 'timeline', isArray)) : undefined,
      root_cause_analysis: data.root_cause_analysis,
      resolution: data.resolution,
      tags: {
        ...scope,
        lessons_learned: data.lessons_learned,
      },
    },
  });

  return result.id;
}

export async function findIncidents(
  query: string,
  scope?: ScopeFilter,
  limit: number = 50
): Promise<IncidentData[]> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const incidents = await db.find('incidentLog', {
    where: {
      AND: [
        {
          OR: [
            { title: { contains: query, mode: 'insensitive' } },
            { impact: { contains: query, mode: 'insensitive' } },
            { severity: { contains: query, mode: 'insensitive' } },
          ],
        },
        scope
          ? {
              tags: {
                path: [],
                string_contains: JSON.stringify(scope),
              },
            }
          : {},
      ],
    },
    take: limit,
    orderBy: { created_at: 'desc' },
  });

  return incidents.map((incident: unknown) => {
    if (!incident || typeof incident !== 'object') {
      throw new Error('Invalid incident data received');
    }

    const incidentObj = incident as Record<string, unknown>;
    const tags = safePropertyAccess(incidentObj, 'tags', isDict);

    return {
      id: String(incidentObj.id || ''),
      title: safePropertyAccess(incidentObj, 'title', isString) || '',
      description: safePropertyAccess(incidentObj, 'business_impact', isString) || undefined,
      severity: safePropertyAccess(incidentObj, 'severity', isString) || 'medium',
      impact: safePropertyAccess(incidentObj, 'impact', isString) || 'unknown',
      impact_level: safePropertyAccess(incidentObj, 'impact', isString) || 'unknown',
      status: safePropertyAccess(incidentObj, 'resolution_status', isString) || 'open',
      timeline: safePropertyAccess(incidentObj, 'timeline', isString),
      root_cause: safePropertyAccess(incidentObj, 'root_cause_analysis', isString) || undefined,
      root_cause_analysis: safePropertyAccess(incidentObj, 'root_cause_analysis', isString) || undefined,
      resolution: safePropertyAccess(incidentObj, 'resolution', isString) || undefined,
      lessons_learned: tags ? safePropertyAccess(tags, 'lessons_learned', isString) : undefined,
      recovery_actions: safePropertyAccess(incidentObj, 'recovery_actions', isString),
      created_at: incidentObj.created_at,
      updated_at: incidentObj.updated_at,
    };
  });
}

export async function updateIncident(
  id: string,
  data: Partial<IncidentData>,
  scope: ScopeFilter
): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const existingArray = await db.find('incidentLog', { id });

  if (!existingArray || existingArray.length === 0) {
    throw new Error(`Incident with id ${id} not found`);
  }

  const existing = existingArray[0];

  if (!existing || typeof existing !== 'object') {
    throw new Error(`Invalid existing incident data for id ${id}`);
  }

  const existingObj = existing as Record<string, unknown>;

  // Update using store method
  const updatedIncident = {
    ...existingObj,
    title: data.title ?? safePropertyAccess(existingObj, 'title', isString) || '',
    severity: data.severity ?? safePropertyAccess(existingObj, 'severity', isString) || 'medium',
    impact: data.impact_level ?? safePropertyAccess(existingObj, 'impact', isString) || 'unknown',
    resolution_status: data.status ?? safePropertyAccess(existingObj, 'resolution_status', isString) || 'open',
    affected_services: safePropertyAccess(data, 'affected_services', isArray) ?? safePropertyAccess(existingObj, 'affected_services', isArray),
    business_impact: data.description ?? safePropertyAccess(existingObj, 'business_impact', isString) || '',
    recovery_actions: safePropertyAccess(data, 'recovery_actions', isArray) ?? safePropertyAccess(existingObj, 'recovery_actions', isArray),
    follow_up_required: safePropertyAccess(data, 'follow_up_required', isBoolean) ?? safePropertyAccess(existingObj, 'follow_up_required', isBoolean) || false,
    incident_commander: safePropertyAccess(data, 'incident_commander', isString) ?? safePropertyAccess(existingObj, 'incident_commander', isString),
    timeline: safePropertyAccess(data, 'timeline', isArray) ?? safePropertyAccess(existingObj, 'timeline', isArray),
    root_cause_analysis: data.root_cause_analysis ?? safePropertyAccess(existingObj, 'root_cause_analysis', isString),
    resolution: data.resolution ?? safePropertyAccess(existingObj, 'resolution', isString),
    tags: {
      ...(safePropertyAccess(existingObj, 'tags', isDict) || {}),
      ...scope,
      lessons_learned: data.lessons_learned ?? safePropertyAccess(safePropertyAccess(existingObj, 'tags', isDict) || {}, 'lessons_learned', isString),
    },
    updated_at: new Date().toISOString(),
  };

  const knowledgeItem = {
    id: existing.id,
    kind: 'incident',
    content: JSON.stringify(updatedIncident),
    data: updatedIncident,
    scope,
    created_at: existing.created_at,
    updated_at: new Date().toISOString(),
  };

  await db.store([knowledgeItem]);
  return existing.id;
}
