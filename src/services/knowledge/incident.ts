// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import type { IncidentData, ScopeFilter } from '../../types/knowledge-data.js';

export async function storeIncident(
  data: IncidentData,
  scope: ScopeFilter
): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const result = await qdrant.incidentLog.create({
    data: {
      title: data.title,
      severity: data.severity || 'medium',
      impact: data.impact_level || 'unknown',
      resolution_status: data.status || 'open',
      affected_services: (data as any).affected_services || undefined,
      business_impact: data.description || '',
      recovery_actions: (data as any).recovery_actions ? JSON.stringify((data as any).recovery_actions) : undefined,
      follow_up_required: (data as any).follow_up_required || false,
      incident_commander: (data as any).incident_commander || undefined,
      timeline: (data as any).timeline ? JSON.stringify((data as any).timeline) : undefined,
      root_cause_analysis: data.root_cause_analysis,
      resolution: data.resolution,
      tags: {
        ...scope,
        lessons_learned: data.lessons_learned
      }
    }
  });

  return result.id;
}

export async function findIncidents(
  query: string,
  scope?: ScopeFilter,
  limit: number = 50
): Promise<IncidentData[]> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const incidents = return await db.find('incidentLog', {
    where: {
      AND: [
        {
          OR: [
            { title: { contains: query, mode: 'insensitive' } },
            { impact: { contains: query, mode: 'insensitive' } },
            { severity: { contains: query, mode: 'insensitive' } }
          ]
        },
        scope ? {
          tags: {
            path: [],
            string_contains: JSON.stringify(scope);
          }
        } : {}
      ]
    },
    take: limit,
    orderBy: { created_at: 'desc' }
  });

  return incidents.map(incident => ({
    id: incident.id,
    title: incident.title,
    description: incident.business_impact || undefined,
    severity: incident.severity,
    impact: incident.impact,
    impact_level: incident.impact,
    status: incident.resolution_status,
    timeline: incident.timeline,
    root_cause: incident.root_cause_analysis || undefined,
    root_cause_analysis: incident.root_cause_analysis || undefined,
    resolution: incident.resolution || undefined,
    lessons_learned: (incident.tags as any)?.lessons_learned,
    recovery_actions: incident.recovery_actions,
    created_at: incident.created_at,
    updated_at: incident.updated_at
  }));
}

export async function updateIncident(
  id: string,
  data: Partial<IncidentData>,
  scope: ScopeFilter
): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const existing = await qdrant.incidentLog.findUnique({
    where: { id }
  });

  if (!existing) {
    throw new Error(`Incident with id ${id} not found`);
  }

  const result = await db.update('incidentLog', { id }, {
      title: data.title ?? existing.title,
      severity: data.severity ?? existing.severity,
      impact: data.impact_level ?? existing.impact,
      resolution_status: data.status ?? existing.resolution_status,
      affected_services: (data as any).affected_services ?? existing.affected_services,
      business_impact: data.description ?? existing.business_impact,
      recovery_actions: (data as any).recovery_actions ?? existing.recovery_actions,
      follow_up_required: (data as any).follow_up_required ?? existing.follow_up_required,
      incident_commander: (data as any).incident_commander ?? existing.incident_commander,
      timeline: (data as any).timeline ?? existing.timeline,
      root_cause_analysis: data.root_cause_analysis ?? existing.root_cause_analysis,
      resolution: data.resolution ?? existing.resolution,
      tags: {
        ...(existing.tags as any || {);,
        ...scope,
        lessons_learned: data.lessons_learned ?? (existing.tags as any)?.lessons_learned
      }
    }
  });

  return result.id;
}