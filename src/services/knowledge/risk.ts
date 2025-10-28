// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import type { RiskData, ScopeFilter } from '../../types/knowledge-data';

export async function storeRisk(data: RiskData, scope: ScopeFilter): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const result = await db.create('riskLog', {
    data: {
      title: data.title,
      category: data.category || 'general',
      impact_description: data.description || data.impact || 'medium',
      probability: String(data.probability || 'possible'),
      risk_level: data.risk_level || 'medium',
      mitigation_strategies: data.mitigation ? [data.mitigation] : undefined,
      trigger_events: undefined,
      owner: (data as any).owner || data.risk_owner || undefined,
      review_date: (data as any).review_date || data.review_date || undefined,
      monitoring_indicators: undefined,
      contingency_plans: data.contingency_plan || undefined,
      tags: {
        ...scope,
        identified_date: data.identified_date,
        impact: data.impact,
      },
    },
  });

  return result.id;
}

export async function findRisks(
  query: string,
  scope?: ScopeFilter,
  limit: number = 50
): Promise<RiskData[]> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const risks = await db.find('riskLog', {
    where: {
      AND: [
        {
          OR: [
            { title: { contains: query, mode: 'insensitive' } },
            { impact_description: { contains: query, mode: 'insensitive' } },
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

  return risks.map((risk) => ({
    id: risk.id,
    title: risk.title,
    description: risk.impact_description,
    probability: (risk.probability as any) || 'possible',
    impact: risk.impact_description,
    risk_level: risk.risk_level,
    category: risk.category,
    mitigation:
      Array.isArray(risk.mitigation_strategies) && risk.mitigation_strategies.length > 0
        ? typeof risk.mitigation_strategies[0] === 'string'
          ? risk.mitigation_strategies[0]
          : JSON.stringify(risk.mitigation_strategies[0])
        : undefined,
    contingency_plan: risk.contingency_plans || undefined,
    risk_owner: risk.owner || undefined,
    review_date: risk.review_date || undefined,
    identified_date: (risk.tags as any)?.identified_date,
    created_at: risk.created_at,
    updated_at: risk.updated_at,
  }));
}

export async function updateRisk(
  id: string,
  data: Partial<RiskData>,
  scope: ScopeFilter
): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const existing = await qdrant.riskLog.findUnique({
    where: { id },
  });

  if (!existing) {
    throw new Error(`Risk with id ${id} not found`);
  }

  const result = await db.update(
    'riskLog',
    { id },
    {
      title: data.title ?? existing.title,
      category: data.category ?? existing.category,
      impact_description: data.description ?? data.impact ?? existing.impact_description,
      probability: data.probability ? String(data.probability) : existing.probability,
      risk_level: data.risk_level ?? existing.risk_level,
      mitigation_strategies: data.mitigation
        ? [data.mitigation]
        : existing.mitigation_strategies || undefined,
      trigger_events: existing.trigger_events as any,
      owner: (data as any).owner ?? data.risk_owner ?? existing.owner,
      review_date: (data as any).review_date ?? data.review_date ?? existing.review_date,
      monitoring_indicators: existing.monitoring_indicators as any,
      contingency_plans: (data.contingency_plan ?? existing.contingency_plans) || undefined,
      tags: {
        ...((existing.tags as any) || {}),
        ...scope,
        identified_date: data.identified_date ?? (existing.tags as any)?.identified_date,
        impact: data.impact ?? (existing.tags as any)?.impact,
      },
    }
  );

  return result.id;
}
