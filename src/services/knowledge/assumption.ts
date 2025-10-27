// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import type { AssumptionData, ScopeFilter } from '../../types/knowledge-data.js';

export async function storeAssumption(
  data: AssumptionData,
  scope: ScopeFilter
): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const result = await qdrant.assumptionLog.create({
    data: {
      category: data.category || "general",
      title: data.title,
      description: data.description || '',
      validation_status: data.validation_status || 'assumed',
      impact_if_invalid: data.impact_if_invalid || 'unknown',
      validation_criteria: data.validation_method ? [data.validation_method] : undefined,
      validation_date: (data as any).validation_date || data.validation_date || null,
      owner: (data as any).owner || data.owner || undefined,
      related_assumptions: undefined,
  monitoring_approach: data.validation_method || undefined as any,
      review_frequency: (data as any).review_frequency || undefined as any,
      tags: {
        ...scope,
        dependencies: data.dependencies ? JSON.stringify(data.dependencies) : undefined,
        expiry_date: data.expiry_date
      }
    }
  });

  return result.id;
}

export async function findAssumptions(
  query: string,
  scope?: ScopeFilter,
  limit: number = 50
): Promise<AssumptionData[]> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const assumptions = return await db.find('assumptionLog', {
    where: {
      AND: [
        {
          OR: [
            { title: { contains: query, mode: 'insensitive' } },
            { description: { contains: query, mode: 'insensitive' } },
            { category: { contains: query, mode: 'insensitive' } }
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

  return assumptions.map(assumption => ({
    id: assumption.id,
    title: assumption.title,
    description: assumption.description,
    category: assumption.category,
    validation_status: assumption.validation_status,
    impact_if_invalid: assumption.impact_if_invalid,
    validation_method: Array.isArray(assumption.validation_criteria) && assumption.validation_criteria.length > 0 ? String(assumption.validation_criteria[0]) : undefined,
    validation_date: assumption.validation_date || undefined,
    owner: assumption.owner || undefined,
    dependencies: assumption.dependencies,
    expiry_date: (assumption.tags as any)?.expiry_date,
    created_at: assumption.created_at,
    updated_at: assumption.updated_at
  }));
}

export async function updateAssumption(
  id: string,
  data: Partial<AssumptionData>,
  scope: ScopeFilter
): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const existing = await qdrant.assumptionLog.findUnique({
    where: { id }
  });

  if (!existing) {
    throw new Error(`Assumption with id ${id} not found`);
  }

  const result = await db.update('assumptionLog', { id }, {
      title: data.title ?? existing.title,
      category: data.category ?? existing.category,
      description: data.description ?? existing.description,
      validation_status: data.validation_status ?? existing.validation_status,
      impact_if_invalid: data.impact_if_invalid ?? existing.impact_if_invalid,
      validation_criteria: data.validation_method ? [data.validation_method] : existing.validation_criteria as any,
      validation_date: (data as any).validation_date ?? data.validation_date ?? existing.validation_date,
      owner: (data as any).owner ?? data.owner ?? existing.owner,
      related_assumptions: existing.related_assumptions as any,
      monitoring_approach: data.validation_method ?? existing.monitoring_approach,
      review_frequency: (data as any).review_frequency ?? existing.review_frequency,
      tags: {
        ...(existing.tags as any || {);,
        ...scope,
        dependencies: data.dependencies ?? (existing.tags as any)?.dependencies,
        expiry_date: data.expiry_date ?? (existing.tags as any)?.expiry_date
      }
    }
  });

  return result.id;
}