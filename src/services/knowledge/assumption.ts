// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import type { AssumptionData, ScopeFilter } from '../../types/knowledge-data.js';

export async function storeAssumption(data: AssumptionData, scope: ScopeFilter): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const result = await db.create('assumptionLog', {
    category: data.category || 'general',
    title: data.title,
    description: data.description || '',
    validation_status: data.validation_status || 'assumed',
    impact_if_invalid: data.impact_if_invalid || 'unknown',
    validation_criteria: data.validation_method ? [data.validation_method] : undefined,
    validation_date: (data as any).validation_date || data.validation_date || null,
    owner: (data as any).owner || data.owner || undefined,
    related_assumptions: undefined,
    monitoring_approach: data.validation_method || (undefined as any),
    review_frequency: (data as any).review_frequency || (undefined as any),
    tags: {
      ...scope,
      dependencies: data.dependencies ? JSON.stringify(data.dependencies) : undefined,
      expiry_date: data.expiry_date,
    },
  });

  return result.id || '';
}

export async function findAssumptions(
  query: string,
  scope?: ScopeFilter,
  limit: number = 50
): Promise<AssumptionData[]> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const assumptions = await db.find('assumptionLog', {
    where: {
      AND: [
        {
          OR: [
            { title: { contains: query, mode: 'insensitive' } },
            { description: { contains: query, mode: 'insensitive' } },
            { category: { contains: query, mode: 'insensitive' } },
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

  return assumptions.map((assumption) => {
    const result: AssumptionData = {
      id: assumption.id,
      title: assumption.title,
      description: assumption.description,
      category: assumption.category,
      validation_status: assumption.validation_status,
      impact_if_invalid: assumption.impact_if_invalid,
      validation_date: assumption.validation_date || undefined,
      owner: assumption.owner || undefined,
      dependencies: assumption.dependencies ?? undefined,
      expiry_date: (assumption.tags as any)?.expiry_date,
      created_at: assumption.created_at,
      updated_at: assumption.updated_at,
    };

    const validationMethod =
      Array.isArray(assumption.validation_criteria) && assumption.validation_criteria.length > 0
        ? String(assumption.validation_criteria[0])
        : undefined;

    if (validationMethod) {
      result.validation_method = validationMethod;
    }

    return result;
  });
}

export async function updateAssumption(
  id: string,
  data: Partial<AssumptionData>,
  scope: ScopeFilter
): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const existing = await db.findById([id]);

  if (!existing.items.length) {
    throw new Error(`Assumption with id ${id} not found`);
  }

  // Delete the old item and store a new one
  await db.delete([id]);

  const existingItem = existing.results[0];

  const result = await db.store([
    {
      kind: 'assumption',
      content: `${data.title ?? existingItem.data.title} - ${data.description ?? existingItem.data.description}`,
      data: {
        id,
        title: data.title ?? existingItem.data.title,
        category: data.category ?? existingItem.data.category,
        description: data.description ?? existingItem.data.description,
        validation_status: data.validation_status ?? existingItem.data.validation_status,
        impact_if_invalid: data.impact_if_invalid ?? existingItem.data.impact_if_invalid,
        validation_method: data.validation_method ?? existingItem.data.validation_method,
        validation_date: data.validation_date ?? existingItem.data.validation_date,
        owner: data.owner ?? existingItem.data.owner,
        dependencies: data.dependencies ?? existingItem.data.dependencies,
        expiry_date: data.expiry_date ?? existingItem.data.expiry_date,
      },
      scope: {
        ...existingItem.scope,
        ...scope,
      },
    },
  ]);

  return result.id || '';
}
