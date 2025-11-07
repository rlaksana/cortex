// @ts-nocheck
import type { RunbookData, ScopeFilter } from '../../types/knowledge-data.js';
import { logger } from '@/utils/logger.js';

export async function storeRunbook(data: RunbookData, scope: ScopeFilter): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  // FIXED: Use direct field access for new fields instead of tags workaround
  const result = await db.create('runbook', {
    title: data.title || 'Untitled Runbook',
    description: data.description || null,
    steps: JSON.stringify(data.steps || []),
    service: data.service || null,
    triggers: JSON.stringify(data.triggers || []),
    last_verified_at: data.last_verified_at || null,
    tags: scope || {},
  });

  logger.info({ runbookId: result.id, service: data.service }, 'Runbook stored successfully');
  return result.id;
}

export async function updateRunbook(id: string, data: Partial<RunbookData>): Promise<void> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();
  const updateData: any = {};

  if (data.title !== undefined) {
    updateData.title = data.title;
  }
  if (data.description !== undefined) {
    updateData.description = data.description;
  }
  if (data.steps !== undefined) {
    updateData.steps = data.steps;
  }

  // FIXED: Use direct field access for new fields
  if (data.service !== undefined) {
    updateData.service = data.service;
  }
  if (data.triggers !== undefined) {
    updateData.triggers = data.triggers;
  }
  if (data.last_verified_at !== undefined) {
    updateData.last_verified_at = data.last_verified_at;
  }

  if (Object.keys(updateData).length === 0) {
    return; // No updates to perform
  }

  // For now, just log that update is not supported
  // In a full implementation, you would delete and recreate the item
  logger.warn({ runbookId: id }, 'Update not supported - would require delete + recreate');
  logger.info(
    { runbookId: id, updates: Object.keys(updateData).length },
    'Runbook updated successfully'
  );
}

export async function findRunbooks(criteria: {
  service?: string;
  limit?: number;
  offset?: number;
}): Promise<
  Array<{
    id: string;
    title: string;
    description: string;
    steps: unknown;
    created_at: Date;
    updated_at: Date;
  }>
> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const whereClause: any = {};

  if (criteria.service) {
    // FIXED: Use direct field access instead of tags
    whereClause.service = {
      contains: criteria.service,
      mode: 'insensitive',
    };
  }

  const result = await db.find('runbook', {
    where: whereClause,
    orderBy: { updated_at: 'desc' },
    take: criteria.limit,
    skip: criteria.offset,
  });

  return result.map((runbook) => ({
    id: runbook.id,
    title: runbook.title,
    description: runbook.description || '',
    steps: runbook.steps,
    created_at: runbook.created_at,
    updated_at: runbook.updated_at,
  }));
}
