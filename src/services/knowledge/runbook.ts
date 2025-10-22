import type { RunbookData, ScopeFilter } from '../../types/knowledge-data.js';
import { logger } from '../../utils/logger.js';
import { getPrismaClient } from '../../db/prisma.js';

export async function storeRunbook(
  data: RunbookData,
  scope: ScopeFilter
): Promise<string> {
  const prisma = getPrismaClient();

  // FIXED: Use direct field access for new fields instead of tags workaround
  const result = await prisma.runbook.create({
    data: {
      title: data.title || 'Untitled Runbook',
      description: data.description || null,
      steps: JSON.stringify(data.steps || []),
      service: data.service || null,
      triggers: JSON.stringify(data.triggers || []),
      last_verified_at: data.last_verified_at || null,
      tags: scope || {}
    }
  });

  logger.info(
    { runbookId: result.id, service: data.service },
    'Runbook stored successfully'
  );
  return result.id;
}

export async function updateRunbook(
  id: string,
  data: Partial<RunbookData>
): Promise<void> {
  const prisma = getPrismaClient();
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

  await prisma.runbook.update({
    where: { id },
    data: updateData
  });
  logger.info({ runbookId: id, updates: Object.keys(updateData).length }, 'Runbook updated successfully');
}

export async function findRunbooks(
  criteria: {
    service?: string;
    limit?: number;
    offset?: number;
  }
): Promise<
  Array<{
    id: string;
    title: string;
    description: string;
    steps: unknown;
    created_at: Date;
    updated_at: Date;
  }>
> {
  const prisma = getPrismaClient();

  const whereClause: any = {};

  if (criteria.service) {
    // FIXED: Use direct field access instead of tags
    whereClause.service = {
      contains: criteria.service,
      mode: 'insensitive'
    };
  }

  const result = await prisma.runbook.findMany({
    where: whereClause,
    orderBy: { updated_at: 'desc' },
    take: criteria.limit,
    skip: criteria.offset
  });

  return result.map(runbook => ({
    id: runbook.id,
    title: runbook.title,
    description: runbook.description || '',
    steps: runbook.steps,
    created_at: runbook.created_at,
    updated_at: runbook.updated_at
  }));
}
