import { getPrismaClient } from '../../db/prisma.js';
import type { DecisionData, ScopeFilter } from '../../types/knowledge-data.js';
import { validateADRImmutability } from '../../utils/immutability.js';

export async function storeDecision(
  data: DecisionData,
  scope: ScopeFilter
): Promise<string> {
  const prisma = getPrismaClient();
  const result = await prisma.adrDecision.create({
    data: {
      component: data.component,
      status: data.status,
      title: data.title,
      rationale: data.rationale,
      alternativesConsidered: (data.alternatives_considered as string[]) || [],
      tags: scope
    }
  });
  return result.id;
}

/**
 * Update existing ADR with immutability checks
 *
 * @throws ImmutabilityViolationError if ADR status is 'accepted'
 */
export async function updateDecision(
  id: string,
  data: Partial<DecisionData>
): Promise<void> {
  const prisma = getPrismaClient();
  // Check immutability before allowing update
  await validateADRImmutability(id);

  const updateData: any = {};

  if (data.component !== undefined) {
    updateData.component = data.component;
  }
  if (data.status !== undefined) {
    updateData.status = data.status;
  }
  if (data.title !== undefined) {
    updateData.title = data.title;
  }
  if (data.rationale !== undefined) {
    updateData.rationale = data.rationale;
  }
  if (data.alternatives_considered !== undefined) {
    updateData.alternativesConsidered = (data.alternatives_considered as string[]) || [];
  }

  if (Object.keys(updateData).length === 0) {
    return; // No updates to perform
  }

  await prisma.adrDecision.update({
    where: { id },
    data: updateData
  });
}
