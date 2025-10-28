// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import type { DecisionData, ScopeFilter } from '../../types/knowledge-data';
import { validateADRImmutability } from '../../utils/immutability';

export async function storeDecision(data: DecisionData, scope: ScopeFilter): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const result = await db.create('adr_decision', {
    component: data.component,
    status: data.status,
    title: data.title,
    rationale: data.rationale,
    alternatives_considered: (data.alternatives_considered as string[]) || [],
    tags: scope,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });
  return result.id;
}

/**
 * Update existing ADR with immutability checks
 *
 * @throws ImmutabilityViolationError if ADR status is 'accepted'
 */
export async function updateDecision(id: string, data: Partial<DecisionData>): Promise<void> {
  const { getQdrantClient } = await import('../../db/qdrant-client');
  const qdrant = getQdrantClient();
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

  await qdrant.adrDecision.update({
    where: { id },
    data: updateData,
  });
}
