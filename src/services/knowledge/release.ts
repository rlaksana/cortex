// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import type { ReleaseData, ScopeFilter } from '../../types/knowledge-data.js';

export async function storeRelease(
  data: ReleaseData,
  scope: ScopeFilter
): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const result = await db.create('releaseLog', {
    data: {
      version: data.version,
      scope: data.description || '',
      status: data.status || 'planned',
      release_type: 'minor', // Default release type
      deployment_date: data.release_date ? new Date(data.release_date) : undefined,
      rollback_plan: data.rollback_plan,
      ticket_references: (data as any).ticket_references || undefined,
      included_changes: data.features ? JSON.stringify(data.features) : undefined,
      deployment_strategy: (data as any).deployment_strategy || undefined,
      testing_status: (data as any).testing_status || 'pending',
      approvers: (data as any).approvers || undefined,
      release_notes: data.release_notes ? JSON.stringify(data.release_notes) : undefined,
      post_release_actions: data.bug_fixes ? JSON.stringify(data.bug_fixes) : undefined,
      tags: {
        ...scope,
        title: data.title,
        breaking_changes: data.breaking_changes ? JSON.stringify(data.breaking_changes) : undefined
      }
    }
  });

  return result.id;
}

export async function findReleases(
  query: string,
  scope?: ScopeFilter,
  limit: number = 50
): Promise<ReleaseData[]> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const releases = await db.find('releaseLog', {
    where: {
      AND: [
        {
          OR: [
            { version: { contains: query, mode: 'insensitive' } },
            { scope: { contains: query, mode: 'insensitive' } }
          ]
        },
        scope ? {
          tags: {
            path: [],
            string_contains: JSON.stringify(scope)
          }
        } : {}
      ]
    },
    take: limit,
    orderBy: { created_at: 'desc' }
  });

  return releases.map(release => ({
    id: release.id,
    version: release.version,
    title: (release.tags as any)?.title,
    description: release.scope,
    status: release.status || undefined,
    deployment_strategy: release.deployment_strategy || undefined,
    release_date: release.deployment_date?.toISOString(),
    release_notes: release.release_notes ? JSON.parse(release.release_notes as string) : undefined,
    features: release.included_changes ? JSON.parse(release.included_changes as string) : undefined,
    bug_fixes: release.post_release_actions ? JSON.parse(release.post_release_actions as string) : undefined,
    breaking_changes: (release.tags as any)?.breaking_changes ? JSON.parse((release.tags as any)?.breaking_changes) : undefined,
    rollback_plan: release.rollback_plan || undefined,
    created_at: release.created_at || undefined,
    updated_at: release.updated_at || undefined
  }));
}

export async function updateRelease(
  id: string,
  data: Partial<ReleaseData>,
  scope: ScopeFilter
): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const existing = await db.find('releaseLog', {
    where: { id }
  });

  if (!existing) {
    throw new Error(`Release with id ${id} not found`);
  }

  const result = await db.update('releaseLog', { id: id }, {
      version: data.version ?? existing.version,
      scope: data.description ?? existing.scope,
      status: data.status ?? existing.status,
      release_type: 'minor'
    });

  return result.id;
}