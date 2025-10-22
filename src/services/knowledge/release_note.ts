import { getPrismaClient } from '../../db/prisma.js';
import type { ReleaseNoteData, ScopeFilter } from '../../types/knowledge-data.js';

export async function storeReleaseNote(
  data: ReleaseNoteData,
  scope: ScopeFilter
): Promise<string> {
  const prisma = getPrismaClient();

  // Check if this is an update operation (has ID)
  if (data.id) {
    const existing = await prisma.releaseNote.findUnique({
      where: { id: data.id }
    });

    if (existing) {
      // Update existing release note
      const result = await prisma.releaseNote.update({
        where: { id: data.id },
        data: {
          version: data.version ?? existing.version,
          summary: data.summary ?? existing.summary,
          tags: {
            ...(existing.tags as any || {}),
            ...scope,
            release_date: data.release_date ?? (existing.tags as any)?.release_date,
            breaking_changes: data.breaking_changes ?? (existing.tags as any)?.breaking_changes,
            new_features: data.new_features ?? (existing.tags as any)?.new_features,
            bug_fixes: data.bug_fixes ?? (existing.tags as any)?.bug_fixes,
            deprecations: data.deprecations ?? (existing.tags as any)?.deprecations
          }
        }
      });
      return result.id;
    }
  }

  // Create new release note
  const result = await prisma.releaseNote.create({
    data: {
      version: data.version,
      summary: data.summary,
      tags: {
        ...scope,
        release_date: data.release_date,
        breaking_changes: JSON.stringify(data.breaking_changes || []),
        new_features: JSON.stringify(data.new_features || []),
        bug_fixes: JSON.stringify(data.bug_fixes || []),
        deprecations: JSON.stringify(data.deprecations || [])
      }
    }
  });

  return result.id;
}
