// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import type { ReleaseNoteData, ScopeFilter } from '../../types/knowledge-data';

export async function storeReleaseNote(data: ReleaseNoteData, scope: ScopeFilter): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  // Check if this is an update operation (has ID)
  if (data.id) {
    const existing = await db.find('releaseNote', {
      where: { id: data.id },
    });

    if (existing && Array.isArray(existing) && existing.length > 0) {
      // const existingItem = existing[0]; // Unused - removed to eliminate warning
      // Update existing release note - placeholder for future implementation
      // For now, just return the existing ID since update is not supported
      const result = { id: data.id };
      return result.id;
    }
  }

  // Create new release note
  const result = await db.create('releaseNote', {
    data: {
      version: data.version,
      summary: data.summary,
      tags: {
        ...scope,
        release_date: data.release_date,
        breaking_changes: JSON.stringify(data.breaking_changes || []),
        new_features: JSON.stringify(data.new_features || []),
        bug_fixes: JSON.stringify(data.bug_fixes || []),
        deprecations: JSON.stringify(data.deprecations || []),
      },
    },
  });

  return result.id;
}
