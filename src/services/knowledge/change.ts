// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import { computeContentHash } from '../../utils/hash.js';
import type { ChangeData, ScopeFilter } from '../../types/knowledge-data.js';

export async function storeChange(data: ChangeData, scope: ScopeFilter): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();
  const hash = computeContentHash(data.summary);

  const result = await qdrant.changeLog.create({
    data: {
      change_type: data.change_type,
      subject_ref: data.subject_ref,
      summary: data.summary,
      author: data.author || 'unknown',
      commit_sha: data.commit_sha,
      tags: {
        ...scope,
        details: data.details,
        content_hash: hash,
        affected_files: JSON.stringify(data.affected_files || []),
      },
    },
  });

  return result.id;
}
