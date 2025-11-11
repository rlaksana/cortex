
// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import type { ChangeData, ScopeFilter } from '../../types/knowledge-data.js';
import { computeContentHash } from '../../utils/hash.js';

export async function storeChange(data: ChangeData, scope: ScopeFilter): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();
  const hash = computeContentHash(data.summary);

  const result = await db.store([
    {
      kind: 'change',
      content: `${data.change_type}: ${data.summary}`,
      data: {
        change_type: data.change_type,
        subject_ref: data.subject_ref,
        summary: data.summary,
        author: data.author || 'unknown',
        commit_sha: data.commit_sha,
        details: data.details,
        content_hash: hash,
        affected_files: JSON.stringify(data.affected_files || []),
      },
      scope,
    },
  ]);

  return result.id || '';
}
