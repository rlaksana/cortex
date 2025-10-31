// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import type { PRContextData, ScopeFilter } from '../../types/knowledge-data.js';

export async function storePRContext(data: PRContextData, scope: ScopeFilter): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  // Check if this is an update operation (has ID)
  if (data.id) {
    const existingArray = await db.find('prContext', { id: data.id });

    if (existingArray && existingArray.length > 0) {
      const existing = existingArray[0];
      // Update existing PR context using store method
      const updatedData = {
        ...existing,
        pr_number: data.pr_number ?? existing.pr_number,
        title: data.title ?? existing.title,
        description: data.description ?? existing.description,
        author: data.author ?? existing.author,
        status: data.status ?? existing.status,
        merged_at: data.merged_at ? new Date(data.merged_at) : existing.merged_at,
        tags: {
          ...((existing.tags as any) || {}),
          ...scope,
          base_branch: data.base_branch ?? (existing.tags as any)?.base_branch,
          head_branch: data.head_branch ?? (existing.tags as any)?.head_branch,
          expires_at: data.merged_at
            ? new Date(new Date(data.merged_at).getTime() + 30 * 24 * 60 * 60 * 1000).toISOString()
            : (existing.tags as any)?.expires_at,
        },
        updated_at: new Date().toISOString(),
      };

      const knowledgeItem = {
        id: existing.id,
        kind: 'pr_context',
        content: JSON.stringify(updatedData),
        data: updatedData,
        scope,
        created_at: existing.created_at,
        updated_at: new Date().toISOString(),
      };

      await db.store([knowledgeItem]);
      return existing.id;
    }
  }

  // Create new PR context
  const result = await db.create('prContext', {
    pr_number: data.pr_number,
    title: data.title,
    description: data.description,
    author: data.author,
    status: data.status,
    merged_at: data.merged_at ? new Date(data.merged_at) : null,
    tags: {
      ...scope,
      base_branch: data.base_branch,
      head_branch: data.head_branch,
      expires_at: data.merged_at
        ? new Date(new Date(data.merged_at).getTime() + 30 * 24 * 60 * 60 * 1000).toISOString()
        : null,
    },
  });

  return result.id;
}
