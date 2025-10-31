// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import type { TodoData, ScopeFilter } from '../../types/knowledge-data.js';

export async function storeTodo(data: TodoData, scope: ScopeFilter): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  // FIXED: Use direct field access for new fields instead of tags workaround
  const result = await db.create('todoLog', {
    data: {
      title: data.text || data.todo_type || 'Untitled Todo',
      description: data.text,
      status: data.status,
      priority: data.priority,
      due_date: data.due_date ? new Date(data.due_date) : null,
      todo_type: data.todo_type || null,
      text: data.text || null,
      assignee: data.assignee || null,
      tags: scope || {},
    },
  });

  return result.id;
}

export async function updateTodo(
  id: string,
  _data: Partial<TodoData>,
  _scope: ScopeFilter
): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const existing = await db.find('todoLog', {
    where: { id },
  });

  if (!existing || !Array.isArray(existing) || existing.length === 0) {
    throw new Error(`Todo with id ${id} not found`);
  }

  // const existingItem = existing[0]; // Unused - removed to eliminate warning
  // For now, just return the existing ID since update is not supported
  // In a full implementation, you would delete and recreate the item
  const result = { id };

  return result.id;
}
