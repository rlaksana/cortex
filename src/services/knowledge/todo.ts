// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import type { TodoData, ScopeFilter } from '../../types/knowledge-data.js';

export async function storeTodo(data: TodoData, scope: ScopeFilter): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
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
  data: Partial<TodoData>,
  scope: ScopeFilter
): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const existing = await db.find('todoLog', {
    where: { id },
  });

  if (!existing) {
    throw new Error(`Todo with id ${id} not found`);
  }

  // FIXED: Update existing todo using direct field access
  const result = await db.update(
    'todoLog',
    { id },
    {
      title: data.text || data.todo_type || existing.title,
      description: data.text ?? existing.description,
      status: data.status ?? existing.status,
      priority: data.priority ?? existing.priority,
      due_date: data.due_date ? new Date(data.due_date) : existing.due_date,
      todo_type: data.todo_type ?? existing.todo_type,
      text: data.text ?? existing.text,
      assignee: data.assignee ?? existing.assignee,
      tags: {
        ...((existing.tags as any) || {}),
        ...scope,
      },
    }
  );

  return result.id;
}
