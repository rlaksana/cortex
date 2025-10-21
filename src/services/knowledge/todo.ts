import { getPrismaClient } from '../../db/prisma.js';
import type { TodoData, ScopeFilter } from '../../types/knowledge-data.js';

export async function storeTodo(data: TodoData, scope: ScopeFilter): Promise<string> {
  const prisma = getPrismaClient();

  // FIXED: Use direct field access for new fields instead of tags workaround
  const result = await prisma.todoLog.create({
    data: {
      title: data.text || data.todo_type || 'Untitled Todo',
      description: data.text,
      status: data.status,
      priority: data.priority,
      due_date: data.due_date ? new Date(data.due_date) : null,
      todo_type: data.todo_type || null,
      text: data.text || null,
      assignee: data.assignee || null,
      tags: scope || {}
    }
  });

  return result.id;
}

export async function updateTodo(
  id: string,
  data: Partial<TodoData>,
  scope: ScopeFilter
): Promise<string> {
  const prisma = getPrismaClient();

  const existing = await prisma.todoLog.findUnique({
    where: { id }
  });

  if (!existing) {
    throw new Error(`Todo with id ${id} not found`);
  }

  // FIXED: Update existing todo using direct field access
  const result = await prisma.todoLog.update({
    where: { id },
    data: {
      title: data.text || data.todo_type || existing.title,
      description: data.text ?? existing.description,
      status: data.status ?? existing.status,
      priority: data.priority ?? existing.priority,
      due_date: data.due_date ? new Date(data.due_date) : existing.due_date,
      todo_type: data.todo_type ?? existing.todo_type,
      text: data.text ?? existing.text,
      assignee: data.assignee ?? existing.assignee,
      tags: {
        ...(existing.tags as any || {}),
        ...scope
      }
    }
  });

  return result.id;
}
