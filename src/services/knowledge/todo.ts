import { Pool } from 'pg';
import type { TodoData, ScopeFilter } from '../../types/knowledge-data.js';

export async function storeTodo(pool: Pool, data: TodoData, scope: ScopeFilter): Promise<string> {
  const result = await pool.query<{ id: string }>(
    `INSERT INTO todo_log (scope, todo_type, text, status, priority, assignee, due_date, tags)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
    [
      JSON.stringify(scope),
      data.todo_type,
      data.text,
      data.status,
      data.priority,
      data.assignee,
      data.due_date,
      JSON.stringify({}),
    ]
  );
  return result.rows[0].id;
}
