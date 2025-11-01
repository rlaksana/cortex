/**
 * Comprehensive Unit Tests for Todo Knowledge Type
 *
 * Tests todo knowledge type functionality including:
 * - Task validation with all required fields
 * - Todo type constraints (task, bug, epic, story, spike)
 * - Status lifecycle and transitions
 * - Priority handling
 * - Assignment and due date validation
 * - Scope isolation for todos
 * - Error handling and edge cases
 * - Integration with task management workflows
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../../src/index';
import { TodoSchema, validateKnowledgeItem } from '../../../src/schemas/knowledge-types';

// Mock Qdrant client - reusing pattern from memory-store.test.ts
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor() {
      this.getCollections = vi.fn().mockResolvedValue({
        collections: [{ name: 'test-collection' }]
      });
      this.createCollection = vi.fn().mockResolvedValue(undefined);
      this.upsert = vi.fn().mockResolvedValue(undefined);
      this.search = vi.fn().mockResolvedValue([]);
      this.getCollection = vi.fn().mockResolvedValue({
        points_count: 0,
        status: 'green'
      });
      this.delete = vi.fn().mockResolvedValue({ status: 'completed' });
      this.count = vi.fn().mockResolvedValue({ count: 0 });
      this.healthCheck = vi.fn().mockResolvedValue(true);
    }
  }
}));

describe('Todo Knowledge Type - Comprehensive Testing', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    db = new VectorDatabase();
    mockQdrant = (db as any).client;
  });

  describe('Todo Schema Validation', () => {
    it('should validate complete todo with all fields', () => {
      const todo = {
        kind: 'todo' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          scope: 'task',
          todo_type: 'task',
          text: 'Implement user authentication system',
          status: 'in_progress',
          priority: 'high',
          assignee: 'developer-1',
          due_date: '2025-02-01T00:00:00Z',
          closed_at: undefined
        },
        tags: { frontend: true, security: true },
        source: {
          actor: 'project-manager',
          tool: 'task-tracker',
          timestamp: '2025-01-01T00:00:00Z'
        }
      };

      const result = TodoSchema.safeParse(todo);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.kind).toBe('todo');
        expect(result.data.data.todo_type).toBe('task');
        expect(result.data.data.status).toBe('in_progress');
        expect(result.data.data.priority).toBe('high');
        expect(result.data.data.assignee).toBe('developer-1');
      }
    });

    it('should validate minimal todo with only required fields', () => {
      const todo = {
        kind: 'todo' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          scope: 'epic',
          todo_type: 'story',
          text: 'Create user dashboard',
          status: 'open'
        }
      };

      const result = TodoSchema.safeParse(todo);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.scope).toBe('epic');
        expect(result.data.data.todo_type).toBe('story');
        expect(result.data.data.status).toBe('open');
        expect(result.data.data.priority).toBeUndefined();
        expect(result.data.data.assignee).toBeUndefined();
      }
    });

    it('should reject todo missing required fields', () => {
      const invalidTodos = [
        {
          kind: 'todo' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing scope
            todo_type: 'task',
            text: 'Test todo',
            status: 'open'
          }
        },
        {
          kind: 'todo' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            scope: 'task',
            // Missing todo_type
            text: 'Test todo',
            status: 'open'
          }
        },
        {
          kind: 'todo' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            scope: 'task',
            todo_type: 'task',
            // Missing text
            status: 'open'
          }
        },
        {
          kind: 'todo' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            scope: 'task',
            todo_type: 'task',
            text: 'Test todo'
            // Missing status
          }
        }
      ];

      invalidTodos.forEach((todo, index) => {
        const result = TodoSchema.safeParse(todo);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues.length).toBeGreaterThan(0);
        }
      });
    });

    it('should enforce valid todo_type values', () => {
      const todo = {
        kind: 'todo' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          scope: 'task',
          todo_type: 'invalid_type' as any, // Invalid todo type
          text: 'Test todo',
          status: 'open'
        }
      };

      const result = TodoSchema.safeParse(todo);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('Invalid enum value');
      }
    });

    it('should enforce valid status values', () => {
      const todo = {
        kind: 'todo' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          scope: 'task',
          todo_type: 'task',
          text: 'Test todo',
          status: 'invalid_status' as any // Invalid status
        }
      };

      const result = TodoSchema.safeParse(todo);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('Invalid enum value');
      }
    });

    it('should enforce scope length constraints', () => {
      const todo = {
        kind: 'todo' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          scope: 'x'.repeat(201), // Exceeds 200 character limit
          todo_type: 'task',
          text: 'Test todo',
          status: 'open'
        }
      };

      const result = TodoSchema.safeParse(todo);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('200 characters or less');
      }
    });
  });

  describe('Todo Storage Operations', () => {
    it('should store todo successfully using memory_store pattern', async () => {
      const todo = {
        kind: 'todo' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          scope: 'task',
          todo_type: 'bug',
          text: 'Fix login authentication issue',
          status: 'in_progress',
          priority: 'critical'
        },
      };

      const result = await db.storeItems([todo]);

      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(result.stored[0]).toHaveProperty('id');
      expect(result.stored[0].kind).toBe('todo');
      expect(result.stored[0].data.todo_type).toBe('bug');
      expect(result.stored[0].data.priority).toBe('critical');

      // Verify Qdrant client was called
      expect(mockQdrant.upsert).toHaveBeenCalled();
    });

    it('should handle batch todo storage successfully', async () => {
      const todos = Array.from({ length: 5 }, (_, i) => ({
        kind: 'todo' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          scope: 'task',
          todo_type: 'task',
          text: `Task ${i + 1}: Complete feature implementation`,
          status: i % 2 === 0 ? 'done' : 'open',
          priority: i % 3 === 0 ? 'high' : 'medium'
        },
      }));

      const result = await db.storeItems(todos);

      expect(result.stored).toHaveLength(5);
      expect(result.errors).toHaveLength(0);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(5);
    });

    it('should handle mixed valid and invalid todos in batch', async () => {
      const items = [
        {
          kind: 'todo' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            scope: 'task',
            todo_type: 'story',
            text: 'Valid todo item',
            status: 'open'
          },
        },
        {
          kind: 'todo' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            scope: 'task',
            todo_type: 'task',
            // Missing text
            status: 'open'
          },
        },
        {
          kind: 'todo' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            scope: 'epic',
            todo_type: 'epic',
            text: 'Another valid todo item',
            status: 'in_progress'
          },
        }
      ];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(2); // 2 valid todos
      expect(result.errors).toHaveLength(1); // 1 invalid todo
    });
  });

  describe('Todo Search Operations', () => {
    beforeEach(() => {
      // Setup search mock for todos
      mockQdrant.search.mockResolvedValue([
        {
          id: 'todo-id-1',
          score: 0.9,
          payload: {
            kind: 'todo',
            data: {
              scope: 'task',
              todo_type: 'bug',
              text: 'Fix authentication timeout issue',
              status: 'in_progress',
              priority: 'high'
            },
            scope: { project: 'test-project', branch: 'main' }
          }
        },
        {
          id: 'todo-id-2',
          score: 0.8,
          payload: {
            kind: 'todo',
            data: {
              scope: 'epic',
              todo_type: 'story',
              text: 'Implement user profile feature',
              status: 'open',
              priority: 'medium'
            },
            scope: { project: 'test-project', branch: 'main' }
          }
        }
      ]);
    });

    it('should find todos by query', async () => {
      const query = 'authentication fix bug';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].data.todo_type).toBe('bug');
      expect(result.items[0].data.text).toContain('authentication');
      expect(result.items[1].data.todo_type).toBe('story');
      expect(mockQdrant.search).toHaveBeenCalled();
    });

    it('should handle empty todo search results', async () => {
      mockQdrant.search.mockResolvedValue([]);

      const result = await db.searchItems('nonexistent todo');

      expect(result.items).toHaveLength(0);
      expect(result.total).toBe(0);
    });
  });

  describe('Todo Types and Statuses', () => {
    it('should handle all valid todo types', async () => {
      const todoTypes: Array<'task' | 'bug' | 'epic' | 'story' | 'spike'> = [
        'task', 'bug', 'epic', 'story', 'spike'
      ];

      for (const todoType of todoTypes) {
        const todo = {
          kind: 'todo' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            scope: 'task',
            todo_type: todoType,
            text: `Test ${todoType} item`,
            status: 'open'
          }
        };

        const result = TodoSchema.safeParse(todo);
        if (!result.success) {
          console.log('Validation error for todoType:', todoType, result.error);
        }
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.todo_type).toBe(todoType);
        }
      }
    });

    it('should handle all valid todo statuses', async () => {
      const statuses: Array<'open' | 'in_progress' | 'done' | 'cancelled' | 'archived'> = [
        'open', 'in_progress', 'done', 'cancelled', 'archived'
      ];

      for (const status of statuses) {
        const todo = {
          kind: 'todo' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            scope: 'task',
            todo_type: 'task',
            text: `Todo with status ${status}`,
            status
          }
        };

        const result = TodoSchema.safeParse(todo);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.status).toBe(status);
        }
      }
    });

    it('should handle all valid priority levels', async () => {
      const priorities: Array<'low' | 'medium' | 'high' | 'critical'> = [
        'low', 'medium', 'high', 'critical'
      ];

      for (const priority of priorities) {
        const todo = {
          kind: 'todo' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            scope: 'task',
            todo_type: 'task',
            text: `Todo with priority ${priority}`,
            status: 'open',
            priority
          }
        };

        const result = TodoSchema.safeParse(todo);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.priority).toBe(priority);
        }
      }
    });
  });

  describe('Todo Lifecycle Management', () => {
    it('should handle todo status transitions', async () => {
      const statusTransitions = [
        { from: 'open', to: 'in_progress' },
        { from: 'in_progress', to: 'done' },
        { from: 'in_progress', to: 'cancelled' },
        { from: 'done', to: 'archived' },
        { from: 'cancelled', to: 'open' }
      ];

      for (const transition of statusTransitions) {
        const todoInitial = {
          kind: 'todo' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            scope: 'task',
            todo_type: 'task',
            text: `Status transition test from ${transition.from} to ${transition.to}`,
            status: transition.from
          }
        };

        const todoUpdated = {
          ...todoInitial,
          data: {
            ...todoInitial.data,
            status: transition.to,
            closed_at: transition.to === 'done' ? '2025-01-01T00:00:00Z' : undefined
          }
        };

        const resultInitial = TodoSchema.safeParse(todoInitial);
        const resultUpdated = TodoSchema.safeParse(todoUpdated);

        expect(resultInitial.success).toBe(true);
        expect(resultUpdated.success).toBe(true);
      }
    });

    it('should handle todo with due dates', async () => {
      const todos = [
        {
          kind: 'todo' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            scope: 'task',
            todo_type: 'task',
            text: 'Todo due today',
            status: 'open',
            due_date: '2025-01-01T23:59:59Z'
          },
        },
        {
          kind: 'todo' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            scope: 'task',
            todo_type: 'bug',
            text: 'Bug due next week',
            status: 'open',
            due_date: '2025-01-08T12:00:00Z'
          },
        }
      ];

      const results = todos.map(todo => TodoSchema.safeParse(todo));
      results.forEach(result => {
        expect(result.success).toBe(true);
      });
    });

    it('should handle todo assignments', async () => {
      const assignments = [
        'developer-1',
        'designer-2',
        'product-manager',
        'qa-engineer-3'
      ];

      for (const assignee of assignments) {
        const todo = {
          kind: 'todo' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            scope: 'task',
            todo_type: 'task',
            text: `Todo assigned to ${assignee}`,
            status: 'in_progress',
            assignee
          },
        };

        const result = TodoSchema.safeParse(todo);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.assignee).toBe(assignee);
        }
      }
    });
  });

  describe('Todo Scope Isolation', () => {
    it('should isolate todos by project scope', async () => {
      const todoProjectA = {
        kind: 'todo' as const,
        scope: {
          project: 'project-A',
          branch: 'main'
        },
        data: {
          scope: 'task',
          todo_type: 'task',
          text: 'Todo in project A',
          status: 'open'
        },
      };

      const todoProjectB = {
        kind: 'todo' as const,
        scope: {
          project: 'project-B',
          branch: 'main'
        },
        data: {
          scope: 'task',
          todo_type: 'task',
          text: 'Todo in project B',
          status: 'open'
        },
      };

      // Store both todos
      await db.storeItems([todoProjectA, todoProjectB]);

      // Verify both were stored
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);
    });

    it('should handle todos with different scope levels', async () => {
      const scopeLevels = [
        { scope: 'task', description: 'Individual task' },
        { scope: 'story', description: 'User story' },
        { scope: 'epic', description: 'Large epic' },
        { scope: 'spike', description: 'Research spike' }
      ];

      for (const level of scopeLevels) {
        const todo = {
          kind: 'todo' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            scope: level.scope as any,
            todo_type: 'task',
            text: `${level.description} item`,
            status: 'open'
          },
        };

        const result = TodoSchema.safeParse(todo);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.scope).toBe(level.scope);
        }
      }
    });
  });

  describe('Todo Edge Cases and Error Handling', () => {
    it('should handle todos with special characters in text', async () => {
      const todos = [
        {
          kind: 'todo' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            scope: 'task',
            todo_type: 'bug',
            text: 'Fix: NullPointerException in UserService#getUserProfile() when user is null',
            status: 'open',
            priority: 'critical'
          },
        },
        {
          kind: 'todo' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            scope: 'task',
            todo_type: 'task',
            text: 'Implement OAuth 2.0 integration with GitHub & Google providers (multi-provider auth)',
            status: 'open'
          },
        }
      ];

      const results = todos.map(todo => TodoSchema.safeParse(todo));
      results.forEach(result => {
        expect(result.success).toBe(true);
      });
    });

    it('should handle todos with very long text', async () => {
      const longTodoText = 'x'.repeat(1000); // 1000 character todo text
      const todo = {
        kind: 'todo' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          scope: 'task',
          todo_type: 'epic',
          text: longTodoText,
          status: 'open'
        },
      };

      const result = TodoSchema.safeParse(todo);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.text).toHaveLength(1000);
      }
    });

    it('should handle todo storage errors gracefully', async () => {
      const todo = {
        kind: 'todo' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          scope: 'task',
          todo_type: 'task',
          text: 'Test todo',
          status: 'open'
        },
      };

      // Mock upsert to throw an error
      mockQdrant.upsert.mockRejectedValue(new Error('Database connection failed'));

      const result = await db.storeItems([todo]);

      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('Database connection failed');
    });
  });

  describe('Todo Integration with Knowledge System', () => {
    it('should integrate with knowledge item validation', () => {
      const todo = {
        kind: 'todo' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          scope: 'task',
          todo_type: 'story',
          text: 'As a user, I want to reset my password via email',
          status: 'in_progress',
          priority: 'high',
          assignee: 'frontend-developer',
          due_date: '2025-01-15T00:00:00Z'
        },
        tags: { user_story: true, security: true },
        source: {
          actor: 'product-owner',
          tool: 'agile-planner',
          timestamp: '2025-01-01T00:00:00Z'
        },
        ttl_policy: 'default' as const
      };

      const result = validateKnowledgeItem(todo);
      expect(result.kind).toBe('todo');
      expect(result.data.todo_type).toBe('story');
      expect(result.data.priority).toBe('high');
      expect(result.tags.user_story).toBe(true);
      expect(result.source.actor).toBe('product-owner');
      expect(result.ttl_policy).toBe('default');
    });

    it('should handle TTL policy for todos', async () => {
      const todo = {
        kind: 'todo' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          scope: 'task',
          todo_type: 'task',
          text: 'Temporary task for testing',
          status: 'open'
        },
        ttl_policy: 'short' as const,
      };

      const result = await db.storeItems([todo]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].ttl_policy).toBe('short');
    });
  });
});