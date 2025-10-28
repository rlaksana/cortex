import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  storeTodo,
  updateTodo
} from '../../../src/services/knowledge/todo';

// Mock the UnifiedDatabaseLayer
const mockDb = {
  initialize: vi.fn().mockResolvedValue(undefined),
  create: vi.fn(),
  update: vi.fn(),
  find: vi.fn(),
};

vi.mock('../../../src/db/unified-database-layer-v2', () => ({
  UnifiedDatabaseLayer: vi.fn().mockImplementation(() => mockDb),
}));

describe('Todo Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('storeTodo', () => {
    const mockTodoData = {
      text: 'Implement OAuth 2.0 authentication',
      status: 'pending',
      priority: 'high',
      due_date: '2023-12-31T23:59:59Z',
      todo_type: 'feature',
      assignee: 'john.doe@example.com',
    };
    const mockScope = { project: 'test-project', org: 'test-org' };

    it('should store todo successfully with all fields', async () => {
      // Arrange
      const expectedId = 'todo-uuid-123';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeTodo(mockTodoData, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.initialize).toHaveBeenCalled();
      expect(mockDb.create).toHaveBeenCalledWith('todoLog', {
        data: {
          title: mockTodoData.text,
          description: mockTodoData.text,
          status: mockTodoData.status,
          priority: mockTodoData.priority,
          due_date: new Date(mockTodoData.due_date),
          todo_type: mockTodoData.todo_type,
          text: mockTodoData.text,
          assignee: mockTodoData.assignee,
          tags: mockScope,
        },
      });
    });

    it('should store todo with only text field', async () => {
      // Arrange
      const minimalTodoData = { text: 'Simple todo item' };
      const expectedId = 'minimal-todo-id';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeTodo(minimalTodoData, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.create).toHaveBeenCalledWith('todoLog', {
        data: {
          title: minimalTodoData.text,
          description: minimalTodoData.text,
          status: undefined,
          priority: undefined,
          due_date: null,
          todo_type: null,
          text: minimalTodoData.text,
          assignee: null,
          tags: mockScope,
        },
      });
    });

    it('should use todo_type as title when text is missing', async () => {
      // Arrange
      const todoWithTodoType = {
        todo_type: 'bug',
        status: 'pending',
      };
      const expectedId = 'todo-type-title';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeTodo(todoWithTodoType, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.create).toHaveBeenCalledWith('todoLog', {
        data: {
          title: todoWithTodoType.todo_type,
          description: todoWithTodoType.todo_type,
          status: todoWithTodoType.status,
          priority: undefined,
          due_date: null,
          todo_type: todoWithTodoType.todo_type,
          text: todoWithTodoType.todo_type,
          assignee: null,
          tags: mockScope,
        },
      });
    });

    it('should use default title when both text and todo_type are missing', async () => {
      // Arrange
      const todoWithoutTitle = {
        status: 'in_progress',
        priority: 'medium',
      };
      const expectedId = 'default-title-todo';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeTodo(todoWithoutTitle, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.create).toHaveBeenCalledWith('todoLog', {
        data: {
          title: 'Untitled Todo',
          description: undefined,
          status: todoWithoutTitle.status,
          priority: todoWithoutTitle.priority,
          due_date: null,
          todo_type: null,
          text: null,
          assignee: null,
          tags: mockScope,
        },
      });
    });

    it('should handle null due_date', async () => {
      // Arrange
      const todoWithNullDueDate = {
        ...mockTodoData,
        due_date: null,
      };
      const expectedId = 'null-due-date';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeTodo(todoWithNullDueDate, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.create).toHaveBeenCalledWith('todoLog', {
        data: expect.objectContaining({
          due_date: null,
        }),
      });
    });

    it('should handle undefined due_date', async () => {
      // Arrange
      const todoWithUndefinedDueDate = {
        ...mockTodoData,
        due_date: undefined,
      };
      const expectedId = 'undefined-due-date';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeTodo(todoWithUndefinedDueDate, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.create).toHaveBeenCalledWith('todoLog', {
        data: expect.objectContaining({
          due_date: null,
        }),
      });
    });

    it('should handle missing due_date field', async () => {
      // Arrange
      const todoWithoutDueDate = { ...mockTodoData };
      delete (todoWithoutDueDate as any).due_date;
      const expectedId = 'no-due-date';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeTodo(todoWithoutDueDate, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.create).toHaveBeenCalledWith('todoLog', {
        data: expect.objectContaining({
          due_date: null,
        }),
      });
    });

    it('should handle database initialization errors', async () => {
      // Arrange
      mockDb.initialize.mockRejectedValue(new Error('Database connection failed'));

      // Act & Assert
      await expect(storeTodo(mockTodoData, mockScope)).rejects.toThrow(
        'Database connection failed'
      );
    });

    it('should handle database creation errors', async () => {
      // Arrange
      mockDb.create.mockRejectedValue(new Error('Insert failed'));

      // Act & Assert
      await expect(storeTodo(mockTodoData, mockScope)).rejects.toThrow(
        'Insert failed'
      );
    });

    it('should handle empty scope', async () => {
      // Arrange
      const expectedId = 'empty-scope-todo';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeTodo(mockTodoData, {});

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.create).toHaveBeenCalledWith('todoLog', {
        data: expect.objectContaining({
          tags: {},
        }),
      });
    });

    it('should handle unicode content in todo data', async () => {
      // Arrange
      const unicodeTodo = {
        text: 'Tâche: 测试 中文 🧠',
        status: 'en_cours',
        priority: 'élevé',
        assignee: 'usuario@ejemplo.español',
      };
      const expectedId = 'unicode-todo';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeTodo(unicodeTodo, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.create).toHaveBeenCalledWith('todoLog', {
        data: expect.objectContaining({
          title: 'Tâche: 测试 中文 🧠',
          description: 'Tâche: 测试 中文 🧠',
          status: 'en_cours',
          priority: 'élevé',
          assignee: 'usuario@ejemplo.español',
        }),
      });
    });

    it('should handle very long todo text', async () => {
      // Arrange
      const longText = 'This is a very long todo description. '.repeat(1000);
      const longTodo = { text: longText };
      const expectedId = 'long-todo';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeTodo(longTodo, mockScope);

      // Assert
      expect(result).toBe(expectedId);
    });

    it('should handle different todo statuses', async () => {
      // Arrange
      const statuses = ['pending', 'in_progress', 'completed', 'cancelled', 'blocked'];

      for (const status of statuses) {
        mockDb.create.mockClear();
        const todoWithStatus = { ...mockTodoData, status };
        const expectedId = `todo-${status}`;
        mockDb.create.mockResolvedValue({ id: expectedId });

        // Act
        const result = await storeTodo(todoWithStatus, mockScope);

        // Assert
        expect(result).toBe(expectedId);
        expect(mockDb.create).toHaveBeenCalledWith('todoLog', {
          data: expect.objectContaining({ status }),
        });
      }
    });

    it('should handle different todo priorities', async () => {
      // Arrange
      const priorities = ['low', 'medium', 'high', 'critical', 'urgent'];

      for (const priority of priorities) {
        mockDb.create.mockClear();
        const todoWithPriority = { ...mockTodoData, priority };
        const expectedId = `todo-${priority}`;
        mockDb.create.mockResolvedValue({ id: expectedId });

        // Act
        const result = await storeTodo(todoWithPriority, mockScope);

        // Assert
        expect(result).toBe(expectedId);
        expect(mockDb.create).toHaveBeenCalledWith('todoLog', {
          data: expect.objectContaining({ priority }),
        });
      }
    });

    it('should handle different todo types', async () => {
      // Arrange
      const todoTypes = ['feature', 'bug', 'enhancement', 'documentation', 'refactor', 'test'];

      for (const todoType of todoTypes) {
        mockDb.create.mockClear();
        const todoWithType = { ...mockTodoData, todo_type: todoType };
        const expectedId = `todo-${todoType}`;
        mockDb.create.mockResolvedValue({ id: expectedId });

        // Act
        const result = await storeTodo(todoWithType, mockScope);

        // Assert
        expect(result).toBe(expectedId);
        expect(mockDb.create).toHaveBeenCalledWith('todoLog', {
          data: expect.objectContaining({ todo_type: todoType }),
        });
      }
    });

    it('should handle invalid date strings in due_date', async () => {
      // Arrange
      const todoWithInvalidDate = {
        ...mockTodoData,
        due_date: 'invalid-date-string',
      };
      const expectedId = 'invalid-date-todo';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeTodo(todoWithInvalidDate, mockScope);

      // Assert - Should create an invalid Date object but not crash
      expect(result).toBe(expectedId);
      expect(mockDb.create).toHaveBeenCalledWith('todoLog', {
        data: expect.objectContaining({
          due_date: expect.any(Date),
        }),
      });
    });
  });

  describe('updateTodo', () => {
    const todoId = 'todo-to-update';
    const mockExistingTodo = {
      id: todoId,
      title: 'Original Title',
      description: 'Original Description',
      status: 'pending',
      priority: 'medium',
      due_date: new Date('2023-12-31'),
      todo_type: 'feature',
      text: 'Original text',
      assignee: 'original@example.com',
      tags: { project: 'existing-project' },
    };

    it('should update todo text successfully', async () => {
      // Arrange
      const updateData = { text: 'Updated todo text' };
      const scope = { project: 'updated-project' };
      mockDb.find.mockResolvedValue([mockExistingTodo]);
      mockDb.update.mockResolvedValue({ id: todoId });

      // Act
      const result = await updateTodo(todoId, updateData, scope);

      // Assert
      expect(result).toBe(todoId);
      expect(mockDb.find).toHaveBeenCalledWith('todoLog', {
        where: { id: todoId },
      });
      expect(mockDb.update).toHaveBeenCalledWith('todoLog',
        { id: todoId },
        {
          title: updateData.text,
          description: updateData.text,
          status: mockExistingTodo.status,
          priority: mockExistingTodo.priority,
          due_date: mockExistingTodo.due_date,
          todo_type: mockExistingTodo.todo_type,
          text: updateData.text,
          assignee: mockExistingTodo.assignee,
          tags: {
            ...mockExistingTodo.tags,
            ...scope,
          },
        }
      );
    });

    it('should update todo status successfully', async () => {
      // Arrange
      const updateData = { status: 'completed' };
      const scope = { project: 'test-project' };
      mockDb.find.mockResolvedValue([mockExistingTodo]);
      mockDb.update.mockResolvedValue({ id: todoId });

      // Act
      const result = await updateTodo(todoId, updateData, scope);

      // Assert
      expect(result).toBe(todoId);
      expect(mockDb.update).toHaveBeenCalledWith('todoLog',
        { id: todoId },
        expect.objectContaining({
          status: 'completed',
        })
      );
    });

    it('should update todo priority successfully', async () => {
      // Arrange
      const updateData = { priority: 'high' };
      const scope = { project: 'test-project' };
      mockDb.find.mockResolvedValue([mockExistingTodo]);
      mockDb.update.mockResolvedValue({ id: todoId });

      // Act
      const result = await updateTodo(todoId, updateData, scope);

      // Assert
      expect(result).toBe(todoId);
      expect(mockDb.update).toHaveBeenCalledWith('todoLog',
        { id: todoId },
        expect.objectContaining({
          priority: 'high',
        })
      );
    });

    it('should update todo due_date successfully', async () => {
      // Arrange
      const newDueDate = '2024-06-30T23:59:59Z';
      const updateData = { due_date: newDueDate };
      const scope = { project: 'test-project' };
      mockDb.find.mockResolvedValue([mockExistingTodo]);
      mockDb.update.mockResolvedValue({ id: todoId });

      // Act
      const result = await updateTodo(todoId, updateData, scope);

      // Assert
      expect(result).toBe(todoId);
      expect(mockDb.update).toHaveBeenCalledWith('todoLog',
        { id: todoId },
        expect.objectContaining({
          due_date: new Date(newDueDate),
        })
      );
    });

    it('should update todo_type successfully', async () => {
      // Arrange
      const updateData = { todo_type: 'bug' };
      const scope = { project: 'test-project' };
      mockDb.find.mockResolvedValue([mockExistingTodo]);
      mockDb.update.mockResolvedValue({ id: todoId });

      // Act
      const result = await updateTodo(todoId, updateData, scope);

      // Assert
      expect(result).toBe(todoId);
      expect(mockDb.update).toHaveBeenCalledWith('todoLog',
        { id: todoId },
        expect.objectContaining({
          todo_type: 'bug',
        })
      );
    });

    it('should update assignee successfully', async () => {
      // Arrange
      const updateData = { assignee: 'new.assignee@example.com' };
      const scope = { project: 'test-project' };
      mockDb.find.mockResolvedValue([mockExistingTodo]);
      mockDb.update.mockResolvedValue({ id: todoId });

      // Act
      const result = await updateTodo(todoId, updateData, scope);

      // Assert
      expect(result).toBe(todoId);
      expect(mockDb.update).toHaveBeenCalledWith('todoLog',
        { id: todoId },
        expect.objectContaining({
          assignee: 'new.assignee@example.com',
        })
      );
    });

    it('should update multiple fields simultaneously', async () => {
      // Arrange
      const updateData = {
        text: 'Completely updated text',
        status: 'in_progress',
        priority: 'critical',
        due_date: '2024-01-15T10:00:00Z',
        todo_type: 'enhancement',
        assignee: 'updated@example.com',
      };
      const scope = { project: 'multi-update', org: 'test-org' };
      mockDb.find.mockResolvedValue([mockExistingTodo]);
      mockDb.update.mockResolvedValue({ id: todoId });

      // Act
      const result = await updateTodo(todoId, updateData, scope);

      // Assert
      expect(result).toBe(todoId);
      expect(mockDb.update).toHaveBeenCalledWith('todoLog',
        { id: todoId },
        {
          title: updateData.text,
          description: updateData.text,
          status: updateData.status,
          priority: updateData.priority,
          due_date: new Date(updateData.due_date),
          todo_type: updateData.todo_type,
          text: updateData.text,
          assignee: updateData.assignee,
          tags: {
            ...mockExistingTodo.tags,
            ...scope,
          },
        }
      );
    });

    it('should use todo_type as title when text is not provided in update', async () => {
      // Arrange
      const updateData = {
        todo_type: 'documentation',
        status: 'completed',
      };
      const scope = { project: 'test-project' };
      mockDb.find.mockResolvedValue([mockExistingTodo]);
      mockDb.update.mockResolvedValue({ id: todoId });

      // Act
      const result = await updateTodo(todoId, updateData, scope);

      // Assert
      expect(result).toBe(todoId);
      expect(mockDb.update).toHaveBeenCalledWith('todoLog',
        { id: todoId },
        expect.objectContaining({
          title: updateData.todo_type,
          description: mockExistingTodo.description, // Should keep existing description
        })
      );
    });

    it('should merge scope tags with existing tags', async () => {
      // Arrange
      const updateData = { status: 'completed' };
      const newScope = {
        project: 'new-project',
        branch: 'feature-branch',
        priority: 'high' // This should be added to tags
      };
      mockDb.find.mockResolvedValue([mockExistingTodo]);
      mockDb.update.mockResolvedValue({ id: todoId });

      // Act
      const result = await updateTodo(todoId, updateData, newScope);

      // Assert
      expect(result).toBe(todoId);
      expect(mockDb.update).toHaveBeenCalledWith('todoLog',
        { id: todoId },
        expect.objectContaining({
          tags: {
            project: 'existing-project',
            ...newScope,
          },
        })
      );
    });

    it('should handle todo not found', async () => {
      // Arrange
      const updateData = { status: 'completed' };
      const scope = { project: 'test-project' };
      mockDb.find.mockResolvedValue([]);

      // Act & Assert
      await expect(updateTodo(todoId, updateData, scope)).rejects.toThrow(
        `Todo with id ${todoId} not found`
      );
      expect(mockDb.update).not.toHaveBeenCalled();
    });

    it('should handle database find errors', async () => {
      // Arrange
      const updateData = { status: 'completed' };
      const scope = { project: 'test-project' };
      mockDb.find.mockRejectedValue(new Error('Find query failed'));

      // Act & Assert
      await expect(updateTodo(todoId, updateData, scope)).rejects.toThrow(
        'Find query failed'
      );
    });

    it('should handle database update errors', async () => {
      // Arrange
      const updateData = { status: 'completed' };
      const scope = { project: 'test-project' };
      mockDb.find.mockResolvedValue([mockExistingTodo]);
      mockDb.update.mockRejectedValue(new Error('Update query failed'));

      // Act & Assert
      await expect(updateTodo(todoId, updateData, scope)).rejects.toThrow(
        'Update query failed'
      );
    });

    it('should handle empty todo ID', async () => {
      // Arrange
      const updateData = { status: 'completed' };
      const scope = { project: 'test-project' };

      // Act & Assert
      await expect(updateTodo('', updateData, scope)).rejects.toThrow(
        'Todo with id  not found'
      );
      await expect(updateTodo(null as any, updateData, scope)).rejects.toThrow(
        'Todo with id null not found'
      );
    });

    it('should handle partial updates with null values', async () => {
      // Arrange
      const updateData = {
        status: null as any,
        priority: undefined,
        due_date: null,
      };
      const scope = { project: 'test-project' };
      mockDb.find.mockResolvedValue([mockExistingTodo]);
      mockDb.update.mockResolvedValue({ id: todoId });

      // Act
      const result = await updateTodo(todoId, updateData, scope);

      // Assert
      expect(result).toBe(todoId);
      expect(mockDb.update).toHaveBeenCalledWith('todoLog',
        { id: todoId },
        expect.objectContaining({
          status: null, // Should preserve null values
          priority: mockExistingTodo.priority, // Should keep existing for undefined
          due_date: null, // Should set null explicitly
        })
      );
    });

    it('should handle unicode content in update data', async () => {
      // Arrange
      const unicodeUpdateData = {
        text: 'Tâche mise à jour: 测试 中文 🧠',
        status: 'terminé',
        assignee: 'usuario.actualizado@ejemplo.español',
      };
      const scope = { project: 'unicode-test' };
      mockDb.find.mockResolvedValue([mockExistingTodo]);
      mockDb.update.mockResolvedValue({ id: todoId });

      // Act
      const result = await updateTodo(todoId, unicodeUpdateData, scope);

      // Assert
      expect(result).toBe(todoId);
      expect(mockDb.update).toHaveBeenCalledWith('todoLog',
        { id: todoId },
        expect.objectContaining({
          title: 'Tâche mise à jour: 测试 中文 🧠',
          description: 'Tâche mise à jour: 测试 中文 🧠',
          status: 'terminé',
          assignee: 'usuario.actualizado@ejemplo.español',
        })
      );
    });

    it('should handle updates to existing todo with missing fields', async () => {
      // Arrange
      const incompleteExistingTodo = {
        id: todoId,
        title: 'Existing Title',
        // Missing other fields
        tags: { project: 'existing' },
      };
      const updateData = { status: 'in_progress' };
      const scope = { project: 'test-project' };
      mockDb.find.mockResolvedValue([incompleteExistingTodo]);
      mockDb.update.mockResolvedValue({ id: todoId });

      // Act
      const result = await updateTodo(todoId, updateData, scope);

      // Assert
      expect(result).toBe(todoId);
      expect(mockDb.update).toHaveBeenCalledWith('todoLog',
        { id: todoId },
        expect.objectContaining({
          status: 'in_progress',
          // Should handle missing existing fields gracefully
        })
      );
    });
  });

  describe('Integration Tests', () => {
    it('should handle complete todo lifecycle', async () => {
      // Arrange
      const todoData = {
        text: 'Implement user authentication',
        status: 'pending',
        priority: 'high',
        todo_type: 'feature',
        assignee: 'developer@example.com',
      };
      const scope = { project: 'lifecycle-test' };

      // Store
      const storedId = 'todo-lifecycle';
      mockDb.create.mockResolvedValue({ id: storedId });
      const result1 = await storeTodo(todoData, scope);

      // Update - In Progress
      const update1 = { status: 'in_progress' };
      const existingTodo = {
        id: storedId,
        title: todoData.text,
        description: todoData.text,
        status: todoData.status,
        priority: todoData.priority,
        due_date: null,
        todo_type: todoData.todo_type,
        text: todoData.text,
        assignee: todoData.assignee,
        tags: scope,
      };
      mockDb.find.mockResolvedValue([existingTodo]);
      mockDb.update.mockResolvedValue({ id: storedId });
      const result2 = await updateTodo(storedId, update1, scope);

      // Update - Completed with notes
      const update2 = {
        status: 'completed',
        text: 'Implement user authentication - COMPLETED'
      };
      mockDb.update.mockResolvedValue({ id: storedId });
      const result3 = await updateTodo(storedId, update2, scope);

      // Assert
      expect(result1).toBe(storedId);
      expect(result2).toBe(storedId);
      expect(result3).toBe(storedId);

      expect(mockDb.create).toHaveBeenCalledWith('todoLog', {
        data: expect.objectContaining({
          title: todoData.text,
          status: todoData.status,
          priority: todoData.priority,
        }),
      });

      expect(mockDb.update).toHaveBeenCalledTimes(2);
      expect(mockDb.update).toHaveBeenNthCalledWith(1, 'todoLog',
        { id: storedId },
        expect.objectContaining({
          status: 'in_progress',
        })
      );
      expect(mockDb.update).toHaveBeenNthCalledWith(2, 'todoLog',
        { id: storedId },
        expect.objectContaining({
          status: 'completed',
          title: 'Implement user authentication - COMPLETED',
          description: 'Implement user authentication - COMPLETED',
          text: 'Implement user authentication - COMPLETED',
        })
      );
    });

    it('should handle todo with due date management', async () => {
      // Arrange
      const todoWithDueDate = {
        text: 'Task with deadline',
        due_date: '2023-12-31T23:59:59Z',
      };
      const scope = { project: 'deadline-test' };

      // Store
      const storedId = 'deadline-todo';
      mockDb.create.mockResolvedValue({ id: storedId });
      const result1 = await storeTodo(todoWithDueDate, scope);

      // Update - Extend deadline
      const updateData = { due_date: '2024-01-15T23:59:59Z' };
      const existingTodo = {
        id: storedId,
        title: todoWithDueDate.text,
        description: todoWithDueDate.text,
        status: undefined,
        priority: undefined,
        due_date: new Date(todoWithDueDate.due_date),
        todo_type: null,
        text: todoWithDueDate.text,
        assignee: null,
        tags: scope,
      };
      mockDb.find.mockResolvedValue([existingTodo]);
      mockDb.update.mockResolvedValue({ id: storedId });
      const result2 = await updateTodo(storedId, updateData, scope);

      // Assert
      expect(result1).toBe(storedId);
      expect(result2).toBe(storedId);
      expect(mockDb.create).toHaveBeenCalledWith('todoLog', {
        data: expect.objectContaining({
          due_date: new Date(todoWithDueDate.due_date),
        }),
      });
      expect(mockDb.update).toHaveBeenCalledWith('todoLog',
        { id: storedId },
        expect.objectContaining({
          due_date: new Date('2024-01-15T23:59:59Z'),
        })
      );
    });

    it('should handle todo reassignment', async () => {
      // Arrange
      const todoWithAssignee = {
        text: 'Task to reassign',
        assignee: 'original.dev@example.com',
      };
      const scope = { project: 'reassign-test' };

      // Store
      const storedId = 'reassign-todo';
      mockDb.create.mockResolvedValue({ id: storedId });
      await storeTodo(todoWithAssignee, scope);

      // Update - Reassign to new person
      const reassignData = {
        assignee: 'new.dev@example.com',
        status: 'in_progress'
      };
      const existingTodo = {
        id: storedId,
        title: todoWithAssignee.text,
        description: todoWithAssignee.text,
        status: undefined,
        priority: undefined,
        due_date: null,
        todo_type: null,
        text: todoWithAssignee.text,
        assignee: todoWithAssignee.assignee,
        tags: scope,
      };
      mockDb.find.mockResolvedValue([existingTodo]);
      mockDb.update.mockResolvedValue({ id: storedId });
      const result = await updateTodo(storedId, reassignData, scope);

      // Assert
      expect(result).toBe(storedId);
      expect(mockDb.update).toHaveBeenCalledWith('todoLog',
        { id: storedId },
        expect.objectContaining({
          assignee: 'new.dev@example.com',
          status: 'in_progress',
        })
      );
    });
  });
});