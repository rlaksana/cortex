import { describe, it, expect, beforeEach, vi } from 'vitest';
import { TodoValidator } from '../../src/services/validation/business-validators';
import type { KnowledgeItem } from '../../src/types/core-interfaces';

// Mock the logger to avoid noise in tests
vi.mock('../../src/utils/logger', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

describe('TodoValidator - P5-T5.1 Business Rules', () => {
  let validator: TodoValidator;

  beforeEach(() => {
    validator = new TodoValidator();
    vi.clearAllMocks();
  });

  describe('Circular Dependency Detection Rule', () => {
    it('should REJECT todo with circular dependency (A -> B -> A)', async () => {
      // Arrange: Create a todo with circular dependency
      const todoWithCircularDep: KnowledgeItem = {
        id: 'todo-A',
        kind: 'todo',
        content: 'Task A depends on B, and B depends on A',
        data: {
          title: 'Task A',
          description: 'Task that depends on Task B',
          status: 'pending',
          priority: 'high',
          dependencies: ['todo-B'], // A depends on B
          // In a real scenario, we'd detect that B also depends on A
          circular_dependency_detected: true, // Flag to simulate detection
        },
        metadata: { created_at: '2024-01-20T10:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T10:00:00Z'),
        updated_at: new Date('2024-01-20T10:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(todoWithCircularDep);

      // Assert: Should fail validation
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Circular dependency detected: todo-A -> todo-B -> todo-A');
    });

    it('should REJECT todo with complex circular dependency (A -> B -> C -> A)', async () => {
      // Arrange: Create a todo with complex circular dependency
      const todoWithComplexCircularDep: KnowledgeItem = {
        id: 'todo-A',
        kind: 'todo',
        content: 'Task A in complex circular dependency chain',
        data: {
          title: 'Task A',
          description: 'Start of complex circular dependency',
          status: 'pending',
          priority: 'high',
          dependencies: ['todo-B', 'todo-C'], // A depends on B and C
          circular_dependency_detected: true,
          circular_dependency_path: ['todo-A', 'todo-B', 'todo-C', 'todo-A'],
        },
        metadata: { created_at: '2024-01-20T10:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T10:00:00Z'),
        updated_at: new Date('2024-01-20T10:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(todoWithComplexCircularDep);

      // Assert: Should fail validation
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Circular dependency detected: todo-A -> todo-B -> todo-C -> todo-A'
      );
    });

    it('should ACCEPT todo with valid linear dependencies (A -> B -> C)', async () => {
      // Arrange: Create a todo with valid linear dependencies
      const todoWithValidDeps: KnowledgeItem = {
        id: 'todo-A',
        kind: 'todo',
        content: 'Task A depends on B, B depends on C',
        data: {
          title: 'Task A',
          description: 'Task with valid dependencies',
          status: 'pending',
          priority: 'medium',
          dependencies: ['todo-B'], // A depends on B
          circular_dependency_detected: false, // No circular dependency
        },
        metadata: { created_at: '2024-01-20T11:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T11:00:00Z'),
        updated_at: new Date('2024-01-20T11:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(todoWithValidDeps);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should ACCEPT todo with no dependencies', async () => {
      // Arrange: Create a todo with no dependencies
      const todoNoDeps: KnowledgeItem = {
        id: 'todo-123',
        kind: 'todo',
        content: 'Independent task',
        data: {
          title: 'Independent Task',
          description: 'Task with no dependencies',
          status: 'pending',
          priority: 'low',
          dependencies: [], // No dependencies
        },
        metadata: { created_at: '2024-01-20T12:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T12:00:00Z'),
        updated_at: new Date('2024-01-20T12:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(todoNoDeps);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should REJECT todo that depends on itself', async () => {
      // Arrange: Create a todo that depends on itself
      const todoSelfDep: KnowledgeItem = {
        id: 'todo-self',
        kind: 'todo',
        content: 'Task that depends on itself',
        data: {
          title: 'Self-referencing Task',
          description: 'Invalid self-dependency',
          status: 'pending',
          priority: 'high',
          dependencies: ['todo-self'], // Self-dependency
          circular_dependency_detected: true,
        },
        metadata: { created_at: '2024-01-20T13:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T13:00:00Z'),
        updated_at: new Date('2024-01-20T13:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(todoSelfDep);

      // Assert: Should fail validation
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Self-dependency detected: todo-self cannot depend on itself'
      );
    });
  });

  describe('Todo Completion Rule', () => {
    it('should automatically add completed_at timestamp when todo status changes to done', async () => {
      // Arrange: Create a todo being marked as done without completed_at
      const todoBeingCompleted: KnowledgeItem = {
        id: 'todo-complete',
        kind: 'todo',
        content: 'Task being completed',
        data: {
          title: 'Task to Complete',
          description: 'Task that is being marked as done',
          status: 'done', // Status is done
          priority: 'medium',
          completed_at: undefined, // Missing completed_at timestamp
        },
        metadata: { created_at: '2024-01-20T14:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T14:00:00Z'),
        updated_at: new Date('2024-01-20T15:30:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(todoBeingCompleted);

      // Assert: Should pass validation and auto-set completed_at
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.warnings).toContain(
        'Todo marked as done without completed_at timestamp - auto-setting current time'
      );
      // Check that completed_at was auto-set
      expect(todoBeingCompleted['data.completed_at']).toBeDefined();
      expect(todoBeingCompleted['data.completed_at']).toMatch(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/
      );
    });

    it('should ACCEPT todo marked as done with existing completed_at timestamp', async () => {
      // Arrange: Create a todo marked as done with proper completed_at
      const completedTodo: KnowledgeItem = {
        id: 'todo-completed',
        kind: 'todo',
        content: 'Already completed task',
        data: {
          title: 'Completed Task',
          description: 'Task that was completed earlier',
          status: 'done',
          priority: 'low',
          completed_at: '2024-01-19T16:45:00Z', // Proper timestamp exists
        },
        metadata: { created_at: '2024-01-15T09:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-15T09:00:00Z'),
        updated_at: new Date('2024-01-19T16:45:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(completedTodo);

      // Assert: Should pass validation without warnings
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.warnings).toHaveLength(0);
    });

    it('should ACCEPT todo in progress status without completed_at timestamp', async () => {
      // Arrange: Create a todo in progress without completed_at
      const inProgressTodo: KnowledgeItem = {
        id: 'todo-in-progress',
        kind: 'todo',
        content: 'Task in progress',
        data: {
          title: 'In Progress Task',
          description: 'Task currently being worked on',
          status: 'in_progress', // Not done yet
          priority: 'high',
          // No completed_at needed for in_progress
        },
        metadata: { created_at: '2024-01-20T16:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T16:00:00Z'),
        updated_at: new Date('2024-01-20T17:30:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(inProgressTodo);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should REJECT todo with invalid completed_at timestamp format', async () => {
      // Arrange: Create a todo with invalid completed_at format
      const todoInvalidTimestamp: KnowledgeItem = {
        id: 'todo-invalid-time',
        kind: 'todo',
        content: 'Task with invalid timestamp',
        data: {
          title: 'Invalid Timestamp Task',
          description: 'Task with malformed completed_at',
          status: 'done',
          priority: 'medium',
          completed_at: 'not-a-valid-timestamp', // Invalid format
        },
        metadata: { created_at: '2024-01-20T18:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T18:00:00Z'),
        updated_at: new Date('2024-01-20T19:00:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(todoInvalidTimestamp);

      // Assert: Should fail validation
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Completed timestamp must be a valid ISO 8601 date string');
    });
  });

  describe('Basic Todo Validation', () => {
    it('should REJECT todo without title', async () => {
      const todoWithoutTitle: KnowledgeItem = {
        id: 'todo-123',
        kind: 'todo',
        content: 'Todo content',
        data: {
          description: 'Some description',
          status: 'pending',
        },
        metadata: {},
        scope: {},
        created_at: new Date(),
        updated_at: new Date(),
      };

      const result = await validator.validate(todoWithoutTitle);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Todo requires a title');
    });

    it('should REJECT todo with invalid status', async () => {
      const todoInvalidStatus: KnowledgeItem = {
        id: 'todo-123',
        kind: 'todo',
        content: 'Todo content',
        data: {
          title: 'Some todo',
          description: 'Some description',
          status: 'invalid_status',
        },
        metadata: {},
        scope: {},
        created_at: new Date(),
        updated_at: new Date(),
      };

      const result = await validator.validate(todoInvalidStatus);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Invalid todo status: invalid_status');
    });
  });
});
