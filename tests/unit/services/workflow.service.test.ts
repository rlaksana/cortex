/**
 * Comprehensive Unit Tests for Workflow Service
 *
 * Tests advanced workflow service functionality including:
 * - Workflow Definition and Management: template creation, validation, versioning, lifecycle
 * - Workflow Execution: sequential execution, parallel branching, conditional logic, state management
 * - Task Orchestration: assignment, routing, dependencies, timeout handling, completion tracking
 * - Human Workflow Integration: user assignment, approvals, escalations, notifications
 * - Monitoring and Analytics: execution metrics, performance monitoring, bottleneck identification
 * - Integration with Services: service task integration, cross-service workflows, event-driven workflows
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { WorkflowService } from '../../../src/services/workflow/workflow.service';
import type {
  WorkflowDefinition,
  WorkflowExecution,
  WorkflowTask,
  WorkflowState,
  WorkflowTemplate,
  WorkflowVersion,
  WorkflowExecutionRequest,
  TaskAssignment,
  WorkflowAnalytics,
  WorkflowMetrics,
  WorkflowPerformanceData,
  WorkflowBottleneck,
  WorkflowReport,
  WorkflowQuery,
  WorkflowFilter,
  WorkflowEvent,
  WorkflowNotification,
  HumanTask,
  ApprovalTask,
  EscalationTask,
  ServiceTask,
  ParallelTask,
  ConditionalTask,
  WorkflowDependency,
  WorkflowIntegration,
  WorkflowTrigger,
  WorkflowAction,
  WorkflowResult,
  WorkflowContext,
  WorkflowConfiguration,
  WorkflowSettings,
  WorkflowValidation,
  WorkflowError,
  WorkflowStatus,
  TaskStatus,
  TaskPriority,
  ExecutionMode,
  TriggerType,
  ActionType,
  NotificationType,
  IntegrationType,
} from '../../../src/types/workflow-interfaces';

// Mock dependencies
vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock('../../../src/db/qdrant', () => ({
  getQdrantClient: () => mockQdrantClient,
}));

vi.mock('../../../src/services/orchestrators/memory-find-orchestrator', () => ({
  MemoryFindOrchestrator: vi.fn().mockImplementation(() => ({
    find: vi.fn(),
  })),
}));

vi.mock('../../../src/services/notifications/notification.service', () => ({
  notificationService: {
    sendNotification: vi.fn(),
    sendBulkNotifications: vi.fn(),
    getNotificationHistory: vi.fn(),
  },
}));

vi.mock('../../../src/services/audit/audit-service', () => ({
  auditService: {
    logEvent: vi.fn(),
    getEventHistory: vi.fn(),
    auditWorkflow: vi.fn(),
  },
}));

// Mock Qdrant client with comprehensive workflow data
const mockQdrantClient = {
  workflowDefinition: {
    create: vi.fn(),
    findUnique: vi.fn(),
    findMany: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    count: vi.fn(),
  },
  workflowExecution: {
    create: vi.fn(),
    findUnique: vi.fn(),
    findMany: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    count: vi.fn(),
  },
  workflowTask: {
    create: vi.fn(),
    findUnique: vi.fn(),
    findMany: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    count: vi.fn(),
  },
  workflowTemplate: {
    create: vi.fn(),
    findUnique: vi.fn(),
    findMany: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    count: vi.fn(),
  },
  workflowVersion: {
    create: vi.fn(),
    findUnique: vi.fn(),
    findMany: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    count: vi.fn(),
  },
  workflowAnalytics: {
    create: vi.fn(),
    findUnique: vi.fn(),
    findMany: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    count: vi.fn(),
  },
  workflowMetrics: {
    create: vi.fn(),
    findUnique: vi.fn(),
    findMany: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    count: vi.fn(),
  },
  workflowEvent: {
    create: vi.fn(),
    findUnique: vi.fn(),
    findMany: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    count: vi.fn(),
  },
  workflowNotification: {
    create: vi.fn(),
    findUnique: vi.fn(),
    findMany: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    count: vi.fn(),
  },
  workflowIntegration: {
    create: vi.fn(),
    findUnique: vi.fn(),
    findMany: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    count: vi.fn(),
  },
  $transaction: vi.fn(),
};

// Mock service data
const mockWorkflowTemplates: WorkflowTemplate[] = [
  {
    id: 'template-1',
    name: 'Document Approval Workflow',
    description: 'Standard document approval process',
    category: 'approval',
    version: '1.0.0',
    tasks: [
      {
        id: 'task-1',
        name: 'Document Review',
        type: 'human',
        assignee: 'reviewer@example.com',
        priority: 'high',
        dependencies: [],
        config: {
          deadline: 24,
          autoReminder: true,
        },
      },
      {
        id: 'task-2',
        name: 'Manager Approval',
        type: 'approval',
        assignee: 'manager@example.com',
        priority: 'high',
        dependencies: ['task-1'],
        config: {
          requiredApprovals: 1,
          autoReminder: true,
        },
      },
    ],
    metadata: {
      created_by: 'system',
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    },
  },
  {
    id: 'template-2',
    name: 'Incident Response Workflow',
    description: 'IT incident response and resolution',
    category: 'incident',
    version: '2.1.0',
    tasks: [
      {
        id: 'task-3',
        name: 'Incident Detection',
        type: 'service',
        priority: 'critical',
        dependencies: [],
        config: {
          service: 'monitoring',
          action: 'detect',
        },
      },
      {
        id: 'task-4',
        name: 'Parallel Investigation',
        type: 'parallel',
        dependencies: ['task-3'],
        config: {
          parallelTasks: [
            {
              id: 'task-4a',
              name: 'Technical Analysis',
              type: 'service',
              config: { service: 'technical' },
            },
            {
              id: 'task-4b',
              name: 'Impact Assessment',
              type: 'human',
              config: { assignee: 'analyst@example.com' },
            },
          ],
        },
      },
    ],
    metadata: {
      created_by: 'system',
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    },
  },
];

const mockWorkflowExecutions: WorkflowExecution[] = [
  {
    id: 'execution-1',
    workflowId: 'template-1',
    status: 'running',
    startedAt: '2024-01-01T10:00:00Z',
    currentTask: 'task-1',
    context: {
      documentId: 'doc-123',
      requestor: 'user@example.com',
    },
    tasks: [
      {
        id: 'task-execution-1',
        taskId: 'task-1',
        status: 'pending',
        assignee: 'reviewer@example.com',
        startedAt: '2024-01-01T10:00:00Z',
      },
    ],
    metadata: {
      started_by: 'user@example.com',
      started_at: '2024-01-01T10:00:00Z',
    },
  },
  {
    id: 'execution-2',
    workflowId: 'template-2',
    status: 'completed',
    startedAt: '2024-01-01T08:00:00Z',
    completedAt: '2024-01-01T12:00:00Z',
    context: {
      incidentId: 'inc-456',
      severity: 'high',
    },
    tasks: [
      {
        id: 'task-execution-2',
        taskId: 'task-3',
        status: 'completed',
        completedAt: '2024-01-01T08:30:00Z',
      },
      {
        id: 'task-execution-3',
        taskId: 'task-4',
        status: 'completed',
        completedAt: '2024-01-01T12:00:00Z',
      },
    ],
    metadata: {
      started_by: 'system',
      started_at: '2024-01-01T08:00:00Z',
      completed_at: '2024-01-01T12:00:00Z',
    },
  },
];

const mockWorkflowAnalytics: WorkflowAnalytics[] = [
  {
    workflowId: 'template-1',
    executionCount: 150,
    averageExecutionTime: 7200,
    successRate: 0.85,
    mostFailedTask: 'task-1',
    commonBottlenecks: ['task-2'],
    lastMonthExecutions: 25,
    averageTaskCompletionTime: {
      'task-1': 3600,
      'task-2': 1800,
    },
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
  },
  {
    workflowId: 'template-2',
    executionCount: 89,
    averageExecutionTime: 14400,
    successRate: 0.92,
    mostFailedTask: 'task-4b',
    commonBottlenecks: ['task-4a'],
    lastMonthExecutions: 12,
    averageTaskCompletionTime: {
      'task-3': 1800,
      'task-4': 7200,
      'task-4a': 3600,
      'task-4b': 5400,
    },
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
  },
];

describe('WorkflowService', () => {
  let workflowService: WorkflowService;

  beforeEach(() => {
    vi.clearAllMocks();
    workflowService = new WorkflowService();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Workflow Definition and Management', () => {
    describe('Template Creation', () => {
      it('should create a new workflow template', async () => {
        const templateData: Partial<WorkflowTemplate> = {
          name: 'New Approval Workflow',
          description: 'Custom approval process',
          category: 'approval',
          version: '1.0.0',
          tasks: [
            {
              id: 'task-new-1',
              name: 'Initial Review',
              type: 'human',
              assignee: 'reviewer@example.com',
              priority: 'medium',
              dependencies: [],
            },
          ],
        };

        mockQdrantClient.workflowTemplate.create.mockResolvedValue({
          id: 'template-new',
          ...templateData,
          metadata: {
            created_by: 'test-user',
            created_at: '2024-01-01T00:00:00Z',
            updated_at: '2024-01-01T00:00:00Z',
          },
        });

        const result = await workflowService.createTemplate(templateData);

        expect(result).toBeDefined();
        expect(result.id).toBe('template-new');
        expect(result.name).toBe('New Approval Workflow');
        expect(mockQdrantClient.workflowTemplate.create).toHaveBeenCalledWith({
          data: expect.objectContaining({
            name: 'New Approval Workflow',
            description: 'Custom approval process',
          }),
        });
      });

      it('should validate template structure before creation', async () => {
        const invalidTemplate = {
          name: '', // Empty name
          tasks: [], // No tasks
        };

        await expect(workflowService.createTemplate(invalidTemplate)).rejects.toThrow(
          'Template validation failed'
        );

        expect(mockQdrantClient.workflowTemplate.create).not.toHaveBeenCalled();
      });

      it('should handle template creation with duplicate names', async () => {
        const templateData = {
          name: 'Document Approval Workflow', // Duplicate name
          category: 'approval',
          version: '1.0.0',
        };

        mockQdrantClient.workflowTemplate.findMany.mockResolvedValue(mockWorkflowTemplates);

        await expect(workflowService.createTemplate(templateData)).rejects.toThrow(
          'Template with this name already exists'
        );
      });
    });

    describe('Template Validation', () => {
      it('should validate task dependencies', async () => {
        const templateWithCircularDeps = {
          name: 'Invalid Workflow',
          tasks: [
            {
              id: 'task-1',
              name: 'Task 1',
              type: 'human',
              dependencies: ['task-2'], // Circular dependency
            },
            {
              id: 'task-2',
              name: 'Task 2',
              type: 'human',
              dependencies: ['task-1'], // Circular dependency
            },
          ],
        };

        const validation = await workflowService.validateTemplate(templateWithCircularDeps as any);

        expect(validation.isValid).toBe(false);
        expect(validation.errors).toContain('Circular dependency detected');
      });

      it('should validate required task configurations', async () => {
        const templateWithIncompleteTasks = {
          name: 'Incomplete Workflow',
          tasks: [
            {
              id: 'task-1',
              name: 'Task 1',
              type: 'human',
              // Missing assignee for human task
            },
          ],
        };

        const validation = await workflowService.validateTemplate(
          templateWithIncompleteTasks as any
        );

        expect(validation.isValid).toBe(false);
        expect(validation.errors).toContain('Human tasks require assignee');
      });
    });

    describe('Template Versioning', () => {
      it('should create new version of existing template', async () => {
        const existingTemplate = mockWorkflowTemplates[0];
        const updates = {
          description: 'Updated approval process with enhanced validation',
          tasks: [
            ...existingTemplate.tasks,
            {
              id: 'task-3',
              name: 'Final Review',
              type: 'human',
              assignee: 'final-reviewer@example.com',
              priority: 'medium',
              dependencies: ['task-2'],
            },
          ],
        };

        mockQdrantClient.workflowTemplate.findUnique.mockResolvedValue(existingTemplate);
        mockQdrantClient.workflowVersion.create.mockResolvedValue({
          id: 'version-2',
          templateId: existingTemplate.id,
          version: '1.1.0',
          changes: updates,
          metadata: {
            created_by: 'test-user',
            created_at: '2024-01-01T00:00:00Z',
          },
        });

        const result = await workflowService.createTemplateVersion(existingTemplate.id, updates);

        expect(result).toBeDefined();
        expect(result.version).toBe('1.1.0');
        expect(result.templateId).toBe(existingTemplate.id);
      });

      it('should maintain version history', async () => {
        const templateId = 'template-1';

        mockQdrantClient.workflowVersion.findMany.mockResolvedValue([
          {
            id: 'version-1',
            templateId,
            version: '1.0.0',
            changes: { name: 'Initial version' },
            createdAt: '2024-01-01T00:00:00Z',
          },
          {
            id: 'version-2',
            templateId,
            version: '1.1.0',
            changes: { name: 'Updated version' },
            createdAt: '2024-01-02T00:00:00Z',
          },
        ]);

        const history = await workflowService.getTemplateVersionHistory(templateId);

        expect(history).toHaveLength(2);
        expect(history[0].version).toBe('1.0.0');
        expect(history[1].version).toBe('1.1.0');
      });
    });

    describe('Template Lifecycle Management', () => {
      it('should activate template for use', async () => {
        const templateId = 'template-1';

        mockQdrantClient.workflowTemplate.update.mockResolvedValue({
          id: templateId,
          status: 'active',
          activatedAt: '2024-01-01T00:00:00Z',
        });

        const result = await workflowService.activateTemplate(templateId);

        expect(result.status).toBe('active');
        expect(result.activatedAt).toBeDefined();
      });

      it('should deactivate template', async () => {
        const templateId = 'template-1';

        mockQdrantClient.workflowTemplate.update.mockResolvedValue({
          id: templateId,
          status: 'inactive',
          deactivatedAt: '2024-01-01T00:00:00Z',
        });

        const result = await workflowService.deactivateTemplate(templateId);

        expect(result.status).toBe('inactive');
        expect(result.deactivatedAt).toBeDefined();
      });

      it('should archive outdated template versions', async () => {
        const templateId = 'template-1';

        mockQdrantClient.workflowVersion.findMany.mockResolvedValue([
          {
            id: 'version-1',
            templateId,
            version: '1.0.0',
            status: 'active',
          },
          {
            id: 'version-2',
            templateId,
            version: '1.1.0',
            status: 'active',
          },
        ]);

        mockQdrantClient.workflowVersion.update.mockResolvedValue({
          id: 'version-1',
          status: 'archived',
          archivedAt: '2024-01-01T00:00:00Z',
        });

        const result = await workflowService.archiveTemplateVersions(templateId, '1.1.0');

        expect(result.archived).toHaveLength(1);
        expect(result.archived[0].id).toBe('version-1');
      });
    });

    describe('Dynamic Template Modification', () => {
      it('should allow modification of inactive templates', async () => {
        const templateId = 'template-1';
        const updates = {
          description: 'Modified description',
          tasks: [
            {
              id: 'task-1',
              name: 'Modified Task',
              type: 'human',
              assignee: 'new-assignee@example.com',
            },
          ],
        };

        mockQdrantClient.workflowTemplate.findUnique.mockResolvedValue({
          ...mockWorkflowTemplates[0],
          status: 'inactive',
        });

        mockQdrantClient.workflowTemplate.update.mockResolvedValue({
          id: templateId,
          ...updates,
          updatedAt: '2024-01-01T00:00:00Z',
        });

        const result = await workflowService.modifyTemplate(templateId, updates);

        expect(result.description).toBe('Modified description');
        expect(result.tasks[0].name).toBe('Modified Task');
      });

      it('should prevent modification of active templates with running executions', async () => {
        const templateId = 'template-1';
        const updates = { description: 'Modified description' };

        mockQdrantClient.workflowTemplate.findUnique.mockResolvedValue({
          ...mockWorkflowTemplates[0],
          status: 'active',
        });

        mockQdrantClient.workflowExecution.findMany.mockResolvedValue([
          { status: 'running' },
          { status: 'pending' },
        ]);

        await expect(workflowService.modifyTemplate(templateId, updates)).rejects.toThrow(
          'Cannot modify template with active executions'
        );
      });
    });

    describe('Template Composition and Nesting', () => {
      it('should compose multiple templates into a complex workflow', async () => {
        const composition = {
          name: 'Composed Workflow',
          subWorkflows: [
            { templateId: 'template-1', alias: 'approval' },
            { templateId: 'template-2', alias: 'incident-response' },
          ],
          connections: [{ from: 'approval.task-2', to: 'incident-response.task-3' }],
        };

        mockQdrantClient.workflowTemplate.findMany.mockResolvedValue(mockWorkflowTemplates);
        mockQdrantClient.workflowTemplate.create.mockResolvedValue({
          id: 'composed-template',
          ...composition,
          metadata: {
            created_at: '2024-01-01T00:00:00Z',
          },
        });

        const result = await workflowService.composeTemplates(composition);

        expect(result.name).toBe('Composed Workflow');
        expect(result.subWorkflows).toHaveLength(2);
      });

      it('should validate template composition for conflicts', async () => {
        const invalidComposition = {
          name: 'Invalid Composition',
          subWorkflows: [
            { templateId: 'template-1', alias: 'approval' },
            { templateId: 'template-1', alias: 'duplicate' }, // Duplicate template
          ],
        };

        await expect(workflowService.composeTemplates(invalidComposition)).rejects.toThrow(
          'Duplicate template in composition'
        );
      });
    });
  });

  describe('Workflow Execution', () => {
    describe('Sequential Execution', () => {
      it('should execute workflow tasks in sequential order', async () => {
        const executionRequest: WorkflowExecutionRequest = {
          templateId: 'template-1',
          context: {
            documentId: 'doc-123',
            requestor: 'user@example.com',
          },
          mode: 'sequential',
        };

        mockQdrantClient.workflowTemplate.findUnique.mockResolvedValue(mockWorkflowTemplates[0]);
        mockQdrantClient.workflowExecution.create.mockResolvedValue({
          id: 'execution-1',
          ...executionRequest,
          status: 'running',
          startedAt: '2024-01-01T10:00:00Z',
        });

        const result = await workflowService.executeWorkflow(executionRequest);

        expect(result.status).toBe('running');
        expect(result.templateId).toBe('template-1');
        expect(result.mode).toBe('sequential');
      });

      it('should handle task failures in sequential execution', async () => {
        const executionId = 'execution-1';

        mockQdrantClient.workflowExecution.findUnique.mockResolvedValue({
          ...mockWorkflowExecutions[0],
          currentTask: 'task-1',
        });

        mockQdrantClient.workflowTask.update.mockResolvedValue({
          id: 'task-execution-1',
          status: 'failed',
          error: 'Task execution failed',
          failedAt: '2024-01-01T11:00:00Z',
        });

        mockQdrantClient.workflowExecution.update.mockResolvedValue({
          id: executionId,
          status: 'failed',
          failedAt: '2024-01-01T11:00:00Z',
        });

        const result = await workflowService.failTask(
          executionId,
          'task-1',
          'Task execution failed'
        );

        expect(result.status).toBe('failed');
        expect(result.failedAt).toBeDefined();
      });

      it('should automatically progress to next task on completion', async () => {
        const executionId = 'execution-1';

        mockQdrantClient.workflowExecution.findUnique.mockResolvedValue({
          ...mockWorkflowExecutions[0],
          currentTask: 'task-1',
        });

        mockQdrantClient.workflowTask.update.mockResolvedValue({
          id: 'task-execution-1',
          status: 'completed',
          completedAt: '2024-01-01T10:30:00Z',
        });

        mockQdrantClient.workflowExecution.update.mockResolvedValue({
          id: executionId,
          currentTask: 'task-2',
          status: 'running',
        });

        const result = await workflowService.completeTask(executionId, 'task-1');

        expect(result.currentTask).toBe('task-2');
        expect(result.status).toBe('running');
      });
    });

    describe('Parallel Execution', () => {
      it('should execute parallel tasks simultaneously', async () => {
        const executionRequest: WorkflowExecutionRequest = {
          templateId: 'template-2',
          context: { incidentId: 'inc-456' },
          mode: 'parallel',
        };

        const parallelTemplate = {
          ...mockWorkflowTemplates[1],
          tasks: [
            {
              id: 'parallel-1',
              name: 'Task 1',
              type: 'service',
              dependencies: [],
            },
            {
              id: 'parallel-2',
              name: 'Task 2',
              type: 'service',
              dependencies: [],
            },
          ],
        };

        mockQdrantClient.workflowTemplate.findUnique.mockResolvedValue(parallelTemplate);
        mockQdrantClient.workflowExecution.create.mockResolvedValue({
          id: 'execution-parallel',
          ...executionRequest,
          status: 'running',
          startedAt: '2024-01-01T10:00:00Z',
          currentTasks: ['parallel-1', 'parallel-2'],
        });

        const result = await workflowService.executeWorkflow(executionRequest);

        expect(result.currentTasks).toHaveLength(2);
        expect(result.mode).toBe('parallel');
      });

      it('should wait for all parallel tasks to complete', async () => {
        const executionId = 'execution-parallel';
        const parallelTasks = ['parallel-1', 'parallel-2'];

        mockQdrantClient.workflowExecution.findUnique.mockResolvedValue({
          id: executionId,
          currentTasks: parallelTasks,
          status: 'running',
        });

        mockQdrantClient.workflowTask.findMany.mockResolvedValue([
          { id: 'task-1', taskId: 'parallel-1', status: 'completed' },
          { id: 'task-2', taskId: 'parallel-2', status: 'completed' },
        ]);

        const result = await workflowService.checkParallelCompletion(executionId);

        expect(result.allCompleted).toBe(true);
        expect(result.nextAction).toBe('continue');
      });

      it('should handle partial failures in parallel execution', async () => {
        const executionId = 'execution-parallel';

        mockQdrantClient.workflowExecution.findUnique.mockResolvedValue({
          id: executionId,
          currentTasks: ['parallel-1', 'parallel-2'],
          status: 'running',
        });

        mockQdrantClient.workflowTask.findMany.mockResolvedValue([
          { id: 'task-1', taskId: 'parallel-1', status: 'completed' },
          { id: 'task-2', taskId: 'parallel-2', status: 'failed' },
        ]);

        const result = await workflowService.checkParallelCompletion(executionId);

        expect(result.hasFailures).toBe(true);
        expect(result.failedTasks).toContain('parallel-2');
      });
    });

    describe('Conditional Execution', () => {
      it('should evaluate conditions and branch accordingly', async () => {
        const conditionalTemplate = {
          id: 'template-conditional',
          name: 'Conditional Workflow',
          tasks: [
            {
              id: 'task-1',
              name: 'Initial Task',
              type: 'service',
              dependencies: [],
            },
            {
              id: 'task-2a',
              name: 'Branch A',
              type: 'human',
              dependencies: ['task-1'],
              condition: {
                field: 'context.priority',
                operator: 'equals',
                value: 'high',
              },
            },
            {
              id: 'task-2b',
              name: 'Branch B',
              type: 'service',
              dependencies: ['task-1'],
              condition: {
                field: 'context.priority',
                operator: 'equals',
                value: 'low',
              },
            },
          ],
        };

        const executionRequest: WorkflowExecutionRequest = {
          templateId: 'template-conditional',
          context: { priority: 'high' },
          mode: 'conditional',
        };

        mockQdrantClient.workflowTemplate.findUnique.mockResolvedValue(conditionalTemplate);
        mockQdrantClient.workflowExecution.create.mockResolvedValue({
          id: 'execution-conditional',
          ...executionRequest,
          status: 'running',
          currentTasks: ['task-2a'], // Only branch A selected
        });

        const result = await workflowService.executeWorkflow(executionRequest);

        expect(result.currentTasks).toContain('task-2a');
        expect(result.currentTasks).not.toContain('task-2b');
      });

      it('should handle complex conditional expressions', async () => {
        const complexCondition = {
          and: [
            { field: 'context.amount', operator: '>', value: 1000 },
            {
              or: [
                { field: 'context.region', operator: 'in', value: ['US', 'CA'] },
                { field: 'context.vip', operator: 'equals', value: true },
              ],
            },
          ],
        };

        const context = {
          amount: 1500,
          region: 'US',
          vip: false,
        };

        const result = await workflowService.evaluateCondition(complexCondition, context);

        expect(result).toBe(true);
      });

      it('should support default branches when no conditions match', async () => {
        const templateWithDefault = {
          tasks: [
            {
              id: 'task-1',
              name: 'Initial Task',
              type: 'service',
              dependencies: [],
            },
            {
              id: 'task-default',
              name: 'Default Branch',
              type: 'service',
              dependencies: ['task-1'],
              default: true,
            },
          ],
        };

        const context = { priority: 'medium' }; // Doesn't match any specific conditions

        mockQdrantClient.workflowTemplate.findUnique.mockResolvedValue(templateWithDefault);

        const nextTasks = await workflowService.getNextTasks(
          'task-1',
          context,
          templateWithDefault
        );

        expect(nextTasks).toContain('task-default');
      });
    });

    describe('State Management', () => {
      it('should maintain workflow state across execution', async () => {
        const executionId = 'execution-1';
        const stateUpdate = {
          currentTask: 'task-2',
          variables: {
            approvedAmount: 5000,
            reviewer: 'john.doe@example.com',
          },
        };

        mockQdrantClient.workflowExecution.update.mockResolvedValue({
          id: executionId,
          ...stateUpdate,
          updatedAt: '2024-01-01T10:30:00Z',
        });

        const result = await workflowService.updateWorkflowState(executionId, stateUpdate);

        expect(result.currentTask).toBe('task-2');
        expect(result.variables.approvedAmount).toBe(5000);
      });

      it('should support state rollback on failure', async () => {
        const executionId = 'execution-1';
        const previousState = {
          currentTask: 'task-1',
          variables: { step: 'initial' },
        };

        mockQdrantClient.workflowExecution.update.mockResolvedValue({
          id: executionId,
          ...previousState,
          rolledBackAt: '2024-01-01T11:00:00Z',
        });

        const result = await workflowService.rollbackWorkflowState(executionId, previousState);

        expect(result.currentTask).toBe('task-1');
        expect(result.rolledBackAt).toBeDefined();
      });

      it('should persist state for long-running workflows', async () => {
        const executionId = 'execution-long-running';

        mockQdrantClient.workflowExecution.findUnique.mockResolvedValue({
          id: executionId,
          status: 'suspended',
          state: {
            checkpoint: 'task-5',
            variables: { progress: 0.6 },
          },
          suspendedAt: '2024-01-01T15:00:00Z',
        });

        const result = await workflowService.resumeWorkflow(executionId);

        expect(result.status).toBe('running');
        expect(result.state.checkpoint).toBe('task-5');
      });
    });
  });

  describe('Task Orchestration', () => {
    describe('Task Assignment and Routing', () => {
      it('should assign tasks to appropriate users', async () => {
        const taskAssignment: TaskAssignment = {
          taskId: 'task-1',
          executionId: 'execution-1',
          assignee: 'reviewer@example.com',
          assignedBy: 'system',
          assignedAt: '2024-01-01T10:00:00Z',
        };

        mockQdrantClient.workflowTask.create.mockResolvedValue({
          id: 'task-assignment-1',
          ...taskAssignment,
          status: 'assigned',
        });

        const result = await workflowService.assignTask(taskAssignment);

        expect(result.assignee).toBe('reviewer@example.com');
        expect(result.status).toBe('assigned');
      });

      it('should route tasks based on skills and availability', async () => {
        const taskRequirements = {
          type: 'technical-review',
          skills: ['javascript', 'security'],
          priority: 'high',
          estimatedDuration: 3600,
        };

        const availableUsers = [
          { id: 'user-1', skills: ['javascript', 'react'], workload: 0.6 },
          { id: 'user-2', skills: ['security', 'python'], workload: 0.3 },
          { id: 'user-3', skills: ['javascript', 'security'], workload: 0.2 },
        ];

        const bestAssignee = await workflowService.findBestAssignee(
          taskRequirements,
          availableUsers
        );

        expect(bestAssignee.id).toBe('user-3'); // Best skill match and lowest workload
      });

      it('should support task reassignment', async () => {
        const taskExecutionId = 'task-execution-1';
        const newAssignee = 'new-reviewer@example.com';

        mockQdrantClient.workflowTask.update.mockResolvedValue({
          id: taskExecutionId,
          assignee: newAssignee,
          reassignedAt: '2024-01-01T11:00:00Z',
          previousAssignee: 'old-reviewer@example.com',
        });

        const result = await workflowService.reassignTask(taskExecutionId, newAssignee);

        expect(result.assignee).toBe(newAssignee);
        expect(result.reassignedAt).toBeDefined();
      });
    });

    describe('Task Dependencies', () => {
      it('should respect task dependency chains', async () => {
        const tasksWithDependencies = [
          {
            id: 'task-1',
            name: 'Setup',
            dependencies: [],
          },
          {
            id: 'task-2',
            name: 'Configuration',
            dependencies: ['task-1'],
          },
          {
            id: 'task-3',
            name: 'Deployment',
            dependencies: ['task-1', 'task-2'],
          },
        ];

        const executionPlan = await workflowService.createExecutionPlan(tasksWithDependencies);

        expect(executionPlan.phases).toHaveLength(3);
        expect(executionPlan.phases[0].tasks).toContain('task-1');
        expect(executionPlan.phases[1].tasks).toContain('task-2');
        expect(executionPlan.phases[2].tasks).toContain('task-3');
      });

      it('should detect and prevent circular dependencies', async () => {
        const tasksWithCircularDeps = [
          {
            id: 'task-1',
            dependencies: ['task-2'],
          },
          {
            id: 'task-2',
            dependencies: ['task-3'],
          },
          {
            id: 'task-3',
            dependencies: ['task-1'], // Circular
          },
        ];

        await expect(workflowService.createExecutionPlan(tasksWithCircularDeps)).rejects.toThrow(
          'Circular dependency detected'
        );
      });

      it('should handle optional dependencies', async () => {
        const tasksWithOptionalDeps = [
          {
            id: 'task-1',
            dependencies: [],
          },
          {
            id: 'task-2',
            dependencies: [{ taskId: 'task-1', required: false }],
          },
          {
            id: 'task-3',
            dependencies: ['task-2'],
          },
        ];

        const plan = await workflowService.createExecutionPlan(tasksWithOptionalDeps);

        expect(plan.phases[0].tasks).toContain('task-1');
        expect(plan.phases[0].tasks).toContain('task-2'); // Can start with optional dep
      });
    });

    describe('Task Timeout and Retry Handling', () => {
      it('should handle task timeouts', async () => {
        const taskExecutionId = 'task-execution-1';
        const timeoutConfig = {
          duration: 3600,
          action: 'escalate',
          escalationTarget: 'manager@example.com',
        };

        mockQdrantClient.workflowTask.findUnique.mockResolvedValue({
          id: taskExecutionId,
          status: 'assigned',
          assignedAt: '2024-01-01T08:00:00Z',
          deadline: '2024-01-01T09:00:00Z',
        });

        mockQdrantClient.workflowTask.update.mockResolvedValue({
          id: taskExecutionId,
          status: 'timeout',
          timeoutAt: '2024-01-01T09:00:00Z',
        });

        const result = await workflowService.handleTaskTimeout(taskExecutionId, timeoutConfig);

        expect(result.status).toBe('timeout');
        expect(result.timeoutAt).toBeDefined();
      });

      it('should implement retry logic for failed tasks', async () => {
        const taskExecutionId = 'task-execution-1';
        const retryConfig = {
          maxRetries: 3,
          backoffStrategy: 'exponential',
          initialDelay: 1000,
        };

        mockQdrantClient.workflowTask.findUnique.mockResolvedValue({
          id: taskExecutionId,
          status: 'failed',
          retryCount: 1,
          lastFailureAt: '2024-01-01T10:00:00Z',
        });

        mockQdrantClient.workflowTask.update.mockResolvedValue({
          id: taskExecutionId,
          status: 'retrying',
          retryCount: 2,
          nextRetryAt: '2024-01-01T10:04:00Z', // Exponential backoff
        });

        const result = await workflowService.retryTask(taskExecutionId, retryConfig);

        expect(result.status).toBe('retrying');
        expect(result.retryCount).toBe(2);
      });

      it('should escalate tasks after max retries', async () => {
        const taskExecutionId = 'task-execution-1';

        mockQdrantClient.workflowTask.findUnique.mockResolvedValue({
          id: taskExecutionId,
          status: 'failed',
          retryCount: 3,
          maxRetries: 3,
        });

        mockQdrantClient.workflowTask.update.mockResolvedValue({
          id: taskExecutionId,
          status: 'escalated',
          escalatedAt: '2024-01-01T11:00:00Z',
          escalatedTo: 'manager@example.com',
        });

        const result = await workflowService.retryTask(taskExecutionId, { maxRetries: 3 });

        expect(result.status).toBe('escalated');
        expect(result.escalatedAt).toBeDefined();
      });
    });

    describe('Task Completion Tracking', () => {
      it('should track individual task completion metrics', async () => {
        const executionId = 'execution-1';

        mockQdrantClient.workflowTask.findMany.mockResolvedValue([
          {
            id: 'task-1',
            status: 'completed',
            completedAt: '2024-01-01T10:30:00Z',
            actualDuration: 1800,
            estimatedDuration: 3600,
          },
          {
            id: 'task-2',
            status: 'completed',
            completedAt: '2024-01-01T11:00:00Z',
            actualDuration: 900,
            estimatedDuration: 1800,
          },
        ]);

        const metrics = await workflowService.getTaskCompletionMetrics(executionId);

        expect(metrics.totalTasks).toBe(2);
        expect(metrics.completedTasks).toBe(2);
        expect(metrics.averageAccuracy).toBeGreaterThan(0.5); // Actual vs estimated
      });

      it('should identify tasks consistently over or under time estimates', async () => {
        const taskHistory = [
          { taskId: 'task-1', actualDuration: 7200, estimatedDuration: 3600 },
          { taskId: 'task-1', actualDuration: 6300, estimatedDuration: 3600 },
          { taskId: 'task-1', actualDuration: 8100, estimatedDuration: 3600 },
          { taskId: 'task-2', actualDuration: 1800, estimatedDuration: 3600 },
          { taskId: 'task-2', actualDuration: 1500, estimatedDuration: 3600 },
        ];

        const analysis = await workflowService.analyzeTaskEstimates(taskHistory);

        expect(analysis['task-1'].consistentlyLate).toBe(true);
        expect(analysis['task-1'].recommendedMultiplier).toBeGreaterThan(1.5);
        expect(analysis['task-2'].consistentlyEarly).toBe(true);
      });
    });
  });

  describe('Human Workflow Integration', () => {
    describe('User Task Assignment', () => {
      it('should create human tasks with proper metadata', async () => {
        const humanTask: HumanTask = {
          id: 'human-task-1',
          name: 'Document Review',
          description: 'Review the attached document for compliance',
          assignee: 'reviewer@example.com',
          priority: 'high',
          dueDate: '2024-01-02T17:00:00Z',
          metadata: {
            documentId: 'doc-123',
            reviewType: 'compliance',
          },
        };

        mockQdrantClient.workflowTask.create.mockResolvedValue({
          id: 'task-assignment-1',
          ...humanTask,
          status: 'assigned',
          assignedAt: '2024-01-01T10:00:00Z',
        });

        const result = await workflowService.createHumanTask(humanTask);

        expect(result.assignee).toBe('reviewer@example.com');
        expect(result.dueDate).toBe('2024-01-02T17:00:00Z');
        expect(result.metadata['documentId']).toBe('doc-123');
      });

      it('should support bulk task assignment', async () => {
        const bulkAssignments = [
          {
            taskId: 'task-1',
            assignee: 'user1@example.com',
            priority: 'high',
          },
          {
            taskId: 'task-2',
            assignee: 'user2@example.com',
            priority: 'medium',
          },
          {
            taskId: 'task-3',
            assignee: 'user3@example.com',
            priority: 'low',
          },
        ];

        mockQdrantClient.$transaction.mockImplementation(async (callback) => {
          return await callback(mockQdrantClient);
        });

        const results = await workflowService.bulkAssignTasks(bulkAssignments);

        expect(results).toHaveLength(3);
        expect(results[0].assignee).toBe('user1@example.com');
        expect(results[1].assignee).toBe('user2@example.com');
        expect(results[2].assignee).toBe('user3@example.com');
      });

      it('should handle user workload balancing', async () => {
        const users = ['user1@example.com', 'user2@example.com', 'user3@example.com'];
        const tasks = Array(5)
          .fill(null)
          .map((_, i) => ({
            id: `task-${i}`,
            estimatedDuration: 3600,
          }));

        mockQdrantClient.workflowTask.findMany.mockResolvedValue([
          { assignee: 'user1@example.com', activeTasks: 3 },
          { assignee: 'user2@example.com', activeTasks: 1 },
          { assignee: 'user3@example.com', activeTasks: 2 },
        ]);

        const assignments = await workflowService.balanceTaskAssignment(tasks, users);

        // User2 has lowest workload, should get more tasks
        const user2Tasks = assignments.filter((a) => a.assignee === 'user2@example.com');
        expect(user2Tasks.length).toBeGreaterThanOrEqual(2);
      });
    });

    describe('Approval Workflows', () => {
      it('should create approval tasks with voting mechanisms', async () => {
        const approvalTask: ApprovalTask = {
          id: 'approval-1',
          name: 'Budget Approval',
          description: 'Approve the proposed budget allocation',
          approvers: ['manager1@example.com', 'manager2@example.com', 'manager3@example.com'],
          requiredApprovals: 2,
          votingMethod: 'majority',
          deadline: '2024-01-03T17:00:00Z',
        };

        mockQdrantClient.workflowTask.create.mockResolvedValue({
          id: 'approval-task-1',
          ...approvalTask,
          status: 'pending_approval',
          createdAt: '2024-01-01T10:00:00Z',
        });

        const result = await workflowService.createApprovalTask(approvalTask);

        expect(result.approvers).toHaveLength(3);
        expect(result.requiredApprovals).toBe(2);
        expect(result.votingMethod).toBe('majority');
      });

      it('should process approval votes and determine outcome', async () => {
        const approvalTaskId = 'approval-task-1';
        const votes = [
          { approver: 'manager1@example.com', decision: 'approve', comment: 'Looks good' },
          { approver: 'manager2@example.com', decision: 'approve', comment: 'Approved' },
          { approver: 'manager3@example.com', decision: 'reject', comment: 'Needs revision' },
        ];

        mockQdrantClient.workflowTask.findUnique.mockResolvedValue({
          id: approvalTaskId,
          requiredApprovals: 2,
          approvers: ['manager1@example.com', 'manager2@example.com', 'manager3@example.com'],
        });

        const outcome = await workflowService.processApprovalVotes(approvalTaskId, votes);

        expect(outcome.approved).toBe(true);
        expect(outcome.approvalCount).toBe(2);
        expect(outcome.rejectionCount).toBe(1);
      });

      it('should handle conditional approval logic', async () => {
        const conditionalApproval = {
          id: 'conditional-approval',
          name: 'High-Value Approval',
          conditions: [
            {
              field: 'amount',
              operator: '>',
              value: 10000,
              requiredApprovals: 3,
            },
            {
              field: 'department',
              operator: 'equals',
              value: 'finance',
              requiredApprovals: 2,
            },
          ],
          defaultApprovals: 1,
        };

        const context = {
          amount: 15000,
          department: 'finance',
        };

        const requiredApprovals = await workflowService.calculateRequiredApprovals(
          conditionalApproval,
          context
        );

        expect(requiredApprovals).toBe(3); // High amount condition takes precedence
      });
    });

    describe('Escalation Procedures', () => {
      it('should automatically escalate overdue tasks', async () => {
        const escalationTask: EscalationTask = {
          id: 'escalation-1',
          originalTaskId: 'task-1',
          escalationLevel: 1,
          escalatedTo: 'manager@example.com',
          reason: 'timeout',
          originalDeadline: '2024-01-01T17:00:00Z',
          newDeadline: '2024-01-02T10:00:00Z',
        };

        mockQdrantClient.workflowTask.create.mockResolvedValue({
          id: 'escalation-task-1',
          ...escalationTask,
          status: 'escalated',
          escalatedAt: '2024-01-01T18:00:00Z',
        });

        const result = await workflowService.createEscalationTask(escalationTask);

        expect(result.escalatedTo).toBe('manager@example.com');
        expect(result.reason).toBe('timeout');
        expect(result.escalationLevel).toBe(1);
      });

      it('should support multi-level escalation chains', async () => {
        const escalationChain = [
          { level: 1, target: 'manager@example.com', delay: 3600 },
          { level: 2, target: 'director@example.com', delay: 7200 },
          { level: 3, target: 'vp@example.com', delay: 14400 },
        ];

        const currentLevel = 2;
        const nextEscalation = await workflowService.getNextEscalation(
          escalationChain,
          currentLevel
        );

        expect(nextEscalation.level).toBe(3);
        expect(nextEscalation.target).toBe('vp@example.com');
        expect(nextEscalation.delay).toBe(14400);
      });

      it('should track escalation effectiveness', async () => {
        const escalationAnalytics = await workflowService.getEscalationAnalytics(
          '2024-01-01',
          '2024-01-31'
        );

        expect(escalationAnalytics.totalEscalations).toBeDefined();
        expect(escalationAnalytics.resolvedAfterEscalation).toBeDefined();
        expect(escalationAnalytics.averageEscalationTime).toBeDefined();
        expect(escalationAnalytics.escalationByLevel).toBeDefined();
      });
    });

    describe('Notification Integration', () => {
      it('should send task assignment notifications', async () => {
        const notification: WorkflowNotification = {
          type: 'task_assigned',
          recipient: 'user@example.com',
          taskId: 'task-1',
          workflowId: 'workflow-1',
          message: 'You have been assigned a new task',
          channels: ['email', 'slack'],
          priority: 'high',
          scheduledAt: '2024-01-01T10:00:00Z',
        };

        const mockNotificationService = {
          sendNotification: vi.fn().mockResolvedValue({ id: 'notif-1', sent: true }),
        };

        const result = await workflowService.sendNotification(
          notification,
          mockNotificationService
        );

        expect(result.sent).toBe(true);
        expect(mockNotificationService.sendNotification).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'task_assigned',
            recipient: 'user@example.com',
          })
        );
      });

      it('should support notification templates and personalization', async () => {
        const template = {
          name: 'Task Reminder',
          subject: 'Reminder: {{task.name}} is due soon',
          body: 'Hi {{user.name}}, your task "{{task.name}}" is due on {{task.dueDate}}',
        };

        const context = {
          user: { name: 'John Doe' },
          task: { name: 'Document Review', dueDate: '2024-01-02T17:00:00Z' },
        };

        const personalized = await workflowService.personalizeNotification(template, context);

        expect(personalized.subject).toBe('Reminder: Document Review is due soon');
        expect(personalized.body).toContain('Hi John Doe');
        expect(personalized.body).toContain('Document Review');
      });

      it('should handle notification preferences and schedules', async () => {
        const userPreferences = {
          emailNotifications: true,
          slackNotifications: false,
          workingHoursOnly: true,
          timezone: 'America/New_York',
          quietHours: { start: '18:00', end: '08:00' },
        };

        const notification = {
          type: 'task_reminder',
          recipient: 'user@example.com',
          scheduledAt: '2024-01-01T20:00:00Z', // During quiet hours
        };

        const adjustedSchedule = await workflowService.adjustNotificationSchedule(
          notification,
          userPreferences
        );

        expect(adjustedSchedule.scheduledAt).not.toBe('2024-01-01T20:00:00Z');
        expect(adjustedSchedule.channels).not.toContain('slack');
      });
    });
  });

  describe('Monitoring and Analytics', () => {
    describe('Workflow Execution Metrics', () => {
      it('should calculate comprehensive execution metrics', async () => {
        const timeRange = { start: '2024-01-01', end: '2024-01-31' };

        mockQdrantClient.workflowExecution.findMany.mockResolvedValue([
          { status: 'completed', duration: 7200, startedAt: '2024-01-01T10:00:00Z' },
          { status: 'completed', duration: 5400, startedAt: '2024-01-02T11:00:00Z' },
          { status: 'failed', duration: 3600, startedAt: '2024-01-03T09:00:00Z' },
          { status: 'running', duration: 1800, startedAt: '2024-01-04T08:00:00Z' },
        ]);

        const metrics = await workflowService.getExecutionMetrics(timeRange);

        expect(metrics.totalExecutions).toBe(4);
        expect(metrics.completedExecutions).toBe(2);
        expect(metrics.failedExecutions).toBe(1);
        expect(metrics.runningExecutions).toBe(1);
        expect(metrics.successRate).toBe(0.5);
        expect(metrics.averageDuration).toBeGreaterThan(0);
      });

      it('should track workflow performance trends over time', async () => {
        const monthlyData = await workflowService.getPerformanceTrends('2023-01-01', '2024-01-01');

        expect(monthlyData.monthlyStats).toHaveLength(12);
        expect(monthlyData.trends).toBeDefined();
        expect(monthlyData.seasonalPatterns).toBeDefined();
        expect(monthlyData.predictions).toBeDefined();
      });

      it('should compare performance across workflow templates', async () => {
        const templateComparison = await workflowService.compareTemplatePerformance([
          'template-1',
          'template-2',
          'template-3',
        ]);

        expect(templateComparison).toHaveLength(3);
        expect(templateComparison[0]).toHaveProperty('templateId');
        expect(templateComparison[0]).toHaveProperty('averageDuration');
        expect(templateComparison[0]).toHaveProperty('successRate');
        expect(templateComparison[0]).toHaveProperty('userSatisfaction');
      });
    });

    describe('Performance Monitoring', () => {
      it('should identify workflow performance bottlenecks', async () => {
        const performanceData: WorkflowPerformanceData[] = [
          {
            taskId: 'task-1',
            averageDuration: 7200,
            queueTime: 1800,
            executionTime: 5400,
            failureRate: 0.1,
          },
          {
            taskId: 'task-2',
            averageDuration: 14400,
            queueTime: 7200,
            executionTime: 7200,
            failureRate: 0.3,
          },
        ];

        const bottlenecks = await workflowService.identifyBottlenecks(performanceData);

        expect(bottlenecks).toHaveLength(1);
        expect(bottlenecks[0].taskId).toBe('task-2');
        expect(bottlenecks[0].issues).toContain('High failure rate');
        expect(bottlenecks[0].recommendations).toBeDefined();
      });

      it('should monitor resource utilization', async () => {
        const resourceMetrics = await workflowService.getResourceUtilization();

        expect(resourceMetrics).toHaveProperty('cpuUsage');
        expect(resourceMetrics).toHaveProperty('memoryUsage');
        expect(resourceMetrics).toHaveProperty('activeWorkers');
        expect(resourceMetrics).toHaveProperty('queueLength');
        expect(resourceMetrics).toHaveProperty('throughput');
      });

      it('should provide real-time execution monitoring', async () => {
        const activeExecutions = await workflowService.getActiveExecutions();

        expect(Array.isArray(activeExecutions)).toBe(true);
        if (activeExecutions.length > 0) {
          expect(activeExecutions[0]).toHaveProperty('id');
          expect(activeExecutions[0]).toHaveProperty('status');
          expect(activeExecutions[0]).toHaveProperty('progress');
          expect(activeExecutions[0]).toHaveProperty('estimatedCompletion');
        }
      });
    });

    describe('Workflow Analytics', () => {
      it('should generate comprehensive workflow analytics', async () => {
        const analytics = await workflowService.generateWorkflowAnalytics(
          'template-1',
          '2024-01-01',
          '2024-01-31'
        );

        expect(analytics).toHaveProperty('executionMetrics');
        expect(analytics).toHaveProperty('taskPerformance');
        expect(analytics).toHaveProperty('userProductivity');
        expect(analytics).toHaveProperty('errorAnalysis');
        expect(analytics).toHaveProperty('optimizationSuggestions');
      });

      it('should analyze user productivity and workload', async () => {
        const userId = 'user@example.com';
        const productivityAnalytics = await workflowService.getUserProductivityAnalytics(userId);

        expect(productivityAnalytics).toHaveProperty('tasksCompleted');
        expect(productivityAnalytics).toHaveProperty('averageCompletionTime');
        expect(productivityAnalytics).toHaveProperty('workloadDistribution');
        expect(productivityAnalytics).toHaveProperty('skillUtilization');
        expect(productivityAnalytics).toHaveProperty('satisfactionScore');
      });

      it('should predict workflow completion times', async () => {
        const executionRequest: WorkflowExecutionRequest = {
          templateId: 'template-1',
          context: { complexity: 'high' },
        };

        const prediction = await workflowService.predictCompletionTime(executionRequest);

        expect(prediction).toHaveProperty('estimatedDuration');
        expect(prediction).toHaveProperty('confidence');
        expect(prediction).toHaveProperty('factors');
        expect(prediction).toHaveProperty('possibleDelays');
      });
    });

    describe('Bottleneck Identification', () => {
      it('should identify systematic bottlenecks across workflows', async () => {
        const bottleneckAnalysis = await workflowService.identifySystematicBottlenecks();

        expect(bottleneckAnalysis).toHaveProperty('taskBottlenecks');
        expect(bottleneckAnalysis).toHaveProperty('userBottlenecks');
        expect(bottleneckAnalysis).toHaveProperty('resourceBottlenecks');
        expect(bottleneckAnalysis).toHaveProperty('recommendations');
      });

      it('should suggest workflow optimizations', async () => {
        const optimizationSuggestions =
          await workflowService.getOptimizationSuggestions('template-1');

        expect(Array.isArray(optimizationSuggestions)).toBe(true);
        if (optimizationSuggestions.length > 0) {
          expect(optimizationSuggestions[0]).toHaveProperty('type');
          expect(optimizationSuggestions[0]).toHaveProperty('description');
          expect(optimizationSuggestions[0]).toHaveProperty('impact');
          expect(optimizationSuggestions[0]).toHaveProperty('effort');
        }
      });

      it('should track bottleneck resolution effectiveness', async () => {
        const resolutionId = 'resolution-1';
        const effectivenessReport =
          await workflowService.getBottleneckResolutionEffectiveness(resolutionId);

        expect(effectivenessReport).toHaveProperty('beforeMetrics');
        expect(effectivenessReport).toHaveProperty('afterMetrics');
        expect(effectivenessReport).toHaveProperty('improvementPercentage');
        expect(effectivenessReport).toHaveProperty('roi');
      });
    });

    describe('Reporting', () => {
      it('should generate comprehensive workflow reports', async () => {
        const reportRequest = {
          type: 'comprehensive',
          templateIds: ['template-1', 'template-2'],
          dateRange: { start: '2024-01-01', end: '2024-01-31' },
          includeMetrics: true,
          includeAnalytics: true,
          includeRecommendations: true,
        };

        const report = await workflowService.generateReport(reportRequest);

        expect(report).toHaveProperty('summary');
        expect(report).toHaveProperty('metrics');
        expect(report).toHaveProperty('analytics');
        expect(report).toHaveProperty('recommendations');
        expect(report).toHaveProperty('visualizations');
      });

      it('should export reports in multiple formats', async () => {
        const reportData = { summary: 'Test report', metrics: {} };

        const pdfExport = await workflowService.exportReport(reportData, 'pdf');
        const excelExport = await workflowService.exportReport(reportData, 'excel');
        const jsonExport = await workflowService.exportReport(reportData, 'json');

        expect(pdfExport).toHaveProperty('data');
        expect(pdfExport).toHaveProperty('filename');
        expect(excelExport).toHaveProperty('data');
        expect(excelExport).toHaveProperty('filename');
        expect(jsonExport).toHaveProperty('data');
        expect(jsonExport.filename).toMatch(/\.json$/);
      });
    });
  });

  describe('Integration with Services', () => {
    describe('Service Task Integration', () => {
      it('should execute service tasks with proper integration', async () => {
        const serviceTask: ServiceTask = {
          id: 'service-task-1',
          name: 'Data Validation',
          serviceConfig: {
            serviceName: 'validation-service',
            endpoint: '/api/validate',
            method: 'POST',
            payload: { data: 'test' },
            timeout: 30000,
            retryConfig: { maxRetries: 3 },
          },
        };

        mockQdrantClient.workflowTask.create.mockResolvedValue({
          id: 'service-execution-1',
          ...serviceTask,
          status: 'running',
          startedAt: '2024-01-01T10:00:00Z',
        });

        const result = await workflowService.executeServiceTask(serviceTask);

        expect(result.status).toBe('running');
        expect(result.serviceConfig).toBeDefined();
      });

      it('should handle service task responses and errors', async () => {
        const taskExecutionId = 'service-execution-1';
        const serviceResponse = {
          status: 200,
          data: { result: 'success', validated: true },
          executionTime: 1500,
        };

        mockQdrantClient.workflowTask.update.mockResolvedValue({
          id: taskExecutionId,
          status: 'completed',
          result: serviceResponse,
          completedAt: '2024-01-01T10:01:30Z',
        });

        const result = await workflowService.completeServiceTask(taskExecutionId, serviceResponse);

        expect(result.status).toBe('completed');
        expect(result.result).toBeDefined();
      });

      it('should implement service task circuit breaker pattern', async () => {
        const serviceName = 'unstable-service';

        // Simulate multiple failures
        const failures = Array(5)
          .fill(null)
          .map((_, i) => ({
            timestamp: Date.now() - i * 60000,
            error: 'Service unavailable',
          }));

        const circuitState = await workflowService.checkCircuitBreaker(serviceName, failures);

        expect(circuitState.isOpen).toBe(true);
        expect(circuitState.openUntil).toBeDefined();
      });
    });

    describe('Cross-Service Workflows', () => {
      it('should orchestrate workflows across multiple services', async () => {
        const crossServiceWorkflow = {
          name: 'Multi-Service Onboarding',
          services: [
            {
              name: 'user-service',
              tasks: ['create-user', 'send-welcome'],
            },
            {
              name: 'billing-service',
              tasks: ['create-account', 'setup-billing'],
            },
            {
              name: 'notification-service',
              tasks: ['setup-preferences', 'send-onboarding'],
            },
          ],
          dependencies: [
            { from: 'user-service.create-user', to: 'billing-service.create-account' },
            {
              from: 'billing-service.create-account',
              to: 'notification-service.setup-preferences',
            },
          ],
        };

        const execution = await workflowService.executeCrossServiceWorkflow(crossServiceWorkflow);

        expect(execution.status).toBe('running');
        expect(execution.serviceExecutions).toHaveLength(3);
        expect(execution.currentPhase).toBeDefined();
      });

      it('should handle service communication failures gracefully', async () => {
        const serviceFailure = {
          service: 'user-service',
          task: 'create-user',
          error: 'Connection timeout',
          retryCount: 2,
        };

        const recoveryAction = await workflowService.handleServiceFailure(serviceFailure);

        expect(recoveryAction).toHaveProperty('action');
        expect(recoveryAction).toHaveProperty('fallbackAvailable');
        expect(recoveryAction).toHaveProperty('estimatedRecoveryTime');
      });

      it('should maintain data consistency across services', async () => {
        const transaction = {
          operations: [
            { service: 'user-service', action: 'create', data: { name: 'John' } },
            { service: 'billing-service', action: 'create', data: { userId: '123' } },
            { service: 'notification-service', action: 'update', data: { userId: '123' } },
          ],
        };

        const result = await workflowService.executeDistributedTransaction(transaction);

        expect(result.success).toBe(true);
        expect(result.operations).toHaveLength(3);
        expect(result.rollbackAvailable).toBe(true);
      });
    });

    describe('Event-Driven Workflows', () => {
      it('should trigger workflows based on events', async () => {
        const workflowEvent: WorkflowEvent = {
          type: 'user_registered',
          source: 'user-service',
          data: {
            userId: 'user-123',
            email: 'user@example.com',
            plan: 'premium',
          },
          timestamp: '2024-01-01T10:00:00Z',
        };

        const triggeredWorkflows = await workflowService.processEvent(workflowEvent);

        expect(Array.isArray(triggeredWorkflows)).toBe(true);
        if (triggeredWorkflows.length > 0) {
          expect(triggeredWorkflows[0]).toHaveProperty('workflowId');
          expect(triggeredWorkflows[0]).toHaveProperty('executionId');
          expect(triggeredWorkflows[0]).toHaveProperty('triggeredBy');
        }
      });

      it('should support complex event patterns and correlations', async () => {
        const eventPattern = {
          name: 'Premium Onboarding',
          conditions: [
            { field: 'type', operator: 'equals', value: 'user_registered' },
            { field: 'data.plan', operator: 'equals', value: 'premium' },
            { field: 'data.source', operator: 'in', value: ['website', 'referral'] },
          ],
          timeframe: 3600,
          correlationId: 'session-123',
        };

        const matchingEvents = [
          { type: 'user_registered', data: { plan: 'premium' }, timestamp: Date.now() },
          { type: 'profile_completed', data: { userId: 'user-123' }, timestamp: Date.now() + 1800 },
        ];

        const patternMatch = await workflowService.evaluateEventPattern(
          eventPattern,
          matchingEvents
        );

        expect(patternMatch.matches).toBe(true);
        expect(patternMatch.confidence).toBeGreaterThan(0.8);
      });

      it('should handle event-driven workflow chaining', async () => {
        const eventChain = [
          { event: 'user_registered', triggers: ['welcome-sequence'] },
          { event: 'profile_completed', triggers: ['profile-review'] },
          { event: 'first-purchase', triggers: ['billing-setup', 'loyalty-enrollment'] },
        ];

        const completedEvents = ['user_registered', 'profile_completed'];
        const activeWorkflows = await workflowService.getActiveEventDrivenChains(
          eventChain,
          completedEvents
        );

        expect(activeWorkflows).toContain('welcome-sequence');
        expect(activeWorkflows).toContain('profile-review');
        expect(activeWorkflows).not.toContain('loyalty-enrollment');
      });
    });

    describe('API Workflow Triggers', () => {
      it('should provide REST API endpoints for workflow management', async () => {
        const apiRequest = {
          method: 'POST',
          endpoint: '/api/workflows',
          body: {
            templateId: 'template-1',
            context: { userId: 'user-123' },
            priority: 'high',
          },
          headers: { Authorization: 'Bearer token-123' },
        };

        const response = await workflowService.handleApiRequest(apiRequest);

        expect(response.status).toBe(201);
        expect(response.data).toHaveProperty('executionId');
        expect(response.data).toHaveProperty('status');
      });

      it('should support webhook-based workflow triggers', async () => {
        const webhookPayload = {
          event: 'github.push',
          repository: 'example/repo',
          branch: 'main',
          commits: [{ id: 'abc123', message: 'Update workflow' }],
        };

        const webhookResult = await workflowService.processWebhook('github', webhookPayload);

        expect(webhookResult.processed).toBe(true);
        expect(webhookResult.triggeredWorkflows).toBeDefined();
      });

      it('should implement proper API authentication and authorization', async () => {
        const unauthorizedRequest = {
          method: 'POST',
          endpoint: '/api/workflows',
          headers: { Authorization: 'Invalid token' },
        };

        const response = await workflowService.handleApiRequest(unauthorizedRequest);

        expect(response.status).toBe(401);
        expect(response.error).toContain('Unauthorized');
      });
    });

    describe('Service Health Monitoring', () => {
      it('should monitor health of integrated services', async () => {
        const serviceHealth = await workflowService.checkServiceHealth();

        expect(serviceHealth).toHaveProperty('overall');
        expect(serviceHealth).toHaveProperty('services');

        if (serviceHealth.services.length > 0) {
          expect(serviceHealth.services[0]).toHaveProperty('name');
          expect(serviceHealth.services[0]).toHaveProperty('status');
          expect(serviceHealth.services[0]).toHaveProperty('responseTime');
          expect(serviceHealth.services[0]).toHaveProperty('lastCheck');
        }
      });

      it('should automatically failover to backup services', async () => {
        const primaryService = {
          name: 'user-service',
          url: 'https://primary.user-service.com',
          status: 'unhealthy',
        };

        const backupService = {
          name: 'user-service-backup',
          url: 'https://backup.user-service.com',
          status: 'healthy',
        };

        const failoverResult = await workflowService.executeFailover(primaryService, backupService);

        expect(failoverResult.success).toBe(true);
        expect(failoverResult.usingBackup).toBe(true);
        expect(failoverResult.backupUrl).toBe(backupService.url);
      });

      it('should provide service performance analytics', async () => {
        const performanceAnalytics =
          await workflowService.getServicePerformanceAnalytics('user-service');

        expect(performanceAnalytics).toHaveProperty('averageResponseTime');
        expect(performanceAnalytics).toHaveProperty('successRate');
        expect(performanceAnalytics).toHaveProperty('errorRate');
        expect(performanceAnalytics).toHaveProperty('throughput');
        expect(performanceAnalytics).toHaveProperty('p95ResponseTime');
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle concurrent workflow execution conflicts', async () => {
      const conflictingRequests = [
        { templateId: 'template-1', context: { resource: 'shared-1' } },
        { templateId: 'template-1', context: { resource: 'shared-1' } },
      ];

      const firstExecution = await workflowService.executeWorkflow(conflictingRequests[0]);

      await expect(workflowService.executeWorkflow(conflictingRequests[1])).rejects.toThrow(
        'Resource conflict detected'
      );
    });

    it('should handle database connection failures gracefully', async () => {
      mockQdrantClient.workflowExecution.create.mockRejectedValue(
        new Error('Database connection failed')
      );

      await expect(workflowService.executeWorkflow({ templateId: 'template-1' })).rejects.toThrow(
        'Unable to start workflow'
      );

      // Verify retry mechanism
      expect(mockQdrantClient.workflowExecution.create).toHaveBeenCalledTimes(3);
    });

    it('should validate workflow configuration before execution', async () => {
      const invalidConfiguration = {
        templateId: 'invalid-template',
        context: null,
        mode: 'invalid-mode',
      };

      await expect(workflowService.executeWorkflow(invalidConfiguration)).rejects.toThrow(
        'Invalid workflow configuration'
      );
    });

    it('should handle large workflow data sets efficiently', async () => {
      const largeWorkflow = {
        templateId: 'large-template',
        context: { data: Array(10000).fill('test data') },
      };

      // Mock streaming response for large data
      mockQdrantClient.workflowExecution.create.mockResolvedValue({
        id: 'large-execution',
        status: 'running',
        streaming: true,
      });

      const result = await workflowService.executeWorkflow(largeWorkflow);

      expect(result.streaming).toBe(true);
      expect(result.id).toBe('large-execution');
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle high volume of concurrent workflow executions', async () => {
      const concurrentRequests = Array(100)
        .fill(null)
        .map((_, i) => ({
          templateId: 'template-1',
          context: { requestId: i },
        }));

      const startTime = Date.now();

      const promises = concurrentRequests.map((req) => workflowService.executeWorkflow(req));
      const results = await Promise.all(promises);

      const endTime = Date.now();
      const executionTime = endTime - startTime;

      expect(results).toHaveLength(100);
      expect(executionTime).toBeLessThan(5000); // Should complete within 5 seconds
    });

    it('should implement efficient caching for workflow templates', async () => {
      const templateId = 'template-1';

      // First call should hit database
      await workflowService.getTemplate(templateId);
      expect(mockQdrantClient.workflowTemplate.findUnique).toHaveBeenCalledTimes(1);

      // Second call should use cache
      await workflowService.getTemplate(templateId);
      expect(mockQdrantClient.workflowTemplate.findUnique).toHaveBeenCalledTimes(1);
    });

    it('should optimize database queries for analytics', async () => {
      const analyticsQuery = {
        templateIds: ['template-1', 'template-2'],
        dateRange: { start: '2024-01-01', end: '2024-01-31' },
        metrics: ['execution_time', 'success_rate', 'user_satisfaction'],
      };

      const analytics = await workflowService.getWorkflowAnalytics(analyticsQuery);

      expect(analytics).toBeDefined();
      // Verify that query was optimized (single database call)
      expect(mockQdrantClient.$transaction).toHaveBeenCalled();
    });
  });
});
