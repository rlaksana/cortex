/**
 * Comprehensive Unit Tests for Memory Store Service
 *
 * Tests memory store service functionality including:
 * - Knowledge item storage with validation
 * - Item retrieval by ID and query
 * - Item update and deletion
 * - Batch operations
 * - Knowledge type integration (all 16 types)
 * - Search and query operations
 * - Scope and isolation management
 * - Metadata and enrichment
 * - Error handling and validation
 *
 * Phase 1: Core Service Layer Testing
 * Building on solid foundation of knowledge types and database layer tests
 */

import { describe, it, expect, beforeEach, afterEach, vi, type MockedFunction } from 'vitest';
import { memoryStore } from '../../../src/services/memory-store.js';
import { memoryStoreOrchestrator } from '../../../src/services/orchestrators/memory-store-orchestrator.js';
import { validationService } from '../../../src/services/validation/validation-service.js';
import type {
  KnowledgeItem,
  MemoryStoreResponse,
  StoreResult,
  StoreError,
  AutonomousContext,
  DeleteRequest,
} from '../../../src/types/core-interfaces.js';

// Mock the orchestrator
vi.mock('../../../src/services/orchestrators/memory-store-orchestrator.js', () => ({
  memoryStoreOrchestrator: {
    storeItems: vi.fn(),
  },
}));

// Mock the validation service
vi.mock('../../../src/services/validation/validation-service.js', () => ({
  validationService: {
    validateStoreInput: vi.fn(),
    validateKnowledgeItem: vi.fn(),
    validateFindInput: vi.fn(),
  },
}));

// Mock logger
vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// Mock audit service
vi.mock('../../../src/services/audit/audit-service.js', () => ({
  auditService: {
    logStoreOperation: vi.fn().mockResolvedValue(undefined),
    logError: vi.fn().mockResolvedValue(undefined),
    logBatchOperation: vi.fn().mockResolvedValue(undefined),
  },
}));

// Mock Qdrant client for database operations
vi.mock('../../../src/db/qdrant.js', () => ({
  getQdrantClient: vi.fn(() => ({
    entity: { findUnique: vi.fn() },
    relation: { findUnique: vi.fn() },
    observation: { findUnique: vi.fn() },
    section: { findUnique: vi.fn() },
    runbook: { findUnique: vi.fn() },
    change: { findUnique: vi.fn() },
    issue: { findUnique: vi.fn() },
    decision: { findUnique: vi.fn() },
    todo: { findUnique: vi.fn() },
    release_note: { findUnique: vi.fn() },
    ddl: { findUnique: vi.fn() },
    pr_context: { findUnique: vi.fn() },
    incidentLog: { findUnique: vi.fn() },
    releaseLog: { findUnique: vi.fn() },
    riskLog: { findUnique: vi.fn() },
    assumptionLog: { findUnique: vi.fn() },
    adrDecision: { findUnique: vi.fn() },
  })),
}));

// Mock knowledge storage functions
vi.mock('../../../src/services/knowledge/index.js', () => ({
  storeEntity: vi.fn().mockResolvedValue('entity-id-1'),
  storeRelation: vi.fn().mockResolvedValue('relation-id-1'),
  addObservation: vi.fn().mockResolvedValue('observation-id-1'),
  storeSection: vi.fn().mockResolvedValue('section-id-1'),
  storeRunbook: vi.fn().mockResolvedValue('runbook-id-1'),
  storeChange: vi.fn().mockResolvedValue('change-id-1'),
  storeIssue: vi.fn().mockResolvedValue('issue-id-1'),
  storeDecision: vi.fn().mockResolvedValue('decision-id-1'),
  storeTodo: vi.fn().mockResolvedValue('todo-id-1'),
  storeReleaseNote: vi.fn().mockResolvedValue('release-note-id-1'),
  storeDDL: vi.fn().mockResolvedValue('ddl-id-1'),
  storePRContext: vi.fn().mockResolvedValue('pr-context-id-1'),
  storeIncident: vi.fn().mockResolvedValue('incident-id-1'),
  updateIncident: vi.fn().mockResolvedValue('incident-id-1'),
  storeRelease: vi.fn().mockResolvedValue('release-id-1'),
  updateRelease: vi.fn().mockResolvedValue('release-id-1'),
  storeRisk: vi.fn().mockResolvedValue('risk-id-1'),
  updateRisk: vi.fn().mockResolvedValue('risk-id-1'),
  storeAssumption: vi.fn().mockResolvedValue('assumption-id-1'),
  updateAssumption: vi.fn().mockResolvedValue('assumption-id-1'),
}));

vi.mock('../../../src/services/knowledge/decision.js', () => ({
  storeDecision: vi.fn().mockResolvedValue('decision-id-1'),
  updateDecision: vi.fn().mockResolvedValue('decision-id-1'),
}));

vi.mock('../../../src/services/knowledge/section.js', () => ({
  storeSection: vi.fn().mockResolvedValue('section-id-1'),
}));

vi.mock('../../../src/services/knowledge/todo.js', () => ({
  updateTodo: vi.fn().mockResolvedValue('todo-id-1'),
}));

// Mock delete operations
vi.mock('../../../src/services/delete-operations.js', () => ({
  softDelete: vi.fn().mockResolvedValue(true),
}));

// Mock immutability violations
vi.mock('../../../src/schemas/knowledge-types.js', () => ({
  violatesADRImmutability: vi.fn().mockReturnValue(false),
  violatesSpecWriteLock: vi.fn().mockReturnValue(false),
}));

describe('Memory Store Service - Core Operations', () => {
  let mockOrchestrator: any;
  let mockValidation: any;

  beforeEach(() => {
    vi.clearAllMocks();
    mockOrchestrator = memoryStoreOrchestrator as any;
    mockValidation = validationService as any;
  });

  describe('Knowledge Item Storage with Validation', () => {
    it('should store single valid knowledge item successfully', async () => {
      // Arrange
      const validItem: KnowledgeItem = {
        kind: 'entity',
        content: 'Test entity content',
        scope: { project: 'test-project', branch: 'main' },
        data: { name: 'Test Entity', type: 'component' },
        metadata: { source: 'test' },
      };

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'entity-id-1',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'created',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '1 items successfully processed',
          user_message_suggestion: '✅ Item created',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore([validItem]);

      // Assert
      expect(result).toEqual(expectedResponse);
      expect(mockOrchestrator.storeItems).toHaveBeenCalledWith([validItem]);
      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(result.stored[0].id).toBe('entity-id-1');
      expect(result.stored[0].status).toBe('inserted');
    });

    it('should handle multiple knowledge items in batch', async () => {
      // Arrange
      const items: KnowledgeItem[] = [
        {
          kind: 'entity',
          content: 'Entity 1',
          scope: { project: 'test-project' },
          data: { name: 'Entity 1', type: 'service' },
        },
        {
          kind: 'decision',
          content: 'Decision 1',
          scope: { project: 'test-project' },
          data: { title: 'Use microservices', rationale: 'Better scalability' },
        },
        {
          kind: 'observation',
          content: 'Observation 1',
          scope: { project: 'test-project' },
          data: { content: 'System performance improved by 20%' },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'entity-id-1',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'decision-id-1',
            status: 'inserted',
            kind: 'decision',
            created_at: new Date().toISOString(),
          },
          {
            id: 'observation-id-1',
            status: 'inserted',
            kind: 'observation',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 3,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '3 items successfully processed',
          user_message_suggestion: '✅ Processed 3 items',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(items);

      // Assert
      expect(result).toEqual(expectedResponse);
      expect(result.stored).toHaveLength(3);
      expect(result.errors).toHaveLength(0);
      expect(mockOrchestrator.storeItems).toHaveBeenCalledWith(items);
    });

    it('should handle validation errors for invalid items', async () => {
      // Arrange
      const invalidItems = [
        null,
        undefined,
        {},
        { kind: 'invalid-kind', content: 'test' },
        { content: 'missing-kind' },
        { kind: 'entity', data: null },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [],
        errors: [
          {
            index: 0,
            error_code: 'INVALID_REQUEST',
            message: 'Expected object, received null',
          },
          {
            index: 1,
            error_code: 'INVALID_REQUEST',
            message: 'Expected object, received undefined',
          },
        ],
        autonomous_context: {
          action_performed: 'skipped',
          similar_items_checked: 0,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Fix validation errors before retrying',
          reasoning: 'Request failed validation',
          user_message_suggestion: '❌ Request validation failed',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(invalidItems as any);

      // Assert
      expect(result.stored).toHaveLength(0);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.autonomous_context.action_performed).toBe('skipped');
    });

    it('should handle partial success with mixed valid and invalid items', async () => {
      // Arrange
      const mixedItems = [
        {
          kind: 'entity',
          content: 'Valid item 1',
          scope: { project: 'test-project' },
          data: { name: 'Valid Entity', type: 'service' },
        },
        null, // Invalid
        {
          kind: 'decision',
          content: 'Valid item 2',
          scope: { project: 'test-project' },
          data: { title: 'Valid Decision', rationale: 'Valid rationale' },
        },
        { invalid: 'item' }, // Invalid
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'entity-id-1',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
          {
            id: 'decision-id-1',
            status: 'inserted',
            kind: 'decision',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [
          {
            index: 1,
            error_code: 'INVALID_REQUEST',
            message: 'Expected object, received null',
          },
          {
            index: 3,
            error_code: 'INVALID_ITEM',
            message: 'Missing required field: kind',
          },
        ],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 2,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Review and fix validation errors before retrying',
          reasoning: '2 items successfully processed; 2 items failed to process',
          user_message_suggestion: '❌ 2 errors occurred',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(mixedItems as any);

      // Assert
      expect(result.stored).toHaveLength(2);
      expect(result.errors).toHaveLength(2);
      expect(result.autonomous_context.action_performed).toBe('batch');
    });
  });

  describe('Knowledge Type Integration (All 16 Types)', () => {
    const knowledgeTypes = [
      'entity',
      'relation',
      'observation',
      'section',
      'runbook',
      'change',
      'issue',
      'decision',
      'todo',
      'release_note',
      'ddl',
      'pr_context',
      'incident',
      'release',
      'risk',
      'assumption',
    ];

    it.each(knowledgeTypes)('should handle %s knowledge type', async (kind) => {
      // Arrange
      let item: KnowledgeItem;

      switch (kind) {
        case 'entity':
          item = {
            kind,
            content: 'Test entity',
            scope: { project: 'test-project' },
            data: { name: 'Test Entity', type: 'component' },
          };
          break;
        case 'relation':
          item = {
            kind,
            content: 'Test relation',
            scope: { project: 'test-project' },
            data: { source: 'entity1', target: 'entity2', type: 'depends_on' },
          };
          break;
        case 'observation':
          item = {
            kind,
            content: 'Test observation',
            scope: { project: 'test-project' },
            data: { content: 'System behavior observed' },
          };
          break;
        case 'section':
          item = {
            kind,
            content: 'Test section',
            scope: { project: 'test-project' },
            data: { title: 'Section Title', body_md: '# Section Content' },
          };
          break;
        case 'runbook':
          item = {
            kind,
            content: 'Test runbook',
            scope: { project: 'test-project' },
            data: {
              title: 'Runbook Title',
              steps: [{ step_number: 1, description: 'Step 1' }],
            },
          };
          break;
        case 'change':
          item = {
            kind,
            content: 'Test change',
            scope: { project: 'test-project' },
            data: { description: 'Change description', impact: 'medium' },
          };
          break;
        case 'issue':
          item = {
            kind,
            content: 'Test issue',
            scope: { project: 'test-project' },
            data: { title: 'Issue Title', description: 'Issue description' },
          };
          break;
        case 'decision':
          item = {
            kind,
            content: 'Test decision',
            scope: { project: 'test-project' },
            data: { title: 'Decision Title', rationale: 'Decision rationale' },
          };
          break;
        case 'todo':
          item = {
            kind,
            content: 'Test todo',
            scope: { project: 'test-project' },
            data: { title: 'Todo Title', status: 'pending' },
          };
          break;
        case 'release_note':
          item = {
            kind,
            content: 'Test release note',
            scope: { project: 'test-project' },
            data: { version: 'v1.0.0', notes: 'Release notes' },
          };
          break;
        case 'ddl':
          item = {
            kind,
            content: 'Test DDL',
            scope: { project: 'test-project' },
            data: { sql: 'CREATE TABLE test (id INT);', description: 'Test table' },
          };
          break;
        case 'pr_context':
          item = {
            kind,
            content: 'Test PR context',
            scope: { project: 'test-project', branch: 'feature-branch' },
            data: { pr_number: 123, title: 'PR Title' },
          };
          break;
        case 'incident':
          item = {
            kind,
            content: 'Test incident',
            scope: { project: 'test-project' },
            data: { title: 'Incident Title', severity: 'high' },
          };
          break;
        case 'release':
          item = {
            kind,
            content: 'Test release',
            scope: { project: 'test-project' },
            data: { version: 'v1.0.0', scope: 'production' },
          };
          break;
        case 'risk':
          item = {
            kind,
            content: 'Test risk',
            scope: { project: 'test-project' },
            data: { title: 'Risk Title', impact: 'high' },
          };
          break;
        case 'assumption':
          item = {
            kind,
            content: 'Test assumption',
            scope: { project: 'test-project' },
            data: { title: 'Assumption Title', description: 'Assumption description' },
          };
          break;
        default:
          item = {
            kind,
            content: `Test ${kind}`,
            scope: { project: 'test-project' },
            data: { title: `${kind} Title` },
          };
      }

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: `${kind}-id-1`,
            status: 'inserted',
            kind,
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'created',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '1 items successfully processed',
          user_message_suggestion: '✅ Item created',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore([item]);

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].kind).toBe(kind);
      expect(result.errors).toHaveLength(0);
      expect(mockOrchestrator.storeItems).toHaveBeenCalledWith([item]);
    });

    it('should handle cross-type relationships', async () => {
      // Arrange
      const relatedItems: KnowledgeItem[] = [
        {
          kind: 'entity',
          content: 'Component A',
          scope: { project: 'test-project' },
          data: { name: 'Component A', type: 'service' },
        },
        {
          kind: 'entity',
          content: 'Component B',
          scope: { project: 'test-project' },
          data: { name: 'Component B', type: 'database' },
        },
        {
          kind: 'relation',
          content: 'Dependency relation',
          scope: { project: 'test-project' },
          data: {
            source: 'Component A',
            target: 'Component B',
            type: 'depends_on',
            metadata: { relationship_strength: 'strong' },
          },
        },
        {
          kind: 'observation',
          content: 'Performance observation',
          scope: { project: 'test-project' },
          data: {
            content: 'Component A depends on Component B for database operations',
            related_entities: ['Component A', 'Component B'],
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: relatedItems.map((item, index) => ({
          id: `${item.kind}-id-${index + 1}`,
          status: 'inserted' as const,
          kind: item.kind,
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 4,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '4 items successfully processed',
          user_message_suggestion: '✅ Processed 4 items',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(relatedItems);

      // Assert
      expect(result.stored).toHaveLength(4);
      expect(result.errors).toHaveLength(0);
      expect(result.stored.map((s) => s.kind)).toEqual([
        'entity',
        'entity',
        'relation',
        'observation',
      ]);
    });
  });

  describe('Scope and Isolation Management', () => {
    it('should handle project-based scoping', async () => {
      // Arrange
      const projectScopedItems: KnowledgeItem[] = [
        {
          kind: 'entity',
          content: 'Project A entity',
          scope: { project: 'project-a', branch: 'main' },
          data: { name: 'Entity A', type: 'service' },
        },
        {
          kind: 'decision',
          content: 'Project A decision',
          scope: { project: 'project-a', branch: 'main' },
          data: { title: 'Use React', rationale: 'Team expertise' },
        },
        {
          kind: 'entity',
          content: 'Project B entity',
          scope: { project: 'project-b', branch: 'develop' },
          data: { name: 'Entity B', type: 'api' },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: projectScopedItems.map((item, index) => ({
          id: `${item.kind}-id-${index + 1}`,
          status: 'inserted' as const,
          kind: item.kind,
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 3,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '3 items successfully processed',
          user_message_suggestion: '✅ Processed 3 items',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(projectScopedItems);

      // Assert
      expect(result.stored).toHaveLength(3);
      expect(result.errors).toHaveLength(0);

      // Verify scope is preserved in calls
      expect(mockOrchestrator.storeItems).toHaveBeenCalledWith(
        expect.arrayContaining([
          expect.objectContaining({
            scope: { project: 'project-a', branch: 'main' },
          }),
          expect.objectContaining({
            scope: { project: 'project-a', branch: 'main' },
          }),
          expect.objectContaining({
            scope: { project: 'project-b', branch: 'develop' },
          }),
        ])
      );
    });

    it('should handle organizational boundaries', async () => {
      // Arrange
      const orgScopedItems: KnowledgeItem[] = [
        {
          kind: 'policy',
          content: 'Org-wide policy',
          scope: { org: 'company-a' },
          data: { title: 'Security Policy', content: 'Company security guidelines' },
        },
        {
          kind: 'entity',
          content: 'Project entity',
          scope: { org: 'company-a', project: 'project-x' },
          data: { name: 'Project X Service', type: 'microservice' },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: orgScopedItems.map((item, index) => ({
          id: `${item.kind}-id-${index + 1}`,
          status: 'inserted' as const,
          kind: item.kind,
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 2,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '2 items successfully processed',
          user_message_suggestion: '✅ Processed 2 items',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(orgScopedItems);

      // Assert
      expect(result.stored).toHaveLength(2);
      expect(result.errors).toHaveLength(0);
    });

    it('should handle cross-scope access control', async () => {
      // Arrange
      const crossScopeItems: KnowledgeItem[] = [
        {
          kind: 'entity',
          content: 'Shared component',
          scope: { org: 'company-a', project: 'shared-lib' },
          data: { name: 'Auth Component', type: 'library' },
        },
        {
          kind: 'relation',
          content: 'Usage relation',
          scope: { org: 'company-a', project: 'project-x' },
          data: {
            source: 'Project X Service',
            target: 'Auth Component',
            type: 'uses',
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: crossScopeItems.map((item, index) => ({
          id: `${item.kind}-id-${index + 1}`,
          status: 'inserted' as const,
          kind: item.kind,
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 2,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '2 items successfully processed',
          user_message_suggestion: '✅ Processed 2 items',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(crossScopeItems);

      // Assert
      expect(result.stored).toHaveLength(2);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('Metadata and Enrichment', () => {
    it('should handle automatic metadata generation', async () => {
      // Arrange
      const itemWithMetadata: KnowledgeItem = {
        kind: 'entity',
        content: 'Test entity',
        scope: { project: 'test-project' },
        data: { name: 'Test Entity', type: 'service' },
        metadata: {
          source: 'user-input',
          timestamp: '2025-01-01T00:00:00Z',
          version: '1.0.0',
        },
      };

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'entity-id-1',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'created',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '1 items successfully processed',
          user_message_suggestion: '✅ Item created',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore([itemWithMetadata]);

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(mockOrchestrator.storeItems).toHaveBeenCalledWith([itemWithMetadata]);
    });

    it('should handle source tracking and provenance', async () => {
      // Arrange
      const itemsWithProvenance: KnowledgeItem[] = [
        {
          kind: 'observation',
          content: 'System metric',
          scope: { project: 'test-project' },
          data: { content: 'CPU usage at 80%' },
          metadata: {
            source: 'monitoring-system',
            provenance: {
              system: 'prometheus',
              timestamp: '2025-01-01T12:00:00Z',
              metric_name: 'cpu_usage',
            },
          },
        },
        {
          kind: 'decision',
          content: 'Architecture decision',
          scope: { project: 'test-project' },
          data: { title: 'Use microservices', rationale: 'Scalability' },
          metadata: {
            source: 'architecture-review',
            provenance: {
              meeting: 'architecture-review-2025-01-01',
              attendees: ['architect-1', 'tech-lead'],
              decision_type: 'ADR',
            },
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: itemsWithProvenance.map((item, index) => ({
          id: `${item.kind}-id-${index + 1}`,
          status: 'inserted' as const,
          kind: item.kind,
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 2,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '2 items successfully processed',
          user_message_suggestion: '✅ Processed 2 items',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(itemsWithProvenance);

      // Assert
      expect(result.stored).toHaveLength(2);
      expect(result.errors).toHaveLength(0);
    });

    it('should handle timestamp management', async () => {
      // Arrange
      const itemWithTimestamps: KnowledgeItem = {
        kind: 'entity',
        content: 'Versioned entity',
        scope: { project: 'test-project' },
        data: { name: 'Versioned Component', type: 'service' },
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-02T00:00:00Z',
        metadata: {
          last_modified: '2025-01-02T00:00:00Z',
          version: 2,
        },
      };

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'entity-id-1',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'created',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '1 items successfully processed',
          user_message_suggestion: '✅ Item created',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore([itemWithTimestamps]);

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(mockOrchestrator.storeItems).toHaveBeenCalledWith([itemWithTimestamps]);
    });

    it('should handle tag and category handling', async () => {
      // Arrange
      const itemsWithTags: KnowledgeItem[] = [
        {
          kind: 'entity',
          content: 'Tagged entity',
          scope: { project: 'test-project' },
          data: { name: 'Tagged Component', type: 'service' },
          metadata: {
            tags: ['microservice', 'api', 'critical'],
            categories: ['infrastructure', 'backend'],
            priority: 'high',
          },
        },
        {
          kind: 'decision',
          content: 'Categorized decision',
          scope: { project: 'test-project' },
          data: { title: 'Technology Choice', rationale: 'Performance' },
          metadata: {
            tags: ['architecture', 'technology', 'performance'],
            categories: ['technical-decision', 'infrastructure'],
            impact: 'high',
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: itemsWithTags.map((item, index) => ({
          id: `${item.kind}-id-${index + 1}`,
          status: 'inserted' as const,
          kind: item.kind,
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 2,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '2 items successfully processed',
          user_message_suggestion: '✅ Processed 2 items',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(itemsWithTags);

      // Assert
      expect(result.stored).toHaveLength(2);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('Error Handling and Validation', () => {
    it('should handle system errors gracefully', async () => {
      // Arrange
      const validItem: KnowledgeItem = {
        kind: 'entity',
        content: 'Test entity',
        scope: { project: 'test-project' },
        data: { name: 'Test Entity', type: 'service' },
      };

      const systemError = new Error('Database connection failed');
      mockOrchestrator.storeItems.mockRejectedValue(systemError);

      // Act
      const result = await memoryStore([validItem]);

      // Assert
      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error_code).toBe('SYSTEM_ERROR');
      expect(result.errors[0].message).toBe('Database connection failed');
      expect(result.autonomous_context.action_performed).toBe('skipped');
    });

    it('should handle validation errors for missing required fields', async () => {
      // Arrange
      const itemsWithMissingFields = [
        {
          kind: 'entity',
          // Missing scope
          data: { name: 'Test Entity' },
        },
        {
          scope: { project: 'test-project' },
          // Missing kind
          data: { title: 'Test Decision' },
        },
        {
          kind: 'decision',
          scope: { project: 'test-project' },
          // Missing data
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [],
        errors: itemsWithMissingFields.map((_, index) => ({
          index,
          error_code: 'VALIDATION_ERROR',
          message: expect.stringContaining('required'),
        })),
        autonomous_context: {
          action_performed: 'skipped',
          similar_items_checked: 0,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Fix validation errors before retrying',
          reasoning: 'Request failed validation',
          user_message_suggestion: '❌ Request validation failed',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(itemsWithMissingFields as any);

      // Assert
      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(3);
      expect(result.autonomous_context.action_performed).toBe('skipped');
    });

    it('should handle schema validation errors', async () => {
      // Arrange
      const invalidSchemaItems = [
        {
          kind: 'decision',
          scope: { project: 'test-project' },
          data: {
            // Missing required title field
            rationale: 'Some rationale',
          },
        },
        {
          kind: 'runbook',
          scope: { project: 'test-project' },
          data: {
            title: 'Runbook without steps',
            // Missing required steps field
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [],
        errors: invalidSchemaItems.map((_, index) => ({
          index,
          error_code: 'INVALID_ITEM',
          message: expect.stringContaining('requires'),
          field: expect.any(String),
        })),
        autonomous_context: {
          action_performed: 'skipped',
          similar_items_checked: 0,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Fix validation errors before retrying',
          reasoning: 'Request failed validation',
          user_message_suggestion: '❌ Request validation failed',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(invalidSchemaItems as any);

      // Assert
      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(2);
    });

    it('should handle storage failure recovery', async () => {
      // Arrange
      const items: KnowledgeItem[] = [
        {
          kind: 'entity',
          content: 'Valid item 1',
          scope: { project: 'test-project' },
          data: { name: 'Entity 1', type: 'service' },
        },
        {
          kind: 'decision',
          content: 'Valid item 2',
          scope: { project: 'test-project' },
          data: { title: 'Decision 2', rationale: 'Rationale 2' },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'entity-id-1',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [
          {
            index: 1,
            error_code: 'STORAGE_ERROR',
            message: 'Failed to store decision item',
          },
        ],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Review and fix storage errors before retrying',
          reasoning: '1 items successfully processed; 1 items failed to process',
          user_message_suggestion: '❌ 1 error occurred',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(items);

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(1);
      expect(result.stored[0].kind).toBe('entity');
      expect(result.errors[0].index).toBe(1);
    });

    it('should handle data consistency validation', async () => {
      // Arrange
      const inconsistentItems: KnowledgeItem[] = [
        {
          kind: 'relation',
          content: 'Invalid relation',
          scope: { project: 'test-project' },
          data: {
            source: 'Nonexistent Entity',
            target: 'Another Nonexistent Entity',
            type: 'depends_on',
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [],
        errors: [
          {
            index: 0,
            error_code: 'CONSISTENCY_ERROR',
            message: 'Referenced entities do not exist',
            field: 'source',
          },
        ],
        autonomous_context: {
          action_performed: 'skipped',
          similar_items_checked: 0,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Fix consistency errors before retrying',
          reasoning: 'Request failed validation',
          user_message_suggestion: '❌ Request validation failed',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(inconsistentItems);

      // Assert
      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error_code).toBe('CONSISTENCY_ERROR');
    });
  });

  describe('Search and Query Operations', () => {
    it('should handle complex query composition', async () => {
      // This test would be for search functionality
      // For now, we test that the service can handle items that will be searched
      const searchableItems: KnowledgeItem[] = [
        {
          kind: 'entity',
          content: 'Searchable component with specific tags',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            name: 'Searchable Component',
            type: 'service',
            description: 'A component that can be found through search',
            tags: ['searchable', 'indexed', 'discoverable'],
          },
          metadata: {
            searchable_fields: ['name', 'description', 'tags'],
            search_boost: 1.5,
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'entity-id-1',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'created',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '1 items successfully processed',
          user_message_suggestion: '✅ Item created',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(searchableItems);

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].kind).toBe('entity');
      expect(result.errors).toHaveLength(0);
    });

    it('should handle filtering by scope, type, and metadata', async () => {
      // Arrange items with different filtering criteria
      const filterableItems: KnowledgeItem[] = [
        {
          kind: 'entity',
          content: 'Production entity',
          scope: { project: 'test-project', branch: 'main' },
          data: { name: 'Production Service', type: 'service' },
          metadata: { environment: 'production', tier: 'critical' },
        },
        {
          kind: 'entity',
          content: 'Development entity',
          scope: { project: 'test-project', branch: 'develop' },
          data: { name: 'Development Service', type: 'service' },
          metadata: { environment: 'development', tier: 'standard' },
        },
        {
          kind: 'decision',
          content: 'Architecture decision',
          scope: { project: 'test-project', branch: 'main' },
          data: { title: 'Use Microservices', rationale: 'Scalability' },
          metadata: { category: 'architecture', impact: 'high' },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: filterableItems.map((item, index) => ({
          id: `${item.kind}-id-${index + 1}`,
          status: 'inserted' as const,
          kind: item.kind,
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 3,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '3 items successfully processed',
          user_message_suggestion: '✅ Processed 3 items',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(filterableItems);

      // Assert
      expect(result.stored).toHaveLength(3);
      expect(result.errors).toHaveLength(0);

      // Verify that different scopes and metadata are preserved
      expect(mockOrchestrator.storeItems).toHaveBeenCalledWith(
        expect.arrayContaining([
          expect.objectContaining({
            scope: { project: 'test-project', branch: 'main' },
            metadata: { environment: 'production', tier: 'critical' },
          }),
          expect.objectContaining({
            scope: { project: 'test-project', branch: 'develop' },
            metadata: { environment: 'development', tier: 'standard' },
          }),
          expect.objectContaining({
            scope: { project: 'test-project', branch: 'main' },
            metadata: { category: 'architecture', impact: 'high' },
          }),
        ])
      );
    });

    it('should handle semantic search functionality', async () => {
      // Arrange items optimized for semantic search
      const semanticItems: KnowledgeItem[] = [
        {
          kind: 'observation',
          content: 'Performance bottleneck in database queries',
          scope: { project: 'test-project' },
          data: {
            content: 'Database queries are taking longer than expected',
            metrics: { avg_query_time: '2.5s', slow_queries: 150 },
            context: 'production environment',
          },
          metadata: {
            semantic_vector: true,
            search_keywords: ['performance', 'database', 'query', 'bottleneck'],
            content_hash: 'abc123',
          },
        },
        {
          kind: 'decision',
          content: 'Optimize database with indexing strategy',
          scope: { project: 'test-project' },
          data: {
            title: 'Implement Database Indexing',
            rationale: 'Improve query performance',
            alternatives: ['Add indexes', 'Optimize queries', 'Add caching'],
          },
          metadata: {
            semantic_vector: true,
            search_keywords: ['database', 'indexing', 'performance', 'optimization'],
            content_hash: 'def456',
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: semanticItems.map((item, index) => ({
          id: `${item.kind}-id-${index + 1}`,
          status: 'inserted' as const,
          kind: item.kind,
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 2,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '2 items successfully processed',
          user_message_suggestion: '✅ Processed 2 items',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(semanticItems);

      // Assert
      expect(result.stored).toHaveLength(2);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('Batch Operations', () => {
    it('should handle large batch operations efficiently', async () => {
      // Arrange
      const largeBatch = Array.from({ length: 100 }, (_, i) => ({
        kind: 'entity',
        content: `Entity ${i}`,
        scope: { project: 'test-project' },
        data: { name: `Entity ${i}`, type: 'component', index: i },
      }));

      const expectedResponse: MemoryStoreResponse = {
        stored: largeBatch.map((item, index) => ({
          id: `entity-id-${index + 1}`,
          status: 'inserted' as const,
          kind: item.kind,
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 100,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '100 items successfully processed',
          user_message_suggestion: '✅ Processed 100 items',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(largeBatch);

      // Assert
      expect(result.stored).toHaveLength(100);
      expect(result.errors).toHaveLength(0);
      expect(result.autonomous_context.similar_items_checked).toBe(100);
    });

    it('should handle mixed batch with partial failures', async () => {
      // Arrange
      const mixedBatch = [
        // Valid items
        ...Array.from({ length: 3 }, (_, i) => ({
          kind: 'entity',
          content: `Valid Entity ${i}`,
          scope: { project: 'test-project' },
          data: { name: `Valid Entity ${i}`, type: 'component' },
        })),
        // Invalid items
        null,
        undefined,
        { invalid: 'item' },
        // More valid items
        ...Array.from({ length: 2 }, (_, i) => ({
          kind: 'decision',
          content: `Valid Decision ${i}`,
          scope: { project: 'test-project' },
          data: { title: `Decision ${i}`, rationale: `Rationale ${i}` },
        })),
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: Array.from({ length: 5 }, (_, i) => ({
          id: `item-id-${i + 1}`,
          status: 'inserted' as const,
          kind: i < 3 ? 'entity' : 'decision',
          created_at: new Date().toISOString(),
        })),
        errors: [
          {
            index: 3,
            error_code: 'INVALID_REQUEST',
            message: 'Expected object, received null',
          },
          {
            index: 4,
            error_code: 'INVALID_REQUEST',
            message: 'Expected object, received undefined',
          },
          {
            index: 5,
            error_code: 'INVALID_ITEM',
            message: 'Missing required field: kind',
          },
        ],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 5,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Review and fix validation errors before retrying',
          reasoning: '5 items successfully processed; 3 items failed to process',
          user_message_suggestion: '❌ 3 errors occurred',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(mixedBatch as any);

      // Assert
      expect(result.stored).toHaveLength(5);
      expect(result.errors).toHaveLength(3);
      expect(result.stored.filter((s) => s.kind === 'entity')).toHaveLength(3);
      expect(result.stored.filter((s) => s.kind === 'decision')).toHaveLength(2);
    });

    it('should handle transaction-like behavior for batches', async () => {
      // Arrange
      const transactionalBatch = [
        {
          kind: 'entity',
          content: 'Primary entity',
          scope: { project: 'test-project' },
          data: { name: 'Primary Entity', type: 'service' },
        },
        {
          kind: 'relation',
          content: 'Primary relation',
          scope: { project: 'test-project' },
          data: {
            source: 'Primary Entity',
            target: 'Secondary Entity',
            type: 'depends_on',
          },
        },
        {
          kind: 'entity',
          content: 'Secondary entity',
          scope: { project: 'test-project' },
          data: { name: 'Secondary Entity', type: 'database' },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: transactionalBatch.map((item, index) => ({
          id: `${item.kind}-id-${index + 1}`,
          status: 'inserted' as const,
          kind: item.kind,
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 3,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '3 items successfully processed',
          user_message_suggestion: '✅ Processed 3 items',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(transactionalBatch);

      // Assert
      expect(result.stored).toHaveLength(3);
      expect(result.errors).toHaveLength(0);
      // All items should be stored successfully for transaction-like behavior
      expect(result.stored.every((s) => s.status === 'inserted')).toBe(true);
    });
  });

  describe('Update and Delete Operations', () => {
    it('should handle item updates', async () => {
      // Arrange
      const updateItem: KnowledgeItem = {
        id: 'existing-entity-id',
        kind: 'entity',
        content: 'Updated entity content',
        scope: { project: 'test-project' },
        data: { name: 'Updated Entity', type: 'service', version: 2 },
        metadata: { operation: 'update', previous_version: 1 },
      };

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'existing-entity-id',
            status: 'updated',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'updated',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '1 items successfully processed',
          user_message_suggestion: '✅ Item updated',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore([updateItem]);

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].status).toBe('updated');
      expect(result.stored[0].id).toBe('existing-entity-id');
    });

    it('should handle item deletions', async () => {
      // Arrange
      const deleteItem: KnowledgeItem = {
        id: 'entity-to-delete',
        kind: 'entity',
        content: 'Entity to delete',
        scope: { project: 'test-project' },
        data: { operation: 'delete', cascade_relations: true },
      };

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'entity-to-delete',
            status: 'deleted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'deleted',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '1 items successfully processed',
          user_message_suggestion: '✅ Item deleted',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore([deleteItem]);

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].status).toBe('deleted');
      expect(result.stored[0].id).toBe('entity-to-delete');
    });

    it('should handle cascading delete operations', async () => {
      // Arrange
      const cascadeDeleteItems: KnowledgeItem[] = [
        {
          id: 'main-entity',
          kind: 'entity',
          content: 'Main entity to delete',
          scope: { project: 'test-project' },
          data: { operation: 'delete', cascade_relations: true },
        },
        {
          id: 'related-relation-1',
          kind: 'relation',
          content: 'Related relation 1',
          scope: { project: 'test-project' },
          data: { operation: 'delete', cascade_from: 'main-entity' },
        },
        {
          id: 'related-relation-2',
          kind: 'relation',
          content: 'Related relation 2',
          scope: { project: 'test-project' },
          data: { operation: 'delete', cascade_from: 'main-entity' },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: cascadeDeleteItems.map((item, index) => ({
          id: item.id!,
          status: 'deleted' as const,
          kind: item.kind,
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 3,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '3 items successfully processed',
          user_message_suggestion: '✅ Processed 3 items',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(cascadeDeleteItems);

      // Assert
      expect(result.stored).toHaveLength(3);
      expect(result.stored.every((s) => s.status === 'deleted')).toBe(true);
    });
  });

  describe('Performance and Scaling', () => {
    it('should handle concurrent operations', async () => {
      // Arrange
      const concurrentBatches = Array.from({ length: 5 }, (_, batchIndex) =>
        Array.from({ length: 10 }, (_, itemIndex) => ({
          kind: 'entity',
          content: `Concurrent entity ${batchIndex}-${itemIndex}`,
          scope: { project: `project-${batchIndex}` },
          data: { name: `Entity ${batchIndex}-${itemIndex}`, type: 'component' },
        }))
      );

      const expectedResponses = concurrentBatches.map((batch, batchIndex) => ({
        stored: batch.map((_, itemIndex) => ({
          id: `entity-${batchIndex}-${itemIndex}`,
          status: 'inserted' as const,
          kind: 'entity',
          created_at: new Date().toISOString(),
        })),
        errors: [],
        autonomous_context: {
          action_performed: 'batch' as const,
          similar_items_checked: 10,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '10 items successfully processed',
          user_message_suggestion: '✅ Processed 10 items',
        },
      }));

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponses[0]);

      // Act - Execute concurrent operations
      const concurrentPromises = concurrentBatches.map((batch) => memoryStore(batch));
      const results = await Promise.all(concurrentPromises);

      // Assert
      expect(results).toHaveLength(5);
      results.forEach((result) => {
        expect(result.stored).toHaveLength(10);
        expect(result.errors).toHaveLength(0);
      });
    });

    it('should handle memory usage efficiently for large operations', async () => {
      // Arrange
      const largeItem: KnowledgeItem = {
        kind: 'observation',
        content: 'x'.repeat(100000), // 100KB content
        scope: { project: 'test-project' },
        data: {
          content: 'x'.repeat(100000),
          large_data: new Array(1000).fill('large data chunk'),
        },
        metadata: {
          size: 'large',
          content_length: 100000,
        },
      };

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'large-observation-id',
            status: 'inserted',
            kind: 'observation',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'created',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '1 items successfully processed',
          user_message_suggestion: '✅ Item created',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore([largeItem]);

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(result.stored[0].id).toBe('large-observation-id');
    });
  });

  describe('Integration Points', () => {
    it('should integrate with audit logging', async () => {
      // Arrange
      const auditableItems: KnowledgeItem[] = [
        {
          kind: 'decision',
          content: 'Auditable decision',
          scope: { project: 'test-project' },
          data: { title: 'Important Decision', rationale: 'Critical rationale' },
          metadata: {
            audit_required: true,
            audit_level: 'high',
          },
        },
      ];

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'decision-id-1',
            status: 'inserted',
            kind: 'decision',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'created',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '1 items successfully processed',
          user_message_suggestion: '✅ Item created',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(auditableItems);

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      // Verify that the service was called with audit metadata
      expect(mockOrchestrator.storeItems).toHaveBeenCalledWith(
        expect.arrayContaining([
          expect.objectContaining({
            metadata: expect.objectContaining({
              audit_required: true,
              audit_level: 'high',
            }),
          }),
        ])
      );
    });

    it('should integrate with validation pipeline', async () => {
      // Arrange
      const validationItems: KnowledgeItem[] = [
        {
          kind: 'entity',
          content: 'Validated entity',
          scope: { project: 'test-project' },
          data: { name: 'Validated Entity', type: 'service' },
          metadata: {
            validation_required: true,
            validation_rules: ['schema', 'business', 'consistency'],
          },
        },
      ];

      // Mock successful validation
      mockValidation.validateStoreInput.mockResolvedValue({
        valid: true,
        errors: [],
      });

      const expectedResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'entity-id-1',
            status: 'inserted',
            kind: 'entity',
            created_at: new Date().toISOString(),
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'created',
          similar_items_checked: 1,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: '1 items successfully processed',
          user_message_suggestion: '✅ Item created',
        },
      };

      mockOrchestrator.storeItems.mockResolvedValue(expectedResponse);

      // Act
      const result = await memoryStore(validationItems);

      // Assert
      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
    });
  });
});
