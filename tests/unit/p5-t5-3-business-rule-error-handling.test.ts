/**
 * P5-T5.3 Business Rule Error Handling Tests
 *
 * Tests business rule violation handling and status translation:
 * - Business rule violations result in status='business_rule_blocked'
 * - Detailed reason inclusion for violations
 * - Batch processing continuation despite individual failures
 * - Proper error translation and response formatting
 *
 * This test file implements TDD approach for P5-T5.3 requirements.
 */

import { describe, it, expect, beforeEach, afterEach, vi, type MockedFunction } from 'vitest';
import { MemoryStoreOrchestrator } from '../../src/services/orchestrators/memory-store-orchestrator.js';
import { validatorRegistry } from '../../src/services/validation/validator-registry.js';
import { createBusinessValidators } from '../../src/services/validation/business-validators.js';
import type {
  KnowledgeItem,
  MemoryStoreResponse,
  ItemResult,
  BatchSummary,
} from '../../src/types/core-interfaces.js';

// Mock logger
vi.mock('../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
  withRequestLogging: vi.fn().mockImplementation((toolName, fn) => fn()),
  createChildLogger: vi.fn().mockReturnValue({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }),
  createRequestLogger: vi.fn().mockReturnValue({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }),
  logSlowQuery: vi.fn(),
}));

// Mock logging patterns
vi.mock('../../src/utils/logging-patterns.js', () => ({
  logRequestStart: vi.fn().mockReturnValue({}),
  logRequestSuccess: vi.fn(),
  logRequestError: vi.fn(),
}));

// Mock audit service
vi.mock('../../src/services/audit/audit-service.js', () => ({
  auditService: {
    logStoreOperation: vi.fn().mockResolvedValue(undefined),
    logError: vi.fn().mockResolvedValue(undefined),
    logBatchOperation: vi.fn().mockResolvedValue(undefined),
  },
}));

// Mock chunking service
vi.mock('../../src/services/chunking/chunking-service.js', () => ({
  ChunkingService: class {
    constructor() {
      // Mock constructor
    }
    processItemsForStorage = vi.fn().mockImplementation((items) => items); // Pass through unchanged
    shouldChunkItem = vi.fn().mockReturnValue(false); // Don't chunk for these tests
  },
}));

// Mock database operations
vi.mock('../../src/db/qdrant', () => ({
  getQdrantClient: vi.fn().mockReturnValue({
    // Mock all the database methods that might be called
    adrDecision: { findUnique: vi.fn().mockResolvedValue(null) },
    section: { findUnique: vi.fn().mockResolvedValue(null) },
    incidentLog: { findUnique: vi.fn().mockResolvedValue(null) },
    releaseLog: { findUnique: vi.fn().mockResolvedValue(null) },
    riskLog: { findUnique: vi.fn().mockResolvedValue(null) },
    assumptionLog: { findUnique: vi.fn().mockResolvedValue(null) },
    todoLog: { findUnique: vi.fn().mockResolvedValue(null) },
    issueLog: { findUnique: vi.fn().mockResolvedValue(null) },
    knowledgeEntity: { findMany: vi.fn().mockResolvedValue([]) },
  }),
  softDelete: vi.fn().mockResolvedValue(true),
}));

// Mock knowledge storage functions
vi.mock('../../src/services/knowledge/index.js', () => ({
  storeEntity: vi.fn().mockResolvedValue('mock-entity-id'),
  storeRelation: vi.fn().mockResolvedValue('mock-relation-id'),
  addObservation: vi.fn().mockResolvedValue('mock-observation-id'),
  storeSection: vi.fn().mockResolvedValue('mock-section-id'),
  storeRunbook: vi.fn().mockResolvedValue('mock-runbook-id'),
  storeChange: vi.fn().mockResolvedValue('mock-change-id'),
  storeIssue: vi.fn().mockResolvedValue('mock-issue-id'),
  storeReleaseNote: vi.fn().mockResolvedValue('mock-release-note-id'),
  storeDDL: vi.fn().mockResolvedValue('mock-ddl-id'),
  storePRContext: vi.fn().mockResolvedValue('mock-pr-context-id'),
  storeIncident: vi.fn().mockResolvedValue('mock-incident-id'),
  storeRelease: vi.fn().mockResolvedValue('mock-release-id'),
  storeRisk: vi.fn().mockResolvedValue('mock-risk-id'),
  storeAssumption: vi.fn().mockResolvedValue('mock-assumption-id'),
  storeTodo: vi.fn().mockResolvedValue('mock-todo-id'),
}));

// Mock decision service
vi.mock('../../src/services/knowledge/decision.js', () => ({
  storeDecision: vi.fn().mockResolvedValue('mock-decision-id'),
  updateDecision: vi.fn().mockResolvedValue('mock-decision-id'),
}));

describe('P5-T5.3: Business Rule Error Handling', () => {
  let orchestrator: MemoryStoreOrchestrator;

  beforeEach(() => {
    vi.clearAllMocks();
    orchestrator = new MemoryStoreOrchestrator();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Business Rule Violation Status Translation', () => {
    it('should translate decision validation errors to business_rule_blocked status', async () => {
      // Arrange
      const invalidDecision = {
        kind: 'decision',
        scope: { project: 'test-project' },
        data: {
          // Missing required title and rationale
          status: 'accepted',
          acceptance_date: new Date().toISOString(),
        },
      };

      // Act
      const response: MemoryStoreResponse = await orchestrator.storeItems([invalidDecision]);

      // Assert - P5-T5.3 requirements
      expect(response).toBeDefined();
      expect(response.items).toHaveLength(1);
      expect(response.items[0].status).toBe('business_rule_blocked');
      expect(response.items[0].kind).toBe('decision');
      expect(response.items[0].reason).toContain('Decision requires a title');
      expect(response.items[0].reason).toContain('Decision requires a rationale');

      // Verify summary includes business_rule_blocked count
      expect(response.summary.business_rule_blocked).toBe(1);
      expect(response.summary.stored).toBe(0);
      expect(response.summary.total).toBe(1);
    });

    it('should translate incident validation errors to business_rule_blocked status', async () => {
      // Arrange
      const criticalIncidentWithoutCommander = {
        kind: 'incident',
        scope: { project: 'test-project' },
        data: {
          title: 'Critical Incident',
          severity: 'critical',
          // Missing required incident_commander for critical severity
        },
      };

      // Act
      const response: MemoryStoreResponse = await orchestrator.storeItems([
        criticalIncidentWithoutCommander,
      ]);

      // Assert
      expect(response.items).toHaveLength(1);
      expect(response.items[0].status).toBe('business_rule_blocked');
      expect(response.items[0].kind).toBe('incident');
      expect(response.items[0].reason).toContain(
        'Critical incidents require assignment of incident commander'
      );
      expect(response.summary.business_rule_blocked).toBe(1);
    });

    it('should translate risk validation errors to business_rule_blocked status', async () => {
      // Arrange
      const criticalRiskWithoutMitigation = {
        kind: 'risk',
        scope: { project: 'test-project' },
        data: {
          title: 'Critical Risk',
          impact: 'High impact on system',
          risk_level: 'critical',
          // Missing required mitigation_strategies for critical risk
        },
      };

      // Act
      const response: MemoryStoreResponse = await orchestrator.storeItems([
        criticalRiskWithoutMitigation,
      ]);

      // Assert
      expect(response.items).toHaveLength(1);
      expect(response.items[0].status).toBe('business_rule_blocked');
      expect(response.items[0].kind).toBe('risk');
      expect(response.items[0].reason).toContain(
        'Critical risks must have documented mitigation strategies'
      );
      expect(response.summary.business_rule_blocked).toBe(1);
    });

    it('should translate todo validation errors to business_rule_blocked status', async () => {
      // Arrange
      const todoWithCircularDependency = {
        kind: 'todo',
        scope: { project: 'test-project' },
        data: {
          title: 'Todo with circular dependency',
          status: 'pending',
          dependencies: ['todo-self-id'], // This would cause self-dependency error
          id: 'todo-self-id', // Same as dependency ID
        },
      };

      // Act
      const response: MemoryStoreResponse = await orchestrator.storeItems([
        todoWithCircularDependency,
      ]);

      // Assert
      expect(response.items).toHaveLength(1);
      expect(response.items[0].status).toBe('business_rule_blocked');
      expect(response.items[0].kind).toBe('todo');
      expect(response.items[0].reason).toContain('Self-dependency detected');
      expect(response.summary.business_rule_blocked).toBe(1);
    });

    it('should translate DDL validation errors to business_rule_blocked status', async () => {
      // Arrange
      const ddlWithDuplicateMigrationId = {
        kind: 'ddl',
        scope: { project: 'test-project' },
        data: {
          sql: 'CREATE TABLE test (id INT);',
          database: 'testdb',
          migration_id: 'duplicate-migration-001',
          duplicate_migration_id_detected: true,
          existing_ddl_id: 'existing-ddl-123',
        },
      };

      // Act
      const response: MemoryStoreResponse = await orchestrator.storeItems([
        ddlWithDuplicateMigrationId,
      ]);

      // Assert
      expect(response.items).toHaveLength(1);
      expect(response.items[0].status).toBe('business_rule_blocked');
      expect(response.items[0].kind).toBe('ddl');
      expect(response.items[0].reason).toContain('Duplicate migration_id');
      expect(response.summary.business_rule_blocked).toBe(1);
    });
  });

  describe('Batch Processing Continuation', () => {
    it('should continue processing other items when one fails business rules', async () => {
      // Arrange
      const mixedBatch = [
        {
          kind: 'entity',
          scope: { project: 'test-project' },
          data: { name: 'Valid Entity', type: 'service' },
        },
        {
          kind: 'decision',
          scope: { project: 'test-project' },
          data: {
            // Invalid decision - missing required fields
            status: 'accepted',
            acceptance_date: new Date().toISOString(),
          },
        },
        {
          kind: 'observation',
          scope: { project: 'test-project' },
          data: { content: 'Valid observation content' },
        },
        {
          kind: 'incident',
          scope: { project: 'test-project' },
          data: {
            title: 'Critical Incident',
            severity: 'critical',
            // Invalid incident - missing commander
          },
        },
      ];

      // Act
      const response: MemoryStoreResponse = await orchestrator.storeItems(mixedBatch);

      // Assert
      expect(response.items).toHaveLength(4);
      expect(response.summary.total).toBe(4);

      // Valid items should be stored
      const validItems = response.items.filter((item) => item.status === 'stored');
      expect(validItems).toHaveLength(2); // entity and observation

      // Invalid items should be business_rule_blocked
      const blockedItems = response.items.filter((item) => item.status === 'business_rule_blocked');
      expect(blockedItems).toHaveLength(2); // decision and incident

      // Verify summary counts
      expect(response.summary.stored).toBe(2);
      expect(response.summary.business_rule_blocked).toBe(2);
    });

    it('should handle all items failing business rules without stopping', async () => {
      // Arrange
      const allInvalidBatch = [
        {
          kind: 'decision',
          scope: { project: 'test-project' },
          data: { status: 'accepted' }, // Missing title, rationale
        },
        {
          kind: 'incident',
          scope: { project: 'test-project' },
          data: { severity: 'critical' }, // Missing title, commander
        },
        {
          kind: 'risk',
          scope: { project: 'test-project' },
          data: { risk_level: 'critical' }, // Missing title, impact, mitigation
        },
      ];

      // Act
      const response: MemoryStoreResponse = await orchestrator.storeItems(allInvalidBatch);

      // Assert
      expect(response.items).toHaveLength(3);
      expect(response.summary.total).toBe(3);

      // All items should be business_rule_blocked
      response.items.forEach((item) => {
        expect(item.status).toBe('business_rule_blocked');
        expect(item.reason).toBeDefined();
        expect(item.reason.length).toBeGreaterThan(0);
      });

      // Verify summary counts
      expect(response.summary.stored).toBe(0);
      expect(response.summary.business_rule_blocked).toBe(3);
    });

    it('should provide detailed reasons for each business rule violation', async () => {
      // Arrange
      const itemsWithSpecificViolations = [
        {
          kind: 'decision',
          scope: { project: 'test-project' },
          data: { status: 'accepted' }, // Missing title and rationale
        },
        {
          kind: 'todo',
          scope: { project: 'test-project' },
          data: {
            title: 'Todo with multiple issues',
            status: 'invalid_status', // Invalid status
            dependencies: ['self-id'],
            id: 'self-id', // Self-dependency
          },
        },
      ];

      // Act
      const response: MemoryStoreResponse = await orchestrator.storeItems(
        itemsWithSpecificViolations
      );

      // Assert
      expect(response.items).toHaveLength(2);

      // Decision should have multiple errors
      const decisionResult = response.items.find((item) => item.kind === 'decision');
      expect(decisionResult?.status).toBe('business_rule_blocked');
      expect(decisionResult?.reason).toContain('Decision requires a title');
      expect(decisionResult?.reason).toContain('Decision requires a rationale');

      // Todo should have multiple errors
      const todoResult = response.items.find((item) => item.kind === 'todo');
      expect(todoResult?.status).toBe('business_rule_blocked');
      expect(todoResult?.reason).toContain('Invalid todo status');
      expect(todoResult?.reason).toContain('Self-dependency detected');
    });
  });

  describe('Integration with Existing Validation System', () => {
    it('should work with validator registry integration', async () => {
      // Arrange
      const validators = createBusinessValidators();

      // Ensure validators are registered
      expect(validators.has('decision')).toBe(true);
      expect(validators.has('incident')).toBe(true);
      expect(validators.has('risk')).toBe(true);
      expect(validators.has('todo')).toBe(true);
      expect(validators.has('ddl')).toBe(true);

      const itemWithBusinessRuleViolation = {
        kind: 'decision',
        scope: { project: 'test-project' },
        data: {
          // Attempting to modify accepted decision without proper supersedes
          title: 'Accepted Decision',
          rationale: 'Original rationale',
          status: 'accepted',
          acceptance_date: '2023-01-01T00:00:00Z',
          updated_at: '2023-01-02T00:00:00Z', // Later than created_at
          created_at: '2023-01-01T00:00:00Z',
        },
      };

      // Act
      const response: MemoryStoreResponse = await orchestrator.storeItems([
        itemWithBusinessRuleViolation,
      ]);

      // Assert
      expect(response.items[0].status).toBe('business_rule_blocked');
      expect(response.items[0].reason).toContain('Cannot modify accepted decision');
    });

    it('should handle warnings alongside errors correctly', async () => {
      // Arrange
      const itemWithWarningsAndErrors = {
        kind: 'incident',
        scope: { project: 'test-project' },
        data: {
          title: 'Critical Incident',
          severity: 'critical',
          incident_commander: {
            name: 'John Doe',
            role: 'Incident Commander',
            // Missing contact info - this would be a warning
          },
          resolution_status: 'closed', // This might generate a warning about reopening
        },
      };

      // Act
      const response: MemoryStoreResponse = await orchestrator.storeItems([
        itemWithWarningsAndErrors,
      ]);

      // Assert - Errors take precedence, should still be business_rule_blocked
      expect(response.items[0].status).toBe('business_rule_blocked');
      expect(response.items[0].reason).toBeDefined();
      // The reason should contain the error (missing contact info is likely an error in this case)
    });
  });

  describe('Error Response Structure Compliance', () => {
    it('should maintain backward compatibility with legacy response format', async () => {
      // Arrange
      const invalidItem = {
        kind: 'decision',
        scope: { project: 'test-project' },
        data: { status: 'accepted' }, // Missing required fields
      };

      // Act
      const response: MemoryStoreResponse = await orchestrator.storeItems([invalidItem]);

      // Assert - Check new format
      expect(response.items).toBeDefined();
      expect(response.summary).toBeDefined();
      expect(response.items[0].status).toBe('business_rule_blocked');

      // Check legacy format compatibility
      expect(response.stored).toBeDefined();
      expect(response.errors).toBeDefined();
      expect(response.autonomous_context).toBeDefined();

      // Legacy stored should be empty for business rule violations
      expect(response.stored).toHaveLength(0);

      // Errors should be empty for business rule violations (they're in items array)
      expect(response.errors).toHaveLength(0);
    });

    it('should include proper error codes and metadata', async () => {
      // Arrange
      const invalidItem = {
        kind: 'ddl',
        scope: { project: 'test-project' },
        data: {
          sql: 'CREATE TABLE test (id INT);',
          database: 'testdb',
          migration_id: 'test-migration',
          duplicate_migration_id_detected: true,
          existing_ddl_id: 'existing-123',
        },
      };

      // Act
      const response: MemoryStoreResponse = await orchestrator.storeItems([invalidItem]);

      // Assert
      const itemResult = response.items[0];
      expect(itemResult.status).toBe('business_rule_blocked');
      expect(itemResult.kind).toBe('ddl');
      expect(itemResult.input_index).toBe(0);
      expect(itemResult.reason).toBeDefined();
      expect(itemResult.reason.length).toBeGreaterThan(0);
      expect(itemResult.created_at).toBeDefined();
    });
  });
});
