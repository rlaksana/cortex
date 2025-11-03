/**
 * Comprehensive test suite for business validators
 * Tests all P5-T5.1 business rules and validation scenarios
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import {
  DecisionValidator,
  IncidentValidator,
  RiskValidator,
  TodoValidator,
  DDLValidator,
  createBusinessValidators,
} from '../business-validators.js';
import type { KnowledgeItem } from '../../../types/core-interfaces.js';

describe('Business Validators', () => {
  describe('DecisionValidator', () => {
    let validator: DecisionValidator;

    beforeEach(() => {
      validator = new DecisionValidator();
    });

    it('should validate a complete decision', async () => {
      const validDecision: KnowledgeItem = {
        id: 'decision-1',
        kind: 'decision',
        scope: { project: 'test-project' },
        data: {
          title: 'Test Decision',
          rationale: 'This is a test rationale for the decision',
          status: 'draft',
          created_at: '2025-01-01T00:00:00Z',
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(validDecision);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject decision without title', async () => {
      const invalidDecision: KnowledgeItem = {
        id: 'decision-2',
        kind: 'decision',
        scope: { project: 'test-project' },
        data: {
          rationale: 'Rationale without title',
          status: 'draft',
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(invalidDecision);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Decision requires a title');
    });

    it('should reject decision without rationale', async () => {
      const invalidDecision: KnowledgeItem = {
        id: 'decision-3',
        kind: 'decision',
        scope: { project: 'test-project' },
        data: {
          title: 'Title without rationale',
          status: 'draft',
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(invalidDecision);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Decision requires a rationale');
    });

    it('should enforce immutability for accepted decisions', async () => {
      const acceptedDecision: KnowledgeItem = {
        id: 'decision-4',
        kind: 'decision',
        scope: { project: 'test-project' },
        data: {
          title: 'Accepted Decision',
          rationale: 'This decision is accepted',
          status: 'accepted',
          acceptance_date: '2025-01-01T00:00:00Z',
          created_at: '2025-01-01T00:00:00Z',
          updated_at: '2025-01-02T00:00:00Z', // Modified after acceptance
        },
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-02T00:00:00Z',
      };

      const result = await validator.validate(acceptedDecision);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Cannot modify accepted decision - must create a new decision that supersedes this one'
      );
    });

    it('should prevent status reversion from accepted to draft', async () => {
      const revertedDecision: KnowledgeItem = {
        id: 'decision-5',
        kind: 'decision',
        scope: { project: 'test-project' },
        data: {
          title: 'Reverted Decision',
          rationale: 'This decision is being reverted',
          status: 'draft',
          original_status: 'accepted', // Attempting to revert
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(revertedDecision);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Cannot revert accepted decision back to draft status - must create new decision'
      );
    });

    it('should allow modifications to accepted decisions with proper supersede relationship', async () => {
      const supersededDecision: KnowledgeItem = {
        id: 'decision-6',
        kind: 'decision',
        scope: { project: 'test-project' },
        data: {
          title: 'Superseded Decision',
          rationale: 'This decision is superseded',
          status: 'superseded',
          acceptance_date: '2025-01-01T00:00:00Z',
          superseded_by: 'decision-7', // Proper supersede relationship
          created_at: '2025-01-01T00:00:00Z',
          updated_at: '2025-01-02T00:00:00Z',
        },
        created_at: '2025-01-01T00:00:00Z',
        updated_at: '2025-01-02T00:00:00Z',
      };

      const result = await validator.validate(supersededDecision);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('IncidentValidator', () => {
    let validator: IncidentValidator;

    beforeEach(() => {
      validator = new IncidentValidator();
    });

    it('should validate a complete incident', async () => {
      const validIncident: KnowledgeItem = {
        id: 'incident-1',
        kind: 'incident',
        scope: { project: 'test-project' },
        data: {
          title: 'Test Incident',
          severity: 'medium',
          description: 'This is a test incident',
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(validIncident);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should require incident commander for critical incidents', async () => {
      const criticalIncident: KnowledgeItem = {
        id: 'incident-2',
        kind: 'incident',
        scope: { project: 'test-project' },
        data: {
          title: 'Critical Incident',
          severity: 'critical',
          description: 'This is a critical incident',
          // Missing incident commander
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(criticalIncident);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Critical incidents require assignment of incident commander'
      );
    });

    it('should require complete commander information', async () => {
      const criticalIncident: KnowledgeItem = {
        id: 'incident-3',
        kind: 'incident',
        scope: { project: 'test-project' },
        data: {
          title: 'Critical Incident',
          severity: 'critical',
          description: 'This is a critical incident',
          incident_commander: {
            name: 'John Doe',
            // Missing role and contact
          },
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(criticalIncident);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Critical incident commander must have complete contact information (name, role, contact)'
      );
    });

    it('should validate critical incident with complete commander info', async () => {
      const validCriticalIncident: KnowledgeItem = {
        id: 'incident-4',
        kind: 'incident',
        scope: { project: 'test-project' },
        data: {
          title: 'Critical Incident',
          severity: 'critical',
          description: 'This is a critical incident',
          incident_commander: {
            name: 'John Doe',
            role: 'Incident Commander',
            contact: 'john.doe@example.com',
          },
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(validCriticalIncident);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should warn about reopening closed incidents', async () => {
      const closedIncident: KnowledgeItem = {
        id: 'incident-5',
        kind: 'incident',
        scope: { project: 'test-project' },
        data: {
          title: 'Closed Incident',
          severity: 'medium',
          description: 'This incident is closed',
          resolution_status: 'closed',
          // Missing reopen_authorized
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(closedIncident);
      expect(result.valid).toBe(true);
      expect(result.warnings).toContain('Reopening closed incidents may require authorization');
    });
  });

  describe('RiskValidator', () => {
    let validator: RiskValidator;

    beforeEach(() => {
      validator = new RiskValidator();
    });

    it('should validate a complete risk', async () => {
      const validRisk: KnowledgeItem = {
        id: 'risk-1',
        kind: 'risk',
        scope: { project: 'test-project' },
        data: {
          title: 'Test Risk',
          impact: 'This is the impact description',
          risk_level: 'medium',
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(validRisk);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should require mitigation strategies for critical risks', async () => {
      const criticalRisk: KnowledgeItem = {
        id: 'risk-2',
        kind: 'risk',
        scope: { project: 'test-project' },
        data: {
          title: 'Critical Risk',
          impact: 'This is a critical risk impact',
          risk_level: 'critical',
          // Missing mitigation strategies
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(criticalRisk);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Critical risks must have documented mitigation strategies');
    });

    it('should require complete mitigation strategy information', async () => {
      const criticalRisk: KnowledgeItem = {
        id: 'risk-3',
        kind: 'risk',
        scope: { project: 'test-project' },
        data: {
          title: 'Critical Risk',
          impact: 'This is a critical risk impact',
          risk_level: 'critical',
          mitigation_strategies: [
            {
              strategy: 'Mitigation strategy',
              // Missing required fields
            },
          ],
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(criticalRisk);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Critical risk mitigation strategies must have complete information (strategy, owner, due_date, status, effectiveness)'
      );
    });

    it('should prevent closure of critical risks without complete mitigation', async () => {
      const closedCriticalRisk: KnowledgeItem = {
        id: 'risk-4',
        kind: 'risk',
        scope: { project: 'test-project' },
        data: {
          title: 'Closed Critical Risk',
          impact: 'This is a critical risk impact',
          risk_level: 'critical',
          status: 'closed',
          mitigation_strategies: [
            {
              strategy: 'Incomplete mitigation',
              owner: 'test',
              due_date: '2025-01-01',
              status: 'pending', // Not completed
              effectiveness: 'unknown',
            },
          ],
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(closedCriticalRisk);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Cannot close critical risk until all mitigation strategies are implemented and verified'
      );
    });

    it('should require owners for accepted risks', async () => {
      const acceptedRisk: KnowledgeItem = {
        id: 'risk-5',
        kind: 'risk',
        scope: { project: 'test-project' },
        data: {
          title: 'Accepted Risk',
          impact: 'This is an accepted risk impact',
          risk_level: 'medium',
          status: 'accepted',
          // Missing owner
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(acceptedRisk);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Accepted risks must have an assigned owner');
    });
  });

  describe('TodoValidator', () => {
    let validator: TodoValidator;

    beforeEach(() => {
      validator = new TodoValidator();
    });

    it('should validate a complete todo', async () => {
      const validTodo: KnowledgeItem = {
        id: 'todo-1',
        kind: 'todo',
        scope: { project: 'test-project' },
        data: {
          title: 'Test Todo',
          status: 'pending',
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(validTodo);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject invalid todo status', async () => {
      const invalidTodo: KnowledgeItem = {
        id: 'todo-2',
        kind: 'todo',
        scope: { project: 'test-project' },
        data: {
          title: 'Invalid Todo',
          status: 'invalid_status',
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(invalidTodo);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Invalid todo status: invalid_status');
    });

    it('should auto-set completed_at timestamp for done todos', async () => {
      const doneTodo: KnowledgeItem = {
        id: 'todo-3',
        kind: 'todo',
        scope: { project: 'test-project' },
        data: {
          title: 'Done Todo',
          status: 'done',
          // Missing completed_at
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(doneTodo);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.warnings).toContain(
        'Todo marked as done without completed_at timestamp - auto-setting current time'
      );
      expect(doneTodo.data.completed_at).toBeDefined();
    });

    it('should detect self-dependency', async () => {
      const selfDependentTodo: KnowledgeItem = {
        id: 'todo-4',
        kind: 'todo',
        scope: { project: 'test-project' },
        data: {
          title: 'Self-Dependent Todo',
          status: 'pending',
          dependencies: ['todo-4'], // Self-dependency
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(selfDependentTodo);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Self-dependency detected: todo-4 cannot depend on itself');
    });

    it('should detect circular dependency flag', async () => {
      const circularTodo: KnowledgeItem = {
        id: 'todo-5',
        kind: 'todo',
        scope: { project: 'test-project' },
        data: {
          title: 'Circular Todo',
          status: 'pending',
          circular_dependency_detected: true,
          circular_dependency_path: ['todo-5', 'todo-6', 'todo-5'],
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(circularTodo);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Circular dependency detected: todo-5 -> todo-6 -> todo-5');
    });
  });

  describe('DDLValidator', () => {
    let validator: DDLValidator;

    beforeEach(() => {
      validator = new DDLValidator();
    });

    it('should validate a complete DDL', async () => {
      const validDDL: KnowledgeItem = {
        id: 'ddl-1',
        kind: 'ddl',
        scope: { project: 'test-project' },
        data: {
          sql: 'CREATE TABLE test (id INT PRIMARY KEY);',
          database: 'test_db',
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(validDDL);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should require checksum when required', async () => {
      const ddlWithoutChecksum: KnowledgeItem = {
        id: 'ddl-2',
        kind: 'ddl',
        scope: { project: 'test-project' },
        data: {
          sql: 'CREATE TABLE test (id INT PRIMARY KEY);',
          database: 'test_db',
          checksum_required: true,
          // Missing checksum
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(ddlWithoutChecksum);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('DDL requires checksum verification');
    });

    it('should validate checksum format', async () => {
      const ddlWithInvalidChecksum: KnowledgeItem = {
        id: 'ddl-3',
        kind: 'ddl',
        scope: { project: 'test-project' },
        data: {
          sql: 'CREATE TABLE test (id INT PRIMARY KEY);',
          database: 'test_db',
          checksum_required: true,
          checksum: 'invalid_checksum_format',
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(ddlWithInvalidChecksum);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Invalid checksum format: must be in format "algorithm:hash"'
      );
    });

    it('should reject duplicate migration IDs', async () => {
      const ddlWithDuplicateMigration: KnowledgeItem = {
        id: 'ddl-4',
        kind: 'ddl',
        scope: { project: 'test-project' },
        data: {
          sql: 'CREATE TABLE test (id INT PRIMARY KEY);',
          database: 'test_db',
          migration_id: '20250101_001_create_test',
          duplicate_migration_id_detected: true,
          existing_ddl_id: 'ddl-old',
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(ddlWithDuplicateMigration);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Duplicate migration_id "20250101_001_create_test" detected in scope "test-project:test_db". Existing DDL ID: ddl-old'
      );
    });

    it('should require rollback SQL when rollback is required', async () => {
      const ddlWithoutRollback: KnowledgeItem = {
        id: 'ddl-5',
        kind: 'ddl',
        scope: { project: 'test-project' },
        data: {
          sql: 'CREATE TABLE test (id INT PRIMARY KEY);',
          database: 'test_db',
          rollback_required: true,
          // Missing rollback_sql
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(ddlWithoutRollback);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('DDL requires rollback SQL when rollback is required');
    });

    it('should warn about destructive migrations without backup', async () => {
      const destructiveDDL: KnowledgeItem = {
        id: 'ddl-6',
        kind: 'ddl',
        scope: { project: 'test-project' },
        data: {
          sql: 'DROP TABLE important_table;',
          database: 'test_db',
          migration_type: 'destructive',
          // Missing backup_required
        },
        created_at: '2025-01-01T00:00:00Z',
      };

      const result = await validator.validate(destructiveDDL);
      expect(result.valid).toBe(true);
      expect(result.warnings).toContain('Destructive migrations should require backup');
    });
  });

  describe('Validator Factory', () => {
    it('should create all required validators', () => {
      const validators = createBusinessValidators();

      expect(validators.size).toBe(5);
      expect(validators.has('decision')).toBe(true);
      expect(validators.has('incident')).toBe(true);
      expect(validators.has('risk')).toBe(true);
      expect(validators.has('todo')).toBe(true);
      expect(validators.has('ddl')).toBe(true);
    });

    it('should create validator instances with correct types', () => {
      const validators = createBusinessValidators();

      expect(validators.get('decision')).toBeInstanceOf(DecisionValidator);
      expect(validators.get('incident')).toBeInstanceOf(IncidentValidator);
      expect(validators.get('risk')).toBeInstanceOf(RiskValidator);
      expect(validators.get('todo')).toBeInstanceOf(TodoValidator);
      expect(validators.get('ddl')).toBeInstanceOf(DDLValidator);
    });
  });

  describe('Validator Type Methods', () => {
    it('should return correct validator types', () => {
      const decisionValidator = new DecisionValidator();
      const incidentValidator = new IncidentValidator();
      const riskValidator = new RiskValidator();
      const todoValidator = new TodoValidator();
      const ddlValidator = new DDLValidator();

      expect(decisionValidator.getType()).toBe('decision');
      expect(incidentValidator.getType()).toBe('incident');
      expect(riskValidator.getType()).toBe('risk');
      expect(todoValidator.getType()).toBe('todo');
      expect(ddlValidator.getType()).toBe('ddl');
    });
  });
});
