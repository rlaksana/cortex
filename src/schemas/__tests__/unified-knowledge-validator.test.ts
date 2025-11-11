/**
 * Unified Knowledge Type Validator Test Suite
 *
 * Comprehensive test coverage for all validation scenarios including:
 * - Schema validation for all 16 knowledge types
 * - Business rule validation
 * - Performance constraint validation
 * - Request/response validation
 * - Edge cases and error handling
 *
 * @version 2.0.0 - T20 Implementation
 */

import { beforeEach,describe, expect, it } from 'vitest';

import {
  BaseScopeSchema,
  DeleteRequestSchema,
  KnowledgeItemSchema,
  MemoryFindRequestSchema,
  MemoryStoreRequestSchema,
  UnifiedKnowledgeTypeValidator,
  validateDeleteRequest,
  validateKnowledgeItem,
  validateMemoryFindRequest,
  validateMemoryStoreRequest,
  ValidationErrorCategory,
  ValidationErrorSeverity,
  ValidationMode,
} from '../unified-knowledge-validator.js';

describe('UnifiedKnowledgeTypeValidator', () => {
  let validator: UnifiedKnowledgeTypeValidator;

  beforeEach(() => {
    validator = UnifiedKnowledgeTypeValidator.getInstance();
  });

  // ============================================================================
  // Schema Validation Tests
  // ============================================================================

  describe('Schema Validation', () => {
    describe('Section Knowledge Type', () => {
      it('should validate a valid section with minimal data', async () => {
        const section = {
          kind: 'section',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test Section', body_md: '# Test Content' },
        };

        const result = await validator.validateKnowledgeItem(section);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should validate a section with complete data', async () => {
        const section = {
          kind: 'section',
          scope: { project: 'test', branch: 'main', org: 'example' },
          data: {
            id: '123e4567-e89b-12d3-a456-426614174000',
            title: 'Complete Section',
            heading: 'Section Heading',
            body_md: '# Section Content\n\nThis is a test section.',
            body_text: 'Section Content\n\nThis is a test section.',
            document_id: '123e4567-e89b-12d3-a456-426614174001',
            citation_count: 5,
          },
          metadata: { source: 'test' },
        };

        const result = await validator.validateKnowledgeItem(section);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should reject section without required fields', async () => {
        const section = {
          kind: 'section',
          scope: { project: 'test', branch: 'main' },
          data: {},
        };

        const result = await validator.validateKnowledgeItem(section);
        expect(result.valid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
        expect(result.errors[0].field).toBe('data');
      });

      it('should reject section with title too long', async () => {
        const section = {
          kind: 'section',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'a'.repeat(501), body_md: '# Test' },
        };

        const result = await validator.validateKnowledgeItem(section);
        expect(result.valid).toBe(false);
        expect(
          result.errors.some((e) => e.message.includes('Title cannot exceed 500 characters'))
        ).toBe(true);
      });
    });

    describe('Decision Knowledge Type', () => {
      it('should validate a valid decision', async () => {
        const decision = {
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: {
            component: 'auth-service',
            status: 'accepted',
            title: 'Use OAuth 2.0 for Authentication',
            rationale:
              'OAuth 2.0 provides industry-standard security with token-based authentication, supporting refresh tokens and revocation.',
          },
        };

        const result = await validator.validateKnowledgeItem(decision);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should reject decision with insufficient rationale', async () => {
        const decision = {
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: {
            component: 'auth-service',
            status: 'accepted',
            title: 'Use OAuth 2.0',
            rationale: 'Good choice',
          },
        };

        const result = await validator.validateKnowledgeItem(decision);
        expect(result.valid).toBe(false);
        expect(result.errors.some((e) => e.code === 'DECISION_INSUFFICIENT_RATIONALE')).toBe(true);
      });

      it('should accept decision with proposed status and minimal rationale', async () => {
        const decision = {
          kind: 'decision',
          scope: { project: 'test', branch: 'main' },
          data: {
            component: 'auth-service',
            status: 'proposed',
            title: 'Use OAuth 2.0',
            rationale: 'Standard authentication approach',
          },
        };

        const result = await validator.validateKnowledgeItem(decision);
        expect(result.valid).toBe(true);
      });
    });

    describe('Issue Knowledge Type', () => {
      it('should validate a valid issue', async () => {
        const issue = {
          kind: 'issue',
          scope: { project: 'test', branch: 'main' },
          data: {
            tracker: 'github',
            external_id: 'GH-123',
            title: 'Authentication fails on mobile',
            description: 'Users report authentication errors when using mobile app',
            severity: 'high',
            status: 'open',
            assignee: 'john.doe',
          },
        };

        const result = await validator.validateKnowledgeItem(issue);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should warn about critical issue without description', async () => {
        const issue = {
          kind: 'issue',
          scope: { project: 'test', branch: 'main' },
          data: {
            title: 'Critical System Down',
            severity: 'critical',
            status: 'open',
          },
        };

        const result = await validator.validateKnowledgeItem(issue);
        expect(result.valid).toBe(true);
        expect(result.warnings.some((e) => e.code === 'CRITICAL_ISSUE_NO_DESCRIPTION')).toBe(true);
      });
    });

    describe('Todo Knowledge Type', () => {
      it('should validate a valid todo', async () => {
        const todo = {
          kind: 'todo',
          scope: { project: 'test', branch: 'main' },
          data: {
            todo_type: 'task',
            text: 'Implement user authentication',
            status: 'open',
            priority: 'high',
            assignee: 'jane.doe',
            due_date: '2024-12-31T23:59:59Z',
          },
        };

        const result = await validator.validateKnowledgeItem(todo);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should warn about critical todo without assignee', async () => {
        const todo = {
          kind: 'todo',
          scope: { project: 'test', branch: 'main' },
          data: {
            todo_type: 'task',
            text: 'Fix critical security vulnerability',
            status: 'open',
            priority: 'critical',
          },
        };

        const result = await validator.validateKnowledgeItem(todo);
        expect(result.valid).toBe(true);
        expect(result.warnings.some((e) => e.code === 'CRITICAL_TODO_NO_ASSIGNEE')).toBe(true);
      });
    });

    describe('Runbook Knowledge Type', () => {
      it('should validate a valid runbook', async () => {
        const runbook = {
          kind: 'runbook',
          scope: { project: 'test', branch: 'main' },
          data: {
            service: 'auth-service',
            title: 'Database Migration',
            description: 'Steps to perform database migration',
            steps: [
              {
                step_number: 1,
                description: 'Backup database',
                command: 'pg_dump db_name > backup.sql',
              },
              { step_number: 2, description: 'Run migration script', command: 'npm run migrate' },
              {
                step_number: 3,
                description: 'Verify migration',
                expected_outcome: 'All tables updated',
              },
            ],
            last_verified_at: '2024-01-15T10:00:00Z',
          },
        };

        const result = await validator.validateKnowledgeItem(runbook);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should reject runbook without steps', async () => {
        const runbook = {
          kind: 'runbook',
          scope: { project: 'test', branch: 'main' },
          data: {
            service: 'auth-service',
            title: 'Empty Runbook',
            steps: [],
          },
        };

        const result = await validator.validateKnowledgeItem(runbook);
        expect(result.valid).toBe(false);
        expect(result.errors.some((e) => e.message.includes('At least one step is required'))).toBe(
          true
        );
      });
    });

    describe('Change Knowledge Type', () => {
      it('should validate a valid change', async () => {
        const change = {
          kind: 'change',
          scope: { project: 'test', branch: 'main' },
          data: {
            change_type: 'feature_add',
            subject_ref: 'PR-456',
            summary: 'Add user authentication feature',
            details: 'Implement OAuth 2.0 authentication with JWT tokens',
            affected_files: ['src/auth/login.js', 'src/auth/middleware.js'],
            author: 'john.doe',
            commit_sha: 'abc123def456',
          },
        };

        const result = await validator.validateKnowledgeItem(change);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });
    });

    describe('Release Note Knowledge Type', () => {
      it('should validate a valid release note', async () => {
        const releaseNote = {
          kind: 'release_note',
          scope: { project: 'test', branch: 'main' },
          data: {
            version: '2.1.0',
            release_date: '2024-01-15T10:00:00Z',
            summary: 'Feature release with user authentication',
            new_features: ['OAuth 2.0 authentication', 'Password reset flow'],
            bug_fixes: ['Fixed login redirect issue'],
          },
        };

        const result = await validator.validateKnowledgeItem(releaseNote);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should warn about breaking changes not in summary', async () => {
        const releaseNote = {
          kind: 'release_note',
          scope: { project: 'test', branch: 'main' },
          data: {
            version: '2.1.0',
            release_date: '2024-01-15T10:00:00Z',
            summary: 'Feature release',
            breaking_changes: ['API endpoint removal'],
          },
        };

        const result = await validator.validateKnowledgeItem(releaseNote);
        expect(result.valid).toBe(true);
        expect(result.warnings.some((e) => e.code === 'BREAKING_CHANGES_NOT_IN_SUMMARY')).toBe(
          true
        );
      });
    });

    describe('DDL Knowledge Type', () => {
      it('should validate a valid DDL', async () => {
        const ddl = {
          kind: 'ddl',
          scope: { project: 'test', branch: 'main' },
          data: {
            migration_id: '20240115_add_users_table',
            ddl_text: 'CREATE TABLE users (id UUID PRIMARY KEY, email VARCHAR(255) UNIQUE);',
            checksum: 'abc123def456',
            description: 'Add users table for authentication',
          },
        };

        const result = await validator.validateKnowledgeItem(ddl);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should warn about invalid migration ID format', async () => {
        const ddl = {
          kind: 'ddl',
          scope: { project: 'test', branch: 'main' },
          data: {
            migration_id: 'invalid@migration#id',
            ddl_text: 'CREATE TABLE users (id UUID PRIMARY KEY);',
          },
        };

        const result = await validator.validateKnowledgeItem(ddl);
        expect(result.valid).toBe(true);
        expect(result.warnings.some((e) => e.code === 'DDL_INVALID_MIGRATION_ID')).toBe(true);
      });
    });

    describe('PR Context Knowledge Type', () => {
      it('should validate a valid PR context', async () => {
        const prContext = {
          kind: 'pr_context',
          scope: { project: 'test', branch: 'main' },
          data: {
            pr_number: 123,
            title: 'Add user authentication feature',
            description: 'Implements OAuth 2.0 authentication',
            author: 'john.doe',
            status: 'merged',
            base_branch: 'main',
            head_branch: 'feature/auth',
            merged_at: '2024-01-15T10:00:00Z',
          },
        };

        const result = await validator.validateKnowledgeItem(prContext);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should reject PR with same base and head branch', async () => {
        const prContext = {
          kind: 'pr_context',
          scope: { project: 'test', branch: 'main' },
          data: {
            pr_number: 123,
            title: 'Test PR',
            author: 'john.doe',
            status: 'open',
            base_branch: 'main',
            head_branch: 'main',
          },
        };

        const result = await validator.validateKnowledgeItem(prContext);
        expect(result.valid).toBe(false);
        expect(result.errors.some((e) => e.code === 'PR_SAME_BRANCH')).toBe(true);
      });
    });

    describe('Entity Knowledge Type', () => {
      it('should validate a valid entity', async () => {
        const entity = {
          kind: 'entity',
          scope: { project: 'test', branch: 'main' },
          data: {
            entity_type: 'user',
            name: 'john.doe',
            data: {
              email: 'john@example.com',
              role: 'developer',
              department: 'engineering',
            },
          },
        };

        const result = await validator.validateKnowledgeItem(entity);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });
    });

    describe('Relation Knowledge Type', () => {
      it('should validate a valid relation', async () => {
        const relation = {
          kind: 'relation',
          scope: { project: 'test', branch: 'main' },
          data: {
            source: '123e4567-e89b-12d3-a456-426614174000',
            target: '123e4567-e89b-12d3-a456-426614174001',
            type: 'implements',
            metadata: { confidence: 0.9 },
          },
        };

        const result = await validator.validateKnowledgeItem(relation);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should warn about self-referencing relations', async () => {
        const relation = {
          kind: 'relation',
          scope: { project: 'test', branch: 'main' },
          data: {
            source: '123e4567-e89b-12d3-a456-426614174000',
            target: '123e4567-e89b-12d3-a456-426614174000',
            type: 'references',
          },
        };

        const result = await validator.validateKnowledgeItem(relation);
        expect(result.valid).toBe(true);
        expect(result.warnings.some((e) => e.code === 'RELATION_SELF_REFERENCE')).toBe(true);
      });
    });

    describe('Observation Knowledge Type', () => {
      it('should validate a valid observation', async () => {
        const observation = {
          kind: 'observation',
          scope: { project: 'test', branch: 'main' },
          data: {
            content: 'User authentication system is working correctly',
            observation_type: 'status',
            metadata: { verified: true, timestamp: '2024-01-15T10:00:00Z' },
          },
        };

        const result = await validator.validateKnowledgeItem(observation);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });
    });

    describe('Incident Knowledge Type', () => {
      it('should validate a valid incident', async () => {
        const incident = {
          kind: 'incident',
          scope: { project: 'test', branch: 'main' },
          data: {
            title: 'Database connectivity issues',
            severity: 'high',
            impact: 'Users unable to access the application',
            timeline: [
              {
                timestamp: '2024-01-15T09:00:00Z',
                event: 'Incident detected',
                actor: 'monitoring',
              },
              {
                timestamp: '2024-01-15T09:15:00Z',
                event: 'Investigation started',
                actor: 'ops-team',
              },
            ],
            root_cause_analysis: 'Database connection pool exhausted',
            resolution: 'Increased connection pool size',
          },
        };

        const result = await validator.validateKnowledgeItem(incident);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should warn about critical incident without RCA', async () => {
        const incident = {
          kind: 'incident',
          scope: { project: 'test', branch: 'main' },
          data: {
            title: 'System outage',
            severity: 'critical',
            impact: 'Complete system downtime',
          },
        };

        const result = await validator.validateKnowledgeItem(incident);
        expect(result.valid).toBe(true);
        expect(result.warnings.some((e) => e.code === 'CRITICAL_INCIDENT_NO_RCA')).toBe(true);
      });
    });

    describe('Release Knowledge Type', () => {
      it('should validate a valid release', async () => {
        const release = {
          kind: 'release',
          scope: { project: 'test', branch: 'main' },
          data: {
            version: '2.1.0',
            title: 'User Authentication Release',
            status: 'completed',
            deployment_strategy: 'blue-green',
            release_date: '2024-01-15T10:00:00Z',
            rollback_plan: 'Switch to previous version using load balancer',
          },
        };

        const result = await validator.validateKnowledgeItem(release);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should warn about release without rollback plan', async () => {
        const release = {
          kind: 'release',
          scope: { project: 'test', branch: 'main' },
          data: {
            version: '2.1.0',
            title: 'Test Release',
            deployment_strategy: 'rolling',
          },
        };

        const result = await validator.validateKnowledgeItem(release);
        expect(result.valid).toBe(true);
        expect(result.warnings.some((e) => e.code === 'RELEASE_NO_ROLLBACK_PLAN')).toBe(true);
      });
    });

    describe('Risk Knowledge Type', () => {
      it('should validate a valid risk', async () => {
        const risk = {
          kind: 'risk',
          scope: { project: 'test', branch: 'main' },
          data: {
            title: 'Database security vulnerability',
            description: 'Potential SQL injection in legacy code',
            probability: 'possible',
            impact: 'High - data breach possible',
            category: 'security',
            mitigation: 'Implement parameterized queries and input validation',
            risk_level: 'high',
          },
        };

        const result = await validator.validateKnowledgeItem(risk);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should warn about very likely risk with low risk level', async () => {
        const risk = {
          kind: 'risk',
          scope: { project: 'test', branch: 'main' },
          data: {
            title: 'Test Risk',
            description: 'Test description',
            probability: 'very_likely',
            impact: 'Test impact',
            category: 'technical',
            risk_level: 'low',
          },
        };

        const result = await validator.validateKnowledgeItem(risk);
        expect(result.valid).toBe(true);
        expect(result.warnings.some((e) => e.code === 'RISK_PROBABILITY_MISMATCH')).toBe(true);
      });
    });

    describe('Assumption Knowledge Type', () => {
      it('should validate a valid assumption', async () => {
        const assumption = {
          kind: 'assumption',
          scope: { project: 'test', branch: 'main' },
          data: {
            title: 'Users will adopt new authentication system',
            description: 'Users will migrate from password-based to OAuth authentication',
            category: 'user',
            validation_status: 'assumed',
            impact_if_invalid: 'Need to maintain legacy authentication system',
            validation_method: 'User adoption metrics',
          },
        };

        const result = await validator.validateKnowledgeItem(assumption);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should warn about expired assumptions', async () => {
        const assumption = {
          kind: 'assumption',
          scope: { project: 'test', branch: 'main' },
          data: {
            title: 'Test Assumption',
            description: 'Test description',
            category: 'technical',
            impact_if_invalid: 'Test impact',
            expiry_date: '2023-01-01T00:00:00Z', // Past date
          },
        };

        const result = await validator.validateKnowledgeItem(assumption);
        expect(result.valid).toBe(true);
        expect(result.warnings.some((e) => e.code === 'ASSUMPTION_EXPIRED')).toBe(true);
      });
    });
  });

  // ============================================================================
  // Request Validation Tests
  // ============================================================================

  describe('Request Validation', () => {
    describe('Memory Store Request', () => {
      it('should validate a valid memory store request', async () => {
        const request = {
          items: [
            {
              kind: 'section',
              scope: { project: 'test', branch: 'main' },
              data: { title: 'Test Section', body_md: '# Test' },
            },
            {
              kind: 'decision',
              scope: { project: 'test', branch: 'main' },
              data: {
                component: 'auth',
                status: 'accepted',
                title: 'Use OAuth',
                rationale: 'Industry standard authentication approach',
              },
            },
          ],
        };

        const result = await validator.validateMemoryStoreRequest(request);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should reject request with too many items', async () => {
        const items = Array(101).fill({
          kind: 'section',
          scope: { project: 'test', branch: 'main' },
          data: { title: 'Test', body_md: '# Test' },
        });

        const request = { items };

        const result = await validator.validateMemoryStoreRequest(request);
        expect(result.valid).toBe(false);
        expect(
          result.errors.some((e) => e.message.includes('Cannot process more than 100 items'))
        ).toBe(true);
      });

      it('should reject request with no items', async () => {
        const request = { items: [] };

        const result = await validator.validateMemoryStoreRequest(request);
        expect(result.valid).toBe(false);
        expect(result.errors.some((e) => e.message.includes('At least one item is required'))).toBe(
          true
        );
      });

      it('should detect duplicate item IDs', async () => {
        const request = {
          items: [
            {
              id: '123e4567-e89b-12d3-a456-426614174000',
              kind: 'section',
              scope: { project: 'test', branch: 'main' },
              data: { title: 'Section 1', body_md: '# Test 1' },
            },
            {
              id: '123e4567-e89b-12d3-a456-426614174000',
              kind: 'section',
              scope: { project: 'test', branch: 'main' },
              data: { title: 'Section 2', body_md: '# Test 2' },
            },
          ],
        };

        const result = await validator.validateMemoryStoreRequest(request);
        expect(result.valid).toBe(false);
        expect(result.errors.some((e) => e.code === 'DUPLICATE_ITEM_IDS')).toBe(true);
      });
    });

    describe('Memory Find Request', () => {
      it('should validate a valid memory find request', async () => {
        const request = {
          query: 'user authentication',
          scope: { project: 'test', branch: 'main' },
          types: ['decision', 'issue'],
          mode: 'auto' as const,
          limit: 20,
        };

        const result = await validator.validateMemoryFindRequest(request);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should warn about large result set', async () => {
        const request = {
          query: 'test query',
          limit: 150,
        };

        const result = await validator.validateMemoryFindRequest(request);
        expect(result.valid).toBe(true);
        expect(result.warnings.some((e) => e.code === 'LARGE_RESULT_SET')).toBe(true);
      });

      it('should warn about long query', async () => {
        const request = {
          query: 'a'.repeat(1001),
        };

        const result = await validator.validateMemoryFindRequest(request);
        expect(result.valid).toBe(true);
        expect(result.warnings.some((e) => e.code === 'LONG_QUERY')).toBe(true);
      });

      it('should reject request without query', async () => {
        const request = {};

        const result = await validator.validateMemoryFindRequest(request);
        expect(result.valid).toBe(false);
        expect(result.errors.some((e) => e.message.includes('Query is required'))).toBe(true);
      });
    });

    describe('Delete Request', () => {
      it('should validate a valid delete request', async () => {
        const request = {
          id: '123e4567-e89b-12d3-a456-426614174000',
          kind: 'section' as const,
          scope: { project: 'test', branch: 'main' },
          cascade_relations: false,
        };

        const result = await validator.validateDeleteRequest(request);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should warn about cascade delete', async () => {
        const request = {
          id: '123e4567-e89b-12d3-a456-426614174000',
          kind: 'section' as const,
          scope: { project: 'test', branch: 'main' },
          cascade_relations: true,
        };

        const result = await validator.validateDeleteRequest(request);
        expect(result.valid).toBe(true);
        expect(result.warnings.some((e) => e.code === 'CASCADE_DELETE')).toBe(true);
      });

      it('should reject request without ID', async () => {
        const request = {
          kind: 'section' as const,
          scope: { project: 'test', branch: 'main' },
        };

        const result = await validator.validateDeleteRequest(request);
        expect(result.valid).toBe(false);
        expect(result.errors.some((e) => e.message.includes('ID is required'))).toBe(true);
      });
    });
  });

  // ============================================================================
  // Validation Mode Tests
  // ============================================================================

  describe('Validation Modes', () => {
    it('should skip business rules in SCHEMA_ONLY mode', async () => {
      const decision = {
        kind: 'decision',
        scope: { project: 'test', branch: 'main' },
        data: {
          component: 'auth',
          status: 'accepted',
          title: 'Use OAuth',
          rationale: 'Good', // Too short for accepted status
        },
      };

      const result = await validator.validateKnowledgeItem(decision, {
        mode: ValidationMode.SCHEMA_ONLY,
      });

      expect(result.valid).toBe(true); // Should be valid in schema-only mode
      expect(result.errors).toHaveLength(0);
    });

    it('should validate business rules in BUSINESS_RULES_ONLY mode', async () => {
      const decision = {
        kind: 'decision',
        scope: { project: 'test', branch: 'main' },
        data: {
          component: 'auth',
          status: 'accepted',
          title: 'Use OAuth',
          rationale: 'Good', // Too short for accepted status
        },
      };

      const result = await validator.validateKnowledgeItem(decision, {
        mode: ValidationMode.BUSINESS_RULES_ONLY,
      });

      expect(result.valid).toBe(false); // Should fail due to business rule
      expect(result.errors.some((e) => e.code === 'DECISION_INSUFFICIENT_RATIONALE')).toBe(true);
    });

    it('should be strict by default', async () => {
      const decision = {
        kind: 'decision',
        scope: { project: 'test', branch: 'main' },
        data: {
          component: 'auth',
          status: 'accepted',
          title: 'Use OAuth',
          rationale: 'Good', // Too short for accepted status
        },
      };

      const result = await validator.validateKnowledgeItem(decision); // Default is STRICT

      expect(result.valid).toBe(false); // Should fail in strict mode
      expect(result.errors.some((e) => e.code === 'DECISION_INSUFFICIENT_RATIONALE')).toBe(true);
    });
  });

  // ============================================================================
  // Performance Constraint Tests
  // ============================================================================

  describe('Performance Constraints', () => {
    it('should warn about large items', async () => {
      const largeContent = 'a'.repeat(1024 * 1024 + 1); // > 1MB
      const section = {
        kind: 'section',
        scope: { project: 'test', branch: 'main' },
        data: { title: 'Large Section', body_md: largeContent },
      };

      const result = await validator.validateKnowledgeItem(section, {
        enablePerformanceChecks: true,
      });

      expect(result.valid).toBe(true);
      expect(result.warnings.some((e) => e.code === 'LARGE_ITEM_SIZE')).toBe(true);
    });

    it('should warn about deeply nested objects', async () => {
      const deepObject: any = {};
      let current = deepObject;

      // Create a 12-level deep object
      for (let i = 0; i < 12; i++) {
        current.nested = {};
        current = current.nested;
      }
      current.value = 'deep value';

      const entity = {
        kind: 'entity',
        scope: { project: 'test', branch: 'main' },
        data: {
          entity_type: 'test',
          name: 'deep entity',
          data: deepObject,
        },
      };

      const result = await validator.validateKnowledgeItem(entity, {
        enablePerformanceChecks: true,
      });

      expect(result.valid).toBe(true);
      expect(result.warnings.some((e) => e.code === 'DEEP_NESTING')).toBe(true);
    });
  });

  // ============================================================================
  // Error Handling Tests
  // ============================================================================

  describe('Error Handling', () => {
    it('should handle circular references gracefully', async () => {
      const circularObject: any = { name: 'test' };
      circularObject.self = circularObject;

      const entity = {
        kind: 'entity',
        scope: { project: 'test', branch: 'main' },
        data: {
          entity_type: 'test',
          name: 'circular entity',
          data: circularObject,
        },
      };

      const result = await validator.validateKnowledgeItem(entity);
      // Should not crash and should handle gracefully
      expect(result).toBeDefined();
    });

    it('should handle invalid input types', async () => {
      const result = await validator.validateKnowledgeItem(null);
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should handle malformed JSON', async () => {
      const malformed = {
        kind: 'section',
        scope: null, // Invalid scope
        data: undefined, // Invalid data
      };

      const result = await validator.validateKnowledgeItem(malformed);
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  // ============================================================================
  // Convenience Function Tests
  // ============================================================================

  describe('Convenience Functions', () => {
    it('should validate knowledge item using convenience function', async () => {
      const section = {
        kind: 'section',
        scope: { project: 'test', branch: 'main' },
        data: { title: 'Test Section', body_md: '# Test' },
      };

      const result = await validateKnowledgeItem(section);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should validate memory store request using convenience function', async () => {
      const request = {
        items: [
          {
            kind: 'section',
            scope: { project: 'test', branch: 'main' },
            data: { title: 'Test Section', body_md: '# Test' },
          },
        ],
      };

      const result = await validateMemoryStoreRequest(request);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should validate memory find request using convenience function', async () => {
      const request = {
        query: 'test query',
        limit: 10,
      };

      const result = await validateMemoryFindRequest(request);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should validate delete request using convenience function', async () => {
      const request = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        kind: 'section' as const,
        scope: { project: 'test', branch: 'main' },
      };

      const result = await validateDeleteRequest(request);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });

  // ============================================================================
  // Edge Cases
  // ============================================================================

  describe('Edge Cases', () => {
    it('should handle empty strings in optional fields', async () => {
      const section = {
        kind: 'section',
        scope: { project: 'test', branch: 'main' },
        data: {
          title: 'Test Section',
          body_md: '# Test',
          heading: '', // Empty optional field
        },
      };

      const result = await validator.validateKnowledgeItem(section);
      expect(result.valid).toBe(true);
    });

    it('should handle special characters in text fields', async () => {
      const section = {
        kind: 'section',
        scope: { project: 'test', branch: 'main' },
        data: {
          title: 'Test with émojis 🚀 and spëcial chars!',
          body_md: '# Content with unicode: àáâãäåæçèéêë',
        },
      };

      const result = await validator.validateKnowledgeItem(section);
      expect(result.valid).toBe(true);
    });

    it('should handle maximum length boundaries', async () => {
      const title500 = 'a'.repeat(500);
      const title501 = 'a'.repeat(501);

      // Should accept exactly 500 characters
      const validSection = {
        kind: 'section',
        scope: { project: 'test', branch: 'main' },
        data: { title: title500, body_md: '# Test' },
      };

      const validResult = await validator.validateKnowledgeItem(validSection);
      expect(validResult.valid).toBe(true);

      // Should reject 501 characters
      const invalidSection = {
        kind: 'section',
        scope: { project: 'test', branch: 'main' },
        data: { title: title501, body_md: '# Test' },
      };

      const invalidResult = await validator.validateKnowledgeItem(invalidSection);
      expect(invalidResult.valid).toBe(false);
    });

    it('should validate UUID formats', async () => {
      const validUUID = '123e4567-e89b-12d3-a456-426614174000';
      const invalidUUID = 'not-a-uuid';

      const validSection = {
        kind: 'section',
        scope: { project: 'test', branch: 'main' },
        data: {
          id: validUUID,
          title: 'Test',
          body_md: '# Test',
        },
      };

      const validResult = await validator.validateKnowledgeItem(validSection);
      expect(validResult.valid).toBe(true);

      const invalidSection = {
        kind: 'section',
        scope: { project: 'test', branch: 'main' },
        data: {
          id: invalidUUID,
          title: 'Test',
          body_md: '# Test',
        },
      };

      const invalidResult = await validator.validateKnowledgeItem(invalidSection);
      expect(invalidResult.valid).toBe(false);
    });
  });
});
