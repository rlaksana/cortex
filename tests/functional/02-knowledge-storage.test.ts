/**
 * Category 2: Knowledge Storage Tests
 * Priority: P0 - CRITICAL
 *
 * Tests storing all 9 knowledge types
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { memoryStore } from '../services/memory-store.ts';
// PostgreSQL import removed - now using Qdrant;

const TEST_SCOPE = {
  project: 'test-project',
  branch: 'test-functional',
  org: 'test-org',
};

describe('Category 2: Knowledge Storage', () => {
  let pool: QdrantClient;

  beforeAll(() => {
    pool = new QdrantClient({
      connectionString:
        process.env.QDRANT_URL || 'http://cortex:trust@localhost:5433/cortex_prod',
    });
  });

  afterAll(async () => {
    // Cleanup test data
    await pool.query(
      `DELETE FROM knowledge WHERE scope->>'project' = $1 AND scope->>'branch' = $2`,
      [TEST_SCOPE.project, TEST_SCOPE.branch]
    );
    await pool.end();
  });

  describe('KS-001: Store Section (basic)', () => {
    it('should store section and return ID', async () => {
      const result = await memoryStore([
        {
          kind: 'section',
          scope: TEST_SCOPE,
          data: {
            title: 'Test Section',
            body_md: '# Test\nThis is test content',
            document_id: 'doc-001',
          },
        },
      ]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0]).toHaveProperty('id');
      expect(result.stored[0].kind).toBe('section');
    });
  });

  describe('KS-002: Store Runbook', () => {
    it('should store runbook', async () => {
      const result = await memoryStore([
        {
          kind: 'runbook',
          scope: TEST_SCOPE,
          data: {
            title: 'Deployment Runbook',
            service: 'api-server',
            steps: [
              { step: 1, action: 'Build Docker image' },
              { step: 2, action: 'Push to registry' },
            ],
            owner: 'devops-team',
          },
        },
      ]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].kind).toBe('runbook');
    });
  });

  describe('KS-003: Store Change', () => {
    it('should store change', async () => {
      const result = await memoryStore([
        {
          kind: 'change',
          scope: TEST_SCOPE,
          data: {
            subject_ref: 'PR-123',
            service: 'auth-service',
            change_type: 'feature_add',
            change_summary: 'Added OAuth support',
            change_details: 'Implemented OAuth 2.0 authentication flow',
          },
        },
      ]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].kind).toBe('change');
    });
  });

  describe('KS-004: Store Issue', () => {
    it('should store issue', async () => {
      const result = await memoryStore([
        {
          kind: 'issue',
          scope: TEST_SCOPE,
          data: {
            subject_ref: 'ISSUE-456',
            severity: 'high',
            status: 'open',
            root_cause: 'Memory leak in connection pool',
            resolution: 'Increased pool size and added monitoring',
            tracker: 'jira',
          },
        },
      ]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].kind).toBe('issue');
    });
  });

  describe('KS-005: Store Decision (ADR)', () => {
    it('should store ADR with status=proposed', async () => {
      const result = await memoryStore([
        {
          kind: 'decision',
          scope: TEST_SCOPE,
          data: {
            component: 'database',
            status: 'proposed',
            title: 'Use PostgreSQL for primary database',
            rationale: 'Strong ACID guarantees, excellent performance',
            alternatives_considered: ['MongoDB', 'MySQL'],
          },
        },
      ]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].kind).toBe('decision');
      expect(result.stored[0].data.status).toBe('proposed');
    });

    it('should store ADR with status=accepted', async () => {
      const result = await memoryStore([
        {
          kind: 'decision',
          scope: TEST_SCOPE,
          data: {
            component: 'api',
            status: 'accepted',
            title: 'Use REST API',
            rationale: 'Industry standard, widely supported',
            alternatives_considered: ['GraphQL', 'gRPC'],
          },
        },
      ]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.status).toBe('accepted');
    });
  });

  describe('KS-006: Store Todo', () => {
    it('should store todo', async () => {
      const result = await memoryStore([
        {
          kind: 'todo',
          scope: TEST_SCOPE,
          data: {
            subject_ref: 'TODO-789',
            task_description: 'Implement user authentication',
            status: 'pending',
            priority: 'high',
            assigned_to: 'john.doe',
          },
        },
      ]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].kind).toBe('todo');
    });
  });

  describe('KS-007: Store Release Note', () => {
    it('should store release_note', async () => {
      const result = await memoryStore([
        {
          kind: 'release_note',
          scope: TEST_SCOPE,
          data: {
            version: '1.0.0',
            release_date: '2025-01-14',
            highlights: ['New feature X', 'Bug fix Y'],
            breaking_changes: [],
          },
        },
      ]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].kind).toBe('release_note');
    });
  });

  describe('KS-008: Store DDL', () => {
    it('should store ddl', async () => {
      const result = await memoryStore([
        {
          kind: 'ddl',
          scope: TEST_SCOPE,
          data: {
            migration_version: 'V001',
            ddl_statement: 'CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT)',
            applied_at: new Date().toISOString(),
            applied_by: 'admin',
          },
        },
      ]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].kind).toBe('ddl');
    });
  });

  describe('KS-009: Store PR Context', () => {
    it('should store pr_context', async () => {
      const result = await memoryStore([
        {
          kind: 'pr_context',
          scope: TEST_SCOPE,
          data: {
            pr_number: 'PR-100',
            title: 'Add authentication system',
            author: 'jane.smith',
            status: 'merged',
            merged_at: new Date().toISOString(),
          },
        },
      ]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].kind).toBe('pr_context');
    });
  });

  describe('KS-010: Store with Tags', () => {
    it('should persist tags correctly', async () => {
      const result = await memoryStore([
        {
          kind: 'section',
          scope: TEST_SCOPE,
          data: {
            title: 'Tagged Section',
            body_md: 'Content',
          },
          tags: {
            category: 'documentation',
            priority: 'high',
            team: 'backend',
          },
        },
      ]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].tags).toEqual({
        category: 'documentation',
        priority: 'high',
        team: 'backend',
      });
    });
  });

  describe('KS-011: Store without Optional Fields', () => {
    it('should use defaults for missing optional fields', async () => {
      const result = await memoryStore([
        {
          kind: 'section',
          scope: TEST_SCOPE,
          data: {
            title: 'Minimal Section',
            body_md: 'Content',
          },
          // No tags, no optional fields
        },
      ]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0]).toHaveProperty('id');
      expect(result.stored[0]).toHaveProperty('created_at');
    });
  });

  describe('KS-012: Store Invalid Kind', () => {
    it('should return error for invalid kind', async () => {
      const result = await memoryStore([
        {
          kind: 'invalid_kind' as any,
          scope: TEST_SCOPE,
          data: {
            title: 'Test',
          },
        },
      ]);

      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error_code).toBe('INVALID_SCHEMA');
    });
  });

  describe('KS-013: Store Missing Required Fields', () => {
    it('should return validation error for missing required fields', async () => {
      const result = await memoryStore([
        {
          kind: 'issue',
          scope: TEST_SCOPE,
          data: {
            // Missing required fields: subject_ref, severity, status, tracker
            root_cause: 'Test',
          } as any,
        },
      ]);

      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error_code).toBe('INVALID_SCHEMA');
      expect(result.errors[0].message).toContain('Required');
    });
  });
});
