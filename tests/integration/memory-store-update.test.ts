import { describe, it, expect, beforeAll, afterAll } from 'vitest';
// PostgreSQL import removed - now using Qdrant;
import { memoryStore } from ' '../../src/services/memory-store.js';
import { ImmutabilityViolationError } from ' '../../src/utils/immutability.js';

/**
 * T089: memory.store UPDATE Functionality Test
 *
 * Validates:
 * - UPDATE operations work when id field is provided
 * - INSERT operations work when id field is omitted
 * - ADR immutability is enforced during UPDATE
 * - Section write-lock is enforced during UPDATE
 * - Proper error messages are returned for violations
 */
describe('memory.store UPDATE Operations', () => {
  let pool: QdrantClient;

  beforeAll(() => {
    pool = new QdrantClient({
      connectionString:
        process.env.QDRANT_URL || 'http://cortex:cortex@localhost:5432/cortex_test',
    });
  });

  afterAll(async () => {
    await pool.end();
  });

  describe('ADR Decision Updates', () => {
    it('should allow updates to proposed ADR content', async () => {
      // Insert ADR with status='proposed'
      const insertResult = await memoryStore([
        {
          kind: 'decision',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            component: 'auth',
            status: 'proposed',
            title: 'Original Title',
            rationale: 'Original rationale',
          },
        },
      ]);

      expect(insertResult.stored).toHaveLength(1);
      expect(insertResult.stored[0].status).toBe('inserted');
      const adrId = insertResult.stored[0].id;

      // Update content (should succeed - not yet accepted)
      const updateResult = await memoryStore([
        {
          kind: 'decision',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            id: adrId,
            title: 'Updated Title',
            rationale: 'Updated rationale',
          },
        },
      ]);

      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');
      expect(updateResult.stored[0].id).toBe(adrId);

      // Verify update in database
      const result = await pool.query('SELECT title, rationale FROM adr_decision WHERE id = $1', [
        adrId,
      ]);
      expect(result.rows[0].title).toBe('Updated Title');
      expect(result.rows[0].rationale).toBe('Updated rationale');

      // Cleanup
      await pool.query('DELETE FROM adr_decision WHERE id = $1', [adrId]);
    });

    it('should block content updates to accepted ADR', async () => {
      // Insert accepted ADR
      const insertResult = await memoryStore([
        {
          kind: 'decision',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            component: 'database',
            status: 'accepted',
            title: 'Immutable Title',
            rationale: 'Immutable rationale',
          },
        },
      ]);

      const adrId = insertResult.stored[0].id;

      // Attempt to update content (should fail)
      await expect(
        memoryStore([
          {
            kind: 'decision',
            scope: { project: 'test-project', branch: 'main' },
            data: {
              id: adrId,
              title: 'Trying to change immutable title',
            },
          },
        ])
      ).rejects.toThrow(ImmutabilityViolationError);

      // Verify original content unchanged
      const result = await pool.query('SELECT title FROM adr_decision WHERE id = $1', [adrId]);
      expect(result.rows[0].title).toBe('Immutable Title');

      // Cleanup
      await pool.query('DELETE FROM adr_decision WHERE id = $1', [adrId]);
    });

    it('should return proper error for non-existent ADR update', async () => {
      const nonExistentId = '00000000-0000-0000-0000-000000000000';

      const updateResult = await memoryStore([
        {
          kind: 'decision',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            id: nonExistentId,
            title: 'Update non-existent',
          },
        },
      ]);

      // Should insert new record instead of updating (no existing record found)
      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('inserted');

      // Cleanup
      await pool.query('DELETE FROM adr_decision WHERE id = $1', [updateResult.stored[0].id]);
    });
  });

  describe('Section Updates', () => {
    it('should allow updates to unapproved section', async () => {
      // Insert section without approved flag
      const insertResult = await memoryStore([
        {
          kind: 'section',
          scope: { project: 'test-project', branch: 'feature' },
          data: {
            title: 'Draft Section',
            body_md: '# Original content',
          },
        },
      ]);

      expect(insertResult.stored).toHaveLength(1);
      const sectionId = insertResult.stored[0].id;

      // Update content (should succeed)
      const updateResult = await memoryStore([
        {
          kind: 'section',
          scope: { project: 'test-project', branch: 'feature' },
          data: {
            id: sectionId,
            body_md: '# Updated content',
          },
        },
      ]);

      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');

      // Verify update in database
      const result = await pool.query('SELECT body_jsonb FROM section WHERE id = $1', [sectionId]);
      expect(result.rows[0].body_jsonb.text).toBe('# Updated content');

      // Cleanup
      await pool.query('DELETE FROM section WHERE id = $1', [sectionId]);
    });

    it('should block content updates to approved section', async () => {
      // Insert approved section
      const insertResult = await memoryStore([
        {
          kind: 'section',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Approved Spec',
            body_md: '# Locked content',
          },
          tags: { approved: true },
        },
      ]);

      const sectionId = insertResult.stored[0].id;

      // Attempt to update content (should fail)
      await expect(
        memoryStore([
          {
            kind: 'section',
            scope: { project: 'test-project', branch: 'main' },
            data: {
              id: sectionId,
              body_md: '# Trying to change locked content',
            },
          },
        ])
      ).rejects.toThrow(ImmutabilityViolationError);

      // Verify original content unchanged
      const result = await pool.query('SELECT body_jsonb FROM section WHERE id = $1', [sectionId]);
      expect(result.rows[0].body_jsonb.text).toBe('# Locked content');

      // Cleanup
      await pool.query('DELETE FROM section WHERE id = $1', [sectionId]);
    });
  });

  describe('Todo Updates', () => {
    it('should allow updates to existing todo items', async () => {
      // Insert todo
      const insertResult = await memoryStore([
        {
          kind: 'todo',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            text: 'Original todo task',
            status: 'pending',
            priority: 'medium',
          },
        },
      ]);

      expect(insertResult.stored).toHaveLength(1);
      expect(insertResult.stored[0].status).toBe('inserted');
      const todoId = insertResult.stored[0].id;

      // Update todo
      const updateResult = await memoryStore([
        {
          kind: 'todo',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            id: todoId,
            text: 'Updated todo task',
            status: 'completed',
            priority: 'high',
          },
        },
      ]);

      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');
      expect(updateResult.stored[0].id).toBe(todoId);

      // Verify update in database
      const result = await pool.query('SELECT title, description, status, priority FROM todo_log WHERE id = $1', [todoId]);
      expect(result.rows[0].title).toBe('Updated todo task');
      expect(result.rows[0].status).toBe('completed');
      expect((result.rows[0].tags).priority).toBe('high');

      // Cleanup
      await pool.query('DELETE FROM todo_log WHERE id = $1', [todoId]);
    });

    it('should insert new todo when id is not provided', async () => {
      const result = await memoryStore([
        {
          kind: 'todo',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            text: 'New todo task',
            status: 'pending',
          },
        },
      ]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].status).toBe('inserted');

      // Cleanup
      await pool.query('DELETE FROM todo_log WHERE id = $1', [result.stored[0].id]);
    });
  });

  describe('Entity Updates', () => {
    it('should allow updates to existing entities', async () => {
      // Insert entity
      const insertResult = await memoryStore([
        {
          kind: 'entity',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            entity_type: 'component',
            name: 'auth-service',
            data: { version: '1.0.0', description: 'Original description' },
          },
        },
      ]);

      expect(insertResult.stored).toHaveLength(1);
      expect(insertResult.stored[0].status).toBe('inserted');
      const entityId = insertResult.stored[0].id;

      // Update entity
      const updateResult = await memoryStore([
        {
          kind: 'entity',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            id: entityId,
            entity_type: 'component',
            name: 'auth-service',
            data: { version: '1.1.0', description: 'Updated description' },
          },
        },
      ]);

      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');
      expect(updateResult.stored[0].id).toBe(entityId);

      // Verify update in database
      const result = await pool.query('SELECT entity_type, name, data FROM knowledge_entity WHERE id = $1', [entityId]);
      expect(result.rows[0].entity_type).toBe('component');
      expect(result.rows[0].name).toBe('auth-service');
      expect((result.rows[0].data).version).toBe('1.1.0');

      // Cleanup
      await pool.query('DELETE FROM knowledge_entity WHERE id = $1', [entityId]);
    });
  });

  describe('Incident Updates', () => {
    it('should allow updates to existing incidents', async () => {
      // Insert incident
      const insertResult = await memoryStore([
        {
          kind: 'incident',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Service Outage',
            severity: 'high',
            impact: 'Users cannot login',
            resolution_status: 'open',
          },
        },
      ]);

      expect(insertResult.stored).toHaveLength(1);
      expect(insertResult.stored[0].status).toBe('inserted');
      const incidentId = insertResult.stored[0].id;

      // Update incident
      const updateResult = await memoryStore([
        {
          kind: 'incident',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            id: incidentId,
            title: 'Service Outage - Updated',
            severity: 'medium',
            resolution_status: 'resolved',
          },
        },
      ]);

      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');
      expect(updateResult.stored[0].id).toBe(incidentId);

      // Verify update in database
      const result = await pool.query('SELECT title, severity, resolution_status FROM incident_log WHERE id = $1', [incidentId]);
      expect(result.rows[0].title).toBe('Service Outage - Updated');
      expect(result.rows[0].severity).toBe('medium');
      expect(result.rows[0].resolution_status).toBe('resolved');

      // Cleanup
      await pool.query('DELETE FROM incident_log WHERE id = $1', [incidentId]);
    });
  });

  describe('Release Updates', () => {
    it('should allow updates to existing releases', async () => {
      // Insert release
      const insertResult = await memoryStore([
        {
          kind: 'release',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            version: '1.0.0',
            release_type: 'major',
            scope: 'Initial release',
            status: 'planned',
          },
        },
      ]);

      expect(insertResult.stored).toHaveLength(1);
      expect(insertResult.stored[0].status).toBe('inserted');
      const releaseId = insertResult.stored[0].id;

      // Update release
      const updateResult = await memoryStore([
        {
          kind: 'release',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            id: releaseId,
            version: '1.0.0',
            status: 'completed',
          },
        },
      ]);

      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');
      expect(updateResult.stored[0].id).toBe(releaseId);

      // Verify update in database
      const result = await pool.query('SELECT version, release_type, scope, status FROM release_log WHERE id = $1', [releaseId]);
      expect(result.rows[0].version).toBe('1.0.0');
      expect(result.rows[0].status).toBe('completed');

      // Cleanup
      await pool.query('DELETE FROM release_log WHERE id = $1', [releaseId]);
    });
  });

  describe('Risk Updates', () => {
    it('should allow updates to existing risks', async () => {
      // Insert risk
      const insertResult = await memoryStore([
        {
          kind: 'risk',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Database Performance',
            category: 'technical',
            risk_level: 'high',
            impact_description: 'Slow queries affecting user experience',
            status: 'active',
          },
        },
      ]);

      expect(insertResult.stored).toHaveLength(1);
      expect(insertResult.stored[0].status).toBe('inserted');
      const riskId = insertResult.stored[0].id;

      // Update risk
      const updateResult = await memoryStore([
        {
          kind: 'risk',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            id: riskId,
            title: 'Database Performance - Mitigated',
            risk_level: 'low',
            status: 'mitigated',
          },
        },
      ]);

      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');
      expect(updateResult.stored[0].id).toBe(riskId);

      // Verify update in database
      const result = await pool.query('SELECT title, category, risk_level, status FROM risk_log WHERE id = $1', [riskId]);
      expect(result.rows[0].title).toBe('Database Performance - Mitigated');
      expect(result.rows[0].risk_level).toBe('low');
      expect(result.rows[0].status).toBe('mitigated');

      // Cleanup
      await pool.query('DELETE FROM risk_log WHERE id = $1', [riskId]);
    });
  });

  describe('Assumption Updates', () => {
    it('should allow updates to existing assumptions', async () => {
      // Insert assumption
      const insertResult = await memoryStore([
        {
          kind: 'assumption',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'User Base Growth',
            description: 'Assume 10% monthly user growth',
            category: 'business',
            validation_status: 'assumed',
            impact_if_invalid: 'Revenue projections will be inaccurate',
          },
        },
      ]);

      expect(insertResult.stored).toHaveLength(1);
      expect(insertResult.stored[0].status).toBe('inserted');
      const assumptionId = insertResult.stored[0].id;

      // Update assumption
      const updateResult = await memoryStore([
        {
          kind: 'assumption',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            id: assumptionId,
            description: 'Assume 15% monthly user growth after market analysis',
            validation_status: 'validated',
          },
        },
      ]);

      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');
      expect(updateResult.stored[0].id).toBe(assumptionId);

      // Verify update in database
      const result = await pool.query('SELECT title, description, category, validation_status FROM assumption_log WHERE id = $1', [assumptionId]);
      expect(result.rows[0].title).toBe('User Base Growth');
      expect(result.rows[0].description).toBe('Assume 15% monthly user growth after market analysis');
      expect(result.rows[0].validation_status).toBe('validated');

      // Cleanup
      await pool.query('DELETE FROM assumption_log WHERE id = $1', [assumptionId]);
    });
  });

  describe('DDL Updates', () => {
    it('should allow updates to existing DDL entries', async () => {
      // Insert DDL
      const insertResult = await memoryStore([
        {
          kind: 'ddl',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            migration_id: '001_initial_schema',
            ddl_text: 'CREATE TABLE users (id SERIAL PRIMARY KEY, name VARCHAR(255));',
            description: 'Initial user table',
          },
        },
      ]);

      expect(insertResult.stored).toHaveLength(1);
      expect(insertResult.stored[0].status).toBe('inserted');
      const ddlId = insertResult.stored[0].id;

      // Update DDL
      const updateResult = await memoryStore([
        {
          kind: 'ddl',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            id: ddlId,
            description: 'Initial user table - updated description',
          },
        },
      ]);

      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');
      expect(updateResult.stored[0].id).toBe(ddlId);

      // Verify update in database
      const result = await pool.query('SELECT migration_id, description FROM ddl_history WHERE id = $1', [ddlId]);
      expect(result.rows[0].migration_id).toBe('001_initial_schema');
      expect(result.rows[0].description).toBe('Initial user table - updated description');

      // Cleanup
      await pool.query('DELETE FROM ddl_history WHERE id = $1', [ddlId]);
    });
  });

  describe('PR Context Updates', () => {
    it('should allow updates to existing PR contexts', async () => {
      // Insert PR context
      const insertResult = await memoryStore([
        {
          kind: 'pr_context',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: 123,
            title: 'Add authentication feature',
            description: 'Implement OAuth2 authentication',
            author: 'developer1',
            status: 'open',
          },
        },
      ]);

      expect(insertResult.stored).toHaveLength(1);
      expect(insertResult.stored[0].status).toBe('inserted');
      const prContextId = insertResult.stored[0].id;

      // Update PR context
      const updateResult = await memoryStore([
        {
          kind: 'pr_context',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            id: prContextId,
            title: 'Add authentication feature - Updated',
            status: 'merged',
            merged_at: new Date().toISOString(),
          },
        },
      ]);

      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');
      expect(updateResult.stored[0].id).toBe(prContextId);

      // Verify update in database
      const result = await pool.query('SELECT pr_number, title, status, merged_at FROM pr_context WHERE id = $1', [prContextId]);
      expect(result.rows[0].pr_number).toBe(123);
      expect(result.rows[0].title).toBe('Add authentication feature - Updated');
      expect(result.rows[0].status).toBe('merged');
      expect(result.rows[0].merged_at).not.toBeNull();

      // Cleanup
      await pool.query('DELETE FROM pr_context WHERE id = $1', [prContextId]);
    });
  });

  describe('Release Note Updates', () => {
    it('should allow updates to existing release notes', async () => {
      // Insert release note
      const insertResult = await memoryStore([
        {
          kind: 'release_note',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            version: '1.0.0',
            summary: 'Initial release with basic functionality',
            breaking_changes: [],
            new_features: ['User authentication', 'Dashboard'],
            bug_fixes: ['Fixed login timeout issue'],
          },
        },
      ]);

      expect(insertResult.stored).toHaveLength(1);
      expect(insertResult.stored[0].status).toBe('inserted');
      const releaseNoteId = insertResult.stored[0].id;

      // Update release note
      const updateResult = await memoryStore([
        {
          kind: 'release_note',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            id: releaseNoteId,
            summary: 'Initial release with basic functionality - updated summary',
            new_features: ['User authentication', 'Dashboard', 'API endpoints'],
          },
        },
      ]);

      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');
      expect(updateResult.stored[0].id).toBe(releaseNoteId);

      // Verify update in database
      const result = await pool.query('SELECT version, summary FROM release_note WHERE id = $1', [releaseNoteId]);
      expect(result.rows[0].version).toBe('1.0.0');
      expect(result.rows[0].summary).toBe('Initial release with basic functionality - updated summary');

      const tagsResult = await pool.query('SELECT tags FROM release_note WHERE id = $1', [releaseNoteId]);
      const tags = tagsResult.rows[0].tags;
      expect(tags.new_features).toContain('API endpoints');

      // Cleanup
      await pool.query('DELETE FROM release_note WHERE id = $1', [releaseNoteId]);
    });
  });

  describe('INSERT vs UPDATE Distinction', () => {
    it('should INSERT when id is not provided', async () => {
      const insertResult = await memoryStore([
        {
          kind: 'decision',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            component: 'api',
            status: 'proposed',
            title: 'New Decision',
            rationale: 'New rationale',
          },
        },
      ]);

      expect(insertResult.stored).toHaveLength(1);
      expect(insertResult.stored[0].status).toBe('inserted');
      expect(insertResult.stored[0].id).toBeDefined();

      // Cleanup
      await pool.query('DELETE FROM adr_decision WHERE id = $1', [insertResult.stored[0].id]);
    });

    it('should UPDATE when id is provided and exists', async () => {
      // First insert
      const insertResult = await memoryStore([
        {
          kind: 'decision',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            component: 'api',
            status: 'proposed',
            title: 'Original',
            rationale: 'Original',
          },
        },
      ]);

      const adrId = insertResult.stored[0].id;

      // Then update
      const updateResult = await memoryStore([
        {
          kind: 'decision',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            id: adrId,
            title: 'Modified',
          },
        },
      ]);

      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');
      expect(updateResult.stored[0].id).toBe(adrId);

      // Cleanup
      await pool.query('DELETE FROM adr_decision WHERE id = $1', [adrId]);
    });
  });
});
