import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { getTestContainer } from '../../helpers/testcontainers.js';
// PostgreSQL import removed - now using Qdrant;
import { v4 as uuidv4 } from 'uuid';

/**
 * Comprehensive Database Integration Tests
 *
 * Tests the complete Cortex Memory MCP database system:
 * - All 16 knowledge types with CRUD operations
 * - 8-LOG SYSTEM functionality
 * - Graph extension (entity, relation, observation)
 * - Audit trail functionality
 * - Auto-purge functionality
 * - Constraints and triggers
 * - PostgreSQL 18 features
 */

describe('Database Integration Tests', () => {
  let client: Client;
  let cleanup: () => Promise<void>;

  beforeAll(async () => {
    const { client: testClient, cleanup: cleanupFn } = await getTestContainer();
    client = testClient;
    cleanup = cleanupFn;
  }, 120000);

  afterAll(async () => {
    await cleanup();
  });

  beforeEach(async () => {
    // Clean up test data before each test
    await client.query('TRUNCATE TABLE knowledge_observation CASCADE');
    await client.query('TRUNCATE TABLE knowledge_relation CASCADE');
    await client.query('TRUNCATE TABLE knowledge_entity CASCADE');
    await client.query('TRUNCATE TABLE event_audit CASCADE');
    await client.query('TRUNCATE TABLE assumption_log CASCADE');
    await client.query('TRUNCATE TABLE risk_log CASCADE');
    await client.query('TRUNCATE TABLE release_log CASCADE');
    await client.query('TRUNCATE TABLE incident_log CASCADE');
    await client.query('TRUNCATE TABLE todo_log CASCADE');
    await client.query('TRUNCATE TABLE pr_context CASCADE');
    await client.query('TRUNCATE TABLE release_note CASCADE');
    await client.query('TRUNCATE TABLE ddl_history CASCADE');
    await client.query('TRUNCATE TABLE issue_log CASCADE');
    await client.query('TRUNCATE TABLE change_log CASCADE');
    await client.query('TRUNCATE TABLE adr_decision CASCADE');
    await client.query('TRUNCATE TABLE runbook CASCADE');
    await client.query('TRUNCATE TABLE section CASCADE');
    await client.query('TRUNCATE TABLE document CASCADE');
  });

  // ============================================================================
  // Database Connection and Schema Tests
  // ============================================================================

  describe('Database Connection and Schema', () => {
    it('should connect to PostgreSQL successfully', async () => {
      const result = await client.query('SELECT NOW() as current_time');
      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].current_time).toBeDefined();
    });

    it('should have PostgreSQL 18+ version', async () => {
      const result = await client.query('SELECT version() as version');
      const version = result.rows[0].version;
      expect(version).toMatch(/PostgreSQL 1[8-9]/);
    });

    it('should have all required extensions', async () => {
      const extensions = ['pgcrypto', 'pg_trgm'];

      for (const ext of extensions) {
        const result = await client.query(`// PostgreSQL system query removed WHERE extname = $1`, [
          ext,
        ]);
        expect(result.rows).toHaveLength(1);
      }
    });

    it('should have all 16 knowledge tables', async () => {
      const expectedTables = [
        'document',
        'section',
        'runbook',
        'change_log',
        'issue_log',
        'adr_decision',
        'todo_log',
        'release_note',
        'pr_context',
        'knowledge_entity',
        'knowledge_relation',
        'knowledge_observation',
        'incident_log',
        'release_log',
        'risk_log',
        'assumption_log',
        'event_audit',
      ];

      for (const table of expectedTables) {
        const result = await client.query(`SELECT tablename FROM .collections WHERE tablename = $1`, [
          table,
        ]);
        expect(result.rows).toHaveLength(1);
      }
    });
  });

  // ============================================================================
  // Knowledge Type CRUD Tests
  // ============================================================================

  describe('Knowledge Type CRUD Operations', () => {
    const testScope = {
      project: 'test-project',
      branch: 'test-branch',
      org: 'test-org',
    };

    describe('Section Operations', () => {
      it('should create, read, update, and delete sections', async () => {
        // Create document first
        const docResult = await client.query(
          `
          INSERT INTO document (id, title, type, tags)
          VALUES ($1, $2, $3, $4)
          RETURNING id
        `,
          [uuidv4(), 'Test Document', 'guide', JSON.stringify(testScope)]
        );

        const documentId = docResult.rows[0].id;

        // Create section
        const sectionId = uuidv4();
        await client.query(
          `
          INSERT INTO section (id, document_id, title, heading, body_md, body_text, tags)
          VALUES ($1, $2, $3, $4, $5, $6, $7)
        `,
          [
            sectionId,
            documentId,
            'Test Section',
            'Test Heading',
            '# Test Content\nThis is test content.',
            'This is test content.',
            JSON.stringify(testScope),
          ]
        );

        // Read section
        const readResult = await client.query('SELECT * FROM section WHERE id = $1', [sectionId]);
        expect(readResult.rows).toHaveLength(1);
        expect(readResult.rows[0].title).toBe('Test Section');

        // Update section
        await client.query(
          `
          UPDATE section SET title = $1, updated_at = NOW()
          WHERE id = $2
        `,
          ['Updated Section', sectionId]
        );

        // Verify update
        const updateResult = await client.query('SELECT title FROM section WHERE id = $1', [
          sectionId,
        ]);
        expect(updateResult.rows[0].title).toBe('Updated Section');

        // Delete section
        await client.query('DELETE FROM section WHERE id = $1', [sectionId]);

        // Verify deletion
        const deleteResult = await client.query('SELECT * FROM section WHERE id = $1', [sectionId]);
        expect(deleteResult.rows).toHaveLength(0);
      });

      it('should enforce section constraints', async () => {
        // Test title length constraint
        await expect(
          client.query(
            `
          INSERT INTO section (id, title, heading, body_text, tags)
          VALUES ($1, $2, $3, $4, $5)
        `,
            [
              uuidv4(),
              'a'.repeat(501), // Exceeds 500 character limit
              'Test Heading',
              'Test content',
              JSON.stringify(testScope),
            ]
          )
        ).rejects.toThrow();
      });
    });

    describe('ADR Decision Operations', () => {
      it('should handle ADR CRUD operations with immutability', async () => {
        const adrId = uuidv4();

        // Create ADR
        await client.query(
          `
          INSERT INTO adr_decision (
            id, component, status, title, rationale, alternatives_considered, tags
          ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        `,
          [
            adrId,
            'auth',
            'proposed',
            'Test ADR',
            'Test rationale for decision',
            JSON.stringify(['alternative1', 'alternative2']),
            JSON.stringify(testScope),
          ]
        );

        // Read ADR
        const readResult = await client.query('SELECT * FROM adr_decision WHERE id = $1', [adrId]);
        expect(readResult.rows).toHaveLength(1);
        expect(readResult.rows[0].status).toBe('proposed');

        // Update ADR (should work when status is not 'accepted')
        await client.query(
          `
          UPDATE adr_decision SET rationale = $1 WHERE id = $2
        `,
          ['Updated rationale', adrId]
        );

        // Accept ADR
        await client.query(
          `
          UPDATE adr_decision SET status = $1 WHERE id = $2
        `,
          ['accepted', adrId]
        );

        // Try to update accepted ADR (should fail due to trigger)
        await expect(
          client.query(
            `
          UPDATE adr_decision SET rationale = $1 WHERE id = $2
        `,
            ['Should fail', adrId]
          )
        ).rejects.toThrow();
      });
    });

    describe('Issue Log Operations', () => {
      it('should handle issue CRUD operations', async () => {
        const issueId = uuidv4();

        // Create issue
        await client.query(
          `
          INSERT INTO issue_log (
            id, title, description, status, severity, priority, tags
          ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        `,
          [
            issueId,
            'Test Issue',
            'This is a test issue description',
            'open',
            'medium',
            'normal',
            JSON.stringify(testScope),
          ]
        );

        // Read issue
        const readResult = await client.query('SELECT * FROM issue_log WHERE id = $1', [issueId]);
        expect(readResult.rows).toHaveLength(1);
        expect(readResult.rows[0].status).toBe('open');

        // Update issue status
        await client.query(
          `
          UPDATE issue_log SET status = $1 WHERE id = $2
        `,
          ['in_progress', issueId]
        );

        // Verify update
        const updateResult = await client.query('SELECT status FROM issue_log WHERE id = $1', [
          issueId,
        ]);
        expect(updateResult.rows[0].status).toBe('in_progress');
      });
    });

    describe('Todo Log Operations', () => {
      it('should handle todo CRUD operations', async () => {
        const todoId = uuidv4();

        // Create todo
        await client.query(
          `
          INSERT INTO todo_log (
            id, text, status, priority, tags
          ) VALUES ($1, $2, $3, $4, $5)
        `,
          [todoId, 'Test todo item', 'pending', 'medium', JSON.stringify(testScope)]
        );

        // Read todo
        const readResult = await client.query('SELECT * FROM todo_log WHERE id = $1', [todoId]);
        expect(readResult.rows).toHaveLength(1);
        expect(readResult.rows[0].status).toBe('pending');

        // Update todo status
        await client.query(
          `
          UPDATE todo_log SET status = $1 WHERE id = $2
        `,
          ['in_progress', todoId]
        );

        // Complete todo
        await client.query(
          `
          UPDATE todo_log SET status = $1 WHERE id = $2
        `,
          ['done', todoId]
        );

        // Verify completion
        const updateResult = await client.query('SELECT status FROM todo_log WHERE id = $1', [
          todoId,
        ]);
        expect(updateResult.rows[0].status).toBe('done');
      });
    });

    describe('Runbook Operations', () => {
      it('should handle runbook CRUD operations', async () => {
        const runbookId = uuidv4();

        // Create runbook
        await client.query(
          `
          INSERT INTO runbook (
            id, title, description, procedures, triggers, tags
          ) VALUES ($1, $2, $3, $4, $5, $6)
        `,
          [
            runbookId,
            'Test Runbook',
            'Test runbook description',
            JSON.stringify(['step1', 'step2', 'step3']),
            JSON.stringify(['trigger1', 'trigger2']),
            JSON.stringify(testScope),
          ]
        );

        // Read runbook
        const readResult = await client.query('SELECT * FROM runbook WHERE id = $1', [runbookId]);
        expect(readResult.rows).toHaveLength(1);
        expect(readResult.rows[0].title).toBe('Test Runbook');

        // Update runbook
        await client.query(
          `
          UPDATE runbook SET description = $1 WHERE id = $2
        `,
          ['Updated description', runbookId]
        );

        // Verify update
        const updateResult = await client.query('SELECT description FROM runbook WHERE id = $1', [
          runbookId,
        ]);
        expect(updateResult.rows[0].description).toBe('Updated description');
      });
    });

    describe('Change Log Operations', () => {
      it('should handle change log CRUD operations', async () => {
        const changeId = uuidv4();

        // Create change log
        await client.query(
          `
          INSERT INTO change_log (
            id, subject_ref, summary, details, change_type, tags
          ) VALUES ($1, $2, $3, $4, $5, $6)
        `,
          [
            changeId,
            'refs/heads/main',
            'Test change summary',
            'Detailed change description',
            'feature',
            JSON.stringify(testScope),
          ]
        );

        // Read change log
        const readResult = await client.query('SELECT * FROM change_log WHERE id = $1', [changeId]);
        expect(readResult.rows).toHaveLength(1);
        expect(readResult.rows[0].subject_ref).toBe('refs/heads/main');
      });
    });

    describe('Release Note Operations', () => {
      it('should handle release note CRUD operations', async () => {
        const releaseId = uuidv4();

        // Create release note
        await client.query(
          `
          INSERT INTO release_note (
            id, version, release_date, summary, changes, tags
          ) VALUES ($1, $2, $3, $4, $5, $6)
        `,
          [
            releaseId,
            '1.0.0',
            new Date(),
            'Release summary',
            JSON.stringify(['change1', 'change2']),
            JSON.stringify(testScope),
          ]
        );

        // Read release note
        const readResult = await client.query('SELECT * FROM release_note WHERE id = $1', [
          releaseId,
        ]);
        expect(readResult.rows).toHaveLength(1);
        expect(readResult.rows[0].version).toBe('1.0.0');
      });
    });

    describe('PR Context Operations', () => {
      it('should handle PR context CRUD operations', async () => {
        const prId = uuidv4();

        // Create PR context
        await client.query(
          `
          INSERT INTO pr_context (
            id, title, pr_number, source_branch, target_branch, status, tags
          ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        `,
          [prId, 'Test PR', 123, 'feature/test', 'main', 'open', JSON.stringify(testScope)]
        );

        // Read PR context
        const readResult = await client.query('SELECT * FROM pr_context WHERE id = $1', [prId]);
        expect(readResult.rows).toHaveLength(1);
        expect(readResult.rows[0].pr_number).toBe(123);

        // Merge PR
        await client.query(
          `
          UPDATE pr_context SET status = $1 WHERE id = $2
        `,
          ['merged', prId]
        );

        // Verify merge
        const updateResult = await client.query('SELECT status FROM pr_context WHERE id = $1', [
          prId,
        ]);
        expect(updateResult.rows[0].status).toBe('merged');
      });
    });

    describe('Incident Log Operations', () => {
      it('should handle incident log CRUD operations', async () => {
        const incidentId = uuidv4();

        // Create incident log
        await client.query(
          `
          INSERT INTO incident_log (
            id, title, description, severity, impact, status, timeline, tags
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `,
          [
            incidentId,
            'Test Incident',
            'Incident description',
            'high',
            'service degradation',
            'open',
            JSON.stringify([
              { timestamp: new Date(), event: 'incident detected' },
              { timestamp: new Date(), event: 'investigation started' },
            ]),
            JSON.stringify(testScope),
          ]
        );

        // Read incident log
        const readResult = await client.query('SELECT * FROM incident_log WHERE id = $1', [
          incidentId,
        ]);
        expect(readResult.rows).toHaveLength(1);
        expect(readResult.rows[0].severity).toBe('high');

        // Update incident status
        await client.query(
          `
          UPDATE incident_log SET status = $1 WHERE id = $2
        `,
          ['resolved', incidentId]
        );

        // Verify update
        const updateResult = await client.query('SELECT status FROM incident_log WHERE id = $1', [
          incidentId,
        ]);
        expect(updateResult.rows[0].status).toBe('resolved');
      });
    });

    describe('Release Log Operations', () => {
      it('should handle release log CRUD operations', async () => {
        const releaseLogId = uuidv4();

        // Create release log
        await client.query(
          `
          INSERT INTO release_log (
            id, version, scope, status, release_date, deployed_at, tags
          ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        `,
          [
            releaseLogId,
            '2.0.0',
            'feature-x',
            'deployed',
            new Date(),
            new Date(),
            JSON.stringify(testScope),
          ]
        );

        // Read release log
        const readResult = await client.query('SELECT * FROM release_log WHERE id = $1', [
          releaseLogId,
        ]);
        expect(readResult.rows).toHaveLength(1);
        expect(readResult.rows[0].version).toBe('2.0.0');
        expect(readResult.rows[0].status).toBe('deployed');
      });
    });

    describe('Risk Log Operations', () => {
      it('should handle risk log CRUD operations', async () => {
        const riskId = uuidv4();

        // Create risk log
        await client.query(
          `
          INSERT INTO risk_log (
            id, title, description, category, impact_probability, status, tags
          ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        `,
          [
            riskId,
            'Test Risk',
            'Risk description',
            'technical',
            JSON.stringify({ impact: 'high', probability: 'medium' }),
            'open',
            JSON.stringify(testScope),
          ]
        );

        // Read risk log
        const readResult = await client.query('SELECT * FROM risk_log WHERE id = $1', [riskId]);
        expect(readResult.rows).toHaveLength(1);
        expect(readResult.rows[0].category).toBe('technical');

        // Update risk status
        await client.query(
          `
          UPDATE risk_log SET status = $1 WHERE id = $2
        `,
          ['mitigated', riskId]
        );

        // Verify update
        const updateResult = await client.query('SELECT status FROM risk_log WHERE id = $1', [
          riskId,
        ]);
        expect(updateResult.rows[0].status).toBe('mitigated');
      });
    });

    describe('Assumption Log Operations', () => {
      it('should handle assumption log CRUD operations', async () => {
        const assumptionId = uuidv4();

        // Create assumption log
        await client.query(
          `
          INSERT INTO assumption_log (
            id, title, description, validation_status, dependencies, tags
          ) VALUES ($1, $2, $3, $4, $5, $6)
        `,
          [
            assumptionId,
            'Test Assumption',
            'Assumption description',
            'unvalidated',
            JSON.stringify(['dependency1', 'dependency2']),
            JSON.stringify(testScope),
          ]
        );

        // Read assumption log
        const readResult = await client.query('SELECT * FROM assumption_log WHERE id = $1', [
          assumptionId,
        ]);
        expect(readResult.rows).toHaveLength(1);
        expect(readResult.rows[0].validation_status).toBe('unvalidated');

        // Validate assumption
        await client.query(
          `
          UPDATE assumption_log SET validation_status = $1 WHERE id = $2
        `,
          ['validated', assumptionId]
        );

        // Verify validation
        const updateResult = await client.query(
          'SELECT validation_status FROM assumption_log WHERE id = $1',
          [assumptionId]
        );
        expect(updateResult.rows[0].validation_status).toBe('validated');
      });
    });
  });

  // ============================================================================
  // Graph Extension Tests
  // ============================================================================

  describe('Graph Extension (Entity, Relation, Observation)', () => {
    describe('Entity Operations', () => {
      it('should handle entity CRUD operations', async () => {
        const entityId = uuidv4();

        // Create entity
        await client.query(
          `
          INSERT INTO knowledge_entity (
            id, name, type, description, metadata, tags
          ) VALUES ($1, $2, $3, $4, $5, $6)
        `,
          [
            entityId,
            'Test Entity',
            'service',
            'Test entity description',
            JSON.stringify({ owner: 'team-a', environment: 'production' }),
            JSON.stringify({ project: 'test-project' }),
          ]
        );

        // Read entity
        const readResult = await client.query('SELECT * FROM knowledge_entity WHERE id = $1', [
          entityId,
        ]);
        expect(readResult.rows).toHaveLength(1);
        expect(readResult.rows[0].name).toBe('Test Entity');

        // Update entity
        await client.query(
          `
          UPDATE knowledge_entity SET description = $1 WHERE id = $2
        `,
          ['Updated description', entityId]
        );

        // Verify update
        const updateResult = await client.query(
          'SELECT description FROM knowledge_entity WHERE id = $1',
          [entityId]
        );
        expect(updateResult.rows[0].description).toBe('Updated description');

        // Soft delete entity
        await client.query(
          `
          UPDATE knowledge_entity SET deleted_at = NOW() WHERE id = $1
        `,
          [entityId]
        );

        // Verify soft delete
        const deleteResult = await client.query(
          'SELECT deleted_at FROM knowledge_entity WHERE id = $1',
          [entityId]
        );
        expect(deleteResult.rows[0].deleted_at).not.toBeNull();
      });
    });

    describe('Relation Operations', () => {
      it('should handle relation CRUD operations', async () => {
        const entityId1 = uuidv4();
        const entityId2 = uuidv4();
        const relationId = uuidv4();

        // Create entities
        await client.query(
          `
          INSERT INTO knowledge_entity (id, name, type, tags)
          VALUES ($1, $2, $3, $4), ($5, $6, $7, $8)
        `,
          [
            entityId1,
            'Entity 1',
            'service',
            JSON.stringify({ project: 'test' }),
            entityId2,
            'Entity 2',
            'database',
            JSON.stringify({ project: 'test' }),
          ]
        );

        // Create relation
        await client.query(
          `
          INSERT INTO knowledge_relation (
            id, from_entity_id, from_entity_type, to_entity_id, to_entity_type,
            relation_type, metadata
          ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        `,
          [
            relationId,
            entityId1,
            'service',
            entityId2,
            'database',
            'depends_on',
            JSON.stringify({ strength: 'strong', critical: true }),
          ]
        );

        // Read relation
        const readResult = await client.query('SELECT * FROM knowledge_relation WHERE id = $1', [
          relationId,
        ]);
        expect(readResult.rows).toHaveLength(1);
        expect(readResult.rows[0].relation_type).toBe('depends_on');

        // Test graph relationships view
        const viewResult = await client.query(
          `
          SELECT * FROM graph_relationships
          WHERE from_entity_id = $1 AND to_entity_id = $2
        `,
          [entityId1, entityId2]
        );
        expect(viewResult.rows.length).toBeGreaterThan(0);
      });
    });

    describe('Observation Operations', () => {
      it('should handle observation CRUD operations', async () => {
        const entityId = uuidv4();
        const observationId = uuidv4();

        // Create entity
        await client.query(
          `
          INSERT INTO knowledge_entity (id, name, type, tags)
          VALUES ($1, $2, $3, $4)
        `,
          [entityId, 'Test Entity', 'service', JSON.stringify({ project: 'test' })]
        );

        // Create observation
        await client.query(
          `
          INSERT INTO knowledge_observation (
            id, entity_id, entity_type, fact, confidence, source, metadata
          ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        `,
          [
            observationId,
            entityId,
            'service',
            'CPU usage is high',
            0.95,
            JSON.stringify({ tool: 'monitoring', timestamp: new Date() }),
            JSON.stringify({ metric: 'cpu_usage', value: 85, threshold: 80 }),
          ]
        );

        // Read observation
        const readResult = await client.query('SELECT * FROM knowledge_observation WHERE id = $1', [
          observationId,
        ]);
        expect(readResult.rows).toHaveLength(1);
        expect(readResult.rows[0].fact).toBe('CPU usage is high');
        expect(parseFloat(readResult.rows[0].confidence)).toBe(0.95);

        // Query observations by entity
        const entityObservations = await client.query(
          `
          SELECT * FROM knowledge_observation WHERE entity_id = $1
        `,
          [entityId]
        );
        expect(entityObservations.rows).toHaveLength(1);
      });
    });
  });

  // ============================================================================
  // Audit Trail Tests
  // ============================================================================

  describe('Audit Trail Functionality', () => {
    it('should automatically log section operations', async () => {
      const sectionId = uuidv4();

      // Create section
      await client.query(
        `
        INSERT INTO section (id, title, heading, body_text, tags)
        VALUES ($1, $2, $3, $4, $5)
      `,
        [
          sectionId,
          'Audit Test Section',
          'Test Heading',
          'Test content',
          JSON.stringify({ project: 'test' }),
        ]
      );

      // Check audit log for creation
      const createAudit = await client.query(
        `
        SELECT * FROM event_audit
        WHERE table_name = 'section' AND record_id = $1 AND operation = 'INSERT'
      `,
        [sectionId]
      );
      expect(createAudit.rows.length).toBeGreaterThan(0);

      // Update section
      await client.query(
        `
        UPDATE section SET title = $1 WHERE id = $2
      `,
        ['Updated Section', sectionId]
      );

      // Check audit log for update
      const updateAudit = await client.query(
        `
        SELECT * FROM event_audit
        WHERE table_name = 'section' AND record_id = $1 AND operation = 'UPDATE'
      `,
        [sectionId]
      );
      expect(updateAudit.rows.length).toBeGreaterThan(0);

      // Delete section
      await client.query('DELETE FROM section WHERE id = $1', [sectionId]);

      // Check audit log for deletion
      const deleteAudit = await client.query(
        `
        SELECT * FROM event_audit
        WHERE table_name = 'section' AND record_id = $1 AND operation = 'DELETE'
      `,
        [sectionId]
      );
      expect(deleteAudit.rows.length).toBeGreaterThan(0);
    });

    it('should audit ADR operations with immutable protection', async () => {
      const adrId = uuidv4();

      // Create ADR as proposed
      await client.query(
        `
        INSERT INTO adr_decision (id, component, status, title, rationale, tags)
        VALUES ($1, $2, $3, $4, $5, $6)
      `,
        [
          adrId,
          'auth',
          'proposed',
          'Test ADR',
          'Test rationale',
          JSON.stringify({ project: 'test' }),
        ]
      );

      // Accept ADR
      await client.query(
        `
        UPDATE adr_decision SET status = $1 WHERE id = $2
      `,
        ['accepted', adrId]
      );

      // Try to modify accepted ADR (should fail and be audited)
      await expect(
        client.query(
          `
        UPDATE adr_decision SET rationale = $1 WHERE id = $2
      `,
          ['Should fail', adrId]
        )
      ).rejects.toThrow();

      // Check audit log for attempted modification
      const auditResult = await client.query(
        `
        SELECT * FROM event_audit
        WHERE table_name = 'adr_decision' AND record_id = $1
        ORDER BY changed_at DESC
      `,
        [adrId]
      );
      expect(auditResult.rows.length).toBeGreaterThan(0);
    });

    it('should handle batch audit operations', async () => {
      // Create multiple sections
      const sectionIds = [uuidv4(), uuidv4(), uuidv4()];

      for (const id of sectionIds) {
        await client.query(
          `
          INSERT INTO section (id, title, heading, body_text, tags)
          VALUES ($1, $2, $3, $4, $5)
        `,
          [id, `Batch Section ${id}`, 'Heading', 'Content', JSON.stringify({ project: 'test' })]
        );
      }

      // Check audit log for all operations
      const auditResult = await client.query(
        `
        SELECT COUNT(*) as count FROM event_audit
        WHERE table_name = 'section' AND operation = 'INSERT'
        AND record_id = ANY($1)
      `,
        [sectionIds]
      );

      expect(parseInt(auditResult.rows[0].count)).toBe(sectionIds.length);
    });
  });

  // ============================================================================
  // Auto-Purge Tests
  // ============================================================================

  describe('Auto-Purge Functionality', () => {
    it('should clean up old audit events', async () => {
      // Create old audit event
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - 100); // 100 days ago

      await client.query(
        `
        INSERT INTO event_audit (
          event_id, event_type, table_name, record_id, operation, changed_at
        ) VALUES ($1, $2, $3, $4, $5, $6)
      `,
        [uuidv4(), 'test', 'test_table', 'test_id', 'INSERT', oldDate]
      );

      // Create recent audit event
      await client.query(
        `
        INSERT INTO event_audit (
          event_id, event_type, table_name, record_id, operation, changed_at
        ) VALUES ($1, $2, $3, $4, $5, $6)
      `,
        [uuidv4(), 'test', 'test_table', 'test_id', 'INSERT', new Date()]
      );

      // Count before cleanup
      const beforeCount = await client.query('SELECT COUNT(*) as count FROM event_audit');
      const initialCount = parseInt(beforeCount.rows[0].count);

      // Run cleanup (older than 90 days)
      await client.query(`
        DELETE FROM event_audit WHERE changed_at < NOW() - INTERVAL '90 days'
      `);

      // Count after cleanup
      const afterCount = await client.query('SELECT COUNT(*) as count FROM event_audit');
      const finalCount = parseInt(afterCount.rows[0].count);

      // Should have removed the old event but kept the recent one
      expect(finalCount).toBe(initialCount - 1);
    });

    it('should clean up closed todos and issues', async () => {
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - 100);

      // Create old closed todo
      await client.query(
        `
        INSERT INTO todo_log (id, text, status, updated_at, tags)
        VALUES ($1, $2, $3, $4, $5)
      `,
        [uuidv4(), 'Old todo', 'done', oldDate, JSON.stringify({ project: 'test' })]
      );

      // Create old closed issue
      await client.query(
        `
        INSERT INTO issue_log (id, title, status, updated_at, tags)
        VALUES ($1, $2, $3, $4, $5)
      `,
        [uuidv4(), 'Old issue', 'closed', oldDate, JSON.stringify({ project: 'test' })]
      );

      // Create recent closed items
      await client.query(
        `
        INSERT INTO todo_log (id, text, status, updated_at, tags)
        VALUES ($1, $2, $3, $4, $5)
      `,
        [uuidv4(), 'Recent todo', 'done', new Date(), JSON.stringify({ project: 'test' })]
      );

      await client.query(
        `
        INSERT INTO issue_log (id, title, status, updated_at, tags)
        VALUES ($1, $2, $3, $4, $5)
      `,
        [uuidv4(), 'Recent issue', 'closed', new Date(), JSON.stringify({ project: 'test' })]
      );

      // Count before cleanup
      const todoBefore = await client.query(
        "SELECT COUNT(*) as count FROM todo_log WHERE status IN ('done', 'cancelled')"
      );
      const issueBefore = await client.query(
        "SELECT COUNT(*) as count FROM issue_log WHERE status = 'closed'"
      );

      // Run cleanup (older than 90 days)
      await client.query(`
        DELETE FROM todo_log
        WHERE status IN ('done', 'cancelled') AND updated_at < NOW() - INTERVAL '90 days'
      `);

      await client.query(`
        DELETE FROM issue_log
        WHERE status = 'closed' AND updated_at < NOW() - INTERVAL '90 days'
      `);

      // Count after cleanup
      const todoAfter = await client.query(
        "SELECT COUNT(*) as count FROM todo_log WHERE status IN ('done', 'cancelled')"
      );
      const issueAfter = await client.query(
        "SELECT COUNT(*) as count FROM issue_log WHERE status = 'closed'"
      );

      // Should have removed old items but kept recent ones
      expect(parseInt(todoAfter.rows[0].count)).toBe(parseInt(todoBefore.rows[0].count) - 1);
      expect(parseInt(issueAfter.rows[0].count)).toBe(parseInt(issueBefore.rows[0].count) - 1);
    });
  });

  // ============================================================================
  // 8-LOG SYSTEM Tests
  // ============================================================================

  describe('8-LOG SYSTEM Functionality', () => {
    it('should maintain consistent logging across all log types', async () => {
      const testScope = { project: 'log-test', branch: 'main' };

      // Create entries in each log type
      const logs = [
        {
          table: 'change_log',
          data: { subject_ref: 'test', summary: 'Test change', change_type: 'feature' },
        },
        {
          table: 'issue_log',
          data: {
            title: 'Test Issue',
            description: 'Test issue',
            status: 'open',
            severity: 'medium',
          },
        },
        {
          table: 'todo_log',
          data: { text: 'Test todo', status: 'pending', priority: 'medium' },
        },
        {
          table: 'release_log',
          data: { version: '1.0.0', scope: 'test', status: 'planned' },
        },
        {
          table: 'incident_log',
          data: {
            title: 'Test Incident',
            description: 'Test incident',
            severity: 'low',
            status: 'open',
          },
        },
        {
          table: 'risk_log',
          data: {
            title: 'Test Risk',
            description: 'Test risk',
            category: 'technical',
            status: 'open',
          },
        },
        {
          table: 'assumption_log',
          data: {
            title: 'Test Assumption',
            description: 'Test assumption',
            validation_status: 'unvalidated',
          },
        },
      ];

      for (const log of logs) {
        const id = uuidv4();
        const columns = Object.keys(log.data).join(', ');
        const placeholders = Object.keys(log.data)
          .map((_, i) => `$${i + 2}`)
          .join(', ');
        const values = [id, ...Object.values(log.data)];

        await client.query(
          `
          INSERT INTO ${log.table} (id, ${columns}, tags)
          VALUES ($1, ${placeholders}, $2)
        `,
          [...values, JSON.stringify(testScope)]
        );
      }

      // Verify all log entries exist
      for (const log of logs) {
        const result = await client.query(
          `
          SELECT COUNT(*) as count FROM ${log.table}
          WHERE tags->>'project' = $1
        `,
          ['log-test']
        );
        expect(parseInt(result.rows[0].count)).toBeGreaterThan(0);
      }
    });

    it('should support cross-log queries and relationships', async () => {
      const testScope = { project: 'cross-log-test', branch: 'main' };

      // Create related entries across different logs
      const changeId = uuidv4();
      const issueId = uuidv4();
      const todoId = uuidv4();

      // Change log entry
      await client.query(
        `
        INSERT INTO change_log (id, subject_ref, summary, change_type, tags)
        VALUES ($1, $2, $3, $4, $5)
      `,
        [changeId, 'refs/changes/test', 'Implement feature X', 'feature', JSON.stringify(testScope)]
      );

      // Related issue
      await client.query(
        `
        INSERT INTO issue_log (id, title, description, status, severity, related_change, tags)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `,
        [
          issueId,
          'Issue with feature X',
          'Found bug in implementation',
          'open',
          'high',
          changeId,
          JSON.stringify(testScope),
        ]
      );

      // Related todo
      await client.query(
        `
        INSERT INTO todo_log (id, text, status, priority, related_issue, tags)
        VALUES ($1, $2, $3, $4, $5, $6)
      `,
        [todoId, 'Fix bug in feature X', 'pending', 'high', issueId, JSON.stringify(testScope)]
      );

      // Query cross-log relationships
      const crossLogResult = await client.query(
        `
        SELECT
          c.id as change_id, c.summary as change_summary,
          i.id as issue_id, i.title as issue_title,
          t.id as todo_id, t.text as todo_text
        FROM change_log c
        LEFT JOIN issue_log i ON i.related_change = c.id
        LEFT JOIN todo_log t ON t.related_issue = i.id
        WHERE c.tags->>'project' = $1
      `,
        ['cross-log-test']
      );

      expect(crossLogResult.rows).toHaveLength(1);
      expect(crossLogResult.rows[0].change_summary).toBe('Implement feature X');
      expect(crossLogResult.rows[0].issue_title).toBe('Issue with feature X');
      expect(crossLogResult.rows[0].todo_text).toBe('Fix bug in feature X');
    });
  });

  // ============================================================================
  // Performance and Scalability Tests
  // ============================================================================

  describe('Performance and Scalability', () => {
    it('should handle bulk insert operations efficiently', async () => {
      const testScope = { project: 'bulk-test', branch: 'main' };
      const bulkSize = 100;
      const sectionIds = [];

      // Create document
      const docResult = await client.query(
        `
        INSERT INTO document (id, title, type, tags)
        VALUES ($1, $2, $3, $4)
        RETURNING id
      `,
        [uuidv4(), 'Bulk Test Document', 'test', JSON.stringify(testScope)]
      );

      const documentId = docResult.rows[0].id;

      // Bulk insert sections
      const bulkInsertStart = Date.now();

      for (let i = 0; i < bulkSize; i++) {
        const sectionId = uuidv4();
        sectionIds.push(sectionId);

        await client.query(
          `
          INSERT INTO section (id, document_id, title, heading, body_text, tags)
          VALUES ($1, $2, $3, $4, $5, $6)
        `,
          [
            sectionId,
            documentId,
            `Section ${i}`,
            `Heading ${i}`,
            `Content for section ${i}`,
            JSON.stringify(testScope),
          ]
        );
      }

      const bulkInsertTime = Date.now() - bulkInsertStart;

      // Verify all sections were created
      const countResult = await client.query(
        `
        SELECT COUNT(*) as count FROM section WHERE document_id = $1
      `,
        [documentId]
      );
      expect(parseInt(countResult.rows[0].count)).toBe(bulkSize);

      // Performance should be reasonable (less than 5 seconds for 100 records)
      expect(bulkInsertTime).toBeLessThan(5000);

      // Test FTS search performance
      const searchStart = Date.now();
      const searchResult = await client.query(
        `
        SELECT id FROM section
        WHERE ts @@ to_tsquery('english', 'content')
        AND document_id = $1
      `,
        [documentId]
      );
      const searchTime = Date.now() - searchStart;

      expect(searchResult.rows.length).toBe(bulkSize);
      expect(searchTime).toBeLessThan(1000); // Search should be fast with FTS index
    });

    it('should handle concurrent operations safely', async () => {
      const testScope = { project: 'concurrent-test', branch: 'main' };
      const concurrentOperations = 10;
      const promises = [];

      // Create document
      const docResult = await client.query(
        `
        INSERT INTO document (id, title, type, tags)
        VALUES ($1, $2, $3, $4)
        RETURNING id
      `,
        [uuidv4(), 'Concurrent Test Document', 'test', JSON.stringify(testScope)]
      );

      const documentId = docResult.rows[0].id;

      // Run concurrent insert operations
      for (let i = 0; i < concurrentOperations; i++) {
        promises.push(
          (async () => {
            const sectionId = uuidv4();
            await client.query(
              `
              INSERT INTO section (id, document_id, title, heading, body_text, tags)
              VALUES ($1, $2, $3, $4, $5, $6)
            `,
              [
                sectionId,
                documentId,
                `Concurrent Section ${i}`,
                `Heading ${i}`,
                `Content for concurrent section ${i}`,
                JSON.stringify(testScope),
              ]
            );
            return sectionId;
          })()
        );
      }

      // Wait for all operations to complete
      const results = await Promise.all(promises);
      expect(results.length).toBe(concurrentOperations);

      // Verify all sections were created without conflicts
      const countResult = await client.query(
        `
        SELECT COUNT(*) as count FROM section WHERE document_id = $1
      `,
        [documentId]
      );
      expect(parseInt(countResult.rows[0].count)).toBe(concurrentOperations);
    });
  });

  // ============================================================================
  // Error Handling and Edge Cases
  // ============================================================================

  describe('Error Handling and Edge Cases', () => {
    it('should handle invalid UUID inputs gracefully', async () => {
      // Try to insert with invalid UUID
      await expect(
        client.query(
          `
        INSERT INTO section (id, title, heading, body_text, tags)
        VALUES ($1, $2, $3, $4, $5)
      `,
          ['invalid-uuid', 'Test', 'Heading', 'Content', JSON.stringify({ project: 'test' })]
        )
      ).rejects.toThrow();
    });

    it('should handle JSON data validation', async () => {
      // Try to insert invalid JSON
      await expect(
        client.query(
          `
        INSERT INTO section (id, title, heading, body_text, tags)
        VALUES ($1, $2, $3, $4, $5)
      `,
          [uuidv4(), 'Test', 'Heading', 'Content', 'invalid-json']
        )
      ).rejects.toThrow();
    });

    it('should handle foreign key constraints', async () => {
      // Try to insert section with non-existent document
      const nonExistentDocId = uuidv4();
      await expect(
        client.query(
          `
        INSERT INTO section (id, document_id, title, heading, body_text, tags)
        VALUES ($1, $2, $3, $4, $5)
      `,
          [
            uuidv4(),
            nonExistentDocId,
            'Test',
            'Heading',
            'Content',
            JSON.stringify({ project: 'test' }),
          ]
        )
      ).rejects.toThrow();
    });

    it('should handle unique constraint violations', async () => {
      const sectionId = uuidv4();

      // Insert section
      await client.query(
        `
        INSERT INTO section (id, title, heading, body_text, tags)
        VALUES ($1, $2, $3, $4, $5)
      `,
        [sectionId, 'Test', 'Heading', 'Content', JSON.stringify({ project: 'test' })]
      );

      // Try to insert again with same ID
      await expect(
        client.query(
          `
        INSERT INTO section (id, title, heading, body_text, tags)
        VALUES ($1, $2, $3, $4, $5)
      `,
          [sectionId, 'Test 2', 'Heading 2', 'Content 2', JSON.stringify({ project: 'test' })]
        )
      ).rejects.toThrow();
    });
  });

  // ============================================================================
  // View and Index Tests
  // ============================================================================

  describe('Views and Indexes', () => {
    it('should have working active_knowledge view', async () => {
      const testScope = { project: 'view-test', branch: 'main' };

      // Create test data
      await client.query(
        `
        INSERT INTO section (id, title, heading, body_text, tags)
        VALUES ($1, $2, $3, $4, $5)
      `,
        [uuidv4(), 'Active Section', 'Heading', 'Content', JSON.stringify(testScope)]
      );

      await client.query(
        `
        INSERT INTO todo_log (id, text, status, tags)
        VALUES ($1, $2, $3, $4)
      `,
        [uuidv4(), 'Active Todo', 'pending', JSON.stringify(testScope)]
      );

      await client.query(
        `
        INSERT INTO todo_log (id, text, status, tags)
        VALUES ($1, $2, $3, $4)
      `,
        [uuidv4(), 'Completed Todo', 'done', JSON.stringify(testScope)]
      );

      // Query active knowledge view
      const result = await client.query(
        `
        SELECT * FROM active_knowledge WHERE tags->>'project' = $1
      `,
        ['view-test']
      );

      // Should return active items (section and pending todo, but not completed todo)
      expect(result.rows.length).toBe(2);
      const types = result.rows.map((row) => row.type);
      expect(types).toContain('section');
      expect(types).toContain('todo');
    });

    it('should have working graph_relationships view', async () => {
      const entityId1 = uuidv4();
      const entityId2 = uuidv4();

      // Create entities and relation
      await client.query(
        `
        INSERT INTO knowledge_entity (id, name, type, tags)
        VALUES ($1, $2, $3, $4), ($5, $6, $7, $8)
      `,
        [
          entityId1,
          'Entity 1',
          'service',
          JSON.stringify({ project: 'view-test' }),
          entityId2,
          'Entity 2',
          'database',
          JSON.stringify({ project: 'view-test' }),
        ]
      );

      await client.query(
        `
        INSERT INTO knowledge_relation (
          from_entity_id, from_entity_type, to_entity_id, to_entity_type, relation_type
        ) VALUES ($1, $2, $3, $4, $5)
      `,
        [entityId1, 'service', entityId2, 'database', 'depends_on']
      );

      // Query graph relationships view
      const result = await client.query(
        `
        SELECT * FROM graph_relationships
        WHERE from_entity_id = $1 AND to_entity_id = $2
      `,
        [entityId1, entityId2]
      );

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].relation_type).toBe('depends_on');
    });

    it('should have working recent_activity view', async () => {
      const testScope = { project: 'activity-test', branch: 'main' };

      // Create recent activity
      await client.query(
        `
        INSERT INTO section (id, title, heading, body_text, tags, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)
      `,
        [uuidv4(), 'Recent Section', 'Heading', 'Content', JSON.stringify(testScope), new Date()]
      );

      await client.query(
        `
        INSERT INTO change_log (id, subject_ref, summary, change_type, tags, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)
      `,
        [uuidv4(), 'test', 'Recent change', 'feature', JSON.stringify(testScope), new Date()]
      );

      // Query recent activity view
      const result = await client.query(
        `
        SELECT * FROM recent_activity WHERE tags->>'project' = $1
      `,
        ['activity-test']
      );

      expect(result.rows.length).toBe(2);
    });
  });
});
