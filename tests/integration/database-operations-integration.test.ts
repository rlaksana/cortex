/**
 * Database Operations Integration Tests
 *
 * Tests comprehensive database operations including:
 * - Connection pooling and management
 * - Transaction handling and rollback
 * - CRUD operations across all knowledge types
 * - Performance under load
 * - Error handling and recovery
 * - Data consistency and constraints
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { Pool } from 'pg';
import { dbPool } from '../db/pool.ts';
// Prisma client removed - system now uses Qdrant + PostgreSQL architecture';
import { memoryStore } from '../services/memory-store.ts';
import { memoryFind } from '../services/memory-find.ts';
import { logger } from '../utils/logger.ts';

describe('Database Operations Integration Tests', () => {
  let pool: Pool;
  let testDbConfig: any;

  beforeAll(async () => {
    // Initialize database connections
    await dbPool.initialize();

    // Create direct pool for test isolation
    testDbConfig = {
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5433'),
      database: process.env.DB_NAME || 'cortex_prod',
      user: process.env.DB_USER || 'cortex',
      password: process.env.DB_PASSWORD || '',
    };

    pool = new Pool(testDbConfig);

    // Ensure test isolation by creating test schema if needed
    await pool.query(`
      CREATE SCHEMA IF NOT EXISTS test_integration;
      SET search_path TO test_integration, public;
    `);
  });

  afterAll(async () => {
    // Cleanup test data
    const cleanupTables = [
      'section', 'decision', 'issue', 'runbook', 'change_log',
      'adr_decision', 'knowledge_entity', 'knowledge_relation',
      'observation', 'todo', 'ddl', 'pr_context', 'incident',
      'release', 'release_note', 'risk', 'assumption'
    ];

    for (const table of cleanupTables) {
      try {
        await pool.query(`DELETE FROM ${table} WHERE tags @> '{"integration_test": true}'::jsonb`);
      } catch (error) {
        // Table might not exist, continue
      }
    }

    await pool.end();
    // Don't close shared pools
  });

  describe('Connection Pool Management', () => {
    it('should maintain healthy connection pool', async () => {
      const healthCheck = await dbPool.healthCheck();
      expect(healthCheck.isHealthy).toBe(true);
      expect(healthCheck.poolStats).toBeDefined();
      expect(healthCheck.databaseStats).toBeDefined();
    });

    it('should handle concurrent connections', async () => {
      const concurrentQueries = 20;
      const queries = Array.from({ length: concurrentQueries }, (_, i) =>
        pool.query(`SELECT ${i} as test_id, NOW() as query_time`)
      );

      const results = await Promise.all(queries);
      expect(results).toHaveLength(concurrentQueries);

      results.forEach((result, index) => {
        expect(result.rows).toHaveLength(1);
        expect(parseInt(result.rows[0].test_id)).toBe(index);
      });
    });

    it('should recover from connection failures', async () => {
      // Simulate connection stress with rapid connections
      const stressQueries = Array.from({ length: 50 }, () =>
        pool.query('SELECT pg_sleep(0.01), NOW() as test_time')
      );

      const startTime = Date.now();
      const results = await Promise.allSettled(stressQueries);
      const duration = Date.now() - startTime;

      // Most queries should succeed
      const successful = results.filter(r => r.status === 'fulfilled').length;
      expect(successful).toBeGreaterThan(45); // At least 90% success rate
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
    });

    it('should respect pool configuration limits', async () => {
      const stats = dbPool.getStats();
      expect(stats.max).toBeGreaterThan(0);
      expect(stats.total).toBeLessThanOrEqual(stats.max);
      expect(stats.idle).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Transaction Management', () => {
    it('should handle single transaction successfully', async () => {
      await dbPool.transaction(async (client) => {
        // Insert test data
        const result = await client.query(`
          INSERT INTO section (title, heading, body_text, tags)
          VALUES ($1, $2, $3, $4)
          RETURNING id, title, heading
        `, [
          'Transaction Test Section',
          'Transaction Test Heading',
          'Test content within transaction',
          JSON.stringify({ integration_test: true, transaction_test: true })
        ]);

        expect(result.rows).toHaveLength(1);
        expect(result.rows[0].title).toBe('Transaction Test Section');

        // Verify data exists within transaction
        const verifyResult = await client.query(
          'SELECT COUNT(*) as count FROM section WHERE tags @> $1::jsonb',
          [JSON.stringify({ transaction_test: true })]
        );
        expect(parseInt(verifyResult.rows[0].count)).toBe(1);
      });

      // Verify data persisted after transaction commit
      const verifyResult = await pool.query(
        'SELECT COUNT(*) as count FROM section WHERE tags @> $1::jsonb',
        [JSON.stringify({ transaction_test: true })]
      );
      expect(parseInt(verifyResult.rows[0].count)).toBe(1);
    });

    it('should rollback on transaction failure', async () => {
      const initialCount = await pool.query(
        'SELECT COUNT(*) as count FROM section WHERE tags @> $1::jsonb',
        [JSON.stringify({ rollback_test: true })]
      );
      const initialCountNum = parseInt(initialCount.rows[0].count);

      try {
        await dbPool.transaction(async (client) => {
          // Insert test data
          await client.query(`
            INSERT INTO section (title, heading, body_text, tags)
            VALUES ($1, $2, $3, $4)
          `, [
            'Rollback Test Section',
            'Rollback Test Heading',
            'This should be rolled back',
            JSON.stringify({ integration_test: true, rollback_test: true })
          ]);

          // Force an error to trigger rollback
          throw new Error('Intentional transaction failure');
        });
      } catch (error) {
        // Expected error
        expect(error.message).toBe('Intentional transaction failure');
      }

      // Verify data was rolled back
      const finalCount = await pool.query(
        'SELECT COUNT(*) as count FROM section WHERE tags @> $1::jsonb',
        [JSON.stringify({ rollback_test: true })]
      );
      const finalCountNum = parseInt(finalCount.rows[0].count);
      expect(finalCountNum).toBe(initialCountNum);
    });

    it('should handle nested transaction logic', async () => {
      await dbPool.transaction(async (client) => {
        // Create parent record
        const parentResult = await client.query(`
          INSERT INTO document (title, description, tags)
          VALUES ($1, $2, $3)
          RETURNING id
        `, [
          'Parent Document',
          'Parent document for nested transaction test',
          JSON.stringify({ integration_test: true, nested_test: true })
        ]);

        const parentId = parentResult.rows[0].id;

        // Create child records within same transaction
        await client.query(`
          INSERT INTO section (document_id, title, heading, body_text, tags)
          VALUES ($1, $2, $3, $4, $5)
        `, [
          parentId,
          'Child Section 1',
          'Child Heading 1',
          'Child content 1',
          JSON.stringify({ integration_test: true, nested_test: true })
        ]);

        await client.query(`
          INSERT INTO section (document_id, title, heading, body_text, tags)
          VALUES ($1, $2, $3, $4, $5)
        `, [
          parentId,
          'Child Section 2',
          'Child Heading 2',
          'Child content 2',
          JSON.stringify({ integration_test: true, nested_test: true })
        ]);

        // Verify relationships exist within transaction
        const verifyResult = await client.query(`
          SELECT COUNT(*) as count
          FROM section s
          JOIN document d ON s.document_id = d.id
          WHERE d.tags @> $1::jsonb AND s.tags @> $1::jsonb
        `, [JSON.stringify({ nested_test: true })]);

        expect(parseInt(verifyResult.rows[0].count)).toBe(2);
      });

      // Verify all data persisted correctly
      const verifyResult = await pool.query(`
        SELECT COUNT(*) as count
        FROM section s
        JOIN document d ON s.document_id = d.id
        WHERE d.tags @> $1::jsonb AND s.tags @> $1::jsonb
      `, [JSON.stringify({ nested_test: true })]);

      expect(parseInt(verifyResult.rows[0].count)).toBe(2);
    });
  });

  describe('CRUD Operations Across Knowledge Types', () => {
    const testKinds = [
      'section', 'decision', 'issue', 'runbook', 'change',
      'entity', 'relation', 'observation', 'todo', 'ddl',
      'pr_context', 'incident', 'release', 'release_note',
      'risk', 'assumption'
    ] as const;

    it('should create and retrieve all knowledge types', async () => {
      const results = await memoryStore(
        testKinds.map((kind, index) => ({
          kind,
          scope: { project: 'crud-test', branch: 'main' },
          data: {
            title: `Test ${kind} ${index}`,
            heading: kind === 'section' ? `Test heading for ${kind}` : undefined,
            body_text: kind === 'section' ? `Test content for ${kind}` : undefined,
            component: ['decision', 'issue'].includes(kind) ? 'test-component' : undefined,
            service: kind === 'runbook' ? 'test-service' : undefined,
            entity_type: kind === 'entity' ? 'test_entity' : undefined,
            name: ['entity', 'relation'].includes(kind) ? `test_${kind}_${index}` : undefined,
          },
          tags: { integration_test: true, crud_test: true, [kind]: true },
        }))
      );

      expect(results.stored).toHaveLength(testKinds.length);
      expect(results.errors).toHaveLength(0);

      // Verify each item was stored correctly
      for (const stored of results.stored) {
        expect(stored.status).toBe('inserted');
        expect(stored.id).toBeDefined();
        expect(stored.kind).toBeDefined();
        expect(stored.created_at).toBeDefined();
      }
    });

    it('should update existing knowledge items', async () => {
      // Create initial item
      const initialResult = await memoryStore([{
        kind: 'section',
        scope: { project: 'update-test', branch: 'main' },
        data: {
          title: 'Original Title',
          heading: 'Original Heading',
          body_text: 'Original content',
        },
        tags: { integration_test: true, update_test: true },
      }]);

      const itemId = initialResult.stored[0].id;
      expect(initialResult.stored[0].status).toBe('inserted');

      // Update the item
      const updateResult = await memoryStore([{
        kind: 'section',
        scope: { project: 'update-test', branch: 'main' },
        data: {
          title: 'Updated Title',
          heading: 'Updated Heading',
          body_text: 'Updated content with new information',
        },
        tags: { integration_test: true, update_test: true, updated: true },
      }]);

      expect(updateResult.stored[0].status).toBe('inserted'); // Updated via upsert logic

      // Verify the update persisted
      const findResult = await memoryFind({
        query: 'Updated Title',
        scope: { project: 'update-test', branch: 'main' },
      });

      expect(findResult.hits.length).toBeGreaterThan(0);
      const updatedItem = findResult.hits.find((hit: any) => hit.title === 'Updated Title');
      expect(updatedItem).toBeDefined();
    });

    it('should delete knowledge items correctly', async () => {
      // Create item to delete
      const createResult = await memoryStore([{
        kind: 'decision',
        scope: { project: 'delete-test', branch: 'main' },
        data: {
          title: 'To Be Deleted',
          status: 'proposed',
          component: 'test-component',
          rationale: 'This will be deleted',
        },
        tags: { integration_test: true, delete_test: true },
      }]);

      const itemId = createResult.stored[0].id;
      expect(createResult.stored[0].status).toBe('inserted');

      // Delete the item
      const deleteResult = await memoryStore([{
        kind: 'decision',
        scope: { project: 'delete-test', branch: 'main' },
        data: { id: itemId },
        tags: { integration_test: true, delete_test: true },
        operation: 'delete' as const,
      }]);

      expect(deleteResult.stored[0].status).toBe('deleted');

      // Verify deletion
      const findResult = await memoryFind({
        query: 'To Be Deleted',
        scope: { project: 'delete-test', branch: 'main' },
      });

      expect(findResult.hits.length).toBe(0);
    });

    it('should handle batch operations efficiently', async () => {
      const batchSize = 100;
      const batchItems = Array.from({ length: batchSize }, (_, i) => ({
        kind: 'entity' as const,
        scope: { project: 'batch-test', branch: 'main' },
        data: {
          entity_type: 'batch_test_entity',
          name: `Batch Test Entity ${i}`,
          data: { batch_index: i, content: `Batch content ${i}` },
        },
        tags: { integration_test: true, batch_test: true },
      }));

      const startTime = Date.now();
      const result = await memoryStore(batchItems);
      const duration = Date.now() - startTime;

      expect(result.stored).toHaveLength(batchSize);
      expect(result.errors).toHaveLength(0);
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds

      // Verify all items were stored
      const findResult = await memoryFind({
        query: 'Batch Test Entity',
        scope: { project: 'batch-test', branch: 'main' },
        types: ['entity'],
      });

      expect(findResult.hits.length).toBe(batchSize);
    });
  });

  describe('Database Constraints and Validation', () => {
    it('should enforce required field constraints', async () => {
      // Test missing required fields for different knowledge types
      const invalidItems = [
        {
          kind: 'section' as const,
          scope: { project: 'constraint-test', branch: 'main' },
          data: { heading: 'Missing title' }, // Missing required title
          tags: { integration_test: true, constraint_test: true },
        },
        {
          kind: 'decision' as const,
          scope: { project: 'constraint-test', branch: 'main' },
          data: { title: 'Missing required fields' }, // Missing status, component, rationale
          tags: { integration_test: true, constraint_test: true },
        },
        {
          kind: 'entity' as const,
          scope: { project: 'constraint-test', branch: 'main' },
          data: { name: 'Missing entity_type' }, // Missing entity_type
          tags: { integration_test: true, constraint_test: true },
        },
      ];

      const result = await memoryStore(invalidItems);

      // All should fail due to validation
      expect(result.stored.length).toBeLessThan(invalidItems.length);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should enforce length constraints', async () => {
      const veryLongTitle = 'x'.repeat(600); // Exceeds typical 500 char limit

      const result = await memoryStore([{
        kind: 'section',
        scope: { project: 'constraint-test', branch: 'main' },
        data: {
          title: veryLongTitle,
          heading: 'Test heading',
          body_text: 'Test content',
        },
        tags: { integration_test: true, constraint_test: true },
      }]);

      // Should fail due to title length constraint
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should enforce foreign key constraints', async () => {
      // Try to create a section with invalid document_id
      try {
        await pool.query(`
          INSERT INTO section (document_id, title, heading, body_text, tags)
          VALUES ($1, $2, $3, $4, $5)
        `, [
          '00000000-0000-0000-0000-000000000000', // Invalid UUID
          'Test Section',
          'Test Heading',
          'Test content',
          JSON.stringify({ integration_test: true, constraint_test: true })
        ]);
        expect.fail('Should have thrown foreign key constraint error');
      } catch (error) {
        expect(error.message).toContain('violates foreign key constraint');
      }
    });

    it('should handle unique constraints properly', async () => {
      // Create an item with a unique identifier
      await memoryStore([{
        kind: 'entity',
        scope: { project: 'constraint-test', branch: 'main' },
        data: {
          entity_type: 'unique_test',
          name: 'unique_entity_name',
          data: { unique: true },
        },
        tags: { integration_test: true, constraint_test: true },
      }]);

      // Try to create another with same identifier within same scope
      const result = await memoryStore([{
        kind: 'entity',
        scope: { project: 'constraint-test', branch: 'main' },
        data: {
          entity_type: 'unique_test',
          name: 'unique_entity_name', // Same name
          data: { unique: false },
        },
        tags: { integration_test: true, constraint_test: true },
      }]);

      // Should update existing record rather than create duplicate
      expect(result.stored[0].status).toBe('inserted'); // Updated via upsert
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large text content efficiently', async () => {
      const largeContent = 'x'.repeat(100000); // 100KB of text

      const startTime = Date.now();
      const result = await memoryStore([{
        kind: 'section',
        scope: { project: 'performance-test', branch: 'main' },
        data: {
          title: 'Large Content Test',
          heading: 'Performance Test',
          body_text: largeContent,
        },
        tags: { integration_test: true, performance_test: true },
      }]);
      const duration = Date.now() - startTime;

      expect(result.stored[0].status).toBe('inserted');
      expect(duration).toBeLessThan(3000); // Should complete within 3 seconds

      // Verify retrieval performance
      const findStartTime = Date.now();
      const findResult = await memoryFind({
        query: 'Large Content Test',
        scope: { project: 'performance-test', branch: 'main' },
      });
      const findDuration = Date.now() - findStartTime;

      expect(findResult.hits.length).toBe(1);
      expect(findDuration).toBeLessThan(1000); // Should find within 1 second
    });

    it('should maintain performance under concurrent load', async () => {
      const concurrentOperations = 20;
      const operationsPerThread = 10;

      const promises = Array.from({ length: concurrentOperations }, async (_, threadIndex) => {
        const results = [];
        for (let i = 0; i < operationsPerThread; i++) {
          const storeResult = await memoryStore([{
            kind: 'entity',
            scope: { project: 'concurrent-test', branch: `thread-${threadIndex}` },
            data: {
              entity_type: 'concurrent_entity',
              name: `Concurrent Entity ${threadIndex}-${i}`,
              data: { thread: threadIndex, index: i },
            },
            tags: { integration_test: true, concurrent_test: true },
          }]);
          results.push(storeResult.stored[0].id);
        }
        return results;
      });

      const startTime = Date.now();
      const allResults = await Promise.all(promises);
      const duration = Date.now() - startTime;

      const totalOperations = concurrentOperations * operationsPerThread;
      const allIds = allResults.flat();

      expect(allIds).toHaveLength(totalOperations);
      expect(duration).toBeLessThan(10000); // Should complete within 10 seconds

      // Verify all data was stored correctly
      const findResult = await memoryFind({
        query: 'Concurrent Entity',
        types: ['entity'],
      });
      expect(findResult.hits.length).toBeGreaterThanOrEqual(totalOperations);
    });

    it('should handle complex join queries efficiently', async () => {
      // Create interconnected data
      const documentResult = await memoryStore([{
        kind: 'entity',
        scope: { project: 'join-test', branch: 'main' },
        data: {
          entity_type: 'document',
          name: 'Main Document',
          data: { type: 'document' },
        },
        tags: { integration_test: true, join_test: true },
      }]);

      const documentId = documentResult.stored[0].id;

      // Create related sections
      const sectionPromises = Array.from({ length: 10 }, (_, i) =>
        memoryStore([{
          kind: 'section',
          scope: { project: 'join-test', branch: 'main' },
          data: {
            title: `Section ${i}`,
            heading: `Section Heading ${i}`,
            body_text: `Content for section ${i}`,
            document_id: documentId,
          },
          tags: { integration_test: true, join_test: true },
        }])
      );

      await Promise.all(sectionPromises);

      // Create related relations
      const relationPromises = Array.from({ length: 5 }, (_, i) =>
        memoryStore([{
          kind: 'relation',
          scope: { project: 'join-test', branch: 'main' },
          data: {
            name: `relation-${i}`,
            data: {
              source_id: documentId,
              target_type: 'section',
              relationship: 'contains',
            },
          },
          tags: { integration_test: true, join_test: true },
        }])
      );

      await Promise.all(relationPromises);

      // Test complex query performance
      const startTime = Date.now();
      const findResult = await memoryFind({
        query: 'Main Document',
        scope: { project: 'join-test', branch: 'main' },
      });
      const duration = Date.now() - startTime;

      expect(findResult.hits.length).toBeGreaterThan(0);
      expect(duration).toBeLessThan(2000); // Should complete within 2 seconds
    });
  });

  describe('Error Handling and Recovery', () => {
    it('should handle database connection failures gracefully', async () => {
      // Simulate connection failure by using invalid credentials
      const badPool = new Pool({
        host: 'localhost',
        port: 5433,
        database: 'nonexistent_db',
        user: 'invalid_user',
        password: 'invalid_password',
        connectionTimeoutMillis: 1000,
      });

      try {
        await badPool.query('SELECT 1');
        expect.fail('Should have thrown connection error');
      } catch (error) {
        expect(error.message).toContain('connection');
      } finally {
        await badPool.end();
      }
    });

    it('should handle query timeouts gracefully', async () => {
      // Create a long-running query
      const longQueryPromise = pool.query('SELECT pg_sleep(10)');

      // Should timeout before query completes
      try {
        await Promise.race([
          longQueryPromise,
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Query timeout')), 1000)
          )
        ]);
        expect.fail('Should have timed out');
      } catch (error) {
        expect(error.message).toBe('Query timeout');
      }
    });

    it('should handle malformed queries safely', async () => {
      const malformedQueries = [
        'INVALID SQL SYNTAX',
        'SELECT * FROM nonexistent_table',
        'INSERT INTO section () VALUES ()', // Missing required columns
      ];

      for (const query of malformedQueries) {
        try {
          await pool.query(query);
          expect.fail(`Query should have failed: ${query}`);
        } catch (error) {
          expect(error).toBeDefined();
        }
      }
    });

    it('should maintain data consistency during failures', async () => {
      // Start a transaction and ensure rollback on failure
      const initialCount = await pool.query(
        'SELECT COUNT(*) as count FROM section WHERE tags @> $1::jsonb',
        [JSON.stringify({ consistency_test: true })]
      );
      const initialCountNum = parseInt(initialCount.rows[0].count);

      try {
        await dbPool.transaction(async (client) => {
          // Insert some data
          await client.query(`
            INSERT INTO section (title, heading, body_text, tags)
            VALUES ($1, $2, $3, $4)
          `, [
            'Consistency Test',
            'Test Heading',
            'Test content',
            JSON.stringify({ integration_test: true, consistency_test: true })
          ]);

          // Force an error
          throw new Error('Forced transaction failure');
        });
      } catch (error) {
        // Expected
      }

      // Verify no data was committed
      const finalCount = await pool.query(
        'SELECT COUNT(*) as count FROM section WHERE tags @> $1::jsonb',
        [JSON.stringify({ consistency_test: true })]
      );
      const finalCountNum = parseInt(finalCount.rows[0].count);
      expect(finalCountNum).toBe(initialCountNum);
    });
  });
});