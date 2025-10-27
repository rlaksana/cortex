/**
 * Concurrent Operations Integration Tests
 *
 * Tests comprehensive concurrent operation scenarios including:
 * - Concurrent data storage and retrieval
 * - Transaction isolation and consistency
 * - Deadlock detection and prevention
 * - Performance under concurrent load
 * - Race condition handling
 * - Resource contention management
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
// PostgreSQL import removed - now using Qdrant;
import { dbQdrantClient } from '../db/pool.ts';
// Prisma client removed - system now uses Qdrant + PostgreSQL architecture';
import { memoryStore } from '../services/memory-store.ts';
import { memoryFind } from '../services/memory-find.ts';

describe('Concurrent Operations Integration Tests', () => {
  let testQdrantClient: QdrantClient;

  beforeAll(async () => {
    await dbQdrantClient.initialize();

    // Create separate test pool for concurrent testing
    testQdrantClient = new QdrantClient({
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5433'),
      database: process.env.DB_NAME || 'cortex_prod',
      user: process.env.DB_USER || 'cortex',
      password: process.env.DB_PASSWORD || '',
      max: 50, // Increase pool size for concurrent testing
      min: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000,
    });
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
        await dbQdrantClient.query(`DELETE FROM ${table} WHERE tags @> '{"concurrent_test": true}'::jsonb`);
      } catch (error) {
        // Table might not exist, continue
      }
    }

    await testQdrantClient.end();
  });

  describe('Concurrent Data Storage', () => {
    it('should handle concurrent storage operations without conflicts', async () => {
      const concurrentWriters = 20;
      const itemsPerWriter = 10;

      const concurrentPromises = Array.from({ length: concurrentWriters }, async (writerIndex) => {
        const writerItems = Array.from({ length: itemsPerWriter }, (_, itemIndex) => ({
          kind: 'section' as const,
          scope: {
            project: `concurrent-project-${writerIndex}`,
            branch: 'main',
            org: `concurrent-org-${Math.floor(writerIndex / 5)}`
          },
          data: {
            title: `Concurrent Section ${writerIndex}-${itemIndex}`,
            heading: `Concurrent Heading ${writerIndex}-${itemIndex}`,
            body_text: `Concurrent content from writer ${writerIndex}, item ${itemIndex}`
          },
          tags: {
            concurrent_test: true,
            storage_test: true,
            writer_index: writerIndex,
            item_index: itemIndex
          }
        }));

        const startTime = Date.now();
        const result = await memoryStore(writerItems);
        const duration = Date.now() - startTime;

        return {
          writerIndex,
          result,
          duration,
          storedCount: result.stored.length,
          errorCount: result.errors.length
        };
      });

      const overallStartTime = Date.now();
      const results = await Promise.all(concurrentPromises);
      const overallDuration = Date.now() - overallStartTime;

      console.log(`Completed ${concurrentWriters} concurrent writers (${concurrentWriters * itemsPerWriter} items) in ${overallDuration}ms`);

      // Verify all operations completed successfully
      expect(results.length).toBe(concurrentWriters);
      let totalStored = 0;
      let totalErrors = 0;

      results.forEach(({ writerIndex, result, duration, storedCount, errorCount }) => {
        expect(storedCount).toBe(itemsPerWriter);
        expect(errorCount).toBe(0);
        expect(duration).toBeLessThan(10000); // Each writer should complete within 10 seconds
        totalStored += storedCount;
        totalErrors += errorCount;
      });

      expect(totalStored).toBe(concurrentWriters * itemsPerWriter);
      expect(totalErrors).toBe(0);
      expect(overallDuration).toBeLessThan(30000); // Should complete within 30 seconds

      // Verify data integrity by checking all items were stored
      const verificationResults = await Promise.all(
        results.map(({ writerIndex }) =>
          memoryFind({
            query: `Concurrent Section ${writerIndex}`,
            scope: { project: `concurrent-project-${writerIndex}`, branch: 'main' }
          })
        )
      );

      verificationResults.forEach((result, writerIndex) => {
        expect(result.hits.length).toBe(itemsPerWriter);
        result.hits.forEach((hit, itemIndex) => {
          expect(hit.title).toBe(`Concurrent Section ${writerIndex}-${itemIndex}`);
        });
      });
    });

    it('should handle concurrent updates to the same entity', async () => {
      // Create initial entity
      const initialResult = await memoryStore([{
        kind: 'entity',
        scope: { project: 'concurrent-update-test', branch: 'main' },
        data: {
          entity_type: 'concurrent_entity',
          name: 'Concurrent Update Test',
          data: { version: 1, counter: 0 }
        },
        tags: { concurrent_test: true, update_test: true }
      }]);

      const entityId = initialResult.stored[0].id;
      expect(entityId).toBeDefined();

      const concurrentUpdaters = 10;
      const updatesPerUpdater = 5;

      const updatePromises = Array.from({ length: concurrentUpdaters }, async (updaterIndex) => {
        const updates = [];

        for (let i = 0; i < updatesPerUpdater; i++) {
          const updateData = {
            kind: 'entity' as const,
            scope: { project: 'concurrent-update-test', branch: 'main' },
            data: {
              entity_type: 'concurrent_entity',
              name: 'Concurrent Update Test',
              data: {
                version: 1 + (updaterIndex * updatesPerUpdater) + i,
                counter: (updaterIndex * updatesPerUpdater) + i,
                updater: `updater-${updaterIndex}`
              }
            },
            tags: { concurrent_test: true, update_test: true, updater_index: updaterIndex }
          };

          try {
            const result = await memoryStore([updateData]);
            updates.push({ success: true, result, updateIndex: i });
          } catch (error) {
            updates.push({ success: false, error, updateIndex: i });
          }

          // Small delay between updates
          await new Promise(resolve => setTimeout(resolve, 10));
        }

        return { updaterIndex, updates };
      });

      const updateResults = await Promise.all(updatePromises);

      // Verify all updates completed (some might have been merged)
      let totalSuccessful = 0;
      updateResults.forEach(({ updaterIndex, updates }) => {
        const successfulUpdates = updates.filter(u => u.success);
        totalSuccessful += successfulUpdates.length;
        console.log(`Updater ${updaterIndex}: ${successfulUpdates.length}/${updates.length} successful`);
      });

      expect(totalSuccessful).toBeGreaterThan(0);

      // Verify final state
      const finalState = await memoryFind({
        query: 'Concurrent Update Test',
        scope: { project: 'concurrent-update-test', branch: 'main' },
        types: ['entity']
      });

      expect(finalState.hits.length).toBe(1);
      const finalEntity = finalState.hits[0];

      // Should have the latest version from one of the updaters
      expect(finalEntity.title || finalEntity.name).toBe('Concurrent Update Test');
      expect(finalEntity.snippet).toBeDefined();
    });

    it('should handle concurrent storage of different knowledge types', async () => {
      const knowledgeTypes = ['section', 'decision', 'entity', 'observation', 'todo', 'risk'] as const;
      const itemsPerType = 5;

      const typePromises = knowledgeTypes.map(async (kind) => {
        const items = Array.from({ length: itemsPerType }, (_, i) => ({
          kind,
          scope: {
            project: `concurrent-type-test-${kind}`,
            branch: 'main',
            org: `type-test-org`
          },
          data: {
            title: `Concurrent ${kind} ${i}`,
            heading: kind === 'section' ? `Heading ${i}` : undefined,
            body_text: kind === 'section' ? `Content for ${kind} ${i}` : undefined,
            status: kind === 'decision' ? 'proposed' : undefined,
            component: kind === 'decision' ? 'test-component' : undefined,
            rationale: kind === 'decision' ? `Rationale for ${kind} ${i}` : undefined,
            entity_type: kind === 'entity' ? 'concurrent_type_entity' : undefined,
            name: kind === 'entity' ? `Entity ${i}` : undefined,
            content: kind === 'observation' ? `Observation content ${i}` : undefined,
            title: kind === 'todo' ? `Todo ${i}` : undefined,
            description: kind === 'risk' ? `Risk description ${i}` : undefined
          },
          tags: {
            concurrent_test: true,
            type_test: true,
            knowledge_type: kind,
            item_index: i
          }
        }));

        const startTime = Date.now();
        const result = await memoryStore(items);
        const duration = Date.now() - startTime;

        return { kind, result, duration, storedCount: result.stored.length };
      });

      const typeResults = await Promise.all(typePromises);

      // Verify all types were stored successfully
      typeResults.forEach(({ kind, result, duration, storedCount }) => {
        expect(storedCount).toBe(itemsPerType);
        expect(result.errors.length).toBe(0);
        expect(duration).toBeLessThan(10000);
        console.log(`Type ${kind}: ${storedCount} items stored in ${duration}ms`);
      });

      // Verify each type can be retrieved correctly
      const verificationPromises = typeResults.map(async ({ kind }) => {
        const findResult = await memoryFind({
          query: `Concurrent ${kind}`,
          scope: { project: `concurrent-type-test-${kind}`, branch: 'main' },
          types: [kind]
        });
        return { kind, count: findResult.hits.length };
      });

      const verificationResults = await Promise.all(verificationPromises);
      verificationResults.forEach(({ kind, count }) => {
        expect(count).toBe(itemsPerType);
      });
    });
  });

  describe('Concurrent Search Operations', () => {
    beforeEach(async () => {
      // Create test data for concurrent search testing
      const searchData = Array.from({ length: 500 }, (_, i) => ({
        kind: ['section', 'decision', 'entity'][i % 3] as const,
        scope: {
          project: `search-project-${Math.floor(i / 100)}`,
          branch: i % 10 === 0 ? 'main' : `feature-${i % 5}`,
          org: `search-org-${Math.floor(i / 200)}`
        },
        data: {
          title: `Search Test Item ${i}`,
          heading: i % 3 === 0 ? `Search Heading ${i}` : undefined,
          body_text: i % 3 === 0 ? `Search content about algorithms, machine learning, and data processing for item ${i}.` : undefined,
          status: i % 3 === 1 ? 'accepted' : undefined,
          component: i % 3 === 1 ? 'search-component' : undefined,
          rationale: i % 3 === 1 ? `Search rationale for decision ${i}.` : undefined,
          entity_type: i % 3 === 2 ? 'search_entity' : undefined,
          name: i % 3 === 2 ? `Search Entity ${i}` : undefined
        },
        tags: {
          concurrent_test: true,
          search_test: true,
          item_index: i,
          category: i % 5,
          priority: i % 3
        }
      }));

      await memoryStore(searchData);
    });

    it('should handle concurrent search operations efficiently', async () => {
      const concurrentSearchers = 15;
      const searchesPerSearcher = 8;

      const searchPromises = Array.from({ length: concurrentSearchers }, async (searcherIndex) => {
        const searches = [];

        for (let i = 0; i < searchesPerSearcher; i++) {
          const queryVariations = [
            'Search Test',
            'algorithms machine learning',
            'search rationale',
            `Search Entity ${searcherIndex * searchesPerSearcher + i}`,
            'search-component',
            `category ${i % 5}`,
            'priority 0',
            'feature main branch'
          ];

          const query = queryVariations[i % queryVariations.length];
          const scopeVariations = [
            { project: `search-project-${searcherIndex % 5}`, branch: 'main' },
            { project: `search-project-${(searcherIndex + 1) % 5}`, branch: `feature-${i % 5}` },
            { org: `search-org-${searcherIndex % 3}` },
            {} // No scope filter
          ];

          const scope = scopeVariations[i % scopeVariations.length];
          const modeVariations = ['fast', 'auto', 'deep'];
          const mode = modeVariations[i % modeVariations.length] as 'fast' | 'auto' | 'deep';

          const startTime = Date.now();
          try {
            const result = await memoryFind({
              query,
              scope,
              mode
            });
            const duration = Date.now() - startTime;

            searches.push({
              success: true,
              query,
              scope,
              mode,
              result,
              duration,
              hitCount: result.hits.length
            });
          } catch (error) {
            searches.push({
              success: false,
              query,
              scope,
              mode,
              error,
              duration: Date.now() - startTime
            });
          }

          // Small delay between searches
          await new Promise(resolve => setTimeout(resolve, 5));
        }

        return { searcherIndex, searches };
      });

      const overallStartTime = Date.now();
      const results = await Promise.all(searchPromises);
      const overallDuration = Date.now() - overallStartTime;

      console.log(`Completed ${concurrentSearchers} concurrent searchers (${concurrentSearchers * searchesPerSearcher} searches) in ${overallDuration}ms`);

      // Verify search performance
      let totalSearches = 0;
      let successfulSearches = 0;
      const durations = [];

      results.forEach(({ searcherIndex, searches }) => {
        searches.forEach(search => {
          totalSearches++;
          durations.push(search.duration);

          if (search.success) {
            successfulSearches++;
            expect(search.duration).toBeLessThan(5000); // Each search should complete within 5 seconds
            expect(search.result).toBeDefined();
            expect(search.result.hits).toBeInstanceOf(Array);
          } else {
            console.warn(`Search failed for searcher ${searcherIndex}:`, search.error);
          }
        });
      });

      expect(totalSearches).toBe(concurrentSearchers * searchesPerSearcher);
      expect(successfulSearches).toBeGreaterThan(totalSearches * 0.95); // At least 95% success rate
      expect(overallDuration).toBeLessThan(20000); // Should complete within 20 seconds

      // Performance analysis
      const avgDuration = durations.reduce((sum, d) => sum + d, 0) / durations.length;
      const maxDuration = Math.max(...durations);
      console.log(`Average search duration: ${avgDuration.toFixed(2)}ms, Max: ${maxDuration}ms`);
      expect(avgDuration).toBeLessThan(1000); // Average should be under 1 second
    });

    it('should handle concurrent searches with different scopes', async () => {
      const scopeCombinations = [
        { project: 'search-project-0', branch: 'main' },
        { project: 'search-project-1', branch: 'feature-1' },
        { project: 'search-project-2', branch: 'feature-2' },
        { org: 'search-org-0' },
        { org: 'search-org-1' },
        {} // No scope
      ];

      const concurrentScopes = scopeCombinations.length;

      const scopePromises = scopeCombinations.map(async (scope, scopeIndex) => {
        const searchesInScope = 5;
        const results = [];

        for (let i = 0; i < searchesInScope; i++) {
          const query = `Search Test Item ${scopeIndex * 10 + i}`;
          const startTime = Date.now();
          const result = await memoryFind({
            query,
            scope
          });
          const duration = Date.now() - startTime;

          results.push({
            query,
            result,
            duration,
            hitCount: result.hits.length,
            scope
          });
        }

        return { scopeIndex, scope, results };
      });

      const scopeResults = await Promise.all(scopePromises);

      // Verify scope isolation works under concurrent load
      scopeResults.forEach(({ scopeIndex, scope, results }) => {
        results.forEach(({ query, result, duration, hitCount }) => {
          expect(duration).toBeLessThan(3000);
          expect(result.hits).toBeInstanceOf(Array);

          // If project is specified, results should be from that project
          if (scope.project) {
            result.hits.forEach(hit => {
              expect(hit.scope?.project).toBe(scope.project);
            });
          }

          // If org is specified, results should be from that org
          if (scope.org) {
            result.hits.forEach(hit => {
              expect(hit.scope?.org).toBe(scope.org);
            });
          }
        });
      });
    });

    it('should maintain search result consistency under load', async () => {
      const searchQuery = 'Search Test Item 100'; // Specific item
      const concurrentSearches = 20;

      // Perform same search concurrently
      const concurrentResults = await Promise.all(
        Array.from({ length: concurrentSearches }, async () => {
          const startTime = Date.now();
          const result = await memoryFind({
            query: searchQuery,
            mode: 'fast'
          });
          const duration = Date.now() - startTime;

          return { result, duration };
        })
      );

      // All results should be identical
      const firstResult = concurrentResults[0].result;
      const firstHitIds = firstResult.hits.map(hit => hit.id).sort();

      concurrentResults.forEach(({ result, duration }) => {
        expect(duration).toBeLessThan(2000);
        expect(result.hits.length).toBe(firstResult.hits.length);

        const hitIds = result.hits.map(hit => hit.id).sort();
        expect(hitIds).toEqual(firstHitIds);
      });

      // Verify metadata consistency
      concurrentResults.forEach(({ result }) => {
        expect(result.autonomous_metadata).toBeDefined();
        expect(result.autonomous_metadata.strategy_used).toBeDefined();
        expect(result.autonomous_metadata.mode_executed).toBe('fast');
      });
    });
  });

  describe('Transaction Isolation and Consistency', () => {
    it('should handle concurrent transactions without interference', async () => {
      const concurrentTransactions = 10;
      const itemsPerTransaction = 5;

      const transactionPromises = Array.from({ length: concurrentTransactions }, async (txIndex) => {
        return dbQdrantClient.transaction(async (client) => {
          const storedItems = [];

          for (let i = 0; i < itemsPerTransaction; i++) {
            const result = await client.query(`
              INSERT INTO section (title, heading, body_text, tags)
              VALUES ($1, $2, $3, $4)
              RETURNING id, title
            `, [
              `Transaction Item ${txIndex}-${i}`,
              `Transaction Heading ${txIndex}-${i}`,
              `Transaction content ${txIndex}-${i}`,
              JSON.stringify({
                concurrent_test: true,
                transaction_test: true,
                tx_index: txIndex,
                item_index: i
              })
            ]);

            storedItems.push(result.rows[0]);
          }

          // Verify within transaction
          const verifyResult = await client.query(`
            SELECT COUNT(*) as count
            FROM section
            WHERE tags->>'tx_index' = $1
          `, [txIndex]);

          expect(parseInt(verifyResult.rows[0].count)).toBe(itemsPerTransaction);

          return { txIndex, storedItems, count: storedItems.length };
        });
      });

      const results = await Promise.all(transactionPromises);

      // Verify all transactions completed successfully
      expect(results.length).toBe(concurrentTransactions);
      results.forEach(({ txIndex, storedItems, count }) => {
        expect(count).toBe(itemsPerTransaction);
        expect(storedItems.length).toBe(itemsPerTransaction);
      });

      // Verify total data in database
      const totalResult = await dbQdrantClient.query(`
        SELECT COUNT(*) as count
        FROM section
        WHERE tags->>'transaction_test' = 'true'
      `);
      expect(parseInt(totalResult.rows[0].count)).toBe(concurrentTransactions * itemsPerTransaction);
    });

    it('should handle transaction rollbacks correctly', async () => {
      const successfulTransactions = 5;
      const failingTransactions = 5;

      const successfulPromises = Array.from({ length: successfulTransactions }, async (txIndex) => {
        return dbQdrantClient.transaction(async (client) => {
          await client.query(`
            INSERT INTO section (title, heading, body_text, tags)
            VALUES ($1, $2, $3, $4)
          `, [
            `Successful TX ${txIndex}`,
            `Successful Heading ${txIndex}`,
            `Successful content ${txIndex}`,
            JSON.stringify({
              concurrent_test: true,
              rollback_test: true,
              tx_type: 'successful',
              tx_index: txIndex
            })
          ]);

          return { txIndex, status: 'success' };
        });
      });

      const failingPromises = Array.from({ length: failingTransactions }, async (txIndex) => {
        try {
          return await dbQdrantClient.transaction(async (client) => {
            await client.query(`
              INSERT INTO section (title, heading, body_text, tags)
              VALUES ($1, $2, $3, $4)
            `, [
              `Failing TX ${txIndex}`,
              `Failing Heading ${txIndex}`,
              `Failing content ${txIndex}`,
              JSON.stringify({
                concurrent_test: true,
                rollback_test: true,
                tx_type: 'failing',
                tx_index: txIndex
              })
            ]);

            // Force rollback
            throw new Error(`Intentional failure in transaction ${txIndex}`);
          });
        } catch (error) {
          return { txIndex, status: 'failed', error: error.message };
        }
      });

      const allResults = await Promise.all([
        ...successfulPromises,
        ...failingPromises
      ]);

      // Verify results
      const successResults = allResults.filter(r => r.status === 'success');
      const failResults = allResults.filter(r => r.status === 'failed');

      expect(successResults.length).toBe(successfulTransactions);
      expect(failResults.length).toBe(failingTransactions);

      // Verify only successful transactions persisted
      const successCount = await dbQdrantClient.query(`
        SELECT COUNT(*) as count
        FROM section
        WHERE tags->>'tx_type' = 'successful'
      `);
      expect(parseInt(successCount.rows[0].count)).toBe(successfulTransactions);

      const failCount = await dbQdrantClient.query(`
        SELECT COUNT(*) as count
        FROM section
        WHERE tags->>'tx_type' = 'failing'
      `);
      expect(parseInt(failCount.rows[0].count)).toBe(0); // Should be rolled back
    });

    it('should prevent deadlocks in concurrent operations', async () => {
      // Create test tables for deadlock scenario
      await testQdrantClient.query(`
        CREATE TABLE deadlock_test_a (
          id SERIAL PRIMARY KEY,
          value INTEGER
        );
      `);

      await testQdrantClient.query(`
        CREATE TABLE deadlock_test_b (
          id SERIAL PRIMARY KEY,
          value INTEGER
        );
      `);

      // Insert initial data
      await testQdrantClient.query('INSERT INTO deadlock_test_a (value) VALUES (1), (2)');
      await testQdrantClient.query('INSERT INTO deadlock_test_b (value) VALUES (10), (20)');

      const deadlockPromises = Array.from({ length: 10 }, async (index) => {
        return testQdrantClient.transaction(async (client) => {
          // Access tables in different order to potentially cause deadlock
          if (index % 2 === 0) {
            await client.query('UPDATE deadlock_test_a SET value = value + 1 WHERE id = 1');
            await new Promise(resolve => setTimeout(resolve, 10)); // Small delay
            await client.query('UPDATE deadlock_test_b SET value = value + 1 WHERE id = 1');
          } else {
            await client.query('UPDATE deadlock_test_b SET value = value + 1 WHERE id = 2');
            await new Promise(resolve => setTimeout(resolve, 10)); // Small delay
            await client.query('UPDATE deadlock_test_a SET value = value + 1 WHERE id = 2');
          }

          return { index, success: true };
        });
      });

      // All transactions should complete without deadlocks
      const results = await Promise.allSettled(deadlockPromises);

      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;

      console.log(`Deadlock test: ${successful} successful, ${failed} failed`);

      // Most should succeed (PostgreSQL has good deadlock detection)
      expect(successful).toBeGreaterThan(results.length * 0.7);

      // Clean up
      await testQdrantClient.query('DROP TABLE deadlock_test_a, deadlock_test_b');
    });
  });

  describe('Resource Contention Management', () => {
    it('should handle connection pool exhaustion gracefully', async () => {
      const maxConnections = 10;
      const concurrentOperations = 20;

      // Create limited pool
      const limitedQdrantClient = new QdrantClient({
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5433'),
        database: process.env.DB_NAME || 'cortex_prod',
        user: process.env.DB_USER || 'cortex',
        password: process.env.DB_PASSWORD || '',
        max: maxConnections,
        min: 2,
        connectionTimeoutMillis: 2000, // Short timeout
        idleTimeoutMillis: 1000
      });

      const operationPromises = Array.from({ length: concurrentOperations }, async (opIndex) => {
        const startTime = Date.now();
        try {
          const result = await limitedQdrantClient.query(`
            SELECT pg_sleep(0.1), ${opIndex} as operation_id, NOW() as start_time
          `);
          const duration = Date.now() - startTime;

          return {
            opIndex,
            success: true,
            duration,
            startTime: result.rows[0].start_time
          };
        } catch (error) {
          const duration = Date.now() - startTime;
          return {
            opIndex,
            success: false,
            duration,
            error: error.message
          };
        }
      });

      const results = await Promise.allSettled(operationPromises);

      // Analyze results
      const successful = results.filter(r => r.status === 'fulfilled' && r.value.success).length;
      const failed = results.filter(r => r.status === 'rejected' || (r.status === 'fulfilled' && !r.value.success)).length;

      console.log(`QdrantClient exhaustion test: ${successful} successful, ${failed} failed`);

      // Some operations should succeed, some might fail due to pool limits
      expect(successful + failed).toBe(concurrentOperations);
      expect(successful).toBeGreaterThan(0);

      await limitedQdrantClient.end();
    });

    it('should maintain performance under high memory load', async () => {
      const memoryIntensiveOperations = 5;
      const largeDataSize = 1000;

      const memoryPromises = Array.from({ length: memoryIntensiveOperations }, async (opIndex) => {
        // Create large memory store operations
        const largeItems = Array.from({ length: largeDataSize }, (_, i) => ({
          kind: 'section' as const,
          scope: { project: `memory-test-${opIndex}`, branch: 'main' },
          data: {
            title: `Memory Test Item ${opIndex}-${i}`,
            heading: `Memory Heading ${opIndex}-${i}`,
            body_text: 'x'.repeat(1000) // 1KB per item
          },
          tags: {
            concurrent_test: true,
            memory_test: true,
            op_index: opIndex,
            item_index: i,
            large_data: true
          }
        }));

        const startTime = Date.now();
        const result = await memoryStore(largeItems);
        const duration = Date.now() - startTime;

        return {
          opIndex,
          duration,
          storedCount: result.stored.length,
          errorCount: result.errors.length,
          memoryUsage: process.memoryUsage()
        };
      });

      const results = await Promise.all(memoryPromises);

      // Verify all operations completed
      results.forEach(({ opIndex, duration, storedCount, errorCount }) => {
        expect(storedCount).toBe(largeDataSize);
        expect(errorCount).toBe(0);
        expect(duration).toBeLessThan(30000); // Should complete within 30 seconds
        console.log(`Memory operation ${opIndex}: ${storedCount} items in ${duration}ms`);
      });

      // Verify total data stored
      const totalStored = await memoryFind({
        query: 'Memory Test Item',
        types: ['section']
      });

      expect(totalStored.hits.length).toBe(memoryIntensiveOperations * largeDataSize);
    });

    it('should handle CPU-intensive operations concurrently', async () => {
      const cpuIntensiveOperations = 8;
      const computationPerOperation = 100;

      const cpuPromises = Array.from({ length: cpuIntensiveOperations }, async (opIndex) => {
        const computations = [];

        for (let i = 0; i < computationPerOperation; i++) {
          const startTime = Date.now();

          // Perform CPU-intensive search with complex queries
          const result = await memoryFind({
            query: `search test computation ${opIndex} ${i}`,
            scope: { project: `cpu-test-${opIndex}`, branch: 'main' },
            mode: 'deep' // Use deep mode for more computation
          });

          const duration = Date.now() - startTime;
          computations.push({ index: i, duration, hitCount: result.hits.length });
        }

        return {
          opIndex,
          computations,
          totalDuration: computations.reduce((sum, c) => sum + c.duration, 0),
          avgDuration: computations.reduce((sum, c) => sum + c.duration, 0) / computations.length
        };
      });

      const results = await Promise.all(cpuPromises);

      // Verify CPU performance
      results.forEach(({ opIndex, computations, totalDuration, avgDuration }) => {
        expect(computations.length).toBe(computationPerOperation);
        expect(avgDuration).toBeLessThan(2000); // Average per computation should be reasonable
        console.log(`CPU operation ${opIndex}: avg ${avgDuration.toFixed(2)}ms per computation`);
      });

      // Overall performance should be reasonable
      const overallAvgDuration = results.reduce((sum, r) => sum + r.avgDuration, 0) / results.length;
      expect(overallAvgDuration).toBeLessThan(1500);
    });
  });

  describe('Race Condition Handling', () => {
    it('should handle concurrent create-or-update operations', async () => {
      const entityName = 'Race Condition Test Entity';
      const concurrentOperations = 15;

      const racePromises = Array.from({ length: concurrentOperations }, async (opIndex) => {
        // Try to create/update same entity concurrently
        const result = await memoryStore([{
          kind: 'entity',
          scope: { project: 'race-condition-test', branch: 'main' },
          data: {
            entity_type: 'race_test_entity',
            name: entityName,
            data: {
              version: opIndex,
              timestamp: Date.now(),
              operator: `operator-${opIndex}`,
              random: Math.random()
            }
          },
          tags: {
            concurrent_test: true,
            race_test: true,
            op_index: opIndex
          }
        }]);

        return { opIndex, result };
      });

      const results = await Promise.all(racePromises);

      // Verify all operations completed
      results.forEach(({ opIndex, result }) => {
        expect(result.stored.length).toBe(1);
        expect(result.errors.length).toBe(0);
      });

      // Should end up with one entity (due to deduplication/update logic)
      const finalEntity = await memoryFind({
        query: entityName,
        scope: { project: 'race-condition-test', branch: 'main' },
        types: ['entity']
      });

      expect(finalEntity.hits.length).toBe(1);

      // The final entity should have data from the last operation
      const entity = finalEntity.hits[0];
      expect(entity.title || entity.name).toBe(entityName);
    });

    it('should handle concurrent count operations accurately', async () => {
      // Create test data
      const itemCount = 100;
      const countingOperations = 20;

      await memoryStore(
        Array.from({ length: itemCount }, (_, i) => ({
          kind: 'section' as const,
          scope: { project: 'count-test', branch: 'main' },
          data: {
            title: `Count Test Item ${i}`,
            heading: `Count Heading ${i}`,
            body_text: `Content for count test ${i}`
          },
          tags: {
            concurrent_test: true,
            count_test: true,
            item_index: i
          }
        }))
      );

      // Perform concurrent count operations
      const countPromises = Array.from({ length: countingOperations }, async (opIndex) => {
        const result = await memoryFind({
          query: 'Count Test Item',
          scope: { project: 'count-test', branch: 'main' }
        });

        return {
          opIndex,
          count: result.hits.length,
          autonomousMetadata: result.autonomous_metadata
        };
      });

      const countResults = await Promise.all(countPromises);

      // All counts should be consistent
      countResults.forEach(({ opIndex, count }) => {
        expect(count).toBe(itemCount);
      });

      // Verify metadata consistency
      const firstMetadata = countResults[0].autonomousMetadata;
      countResults.forEach(({ autonomousMetadata }) => {
        expect(autonomousMetadata.total_results).toBe(firstMetadata.total_results);
      });
    });

    it('should handle concurrent deletion operations safely', async () => {
      const itemsToDelete = 50;
      const deleteOperations = 10;

      // Create test data
      const createResult = await memoryStore(
        Array.from({ length: itemsToDelete }, (_, i) => ({
          kind: 'section' as const,
          scope: { project: 'delete-test', branch: 'main' },
          data: {
            title: `Delete Test Item ${i}`,
            heading: `Delete Heading ${i}`,
            body_text: `Content for delete test ${i}`
          },
          tags: {
            concurrent_test: true,
            delete_test: true,
            item_index: i
          }
        }))
      );

      const createdIds = createResult.stored.map(item => item.id);
      expect(createdIds.length).toBe(itemsToDelete);

      // Perform concurrent deletions
      const deletePromises = Array.from({ length: deleteOperations }, async (opIndex) => {
        const itemsToDeleteInBatch = Math.ceil(createdIds.length / deleteOperations);
        const startIndex = opIndex * itemsToDeleteInBatch;
        const endIndex = Math.min(startIndex + itemsToDeleteInBatch, createdIds.length);
        const batchIds = createdIds.slice(startIndex, endIndex);

        const results = [];
        for (const id of batchIds) {
          const result = await memoryStore([{
            kind: 'section',
            scope: { project: 'delete-test', branch: 'main' },
            data: { id },
            tags: { concurrent_test: true, delete_test: true },
            operation: 'delete' as const
          }]);
          results.push(result);
        }

        return { opIndex, deletedCount: results.filter(r => r.stored[0]?.status === 'deleted').length };
      });

      const deleteResults = await Promise.all(deletePromises);

      // Verify deletions
      const totalDeleted = deleteResults.reduce((sum, r) => sum + r.deletedCount, 0);
      expect(totalDeleted).toBe(itemsToDelete);

      // Verify items are gone
      const finalCheck = await memoryFind({
        query: 'Delete Test Item',
        scope: { project: 'delete-test', branch: 'main' }
      });

      expect(finalCheck.hits.length).toBe(0);
    });
  });
});