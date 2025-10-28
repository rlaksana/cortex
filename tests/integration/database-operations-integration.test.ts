/**
 * Database Operations Integration Tests
 *
 * Tests comprehensive database operations including:
 * - Connection management and health checks
 * - Vector operations and semantic search
 * - CRUD operations across all knowledge types
 * - Performance under load
 * - Error handling and recovery
 * - Data consistency and constraints
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { QdrantAdapter } from '../../src/db/adapters/qdrant-adapter.ts';
import { memoryStore } from '../../src/services/memory-store.ts';
import { memoryFind } from '../../src/services/memory-find.ts';
import { logger } from '../../src/utils/logger.ts';
import type { KnowledgeItem, VectorConfig } from '../../src/types/core-interfaces';

describe('Database Operations Integration Tests', () => {
  let qdrantAdapter: QdrantAdapter;
  let testConfig: VectorConfig;

  beforeAll(async () => {
    // Initialize test configuration
    testConfig = {
      url: process.env.TEST_QDRANT_URL || process.env.QDRANT_URL || 'http://localhost:6333',
      apiKey: process.env.QDRANT_API_KEY,
      vectorSize: 1536,
      distance: 'Cosine',
      collectionName: 'test-knowledge-items',
      logQueries: false,
      connectionTimeout: 30000,
      maxConnections: 10,
    };

    // Initialize Qdrant adapter
    qdrantAdapter = new QdrantAdapter(testConfig);
    await qdrantAdapter.initialize();

    // Clean up any existing test data
    await qdrantAdapter.bulkDelete({
      scope: { project: 'integration-test' }
    });
  });

  afterAll(async () => {
    // Cleanup test data
    try {
      await qdrantAdapter.bulkDelete({
        scope: { project: 'integration-test' }
      });
    } catch (error) {
      logger.warn({ error }, 'Failed to cleanup test data');
    }

    // Close connection
    await qdrantAdapter.close();
  });

  describe('Connection Management', () => {
    it('should maintain healthy connection', async () => {
      const isHealthy = await qdrantAdapter.healthCheck();
      expect(isHealthy).toBe(true);
    });

    it('should provide database metrics', async () => {
      const metrics = await qdrantAdapter.getMetrics();
      expect(metrics.type).toBe('qdrant');
      expect(metrics.healthy).toBe(true);
      expect(metrics.vectorCount).toBeGreaterThanOrEqual(0);
      expect(metrics.lastHealthCheck).toBeDefined();
    });

    it('should handle connection recovery', async () => {
      // Test connection resilience
      const initialHealth = await qdrantAdapter.healthCheck();
      expect(initialHealth).toBe(true);

      // Simulate connection stress with rapid operations
      const operations = Array.from({ length: 10 }, () =>
        qdrantAdapter.healthCheck()
      );

      const results = await Promise.allSettled(operations);
      const successful = results.filter(r => r.status === 'fulfilled').length;
      expect(successful).toBeGreaterThan(8); // At least 80% success rate
    });
  });

  describe('Vector Operations', () => {
    it('should generate embeddings for content', async () => {
      const content = 'Test content for embedding generation';
      const embedding = await qdrantAdapter.generateEmbedding(content);

      expect(Array.isArray(embedding)).toBe(true);
      expect(embedding.length).toBe(1536); // OpenAI ada-002 dimension
      expect(embedding.every(val => typeof val === 'number' && !isNaN(val))).toBe(true);
    });

    it('should handle semantic search', async () => {
      // First store some test data
      const testItems: KnowledgeItem[] = [
        {
          kind: 'section',
          scope: { project: 'integration-test', branch: 'main' },
          data: {
            title: 'Machine Learning Basics',
            heading: 'Introduction to ML',
            body_text: 'Machine learning is a subset of artificial intelligence that focuses on algorithms.',
          }
        },
        {
          kind: 'section',
          scope: { project: 'integration-test', branch: 'main' },
          data: {
            title: 'Deep Learning Networks',
            heading: 'Neural Network Fundamentals',
            body_text: 'Deep learning uses neural networks with multiple layers to learn complex patterns.',
          }
        },
        {
          kind: 'entity',
          scope: { project: 'integration-test', branch: 'main' },
          data: {
            entity_type: 'concept',
            name: 'Data Science',
            data: { field: 'analytics', description: 'Extracting insights from data' }
          }
        }
      ];

      await qdrantAdapter.store(testItems);

      // Perform semantic search
      const searchResults = await qdrantAdapter.semanticSearch('artificial intelligence algorithms', {
        limit: 10,
        score_threshold: 0.5
      });

      expect(searchResults.length).toBeGreaterThan(0);
      expect(searchResults[0].confidence_score).toBeGreaterThan(0.5);
      expect(searchResults[0].kind).toBeDefined();
      expect(searchResults[0].data).toBeDefined();
    });

    it('should handle hybrid search', async () => {
      const searchResults = await qdrantAdapter.hybridSearch('machine learning', {
        limit: 5
      });

      expect(Array.isArray(searchResults)).toBe(true);
      searchResults.forEach(result => {
        expect(result.confidence_score).toBeGreaterThan(0);
        expect(result.kind).toBeDefined();
      });
    });

    it('should find similar items', async () => {
      const testItem: KnowledgeItem = {
        kind: 'entity',
        scope: { project: 'integration-test', branch: 'main' },
        data: {
          entity_type: 'concept',
          name: 'Test Concept',
          data: { category: 'test', description: 'A test concept for similarity' }
        }
      };

      // Store the item first
      await qdrantAdapter.store([testItem]);

      // Find similar items
      const similarItems = await qdrantAdapter.findSimilar(testItem, 0.5);

      expect(Array.isArray(similarItems)).toBe(true);
      similarItems.forEach(item => {
        expect(item.confidence_score).toBeGreaterThan(0.5);
        expect(item.kind).toBeDefined();
      });
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
      const items = testKinds.map((kind, index) => ({
        kind,
        scope: { project: 'integration-test', branch: 'main' },
        data: {
          title: `Test ${kind} ${index}`,
          heading: kind === 'section' ? `Test heading for ${kind}` : undefined,
          body_text: kind === 'section' ? `Test content for ${kind}` : undefined,
          component: ['decision', 'issue'].includes(kind) ? 'test-component' : undefined,
          service: kind === 'runbook' ? 'test-service' : undefined,
          entity_type: kind === 'entity' ? 'test_entity' : undefined,
          name: ['entity', 'relation'].includes(kind) ? `test_${kind}_${index}` : undefined,
        },
      }));

      const result = await qdrantAdapter.store(items);

      expect(result.stored).toHaveLength(testKinds.length);
      expect(result.errors).toHaveLength(0);

      // Verify each item was stored correctly
      result.stored.forEach((stored, index) => {
        expect(stored.status).toBe('inserted');
        expect(stored.id).toBeDefined();
        expect(stored.kind).toBe(testKinds[index]);
        expect(stored.created_at).toBeDefined();
      });
    });

    it('should update existing knowledge items', async () => {
      // Create initial item
      const initialItem: KnowledgeItem = {
        kind: 'section',
        scope: { project: 'integration-test', branch: 'main' },
        data: {
          title: 'Original Title',
          heading: 'Original Heading',
          body_text: 'Original content',
        }
      };

      const initialResult = await qdrantAdapter.store([initialItem]);
      const storedItem = initialResult.stored[0];
      expect(storedItem.status).toBe('inserted');

      // Update the item
      const updatedItem: KnowledgeItem = {
        ...initialItem,
        id: storedItem.id,
        data: {
          title: 'Updated Title',
          heading: 'Updated Heading',
          body_text: 'Updated content with new information',
        }
      };

      const updateResult = await qdrantAdapter.update([updatedItem]);
      expect(updateResult.stored[0].status).toBe('inserted'); // Updated via upsert logic

      // Verify the update persisted by finding the item
      const findResults = await qdrantAdapter.findById([storedItem.id]);
      expect(findResults).toHaveLength(1);
      expect(findResults[0].data.title).toBe('Updated Title');
    });

    it('should delete knowledge items correctly', async () => {
      // Create item to delete
      const itemToDelete: KnowledgeItem = {
        kind: 'decision',
        scope: { project: 'integration-test', branch: 'main' },
        data: {
          title: 'To Be Deleted',
          status: 'proposed',
          component: 'test-component',
          rationale: 'This will be deleted',
        }
      };

      const createResult = await qdrantAdapter.store([itemToDelete]);
      const itemId = createResult.stored[0].id;
      expect(createResult.stored[0].status).toBe('inserted');

      // Delete the item
      const deleteResult = await qdrantAdapter.delete([itemId]);
      expect(deleteResult.deleted).toBe(1);
      expect(deleteResult.errors).toHaveLength(0);

      // Verify deletion
      const findResults = await qdrantAdapter.findById([itemId]);
      expect(findResults).toHaveLength(0);
    });

    it('should handle batch operations efficiently', async () => {
      const batchSize = 50;
      const batchItems = Array.from({ length: batchSize }, (_, i) => ({
        kind: 'entity' as const,
        scope: { project: 'integration-test', branch: 'main' },
        data: {
          entity_type: 'batch_test_entity',
          name: `Batch Test Entity ${i}`,
          data: { batch_index: i, content: `Batch content ${i}` },
        },
      }));

      const startTime = Date.now();
      const result = await qdrantAdapter.bulkStore(batchItems);
      const duration = Date.now() - startTime;

      expect(result.stored).toHaveLength(batchSize);
      expect(result.errors).toHaveLength(0);
      expect(duration).toBeLessThan(10000); // Should complete within 10 seconds

      // Verify all items were stored
      const stats = await qdrantAdapter.getStatistics({ project: 'integration-test' });
      expect(stats.totalItems).toBeGreaterThan(batchSize);
    });
  });

  describe('Scope Isolation', () => {
    it('should isolate data by project scope', async () => {
      const projectAItems = [
        {
          kind: 'entity' as const,
          scope: { project: 'project-a', branch: 'main' },
          data: { entity_type: 'test', name: 'Project A Item 1' }
        },
        {
          kind: 'entity' as const,
          scope: { project: 'project-a', branch: 'main' },
          data: { entity_type: 'test', name: 'Project A Item 2' }
        }
      ];

      const projectBItems = [
        {
          kind: 'entity' as const,
          scope: { project: 'project-b', branch: 'main' },
          data: { entity_type: 'test', name: 'Project B Item 1' }
        }
      ];

      // Store items in different projects
      await qdrantAdapter.store(projectAItems);
      await qdrantAdapter.store(projectBItems);

      // Find items by scope
      const projectAResults = await qdrantAdapter.findByScope({ project: 'project-a' });
      const projectBResults = await qdrantAdapter.findByScope({ project: 'project-b' });

      expect(projectAResults).toHaveLength(2);
      expect(projectBResults).toHaveLength(1);

      // Verify no cross-contamination
      const projectANames = projectAResults.map(r => r.data.name);
      const projectBNames = projectBResults.map(r => r.data.name);

      expect(projectANames).toContain('Project A Item 1');
      expect(projectANames).toContain('Project A Item 2');
      expect(projectBNames).toContain('Project B Item 1');
      expect(projectANames).not.toContain('Project B Item 1');
      expect(projectBNames).not.toContain('Project A Item 1');
    });

    it('should isolate data by branch scope', async () => {
      const mainBranchItem = {
        kind: 'section' as const,
        scope: { project: 'branch-test', branch: 'main' },
        data: { title: 'Main Branch Section', body_text: 'Content for main branch' }
      };

      const featureBranchItem = {
        kind: 'section' as const,
        scope: { project: 'branch-test', branch: 'feature-branch' },
        data: { title: 'Feature Branch Section', body_text: 'Content for feature branch' }
      };

      // Store items in different branches
      await qdrantAdapter.store([mainBranchItem, featureBranchItem]);

      // Find items by branch
      const mainResults = await qdrantAdapter.findByScope({ project: 'branch-test', branch: 'main' });
      const featureResults = await qdrantAdapter.findByScope({ project: 'branch-test', branch: 'feature-branch' });

      expect(mainResults).toHaveLength(1);
      expect(featureResults).toHaveLength(1);
      expect(mainResults[0].data.title).toBe('Main Branch Section');
      expect(featureResults[0].data.title).toBe('Feature Branch Section');
    });
  });

  describe('Deduplication', () => {
    it('should detect duplicate content', async () => {
      const duplicateContent = 'This is duplicate content that should be detected';

      const item1 = {
        kind: 'section' as const,
        scope: { project: 'dedupe-test', branch: 'main' },
        data: { title: 'Item 1', body_text: duplicateContent }
      };

      const item2 = {
        kind: 'section' as const,
        scope: { project: 'dedupe-test', branch: 'main' },
        data: { title: 'Item 2', body_text: duplicateContent }
      };

      // Check for duplicates before storing
      const duplicateCheck = await qdrantAdapter.checkDuplicates([item1, item2]);
      expect(duplicateCheck.duplicates).toHaveLength(0); // No duplicates yet
      expect(duplicateCheck.originals).toHaveLength(2);

      // Store first item
      await qdrantAdapter.store([item1]);

      // Check again - second item should now be detected as duplicate
      const duplicateCheck2 = await qdrantAdapter.checkDuplicates([item2]);
      expect(duplicateCheck2.duplicates).toHaveLength(1);
      expect(duplicateCheck2.originals).toHaveLength(1);
    });

    it('should handle duplicate detection with skipDuplicates option', async () => {
      const content = 'Content for skip duplicate test';

      const items = Array.from({ length: 3 }, (_, i) => ({
        kind: 'entity' as const,
        scope: { project: 'skip-dedupe-test', branch: 'main' },
        data: { entity_type: 'test', name: `Item ${i}`, content }
      }));

      // Store items with duplicate detection enabled
      const result1 = await qdrantAdapter.store([items[0]], { skipDuplicates: true });
      expect(result1.stored).toHaveLength(1);
      expect(result1.stored[0].status).toBe('inserted');

      // Try to store duplicate - should be skipped
      const result2 = await qdrantAdapter.store([items[1]], { skipDuplicates: true });
      expect(result2.stored).toHaveLength(1);
      expect(result2.stored[0].status).toBe('skipped_dedupe');

      // Store different content - should be inserted
      const differentItem = {
        ...items[2],
        data: { ...items[2].data, content: 'Different content' }
      };
      const result3 = await qdrantAdapter.store([differentItem], { skipDuplicates: true });
      expect(result3.stored).toHaveLength(1);
      expect(result3.stored[0].status).toBe('inserted');
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large text content efficiently', async () => {
      const largeContent = 'x'.repeat(50000); // 50KB of text

      const startTime = Date.now();
      const result = await qdrantAdapter.store([{
        kind: 'section',
        scope: { project: 'performance-test', branch: 'main' },
        data: {
          title: 'Large Content Test',
          heading: 'Performance Test',
          body_text: largeContent,
        }
      }]);
      const duration = Date.now() - startTime;

      expect(result.stored[0].status).toBe('inserted');
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds

      // Verify retrieval performance
      const findStartTime = Date.now();
      const searchResults = await qdrantAdapter.search({
        query: 'Large Content Test',
        scope: { project: 'performance-test', branch: 'main' }
      });
      const findDuration = Date.now() - findStartTime;

      expect(searchResults.results.length).toBe(1);
      expect(findDuration).toBeLessThan(2000); // Should find within 2 seconds
    });

    it('should maintain performance under concurrent load', async () => {
      const concurrentOperations = 10;
      const operationsPerThread = 5;

      const promises = Array.from({ length: concurrentOperations }, async (_, threadIndex) => {
        const results = [];
        for (let i = 0; i < operationsPerThread; i++) {
          const storeResult = await qdrantAdapter.store([{
            kind: 'entity',
            scope: { project: 'concurrent-test', branch: `thread-${threadIndex}` },
            data: {
              entity_type: 'concurrent_entity',
              name: `Concurrent Entity ${threadIndex}-${i}`,
              data: { thread: threadIndex, index: i },
            }
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
      expect(duration).toBeLessThan(15000); // Should complete within 15 seconds

      // Verify all data was stored correctly
      const stats = await qdrantAdapter.getStatistics();
      expect(stats.totalItems).toBeGreaterThan(totalOperations);
    });
  });

  describe('Error Handling and Recovery', () => {
    it('should handle invalid item structures gracefully', async () => {
      const invalidItems = [
        {
          kind: 'section' as const,
          scope: { project: 'error-test', branch: 'main' },
          data: { heading: 'Missing title' }, // Missing required content
        },
        {
          kind: 'invalid_kind' as any, // Invalid kind
          scope: { project: 'error-test', branch: 'main' },
          data: { title: 'Invalid kind test' }
        }
      ];

      const result = await qdrantAdapter.store(invalidItems);

      // Should handle errors gracefully
      expect(result.stored.length).toBeLessThan(invalidItems.length);
      expect(result.errors.length).toBeGreaterThan(0);

      result.errors.forEach(error => {
        expect(error.error_code).toBeDefined();
        expect(error.message).toBeDefined();
        expect(error.index).toBeGreaterThanOrEqual(0);
      });
    });

    it('should handle search with invalid queries gracefully', async () => {
      // Search with empty query
      const emptyResult = await qdrantAdapter.search({
        query: '',
        scope: { project: 'error-test', branch: 'main' }
      });

      expect(Array.isArray(emptyResult.results)).toBe(true);
      expect(emptyResult.total_count).toBe(0);

      // Search with non-existent scope
      const noResults = await qdrantAdapter.search({
        query: 'test',
        scope: { project: 'non-existent-project', branch: 'main' }
      });

      expect(noResults.results).toHaveLength(0);
      expect(noResults.total_count).toBe(0);
    });

    it('should maintain data consistency during failures', async () => {
      // Store some initial data
      const validItems = [
        {
          kind: 'entity' as const,
          scope: { project: 'consistency-test', branch: 'main' },
          data: { entity_type: 'test', name: 'Valid Item 1' }
        },
        {
          kind: 'entity' as const,
          scope: { project: 'consistency-test', branch: 'main' },
          data: { entity_type: 'test', name: 'Valid Item 2' }
        }
      ];

      const validResult = await qdrantAdapter.store(validItems);
      expect(validResult.stored).toHaveLength(2);

      // Try to store mixed valid/invalid items
      const mixedItems = [
        {
          kind: 'entity' as const,
          scope: { project: 'consistency-test', branch: 'main' },
          data: { entity_type: 'test', name: 'Another Valid Item' }
        },
        {
          kind: 'invalid_kind' as any,
          scope: { project: 'consistency-test', branch: 'main' },
          data: { title: 'Invalid Item' }
        }
      ];

      const mixedResult = await qdrantAdapter.store(mixedItems);
      expect(mixedResult.stored).toHaveLength(1); // Only valid item stored
      expect(mixedResult.errors).toHaveLength(1); // Invalid item failed

      // Verify that valid data was not affected
      const finalStats = await qdrantAdapter.getStatistics({ project: 'consistency-test' });
      expect(finalStats.totalItems).toBe(3); // 2 original + 1 new valid
    });
  });

  describe('Collection Management', () => {
    it('should provide collection statistics', async () => {
      const stats = await qdrantAdapter.getStatistics();

      expect(stats.totalItems).toBeGreaterThanOrEqual(0);
      expect(stats.itemsByKind).toBeDefined();
      expect(stats.storageSize).toBeGreaterThanOrEqual(0);
      expect(stats.lastUpdated).toBeDefined();
      expect(stats.vectorCount).toBeGreaterThanOrEqual(0);
    });

    it('should validate collection health', async () => {
      const validation = await qdrantAdapter.validate();

      expect(validation.valid).toBe(true);
      expect(validation.issues).toHaveLength(0);
    });
  });
});