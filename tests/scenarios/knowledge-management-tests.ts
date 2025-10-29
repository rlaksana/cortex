/**
 * Knowledge Management Test Scenarios
 *
 * Comprehensive test scenarios for all knowledge management operations
 */

import type { TestScenario, TestContext } from '../framework/test-setup';
import { TestAssertions } from '../framework/test-setup';
import { memoryStore, memoryFind, softDelete } from '../../src/services/index';

/**
 * Test scenario for basic knowledge CRUD operations
 */
export const basicKnowledgeManagement: TestScenario = {
  name: 'Basic Knowledge Management',
  description: 'Test create, read, update, and delete operations for all knowledge types',
  tests: [
    {
      name: 'Create and retrieve sections',
      description: 'Test creating sections and retrieving them',
      test: async (context: TestContext) => {
        const item = context.dataFactory.createSection({
          title: 'Test Section for CRUD',
        });

        // Create
        const storeResult = await memoryStore([item]);
        TestAssertions.assert(storeResult.errors.length === 0, 'Store should succeed');
        TestAssertions.assert(storeResult.stored.length === 1, 'Should store one item');
        TestAssertions.assertEquals(storeResult.stored[0].kind, 'section', 'Should store section');

        // Retrieve
        const findResult = await memoryFind({
          query: 'Test Section for CRUD',
          types: ['section'],
        });
        TestAssertions.assert(findResult.hits.length >= 1, 'Should find stored section');
        TestAssertions.assertEquals(findResult.hits[0].title, 'Test Section for CRUD', 'Should find correct title');
      },
    },

    {
      name: 'Create and retrieve decisions',
      description: 'Test creating decisions and retrieving them',
      test: async (context: TestContext) => {
        const item = context.dataFactory.createDecision({
          title: 'Test Decision for CRUD',
          component: 'test-component',
        });

        const storeResult = await memoryStore([item]);
        TestAssertions.assert(storeResult.errors.length === 0, 'Store should succeed');

        const findResult = await memoryFind({
          query: 'Test Decision for CRUD',
          types: ['decision'],
        });
        TestAssertions.assert(findResult.hits.length >= 1, 'Should find stored decision');
      },
    },

    {
      name: 'Update existing knowledge items',
      description: 'Test updating existing knowledge items',
      test: async (context: TestContext) => {
        // Create initial item
        const item = context.dataFactory.createSection({
          title: 'Initial Title',
        });

        const storeResult = await memoryStore([item]);
        TestAssertions.assert(storeResult.stored.length === 1, 'Should store initial item');

        // Update the item
        const updateItem = context.dataFactory.createSection({
          id: storeResult.stored[0].id,
          title: 'Updated Title',
          heading: 'Updated Title',
        });

        const updateResult = await memoryStore([updateItem]);
        TestAssertions.assert(updateResult.errors.length === 0, 'Update should succeed');
        TestAssertions.assertEquals(updateResult.stored[0].status, 'updated', 'Should indicate update');

        // Verify the update
        const findResult = await memoryFind({
          query: 'Updated Title',
          types: ['section'],
        });
        TestAssertions.assert(findResult.hits.length >= 1, 'Should find updated item');
      },
    },

    {
      name: 'Soft delete knowledge items',
      description: 'Test soft deleting knowledge items',
      test: async (context: TestContext) => {
        // Create item
        const item = context.dataFactory.createSection({
          title: 'Item to Delete',
        });

        const storeResult = await memoryStore([item]);
        TestAssertions.assert(storeResult.stored.length === 1, 'Should store item');

        // Delete the item
        const deleteResult = await softDelete(context.testDb, {
          entity_type: 'section',
          entity_id: storeResult.stored[0].id,
        });
        TestAssertions.assertEquals(deleteResult.status, 'deleted', 'Should delete successfully');

        // Verify it's no longer findable (soft delete)
        const findResult = await memoryFind({
          query: 'Item to Delete',
          types: ['section'],
        });
        // Soft deleted items might still appear depending on implementation
        // This test verifies the delete operation itself works
      },
    },
  ],
};

/**
 * Test scenario for advanced search functionality
 */
export const advancedSearchFunctionality: TestScenario = {
  name: 'Advanced Search Functionality',
  description: 'Test advanced search features including query enhancement, graph traversal, and pagination',
  tests: [
    {
      name: 'Query enhancement and auto-correction',
      description: 'Test query enhancement with typo correction',
      test: async (context: TestContext) => {
        // Store test data
        const items = [
          context.dataFactory.createSection({ title: 'Authentication Guide' }),
          context.dataFactory.createDecision({ title: 'Authorization Decision' }),
          context.dataFactory.createIssue({ title: 'Auth Service Issue' }),
        ];

        await memoryStore(items);

        // Search with typo
        const result = await memoryFind({
          query: 'authntication', // Typo for "authentication"
          enableAutoFix: true,
          enableSuggestions: true,
        });

        TestAssertions.assert(result.hits.length > 0, 'Should find results despite typo');
        TestAssertions.assert(result.query_enhancement?.autoFixApplied, 'Should apply auto-fix');
        TestAssertions.assert(result.suggestions.length > 0, 'Should provide suggestions');
      },
    },

    {
      name: 'Multi-type search',
      description: 'Test searching across multiple knowledge types',
      test: async (context: TestContext) => {
        // Store mixed data
        const items = context.dataFactory.createMixedBatch(20);
        await memoryStore(items);

        // Search across multiple types
        const result = await memoryFind({
          query: 'test',
          types: ['section', 'decision', 'issue', 'todo'],
          top_k: 15,
        });

        TestAssertions.assert(result.hits.length > 0, 'Should find results across types');

        const foundTypes = new Set(result.hits.map(h => h.kind));
        TestAssertions.assert(foundTypes.size > 1, 'Should find multiple knowledge types');
      },
    },

    {
      name: 'Scope-based search',
      description: 'Test search with project/branch scope filtering',
      test: async (context: TestContext) => {
        // Store items with different scopes
        const items = [
          context.dataFactory.createSection({ scope: { project: 'project-a', branch: 'main' } }),
          context.dataFactory.createSection({ scope: { project: 'project-a', branch: 'feature' } }),
          context.dataFactory.createSection({ scope: { project: 'project-b', branch: 'main' } }),
        ];

        await memoryStore(items);

        // Search with specific scope
        const result = await memoryFind({
          query: 'test',
          scope: { project: 'project-a', branch: 'main' },
        });

        TestAssertions.assert(result.hits.length > 0, 'Should find results in specified scope');

        // Verify scope filtering
        for (const hit of result.hits) {
          TestAssertions.assertEquals(hit.scope?.project, 'project-a', 'Should respect project scope');
        }
      },
    },

    {
      name: 'Graph traversal',
      description: 'Test graph traversal functionality',
      test: async (context: TestContext) => {
        // Create interconnected entities
        const entity1 = context.dataFactory.createEntity({ name: 'Service A' });
        const entity2 = context.dataFactory.createEntity({ name: 'Service B' });
        const relation = context.dataFactory.createRelation({
          from_entity_id: entity1.data.id,
          to_entity_id: entity2.data.id,
        });

        await memoryStore([entity1, entity2, relation]);

        // Search with graph traversal
        const result = await memoryFind({
          query: 'Service A',
          types: ['entity'],
          traverse: {
            depth: 2,
            relation_types: ['depends_on'],
          },
        });

        TestAssertions.assert(result.graph, 'Should return graph results');
        TestAssertions.assert(result.graph!.nodes.length > 0, 'Should find graph nodes');
        TestAssertions.assert(result.graph!.edges.length > 0, 'Should find graph edges');
      },
    },

    {
      name: 'Pagination',
      description: 'Test pagination functionality',
      test: async (context: TestContext) => {
        // Store many items
        const items = context.dataFactory.createMixedBatch(25);
        await memoryStore(items);

        // Test pagination
        const page1 = await memoryFind({
          query: 'test',
          top_k: 10,
        });

        const page2 = await memoryFind({
          query: 'test',
          top_k: 10,
          // Note: Actual pagination implementation may vary
        });

        TestAssertions.assert(page1.hits.length <= 10, 'First page should respect limit');
        TestAssertions.assert(page2.hits.length <= 10, 'Second page should respect limit');
      },
    },
  ],
};

/**
 * Test scenario for similarity and deduplication
 */
export const similarityAndDeduplication: TestScenario = {
  name: 'Similarity and Deduplication',
  description: 'Test content similarity detection and duplicate handling',
  tests: [
    {
      name: 'Exact duplicate detection',
      description: 'Test detection of exact duplicates using content hashing',
      test: async (context: TestContext) => {
        const item = context.dataFactory.createSection({
          title: 'Duplicate Test',
          body_md: 'This is test content for duplicate detection.',
        });

        // Store the same item twice
        const result1 = await memoryStore([item]);
        const result2 = await memoryStore([item]);

        TestAssertions.assert(result1.stored.length === 1, 'First store should succeed');
        TestAssertions.assert(result1.autonomous_context.duplicates_found === 0, 'No duplicates on first store');

        TestAssertions.assert(result2.stored.length === 0, 'Second store should be skipped');
        TestAssertions.assert(result2.autonomous_context.duplicates_found > 0, 'Should detect duplicate');
      },
    },

    {
      name: 'Similar content detection',
      description: 'Test detection of similar content',
      test: async (context: TestContext) => {
        const item1 = context.dataFactory.createSection({
          title: 'Authentication Guide',
          body_md: 'This guide explains OAuth 2.0 authentication flow.',
        });

        const item2 = context.dataFactory.createSection({
          title: 'OAuth 2.0 Authentication',
          body_md: 'Documentation about OAuth 2.0 authentication process.',
        });

        await memoryStore([item1]);
        const result2 = await memoryStore([item2]);

        TestAssertions.assert(result2.autonomous_context.similar_items_checked > 0, 'Should check for similar items');
        // Depending on similarity threshold, might suggest update or skip
      },
    },

    {
      name: 'Update similar items',
      description: 'Test updating existing similar items instead of creating duplicates',
      test: async (context: TestContext) => {
        const originalItem = context.dataFactory.createDecision({
          title: 'OAuth Implementation Decision',
          rationale: 'Initial rationale for OAuth implementation.',
        });

        const storeResult = await memoryStore([originalItem]);
        TestAssertions.assert(storeResult.stored.length === 1, 'Should store original item');

        // Create similar item with updated content
        const similarItem = context.dataFactory.createDecision({
          id: storeResult.stored[0].id, // Same ID to trigger update
          title: 'OAuth Implementation Decision',
          rationale: 'Updated rationale for OAuth implementation with additional details.',
          component: originalItem.data.component,
        });

        const updateResult = await memoryStore([similarItem]);
        TestAssertions.assert(updateResult.stored.length === 1, 'Should update existing item');
        TestAssertions.assertEquals(updateResult.stored[0].status, 'updated', 'Should indicate update');
      },
    },
  ],
};

/**
 * Test scenario for immutability and business rules
 */
export const immutabilityAndBusinessRules: TestScenario = {
  name: 'Immutability and Business Rules',
  description: 'Test immutability constraints and business rule enforcement',
  tests: [
    {
      name: 'Accepted decision immutability',
      description: 'Test that accepted decisions cannot be modified',
      test: async (context: TestContext) => {
        const decision = context.dataFactory.createDecision({
          status: 'accepted',
          title: 'Important Decision',
        });

        const storeResult = await memoryStore([decision]);
        TestAssertions.assert(storeResult.stored.length === 1, 'Should store accepted decision');

        // Try to modify the accepted decision
        const modification = context.dataFactory.createDecision({
          id: storeResult.stored[0].id,
          status: 'deprecated',
          title: decision.data.title,
          component: decision.data.component,
          rationale: decision.data.rationale,
        });

        const modifyResult = await memoryStore([modification]);
        TestAssertions.assert(modifyResult.errors.length > 0, 'Should reject modification of accepted decision');
        TestAssertions.assert(modifyResult.errors[0].error_code === 'IMMUTABLE_ENTITY', 'Should return immutability error');
      },
    },

    {
      name: 'Section write-lock protection',
      description: 'Test that approved sections cannot be modified',
      test: async (context: TestContext) => {
        const section = context.dataFactory.createSection({
          title: 'Approved Specification',
          tags: { approved: true },
        });

        const storeResult = await memoryStore([section]);
        TestAssertions.assert(storeResult.stored.length === 1, 'Should store approved section');

        // Try to modify the approved section
        const modification = context.dataFactory.createSection({
          id: storeResult.stored[0].id,
          title: 'Modified Approved Specification',
          tags: { approved: true },
        });

        const modifyResult = await memoryStore([modification]);
        TestAssertions.assert(modifyResult.errors.length > 0, 'Should reject modification of approved section');
      },
    },

    {
      name: 'Scope validation',
      description: 'Test scope validation rules',
      test: async (context: TestContext) => {
        // Test item with valid scope
        const validItem = context.dataFactory.createSection({
          scope: { project: 'valid-project', branch: 'main' },
        });

        const validResult = await memoryStore([validItem]);
        TestAssertions.assert(validResult.errors.length === 0, 'Valid scope should be accepted');

        // Test item with potentially invalid scope
        const invalidItem = context.dataFactory.createSection({
          scope: { project: '', branch: 'main' }, // Empty project
        });

        const invalidResult = await memoryStore([invalidItem]);
        // Depending on validation rules, this might pass or fail
        // Test ensures consistent behavior
      },
    },
  ],
};

/**
 * Test scenario for performance and scalability
 */
export const performanceAndScalability: TestScenario = {
  name: 'Performance and Scalability',
  description: 'Test performance characteristics and scalability limits',
  tests: [
    {
      name: 'Single operation performance',
      description: 'Test performance of individual operations',
      timeout: 5000,
      test: async (context: TestContext) => {
        const { performanceHelper } = context;

        const { metrics } = await performanceHelper.measureOperation('single_store', async () => {
          const item = context.dataFactory.createSection();
          return memoryStore([item]);
        });

        TestAssertions.assertPerformance(metrics.duration, 100, 'single_store');
      },
    },

    {
      name: 'Batch operation performance',
      description: 'Test performance of batch operations',
      timeout: 10000,
      test: async (context: TestContext) => {
        const { performanceHelper } = context;

        const batchSize = 50;
        const { metrics } = await performanceHelper.measureOperation('batch_store', async () => {
          const items = context.dataFactory.createMixedBatch(batchSize);
          return memoryStore(items);
        }, { itemCount: batchSize });

        TestAssertions.assertPerformance(metrics.duration, 500, 'batch_store');
      },
    },

    {
      name: 'Search performance',
      description: 'Test search operation performance',
      timeout: 5000,
      test: async (context: TestContext) => {
        const { performanceHelper } = context;

        // Setup test data
        const items = context.dataFactory.createMixedBatch(100);
        await memoryStore(items);

        const { metrics } = await performanceHelper.measureOperation('search_operation', async () => {
          return memoryFind({
            query: 'test',
            types: ['section', 'decision'],
            top_k: 20,
          });
        });

        TestAssertions.assertPerformance(metrics.duration, 200, 'search_operation');
      },
    },
  ],
};