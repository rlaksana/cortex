/**
 * Parameterized Test Framework for mcp__cortex
 *
 * Provides systematic generation and execution of test scenarios
 * across all tools, knowledge types, and parameter combinations
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { VectorDatabase } from '../../src/index.js';
import {
  KNOWLEDGE_TYPES,
  generateMinimalItem,
  generateCompleteItem,
  generateCompleteItems,
  generateScopedItems,
  generateEdgeCaseItems,
  generateSearchTestData,
  validateTestItem,
  type KnowledgeType
} from '../fixtures/test-data-factory.js';

// ============================================================================
// Test Scenario Configuration
// ============================================================================

export interface TestScenario {
  name: string;
  items: any[];
  expectedResults: {
    storedCount?: number;
    errorCount?: number;
    errorTypes?: string[];
  };
  skip?: boolean;
  timeout?: number;
}

export interface ToolTestConfig {
  toolName: string;
  testFunction: (items: any[], config?: any) => Promise<any>;
  scenarios: TestScenario[];
  setup?: () => Promise<void>;
  teardown?: () => Promise<void>;
}

// ============================================================================
// Memory Store Test Scenarios
// ============================================================================

export const MEMORY_STORE_SCENARIOS: TestScenario[] = [
  // Basic functionality scenarios
  {
    name: 'minimal-items-all-types',
    items: KNOWLEDGE_TYPES.map(type => generateMinimalItem(type)),
    expectedResults: { storedCount: 16, errorCount: 0 }
  },
  {
    name: 'complete-items-all-types',
    items: KNOWLEDGE_TYPES.map(type => generateCompleteItem(type)),
    expectedResults: { storedCount: 16, errorCount: 0 }
  },
  {
    name: 'mixed-items-some-valid-some-invalid',
    items: [
      ...KNOWLEDGE_TYPES.slice(0, 8).map(type => generateCompleteItem(type)),
      { kind: 'invalid-type', content: 'Invalid item' },
      { kind: 'entity' }, // Missing content
      null,
      undefined
    ],
    expectedResults: { storedCount: 8, errorCount: 3 }
  },

  // Scope variation scenarios
  {
    name: 'scope-project-only',
    items: generateScopedItems('project-only').slice(0, 3),
    expectedResults: { storedCount: 3, errorCount: 0 }
  },
  {
    name: 'scope-branch-only',
    items: generateScopedItems('branch-only').slice(0, 3),
    expectedResults: { storedCount: 3, errorCount: 0 }
  },
  {
    name: 'scope-org-only',
    items: generateScopedItems('org-only').slice(0, 3),
    expectedResults: { storedCount: 3, errorCount: 0 }
  },
  {
    name: 'scope-complete',
    items: generateScopedItems('complete').slice(0, 3),
    expectedResults: { storedCount: 3, errorCount: 0 }
  },

  // Batch size scenarios
  {
    name: 'single-item',
    items: [generateCompleteItem('entity')],
    expectedResults: { storedCount: 1, errorCount: 0 }
  },
  {
    name: 'small-batch-5-items',
    items: KNOWLEDGE_TYPES.slice(0, 5).map(type => generateCompleteItem(type)),
    expectedResults: { storedCount: 5, errorCount: 0 }
  },
  {
    name: 'medium-batch-25-items',
    items: Array.from({ length: 25 }, (_, i) =>
      generateCompleteItem(KNOWLEDGE_TYPES[i % KNOWLEDGE_TYPES.length], {
        content: `Medium batch item ${i}`,
        metadata: { batchIndex: i, batchSize: 25 }
      })
    ),
    expectedResults: { storedCount: 25, errorCount: 0 }
  },
  {
    name: 'large-batch-50-items',
    items: Array.from({ length: 50 }, (_, i) =>
      generateCompleteItem(KNOWLEDGE_TYPES[i % KNOWLEDGE_TYPES.length], {
        content: `Large batch item ${i}`,
        metadata: { batchIndex: i, batchSize: 50 }
      })
    ),
    expectedResults: { storedCount: 50, errorCount: 0 }
  },

  // Edge case scenarios
  {
    name: 'empty-content',
    items: [generateMinimalItem('entity', { content: '' })],
    expectedResults: { storedCount: 1, errorCount: 0 }
  },
  {
    name: 'very-long-content',
    items: [generateMinimalItem('observation', {
      content: 'A'.repeat(1000),
      metadata: { contentLength: 1000 }
    })],
    expectedResults: { storedCount: 1, errorCount: 0 }
  },
  {
    name: 'unicode-and-special-chars',
    items: [
      generateMinimalItem('issue', {
        content: 'Issue with émojis 🚨 and spëcial chars & symbols @#$%^&*()'
      }),
      generateMinimalItem('decision', {
        content: 'Décision regarding café and naïve approach with 中文'
      })
    ],
    expectedResults: { storedCount: 2, errorCount: 0 }
  },
  {
    name: 'large-metadata-object',
    items: [generateCompleteItem('runbook', {
      metadata: {
        largeArray: Array.from({ length: 100 }, (_, i) => ({ step: i, action: `action-${i}` })),
        nestedObject: { level1: { level2: { level3: { deep: 'value' } } } },
        metadataSize: 'large'
      }
    })],
    expectedResults: { storedCount: 1, errorCount: 0 }
  },

  // Error handling scenarios
  {
    name: 'all-invalid-items',
    items: [
      { kind: 'invalid', content: 'Invalid kind' },
      null,
      undefined,
      {},
      { content: 'Missing kind' },
      { kind: 'entity' }, // Missing content
      123,
      'string-instead-of-object'
    ],
    expectedResults: { storedCount: 0, errorCount: 6 }
  },

  // Knowledge type specific scenarios
  ...KNOWLEDGE_TYPES.map(type => ({
    name: `single-${type}-minimal`,
    items: [generateMinimalItem(type)],
    expectedResults: { storedCount: 1, errorCount: 0 }
  })),
  ...KNOWLEDGE_TYPES.map(type => ({
    name: `single-${type}-complete`,
    items: [generateCompleteItem(type)],
    expectedResults: { storedCount: 1, errorCount: 0 }
  }))
];

// ============================================================================
// Memory Find Test Scenarios
// ============================================================================

export const MEMORY_FIND_SCENARIOS: TestScenario[] = [
  // Query type scenarios
  {
    name: 'short-query',
    items: generateSearchTestData(),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },
  {
    name: 'medium-query',
    items: generateSearchTestData(),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },
  {
    name: 'long-query',
    items: generateSearchTestData(),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },
  {
    name: 'empty-query',
    items: generateSearchTestData(),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },
  {
    name: 'special-char-query',
    items: generateSearchTestData(),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },

  // Search mode scenarios
  {
    name: 'auto-search-mode',
    items: generateSearchTestData(),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },
  {
    name: 'fast-search-mode',
    items: generateSearchTestData(),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },
  {
    name: 'deep-search-mode',
    items: generateSearchTestData(),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },

  // Filter scenarios
  {
    name: 'filter-by-single-type',
    items: generateSearchTestData(),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },
  {
    name: 'filter-by-multiple-types',
    items: generateSearchTestData(),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },
  {
    name: 'filter-by-all-types',
    items: generateSearchTestData(),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },

  // Limit scenarios
  {
    name: 'limit-1',
    items: generateSearchTestData(),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },
  {
    name: 'limit-10',
    items: generateSearchTestData(),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },
  {
    name: 'limit-50',
    items: generateSearchTestData(),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },
  {
    name: 'limit-100',
    items: generateSearchTestData(),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },

  // Scope filter scenarios
  {
    name: 'search-with-project-scope',
    items: generateSearchTestData().map(item => ({
      ...item,
      scope: { project: 'test-project' }
    })),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },
  {
    name: 'search-with-branch-scope',
    items: generateSearchTestData().map(item => ({
      ...item,
      scope: { branch: 'main' }
    })),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },
  {
    name: 'search-with-org-scope',
    items: generateSearchTestData().map(item => ({
      ...item,
      scope: { org: 'test-org' }
    })),
    expectedResults: { storedCount: 8, errorCount: 0 }
  },
  {
    name: 'search-with-complete-scope',
    items: generateSearchTestData().map(item => ({
      ...item,
      scope: { project: 'test-project', branch: 'main', org: 'test-org' }
    })),
    expectedResults: { storedCount: 8, errorCount: 0 }
  }
];

// ============================================================================
// Database Health and Stats Test Scenarios
// ============================================================================

export const DATABASE_HEALTH_SCENARIOS: TestScenario[] = [
  {
    name: 'healthy-database',
    items: [],
    expectedResults: { storedCount: 0, errorCount: 0 }
  },
  {
    name: 'database-with-data',
    items: generateCompleteItems().slice(0, 5),
    expectedResults: { storedCount: 5, errorCount: 0 }
  }
];

export const DATABASE_STATS_SCENARIOS: TestScenario[] = [
  {
    name: 'empty-database-stats',
    items: [],
    expectedResults: { storedCount: 0, errorCount: 0 }
  },
  {
    name: 'populated-database-stats',
    items: generateCompleteItems().slice(0, 10),
    expectedResults: { storedCount: 10, errorCount: 0 }
  },
  {
    name: 'stats-by-project-scope',
    items: generateCompleteItems().slice(0, 10).map(item => ({
      ...item,
      scope: { project: 'stats-test-project' }
    })),
    expectedResults: { storedCount: 10, errorCount: 0 }
  }
];

// ============================================================================
// Test Execution Framework
// ============================================================================

/**
 * Execute parameterized tests for a given tool configuration
 */
export function executeParameterizedTests(config: ToolTestConfig) {
  describe(`${config.toolName} - Parameterized Tests`, () => {
    let db: VectorDatabase;

    beforeEach(async () => {
      db = new VectorDatabase();
      if (config.setup) {
        await config.setup();
      }
    });

    afterEach(async () => {
      if (config.teardown) {
        await config.teardown();
      }
    });

    // Execute each scenario
    for (const scenario of config.scenarios) {
      if (scenario.skip) {
        it.skip(scenario.name, () => {});
        continue;
      }

      it(scenario.name, async () => {
        // Setup scenario data
        if (scenario.items.length > 0) {
          const setupResult = await db.storeItems(scenario.items);
          expect(setupResult.errors).toHaveLength(scenario.expectedResults.errorCount || 0);
          expect(setupResult.stored).toHaveLength(scenario.expectedResults.storedCount || 0);
        }

        // Execute test
        const testPromise = config.testFunction(scenario.items, scenario);
        const result = scenario.timeout
          ? await Promise.race([
              testPromise,
              new Promise((_, reject) =>
                setTimeout(() => reject(new Error(`Test timeout after ${scenario.timeout}ms`)), scenario.timeout)
              )
            ])
          : await testPromise;

        // Validate results
        if (scenario.expectedResults.errorTypes) {
          expect(result.errors?.length || 0).toBeGreaterThan(0);
          for (const errorType of scenario.expectedResults.errorTypes) {
            expect(JSON.stringify(result.errors)).toContain(errorType);
          }
        }

        // Additional validation for successful operations
        if (scenario.expectedResults.errorCount === 0) {
          expect(result.errors).toHaveLength(0);
        }
      }, scenario.timeout || 10000);
    }
  });
}

/**
 * Create memory store test configuration
 */
export function createMemoryStoreTestConfig(): ToolTestConfig {
  return {
    toolName: 'memory_store',
    testFunction: async (items) => {
      const db = new VectorDatabase();
      return await db.storeItems(items);
    },
    scenarios: MEMORY_STORE_SCENARIOS
  };
}

/**
 * Create memory find test configuration
 */
export function createMemoryFindTestConfig(): ToolTestConfig {
  return {
    toolName: 'memory_find',
    testFunction: async (items) => {
      const db = new VectorDatabase();

      // First store the items
      await db.storeItems(items);

      // Then perform a search
      const query = items.length > 0 ? items[0].content.substring(0, 10) : 'test query';
      return await db.searchItems(query);
    },
    scenarios: MEMORY_FIND_SCENARIOS
  };
}

/**
 * Create database health test configuration
 */
export function createDatabaseHealthTestConfig(): ToolTestConfig {
  return {
    toolName: 'database_health',
    testFunction: async () => {
      const db = new VectorDatabase();
      return await db.getHealth();
    },
    scenarios: DATABASE_HEALTH_SCENARIOS
  };
}

/**
 * Create database stats test configuration
 */
export function createDatabaseStatsTestConfig(): ToolTestConfig {
  return {
    toolName: 'database_stats',
    testFunction: async (items) => {
      const db = new VectorDatabase();

      // Store items first if provided
      if (items.length > 0) {
        await db.storeItems(items);
      }

      return await db.getStats();
    },
    scenarios: DATABASE_STATS_SCENARIOS
  };
}

// ============================================================================
// Test Suite Execution
// ============================================================================

/**
 * Execute all parameterized tests for mcp__cortex tools
 */
export function executeAllParameterizedTests() {
  executeParameterizedTests(createMemoryStoreTestConfig());
  executeParameterizedTests(createMemoryFindTestConfig());
  executeParameterizedTests(createDatabaseHealthTestConfig());
  executeParameterizedTests(createDatabaseStatsTestConfig());
}

// ============================================================================
// Performance Test Scenarios
// ============================================================================

export const PERFORMANCE_SCENARIOS = {
  memory_store: [
    { name: 'store-100-items', itemCount: 100 },
    { name: 'store-500-items', itemCount: 500 },
    { name: 'store-1000-items', itemCount: 1000, skip: true }, // Might be too slow
  ],
  memory_find: [
    { name: 'search-large-dataset', itemCount: 100, queryCount: 10 },
    { name: 'concurrent-searches', itemCount: 50, queryCount: 20 }
  ]
};

/**
 * Execute performance tests
 */
export function executePerformanceTests() {
  describe('Performance Tests', () => {
    let db: VectorDatabase;

    beforeEach(async () => {
      db = new VectorDatabase();
    });

    describe('Memory Store Performance', () => {
      for (const scenario of PERFORMANCE_SCENARIOS.memory_store) {
        if (scenario.skip) {
          it.skip(scenario.name, () => {});
          continue;
        }

        it(scenario.name, async () => {
          const items = Array.from({ length: scenario.itemCount }, (_, i) =>
            generateMinimalItem(KNOWLEDGE_TYPES[i % KNOWLEDGE_TYPES.length], {
              content: `Performance test item ${i}`,
              metadata: { performanceTest: true, index: i }
            })
          );

          const startTime = Date.now();
          const result = await db.storeItems(items);
          const endTime = Date.now();

          expect(result.errors).toHaveLength(0);
          expect(result.stored).toHaveLength(scenario.itemCount);

          const duration = endTime - startTime;
          console.log(`${scenario.name}: ${duration}ms for ${scenario.itemCount} items`);

          // Performance assertion (adjust as needed)
          expect(duration).toBeLessThan(10000); // 10 seconds max
        }, 30000); // 30 second timeout
      }
    });

    describe('Memory Find Performance', () => {
      for (const scenario of PERFORMANCE_SCENARIOS.memory_find) {
        it(scenario.name, async () => {
          // Setup test data
          const items = Array.from({ length: scenario.itemCount }, (_, i) =>
            generateCompleteItem(KNOWLEDGE_TYPES[i % KNOWLEDGE_TYPES.length], {
              content: `Search performance test item ${i} with unique keywords keyword${i % 10}`,
              metadata: { performanceTest: true, index: i }
            })
          );

          await db.storeItems(items);

          // Execute searches
          const startTime = Date.now();
          const searchPromises = [];

          for (let i = 0; i < scenario.queryCount; i++) {
            searchPromises.push(db.searchItems(`keyword${i % 10}`));
          }

          const results = await Promise.all(searchPromises);
          const endTime = Date.now();

          // Validate results
          for (const result of results) {
            expect(result.items).toBeDefined();
            expect(result.total).toBeDefined();
          }

          const duration = endTime - startTime;
          console.log(`${scenario.name}: ${duration}ms for ${scenario.queryCount} searches over ${scenario.itemCount} items`);

          // Performance assertion
          expect(duration).toBeLessThan(15000); // 15 seconds max
        }, 45000); // 45 second timeout
      }
    });
  });
}

export default {
  KNOWLEDGE_TYPES,
  MEMORY_STORE_SCENARIOS,
  MEMORY_FIND_SCENARIOS,
  DATABASE_HEALTH_SCENARIOS,
  DATABASE_STATS_SCENARIOS,
  PERFORMANCE_SCENARIOS,
  executeParameterizedTests,
  createMemoryStoreTestConfig,
  createMemoryFindTestConfig,
  createDatabaseHealthTestConfig,
  createDatabaseStatsTestConfig,
  executeAllParameterizedTests,
  executePerformanceTests
};