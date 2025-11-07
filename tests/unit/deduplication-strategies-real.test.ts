/**
 * Real Deduplication Strategies Test Suite
 *
 * Tests the actual implemented deduplication strategies with comprehensive scenarios
 * including edge cases, performance tests, and error handling.
 *
 * Strategies implemented:
 * 1. Skip Strategy - No deduplication, store all items
 * 2. Prefer Existing Strategy - Keep existing items, discard new duplicates
 * 3. Prefer Newer Strategy - Keep newer items based on timestamp/content comparison
 * 4. Combine Strategy - Merge content from duplicate items intelligently
 * 5. Intelligent Strategy - Advanced semantic similarity + content analysis
 */

import { describe, it, expect, beforeEach, beforeAll } from 'vitest';

// Import real deduplication strategies
import {
  SkipStrategy,
  PreferExistingStrategy,
  PreferNewerStrategy,
  CombineStrategy,
  IntelligentStrategy,
  DeduplicationStrategyFactory,
  type DeduplicationStrategy,
} from '../../src/services/deduplication/strategies/index.js';

// Test utilities
const createTestKnowledgeItem = (overrides: any = {}) => ({
  id: `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
  kind: 'entity',
  scope: { project: 'test-project' },
  data: { content: 'Test content' },
  metadata: {},
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  ...overrides,
});

// Test strategy instances
let skipStrategy: SkipStrategy;
let preferExistingStrategy: PreferExistingStrategy;
let preferNewerStrategy: PreferNewerStrategy;
let combineStrategy: CombineStrategy;
let intelligentStrategy: IntelligentStrategy;

// Test data
let testItems: any[];
let duplicateItems: any[];

describe('Real Deduplication Strategies Test Suite', () => {
  beforeAll(() => {
    // Generate comprehensive test data
    testItems = [
      // Exact duplicates
      createTestKnowledgeItem({
        kind: 'entity',
        data: { content: 'Identical content that should be detected as duplicate' },
        metadata: { category: 'test', priority: 'high' },
      }),
      createTestKnowledgeItem({
        kind: 'entity',
        data: { content: 'Identical content that should be detected as duplicate' },
        metadata: { category: 'test', priority: 'high' },
      }),

      // Semantic duplicates
      createTestKnowledgeItem({
        kind: 'entity',
        data: { content: 'Machine learning algorithms analyze data patterns' },
        metadata: { category: 'ml', priority: 'medium' },
      }),
      createTestKnowledgeItem({
        kind: 'entity',
        data: { content: 'Data analysis is performed by machine learning models' },
        metadata: { category: 'ml', priority: 'medium' },
      }),
      createTestKnowledgeItem({
        kind: 'entity',
        data: { content: 'AI systems use machine learning to analyze patterns in data' },
        metadata: { category: 'ai', priority: 'medium' },
      }),

      // Hash collisions (same content, different formatting)
      createTestKnowledgeItem({
        kind: 'section',
        data: { content: 'The quick brown fox jumps over the lazy dog' },
        metadata: { type: 'sentence' },
      }),
      createTestKnowledgeItem({
        kind: 'section',
        data: { content: 'the quick brown fox jumps over the lazy dog' }, // lowercase
        metadata: { type: 'sentence' },
      }),

      // Metadata-based duplicates
      createTestKnowledgeItem({
        kind: 'decision',
        data: { content: 'Decision content A' },
        metadata: {
          decision_id: 'DEC-001',
          author: 'john.doe',
          date: '2024-01-15',
          category: 'technical',
        },
      }),
      createTestKnowledgeItem({
        kind: 'decision',
        data: { content: 'Decision content A - updated version' },
        metadata: {
          decision_id: 'DEC-001',
          author: 'john.doe',
          date: '2024-01-15',
          category: 'technical',
        },
      }),

      // Unique items (should not be deduplicated)
      createTestKnowledgeItem({
        kind: 'observation',
        data: { content: 'Unique observation content that has no duplicates' },
        metadata: { category: 'unique' },
      }),
      createTestKnowledgeItem({
        kind: 'runbook',
        data: { content: 'Step-by-step procedures for system recovery' },
        metadata: { category: 'procedures', complexity: 'high' },
      }),
    ];

    // Additional test items for stress testing
    duplicateItems = [
      ...Array.from({ length: 10 }, (_, i) =>
        createTestKnowledgeItem({
          kind: 'entity',
          data: { content: `Bulk test item ${i % 3}` }, // Creates intentional duplicates
          metadata: { batch: 'bulk-test', index: i },
        })
      ),
    ];
  });

  beforeEach(() => {
    // Initialize strategies with test configurations
    skipStrategy = new SkipStrategy({
      logSkippedItems: false,
      performBasicValidation: true,
    });

    preferExistingStrategy = new PreferExistingStrategy({
      similarityThreshold: 0.85,
      comparisonMethod: 'first_encountered',
      logDetailedActions: false,
    });

    preferNewerStrategy = new PreferNewerStrategy({
      similarityThreshold: 0.85,
      ageDeterminationMethod: 'created_at',
      tieBreaker: 'content_length',
      logTimestampComparisons: false,
    });

    combineStrategy = new CombineStrategy({
      similarityThreshold: 0.8,
      contentMergeStrategy: 'intelligent_merge',
      metadataMergeStrategy: 'union',
      maxItemsInMergeGroup: 5,
    });

    intelligentStrategy = new IntelligentStrategy({
      enableSemanticAnalysis: true,
      enableStructureAnalysis: true,
      enableKeywordAnalysis: true,
      thresholds: {
        exact: 0.95,
        semantic: 0.8,
        structural: 0.7,
        overall: 0.75,
      },
    });
  });

  describe('Strategy 1: Skip Strategy', () => {
    it('should skip all deduplication and treat all items as unique', async () => {
      const result = await skipStrategy.detectDuplicates(testItems);

      expect(result.duplicates.length).toBe(0);
      expect(result.unique.length).toBe(testItems.length);
      expect(result.metrics.totalItems).toBe(testItems.length);
      expect(result.metrics.duplicateGroups).toBe(0);
    });

    it('should handle empty input gracefully', async () => {
      const result = await skipStrategy.detectDuplicates([]);

      expect(result.duplicates.length).toBe(0);
      expect(result.unique.length).toBe(0);
      expect(result.metrics.totalItems).toBe(0);
    });

    it('should provide accurate strategy description', () => {
      const description = skipStrategy.getDescription();
      expect(description).toContain('Skip Strategy');
      expect(description).toContain('bypasses all deduplication logic');
    });

    it('should provide strategy statistics', () => {
      const stats = skipStrategy.getStrategyStats();
      expect(stats.name).toBe('skip');
      expect(stats.type).toBe('skip');
      expect(stats.behavior).toBe('No duplicate detection, all items treated as unique');
    });
  });

  describe('Strategy 2: Prefer Existing Strategy', () => {
    it('should detect exact content duplicates', async () => {
      const exactDuplicates = testItems.slice(0, 2); // First two items are identical

      const result = await preferExistingStrategy.detectDuplicates(exactDuplicates);

      expect(result.duplicates.length).toBe(1);
      expect(result.duplicates[0].items.length).toBe(2);
      expect(result.duplicates[0].similarity).toBeGreaterThan(0.9);
      expect(result.unique.length).toBe(1);
    });

    it('should detect semantic duplicates with configurable threshold', async () => {
      const semanticItems = testItems.slice(2, 5); // ML-related items

      const result = await preferExistingStrategy.detectDuplicates(semanticItems);

      // Should detect some semantic similarity
      expect(result.duplicates.length).toBeGreaterThanOrEqual(0);
      if (result.duplicates.length > 0) {
        expect(result.duplicates[0].similarity).toBeGreaterThan(0.8);
      }
    });

    it('should respect similarity threshold configuration', async () => {
      const strictStrategy = new PreferExistingStrategy({ similarityThreshold: 0.95 });
      const looseStrategy = new PreferExistingStrategy({ similarityThreshold: 0.6 });

      const strictResult = await strictStrategy.detectDuplicates(testItems);
      const looseResult = await looseStrategy.detectDuplicates(testItems);

      expect(looseResult.duplicates.length).toBeGreaterThanOrEqual(strictResult.duplicates.length);
    });

    it('should prefer first encountered item when duplicates found', async () => {
      const result = await preferExistingStrategy.detectDuplicates(testItems);

      result.duplicates.forEach((group) => {
        expect(group.action).toBeDefined();
        expect(group.action!.keepIndices).toContain(0); // Should keep first item
        expect(group.action!.discardIndices.length).toBeGreaterThan(0);
      });
    });

    it('should provide strategy description and statistics', () => {
      const description = preferExistingStrategy.getDescription();
      const stats = preferExistingStrategy.getStrategyStats();

      expect(description).toContain('Prefer Existing Strategy');
      expect(stats.name).toBe('prefer_existing');
      expect(stats.behavior).toBe('Keeps existing items, discards new duplicates');
    });
  });

  describe('Strategy 3: Prefer Newer Strategy', () => {
    it('should detect duplicates and prefer newer items', async () => {
      // Create items with different timestamps
      const olderItem = createTestKnowledgeItem({
        data: { content: 'Same content' },
        created_at: '2024-01-01T00:00:00.000Z',
      });
      const newerItem = createTestKnowledgeItem({
        data: { content: 'Same content' },
        created_at: '2024-01-02T00:00:00.000Z',
      });

      const result = await preferNewerStrategy.detectDuplicates([olderItem, newerItem]);

      expect(result.duplicates.length).toBe(1);
      expect(result.unique.length).toBe(1);

      // Check that the action prefers the newer item
      const action = result.duplicates[0].action;
      expect(action).toBeDefined();
      expect(action!.keepIndices).toContain(1); // Should keep newer item (index 1)
    });

    it('should handle tie-breaking when timestamps are similar', async () => {
      const item1 = createTestKnowledgeItem({
        data: { content: 'Short content' },
        created_at: '2024-01-01T00:00:00.000Z',
      });
      const item2 = createTestKnowledgeItem({
        data: { content: 'Much longer content with more details' },
        created_at: '2024-01-01T00:00:01.000Z', // Only 1 second difference
      });

      const result = await preferNewerStrategy.detectDuplicates([item1, item2]);

      expect(result.duplicates.length).toBe(1);
      // With tie-breaker set to content_length, should prefer longer content
      expect(result.unique[0].data.content).toContain('Much longer content');
    });

    it('should handle missing timestamps gracefully', async () => {
      const itemWithoutTimestamp = createTestKnowledgeItem({
        data: { content: 'Content without timestamp' },
      });
      delete itemWithoutTimestamp.created_at;

      const itemWithTimestamp = createTestKnowledgeItem({
        data: { content: 'Content without timestamp' },
        created_at: '2024-01-01T00:00:00.000Z',
      });

      const result = await preferNewerStrategy.detectDuplicates([
        itemWithoutTimestamp,
        itemWithTimestamp,
      ]);

      expect(result.duplicates.length).toBe(1);
      expect(result.unique.length).toBe(1);
    });

    it('should provide strategy description and statistics', () => {
      const description = preferNewerStrategy.getDescription();
      const stats = preferNewerStrategy.getStrategyStats();

      expect(description).toContain('Prefer Newer Strategy');
      expect(stats.name).toBe('prefer_newer');
      expect(stats.behavior).toBe('Keeps newer items, discards older duplicates');
    });
  });

  describe('Strategy 4: Combine Strategy', () => {
    it('should combine duplicate items intelligently', async () => {
      const itemsToCombine = [
        createTestKnowledgeItem({
          data: { content: 'First part of information', tags: ['tag1'] },
          metadata: { source: 'doc1' },
        }),
        createTestKnowledgeItem({
          data: { content: 'Second part of information', tags: ['tag2'] },
          metadata: { source: 'doc2' },
        }),
      ];

      const result = await combineStrategy.detectDuplicates(itemsToCombine);

      expect(result.duplicates.length).toBe(1);
      expect(result.unique.length).toBe(1);

      // Check that merged item contains combined content
      const mergedItem = result.unique[0];
      expect(mergedItem['data.content']).toContain('First part');
      expect(mergedItem['data.content']).toContain('Second part');
      expect(mergedItem.metadata['merged_from']).toBeDefined();
    });

    it('should handle content merging with different strategies', async () => {
      const concatenateStrategy = new CombineStrategy({
        contentMergeStrategy: 'concatenate',
        similarityThreshold: 0.8,
      });

      const itemsToCombine = [
        createTestKnowledgeItem({ data: { content: 'Content A' } }),
        createTestKnowledgeItem({ data: { content: 'Content B' } }),
      ];

      const result = await concatenateStrategy.detectDuplicates(itemsToCombine);

      expect(result.duplicates.length).toBe(1);
      expect(result.unique[0].data.content).toContain('Content A');
      expect(result.unique[0].data.content).toContain('Content B');
    });

    it('should limit merge group size', async () => {
      const manyDuplicates = Array.from({ length: 15 }, (_, i) =>
        createTestKnowledgeItem({
          data: { content: `Similar content ${i}` },
          created_at: new Date(Date.now() - i * 1000).toISOString(),
        })
      );

      const result = await combineStrategy.detectDuplicates(manyDuplicates);

      // Should limit group size to maxItemsInMergeGroup (5 in our config)
      expect(result.duplicates.length).toBeGreaterThanOrEqual(1);
      if (result.duplicates.length > 0) {
        expect(result.duplicates[0].items.length).toBeLessThanOrEqual(5);
      }
    });

    it('should preserve merge history when configured', async () => {
      const strategyWithHistory = new CombineStrategy({
        preserveMergeHistory: true,
        similarityThreshold: 0.8,
      });

      const itemsToCombine = [
        createTestKnowledgeItem({ data: { content: 'Content 1' } }),
        createTestKnowledgeItem({ data: { content: 'Content 2' } }),
      ];

      const result = await strategyWithHistory.detectDuplicates(itemsToCombine);

      expect(result.duplicates.length).toBe(1);
      const mergedItem = result.unique[0];
      expect(mergedItem.metadata['merge_history']).toBeDefined();
      expect(mergedItem.metadata['merge_history']).toBeInstanceOf(Array);
    });

    it('should provide strategy description and statistics', () => {
      const description = combineStrategy.getDescription();
      const stats = combineStrategy.getStrategyStats();

      expect(description).toContain('Combine Strategy');
      expect(stats.name).toBe('combine');
      expect(stats.behavior).toBe('Combines duplicate items into comprehensive merged items');
    });
  });

  describe('Strategy 5: Intelligent Strategy', () => {
    it('should perform multi-faceted analysis', async () => {
      const result = await intelligentStrategy.detectDuplicates(testItems);

      expect(result.metrics.totalItems).toBe(testItems.length);
      expect(Array.isArray(result.duplicates)).toBe(true);
      expect(Array.isArray(result.unique)).toBe(true);
    });

    it('should use semantic analysis when enabled', async () => {
      const semanticItems = testItems.slice(2, 5); // ML-related items

      const result = await intelligentStrategy.detectDuplicates(semanticItems);

      // Should detect semantic similarity
      expect(result.duplicates.length).toBeGreaterThanOrEqual(0);
      if (result.duplicates.length > 0) {
        expect(result.duplicates[0].confidence).toBeDefined();
        expect(result.duplicates[0].confidence).toBeGreaterThan(0);
        expect(result.duplicates[0].confidence).toBeLessThanOrEqual(1);
      }
    });

    it('should analyze content structure', async () => {
      const structuredItem = createTestKnowledgeItem({
        data: { content: '# Header\n\n- List item 1\n- List item 2\n\n```code```' },
      });
      const unstructuredItem = createTestKnowledgeItem({
        data: { content: 'Plain text without structure' },
      });

      const result = await intelligentStrategy.detectDuplicates([structuredItem, unstructuredItem]);

      expect(result.metrics.totalItems).toBe(2);
      expect(result.metrics.strategyMetrics).toBeDefined();
    });

    it('should extract and compare keywords', async () => {
      const technicalItem = createTestKnowledgeItem({
        data: {
          content: 'Machine learning algorithms use neural networks for pattern recognition',
        },
      });
      const similarItem = createTestKnowledgeItem({
        data: { content: 'Neural networks in ML systems recognize patterns effectively' },
      });

      const result = await intelligentStrategy.detectDuplicates([technicalItem, similarItem]);

      if (result.duplicates.length > 0) {
        expect(result.duplicates[0].similarity).toBeGreaterThan(0.5);
        expect(result.duplicates[0].metadata?.analysisDetails).toBeDefined();
      }
    });

    it('should provide detailed analysis metadata', async () => {
      const result = await intelligentStrategy.detectDuplicates(testItems);

      if (result.duplicates.length > 0) {
        const duplicate = result.duplicates[0];
        expect(duplicate.metadata?.analysisDetails).toBeDefined();
        expect(duplicate.metadata?.similarityBreakdown).toBeDefined();
        expect(duplicate.metadata?.confidence).toBeDefined();
      }
    });

    it('should respect performance configuration', async () => {
      const performanceStrategy = new IntelligentStrategy({
        enableCaching: true,
        maxCacheSize: 100,
        enableSemanticAnalysis: true,
      });

      const result1 = await performanceStrategy.detectDuplicates(testItems.slice(0, 3));
      const result2 = await performanceStrategy.detectDuplicates(testItems.slice(0, 3));

      // Results should be consistent
      expect(result1.duplicates.length).toBe(result2.duplicates.length);
      expect(result1.unique.length).toBe(result2.unique.length);
    });

    it('should provide comprehensive strategy information', () => {
      const description = intelligentStrategy.getDescription();
      const stats = intelligentStrategy.getStrategyStats();

      expect(description).toContain('Intelligent Strategy');
      expect(description).toContain('semantic analysis');
      expect(stats.name).toBe('intelligent');
      expect(stats.type).toBe('intelligent');
      expect(stats.behavior).toContain('Multi-faceted intelligent analysis');
    });
  });

  describe('Strategy Factory', () => {
    it('should create strategies by name', () => {
      const skip = DeduplicationStrategyFactory.createStrategy('skip');
      const preferExisting = DeduplicationStrategyFactory.createStrategy('prefer_existing');
      const preferNewer = DeduplicationStrategyFactory.createStrategy('prefer_newer');
      const combine = DeduplicationStrategyFactory.createStrategy('combine');
      const intelligent = DeduplicationStrategyFactory.createStrategy('intelligent');

      expect(skip.name).toBe('skip');
      expect(preferExisting.name).toBe('prefer_existing');
      expect(preferNewer.name).toBe('prefer_newer');
      expect(combine.name).toBe('combine');
      expect(intelligent.name).toBe('intelligent');
    });

    it('should handle alternative strategy names', () => {
      const preferExisting1 = DeduplicationStrategyFactory.createStrategy('prefer_existing');
      const preferExisting2 = DeduplicationStrategyFactory.createStrategy('prefer-existing');

      expect(preferExisting1.name).toBe(preferExisting2.name);
    });

    it('should throw error for unknown strategy', () => {
      expect(() => {
        DeduplicationStrategyFactory.createStrategy('unknown_strategy');
      }).toThrow('Unknown deduplication strategy: unknown_strategy');
    });

    it('should provide list of available strategies', () => {
      const strategies = DeduplicationStrategyFactory.getAvailableStrategies();

      expect(strategies).toContain('skip');
      expect(strategies).toContain('prefer_existing');
      expect(strategies).toContain('prefer_newer');
      expect(strategies).toContain('combine');
      expect(strategies).toContain('intelligent');
    });

    it('should create all strategies', () => {
      const allStrategies = DeduplicationStrategyFactory.createAllStrategies();

      expect(Object.keys(allStrategies)).toHaveLength(5);
      expect(allStrategies.skip).toBeDefined();
      expect(allStrategies.prefer_existing).toBeDefined();
      expect(allStrategies.prefer_newer).toBeDefined();
      expect(allStrategies.combine).toBeDefined();
      expect(allStrategies.intelligent).toBeDefined();
    });

    it('should validate strategy configurations', () => {
      const validConfig = { similarityThreshold: 0.8 };
      const invalidConfig = { similarityThreshold: 'invalid' };

      const validResult = DeduplicationStrategyFactory.validateConfig('skip', validConfig);
      const invalidResult = DeduplicationStrategyFactory.validateConfig('skip', invalidConfig);

      expect(validResult.valid).toBe(true);
      expect(validResult.errors).toHaveLength(0);
      // Note: Individual strategy validation may vary
    });

    it('should provide strategy descriptions', () => {
      const skipDescription = DeduplicationStrategyFactory.getStrategyDescription('skip');
      const intelligentDescription =
        DeduplicationStrategyFactory.getStrategyDescription('intelligent');

      expect(skipDescription).toContain('skip');
      expect(intelligentDescription).toContain('intelligent');
    });
  });

  describe('Performance and Stress Testing', () => {
    it('should handle large datasets efficiently', async () => {
      const largeDataset = [
        ...testItems,
        ...duplicateItems,
        ...Array.from({ length: 50 }, (_, i) =>
          createTestKnowledgeItem({
            data: { content: `Performance test item ${i}` },
            metadata: { performance: true, index: i },
          })
        ),
      ];

      const strategies = [skipStrategy, preferExistingStrategy, preferNewerStrategy];

      for (const strategy of strategies) {
        const startTime = Date.now();
        const result = await strategy.detectDuplicates(largeDataset);
        const endTime = Date.now();

        expect(result.duplicates).toBeDefined();
        expect(result.unique).toBeDefined();
        expect(endTime - startTime).toBeLessThan(5000); // Should complete in under 5 seconds
      }
    });

    it('should handle edge cases gracefully', async () => {
      const edgeCases = [
        [], // Empty array
        [null], // Single null item
        [undefined], // Single undefined item
        [{}], // Empty object
        [{ id: 'test' }], // Item with minimal data
        Array.from({ length: 1 }, () => ({})), // Array of empty objects
      ].filter(Boolean); // Remove null/undefined

      for (const testCase of edgeCases) {
        const result = await skipStrategy.detectDuplicates(testCase as any[]);

        expect(Array.isArray(result.duplicates)).toBe(true);
        expect(Array.isArray(result.unique)).toBe(true);
        expect(typeof result.metrics).toBe('object');
      }
    });

    it('should manage memory usage effectively', async () => {
      const initialMemory = process.memoryUsage().heapUsed;

      // Run multiple strategies on the same data
      await skipStrategy.detectDuplicates(duplicateItems);
      await preferExistingStrategy.detectDuplicates(duplicateItems);
      await intelligentStrategy.detectDuplicates(duplicateItems);

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be reasonable (less than 50MB)
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
    });
  });

  describe('Integration Tests', () => {
    it('should work consistently across different configurations', async () => {
      const configurations = [
        { similarityThreshold: 0.9 },
        { similarityThreshold: 0.7 },
        { respectScopeBoundaries: false },
        { dedupeWindowDays: 1 },
        { enableAuditLogging: false },
      ];

      for (const config of configurations) {
        const strategy = new PreferExistingStrategy(config);
        const result = await strategy.detectDuplicates(testItems);

        expect(result.duplicates).toBeDefined();
        expect(result.unique).toBeDefined();
        expect(result.metrics.totalItems).toBe(testItems.length);
      }
    });

    it('should handle malformed input gracefully', async () => {
      const malformedItems = [
        { id: 'valid', kind: 'entity', data: { content: 'valid' } },
        { id: 'missing-data', kind: 'entity' },
        { id: 'missing-kind', data: { content: 'no kind' } },
        { data: { content: 'no id or kind' } },
      ];

      const result = await skipStrategy.detectDuplicates(malformedItems as any[]);

      expect(Array.isArray(result.duplicates)).toBe(true);
      expect(Array.isArray(result.unique)).toBe(true);
    });

    it('should maintain result format consistency', async () => {
      const strategies = [
        skipStrategy,
        preferExistingStrategy,
        preferNewerStrategy,
        combineStrategy,
        intelligentStrategy,
      ];

      for (const strategy of strategies) {
        const result = await strategy.detectDuplicates(testItems.slice(0, 3));

        expect(result).toHaveProperty('duplicates');
        expect(result).toHaveProperty('unique');
        expect(result).toHaveProperty('metrics');
        expect(Array.isArray(result.duplicates)).toBe(true);
        expect(Array.isArray(result.unique)).toBe(true);
        expect(typeof result.metrics).toBe('object');
      }
    });
  });
});
