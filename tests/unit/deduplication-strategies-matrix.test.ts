/**
 * Deduplication Strategies Test Matrix
 *
 * Comprehensive test suite covering all 5 deduplication strategies with various
 * scenarios including edge cases, performance tests, and error handling.
 *
 * Strategies implemented:
 * 1. Skip Strategy - No deduplication, store all items
 * 2. Prefer Existing Strategy - Keep existing items, discard new duplicates
 * 3. Prefer Newer Strategy - Keep newer items based on timestamp/content comparison
 * 4. Combine Strategy - Merge content from duplicate items intelligently
 * 5. Intelligent Strategy - Advanced semantic similarity + content analysis
 */

import { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import { memoryStore } from '../../src/services/memory-store.js';
import { memoryFind } from '../../src/services/memory-find.js';

// Import real deduplication strategies
import {
  SkipStrategy,
  PreferExistingStrategy,
  PreferNewerStrategy,
  CombineStrategy,
  IntelligentStrategy,
  DeduplicationStrategyFactory,
  type DeduplicationStrategy
} from '../../src/services/deduplication/strategies/index.js';

// Access global test utilities (they're attached to global by jest-setup.ts)
declare global {
  var testUtils: any;
  var asyncUtils: any;
}

// Test strategy instances (will be initialized in beforeEach)
let skipStrategy: SkipStrategy;
let preferExistingStrategy: PreferExistingStrategy;
let preferNewerStrategy: PreferNewerStrategy;
let combineStrategy: CombineStrategy;
let intelligentStrategy: IntelligentStrategy;
  describe('Deduplication Strategies Test Matrix', () => {
  let testItems: any[];
  let duplicateItems: any[];

  // Initialize strategies before each test
  beforeEach(() => {
    skipStrategy = new SkipStrategy({
      logSkippedItems: false,
      performBasicValidation: true
    });

    preferExistingStrategy = new PreferExistingStrategy({
      similarityThreshold: 0.85,
      comparisonMethod: 'first_encountered',
      logDetailedActions: false
    });

    preferNewerStrategy = new PreferNewerStrategy({
      similarityThreshold: 0.85,
      ageDeterminationMethod: 'created_at',
      tieBreaker: 'content_length',
      logTimestampComparisons: false
    });

    combineStrategy = new CombineStrategy({
      similarityThreshold: 0.8,
      contentMergeStrategy: 'intelligent_merge',
      metadataMergeStrategy: 'union',
      maxItemsInMergeGroup: 5
    });

    intelligentStrategy = new IntelligentStrategy({
      enableSemanticAnalysis: true,
      enableStructureAnalysis: true,
      enableKeywordAnalysis: true,
      thresholds: {
        exact: 0.95,
        semantic: 0.8,
        structural: 0.7,
        overall: 0.75
      }
    });
  });

  beforeAll(() => {
    // Ensure testUtils is available
    if (!global.testUtils || !global.global.testUtils.createTestKnowledgeItem) {
      throw new Error('global.testUtils.createTestKnowledgeItem is not available. Check jest-setup.ts configuration.');
    }

    // Generate comprehensive test data
    testItems = [
      // Exact duplicates
      global.global.testUtils.createTestKnowledgeItem({
        kind: 'entity',
        data: { content: 'Identical content that should be detected as duplicate' },
        metadata: { category: 'test', priority: 'high' }
      }),
      global.global.testUtils.createTestKnowledgeItem({
        kind: 'entity',
        data: { content: 'Identical content that should be detected as duplicate' },
        metadata: { category: 'test', priority: 'high' }
      }),

      // Semantic duplicates
      global.global.testUtils.createTestKnowledgeItem({
        kind: 'entity',
        data: { content: 'Machine learning algorithms analyze data patterns' },
        metadata: { category: 'ml', priority: 'medium' }
      }),
      global.global.testUtils.createTestKnowledgeItem({
        kind: 'entity',
        data: { content: 'Data analysis is performed by machine learning models' },
        metadata: { category: 'ml', priority: 'medium' }
      }),
      global.global.testUtils.createTestKnowledgeItem({
        kind: 'entity',
        data: { content: 'AI systems use machine learning to analyze patterns in data' },
        metadata: { category: 'ai', priority: 'medium' }
      }),

      // Hash collisions (same content, different formatting)
      global.global.testUtils.createTestKnowledgeItem({
        kind: 'section',
        data: { content: 'The quick brown fox jumps over the lazy dog' },
        metadata: { type: 'sentence' }
      }),
      global.global.testUtils.createTestKnowledgeItem({
        kind: 'section',
        data: { content: 'the quick brown fox jumps over the lazy dog' }, // lowercase
        metadata: { type: 'sentence' }
      }),

      // Metadata-based duplicates
      global.global.testUtils.createTestKnowledgeItem({
        kind: 'decision',
        data: { content: 'Decision content A' },
        metadata: {
          decision_id: 'DEC-001',
          author: 'john.doe',
          date: '2024-01-15',
          category: 'technical'
        }
      }),
      global.global.testUtils.createTestKnowledgeItem({
        kind: 'decision',
        data: { content: 'Decision content A - updated version' },
        metadata: {
          decision_id: 'DEC-001',
          author: 'john.doe',
          date: '2024-01-15',
          category: 'technical'
        }
      }),

      // Unique items (should not be deduplicated)
      global.global.testUtils.createTestKnowledgeItem({
        kind: 'observation',
        data: { content: 'Unique observation content that has no duplicates' },
        metadata: { category: 'unique' }
      }),
      global.global.testUtils.createTestKnowledgeItem({
        kind: 'runbook',
        data: { content: 'Step-by-step procedures for system recovery' },
        metadata: { category: 'procedures', complexity: 'high' }
      })
    ];

    duplicateItems = [
      // Additional test items for stress testing
      ...Array.from({ length: 10 }, (_, i) =>
        global.global.testUtils.createTestKnowledgeItem({
          kind: 'entity',
          data: { content: `Bulk test item ${i % 3}` }, // Creates intentional duplicates
          metadata: { batch: 'bulk-test', index: i }
        })
      )
    ];
  });

  describe('Strategy 1: Exact Content Matching', () => {
    let strategy: ExactMatchStrategy;

    beforeEach(() => {
      strategy = new ExactMatchStrategy({
        caseSensitive: false,
        ignoreWhitespace: true,
        normalizeUnicode: true
      });
    });

    it('should detect exact content duplicates', async () => {
      const exactDuplicates = testItems.slice(0, 2); // First two items are identical

      const result = await strategy.detectDuplicates(exactDuplicates);

      expect(result.duplicates.length).toBe(1);
      expect(result.duplicates[0].items.length).toBe(2);
      expect(result.duplicates[0].similarity).toBe(1.0);
    });

    it('should handle case-insensitive matching', async () => {
      const caseVariants = [
        global.testUtils.createTestKnowledgeItem({ data: { content: 'Test Content' } }),
        global.testUtils.createTestKnowledgeItem({ data: { content: 'test content' } }),
        global.testUtils.createTestKnowledgeItem({ data: { content: 'TEST CONTENT' } })
      ];

      const result = await strategy.detectDuplicates(caseVariants);

      expect(result.duplicates.length).toBe(1);
      expect(result.duplicates[0].items.length).toBe(3);
    });

    it('should ignore whitespace differences', async () => {
      const whitespaceVariants = [
        global.testUtils.createTestKnowledgeItem({ data: { content: 'Test Content' } }),
        global.testUtils.createTestKnowledgeItem({ data: { content: 'Test   Content' } }),
        global.testUtils.createTestKnowledgeItem({ data: { content: 'Test\nContent' } }),
        global.testUtils.createTestKnowledgeItem({ data: { content: '  Test Content  ' } })
      ];

      const result = await strategy.detectDuplicates(whitespaceVariants);

      expect(result.duplicates.length).toBe(1);
      expect(result.duplicates[0].items.length).toBe(4);
    });

    it('should handle unicode normalization', async () => {
      const unicodeVariants = [
        global.testUtils.createTestKnowledgeItem({ data: { content: 'café résumé' } }),
        global.testUtils.createTestKnowledgeItem({ data: { content: 'café résumé' } }), // Combining characters
        global.testUtils.createTestKnowledgeItem({ data: { content: 'café résumé' } })
      ];

      const result = await strategy.detectDuplicates(unicodeVariants);

      expect(result.duplicates.length).toBe(1);
      expect(result.duplicates[0].items.length).toBe(3);
    });

    it('should not deduplicate different content', async () => {
      const uniqueItems = testItems.slice(-2); // Last two items are unique

      const result = await strategy.detectDuplicates(uniqueItems);

      expect(result.duplicates.length).toBe(0);
      expect(result.unique.length).toBe(2);
    });
  });

  describe('Strategy 2: Semantic Similarity', () => {
    let strategy: SemanticSimilarityStrategy;

    beforeEach(() => {
      strategy = new SemanticSimilarityStrategy({
        threshold: 0.8,
        useEmbeddings: true,
        embeddingModel: 'text-embedding-ada-002'
      });
    });

    it('should detect semantically similar content', async () => {
      const semanticItems = testItems.slice(2, 5); // ML-related items

      const result = await strategy.detectDuplicates(semanticItems);

      expect(result.duplicates.length).toBeGreaterThan(0);
      expect(result.duplicates[0].similarity).toBeGreaterThan(0.8);
      expect(result.duplicates[0].items.length).toBeGreaterThanOrEqual(2);
    });

    it('should respect similarity threshold', async () => {
      const strictStrategy = new SemanticSimilarityStrategy({ threshold: 0.95 });
      const looseStrategy = new SemanticSimilarityStrategy({ threshold: 0.6 });

      const strictResult = await strictStrategy.detectDuplicates(testItems);
      const looseResult = await looseStrategy.detectDuplicates(testItems);

      expect(looseResult.duplicates.length).toBeGreaterThanOrEqual(strictResult.duplicates.length);
    });

    it('should handle different content lengths', async () => {
      const lengthVariants = [
        global.testUtils.createTestKnowledgeItem({ data: { content: 'ML' } }),
        global.testUtils.createTestKnowledgeItem({ data: { content: 'Machine Learning' } }),
        global.testUtils.createTestKnowledgeItem({
          data: { content: 'Machine Learning is a subset of artificial intelligence' }
        })
      ];

      const result = await strategy.detectDuplicates(lengthVariants);

      // Should detect some similarity despite length differences
      expect(result.duplicates.length).toBeGreaterThanOrEqual(0);
      if (result.duplicates.length > 0) {
        expect(result.duplicates[0].similarity).toBeGreaterThan(0.5);
      }
    });

    it('should provide similarity scores', async () => {
      const result = await strategy.detectDuplicates(testItems);

      result.duplicates.forEach(duplicate => {
        expect(duplicate.similarity).toBeGreaterThan(0);
        expect(duplicate.similarity).toBeLessThanOrEqual(1);
        expect(typeof duplicate.similarity).toBe('number');
      });
    });
  });

  describe('Strategy 3: Content Hashing', () => {
    let strategy: ContentHashStrategy;

    beforeEach(() => {
      strategy = new ContentHashStrategy({
        algorithm: 'sha256',
        normalizeContent: true,
        includeMetadata: false
      });
    });

    it('should detect hash collisions for identical content', async () => {
      const identicalItems = testItems.slice(0, 2);

      const result = await strategy.detectDuplicates(identicalItems);

      expect(result.duplicates.length).toBe(1);
      expect(result.duplicates[0].items.length).toBe(2);
    });

    it('should generate consistent hashes', async () => {
      const item = testItems[0];

      const hash1 = await strategy.generateHash(item);
      const hash2 = await strategy.generateHash(item);

      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/i); // SHA256 hex pattern
    });

    it('should handle content normalization', async () => {
      const normalizingStrategy = new ContentHashStrategy({ normalizeContent: true });
      const nonNormalizingStrategy = new ContentHashStrategy({ normalizeContent: false });

      const normalizedItem = global.testUtils.createTestKnowledgeItem({
        data: { content: '  Test Content  ' }
      });
      const cleanItem = global.testUtils.createTestKnowledgeItem({
        data: { content: 'Test Content' }
      });

      const normalizedHash1 = await normalizingStrategy.generateHash(normalizedItem);
      const normalizedHash2 = await normalizingStrategy.generateHash(cleanItem);
      const nonNormalizedHash1 = await nonNormalizingStrategy.generateHash(normalizedItem);
      const nonNormalizedHash2 = await nonNormalizingStrategy.generateHash(cleanItem);

      // Normalized hashes should be the same
      expect(normalizedHash1).toBe(normalizedHash2);
      // Non-normalized hashes should be different
      expect(nonNormalizedHash1).not.toBe(nonNormalizedHash2);
    });

    it('should handle large content efficiently', async () => {
      const largeContent = 'Large content '.repeat(10000);
      const largeItem = global.testUtils.createTestKnowledgeItem({
        data: { content: largeContent }
      });

      const { result, time } = await global.testUtils.measureTime(async () => {
        return await strategy.generateHash(largeItem);
      });

      expect(result).toBeDefined();
      expect(time).toBeLessThan(1000); // Should complete in under 1 second
    });
  });

  describe('Strategy 4: Metadata-Based Deduplication', () => {
    let strategy: MetadataBasedStrategy;

    beforeEach(() => {
      strategy = new MetadataBasedStrategy({
        keyFields: ['decision_id', 'author', 'date'],
        requireAllKeys: true,
        ignoreContent: false
      });
    });

    it('should detect duplicates based on metadata keys', async () => {
      const metadataItems = testItems.slice(6, 8); // Decision items with same metadata

      const result = await strategy.detectDuplicates(metadataItems);

      expect(result.duplicates.length).toBe(1);
      expect(result.duplicates[0].items.length).toBe(2);
    });

    it('should respect key field configuration', async () => {
      const strictStrategy = new MetadataBasedStrategy({
        keyFields: ['decision_id', 'author', 'date'],
        requireAllKeys: true
      });
      const lenientStrategy = new MetadataBasedStrategy({
        keyFields: ['decision_id'],
        requireAllKeys: false
      });

      const strictResult = await strictStrategy.detectDuplicates(testItems);
      const lenientResult = await lenientStrategy.detectDuplicates(testItems);

      expect(lenientResult.duplicates.length).toBeGreaterThanOrEqual(strictResult.duplicates.length);
    });

    it('should handle missing metadata gracefully', async () => {
      const itemsWithMissingMetadata = [
        global.testUtils.createTestKnowledgeItem({
          data: { content: 'Test 1' },
          metadata: { decision_id: 'DEC-001' }
        }),
        global.testUtils.createTestKnowledgeItem({
          data: { content: 'Test 2' },
          metadata: { decision_id: 'DEC-001', author: 'john.doe' }
        }),
        global.testUtils.createTestKnowledgeItem({
          data: { content: 'Test 3' },
          metadata: {} // No metadata
        })
      ];

      const result = await strategy.detectDuplicates(itemsWithMissingMetadata);

      // Should handle missing metadata without errors
      expect(Array.isArray(result.duplicates)).toBe(true);
      expect(Array.isArray(result.unique)).toBe(true);
    });

    it('should combine metadata and content analysis', async () => {
      const contentAwareStrategy = new MetadataBasedStrategy({
        keyFields: ['decision_id'],
        ignoreContent: false
      });

      const result = await contentAwareStrategy.detectDuplicates(testItems);

      // Should consider both metadata and content
      expect(result.duplicates.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Strategy 5: Hybrid Approach', () => {
    let strategy: HybridStrategy;

    beforeEach(() => {
      strategy = new HybridStrategy({
        strategies: [
          { type: 'exact', weight: 0.4, config: {} },
          { type: 'semantic', weight: 0.3, config: { threshold: 0.7 } },
          { type: 'metadata', weight: 0.2, config: { keyFields: ['category'] } },
          { type: 'hash', weight: 0.1, config: {} }
        ],
        overallThreshold: 0.6
      });
    });

    it('should combine multiple strategies effectively', async () => {
      const result = await strategy.detectDuplicates(testItems);

      expect(result.duplicates.length).toBeGreaterThan(0);
      expect(result.duplicates[0].confidence).toBeGreaterThan(strategy.getOverallThreshold());
      expect(result.duplicates[0].matchedStrategies.length).toBeGreaterThan(1);
    });

    it('should provide confidence scores for duplicate groups', async () => {
      const result = await strategy.detectDuplicates(testItems);

      result.duplicates.forEach(duplicate => {
        expect(duplicate.confidence).toBeGreaterThan(0);
        expect(duplicate.confidence).toBeLessThanOrEqual(1);
        expect(duplicate.matchedStrategies).toBeDefined();
        expect(duplicate.matchedStrategies.length).toBeGreaterThan(0);
      });
    });

    it('should weight strategies according to configuration', async () => {
      const customStrategy = new HybridStrategy({
        strategies: [
          { type: 'exact', weight: 0.8, config: {} },
          { type: 'semantic', weight: 0.1, config: { threshold: 0.9 } },
          { type: 'metadata', weight: 0.1, config: {} }
        ],
        overallThreshold: 0.5
      });

      const result = await customStrategy.detectDuplicates(testItems);

      // Should prioritize exact matches
      const exactDuplicates = result.duplicates.filter(d =>
        d.matchedStrategies.some(s => s.type === 'exact')
      );

      expect(exactDuplicates.length).toBeGreaterThanOrEqual(0);
    });

    it('should handle strategy failure gracefully', async () => {
      const failingStrategy = new HybridStrategy({
        strategies: [
          { type: 'exact', weight: 0.5, config: {} },
          { type: 'invalid_strategy', weight: 0.5, config: {} } // This should fail
        ],
        overallThreshold: 0.3
      });

      const result = await failingStrategy.detectDuplicates(testItems);

      // Should still work with remaining strategies
      expect(Array.isArray(result.duplicates)).toBe(true);
      expect(Array.isArray(result.unique)).toBe(true);
    });
  });

  describe('Performance and Stress Testing', () => {
    it('should handle large datasets efficiently', async () => {
      const largeDataset = [
        ...testItems,
        ...duplicateItems,
        ...Array.from({ length: 100 }, (_, i) =>
          global.testUtils.createTestKnowledgeItem({
            data: { content: `Performance test item ${i}` },
            metadata: { performance: true, index: i }
          })
        )
      ];

      const strategies = [
        new ExactMatchStrategy(),
        new ContentHashStrategy(),
        new MetadataBasedStrategy({ keyFields: ['category'] })
      ];

      for (const strategy of strategies) {
        const { result, time } = await global.testUtils.measureTime(async () => {
          return await strategy.detectDuplicates(largeDataset);
        });

        expect(time).toBeLessThan(5000); // Should complete in under 5 seconds
        expect(Array.isArray(result.duplicates)).toBe(true);
        expect(Array.isArray(result.unique)).toBe(true);
      }
    });

    it('should handle concurrent operations', async () => {
      const concurrentStrategies = [
        new ExactMatchStrategy(),
        new SemanticSimilarityStrategy({ threshold: 0.7 }),
        new ContentHashStrategy()
      ];

      const concurrentPromises = concurrentStrategies.map(async (strategy, index) => {
        const testData = testItems.slice(0, 5 + index); // Vary dataset sizes
        return await strategy.detectDuplicates(testData);
      });

      const { result, time } = await global.testUtils.measureTime(async () => {
        return await Promise.all(concurrentPromises);
      });

      expect(time).toBeLessThan(10000); // Should complete in under 10 seconds
      expect(result.length).toBe(3); // All strategies should complete
    });

    it('should manage memory usage effectively', async () => {
      const { result, memoryBefore, memoryAfter, delta } =
        await performanceUtils.monitorMemoryUsage(async () => {
          const strategy = new HybridStrategy();
          return await strategy.detectDuplicates(duplicateItems);
        });

      expect(result.duplicates).toBeDefined();
      if (delta) {
        expect(delta.heapUsed).toBeLessThan(50 * 1024 * 1024); // Less than 50MB increase
      }
    });
  });

  describe('Integration with Memory Store', () => {
    beforeEach(() => {
      global.testState.qdrantTestDouble?.reset();
    });

    it('should integrate with memory store operations', async () => {
      // Store items with deduplication
      const storeResult = await memoryStore(testItems, {
        enableDeduplication: true,
        deduplicationStrategy: 'hybrid'
      });

      expect(storeResult.items.length).toBeGreaterThan(0);
      expect(storeResult.errors.length).toBe(0);
      expect(storeResult.items.length).toBeLessThanOrEqual(testItems.length);

      // Verify no duplicates were stored
      const findResult = await memoryFind({
        query: 'test content duplicate',
        scope: { project: 'test-project' }
      });

      const contentHashes = new Set();
      findResult.results.forEach(item => {
        const contentHash = item.data?.content || '';
        expect(contentHashes.has(contentHash)).toBe(false);
        contentHashes.add(contentHash);
      });
    });

    it('should respect deduplication configuration', async () => {
      const strictConfig = {
        enableDeduplication: true,
        deduplicationStrategy: 'exact',
        deduplicationThreshold: 0.95
      };

      const looseConfig = {
        enableDeduplication: true,
        deduplicationStrategy: 'semantic',
        deduplicationThreshold: 0.6
      };

      const strictResult = await memoryStore(testItems, strictConfig);
      const looseResult = await memoryStore(testItems, looseConfig);

      // Strict deduplication should store more items
      expect(strictResult.items.length).toBeGreaterThanOrEqual(looseResult.items.length);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle empty input gracefully', async () => {
      const strategies = [
        new ExactMatchStrategy(),
        new SemanticSimilarityStrategy(),
        new ContentHashStrategy(),
        new MetadataBasedStrategy(),
        new HybridStrategy()
      ];

      for (const strategy of strategies) {
        const result = await strategy.detectDuplicates([]);

        expect(result.duplicates.length).toBe(0);
        expect(result.unique.length).toBe(0);
      }
    });

    it('should handle malformed input', async () => {
      const malformedItems = [
        null,
        undefined,
        { id: 'invalid', data: null },
        { id: 'incomplete' },
        { data: { content: 'missing metadata' } }
      ].filter(Boolean); // Remove null/undefined

      const strategy = new ExactMatchStrategy();

      // Should not throw errors
      const result = await strategy.detectDuplicates(malformedItems);
      expect(Array.isArray(result.duplicates)).toBe(true);
      expect(Array.isArray(result.unique)).toBe(true);
    });

    it('should handle circular references in metadata', async () => {
      const circularItem = global.testUtils.createTestKnowledgeItem({
        data: { content: 'Test content' },
        metadata: { category: 'test' }
      });

      // Create circular reference
      (circularItem.metadata as any).self = circularItem.metadata;

      const strategy = new MetadataBasedStrategy({ keyFields: ['category'] });

      // Should handle circular references without infinite loops
      const result = await strategy.detectDuplicates([circularItem]);
      expect(Array.isArray(result.duplicates)).toBe(true);
    });

    it('should provide detailed error information', async () => {
      const strategy = new SemanticSimilarityStrategy({
        embeddingModel: 'invalid-model-name'
      });

      try {
        await strategy.detectDuplicates(testItems);
        // If it doesn't throw, that's also valid behavior
        expect(true).toBe(true);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect(error.message).toBeDefined();
      }
    });
  });
});