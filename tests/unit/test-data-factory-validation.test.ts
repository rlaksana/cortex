/**
 * Test Data Factory Validation
 *
 * Validates that the test data factory generates valid test data
 * for all 16 knowledge types across all scenarios
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { VectorDatabase } from '../../src/index.js';

// Mock Qdrant client for testing
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor() {
      this.getCollections = vi.fn().mockResolvedValue({
        collections: [{ name: 'test-collection' }]
      });
    }
    getCollection = vi.fn().mockResolvedValue({});
    createCollection = vi.fn().mockResolvedValue({});
    deleteCollection = vi.fn().mockResolvedValue({});
    upsert = vi.fn().mockResolvedValue({ status: 'completed' });
    search = vi.fn().mockResolvedValue([]);
    scroll = vi.fn().mockResolvedValue({ result: [] });
    count = vi.fn().mockResolvedValue({ count: 0 });
  }
}));

import {
  KNOWLEDGE_TYPES,
  generateMinimalItem,
  generateCompleteItem,
  generateCompleteItems,
  generateScopedItems,
  generateEdgeCaseItems,
  generateSearchTestData,
  validateTestItem,
  getRandomKnowledgeType,
  generateRandomItem
} from '../fixtures/test-data-factory.js';

describe('Test Data Factory Validation', () => {
  let db: VectorDatabase;

  beforeEach(() => {
    db = new VectorDatabase();
  });

  describe('Knowledge Type Coverage', () => {
    it('should have all 16 required knowledge types', () => {
      expect(KNOWLEDGE_TYPES).toHaveLength(16);
      expect(KNOWLEDGE_TYPES).toContain('entity');
      expect(KNOWLEDGE_TYPES).toContain('relation');
      expect(KNOWLEDGE_TYPES).toContain('observation');
      expect(KNOWLEDGE_TYPES).toContain('section');
      expect(KNOWLEDGE_TYPES).toContain('runbook');
      expect(KNOWLEDGE_TYPES).toContain('change');
      expect(KNOWLEDGE_TYPES).toContain('issue');
      expect(KNOWLEDGE_TYPES).toContain('decision');
      expect(KNOWLEDGE_TYPES).toContain('todo');
      expect(KNOWLEDGE_TYPES).toContain('release_note');
      expect(KNOWLEDGE_TYPES).toContain('ddl');
      expect(KNOWLEDGE_TYPES).toContain('pr_context');
      expect(KNOWLEDGE_TYPES).toContain('incident');
      expect(KNOWLEDGE_TYPES).toContain('release');
      expect(KNOWLEDGE_TYPES).toContain('risk');
      expect(KNOWLEDGE_TYPES).toContain('assumption');
    });

    it('should generate valid minimal items for all knowledge types', () => {
      for (const type of KNOWLEDGE_TYPES) {
        const item = generateMinimalItem(type);
        const validation = validateTestItem(item);

        expect(validation.valid).toBe(true);
        expect(validation.errors).toHaveLength(0);
        expect(item.kind).toBe(type);
        expect(item.content).toBeDefined();
        expect(typeof item.content).toBe('string');
      }
    });

    it('should generate valid complete items for all knowledge types', () => {
      for (const type of KNOWLEDGE_TYPES) {
        const item = generateCompleteItem(type);
        const validation = validateTestItem(item);

        expect(validation.valid).toBe(true);
        expect(validation.errors).toHaveLength(0);
        expect(item.kind).toBe(type);
        expect(item.content).toBeDefined();
        expect(item.metadata).toBeDefined();
        expect(item.scope).toBeDefined();
      }
    });
  });

  describe('Batch Generation Functions', () => {
    it('should generate minimal items for all knowledge types', () => {
      const items = KNOWLEDGE_TYPES.map(type => generateMinimalItem(type));

      expect(items).toHaveLength(16);

      for (let i = 0; i < KNOWLEDGE_TYPES.length; i++) {
        expect(items[i].kind).toBe(KNOWLEDGE_TYPES[i]);
        expect(validateTestItem(items[i]).valid).toBe(true);
      }
    });

    it('should generate complete items for all knowledge types', () => {
      const items = generateCompleteItems();

      expect(items).toHaveLength(16);

      for (let i = 0; i < KNOWLEDGE_TYPES.length; i++) {
        expect(items[i].kind).toBe(KNOWLEDGE_TYPES[i]);
        expect(validateTestItem(items[i]).valid).toBe(true);
        expect(items[i].metadata).toBeDefined();
        expect(items[i].scope).toBeDefined();
      }
    });

    it('should generate scoped items correctly', () => {
      const projectOnlyItems = generateScopedItems('project-only').slice(0, 3);
      const branchOnlyItems = generateScopedItems('branch-only').slice(0, 3);
      const orgOnlyItems = generateScopedItems('org-only').slice(0, 3);
      const completeItems = generateScopedItems('complete').slice(0, 3);

      // Test project-only scope
      for (const item of projectOnlyItems) {
        expect(item.scope?.project).toBeDefined();
        expect(item.scope?.branch).toBeUndefined();
        expect(item.scope?.org).toBeUndefined();
        expect(validateTestItem(item).valid).toBe(true);
      }

      // Test branch-only scope
      for (const item of branchOnlyItems) {
        expect(item.scope?.project).toBeUndefined();
        expect(item.scope?.branch).toBeDefined();
        expect(item.scope?.org).toBeUndefined();
        expect(validateTestItem(item).valid).toBe(true);
      }

      // Test org-only scope
      for (const item of orgOnlyItems) {
        expect(item.scope?.project).toBeUndefined();
        expect(item.scope?.branch).toBeUndefined();
        expect(item.scope?.org).toBeDefined();
        expect(validateTestItem(item).valid).toBe(true);
      }

      // Test complete scope
      for (const item of completeItems) {
        expect(item.scope?.project).toBeDefined();
        expect(item.scope?.branch).toBeDefined();
        expect(item.scope?.org).toBeDefined();
        expect(validateTestItem(item).valid).toBe(true);
      }
    });
  });

  describe('Search Test Data', () => {
    it('should generate valid search test data', () => {
      const items = generateSearchTestData();

      expect(items.length).toBeGreaterThan(0);
      expect(Array.isArray(items)).toBe(true);

      for (const item of items) {
        expect(validateTestItem(item).valid).toBe(true);
        expect(item.content).toBeDefined();
        expect(typeof item.content).toBe('string');
      }
    });
  });

  describe('Edge Cases', () => {
    it('should generate valid edge case items', () => {
      const items = generateEdgeCaseItems();

      expect(items.length).toBeGreaterThan(0);

      // Some edge cases are intentionally invalid, but the generator should handle them
      const validItems = items.filter(item => validateTestItem(item).valid);
      const invalidItems = items.filter(item => !validateTestItem(item).valid);

      expect(validItems.length).toBeGreaterThan(0);
      expect(invalidItems.length).toBeGreaterThan(0);
    });
  });

  describe('Random Generation', () => {
    it('should generate random knowledge type', () => {
      const randomType = getRandomKnowledgeType();

      expect(KNOWLEDGE_TYPES).toContain(randomType);
      expect(typeof randomType).toBe('string');
    });

    it('should generate random item', () => {
      const randomItem = generateRandomItem(false); // minimal
      const validation = validateTestItem(randomItem);

      expect(validation.valid).toBe(true);
      expect(KNOWLEDGE_TYPES).toContain(randomItem.kind);
    });

    it('should generate random complete item', () => {
      const randomItem = generateRandomItem(true); // complete
      const validation = validateTestItem(randomItem);

      expect(validation.valid).toBe(true);
      expect(KNOWLEDGE_TYPES).toContain(randomItem.kind);
      expect(randomItem.metadata).toBeDefined();
      expect(randomItem.scope).toBeDefined();
    });
  });

  describe('Storage Validation', () => {
    it('should successfully store all minimal items', async () => {
      const items = KNOWLEDGE_TYPES.map(type => generateMinimalItem(type));
      const result = await db.storeItems(items);

      expect(result.errors).toHaveLength(0);
      expect(result.stored).toHaveLength(16);

      // Verify each item was stored with correct type
      for (let i = 0; i < items.length; i++) {
        expect(result.stored[i].kind).toBe(items[i].kind);
        expect(result.stored[i].id).toBeDefined();
      }
    });

    it('should successfully store all complete items', async () => {
      const items = generateCompleteItems();
      const result = await db.storeItems(items);

      expect(result.errors).toHaveLength(0);
      expect(result.stored).toHaveLength(16);

      // Verify metadata and scope are preserved
      for (const stored of result.stored) {
        expect(stored.metadata).toBeDefined();
        expect(stored.scope).toBeDefined();
      }
    });

    it('should handle scoped items correctly', async () => {
      const items = [
        ...generateScopedItems('project-only').slice(0, 2),
        ...generateScopedItems('branch-only').slice(0, 2),
        ...generateScopedItems('org-only').slice(0, 2),
        ...generateScopedItems('complete').slice(0, 2)
      ];

      const result = await db.storeItems(items);

      expect(result.errors).toHaveLength(0);
      expect(result.stored).toHaveLength(8);

      // Verify different scope types are preserved
      const scopes = result.stored.map(item => item.scope);
      expect(scopes).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ project: expect.any(String) }),
          expect.objectContaining({ branch: expect.any(String) }),
          expect.objectContaining({ org: expect.any(String) }),
          expect.objectContaining({
            project: expect.any(String),
            branch: expect.any(String),
            org: expect.any(String)
          })
        ])
      );
    });

    it('should handle search test data correctly', async () => {
      const items = generateSearchTestData();
      const result = await db.storeItems(items);

      expect(result.errors).toHaveLength(0);
      expect(result.stored).toHaveLength(items.length);

      // Test search functionality
      for (const item of items) {
        const searchResult = await db.searchItems(item.content.substring(0, 5));
        expect(searchResult.items).toBeDefined();
        expect(Array.isArray(searchResult.items)).toBe(true);
      }
    });
  });

  describe('Test Data Factory Statistics', () => {
    it('should report comprehensive test coverage', () => {
      console.log('📊 Test Data Factory Statistics:');
      console.log(`   Knowledge Types: ${KNOWLEDGE_TYPES.length}`);
      console.log(`   Minimal Items Generated: ${KNOWLEDGE_TYPES.length}`);
      console.log(`   Complete Items Generated: ${generateCompleteItems().length}`);
      console.log(`   Search Test Items: ${generateSearchTestData().length}`);
      console.log(`   Edge Case Items: ${generateEdgeCaseItems().length}`);

      // Test that we can generate a large number of items without issues
      const stressTestItems = Array.from({ length: 100 }, (_, i) =>
        generateRandomItem(false)
      );

      expect(stressTestItems).toHaveLength(100);
      console.log(`   Stress Test Items: ${stressTestItems.length}`);

      console.log('✅ Test Data Factory fully operational!');
      console.log('🚀 Ready for comprehensive MCP Cortex testing!');
    });
  });
});