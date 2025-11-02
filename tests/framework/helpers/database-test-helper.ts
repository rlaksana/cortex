/**
 * Qdrant Test Helper
 *
 * Provides Qdrant collection setup, cleanup, and test data management
 * for isolated test environments.
 */

import { QdrantClient } from '@qdrant/js-client-rest';
import { qdrantConnectionManager } from '../../../src/db/pool';
import { qdrantSchemaManager } from '../../../src/db/schema';

/**
 * Qdrant test helper for managing test collections and data
 */
export class DatabaseTestHelper {
  private static testCollections: Set<string> = new Set();

  /**
   * Setup test environment with all required collections
   */
  static async setupTestEnvironment(client: QdrantClient): Promise<void> {
    // Create all collections for the 16 knowledge types
    await this.createKnowledgeCollections(client);

    // Create indexes for performance
    await this.createPerformanceIndexes(client);

    // Insert basic test data
    await this.seedBasicTestData(client);
  }

  /**
   * Create isolated test collection
   */
  static async setupTestCollection(collectionName: string): Promise<QdrantClient> {
    try {
      // Create the test collection
      await qdrantConnectionManager.getClient().createCollection(collectionName, {
        vectors: {
          size: 1536,
          distance: 'Cosine',
        },
        payload_schema: {
          type: 'object',
          properties: {
            test_id: { type: 'keyword' },
            created_at: { type: 'datetime' },
          },
        },
      });
      this.testCollections.add(collectionName);

      return qdrantConnectionManager.getClient();
    } catch (error) {
      throw new Error(`Failed to create test collection ${collectionName}: ${error}`);
    }
  }

  /**
   * Clean up test collection
   */
  static async cleanupTestCollection(collectionName: string): Promise<void> {
    try {
      await qdrantConnectionManager.getClient().deleteCollection(collectionName);
      this.testCollections.delete(collectionName);
    } catch (error) {
      console.warn(`Failed to cleanup test collection ${collectionName}:`, error);
    }
  }

  /**
   * Clean up all test collections
   */
  static async cleanupAllTestCollections(): Promise<void> {
    const cleanupPromises = Array.from(this.testCollections).map((collectionName) =>
      this.cleanupTestCollection(collectionName)
    );
    await Promise.allSettled(cleanupPromises);
    this.testCollections.clear();
  }

  /**
   * Create collections for all 16 knowledge types
   */
  private static async createKnowledgeCollections(client: QdrantClient): Promise<void> {
    const knowledgeTypes = [
      'entity',
      'relation',
      'observation',
      'section',
      'runbook',
      'change',
      'issue',
      'decision',
      'todo',
      'release_note',
      'ddl',
      'pr_context',
      'incident',
      'release',
      'risk',
      'assumption',
    ];

    for (const type of knowledgeTypes) {
      const collectionName = `test_${type}_${Date.now()}`;

      try {
        await client.createCollection(collectionName, {
          vectors: {
            size: 1536,
            distance: 'Cosine',
          },
          payload_schema: {
            type: 'object',
            properties: {
              knowledge_type: { type: 'keyword' },
              test_id: { type: 'keyword' },
              created_at: { type: 'datetime' },
              updated_at: { type: 'datetime' },
              tags: { type: 'array', items: { type: 'keyword' } },
            },
          },
        });
        this.testCollections.add(collectionName);
      } catch (error) {
        console.warn(`Failed to create test collection ${collectionName}:`, error);
      }
    }
  }

  /**
   * Create performance indexes for test collections
   */
  private static async createPerformanceIndexes(client: QdrantClient): Promise<void> {
    for (const collectionName of this.testCollections) {
      try {
        await client.createCollectionIndex(collectionName, {
          field_name: 'knowledge_type',
          field_schema: 'keyword',
        });

        await client.createCollectionIndex(collectionName, {
          field_name: 'test_id',
          field_schema: 'keyword',
        });

        await client.createCollectionIndex(collectionName, {
          field_name: 'created_at',
          field_schema: 'datetime',
        });
      } catch (error) {
        console.warn(`Failed to create indexes for ${collectionName}:`, error);
      }
    }
  }

  /**
   * Seed basic test data
   */
  private static async seedBasicTestData(client: QdrantClient): Promise<void> {
    const testData = {
      entity: [
        {
          id: 'test-entity-1',
          vector: Array(1536)
            .fill(0.1)
            .map((_, i) => Math.sin(i)),
          payload: {
            knowledge_type: 'entity',
            entity_type: 'test',
            name: 'Test Entity 1',
            test_id: 'test-run-1',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            tags: ['test', 'entity'],
          },
        },
      ],
      relation: [
        {
          id: 'test-relation-1',
          vector: Array(1536)
            .fill(0.2)
            .map((_, i) => Math.cos(i)),
          payload: {
            knowledge_type: 'relation',
            relation_type: 'test_relation',
            from_entity_type: 'test',
            to_entity_type: 'test',
            test_id: 'test-run-1',
            created_at: new Date().toISOString(),
            tags: ['test', 'relation'],
          },
        },
      ],
    };

    for (const [type, points] of Object.entries(testData)) {
      const collectionName = Array.from(this.testCollections).find((name) => name.includes(type));

      if (collectionName) {
        try {
          await client.upsert(collectionName, {
            points: points as any[],
          });
        } catch (error) {
          console.warn(`Failed to seed test data for ${collectionName}:`, error);
        }
      }
    }
  }

  /**
   * Get test collection names
   */
  static getTestCollections(): string[] {
    return Array.from(this.testCollections);
  }

  /**
   * Check if collection exists
   */
  static async collectionExists(collectionName: string): Promise<boolean> {
    try {
      const collections = await qdrantConnectionManager.getClient().getCollections();
      return collections.collections.some((c) => c.name === collectionName);
    } catch {
      return false;
    }
  }

  /**
   * Clear all data from test collections (but keep collections)
   */
  static async clearTestData(): Promise<void> {
    for (const collectionName of this.testCollections) {
      try {
        // Delete all points from the collection
        await qdrantConnectionManager.getClient().delete(collectionName, {
          filter: {
            must: [{ key: 'test_id', match: { value: 'test-run-1' } }],
          },
        });
      } catch (error) {
        console.warn(`Failed to clear test data from ${collectionName}:`, error);
      }
    }
  }

  /**
   * Initialize test environment
   */
  static async initialize(): Promise<void> {
    await qdrantConnectionManager.initialize();
  }

  /**
   * Shutdown test environment
   */
  static async shutdown(): Promise<void> {
    await this.cleanupAllTestCollections();
    await qdrantConnectionManager.shutdown();
  }
}
