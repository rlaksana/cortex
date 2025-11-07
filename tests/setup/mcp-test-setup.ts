/**
 * MCP Test Environment Setup
 *
 * This file sets up the test environment for MCP server testing.
 * It provides mock Qdrant client, test data, and helper utilities.
 */

import { beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { QdrantClient } from '@qdrant/js-client-rest';

// Test environment variables
process.env.NODE_ENV = 'test';
process.env.QDRANT_URL = process.env.QDRANT_URL || 'http://localhost:6333';
process.env.QDRANT_COLLECTION_NAME = `test-cortex-memory-${Date.now()}`;

// Mock Qdrant client for testing
export class MockQdrantClient {
  private collections = new Map<string, any>();
  private points = new Map<string, any[]>();

  async getCollection(collectionName: string) {
    const collection = this.collections.get(collectionName);
    if (!collection) {
      throw new Error(`Collection ${collectionName} not found`);
    }
    return {
      points_count: this.points.get(collectionName)?.length || 0,
      ...collection
    };
  }

  async createCollection(collectionName: string, config: any) {
    this.collections.set(collectionName, {
      name: collectionName,
      config,
      created_at: new Date().toISOString()
    });
    this.points.set(collectionName, []);
  }

  async upsert(collectionName: string, points: any) {
    if (!this.points.has(collectionName)) {
      this.points.set(collectionName, []);
    }

    const collectionPoints = this.points.get(collectionName);

    for (const point of points.points) {
      const existingIndex = collectionPoints.findIndex((p: any) => p.id === point.id);
      if (existingIndex >= 0) {
        collectionPoints[existingIndex] = point;
      } else {
        collectionPoints.push(point);
      }
    }
  }

  async search(collectionName: string, params: any) {
    const collectionPoints = this.points.get(collectionName) || [];

    // Simple mock search - return all points that match filter
    let filteredPoints = collectionPoints;

    if (params.filter) {
      filteredPoints = collectionPoints.filter((point: any) => {
        return this.matchesFilter(point.payload, params.filter);
      });
    }

    const results = filteredPoints
      .slice(0, params.limit || 10)
      .map((point: any) => ({
        id: point.id,
        score: Math.random(), // Mock similarity score
        payload: params.with_payload ? point.payload : undefined
      }));

    return results;
  }

  private matchesFilter(payload: any, filter: any): boolean {
    // Simple filter implementation for testing
    if (!filter || !filter.must) return true;

    return filter.must.every((condition: any) => {
      if (condition.key && condition.match) {
        const value = this.getNestedValue(payload, condition.key);
        if (condition.match.any) {
          return condition.match.any.includes(value);
        }
        if (condition.match.value !== undefined) {
          return value === condition.match.value;
        }
      }
      return true;
    });
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => current?.[key], obj);
  }

  async deleteCollection(collectionName: string) {
    this.collections.delete(collectionName);
    this.points.delete(collectionName);
  }
}

// Global test utilities
export class TestUtils {
  static generateTestMemoryItem(type: string = 'entity', data: any = {}) {
    return {
      kind: type,
      data: {
        title: `Test ${type}`,
        description: `Test ${type} description`,
        created_at: new Date().toISOString(),
        ...data
      },
      scope: {
        project: 'test-project',
        branch: 'test-branch',
        org: 'test-org'
      }
    };
  }

  static generateBatchTestItems(count: number = 5) {
    const items = [];
    const types = ['entity', 'relation', 'observation', 'decision', 'todo'];

    for (let i = 0; i < count; i++) {
      const type = types[i % types.length];
      items.push(this.generateTestMemoryItem(type, { index: i }));
    }

    return items;
  }

  static async sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  static createTestServerRequest(toolName: string, args: any = {}) {
    return {
      jsonrpc: '2.0' as const,
      id: Math.random().toString(36).substring(7),
      method: 'tools/call' as const,
      params: {
        name: toolName,
        arguments: args
      }
    };
  }

  static async withTimeout<T>(promise: Promise<T>, timeoutMs: number = 30000): Promise<T> {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(`Operation timed out after ${timeoutMs}ms`)), timeoutMs);
    });

    return Promise.race([promise, timeoutPromise]);
  }
}

// Test environment lifecycle
let mockQdrantClient: MockQdrantClient;

beforeAll(async () => {
  // Initialize mock Qdrant client
  mockQdrantClient = new MockQdrantClient();

  // Override the QdrantClient constructor for testing
  global.MockQdrantClient = MockQdrantClient;

  console.log('🧪 MCP Test environment initialized');
});

afterAll(async () => {
  // Cleanup test collections
  if (mockQdrantClient) {
    // Clean up any test collections
    console.log('🧹 MCP Test environment cleaned up');
  }
});

beforeEach(async () => {
  // Reset test state before each test
  console.log('🔄 Test case setup completed');
});

afterEach(async () => {
  // Cleanup after each test
  console.log('✅ Test case cleanup completed');
});

// Export for use in test files
export { mockQdrantClient };

// Type declarations for global test helpers
declare global {
  var MockQdrantClient: typeof MockQdrantClient;
}