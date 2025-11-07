/**
 * Global Test Setup for CI Environment
 *
 * This file sets up the global test environment for CI/CD pipelines.
 * It initializes test databases, mocks external services, and ensures
 * a clean, predictable testing environment.
 */

import { vi } from 'vitest';
import { randomUUID } from 'crypto';

// Global test configuration
declare global {
  var __CI__: string;
  var __TEST_ENV__: string;
  var __MOCK_EXTERNAL_SERVICES__: string;
}

export interface GlobalTestContext {
  testDatabase: any;
  mockEmbeddings: any;
  mockQdrant: any;
  testStartTime: number;
  testRunId: string;
}

/**
 * Global setup function called once before all tests
 */
export default async function setup(): Promise<GlobalTestContext> {
  console.log('🧪 Setting up CI test environment...');

  const testRunId = randomUUID();
  const testStartTime = Date.now();

  // Set global environment
  process.env['NODE_ENV'] = 'test';
  process.env['CI'] = 'true';
  process.env['TEST_RUN_ID'] = testRunId;

  // Mock external services by default
  if (process.env['__MOCK_EXTERNAL_SERVICES__'] === 'true') {
    await setupExternalServiceMocks();
  }

  // Initialize test database (in-memory for CI)
  const testDatabase = await setupTestDatabase();

  // Initialize mock embedding service
  const mockEmbeddings = await setupMockEmbeddings();

  // Initialize mock Qdrant
  const mockQdrant = await setupMockQdrant();

  console.log('✅ CI test environment setup completed');

  return {
    testDatabase,
    mockEmbeddings,
    mockQdrant,
    testStartTime,
    testRunId,
  };
}

/**
 * Mock external services for CI testing
 */
async function setupExternalServiceMocks(): Promise<void> {
  // Mock environment variables
  vi.stubEnv('QDRANT_URL', 'http://localhost:6333');
  vi.stubEnv('QDRANT_API_KEY', 'test-api-key');
  vi.stubEnv('EMBEDDING_SERVICE_URL', 'http://localhost:11434');
  vi.stubEnv('REDIS_URL', 'redis://localhost:6379');

  // Mock console methods to reduce noise in CI logs
  const originalConsole = { ...console };
  console.debug = vi.fn();
  console.trace = vi.fn();

  // Restore console on teardown
  return () => {
    Object.assign(console, originalConsole);
  };
}

/**
 * Setup in-memory test database
 */
async function setupTestDatabase(): Promise<any> {
  // This would create an in-memory database instance
  // For now, return a mock implementation
  return {
    connect: vi.fn().mockResolvedValue(true),
    disconnect: vi.fn().mockResolvedValue(true),
    query: vi.fn(),
    insert: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  };
}

/**
 * Setup mock embedding service
 */
async function setupMockEmbeddings(): Promise<any> {
  // Generate consistent mock embeddings
  const generateMockEmbedding = (text: string): number[] => {
    // Create deterministic embeddings based on text hash
    const hash = Array.from(text).reduce((acc, char) => acc + char.charCodeAt(0), 0);
    const embedding = [];
    for (let i = 0; i < 1536; i++) {
      embedding.push(Math.sin((hash + i) * 0.1) * 0.5 + 0.5);
    }
    return embedding;
  };

  return {
    generateEmbedding: vi.fn().mockImplementation((text: string) =>
      Promise.resolve({
        vector: generateMockEmbedding(text),
        dimensions: 1536,
        model: 'test-model',
      })
    ),
    generateBatchEmbeddings: vi.fn().mockImplementation((texts: string[]) =>
      Promise.resolve({
        vectors: texts.map(generateMockEmbedding),
        dimensions: 1536,
        model: 'test-model',
      })
    ),
  };
}

/**
 * Setup mock Qdrant client
 */
async function setupMockQdrant(): Promise<any> {
  const mockCollections = new Map();

  return {
    getCollections: vi.fn().mockResolvedValue({
      collections: [],
    }),
    createCollection: vi.fn().mockImplementation((name: string, config: any) => {
      mockCollections.set(name, {
        name,
        config,
        points: [],
      });
      return Promise.resolve();
    }),
    deleteCollection: vi.fn().mockImplementation((name: string) => {
      mockCollections.delete(name);
      return Promise.resolve();
    }),
    upsert: vi.fn().mockImplementation((collectionName: string, points: any[]) => {
      const collection = mockCollections.get(collectionName);
      if (collection) {
        points.forEach((point) => {
          collection.points.push(point);
        });
      }
      return Promise.resolve({ status: 'completed' });
    }),
    search: vi.fn().mockImplementation((collectionName: string, query: any) => {
      const collection = mockCollections.get(collectionName);
      if (collection && collection.points.length > 0) {
        return Promise.resolve({
          points: collection.points.slice(0, query.limit || 10),
        });
      }
      return Promise.resolve({ points: [] });
    }),
    retrieve: vi.fn().mockImplementation((collectionName: string, ids: string[]) => {
      const collection = mockCollections.get(collectionName);
      if (collection) {
        const points = collection.points.filter((point: any) => ids.includes(point.id));
        return Promise.resolve(points);
      }
      return Promise.resolve([]);
    }),
    delete: vi.fn().mockImplementation((collectionName: string, ids: string[]) => {
      const collection = mockCollections.get(collectionName);
      if (collection) {
        collection.points = collection.points.filter((point: any) => !ids.includes(point.id));
      }
      return Promise.resolve({ status: 'completed' });
    }),
  };
}

/**
 * Global teardown function called after all tests
 */
export async function teardown(context: GlobalTestContext): Promise<void> {
  console.log('🧹 Tearing down CI test environment...');

  const duration = Date.now() - context.testStartTime;
  console.log(`⏱️  Test run completed in ${duration}ms (ID: ${context.testRunId})`);

  // Cleanup test database
  if (context.testDatabase?.disconnect) {
    await context.testDatabase.disconnect();
  }

  // Clear all mocks
  vi.clearAllMocks();

  console.log('✅ CI test environment teardown completed');
}
