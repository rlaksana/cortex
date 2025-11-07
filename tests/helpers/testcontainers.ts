import { QdrantClient } from '@qdrant/js-client-rest';
import { GenericContainer, StartedTestContainer } from 'testcontainers';
import { qdrantConnectionManager } from '../../src/db/pool';
import { qdrantSchemaManager } from '../../src/db/schema';
import { qdrantMigrationManager } from '../../src/db/migrate';

export async function getTestContainer(): Promise<{
  client: QdrantClient;
  cleanup: () => Promise<void>;
}> {
  // Start Qdrant container for testing
  const container = await new GenericContainer('qdrant/qdrant:latest')
    .withExposedPorts(6333, 6334)
    .withEnvironment({
      QDRANT__SERVICE__HTTP_PORT: '6333',
      QDRANT__SERVICE__GRPC_PORT: '6334',
    })
    .start();

  const host = container.getHost();
  const httpPort = container.getMappedPort(6333);
  const grpcPort = container.getMappedPort(6334);

  // Configure connection to test container
  process.env['QDRANT_URL'] = `http://${host}:${httpPort}`;
  process.env['QDRANT_TIMEOUT'] = '30000';

  try {
    // Initialize Qdrant connection
    await qdrantConnectionManager.initialize();

    // Initialize schema collections
    await qdrantSchemaManager.initializeCollections();

    // Run any pending migrations
    await qdrantMigrationManager.migrate();

    const client = qdrantConnectionManager.getClient();

    return {
      client,
      cleanup: async () => {
        try {
          // Clean up test collections
          const collections = await client.getCollections();
          for (const collection of collections.collections) {
            if (collection.name.startsWith('test_')) {
              await client.deleteCollection(collection.name);
            }
          }
        } catch (error) {
          console.warn('Error cleaning up test collections:', error);
        }

        await qdrantConnectionManager.shutdown();
        await container.stop();
      },
    };
  } catch (error) {
    await container.stop();
    throw error;
  }
}

export async function getTestClient(): Promise<QdrantClient> {
  // For tests that don't need a full container, use in-memory or mock Qdrant
  const client = new QdrantClient({
    url: process.env['QDRANT_URL'] || 'http://localhost:6333',
    timeout: 30000,
  });

  try {
    // Test connectivity
    await client.getCollections();
    return client;
  } catch (error) {
    console.warn('Qdrant not available for testing, using mock client');
    // Return a mock client for tests that don't require real Qdrant
    return createMockQdrantClient();
  }
}

function createMockQdrantClient(): QdrantClient {
  // Basic mock implementation for testing without Qdrant
  const mockClient = {
    async getCollections() {
      return { collections: [] };
    },
    async createCollection(name: string, config: any) {
      // Mock implementation
      console.log(`Mock: Creating collection ${name}`);
    },
    async deleteCollection(name: string) {
      // Mock implementation
      console.log(`Mock: Deleting collection ${name}`);
    },
    async upsert(collection: string, points: any) {
      // Mock implementation
      console.log(`Mock: Upserting points to ${collection}`);
    },
    async search(collection: string, params: any) {
      // Mock implementation
      return { result: [] };
    },
    async delete(collection: string, params: any) {
      // Mock implementation
      console.log(`Mock: Deleting points from ${collection}`);
    },
    async createCollectionIndex(collection: string, index: any) {
      // Mock implementation
      console.log(`Mock: Creating index on ${collection}`);
    },
  } as any;

  return mockClient;
}
