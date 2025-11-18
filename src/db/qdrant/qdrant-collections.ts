import { type QdrantClient } from '@qdrant/js-client-rest';

interface CollectionConfig {
  vectors: {
    size: number;
    distance: 'Cosine' | 'Euclid' | 'Dot' | 'Manhattan';
  };
  sparse_vectors?: Record<string, { index: { type: string } }>;
  timeout?: number;
}

export async function createCollection(
  client: QdrantClient,
  name: string,
  config: CollectionConfig
) {
  return client.createCollection(name, config);
}

export async function ensureCollection(
  client: QdrantClient,
  name: string,
  config: CollectionConfig
) {
  const collections = await client.getCollections();
  const exists = collections.collections.some((c) => c.name === name);
  if (!exists) {
    await client.createCollection(name, config);
  }
}
