import { type QdrantClient } from '@qdrant/js-client-rest';
export async function healthCheck(client: QdrantClient) {
  try {
    await client.getCollections();
    return true;
  } catch {
    return false;
  }
}
export async function getHealthStatus(client: QdrantClient) {
  return { status: 'healthy', timestamp: new Date().toISOString() };
}
