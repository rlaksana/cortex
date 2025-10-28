/**
 * Qdrant Database Export - Legacy Compatibility
 *
 * Provides backward compatibility for existing imports.
 * Re-exports the qdrant client from qdrant-client.ts
 */

export { qdrant, getQdrantClient } from './qdrant-client';

// Default export for compatibility
export { qdrant as default } from './qdrant-client';
