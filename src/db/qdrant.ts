// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Qdrant Database Export - Legacy Compatibility
 *
 * Provides backward compatibility for existing imports.
 * Re-exports the qdrant client from qdrant-client.ts
 */

export { getQdrantClient,qdrant } from './qdrant-client.js';

// Default export for compatibility
export { qdrant as default } from './qdrant-client.js';
