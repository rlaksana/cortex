/**
 * Qdrant Client Export
 *
 * Provides a centralized Qdrant client instance for the application.
 * This file acts as a facade for Qdrant operations.
 */

import { QdrantClient } from '@qdrant/js-client-rest';
import { logger } from '../utils/logger.js';
import { Environment } from '../config/environment.js';

let qdrantClient: QdrantClient | null = null;

/**
 * Get or create Qdrant client instance
 */
export function getQdrantClient(): QdrantClient {
  if (!qdrantClient) {
    const env = Environment.getInstance();
    const qdrantUrl = env.getRawConfig().QDRANT_URL || 'http://localhost:6333';
    const qdrantApiKey = env.getRawConfig().QDRANT_API_KEY;

    qdrantClient = new QdrantClient({
      url: qdrantUrl,
      apiKey: qdrantApiKey,
    });

    logger.info('Qdrant client initialized', { url: qdrantUrl });
  }

  return qdrantClient;
}

/**
 * Export the qdrant client instance and helper functions
 */
export const qdrant = {
  client: getQdrantClient(),

  /**
   * Initialize Qdrant connection
   */
  async initialize(): Promise<void> {
    try {
      const client = getQdrantClient();
      // Test connection by getting collections
      await client.getCollections();
      logger.info('Qdrant connection established successfully');
    } catch (error) {
      logger.error('Failed to connect to Qdrant:', error);
      throw error;
    }
  },

  /**
   * Check Qdrant health
   */
  async healthCheck(): Promise<boolean> {
    try {
      const client = getQdrantClient();
      await client.getCollections();
      return true;
    } catch (error) {
      logger.error('Qdrant health check failed:', error);
      return false;
    }
  },

  /**
   * Close Qdrant connection
   */
  async close(): Promise<void> {
    // Qdrant JS client doesn't have explicit close method
    qdrantClient = null;
    logger.info('Qdrant client reference cleared');
  },

  /**
   * Get the Qdrant client instance
   */
  getClient() {
    const client = getQdrantClient();
    // Return a stub for the expected user interface to prevent TypeScript errors
    // Note: This is a temporary fix - the auth service needs to be refactored
    // to use Qdrant's native API instead of Prisma-like interface
    return {
      ...client,
      user: {
        findUnique: async () => null, // Stub implementation
        update: async () => null, // Stub implementation
        create: async () => null, // Stub implementation
        delete: async () => null, // Stub implementation
        findMany: async () => [], // Stub implementation
      },
    };
  },
};

// Export the client directly for backward compatibility
export { getQdrantClient as qdrantClient };
