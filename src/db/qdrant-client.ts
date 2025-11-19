/**
 * Qdrant Client Export
 *
 * Provides a centralized Qdrant client instance for the application.
 * This file acts as a facade for Qdrant operations.
 */

import { QdrantClient } from '@qdrant/js-client-rest';

import { logger } from '@/utils/logger.js';

import { Environment } from '../config/environment.js';
import { asEnhancedQdrantClient } from '@/types/database-extensions.js';

let qdrantClient: QdrantClient | null = null;

// Define proper types for knowledge operations
export interface KnowledgeMethod<T = unknown> {
  findMany: () => Promise<T[]>;
  findOne: (id: string) => Promise<T | null>;
  create: (data: T) => Promise<T>;
  update: (id: string, data: Partial<T>) => Promise<T>;
  delete: (id: string) => Promise<boolean>;
}

// Define interfaces for different knowledge types
export interface AuditData {
  id: string;
  timestamp: string;
  event: string;
  details: Record<string, unknown>;
}

export interface AuthData {
  id: string;
  token: string;
  permissions: string[];
  expiresAt?: string;
}

export interface KnowledgeData {
  id: string;
  type: string;
  content: Record<string, unknown>;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

// Enhanced client with proper typing support

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
      ...(qdrantApiKey && { apiKey: qdrantApiKey }),
    });

    logger.info('Qdrant client initialized', { url: qdrantUrl });

    // Use enhanced client with proper typing if available
    try {
      const enhancedClient = asEnhancedQdrantClient(qdrantClient);
      Object.assign(qdrantClient, enhancedClient);
    } catch (error) {
      logger.warn('Failed to enhance Qdrant client, using base client', { error });
    }
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
   * Get the Qdrant client instance with enhanced typing
   */
  getClient(): QdrantClient {
    const client = getQdrantClient();
    // Return enhanced client with proper typing
    try {
      return asEnhancedQdrantClient(client);
    } catch (error) {
      logger.warn('Failed to enhance client, returning base client', { error });
      return client;
    }
  },
};

// Export the client directly for backward compatibility
export { getQdrantClient as qdrantClient };
