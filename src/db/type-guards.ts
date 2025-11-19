/**
 * Database Type Guards
 *
 * Provides type guard functions and runtime validation for database configurations
 * to ensure type safety without unknown casting.
 */

import type { VectorConfig } from './interfaces/vector-adapter.interface.js';
import type { DatabaseFactoryConfig } from './interfaces/database-factory.interface.js';
import type { DatabaseManagerConfig } from './database-manager.js';

/**
 * Type guard for VectorConfig
 */
export function isVectorConfig(obj: unknown): obj is VectorConfig {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const config = obj as Record<string, unknown>;

  return (
    typeof config.type === 'string' &&
    ['qdrant', 'weaviate', 'pinecone', 'milvus'].includes(config.type) &&
    typeof config.size === 'number' &&
    typeof config.embeddingModel === 'string' &&
    typeof config.batchSize === 'number'
  );
}

/**
 * Type guard for DatabaseFactoryConfig
 */
export function isDatabaseFactoryConfig(obj: unknown): obj is DatabaseFactoryConfig {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const config = obj as Record<string, unknown>;

  return (
    typeof config.type === 'string' &&
    ['qdrant'].includes(config.type) &&
    (config.qdrant === undefined || isVectorConfig(config.qdrant))
  );
}

/**
 * Type guard for DatabaseManagerConfig
 */
export function isDatabaseManagerConfig(obj: unknown): obj is DatabaseManagerConfig {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const config = obj as Record<string, unknown>;

  return (
    typeof config.enableVectorOperations === 'boolean' &&
    typeof config.enableFallback === 'boolean' &&
    config.qdrant !== undefined &&
    typeof config.qdrant === 'object' &&
    config.qdrant !== null &&
    typeof (config.qdrant as Record<string, unknown>).url === 'string' &&
    typeof (config.qdrant as Record<string, unknown>).timeout === 'number'
  );
}

/**
 * Safe accessor for VectorConfig properties
 */
export function getVectorConfigProperty<T extends keyof VectorConfig>(
  config: unknown,
  property: T,
  defaultValue: VectorConfig[T]
): VectorConfig[T] {
  if (!isVectorConfig(config)) {
    return defaultValue;
  }

  return config[property] ?? defaultValue;
}

/**
 * Safe accessor for nested qdrant config
 */
export function getQdrantNestedConfig(config: VectorConfig): {
  url: string;
  apiKey?: string;
  timeout?: number;
} {
  return {
    url: config.url || config.qdrant?.url || 'http://localhost:6333',
    apiKey: config.apiKey || config.qdrant?.apiKey,
    timeout: config.timeout || config.qdrant?.timeout || 30000,
  };
}

/**
 * Validate and normalize VectorConfig
 */
export function validateVectorConfig(config: unknown): VectorConfig {
  if (!isVectorConfig(config)) {
    throw new Error('Invalid VectorConfig provided');
  }

  // Ensure required properties have valid values
  const normalizedConfig: VectorConfig = {
    type: config.type,
    size: config.size > 0 ? config.size : 1536,
    vectorSize: config.vectorSize || config.size || 1536,
    embeddingModel: config.embeddingModel || 'text-embedding-3-small',
    batchSize: config.batchSize > 0 ? config.batchSize : 10,
    distance: config.distance || 'Cosine',
    url: config.url || 'http://localhost:6333',
    logQueries: config.logQueries || false,
    connectionTimeout: config.connectionTimeout || 30000,
    maxConnections: config.maxConnections || 10,
    maxRetries: config.maxRetries || 3,
    timeout: config.timeout || 30000,
    dimensions: config.dimensions || config.size || 1536,
    distanceMetric: config.distanceMetric || config.distance || 'Cosine',
    collectionName: config.collectionName || 'knowledge',
    // Preserve optional properties
    ...(config.apiKey && { apiKey: config.apiKey }),
    ...(config.openaiApiKey && { openaiApiKey: config.openaiApiKey }),
    ...(config.host && { host: config.host }),
    ...(config.port && { port: config.port }),
    ...(config.database && { database: config.database }),
    ...(config.qdrant && { qdrant: config.qdrant }),
    ...(config.vectorSize !== undefined && { vectorSize: config.vectorSize }),
  };

  return normalizedConfig;
}

/**
 * Create a type-safe VectorConfig from partial configuration
 */
export function createVectorConfig(partial: Partial<VectorConfig>): VectorConfig {
  const defaults: VectorConfig = {
    type: 'qdrant',
    size: 1536,
    vectorSize: 1536,
    embeddingModel: 'text-embedding-3-small',
    batchSize: 10,
    distance: 'Cosine',
    url: 'http://localhost:6333',
    logQueries: false,
    connectionTimeout: 30000,
    maxConnections: 10,
    maxRetries: 3,
    timeout: 30000,
    dimensions: 1536,
    distanceMetric: 'Cosine',
    collectionName: 'knowledge',
  };

  return validateVectorConfig({ ...defaults, ...partial });
}

/**
 * Type guard for ensuring an object has required properties
 */
export function hasRequiredProperties<T extends Record<string, unknown>>(
  obj: unknown,
  requiredProps: (keyof T)[]
): obj is T {
  if (!obj || typeof obj !== 'object') {
    return false;
  }

  const record = obj as Record<string, unknown>;

  return requiredProps.every(prop => {
    const key = prop as string;
    return key in record && record[key] !== undefined;
  });
}