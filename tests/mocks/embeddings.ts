/**
 * Embedding Service Mocks for CI Testing
 *
 * Provides consistent embedding mocks that simulate real embedding service
 * behavior without requiring external API calls in CI environments.
 */

import { vi } from 'vitest';

// Mock embedding service
export const mockEmbeddingService = {
  // Single embedding generation
  generateEmbedding: vi.fn().mockImplementation(async (text: string) => {
    // Generate deterministic embeddings based on text content
    const hash = text.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
    const embedding = Array.from({ length: 1536 }, (_, i) => {
      // Create pseudo-random but deterministic values
      const seed = hash + i;
      return (Math.sin(seed * 0.1) + 1) * 0.5;
    });

    return {
      vector: embedding,
      dimensions: 1536,
      model: 'mock-text-embedding-ada-002',
      usage: {
        prompt_tokens: text.split(' ').length,
        total_tokens: text.split(' ').length,
      },
      created_at: new Date().toISOString(),
    };
  }),

  // Batch embedding generation
  generateBatchEmbeddings: vi.fn().mockImplementation(async (texts: string[]) => {
    const embeddings = texts.map((text) => {
      const hash = text.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
      return Array.from({ length: 1536 }, (_, i) => {
        const seed = hash + i;
        return (Math.sin(seed * 0.1) + 1) * 0.5;
      });
    });

    return {
      vectors: embeddings,
      dimensions: 1536,
      model: 'mock-text-embedding-ada-002',
      usage: {
        prompt_tokens: texts.reduce((acc, text) => acc + text.split(' ').length, 0),
        total_tokens: texts.reduce((acc, text) => acc + text.split(' ').length, 0),
      },
      created_at: new Date().toISOString(),
    };
  }),

  // Similarity calculation
  calculateSimilarity: vi.fn().mockImplementation((vector1: number[], vector2: number[]) => {
    if (vector1.length !== vector2.length) {
      throw new Error('Vectors must have the same dimensions');
    }

    // Calculate cosine similarity
    let dotProduct = 0;
    let norm1 = 0;
    let norm2 = 0;

    for (let i = 0; i < vector1.length; i++) {
      dotProduct += vector1[i] * vector2[i];
      norm1 += vector1[i] * vector1[i];
      norm2 += vector2[i] * vector2[i];
    }

    const similarity = dotProduct / (Math.sqrt(norm1) * Math.sqrt(norm2));
    return Math.max(0, Math.min(1, similarity)); // Clamp between 0 and 1
  }),

  // Model information
  getModelInfo: vi.fn().mockResolvedValue({
    model: 'mock-text-embedding-ada-002',
    dimensions: 1536,
    max_tokens: 8192,
    supported_languages: ['en', 'es', 'fr', 'de', 'it', 'pt', 'zh', 'ja'],
    pricing: {
      input_per_1k_tokens: 0.0001,
      output_per_1k_tokens: 0.0001,
    },
  }),

  // Health check
  healthCheck: vi.fn().mockResolvedValue({
    status: 'healthy',
    model: 'mock-text-embedding-ada-002',
    latency_ms: 15,
    uptime_seconds: 3600,
  }),

  // Performance metrics
  getMetrics: vi.fn().mockResolvedValue({
    total_requests: 0,
    successful_requests: 0,
    failed_requests: 0,
    average_latency_ms: 15,
    p95_latency_ms: 30,
    p99_latency_ms: 50,
    tokens_processed: 0,
  }),

  // Cache management
  clearCache: vi.fn().mockResolvedValue(true),
  getCacheStats: vi.fn().mockResolvedValue({
    cache_size: 0,
    cache_hits: 0,
    cache_misses: 0,
    hit_rate: 0,
  }),

  // Batch processing options
  processInBatches: vi.fn().mockImplementation(async (texts: string[], batchSize: number = 100) => {
    const batches = [];
    for (let i = 0; i < texts.length; i += batchSize) {
      const batch = texts.slice(i, i + batchSize);
      const result = await mockEmbeddingService.generateBatchEmbeddings(batch);
      batches.push(result);
    }
    return {
      batches,
      total_processed: texts.length,
      batch_size: batchSize,
      total_batches: batches.length,
    };
  }),
};

// Mock embedding models configuration
export const mockEmbeddingModels = {
  'mock-text-embedding-ada-002': {
    dimensions: 1536,
    max_tokens: 8192,
    pricing: { input_per_1k_tokens: 0.0001 },
    languages: ['en', 'es', 'fr', 'de', 'it', 'pt', 'zh', 'ja'],
  },
  'mock-text-embedding-3-small': {
    dimensions: 1536,
    max_tokens: 8192,
    pricing: { input_per_1k_tokens: 0.00002 },
    languages: ['en', 'es', 'fr', 'de', 'it', 'pt', 'zh', 'ja'],
  },
  'mock-text-embedding-3-large': {
    dimensions: 3072,
    max_tokens: 8192,
    pricing: { input_per_1k_tokens: 0.00013 },
    languages: ['en', 'es', 'fr', 'de', 'it', 'pt', 'zh', 'ja'],
  },
};

// Mock embedding provider
export const mockEmbeddingProvider = {
  // Provider configuration
  getAvailableModels: vi.fn().mockResolvedValue(Object.keys(mockEmbeddingModels)),
  setModel: vi.fn().mockImplementation((model: string) => {
    if (!mockEmbeddingModels[model]) {
      throw new Error(`Model ${model} not available`);
    }
    return Promise.resolve({ model, ...mockEmbeddingModels[model] });
  }),
  getCurrentModel: vi.fn().mockReturnValue('mock-text-embedding-ada-002'),

  // Rate limiting
  checkRateLimit: vi.fn().mockResolvedValue({
    allowed: true,
    remaining: 1000,
    reset_time: Date.now() + 3600000,
  }),

  // Error handling
  simulateError: vi
    .fn()
    .mockImplementation((errorType: 'rate_limit' | 'timeout' | 'invalid_request') => {
      const errors = {
        rate_limit: { error: 'Rate limit exceeded', code: 'rate_limit_exceeded' },
        timeout: { error: 'Request timeout', code: 'timeout' },
        invalid_request: { error: 'Invalid request', code: 'invalid_request' },
      };
      throw new Error(errors[errorType].error);
    }),
};

// Test utilities for embedding testing
export const embeddingTestHelpers = {
  /**
   * Create sample text for testing
   */
  createSampleTexts: (count: number = 5) => {
    return Array.from(
      { length: count },
      (_, index) => `Sample text ${index + 1} for embedding testing`
    );
  },

  /**
   * Create a known embedding vector for testing
   */
  createKnownEmbedding: (seed: number = 42) => {
    return Array.from({ length: 1536 }, (_, i) => {
      const value = Math.sin((seed + i) * 0.1);
      return (value + 1) * 0.5; // Normalize to [0, 1]
    });
  },

  /**
   * Calculate expected similarity between two embeddings
   */
  calculateExpectedSimilarity: (embedding1: number[], embedding2: number[]) => {
    let dotProduct = 0;
    let norm1 = 0;
    let norm2 = 0;

    for (let i = 0; i < embedding1.length; i++) {
      dotProduct += embedding1[i] * embedding2[i];
      norm1 += embedding1[i] * embedding1[i];
      norm2 += embedding2[i] * embedding2[i];
    }

    return dotProduct / (Math.sqrt(norm1) * Math.sqrt(norm2));
  },

  /**
   * Generate test embeddings with specific similarity
   */
  generateEmbeddingsWithSimilarity: (baseText: string, similarity: number, count: number = 2) => {
    const baseEmbedding = mockEmbeddingService.generateEmbedding(baseText);
    const embeddings = [baseEmbedding];

    for (let i = 1; i < count; i++) {
      // Create variations with controlled similarity
      const variation = baseEmbedding.map((value, index) => {
        const noise = (Math.random() - 0.5) * 2 * (1 - similarity);
        return Math.max(0, Math.min(1, value + noise));
      });
      embeddings.push(
        Promise.resolve({
          vector: variation,
          dimensions: 1536,
          model: 'mock-text-embedding-ada-002',
          usage: { prompt_tokens: 10, total_tokens: 10 },
          created_at: new Date().toISOString(),
        })
      );
    }

    return Promise.all(embeddings);
  },

  /**
   * Assert embedding properties
   */
  assertEmbeddingProperties: (embedding: any, expectedDimensions: number = 1536) => {
    expect(embedding).toHaveProperty('vector');
    expect(embedding).toHaveProperty('dimensions');
    expect(embedding).toHaveProperty('model');
    expect(embedding.vector).toHaveLength(expectedDimensions);
    expect(embedding.dimensions).toBe(expectedDimensions);
    expect(embedding.model).toBe('mock-text-embedding-ada-002');
  },

  /**
   * Reset embedding mocks
   */
  resetEmbeddingMocks: () => {
    Object.values(mockEmbeddingService).forEach((method) => {
      if (vi.isMockFunction(method)) {
        vi.clearAllMocks();
      }
    });
    Object.values(mockEmbeddingProvider).forEach((method) => {
      if (vi.isMockFunction(method)) {
        vi.clearAllMocks();
      }
    });
  },
};

// Export for use in tests
export {
  mockEmbeddingService as embeddingService,
  mockEmbeddingProvider as embeddingProvider,
  mockEmbeddingModels as embeddingModels,
};
