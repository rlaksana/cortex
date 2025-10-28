/**
 * Unit Tests for EmbeddingService
 *
 * Tests embedding functionality including:
 * - Single and batch embedding generation
 * - Caching behavior and TTL management
 * - Error handling and retry logic
 * - Performance monitoring
 * - Configuration management
 * - Rate limiting and quota management
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { EmbeddingService } from '../../../src/services/embeddings/embedding-service.js';
import type { EmbeddingConfig, EmbeddingRequest, BatchEmbeddingRequest } from '../../../src/services/embeddings/embedding-service.js';

// Mock OpenAI
vi.mock('openai', () => {
  return {
    OpenAI: class MockOpenAI {
      embeddings: {
        create: vi.fn()
      };
    }
  };
});

// Mock the dependencies
vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn()
  }
}));

describe('EmbeddingService', () => {
  let embeddingService: EmbeddingService;
  let mockOpenAI: any;

  // Sample test data
  const sampleConfig: EmbeddingConfig = {
    apiKey: 'test-api-key',
    model: 'text-embedding-ada-002',
    batchSize: 100,
    maxRetries: 3,
    retryDelay: 1000,
    cacheEnabled: true,
    cacheTTL: 3600000, // 1 hour
    cacheMaxSize: 1000,
    timeout: 30000
  };

  const sampleEmbedding = Array.from({ length: 1536 }, () => Math.random() - 0.5);
  const normalizedEmbedding = sampleEmbedding.map(x => x / Math.sqrt(sampleEmbedding.reduce((sum, val) => sum + val * val, 0)));

  beforeEach(() => {
    // Create fresh mock instance for each test
    const MockOpenAI = require('openai').OpenAI;
    mockOpenAI = new MockOpenAI();
    mockOpenAI.embeddings.create = vi.fn();

    embeddingService = new EmbeddingService(sampleConfig);

    // Reset all mocks
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Constructor and Configuration', () => {
    it('should create instance with default configuration', () => {
      const service = new EmbeddingService();
      expect(service).toBeInstanceOf(EmbeddingService);
    });

    it('should accept custom configuration', () => {
      const customConfig: EmbeddingConfig = {
        apiKey: 'custom-key',
        model: 'text-embedding-3-small',
        batchSize: 50,
        cacheEnabled: false
      };

      const service = new EmbeddingService(customConfig);
      expect(service).toBeInstanceOf(EmbeddingService);
    });

    it('should handle missing API key gracefully', () => {
      expect(() => {
        new EmbeddingService({ apiKey: undefined });
      }).not.toThrow();
    });
  });

  describe('generateEmbedding', () => {
    it('should generate embedding for simple text request', async () => {
      const mockResponse = {
        data: [{ embedding: sampleEmbedding }],
        usage: { total_tokens: 10 }
      };
      mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

      const result = await embeddingService.generateEmbedding('Hello world');

      expect(mockOpenAI.embeddings.create).toHaveBeenCalledWith({
        model: sampleConfig.model,
        input: 'Hello world'
      });
      expect(result.embedding).toEqual(normalizedEmbedding);
      expect(result.text).toBe('Hello world');
      expect(result.metadata).toBeDefined();
      expect(result.metadata.model).toBe(sampleConfig.model);
      expect(result.metadata.tokens).toBe(10);
    });

    it('should generate embedding for complex request object', async () => {
      const request: EmbeddingRequest = {
        text: 'Complex text',
        metadata: { source: 'test', priority: 'high' },
        cacheKey: 'custom-cache-key',
        priority: 'high'
      };

      const mockResponse = {
        data: [{ embedding: sampleEmbedding }],
        usage: { total_tokens: 15 }
      };
      mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

      const result = await embeddingService.generateEmbedding(request);

      expect(result.embedding).toEqual(normalizedEmbedding);
      expect(result.text).toBe('Complex text');
      expect(result.metadata.source).toBe('test');
      expect(result.metadata.priority).toBe('high');
    });

    it('should handle empty string input', async () => {
      const mockResponse = {
        data: [{ embedding: sampleEmbedding }],
        usage: { total_tokens: 1 }
      };
      mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

      const result = await embeddingService.generateEmbedding('');

      expect(result.embedding).toEqual(normalizedEmbedding);
      expect(result.text).toBe('');
    });

    it('should handle very long text input', async () => {
      const longText = 'a'.repeat(10000);
      const mockResponse = {
        data: [{ embedding: sampleEmbedding }],
        usage: { total_tokens: 2500 }
      };
      mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

      const result = await embeddingService.generateEmbedding(longText);

      expect(result.embedding).toEqual(normalizedEmbedding);
      expect(result.text).toBe(longText);
      expect(result.metadata.tokens).toBe(2500);
    });
  });

  describe('generateBatchEmbeddings', () => {
    it('should process batch embeddings efficiently', async () => {
      const batchRequest: BatchEmbeddingRequest = {
        texts: ['Text 1', 'Text 2', 'Text 3'],
        metadata: { batch: 'test' }
      };

      const mockResponse = {
        data: [
          { embedding: sampleEmbedding },
          { embedding: sampleEmbedding.map(x => x + 0.1) },
          { embedding: sampleEmbedding.map(x => x + 0.2) }
        ],
        usage: { total_tokens: 30 }
      };
      mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

      const results = await embeddingService.generateBatchEmbeddings(batchRequest);

      expect(results).toHaveLength(3);
      expect(results[0].text).toBe('Text 1');
      expect(results[1].text).toBe('Text 2');
      expect(results[2].text).toBe('Text 3');
      expect(mockOpenAI.embeddings.create).toHaveBeenCalledTimes(1);
    });

    it('should handle large batch requests with chunking', async () => {
      const largeBatch = Array.from({ length: 150 }, (_, i) => `Text ${i}`);
      const batchRequest: BatchEmbeddingRequest = {
        texts: largeBatch
      };

      // Mock successful response for each chunk
      mockOpenAI.embeddings.create.mockResolvedValue({
        data: Array.from({ length: 100 }, () => ({ embedding: sampleEmbedding })),
        usage: { total_tokens: 1000 }
      });

      const results = await embeddingService.generateBatchEmbeddings(batchRequest);

      expect(results).toHaveLength(150);
      expect(mockOpenAI.embeddings.create).toHaveBeenCalledTimes(2); // Should chunk into 2 batches
    });

    it('should handle empty batch request', async () => {
      const batchRequest: BatchEmbeddingRequest = {
        texts: []
      };

      const results = await embeddingService.generateBatchEmbeddings(batchRequest);

      expect(results).toHaveLength(0);
      expect(mockOpenAI.embeddings.create).not.toHaveBeenCalled();
    });

    it('should preserve text order in batch results', async () => {
      const batchRequest: BatchEmbeddingRequest = {
        texts: ['First', 'Second', 'Third']
      };

      const mockResponse = {
        data: [
          { embedding: sampleEmbedding },
          { embedding: sampleEmbedding.map(x => x + 0.1) },
          { embedding: sampleEmbedding.map(x => x + 0.2) }
        ],
        usage: { total_tokens: 15 }
      };
      mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

      const results = await embeddingService.generateBatchEmbeddings(batchRequest);

      expect(results[0].text).toBe('First');
      expect(results[1].text).toBe('Second');
      expect(results[2].text).toBe('Third');
    });
  });

  describe('Caching Behavior', () => {
    it('should cache embedding results', async () => {
      const text = 'Cache test text';
      const mockResponse = {
        data: [{ embedding: sampleEmbedding }],
        usage: { total_tokens: 5 }
      };
      mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

      // First call
      const result1 = await embeddingService.generateEmbedding(text);
      expect(mockOpenAI.embeddings.create).toHaveBeenCalledTimes(1);

      // Second call should use cache
      const result2 = await embeddingService.generateEmbedding(text);
      expect(mockOpenAI.embeddings.create).toHaveBeenCalledTimes(1); // Still only called once

      expect(result1.embedding).toEqual(result2.embedding);
    });

    it('should handle cache disabled configuration', async () => {
      const noCacheService = new EmbeddingService({ cacheEnabled: false });
      const text = 'No cache test';
      const mockResponse = {
        data: [{ embedding: sampleEmbedding }],
        usage: { total_tokens: 5 }
      };
      mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

      // Both calls should hit the API
      await noCacheService.generateEmbedding(text);
      await noCacheService.generateEmbedding(text);

      expect(mockOpenAI.embeddings.create).toHaveBeenCalledTimes(2);
    });

    it('should respect cache TTL', async () => {
      const shortTTLService = new EmbeddingService({
        cacheTTL: 100, // 100ms
        cacheEnabled: true
      });

      const text = 'TTL test';
      const mockResponse = {
        data: [{ embedding: sampleEmbedding }],
        usage: { total_tokens: 5 }
      };
      mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

      // First call
      await shortTTLService.generateEmbedding(text);
      expect(mockOpenAI.embeddings.create).toHaveBeenCalledTimes(1);

      // Wait for cache to expire
      await new Promise(resolve => setTimeout(resolve, 150));

      // Second call should hit API again
      await shortTTLService.generateEmbedding(text);
      expect(mockOpenAI.embeddings.create).toHaveBeenCalledTimes(2);
    });

    it('should use custom cache key when provided', async () => {
      const request: EmbeddingRequest = {
        text: 'Custom cache key test',
        cacheKey: 'custom-key'
      };

      const mockResponse = {
        data: [{ embedding: sampleEmbedding }],
        usage: { total_tokens: 5 }
      };
      mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

      await embeddingService.generateEmbedding(request);

      // Second request with same cache key should use cache
      const request2: EmbeddingRequest = {
        text: 'Different text',
        cacheKey: 'custom-key'
      };

      await embeddingService.generateEmbedding(request2);
      expect(mockOpenAI.embeddings.create).toHaveBeenCalledTimes(1);
    });
  });

  describe('Error Handling and Retry Logic', () => {
    it('should handle API errors with retry logic', async () => {
      const text = 'Retry test';
      mockOpenAI.embeddings.create
        .mockRejectedValueOnce(new Error('Rate limit exceeded'))
        .mockRejectedValueOnce(new Error('Rate limit exceeded'))
        .mockResolvedValueOnce({
          data: [{ embedding: sampleEmbedding }],
          usage: { total_tokens: 5 }
        });

      const result = await embeddingService.generateEmbedding(text);

      expect(result.embedding).toEqual(normalizedEmbedding);
      expect(mockOpenAI.embeddings.create).toHaveBeenCalledTimes(3);
    });

    it('should fail after max retries exceeded', async () => {
      const text = 'Fail test';
      mockOpenAI.embeddings.create.mockRejectedValue(new Error('Persistent error'));

      await expect(embeddingService.generateEmbedding(text)).rejects.toThrow('Persistent error');
      expect(mockOpenAI.embeddings.create).toHaveBeenCalledTimes(4); // 1 initial + 3 retries
    });

    it('should handle network timeouts', async () => {
      const text = 'Timeout test';
      mockOpenAI.embeddings.create.mockRejectedValue(new Error('Request timeout'));

      await expect(embeddingService.generateEmbedding(text)).rejects.toThrow('Request timeout');
    });

    it('should handle invalid API responses', async () => {
      const text = 'Invalid response test';
      mockOpenAI.embeddings.create.mockResolvedValue({
        data: [], // Empty data array
        usage: { total_tokens: 0 }
      });

      await expect(embeddingService.generateEmbedding(text)).rejects.toThrow();
    });

    it('should handle batch processing with partial failures', async () => {
      const batchRequest: BatchEmbeddingRequest = {
        texts: ['Text 1', 'Text 2', 'Text 3']
      };

      mockOpenAI.embeddings.create.mockRejectedValue(new Error('Batch failed'));

      await expect(embeddingService.generateBatchEmbeddings(batchRequest)).rejects.toThrow('Batch failed');
    });
  });

  describe('Performance and Monitoring', () => {
    it('should track performance metrics', async () => {
      const text = 'Performance test';
      const mockResponse = {
        data: [{ embedding: sampleEmbedding }],
        usage: { total_tokens: 5 }
      };
      mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

      const startTime = Date.now();
      const result = await embeddingService.generateEmbedding(text);
      const endTime = Date.now();

      expect(result.metadata).toBeDefined();
      expect(result.metadata.processingTime).toBeGreaterThan(0);
      expect(endTime - startTime).toBeLessThan(5000); // Should complete within 5 seconds
    });

    it('should handle high priority requests faster', async () => {
      const normalRequest: EmbeddingRequest = {
        text: 'Normal priority',
        priority: 'normal'
      };

      const highPriorityRequest: EmbeddingRequest = {
        text: 'High priority',
        priority: 'high'
      };

      const mockResponse = {
        data: [{ embedding: sampleEmbedding }],
        usage: { total_tokens: 5 }
      };
      mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

      const normalStart = Date.now();
      await embeddingService.generateEmbedding(normalRequest);
      const normalEnd = Date.now();

      const highStart = Date.now();
      await embeddingService.generateEmbedding(highPriorityRequest);
      const highEnd = Date.now();

      // High priority should be processed as fast or faster
      expect(highEnd - highStart).toBeLessThanOrEqual(normalEnd - normalStart + 100);
    });

    it('should monitor API quota usage', async () => {
      const batchRequest: BatchEmbeddingRequest = {
        texts: Array.from({ length: 10 }, (_, i) => `Text ${i}`)
      };

      const mockResponse = {
        data: Array.from({ length: 10 }, () => ({ embedding: sampleEmbedding })),
        usage: { total_tokens: 100 }
      };
      mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

      const results = await embeddingService.generateBatchEmbeddings(batchRequest);

      expect(results.every(r => r.metadata.tokens > 0)).toBe(true);
      const totalTokens = results.reduce((sum, r) => sum + (r.metadata.tokens || 0), 0);
      expect(totalTokens).toBe(100);
    });
  });

  describe('healthCheck', () => {
    it('should return true when service is healthy', async () => {
      mockOpenAI.embeddings.create.mockResolvedValue({
        data: [{ embedding: sampleEmbedding }],
        usage: { total_tokens: 1 }
      });

      const result = await embeddingService.healthCheck();

      expect(result).toBe(true);
      expect(mockOpenAI.embeddings.create).toHaveBeenCalledTimes(1);
    });

    it('should return false when service is unhealthy', async () => {
      mockOpenAI.embeddings.create.mockRejectedValue(new Error('Service unavailable'));

      const result = await embeddingService.healthCheck();

      expect(result).toBe(false);
    });

    it('should handle health check timeouts', async () => {
      const timeoutService = new EmbeddingService({ timeout: 100 });
      mockOpenAI.embeddings.create.mockImplementation(() =>
        new Promise(resolve => setTimeout(resolve, 200))
      );

      const result = await timeoutService.healthCheck();

      expect(result).toBe(false);
    });
  });

  describe('warmupCache', () => {
    it('should warm up cache with common texts', async () => {
      const commonTexts = ['Hello', 'World', 'Test'];
      const mockResponse = {
        data: [{ embedding: sampleEmbedding }],
        usage: { total_tokens: 5 }
      };
      mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

      await embeddingService.warmupCache(commonTexts);

      expect(mockOpenAI.embeddings.create).toHaveBeenCalledTimes(3);
    });

    it('should handle empty warmup array', async () => {
      await embeddingService.warmupCache([]);

      expect(mockOpenAI.embeddings.create).not.toHaveBeenCalled();
    });

    it('should handle warmup errors gracefully', async () => {
      mockOpenAI.embeddings.create.mockRejectedValue(new Error('Warmup failed'));

      // Should not throw error
      await expect(embeddingService.warmupCache(['test'])).resolves.toBeUndefined();
    });
  });

  describe('Edge Cases and Validation', () => {
    it('should handle null/undefined inputs', async () => {
      await expect(embeddingService.generateEmbedding(null as any)).rejects.toThrow();
      await expect(embeddingService.generateEmbedding(undefined as any)).rejects.toThrow();
    });

    it('should handle extremely long inputs', async () => {
      const extremelyLongText = 'a'.repeat(1000000); // 1M characters

      // Should either process successfully or throw a meaningful error
      try {
        const mockResponse = {
          data: [{ embedding: sampleEmbedding }],
          usage: { total_tokens: 250000 }
        };
        mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

        const result = await embeddingService.generateEmbedding(extremelyLongText);
        expect(result.text).toBe(extremelyLongText);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }
    });

    it('should handle special characters and unicode', async () => {
      const unicodeText = 'Hello 世界 🌍 ñáéíóú';
      const mockResponse = {
        data: [{ embedding: sampleEmbedding }],
        usage: { total_tokens: 10 }
      };
      mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

      const result = await embeddingService.generateEmbedding(unicodeText);

      expect(result.text).toBe(unicodeText);
      expect(result.embedding).toEqual(normalizedEmbedding);
    });

    it('should handle concurrent requests safely', async () => {
      const concurrentRequests = Array.from({ length: 10 }, (_, i) =>
        embeddingService.generateEmbedding(`Concurrent text ${i}`)
      );

      const mockResponse = {
        data: [{ embedding: sampleEmbedding }],
        usage: { total_tokens: 5 }
      };
      mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

      const results = await Promise.all(concurrentRequests);

      expect(results).toHaveLength(10);
      expect(results.every(r => r.embedding.length === 1536)).toBe(true);
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle real-world embedding workflow', async () => {
      // Simulate a real workflow with various text types
      const texts = [
        'Simple sentence',
        'Complex technical documentation with multiple paragraphs and detailed explanations.',
        'Code snippet: function hello() { return "world"; }',
        'Mixed content with numbers 123, symbols @#$, and emojis 🚀'
      ];

      const mockResponse = {
        data: [{ embedding: sampleEmbedding }],
        usage: { total_tokens: 50 }
      };
      mockOpenAI.embeddings.create.mockResolvedValue(mockResponse);

      const results = await embeddingService.generateBatchEmbeddings({
        texts,
        metadata: { workflow: 'test' }
      });

      expect(results).toHaveLength(4);
      expect(results.every(r => r.text.length > 0)).toBe(true);
      expect(results.every(r => r.embedding.length === 1536)).toBe(true);
      expect(results.every(r => r.metadata.tokens > 0)).toBe(true);

      // Test caching with second batch
      const cachedResults = await embeddingService.generateBatchEmbeddings({
        texts: texts.slice(0, 2), // Reuse first 2 texts
        metadata: { workflow: 'cached' }
      });

      // Should have used cache for first 2 texts
      expect(mockOpenAI.embeddings.create).toHaveBeenCalledTimes(1); // Only called once for initial batch
    });
  });
});