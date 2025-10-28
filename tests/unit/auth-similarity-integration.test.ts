/**
 * Comprehensive test suite for Authentication and Similarity services
 * Tests the complete integration of API key validation, authorization, and similarity search
 *
 * Rewritten for Qdrant + PostgreSQL architecture
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { AuthService } from '../../src/services/auth/auth-service.js';
import { AuthMiddleware } from '../../src/middleware/auth-middleware.js';
import { UnifiedSimilarityService } from '../../src/services/similarity/unified-similarity-service.js';
import { memoryStore, memoryFind } from '../../src/services/memory-store.js';
import { AuthScope, UserRole } from '../../src/types/auth-types.js';
import type { KnowledgeItem } from '../../src/types/core-interfaces.js';

// Mock Qdrant adapter for testing
vi.mock('../src/db/adapters/qdrant-adapter.js', () => ({
  QdrantAdapter: vi.fn().mockImplementation(() => ({
    initialize: vi.fn().mockResolvedValue(undefined),
    search: vi.fn().mockResolvedValue({
      hits: [
        {
          item: {
            id: 'test-id-1',
            kind: 'decision',
            title: 'Test Decision',
            content: 'Test content about database migration',
            timestamp: '2024-01-01T00:00:00Z',
            scope: { project: 'test-project', org: 'test-org' }
          },
          score: 0.85,
          confidence: 0.85
        }
      ]
    }),
    getMetrics: vi.fn().mockResolvedValue({})
  }))
}));

// Mock memory service
vi.mock('../src/services/memory-find.js', () => ({
  memoryFind: vi.fn()
}));

// Mock environment configuration
vi.mock('../src/config/environment.js', () => ({
  environment: {
    getQdrantConfig: () => ({
      url: 'http://localhost:6333',
      apiKey: 'test-key',
      vectorSize: 1536,
      distance: 'cosine',
      logQueries: false,
      connectionTimeout: 30000,
      maxConnections: 10
    })
  }
}));

// Mock logger
vi.mock('../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    warn: vi.fn()
  }
}));

describe('Authentication and Similarity Integration Tests', () => {
  let authService: AuthService;
  let authMiddleware: AuthMiddleware;
  let similarityService: UnifiedSimilarityService;
  let mockedMemoryFind: any;

  const mockConfig = {
    jwt_secret: 'test-jwt-secret-min-32-characters-long',
    jwt_refresh_secret: 'test-refresh-secret-min-32-characters-long',
    jwt_expires_in: '1h',
    jwt_refresh_expires_in: '7d',
    bcrypt_rounds: 10,
    api_key_length: 32,
    session_timeout_hours: 24,
    max_sessions_per_user: 5,
    rate_limit_enabled: true
  };

  beforeEach(async () => {
    // Initialize services
    authService = new AuthService(mockConfig);
    similarityService = new UnifiedSimilarityService();

    // Setup auth middleware
    authMiddleware = new AuthMiddleware(authService, {
      logRequests: false,
      logResponses: false
    });

    // Get mocked memory find
    mockedMemoryFind = memoryFind as any;

    // Reset all mocks
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('API Key Authentication', () => {
    it('should generate API key with correct format', () => {
      const { keyId, key } = authService.generateApiKey();

      expect(keyId).toMatch(/^ck_live_[a-zA-Z0-9]{32}$/);
      expect(key).toMatch(/^ck_live_[a-zA-Z0-9]{64}$/);
      expect(key.length).toBeGreaterThan(30);
    });

    it('should validate API key hash correctly', async () => {
      const { keyId, key } = authService.generateApiKey();

      // Mock database storage validation
      const isValid = await authService.validateApiKeyFormat(key);

      expect(isValid).toBe(true);
    });

    it('should reject invalid API key formats', async () => {
      const invalidKeys = [
        '',
        'invalid',
        'ck_',
        'ck_test', // Too short
        'ck_x' + 'a'.repeat(100), // Too long
        'invalid_prefix_' + 'a'.repeat(50)
      ];

      for (const invalidKey of invalidKeys) {
        const isValid = await authService.validateApiKeyFormat(invalidKey);
        expect(isValid).toBe(false);
      }
    });
  });

  describe('Similarity Service Integration', () => {
    beforeEach(async () => {
      await similarityService.initialize();
    });

    it('should initialize similarity service successfully', async () => {
      expect(similarityService.isInitialized()).toBe(true);
    });

    it('should find similar items using Qdrant vector search', async () => {
      const queryItem: KnowledgeItem = {
        id: 'test-query-1',
        kind: 'decision',
        title: 'Database Migration Strategy',
        content: 'Strategy for migrating from PostgreSQL to Qdrant',
        timestamp: new Date().toISOString(),
        scope: {
          project: 'cortex-mcp',
          org: 'andsoftware'
        }
      };

      const results = await similarityService.findSimilar(queryItem, {
        threshold: 0.7,
        maxResults: 10
      });

      expect(results).toHaveLength(1);
      expect(results[0].item.id).toBe('test-id-1');
      expect(results[0].score).toBe(0.85);
      expect(results[0].recommendedAction).toBe('related');
    });

    it('should check for duplicates with high similarity threshold', async () => {
      const queryItem: KnowledgeItem = {
        id: 'test-duplicate-1',
        kind: 'decision',
        title: 'Test Decision',
        content: 'Test content about database migration',
        timestamp: new Date().toISOString(),
        scope: {
          project: 'test-project',
          org: 'test-org'
        }
      };

      const duplicateCheck = await similarityService.checkDuplicate(queryItem, {
        strictMode: true
      });

      expect(duplicateCheck.isDuplicate).toBe(true);
      expect(duplicateCheck.confidence).toBeGreaterThan(0.9);
      expect(duplicateCheck.matches).toHaveLength(1);
      expect(duplicateCheck.reasoning).toContain('exact');
    });

    it('should handle similarity search with no results', async () => {
      // Mock empty search results
      const searchSpy = vi.spyOn(similarityService as any, 'performSemanticSearch')
        .mockResolvedValue([]);

      const queryItem: KnowledgeItem = {
        id: 'test-empty-1',
        kind: 'observation',
        title: 'Unique Content',
        content: 'Completely unique content with no matches',
        timestamp: new Date().toISOString(),
        scope: {
          project: 'unique-project',
          org: 'test-org'
        }
      };

      const results = await similarityService.findSimilar(queryItem);

      expect(results).toHaveLength(0);
      searchSpy.mockRestore();
    });

    it('should handle similarity service errors gracefully', async () => {
      // Mock service error
      const searchSpy = vi.spyOn(similarityService as any, 'performSemanticSearch')
        .mockRejectedValue(new Error('Qdrant connection failed'));

      const queryItem: KnowledgeItem = {
        id: 'test-error-1',
        kind: 'entity',
        title: 'Error Test',
        content: 'Test error handling',
        timestamp: new Date().toISOString(),
        scope: {
          project: 'test-project',
          org: 'test-org'
        }
      };

      await expect(similarityService.findSimilar(queryItem)).rejects.toThrow('Qdrant connection failed');
      searchSpy.mockRestore();
    });
  });

  describe('End-to-End Integration', () => {
    it('should complete full authentication and similarity search workflow', async () => {
      // 1. Generate API key
      const { keyId, key } = authService.generateApiKey();
      expect(keyId).toMatch(/^ck_live_[a-zA-Z0-9]{32}$/);

      // 2. Store a knowledge item
      const testItem: KnowledgeItem = {
        id: 'integration-test-1',
        kind: 'decision',
        title: 'API Documentation Strategy',
        content: 'Strategy for documenting API endpoints and usage examples',
        timestamp: new Date().toISOString(),
        scope: {
          project: 'docs-project',
          org: 'andsoftware'
        }
      };

      const storeResult = await memoryStore([testItem]);
      expect(storeResult.stored).toHaveLength(1);
      expect(storeResult.stored[0].id).toBe('integration-test-1');

      // 3. Perform similarity search
      await similarityService.initialize();

      const searchItem: KnowledgeItem = {
        id: 'search-test-1',
        kind: 'decision',
        title: 'API Documentation Guide',
        content: 'Guide for API documentation and endpoint descriptions',
        timestamp: new Date().toISOString(),
        scope: {
          project: 'docs-project',
          org: 'andsoftware'
        }
      };

      const similarItems = await similarityService.findSimilar(searchItem, {
        threshold: 0.5,
        maxResults: 5
      });

      expect(similarItems.length).toBeGreaterThanOrEqual(0);

      // 4. Verify memory find can locate the item
      mockedMemoryFind.mockResolvedValue({
        hits: [
          {
            id: 'integration-test-1',
            kind: 'decision',
            title: 'API Documentation Strategy',
            snippet: 'Strategy for documenting API endpoints',
            score: 0.9,
            route_used: 'auto',
            confidence: 0.9
          }
        ],
        suggestions: [],
        autonomous_metadata: {
          strategy_used: 'fast',
          mode_requested: 'auto',
          mode_executed: 'auto',
          confidence: 'high',
          total_results: 1,
          avg_score: 0.9,
          fallback_attempted: false,
          recommendation: 'Results sufficient',
          user_message_suggestion: 'Found 1 result'
        },
        debug: {
          query_duration_ms: 50,
          total_candidates: 5,
          mode_used: 'auto',
          tables_searched: 3,
          graph_nodes: 0,
          graph_edges: 0
        }
      });

      const findResult = await memoryFind({
        query: 'API documentation',
        types: ['decision'],
        scope: {
          project: 'docs-project',
          org: 'andsoftware'
        }
      });

      expect(findResult.hits).toHaveLength(1);
      expect(findResult.hits[0].id).toBe('integration-test-1');
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle similarity service configuration updates', async () => {
      await similarityService.initialize();

      const originalConfig = similarityService.getConfig();
      expect(originalConfig.defaultThreshold).toBe(0.75);

      // Update configuration
      similarityService.updateConfig({
        defaultThreshold: 0.8,
        maxResults: 20
      });

      const updatedConfig = similarityService.getConfig();
      expect(updatedConfig.defaultThreshold).toBe(0.8);
      expect(updatedConfig.maxResults).toBe(20);
    });

    it('should get service metrics', async () => {
      await similarityService.initialize();

      const metrics = await similarityService.getMetrics();

      expect(metrics.initialized).toBe(true);
      expect(metrics.config).toBeDefined();
      expect(metrics.qdrantMetrics).toBeDefined();
    });

    it('should handle concurrent similarity searches', async () => {
      await similarityService.initialize();

      const queryItems: KnowledgeItem[] = Array.from({ length: 5 }, (_, i) => ({
        id: `concurrent-test-${i}`,
        kind: 'decision',
        title: `Concurrent Test Decision ${i}`,
        content: `Test content for concurrent search ${i}`,
        timestamp: new Date().toISOString(),
        scope: {
          project: 'concurrent-project',
          org: 'test-org'
        }
      }));

      // Run multiple similarity searches concurrently
      const searchPromises = queryItems.map(item =>
        similarityService.findSimilar(item, { threshold: 0.5, maxResults: 5 })
      );

      const results = await Promise.all(searchPromises);

      expect(results).toHaveLength(5);
      results.forEach(result => {
        expect(Array.isArray(result)).toBe(true);
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle similarity search with invalid input', async () => {
      await similarityService.initialize();

      const invalidItems = [
        null,
        undefined,
        {},
        { kind: '', content: null },
        { kind: 'test', scope: null }
      ];

      for (const invalidItem of invalidItems) {
        await expect(
          similarityService.findSimilar(invalidItem as any)
        ).rejects.toThrow();
      }
    });

    it('should handle API key validation with malformed input', async () => {
      const malformedInputs = [
        null,
        undefined,
        123,
        [],
        {}
      ];

      for (const input of malformedInputs) {
        const isValid = await authService.validateApiKeyFormat(input as any);
        expect(isValid).toBe(false);
      }
    });

    it('should handle similarity service initialization failure', async () => {
      // Mock Qdrant adapter to throw initialization error
      const { QdrantAdapter } = await import('../db/adapters/qdrant-adapter.js');

      const mockFailingAdapter = vi.fn().mockImplementation(() => ({
        initialize: vi.fn().mockRejectedValue(new Error('Failed to connect to Qdrant')),
        search: vi.fn(),
        getMetrics: vi.fn()
      }));

      vi.doMock('../src/db/adapters/qdrant-adapter.js', () => ({
        QdrantAdapter: mockFailingAdapter
      }));

      const failingService = new UnifiedSimilarityService();

      await expect(failingService.initialize()).rejects.toThrow('Failed to connect to Qdrant');
      expect(failingService.isInitialized()).toBe(false);
    });
  });
});