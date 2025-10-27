/**
 * Comprehensive test suite for Authentication and Similarity services
 * Tests the complete integration of API key validation, authorization, and similarity search
 *
 * NOTE: This test is DISABLED because it was written for Prisma database architecture.
 * The system now uses Qdrant (vector database) + PostgreSQL architecture.
 * This test needs to be completely rewritten to work with the new database system.
 */

/*
TODO: Rewrite this test for Qdrant + PostgreSQL architecture

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { AuthService } from '../services/auth/auth-service.ts';
import { AuthMiddleware } from '../middleware/auth-middleware.ts';
import { SimilarityService } from '../services/similarity/similarity-service.ts';
import { AuditService } from '../services/audit/audit-service.ts';
import { AuthScope, UserRole } from '../types/auth-types.ts';
import { KnowledgeItem } from '../types/core-interfaces.ts';

// Mock dependencies for new architecture
jest.mock('../src/utils/logger.js');
jest.mock('../src/db/database-factory.js');

describe.skip('Authentication and Similarity Integration Tests (DISABLED - Needs Rewrite)', () => {
  let authService: AuthService;
  let authMiddleware: AuthMiddleware;
  let similarityService: SimilarityService;
  let auditService: AuditService;

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
    auditService = new AuditService();
    authMiddleware = new AuthMiddleware(authService, auditService);
    similarityService = new SimilarityService();

    // Mock Prisma client methods
    mockPrisma.getClient.mockReturnValue({
      apiKey: {
        findFirst: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
        updateMany: jest.fn(),
        findMany: jest.fn()
      },
      knowledgeEntity: {
        findMany: jest.fn()
      },
      user: {
        findFirst: jest.fn()
      }
    } as any);

    // Reset all mocks
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('API Key Authentication', () => {
    const mockApiKeyRecord = {
      id: 'api-key-123',
      key_id: 'ck_live_abcdef123456',
      key_hash: '$2a$12$hashedkeyvalue',
      user_id: 'user-123',
      name: 'Test API Key',
      description: 'Test key for integration testing',
      scopes: [AuthScope.MEMORY_READ, AuthScope.MEMORY_WRITE],
      is_active: true,
      expires_at: null,
      last_used: null,
      created_at: new Date('2024-01-01'),
      updated_at: new Date('2024-01-01'),
      user: {
        id: 'user-123',
        username: 'testuser',
        email: 'test@example.com',
        role: UserRole.USER,
        is_active: true,
        created_at: new Date('2024-01-01'),
        updated_at: new Date('2024-01-01'),
        last_login: null
      }
    };

    it('should validate API key successfully with correct format and database record', async () => {
      const apiKey = 'ck_live_abcdef123456789012345678';

      mockPrisma.getClient().apiKey.findFirst.mockResolvedValue(mockApiKeyRecord);
      mockPrisma.getClient().apiKey.update.mockResolvedValue({});

      const result = await authService.validateApiKeyWithDatabase(apiKey);

      expect(result).toBeTruthy();
      expect(result!.user.id).toBe('user-123');
      expect(result!.user.username).toBe('testuser');
      expect(result!.scopes).toContain(AuthScope.MEMORY_READ);
      expect(result!.apiKeyInfo.key_id).toBe('ck_live_abcdef123456');

      // Verify last_used was updated
      expect(mockPrisma.getClient().apiKey.update).toHaveBeenCalledWith({
        where: { id: 'api-key-123' },
        data: { last_used: expect.any(Date) }
      });
    });

    it('should reject API key with invalid format', async () => {
      const invalidApiKey = 'invalid_key_format';

      const result = await authService.validateApiKeyWithDatabase(invalidApiKey);

      expect(result).toBeNull();
      expect(mockPrisma.getClient().apiKey.findFirst).not.toHaveBeenCalled();
    });

    it('should reject API key when database record not found', async () => {
      const apiKey = 'ck_live_nonexistent123';

      mockPrisma.getClient().apiKey.findFirst.mockResolvedValue(null);

      const result = await authService.validateApiKeyWithDatabase(apiKey);

      expect(result).toBeNull();
    });

    it('should reject expired API key', async () => {
      const apiKey = 'ck_live_expired123';
      const expiredRecord = {
        ...mockApiKeyRecord,
        key_id: 'ck_live_expired123',
        expires_at: new Date('2023-01-01') // Past date
      };

      mockPrisma.getClient().apiKey.findFirst.mockResolvedValue(expiredRecord);

      const result = await authService.validateApiKeyWithDatabase(apiKey);

      expect(result).toBeNull();
    });

    it('should reject API key for inactive user', async () => {
      const apiKey = 'ck_live_inactive123';
      const inactiveUserRecord = {
        ...mockApiKeyRecord,
        key_id: 'ck_live_inactive123',
        user: {
          ...mockApiKeyRecord.user,
          is_active: false
        }
      };

      mockPrisma.getClient().apiKey.findFirst.mockResolvedValue(inactiveUserRecord);

      const result = await authService.validateApiKeyWithDatabase(apiKey);

      expect(result).toBeNull();
    });

    it('should handle database errors gracefully', async () => {
      const apiKey = 'ck_live_error123';

      mockPrisma.getClient().apiKey.findFirst.mockRejectedValue(new Error('Database connection failed'));

      const result = await authService.validateApiKeyWithDatabase(apiKey);

      expect(result).toBeNull();
    });
  });

  describe('Auth Middleware Integration', () => {
    const mockRequest = {
      headers: {
        'x-api-key': 'ck_live_test123456',
        'user-agent': 'test-agent',
        'x-forwarded-for': '192.168.1.1'
      },
      ip: '192.168.1.1',
      path: '/api/memory/store',
      method: 'POST'
    } as any;

    const mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    const mockNext = jest.fn();

    it('should authenticate successfully with valid API key', async () => {
      const mockApiKeyRecord = {
        id: 'api-key-123',
        key_id: 'ck_live_test123456',
        key_hash: '$2a$12$hashedkeyvalue',
        user_id: 'user-123',
        name: 'Test Key',
        scopes: [AuthScope.MEMORY_WRITE],
        is_active: true,
        expires_at: null,
        last_used: null,
        created_at: new Date(),
        updated_at: new Date(),
        user: {
          id: 'user-123',
          username: 'testuser',
          email: 'test@example.com',
          role: UserRole.USER,
          is_active: true,
          created_at: new Date(),
          updated_at: new Date()
        }
      };

      mockPrisma.getClient().apiKey.findFirst.mockResolvedValue(mockApiKeyRecord);
      mockPrisma.getClient().apiKey.update.mockResolvedValue({});

      const middleware = authMiddleware.authenticate({
        required_scopes: [AuthScope.MEMORY_WRITE]
      });

      await middleware(mockRequest, mockResponse, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockRequest.auth).toBeDefined();
      expect(mockRequest.auth!.user.id).toBe('user-123');
      expect(mockRequest.auth!.scopes).toContain(AuthScope.MEMORY_WRITE);
    });

    it('should reject request with insufficient scopes', async () => {
      const mockApiKeyRecord = {
        id: 'api-key-123',
        key_id: 'ck_live_test123456',
        key_hash: '$2a$12$hashedkeyvalue',
        user_id: 'user-123',
        name: 'Test Key',
        scopes: [AuthScope.MEMORY_READ], // Only read scope
        is_active: true,
        expires_at: null,
        last_used: null,
        created_at: new Date(),
        updated_at: new Date(),
        user: {
          id: 'user-123',
          username: 'testuser',
          email: 'test@example.com',
          role: UserRole.USER,
          is_active: true,
          created_at: new Date(),
          updated_at: new Date()
        }
      };

      mockPrisma.getClient().apiKey.findFirst.mockResolvedValue(mockApiKeyRecord);
      mockPrisma.getClient().apiKey.update.mockResolvedValue({});

      const middleware = authMiddleware.authenticate({
        required_scopes: [AuthScope.MEMORY_WRITE] // Requires write scope
      });

      await middleware(mockRequest, mockResponse, mockNext);

      expect(mockNext).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({
            code: 'INSUFFICIENT_SCOPES'
          })
        })
      );
    });
  });

  describe('Similarity Service Integration', () => {
    const mockKnowledgeEntity = {
      id: 'entity-123',
      entity_type: 'decision',
      name: 'Test Decision',
      data: {
        title: 'Database Migration Strategy',
        description: 'Strategy for migrating to PostgreSQL',
        scope: {
          project: 'cortex-mcp',
          branch: 'main',
          org: 'andsoftware'
        }
      },
      metadata: {
        scope: {
          project: 'cortex-mcp',
          branch: 'main',
          org: 'andsoftware'
        }
      },
      created_at: new Date('2024-01-01'),
      updated_at: new Date('2024-01-01'),
      tags: {}
    };

    it('should find similar items using KnowledgeEntity table', async () => {
      const testItem: KnowledgeItem = {
        id: 'test-123',
        kind: 'decision',
        scope: {
          project: 'cortex-mcp',
          org: 'andsoftware'
        },
        data: {
          title: 'Database Migration Plan',
          description: 'Plan to migrate database system'
        }
      };

      mockPrisma.getClient().knowledgeEntity.findMany.mockResolvedValue([mockKnowledgeEntity]);

      const similarItems = await similarityService.findSimilar(testItem, 0.3);

      expect(similarItems).toHaveLength(1);
      expect(similarItems[0].id).toBe('entity-123');
      expect(similarItems[0].kind).toBe('decision');
      expect(similarItems[0].scope.project).toBe('cortex-mcp');

      expect(mockPrisma.getClient().knowledgeEntity.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            entity_type: 'decision',
            deleted_at: null
          })
        })
      );
    });

    it('should handle empty results gracefully', async () => {
      const testItem: KnowledgeItem = {
        id: 'test-456',
        kind: 'observation',
        scope: {
          project: 'different-project'
        },
        data: {
          title: 'Completely Different Item'
        }
      };

      mockPrisma.getClient().knowledgeEntity.findMany.mockResolvedValue([]);

      const similarItems = await similarityService.findSimilar(testItem, 0.8);

      expect(similarItems).toHaveLength(0);
    });

    it('should calculate similarity between two items', async () => {
      const item1: KnowledgeItem = {
        id: 'item-1',
        kind: 'decision',
        scope: { project: 'test' },
        data: { title: 'Database Migration', description: 'Migrate to PostgreSQL' }
      };

      const item2: KnowledgeItem = {
        id: 'item-2',
        kind: 'decision',
        scope: { project: 'test' },
        data: { title: 'Database Migration', description: 'Migrate database system' }
      };

      const similarity = await similarityService.calculateSimilarity(item1, item2);

      expect(typeof similarity).toBe('number');
      expect(similarity).toBeGreaterThanOrEqual(0);
      expect(similarity).toBeLessThanOrEqual(1);
    });

    it('should handle database errors in similarity search', async () => {
      const testItem: KnowledgeItem = {
        id: 'test-789',
        kind: 'entity',
        scope: { project: 'test' },
        data: { title: 'Test Item' }
      };

      mockPrisma.getClient().knowledgeEntity.findMany.mockRejectedValue(new Error('Database error'));

      const similarItems = await similarityService.findSimilar(testItem);

      expect(similarItems).toHaveLength(0);
    });
  });

  describe('End-to-End Integration', () => {
    it('should complete full authentication and similarity search workflow', async () => {
      // 1. Setup mock API key authentication
      const mockApiKeyRecord = {
        id: 'api-key-456',
        key_id: 'ck_live_workflow123',
        key_hash: '$2a$12$hashedkeyvalue',
        user_id: 'user-456',
        name: 'Workflow Test Key',
        scopes: [AuthScope.MEMORY_READ, AuthScope.SEARCH_BASIC],
        is_active: true,
        expires_at: null,
        last_used: null,
        created_at: new Date(),
        updated_at: new Date(),
        user: {
          id: 'user-456',
          username: 'workflowuser',
          email: 'workflow@example.com',
          role: UserRole.USER,
          is_active: true,
          created_at: new Date(),
          updated_at: new Date()
        }
      };

      // 2. Setup mock similarity data
      const mockEntity = {
        id: 'entity-456',
        entity_type: 'section',
        name: 'Documentation Section',
        data: {
          title: 'API Documentation',
          content: 'This is the API documentation content',
          scope: { project: 'docs-project', org: 'andsoftware' }
        },
        metadata: {
          scope: { project: 'docs-project', org: 'andsoftware' }
        },
        created_at: new Date(),
        updated_at: new Date(),
        tags: {}
      };

      mockPrisma.getClient().apiKey.findFirst.mockResolvedValue(mockApiKeyRecord);
      mockPrisma.getClient().apiKey.update.mockResolvedValue({});
      mockPrisma.getClient().knowledgeEntity.findMany.mockResolvedValue([mockEntity]);

      // 3. Authenticate with API key
      const apiKey = 'ck_live_workflow123456789';
      const authResult = await authService.validateApiKeyWithDatabase(apiKey);

      expect(authResult).toBeTruthy();
      expect(authResult!.scopes).toContain(AuthScope.MEMORY_READ);

      // 4. Perform similarity search
      const searchItem: KnowledgeItem = {
        id: 'search-123',
        kind: 'section',
        scope: { project: 'docs-project', org: 'andsoftware' },
        data: { title: 'API Guide', content: 'API usage guide content' }
      };

      const similarItems = await similarityService.findSimilar(searchItem);

      expect(similarItems).toHaveLength(1);
      expect(similarItems[0].kind).toBe('section');
      expect(similarItems[0].data.title).toBe('API Documentation');

      // 5. Verify audit logs would be created
      expect(mockPrisma.getClient().apiKey.update).toHaveBeenCalled();
      expect(mockPrisma.getClient().knowledgeEntity.findMany).toHaveBeenCalled();
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle malformed API keys gracefully', async () => {
      const malformedKeys = [
        '',
        'invalid',
        'ck_',
        'ck_test', // Too short
        'ck_x' + 'a'.repeat(100) // Too long
      ];

      for (const key of malformedKeys) {
        const result = await authService.validateApiKeyWithDatabase(key);
        expect(result).toBeNull();
      }
    });

    it('should handle similarity search with invalid input', async () => {
      const invalidItems = [
        null,
        undefined,
        {},
        { kind: '', data: null },
        { kind: 'test', scope: null }
      ];

      for (const item of invalidItems) {
        const result = await similarityService.findSimilar(item as any);
        expect(Array.isArray(result)).toBe(true);
      }
    });

    it('should handle concurrent API key validations', async () => {
      const apiKey = 'ck_live_concurrent123';
      const mockRecord = {
        id: 'api-key-concurrent',
        key_id: 'ck_live_concurrent123',
        key_hash: '$2a$12$hashedkeyvalue',
        user_id: 'user-concurrent',
        name: 'Concurrent Test Key',
        scopes: [AuthScope.MEMORY_READ],
        is_active: true,
        expires_at: null,
        last_used: null,
        created_at: new Date(),
        updated_at: new Date(),
        user: {
          id: 'user-concurrent',
          username: 'concurrentuser',
          email: 'concurrent@example.com',
          role: UserRole.USER,
          is_active: true,
          created_at: new Date(),
          updated_at: new Date()
        }
      };

      mockPrisma.getClient().apiKey.findFirst.mockResolvedValue(mockRecord);
      mockPrisma.getClient().apiKey.update.mockResolvedValue({});

      // Run multiple validations concurrently
      const promises = Array.from({ length: 10 }, () =>
        authService.validateApiKeyWithDatabase(apiKey)
      );

      const results = await Promise.all(promises);

      // All should succeed
      expect(results.every(result => result !== null)).toBe(true);
      expect(mockPrisma.getClient().apiKey.findFirst).toHaveBeenCalledTimes(10);
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large similarity searches efficiently', async () => {
      const mockEntities = Array.from({ length: 100 }, (_, i) => ({
        id: `entity-${i}`,
        entity_type: 'decision',
        name: `Decision ${i}`,
        data: {
          title: `Decision Title ${i}`,
          description: `Description for decision ${i}`,
          scope: { project: 'test-project', org: 'test-org' }
        },
        metadata: {
          scope: { project: 'test-project', org: 'test-org' }
        },
        created_at: new Date(),
        updated_at: new Date(),
        tags: {}
      }));

      mockPrisma.getClient().knowledgeEntity.findMany.mockResolvedValue(mockEntities);

      const searchItem: KnowledgeItem = {
        id: 'search-large',
        kind: 'decision',
        scope: { project: 'test-project' },
        data: { title: 'Test Decision', description: 'Test description' }
      };

      const startTime = Date.now();
      const similarItems = await similarityService.findSimilar(searchItem);
      const duration = Date.now() - startTime;

      expect(similarItems.length).toBeLessThanOrEqual(50); // Should be limited by similarity service
      expect(duration).toBeLessThan(1000); // Should complete within 1 second
    });
  });
});
*/

/**
 * Manual test runner for development
 * This can be executed to verify the integration manually
 * NOTE: This also needs to be updated for the new architecture
 */
export async function runManualIntegrationTest() {
  console.log('🧪 Starting manual integration tests...');

  try {
    // Test basic API key generation
    const authConfig = {
      jwt_secret: 'manual-test-jwt-secret-min-32-chars',
      jwt_refresh_secret: 'manual-test-refresh-secret-min-32',
      jwt_expires_in: '1h',
      jwt_refresh_expires_in: '7d',
      bcrypt_rounds: 10,
      api_key_length: 32,
      session_timeout_hours: 24,
      max_sessions_per_user: 5,
      rate_limit_enabled: true
    };

    const authService = new AuthService(authConfig);
    const { keyId, key } = authService.generateApiKey();

    console.log(`✅ API Key generated: ${keyId}`);
    console.log(`✅ Key format valid: ${key.startsWith('ck_') && key.length > 30}`);

    // Test similarity service
    const similarityService = new SimilarityService();
    const testItem: KnowledgeItem = {
      id: 'manual-test',
      kind: 'decision',
      scope: { project: 'manual-test' },
      data: { title: 'Manual Test', description: 'Testing similarity search' }
    };

    const similarItems = await similarityService.findSimilar(testItem);
    console.log(`✅ Similarity search completed: ${similarItems.length} results found`);

    console.log('🎉 Manual integration tests passed!');

  } catch (error) {
    console.error('❌ Manual integration tests failed:', error);
  }
}

// Run manual tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runManualIntegrationTest();
}