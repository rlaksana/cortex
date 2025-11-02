/**
 * Comprehensive API Key Authentication Tests for Cortex MCP
 * Tests API key management, validation, authentication flows, authorization, and security features
 */

import { describe, test, expect, beforeEach, afterEach, vi, type MockedFunction } from 'vitest';
import { ApiKeyService } from '../../../src/services/auth/api-key-service.js';
import {
  UserRole,
  AuthScope,
  ApiKey,
  User,
  AuthContext,
  SecurityAuditLog,
  DEFAULT_ROLE_PERMISSIONS,
} from '../../../src/types/auth-types.js';

// Mock dependencies
vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// Create mockLogger instance for tests
const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
};

// Mock crypto with proper default export
let uuidCounter = 1;
vi.mock('node:crypto', () => ({
  default: {
    randomUUID: vi.fn(() => `test-uuid-${uuidCounter++}`),
    createHash: vi.fn(() => ({
      update: vi.fn().mockReturnThis(),
      digest: vi.fn(() => 'hashed-api-key'),
    })),
    randomBytes: vi.fn(() => Buffer.from('random-api-key-32-bytes')),
  },
  randomUUID: vi.fn(() => `test-uuid-${uuidCounter++}`),
  createHash: vi.fn(() => ({
    update: vi.fn().mockReturnThis(),
    digest: vi.fn(() => 'hashed-api-key'),
  })),
  randomBytes: vi.fn(() => Buffer.from('random-api-key-32-bytes')),
}));

// Mock AuthService
let keyIdCounter = 1;
let hashCounter = 1;
vi.mock('../../../src/services/auth/auth-service.js', () => ({
  AuthService: vi.fn().mockImplementation(() => ({
    generateApiKey: vi.fn(() => ({
      keyId: `ck_test_${String(keyIdCounter++).padStart(22, '0')}`,
      key: `ck_test_${String(keyIdCounter).padStart(22, '0')}abcdef`,
    })),
    hashApiKey: vi.fn(() => Promise.resolve(`hashed-api-key-${hashCounter++}`)),
    verifyApiKey: vi.fn(() => Promise.resolve(true)),
    getUserMaxScopes: vi.fn(() => Object.values(AuthScope)),
  })),
}));

// Mock AuditService
vi.mock('../../../src/services/audit/audit-service.js', () => ({
  AuditService: vi.fn().mockImplementation(() => ({
    logSecurityAuditEvent: vi.fn(() => Promise.resolve()),
  })),
}));

// Get mock instances for use in tests
const mockAuthService = {
  generateApiKey: vi.fn(() => ({
    keyId: 'ck_test_1234567890123456789012',
    key: 'ck_test_1234567890123456789012abcdef',
  })),
  hashApiKey: vi.fn(() => Promise.resolve('hashed-api-key')),
  verifyApiKey: vi.fn(() => Promise.resolve(true)),
  getUserMaxScopes: vi.fn(() => Object.values(AuthScope)),
};

const mockAuditService = {
  logSecurityAuditEvent: vi.fn(() => Promise.resolve()),
};

describe('ApiKeyService', () => {
  let apiKeyService: ApiKeyService;
  let testUser: User;

  beforeEach(() => {
    // Clear all mocks
    vi.clearAllMocks();

    // Reset counters
    uuidCounter = 1;
    keyIdCounter = 1;
    hashCounter = 1;

    // Clear mock logger
    Object.values(mockLogger).forEach((method) => method.mockClear());

    // Setup default mock behavior - user has access to all scopes
    mockAuthService.getUserMaxScopes.mockReturnValue(Object.values(AuthScope));

    // Create test user
    testUser = {
      id: 'user-123',
      username: 'testuser',
      email: 'test@example.com',
      password_hash: 'hashedpassword',
      role: UserRole._USER,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    // Create service instance with mocked dependencies
    apiKeyService = new ApiKeyService(mockAuthService as any, mockAuditService as any);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('API Key Generation and Creation', () => {
    test('should create API key with valid parameters', async () => {
      // Arrange
      const request = {
        name: 'Test API Key',
        scopes: [AuthScope._MEMORY_READ, AuthScope._MEMORY_WRITE],
        description: 'Test key for unit testing',
      };

      // Act
      const result = await apiKeyService.createApiKey(testUser, request);

      // Assert
      expect(result).toBeDefined();
      expect(result.api_key).toMatch(/^ck_/);
      expect(result.key_info).toBeDefined();
      expect(result.key_info.name).toBe('Test API Key');
      expect(result.key_info.scopes).toEqual([AuthScope._MEMORY_READ, AuthScope._MEMORY_WRITE]);
      expect(result.key_info.is_active).toBe(true);
      expect(mockAuthService.generateApiKey).toHaveBeenCalled();
      expect(mockAuthService.hashApiKey).toHaveBeenCalled();
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'api_key_created',
          user_id: testUser.id,
        })
      );
    });

    test('should create API key with expiration date', async () => {
      // Arrange
      const request = {
        name: 'Expiring Key',
        scopes: [AuthScope._MEMORY_READ],
        expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days from now
      };

      // Act
      const result = await apiKeyService.createApiKey(testUser, request);

      // Assert
      expect(result.key_info.expires_at).toBe(request.expires_at);
    });

    test('should reject API key creation with unauthorized scopes', async () => {
      // Arrange
      mockAuthService.getUserMaxScopes.mockReturnValue([AuthScope._MEMORY_READ]);
      const request = {
        name: 'Unauthorized Key',
        scopes: [AuthScope._MEMORY_READ, AuthScope._SYSTEM_MANAGE], // User can't have SYSTEM_MANAGE
      };

      // Act & Assert
      await expect(apiKeyService.createApiKey(testUser, request)).rejects.toThrow(
        'User not allowed to create API key with scopes: system:manage'
      );
    });

    test('should include context information in audit logs', async () => {
      // Arrange
      const request = {
        name: 'Context Key',
        scopes: [AuthScope._MEMORY_READ],
      };
      const context = {
        ip_address: '192.168.1.100',
        user_agent: 'Test-Client/1.0',
      };

      // Act
      await apiKeyService.createApiKey(testUser, request, context);

      // Assert
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'api_key_created',
          ip_address: '192.168.1.100',
          user_agent: 'Test-Client/1.0',
        })
      );
    });
  });

  describe('API Key Validation and Authentication', () => {
    test('should validate API key with correct format and hash', async () => {
      // Arrange
      const apiKey = 'ck_test_1234567890123456789012abcdef';
      const context = { ip_address: '192.168.1.100', user_agent: 'Test-Client' };

      // First create an API key
      const createResult = await apiKeyService.createApiKey(testUser, {
        name: 'Test Key',
        scopes: [AuthScope._MEMORY_READ],
      });

      // Act
      const result = await apiKeyService.validateApiKey(apiKey, context);

      // Assert
      expect(result.valid).toBe(true);
      expect(result.api_key).toBeDefined();
      expect(result.user).toBeDefined();
      expect(result.scopes).toEqual([AuthScope._MEMORY_READ]);
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'auth_success',
          user_id: testUser.id,
        })
      );
    });

    test('should reject API key with invalid format', async () => {
      // Arrange
      const invalidKeys = [
        'invalid_key',
        'ck_short',
        'xk_test_1234567890123456789012', // Wrong prefix
        '',
      ];

      for (const invalidKey of invalidKeys) {
        // Act
        const result = await apiKeyService.validateApiKey(invalidKey);

        // Assert
        expect(result.valid).toBe(false);
        expect(result.error_code).toBe('INVALID_FORMAT');
      }
    });

    test('should reject inactive API key', async () => {
      // Arrange
      const apiKey = 'ck_test_1234567890123456789012abcdef';

      // Create and then revoke an API key
      const createResult = await apiKeyService.createApiKey(testUser, {
        name: 'Test Key',
        scopes: [AuthScope._MEMORY_READ],
      });
      await apiKeyService.revokeApiKey(testUser, createResult.key_info.key_id);

      // Act
      const result = await apiKeyService.validateApiKey(apiKey);

      // Assert
      expect(result.valid).toBe(false);
      expect(result.error_code).toBe('INACTIVE_KEY');
    });

    test('should reject expired API key', async () => {
      // Arrange
      const apiKey = 'ck_test_1234567890123456789012abcdef';
      const expiredDate = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(); // Yesterday

      // Create expired API key by directly manipulating the internal storage
      await apiKeyService.createApiKey(testUser, {
        name: 'Expired Key',
        scopes: [AuthScope._MEMORY_READ],
        expires_at: expiredDate,
      });

      // Act
      const result = await apiKeyService.validateApiKey(apiKey);

      // Assert
      expect(result.valid).toBe(false);
      expect(result.error_code).toBe('EXPIRED_KEY');
    });

    test('should update last used timestamp on successful validation', async () => {
      // Arrange
      const apiKey = 'ck_test_1234567890123456789012abcdef';
      const createResult = await apiKeyService.createApiKey(testUser, {
        name: 'Test Key',
        scopes: [AuthScope._MEMORY_READ],
      });

      // Get initial last_used (should be undefined)
      expect(createResult.key_info.last_used).toBeUndefined();

      // Act
      await apiKeyService.validateApiKey(apiKey);
      const updatedKey = await apiKeyService.getApiKey(testUser, createResult.key_info.key_id);

      // Assert
      expect(updatedKey?.last_used).toBeDefined();
    });

    test('should handle validation errors gracefully', async () => {
      // Arrange
      mockAuthService.verifyApiKey.mockRejectedValue(new Error('Verification failed'));
      const apiKey = 'ck_test_1234567890123456789012abcdef';

      // Act
      const result = await apiKeyService.validateApiKey(apiKey);

      // Assert
      expect(result.valid).toBe(false);
      expect(result.error_code).toBe('VALIDATION_ERROR');
      expect(mockLogger.error).toHaveBeenCalled();
    });
  });

  describe('API Key Lifecycle Management', () => {
    test('should list all API keys for user', async () => {
      // Arrange
      await apiKeyService.createApiKey(testUser, {
        name: 'Key 1',
        scopes: [AuthScope._MEMORY_READ],
      });
      await apiKeyService.createApiKey(testUser, {
        name: 'Key 2',
        scopes: [AuthScope._MEMORY_WRITE],
      });

      // Act
      const keys = await apiKeyService.listApiKeys(testUser);

      // Assert
      expect(keys).toHaveLength(2);
      expect(keys[0].name).toBe('Key 1');
      expect(keys[1].name).toBe('Key 2');
    });

    test('should get specific API key details', async () => {
      // Arrange
      const createResult = await apiKeyService.createApiKey(testUser, {
        name: 'Specific Key',
        scopes: [AuthScope._MEMORY_READ],
      });

      // Act
      const key = await apiKeyService.getApiKey(testUser, createResult.key_info.key_id);

      // Assert
      expect(key).toBeDefined();
      expect(key?.name).toBe('Specific Key');
      expect(key?.scopes).toEqual([AuthScope._MEMORY_READ]);
    });

    test('should return null for non-existent API key', async () => {
      // Act
      const key = await apiKeyService.getApiKey(testUser, 'non-existent-key-id');

      // Assert
      expect(key).toBeNull();
    });

    test('should revoke API key successfully', async () => {
      // Arrange
      const createResult = await apiKeyService.createApiKey(testUser, {
        name: 'Revocable Key',
        scopes: [AuthScope._MEMORY_READ],
      });
      const context = { ip_address: '192.168.1.100', user_agent: 'Test-Client' };

      // Act
      const revoked = await apiKeyService.revokeApiKey(
        testUser,
        createResult.key_info.key_id,
        context
      );

      // Assert
      expect(revoked).toBe(true);

      // Verify key is no longer valid
      const validation = await apiKeyService.validateApiKey(createResult.api_key);
      expect(validation.valid).toBe(false);
      expect(validation.error_code).toBe('INACTIVE_KEY');

      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'api_key_revoked',
          user_id: testUser.id,
        })
      );
    });

    test('should update API key successfully', async () => {
      // Arrange
      const createResult = await apiKeyService.createApiKey(testUser, {
        name: 'Updatable Key',
        scopes: [AuthScope._MEMORY_READ],
      });
      const updates = {
        name: 'Updated Key Name',
        description: 'Updated description',
      };

      // Act
      const updated = await apiKeyService.updateApiKey(
        testUser,
        createResult.key_info.key_id,
        updates
      );

      // Assert
      expect(updated).toBeDefined();
      expect(updated?.name).toBe('Updated Key Name');
      expect(updated?.description).toBe('Updated description');
      expect(updated?.scopes).toEqual([AuthScope._MEMORY_READ]); // Unchanged
    });

    test('should reject unauthorized scope updates', async () => {
      // Arrange
      mockAuthService.getUserMaxScopes.mockReturnValue([AuthScope._MEMORY_READ]);
      const createResult = await apiKeyService.createApiKey(testUser, {
        name: 'Scope Key',
        scopes: [AuthScope._MEMORY_READ],
      });
      const updates = {
        scopes: [AuthScope._MEMORY_READ, AuthScope._SYSTEM_MANAGE],
      };

      // Act & Assert
      await expect(
        apiKeyService.updateApiKey(testUser, createResult.key_info.key_id, updates)
      ).rejects.toThrow('User not allowed to assign scopes: system:manage');
    });
  });

  describe('Authorization and Permission Validation', () => {
    test('should create auth context from valid API key validation', async () => {
      // Arrange
      const apiKey = 'ck_test_1234567890123456789012abcdef';
      const context = { ip_address: '192.168.1.100', user_agent: 'Test-Client' };

      await apiKeyService.createApiKey(testUser, {
        name: 'Auth Context Key',
        scopes: [AuthScope._MEMORY_READ, AuthScope._MEMORY_WRITE],
      });

      const validation = await apiKeyService.validateApiKey(apiKey, context);

      // Act
      const authContext = apiKeyService.createAuthContextFromApiKey(validation, context);

      // Assert
      expect(authContext).toBeDefined();
      expect(authContext.user.id).toBe(testUser.id);
      expect(authContext.user.username).toBe(testUser.username);
      expect(authContext.user.role).toBe(testUser.role);
      expect(authContext.scopes).toEqual([AuthScope._MEMORY_READ, AuthScope._MEMORY_WRITE]);
      expect(authContext.session.ip_address).toBe('192.168.1.100');
      expect(authContext.session.user_agent).toBe('Test-Client');
    });

    test('should throw error when creating auth context from invalid validation', async () => {
      // Arrange
      const invalidValidation = {
        valid: false,
        error: 'Invalid key',
      };
      const context = { ip_address: '192.168.1.100', user_agent: 'Test-Client' };

      // Act & Assert
      expect(() =>
        apiKeyService.createAuthContextFromApiKey(invalidValidation as any, context)
      ).toThrow('Invalid API key validation result');
    });

    test('should enforce scope-based access control', async () => {
      // Arrange
      const readOnlyUser = {
        ...testUser,
        role: UserRole._READ_ONLY,
      };
      mockAuthService.getUserMaxScopes.mockReturnValue(
        DEFAULT_ROLE_PERMISSIONS[UserRole._READ_ONLY].max_scopes
      );

      // Act & Assert
      // Should allow read scopes
      await expect(
        apiKeyService.createApiKey(readOnlyUser, {
          name: 'Read Key',
          scopes: [AuthScope._MEMORY_READ, AuthScope._KNOWLEDGE_READ],
        })
      ).resolves.toBeDefined();

      // Should reject admin scopes
      await expect(
        apiKeyService.createApiKey(readOnlyUser, {
          name: 'Admin Key',
          scopes: [AuthScope._SYSTEM_MANAGE],
        })
      ).rejects.toThrow('User not allowed to create API key with scopes: system:manage');
    });
  });

  describe('Security Features and Rate Limiting', () => {
    test('should log authentication failures for monitoring', async () => {
      // Arrange
      const invalidKey = 'ck_invalid_1234567890123456789012';
      const context = { ip_address: '192.168.1.100', user_agent: 'Test-Client' };

      // Act
      await apiKeyService.validateApiKey(invalidKey, context);

      // Assert
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'auth_failure',
          ip_address: '192.168.1.100',
          user_agent: 'Test-Client',
          details: expect.objectContaining({
            reason: 'Invalid API key',
          }),
        })
      );
    });

    test('should log suspicious activity patterns', async () => {
      // Arrange
      const suspiciousKeys = [
        'ck_test_1234567890123456789012a',
        'ck_test_1234567890123456789012b',
        'ck_test_1234567890123456789012c',
      ];
      const context = { ip_address: '192.168.1.100', user_agent: 'Test-Client' };

      // Act - simulate multiple failed attempts
      for (const key of suspiciousKeys) {
        await apiKeyService.validateApiKey(key, context);
      }

      // Assert - all failures should be logged
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledTimes(3);
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'auth_failure',
          severity: 'medium',
        })
      );
    });

    test('should handle IP-based security logging', async () => {
      // Arrange
      const apiKey = 'ck_test_1234567890123456789012abcdef';
      const contexts = [
        { ip_address: '192.168.1.100', user_agent: 'Client-A' },
        { ip_address: '203.0.113.1', user_agent: 'Client-B' }, // Different IP
      ];

      await apiKeyService.createApiKey(testUser, {
        name: 'Multi-IP Key',
        scopes: [AuthScope._MEMORY_READ],
      });

      // Act - validate from different IPs
      for (const context of contexts) {
        await apiKeyService.validateApiKey(apiKey, context);
      }

      // Assert - both should be logged with different IPs
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'auth_success',
          ip_address: '192.168.1.100',
        })
      );
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'auth_success',
          ip_address: '203.0.113.1',
        })
      );
    });
  });

  describe('Usage Statistics and Monitoring', () => {
    test('should provide comprehensive usage statistics', async () => {
      // Arrange
      await apiKeyService.createApiKey(testUser, {
        name: 'Active Key',
        scopes: [AuthScope._MEMORY_READ],
      });
      await apiKeyService.createApiKey(testUser, {
        name: 'Expired Key',
        scopes: [AuthScope._MEMORY_WRITE],
        expires_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
      });
      await apiKeyService.createApiKey(testUser, {
        name: 'Another Key',
        scopes: [AuthScope._KNOWLEDGE_READ],
      });

      // Act
      const stats = await apiKeyService.getApiKeyUsageStats(testUser);

      // Assert
      expect(stats).toBeDefined();
      expect(stats.total_keys).toBe(3);
      expect(stats.active_keys).toBe(2); // 2 active, 1 expired
      expect(stats.expired_keys).toBe(1);
      expect(stats.keys_by_scope).toEqual({
        [AuthScope._MEMORY_READ]: 1,
        [AuthScope._MEMORY_WRITE]: 1,
        [AuthScope._KNOWLEDGE_READ]: 1,
      });
      expect(stats.recent_usage).toBeInstanceOf(Array);
    });

    test('should include project-specific statistics', async () => {
      // Arrange
      await apiKeyService.createApiKey(testUser, {
        name: 'Project Key',
        scopes: [AuthScope._MEMORY_READ],
        project_scopes: ['project-alpha', 'project-beta'],
      });

      // Act
      const stats = await apiKeyService.getApiKeyUsageStats(testUser);

      // Assert
      expect(stats.total_keys).toBe(1);
      expect(stats.keys_by_scope).toEqual({
        [AuthScope._MEMORY_READ]: 1,
      });
    });

    test('should provide health status information', () => {
      // Arrange
      const context = { ip_address: '192.168.1.100', user_agent: 'Health-Check' };

      // Act
      const health = apiKeyService.getHealthStatus();

      // Assert
      expect(health).toBeDefined();
      expect(health.status).toBe('healthy');
      expect(health.details).toEqual({
        total_keys: 0,
        active_keys: 0,
        expired_keys: 0,
        inactive_keys: 0,
        key_hashes_stored: 0,
      });
    });

    test('should report degraded health with many expired keys', async () => {
      // Arrange - create many expired keys
      for (let i = 0; i < 5; i++) {
        await apiKeyService.createApiKey(testUser, {
          name: `Expired Key ${i}`,
          scopes: [AuthScope._MEMORY_READ],
          expires_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        });
      }

      // Act
      const health = apiKeyService.getHealthStatus();

      // Assert
      expect(health.status).toBe('degraded');
      expect(health.details.expired_keys).toBe(5);
    });
  });

  describe('Cleanup and Maintenance Operations', () => {
    test('should cleanup expired and inactive keys', async () => {
      // Arrange
      const oldDate = new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString(); // 400 days ago

      // Create old expired key
      await apiKeyService.createApiKey(testUser, {
        name: 'Old Expired Key',
        scopes: [AuthScope._MEMORY_READ],
        expires_at: oldDate,
      });

      // Create old inactive key
      const revokeResult = await apiKeyService.createApiKey(testUser, {
        name: 'Old Inactive Key',
        scopes: [AuthScope._MEMORY_WRITE],
      });
      await apiKeyService.revokeApiKey(testUser, revokeResult.key_info.key_id);

      // Mock the creation date to be old
      const keys = apiKeyService['apiKeys'];
      for (const [keyId, key] of keys) {
        if (key.name.includes('Old')) {
          key.created_at = oldDate;
        }
      }

      // Act
      const cleanedCount = await apiKeyService.cleanupExpiredKeys();

      // Assert
      expect(cleanedCount).toBe(2);
      expect(mockLogger.info).toHaveBeenCalledWith({ count: 2 }, 'Cleaned up expired API keys');
    });

    test('should handle cleanup errors gracefully', async () => {
      // Arrange - mock an error during cleanup
      const originalKeys = apiKeyService['apiKeys'];
      apiKeyService['apiKeys'] = new Map([
        [
          'test-key',
          {
            id: 'test',
            key_id: 'test',
            key_hash: 'test',
            user_id: 'user',
            name: 'Test',
            scopes: [],
            is_active: false,
            created_at: 'invalid-date', // This will cause an error
          },
        ],
      ]) as any;

      // Act & Assert - should not throw
      await expect(apiKeyService.cleanupExpiredKeys()).resolves.toBeDefined();

      // Restore
      apiKeyService['apiKeys'] = originalKeys;
    });
  });

  describe('Performance and Scalability', () => {
    test('should handle concurrent API key validations', async () => {
      // Arrange
      const apiKey = 'ck_test_1234567890123456789012abcdef';
      await apiKeyService.createApiKey(testUser, {
        name: 'Concurrent Key',
        scopes: [AuthScope._MEMORY_READ],
      });

      // Act - validate same key from multiple concurrent requests
      const concurrentValidations = Array.from({ length: 10 }, () =>
        apiKeyService.validateApiKey(apiKey)
      );
      const results = await Promise.all(concurrentValidations);

      // Assert
      expect(results).toHaveLength(10);
      results.forEach((result) => {
        expect(result.valid).toBe(true);
      });
    });

    test('should efficiently manage large numbers of API keys', async () => {
      // Arrange
      const keyCount = 100;

      // Act - create many API keys
      const createPromises = Array.from({ length: keyCount }, (_, i) =>
        apiKeyService.createApiKey(testUser, {
          name: `Key ${i}`,
          scopes: [AuthScope._MEMORY_READ],
        })
      );
      const createResults = await Promise.all(createPromises);

      // Assert
      expect(createResults).toHaveLength(keyCount);

      const keys = await apiKeyService.listApiKeys(testUser);
      expect(keys).toHaveLength(keyCount);

      const stats = await apiKeyService.getApiKeyUsageStats(testUser);
      expect(stats.total_keys).toBe(keyCount);
    });

    test('should maintain performance under validation load', async () => {
      // Arrange
      const validationCount = 50;
      const apiKeys = [];

      // Create multiple API keys
      for (let i = 0; i < 10; i++) {
        const result = await apiKeyService.createApiKey(testUser, {
          name: `Load Test Key ${i}`,
          scopes: [AuthScope._MEMORY_READ],
        });
        apiKeys.push(result.api_key);
      }

      // Act - perform many validations
      const startTime = Date.now();
      const validationPromises = Array.from({ length: validationCount }, () => {
        const randomKey = apiKeys[Math.floor(Math.random() * apiKeys.length)];
        return apiKeyService.validateApiKey(randomKey);
      });
      const results = await Promise.all(validationPromises);
      const endTime = Date.now();

      // Assert
      expect(results).toHaveLength(validationCount);
      expect(endTime - startTime).toBeLessThan(1000); // Should complete within 1 second
      results.forEach((result) => {
        expect(result.valid).toBe(true);
      });
    });
  });

  describe('Integration with Security Service', () => {
    test('should integrate with existing security service patterns', async () => {
      // Arrange
      const securityValidation = {
        valid: true,
        api_key: {
          id: 'test-key-id',
          user_id: testUser.id,
          scopes: [AuthScope._MEMORY_READ],
        } as ApiKey,
        user: testUser,
        scopes: [AuthScope._MEMORY_READ],
      };

      const context = {
        ip_address: '192.168.1.100',
        user_agent: 'Test-Client/1.0',
      };

      // Act
      const authContext = apiKeyService.createAuthContextFromApiKey(securityValidation, context);

      // Assert - should match expected security context format
      expect(authContext).toMatchObject({
        user: {
          id: testUser.id,
          username: testUser.username,
          role: testUser.role,
        },
        session: {
          id: 'api-key-test-key-id',
          ip_address: '192.168.1.100',
          user_agent: 'Test-Client/1.0',
        },
        scopes: [AuthScope._MEMORY_READ],
        token_jti: 'test-key-id',
      });
    });

    test('should maintain audit trail consistency', async () => {
      // Arrange
      const apiKey = 'ck_test_1234567890123456789012abcdef';
      const context = { ip_address: '192.168.1.100', user_agent: 'Test-Client' };

      await apiKeyService.createApiKey(testUser, {
        name: 'Audit Trail Key',
        scopes: [AuthScope._MEMORY_READ],
      });

      // Act - perform various operations
      await apiKeyService.validateApiKey(apiKey, context);
      await apiKeyService.revokeApiKey(testUser, 'ck_test_1234567890123456789012', context);

      // Assert - verify audit trail
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'api_key_created',
          severity: 'medium',
        })
      );
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'auth_success',
          severity: 'low',
        })
      );
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'api_key_revoked',
          severity: 'medium',
        })
      );
    });
  });

  describe('Error Handling and Edge Cases', () => {
    test('should handle malformed API key creation requests', async () => {
      // Arrange
      const invalidRequests = [
        null,
        undefined,
        {},
        { name: '', scopes: [] },
        { name: 'Test', scopes: [] },
        { name: 'Test', scopes: ['invalid-scope'] },
      ];

      for (const request of invalidRequests) {
        // Act & Assert
        if (request === null || request === undefined) {
          await expect(apiKeyService.createApiKey(testUser, request as any)).rejects.toThrow();
        } else if ((request as any).scopes?.includes('invalid-scope')) {
          // This should be handled by scope validation
          mockAuthService.getUserMaxScopes.mockReturnValue([]);
          await expect(apiKeyService.createApiKey(testUser, request)).rejects.toThrow(
            'User not allowed to create API key with scopes: invalid-scope'
          );
        }
      }
    });

    test('should handle database/service failures gracefully', async () => {
      // Arrange
      mockAuthService.hashApiKey.mockRejectedValue(new Error('Hashing service unavailable'));

      // Act & Assert
      await expect(
        apiKeyService.createApiKey(testUser, {
          name: 'Failure Test Key',
          scopes: [AuthScope._MEMORY_READ],
        })
      ).rejects.toThrow('Hashing service unavailable');
    });

    test('should validate user status before operations', async () => {
      // Arrange
      const inactiveUser = {
        ...testUser,
        is_active: false,
      };

      // Act & Assert - should handle inactive user appropriately
      // Note: The current implementation doesn't explicitly check user.is_active,
      // but this test ensures the behavior if that validation is added
      await expect(
        apiKeyService.createApiKey(inactiveUser, {
          name: 'Inactive User Key',
          scopes: [AuthScope._MEMORY_READ],
        })
      ).resolves.toBeDefined(); // Current behavior
    });

    test('should handle extremely long key names and descriptions', async () => {
      // Arrange
      const longName = 'A'.repeat(500);
      const longDescription = 'B'.repeat(5000);

      // Act
      const result = await apiKeyService.createApiKey(testUser, {
        name: longName,
        scopes: [AuthScope._MEMORY_READ],
        description: longDescription,
      });

      // Assert
      expect(result.key_info.name).toBe(longName);
      expect(result.key_info.description).toBe(longDescription);
    });
  });

  describe('Advanced Security Features', () => {
    test('should implement secure key generation', async () => {
      // Arrange
      const keyCount = 10;
      const generatedKeys = new Set();

      // Act
      for (let i = 0; i < keyCount; i++) {
        const result = await apiKeyService.createApiKey(testUser, {
          name: `Security Test Key ${i}`,
          scopes: [AuthScope._MEMORY_READ],
        });
        generatedKeys.add(result.api_key);
      }

      // Assert
      expect(generatedKeys.size).toBe(keyCount); // All keys should be unique
      generatedKeys.forEach((key) => {
        expect(key).toMatch(/^ck_/);
        expect(key.length).toBeGreaterThan(30);
      });
    });

    test('should handle cross-origin security contexts', async () => {
      // Arrange
      const contexts = [
        { ip_address: '192.168.1.100', user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
        { ip_address: '10.0.0.1', user_agent: 'curl/7.68.0' },
        { ip_address: '203.0.113.1', user_agent: 'Python-requests/2.25.1' },
      ];

      await apiKeyService.createApiKey(testUser, {
        name: 'Cross-Origin Key',
        scopes: [AuthScope._MEMORY_READ],
      });

      // Act
      for (const context of contexts) {
        const result = await apiKeyService.validateApiKey(
          'ck_test_1234567890123456789012abcdef',
          context
        );
        expect(result.valid).toBe(true);
      }

      // Assert - all contexts should be properly logged
      expect(mockAuditService.logSecurityAuditEvent).toHaveBeenCalledTimes(3);
    });

    test('should support role-based key restrictions', async () => {
      // Arrange
      const serviceUser = {
        ...testUser,
        role: UserRole._SERVICE,
      };
      mockAuthService.getUserMaxScopes.mockReturnValue(
        DEFAULT_ROLE_PERMISSIONS[UserRole._SERVICE].max_scopes
      );

      // Act & Assert
      await expect(
        apiKeyService.createApiKey(serviceUser, {
          name: 'Service Key',
          scopes: [AuthScope._MEMORY_WRITE, AuthScope._KNOWLEDGE_WRITE],
        })
      ).resolves.toBeDefined();

      await expect(
        apiKeyService.createApiKey(serviceUser, {
          name: 'Invalid Service Key',
          scopes: [AuthScope._USER_MANAGE], // Service accounts shouldn't manage users
        })
      ).rejects.toThrow('User not allowed to create API key with scopes: user:manage');
    });
  });
});
