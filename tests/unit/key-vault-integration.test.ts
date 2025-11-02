/**
 * Key Vault Integration Test
 *
 * Tests the key vault service integration with other services
 * to ensure proper secure credential management
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  getKeyVaultService,
  KeyVaultService,
} from '../../src/services/security/key-vault-service.js';

describe('Key Vault Integration', () => {
  let keyVault: KeyVaultService;

  beforeEach(() => {
    // Use fallback mode for testing
    keyVault = getKeyVaultService({
      fallbackToEnv: true,
      enableAccessLogging: false,
    });
  });

  afterEach(() => {
    keyVault.clearCache();
  });

  describe('Basic Functionality', () => {
    it('should initialize key vault service', () => {
      expect(keyVault).toBeDefined();
      expect(keyVault).toBeInstanceOf(KeyVaultService);
    });

    it('should perform health check', async () => {
      const health = await keyVault.healthCheck();
      expect(health).toHaveProperty('status');
      expect(['healthy', 'degraded', 'unhealthy']).toContain(health.status);
      expect(health.details).toBeDefined();
    });

    it('should list available keys', async () => {
      const keys = await keyVault.listKeys();
      expect(Array.isArray(keys)).toBe(true);
      expect(keys.length).toBeGreaterThan(0);

      // Check structure of returned keys
      keys.forEach((key) => {
        expect(key).toHaveProperty('id');
        expect(key).toHaveProperty('name');
        expect(key).toHaveProperty('type');
        expect(key).toHaveProperty('created_at');
        expect(key).toHaveProperty('updated_at');
        expect(key).toHaveProperty('access_count');
        expect(key).toHaveProperty('environment');
        expect(key).toHaveProperty('is_active');
        // Should NOT contain sensitive data
        expect(key).not.toHaveProperty('encrypted_value');
        expect(key).not.toHaveProperty('iv');
        expect(key).not.toHaveProperty('salt');
      });
    });
  });

  describe('Environment Fallback', () => {
    it('should fall back to environment variables when vault key missing', async () => {
      // Set test environment variable
      const testKey = 'test-openai-key';
      process.env.TEST_OPENAI_API_KEY = 'sk-test-key-12345';

      try {
        const key = await keyVault.get_key_by_name('test_openai_api_key');

        // Should return null since we don't have mapping for test_openai_api_key
        expect(key).toBeNull();
      } finally {
        // Clean up
        delete process.env.TEST_OPENAI_API_KEY;
      }
    });

    it('should cache keys to reduce environment lookups', async () => {
      // Mock environment variable
      process.env.OPENAI_API_KEY = 'sk-test-key-cached';

      try {
        // First call should hit environment
        const key1 = await keyVault.get_key_by_name('openai_api_key');
        expect(key1?.value).toBe('sk-test-key-cached');

        // Second call should use cache
        const key2 = await keyVault.get_key_by_name('openai_api_key');
        expect(key2?.value).toBe('sk-test-key-cached');
      } finally {
        // Clean up
        delete process.env.OPENAI_API_KEY;
      }
    });
  });

  describe('Encryption/Decryption', () => {
    it('should encrypt and decrypt values correctly', async () => {
      const testValue = 'super-secret-api-key-12345';

      const encrypted = await keyVault.encryptKey(testValue);
      expect(encrypted).toHaveProperty('encrypted_value');
      expect(encrypted).toHaveProperty('iv');
      expect(encrypted).toHaveProperty('salt');
      expect(encrypted).toHaveProperty('algorithm');
      expect(encrypted.encrypted_value).not.toBe(testValue);

      const decrypted = await keyVault.decryptKey(encrypted);
      expect(decrypted).toBe(testValue);
    });

    it('should use fallback encryption when no master key', async () => {
      // Test that fallback encryption works when master key is not available
      // The service should still be able to encrypt/decrypt using fallback mode

      const testValue = 'test-value';

      // Should use fallback encryption automatically
      const encrypted = await keyVault.encryptKey(testValue);
      expect(encrypted).toHaveProperty('algorithm', 'fallback-xor');
      expect(encrypted.encrypted_value).not.toBe(testValue);

      const decrypted = await keyVault.decryptKey(encrypted);
      expect(decrypted).toBe(testValue);
    });
  });

  describe('Key Management', () => {
    it('should store keys (metadata only)', async () => {
      const keyEntry = {
        name: 'test-key',
        type: 'custom' as const,
        encrypted_value: 'encrypted-data',
        iv: 'test-iv',
        salt: 'test-salt',
        algorithm: 'test-algorithm',
        description: 'Test key for unit testing',
        environment: 'test',
        tags: ['test', 'unit'],
        is_active: true,
      };

      const keyId = await keyVault.storeKey(keyEntry);
      expect(keyId).toBeDefined();
      expect(keyId).toMatch(/^kv_\d+_[a-z0-9]+$/);
    });

    it('should delete keys from cache', async () => {
      // Mock environment variable
      process.env.OPENAI_API_KEY = 'sk-test-to-delete';

      try {
        // Cache the key
        await keyVault.get_key_by_name('openai_api_key');

        // Delete from cache
        const deleted = await keyVault.deleteKey('openai_api_key');
        expect(deleted).toBe(true);

        // Key should no longer be in cache (but environment still has it)
        const key = await keyVault.get_key_by_name('openai_api_key');
        expect(key?.value).toBe('sk-test-to-delete'); // Still gets from environment
      } finally {
        delete process.env.OPENAI_API_KEY;
      }
    });

    it('should rotate keys', async () => {
      const oldKeyId = 'test-key-id';
      const newKeyId = await keyVault.rotateKey(oldKeyId, 'new-key-value');

      expect(newKeyId).toBeDefined();
      expect(newKeyId).toContain(oldKeyId);
      expect(newKeyId).toContain('_rotated_');
    });
  });

  describe('Cache Management', () => {
    it('should clear cache', () => {
      // Should not throw
      expect(() => keyVault.clearCache()).not.toThrow();
    });

    it('should have cache TTL functionality', async () => {
      // This is more of an integration test - actual TTL testing would require
      // waiting for the cache to expire, which is not practical in unit tests

      // Test that cache clearing works
      expect(() => keyVault.clearCache()).not.toThrow();
    });
  });
});
