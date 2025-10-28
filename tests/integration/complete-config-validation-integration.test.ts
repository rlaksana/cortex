/**
 * Complete Configuration Validation Integration Test
 *
 * Integration test that validates the entire configuration system
 * including environment variables, validation rules, and service integration.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { Environment } from ' '../../src/config/environment.js';
import { configValidator } from ' '../../src/config/validation.js';

describe('Complete Configuration Validation Integration', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('Environment Variable Coverage', () => {
    it('should validate complete production configuration', async () => {
      // Set up a complete production configuration
      process.env.NODE_ENV = 'production';
      process.env.QDRANT_URL = 'https://qdrant.production.example.com';
      process.env.QDRANT_API_KEY = 'prod-qdrant-key';
      process.env.OPENAI_API_KEY = 'prod-openai-key';
      process.env.JWT_SECRET = 'a'.repeat(64); // Strong secret
      process.env.JWT_REFRESH_SECRET = 'b'.repeat(64); // Strong refresh secret
      process.env.ENCRYPTION_KEY = 'c'.repeat(64); // Strong encryption key
      process.env.VECTOR_SIZE = '1536';
      process.env.VECTOR_DISTANCE = 'Cosine';
      process.env.EMBEDDING_MODEL = 'text-embedding-ada-002';
      process.env.LOG_LEVEL = 'warn';
      process.env.ENABLE_AUTH = 'true';
      process.env.ENABLE_CACHING = 'true';
      process.env.METRICS_ENABLED = 'true';

      const env = Environment.getInstance();
      const validation = env.validateRequiredConfig();

      expect(validation.valid).toBe(true);
      expect(validation.errors).toHaveLength(0);

      // Verify production-specific settings
      expect(env.isProductionMode()).toBe(true);
      expect(env.getFeatureFlag('auth')).toBe(true);
      expect(env.getFeatureFlag('caching')).toBe(true);
    });

    it('should reject production configuration with weak security', async () => {
      process.env.NODE_ENV = 'production';
      process.env.QDRANT_URL = 'https://qdrant.example.com';
      process.env.OPENAI_API_KEY = 'test-key';
      process.env.JWT_SECRET = 'weak'; // Too short
      process.env.LOG_LEVEL = 'debug'; // Too verbose for production

      const env = Environment.getInstance();
      const validation = env.validateRequiredConfig();

      expect(validation.valid).toBe(false);
      expect(validation.errors.length).toBeGreaterThan(0);
    });
  });

  describe('Development Configuration Validation', () => {
    it('should validate development configuration with sensible defaults', async () => {
      process.env.NODE_ENV = 'development';
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'dev-key';
      process.env.LOG_LEVEL = 'debug';
      process.env.DEBUG_MODE = 'true';
      process.env.HOT_RELOAD = 'true';
      process.env.ENABLE_AUTH = 'false';

      const env = Environment.getInstance();
      const validation = env.validateRequiredConfig();

      expect(validation.valid).toBe(true);
      expect(validation.errors).toHaveLength(0);

      expect(env.isDevelopmentMode()).toBe(true);
      expect(env.getFeatureFlag('auth')).toBe(false);
    });
  });

  describe('Testing Configuration Validation', () => {
    it('should validate test configuration', async () => {
      process.env.NODE_ENV = 'test';
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'test-key';
      process.env.TEST_QDRANT_URL = 'http://localhost:6334/test';
      process.env.LOG_LEVEL = 'error';
      process.env.METRICS_ENABLED = 'false';
      process.env.ENABLE_AUTH = 'false';
      process.env.MOCK_EXTERNAL_SERVICES = 'true';

      const env = Environment.getInstance();
      const validation = env.validateRequiredConfig();

      expect(validation.valid).toBe(true);
      expect(validation.errors).toHaveLength(0);

      expect(env.isTestMode()).toBe(true);
    });
  });

  describe('Database Configuration Integration', () => {
    it('should validate Qdrant configuration', async () => {
      process.env.QDRANT_URL = 'http://qdrant.example.com:6333';
      process.env.QDRANT_API_KEY = 'qdrant-key';
      process.env.OPENAI_API_KEY = 'openai-key';
      process.env.EMBEDDING_MODEL = 'text-embedding-ada-002';
      process.env.VECTOR_SIZE = '1536';
      process.env.VECTOR_DISTANCE = 'Cosine';

      const env = Environment.getInstance();
      const validation = env.validateRequiredConfig();

      expect(validation.valid).toBe(true);

      const dbConfig = env.getDatabaseConnectionConfig();
      expect(dbConfig.url).toBe('http://qdrant.example.com:6333');
      expect(dbConfig.vectorSize).toBe(1536);
      expect(dbConfig.distance).toBe('Cosine');
    });

    it('should validate vector configuration consistency', async () => {
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'test-key';
      process.env.EMBEDDING_MODEL = 'text-embedding-ada-002';
      process.env.VECTOR_SIZE = '1536';
      process.env.VECTOR_DISTANCE = 'Cosine';

      const env = Environment.getInstance();
      const validation = env.validateRequiredConfig();
      expect(validation.valid).toBe(true);

      // Test inconsistency
      process.env.VECTOR_SIZE = '768'; // Wrong size for the model

      const validation2 = env.validateRequiredConfig();
      expect(validation2.valid).toBe(false);
      expect(validation2.errors.some(e => e.includes('VECTOR_SIZE'))).toBe(true);
    });
  });

  describe('Security Configuration Integration', () => {
    it('should validate complete security configuration', async () => {
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'test-key';
      process.env.JWT_SECRET = 'a'.repeat(64);
      process.env.JWT_REFRESH_SECRET = 'b'.repeat(64);
      process.env.ENCRYPTION_KEY = 'c'.repeat(64);
      process.env.ENABLE_AUTH = 'true';

      const env = Environment.getInstance();
      const validation = env.validateRequiredConfig();
      expect(validation.valid).toBe(true);

      const securityConfig = env.getSecurityConfig();
      expect(securityConfig.jwtSecret).toBe('a'.repeat(64));
      expect(securityConfig.jwtRefreshSecret).toBe('b'.repeat(64));
      expect(securityConfig.encryptionKey).toBe('c'.repeat(64));
      expect(env.getFeatureFlag('auth')).toBe(true);
    });
  });

  describe('Performance Configuration Integration', () => {
    it('should validate performance configuration', async () => {
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'test-key';
      process.env.CACHE_TTL = '7200';
      process.env.CACHE_MAX_SIZE = '2000';
      process.env.SEARCH_LIMIT = '100';
      process.env.BATCH_SIZE = '75';
      process.env.API_RATE_LIMIT = '200';
      process.env.METRICS_ENABLED = 'true';

      const env = Environment.getInstance();
      const validation = env.validateRequiredConfig();
      expect(validation.valid).toBe(true);

      const cacheConfig = env.getCacheConfig();
      const searchConfig = env.getSearchConfig();
      const batchConfig = env.getBatchConfig();
      const apiConfig = env.getApiConfig();

      expect(cacheConfig.ttl).toBe(7200);
      expect(cacheConfig.maxSize).toBe(2000);
      expect(searchConfig.limit).toBe(100);
      expect(batchConfig.size).toBe(75);
      expect(apiConfig.rateLimit).toBe(200);
    });
  });

  describe('Configuration Export and Integration', () => {
    it('should export configuration for MCP integration', () => {
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'test-key';
      process.env.ENABLE_CACHING = 'true';
      process.env.METRICS_ENABLED = 'true';
      process.env.CORTEX_ORG = 'test-org';
      process.env.CORTEX_PROJECT = 'test-project';

      const env = Environment.getInstance();
      const exported = env.exportForMcp();

      expect(exported.database).toBeDefined();
      expect(exported.application).toBeDefined();
      expect(exported.features).toBeDefined();
      expect(exported.environment).toBeDefined();
      expect(exported.mcp).toBeDefined();
      expect(exported.scope).toBeDefined();

      expect(exported.features.caching).toBe(true);
      expect(exported.features.metrics).toBe(true);
      expect(exported.scope.org).toBe('test-org');
      expect(exported.scope.project).toBe('test-project');
    });

    it('should maintain configuration hash consistency', () => {
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'test-key';

      const env = Environment.getInstance();
      const hash1 = env.generateConfigHash();
      const hash2 = env.generateConfigHash();

      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('Real-world Configuration Scenarios', () => {
    it('should handle Docker development environment', async () => {
      // Simulate Docker Compose development environment
      process.env.NODE_ENV = 'development';
      process.env.QDRANT_URL = 'http://qdrant:6333';
      process.env.OPENAI_API_KEY = 'sk-test-key';
      process.env.LOG_LEVEL = 'info';
      process.env.ENABLE_CACHING = 'true';
      process.env.METRICS_ENABLED = 'true';

      const env = Environment.getInstance();
      const validation = env.validateRequiredConfig();
      expect(validation.valid).toBe(true);

      expect(env.isDevelopmentMode()).toBe(true);
    });

    it('should handle CI/CD environment', async () => {
      // Simulate GitHub Actions CI environment
      process.env.NODE_ENV = 'test';
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'sk-test-key';
      process.env.TEST_QDRANT_URL = 'http://localhost:6334/ci_test';
      process.env.LOG_LEVEL = 'error';
      process.env.GITHUB_ACTIONS = 'true';
      process.env.GITHUB_SHA = 'abc123def456';
      process.env.GITHUB_REF_NAME = 'pull/123/head';

      const env = Environment.getInstance();
      const validation = env.validateRequiredConfig();
      expect(validation.valid).toBe(true);

      expect(env.isTestMode()).toBe(true);
    });

    it('should handle minimal production deployment', async () => {
      // Simulate minimal production deployment with required variables only
      process.env.NODE_ENV = 'production';
      process.env.QDRANT_URL = 'https://qdrant.production.com';
      process.env.OPENAI_API_KEY = 'sk-prod-key';
      process.env.JWT_SECRET = 'a'.repeat(64);
      process.env.JWT_REFRESH_SECRET = 'b'.repeat(64);
      process.env.ENCRYPTION_KEY = 'c'.repeat(64);
      process.env.LOG_LEVEL = 'warn';

      const env = Environment.getInstance();
      const validation = env.validateRequiredConfig();
      expect(validation.valid).toBe(true);

      expect(env.isProductionMode()).toBe(true);
    });
  });
});