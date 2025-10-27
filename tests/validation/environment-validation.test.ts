/**
 * Comprehensive Environment Configuration Validation Tests
 *
 * Tests for:
 * - All environment variables validation
 * - Environment-specific configurations
 * - Missing variable detection
 * - Configuration consistency
 * - Security validation
 * - Performance validation
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { Environment } from '../config/environment.ts';

describe('Environment Configuration Validation', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('Basic Environment Loading', () => {
    it('should load with minimal configuration', () => {
      process.env.NODE_ENV = 'development';
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'test-key';

      const env = Environment.getInstance();
      expect(env.isDevelopmentMode()).toBe(true);
      expect(env.isProductionMode()).toBe(false);
      expect(env.isTestMode()).toBe(false);
    });

    it('should handle production environment', () => {
      process.env.NODE_ENV = 'production';
      process.env.QDRANT_URL = 'https://qdrant.example.com';
      process.env.OPENAI_API_KEY = 'prod-key';
      process.env.JWT_SECRET = 'a'.repeat(32);
      process.env.ENCRYPTION_KEY = 'b'.repeat(32);
      process.env.JWT_REFRESH_SECRET = 'c'.repeat(32);

      const env = Environment.getInstance();
      expect(env.isProductionMode()).toBe(true);
      expect(env.isDevelopmentMode()).toBe(false);
    });

    it('should handle test environment', () => {
      process.env.NODE_ENV = 'test';
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'test-key';

      const env = Environment.getInstance();
      expect(env.isTestMode()).toBe(true);
      expect(env.isDevelopmentMode()).toBe(false);
      expect(env.isProductionMode()).toBe(false);
    });
  });

  describe('Database Configuration Validation', () => {
    it('should validate Qdrant configuration', () => {
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.VECTOR_SIZE = '1536';
      process.env.VECTOR_DISTANCE = 'Cosine';
      process.env.QDRANT_COLLECTION_NAME = 'test-collection';

      const env = Environment.getInstance();
      const qdrantConfig = env.getQdrantConfig();

      expect(qdrantConfig.url).toBe('http://localhost:6333');
      expect(qdrantConfig.vectorSize).toBe(1536);
      expect(qdrantConfig.distance).toBe('Cosine');
      expect(qdrantConfig.collectionName).toBe('test-collection');
    });

    it('should validate database connection configuration', () => {
      process.env.DB_HOST = 'localhost';
      process.env.DB_PORT = '5433';
      process.env.DB_NAME = 'test_db';
      process.env.DB_USER = 'test_user';
      process.env.DB_PASSWORD = 'test_password';
      process.env.DB_SSL = 'true';
      process.env.DB_QUERY_TIMEOUT = '45000';
      process.env.DB_STATEMENT_TIMEOUT = '30000';
      process.env.DB_MAX_USES = '10000';

      const env = Environment.getInstance();
      const dbConfig = env.getDatabaseConnectionConfig();

      expect(dbConfig.host).toBe('localhost');
      expect(dbConfig.port).toBe(5433);
      expect(dbConfig.database).toBe('test_db');
      expect(dbConfig.user).toBe('test_user');
      expect(dbConfig.password).toBe('test_password');
      expect(dbConfig.ssl).toBe(true);
      expect(dbConfig.queryTimeout).toBe(45000);
      expect(dbConfig.statementTimeout).toBe(30000);
      expect(dbConfig.maxUses).toBe(10000);
    });

    it('should handle DATABASE_URL fallback', () => {
      process.env.DATABASE_URL = 'http://qdrant.example.com:6333';
      process.env.QDRANT_URL = '';

      const env = Environment.getInstance();
      const qdrantConfig = env.getQdrantConfig();

      expect(qdrantConfig.url).toBe('http://qdrant.example.com:6333');
    });
  });

  describe('Security Configuration Validation', () => {
    it('should validate security configuration', () => {
      process.env.JWT_SECRET = 'a'.repeat(32);
      process.env.JWT_REFRESH_SECRET = 'b'.repeat(32);
      process.env.ENCRYPTION_KEY = 'c'.repeat(32);

      const env = Environment.getInstance();
      const securityConfig = env.getSecurityConfig();

      expect(securityConfig.jwtSecret).toBe('a'.repeat(32));
      expect(securityConfig.jwtRefreshSecret).toBe('b'.repeat(32));
      expect(securityConfig.encryptionKey).toBe('c'.repeat(32));
    });

    it('should require security keys in production', () => {
      process.env.NODE_ENV = 'production';
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'test-key';

      const env = Environment.getInstance();
      const validation = env.validateRequiredConfig();

      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('JWT_SECRET is required in production');
      expect(validation.errors).toContain('ENCRYPTION_KEY is required in production');
      expect(validation.errors).toContain('JWT_REFRESH_SECRET is required in production');
    });

    it('should validate JWT secret length', () => {
      process.env.JWT_SECRET = 'short';

      expect(() => {
        new Environment();
      }).toThrow();
    });
  });

  describe('Vector Configuration Validation', () => {
    it('should validate vector size options', () => {
      const validSizes = [384, 768, 1024, 1536, 2048, 3072];

      for (const size of validSizes) {
        process.env.VECTOR_SIZE = size.toString();
        const env = new Environment();
        const config = env.getQdrantConfig();
        expect(config.vectorSize).toBe(size);
      }
    });

    it('should reject invalid vector sizes', () => {
      process.env.VECTOR_SIZE = '999';

      expect(() => {
        new Environment();
      }).toThrow();
    });

    it('should validate embedding model consistency', () => {
      process.env.EMBEDDING_MODEL = 'text-embedding-ada-002';
      process.env.VECTOR_SIZE = '1536';

      const env = Environment.getInstance();
      const validation = env.validateRequiredConfig();
      expect(validation.valid).toBe(true);

      // Test inconsistency
      process.env.VECTOR_SIZE = '768';
      const env2 = new Environment();
      const validation2 = env2.validateRequiredConfig();
      expect(validation2.valid).toBe(false);
      expect(validation2.errors).toContain('VECTOR_SIZE must be 1536 for text-embedding-ada-002 model');
    });
  });

  describe('Environment-Specific Configuration', () => {
    it('should provide production defaults', () => {
      process.env.NODE_ENV = 'production';

      const env = Environment.getInstance();
      const defaults = env.getEnvironmentSpecificDefaults();

      expect(defaults.LOG_LEVEL).toBe('warn');
      expect(defaults.METRICS_ENABLED).toBe(true);
      expect(defaults.ENABLE_AUTH).toBe(true);
      expect(defaults.CACHE_TTL).toBe(7200);
    });

    it('should provide development defaults', () => {
      process.env.NODE_ENV = 'development';

      const env = Environment.getInstance();
      const defaults = env.getEnvironmentSpecificDefaults();

      expect(defaults.LOG_LEVEL).toBe('debug');
      expect(defaults.DEBUG_MODE).toBe(true);
      expect(defaults.HOT_RELOAD).toBe(true);
    });

    it('should provide test defaults', () => {
      process.env.NODE_ENV = 'test';

      const env = Environment.getInstance();
      const defaults = env.getEnvironmentSpecificDefaults();

      expect(defaults.LOG_LEVEL).toBe('error');
      expect(defaults.METRICS_ENABLED).toBe(false);
      expect(defaults.ENABLE_AUTH).toBe(false);
      expect(defaults.MOCK_EXTERNAL_SERVICES).toBe(true);
    });

    it('should validate environment-specific requirements', () => {
      process.env.NODE_ENV = 'production';
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'test-key';
      process.env.LOG_LEVEL = 'debug';

      const env = Environment.getInstance();
      const validation = env.validateEnvironmentSpecificRequirements();

      expect(validation.valid).toBe(false); // Missing security keys
      expect(validation.warnings).toContain('Debug logging enabled in production');
    });
  });

  describe('Testing Configuration Validation', () => {
    it('should validate testing configuration', () => {
      process.env.TEST_DATABASE_URL = 'http://localhost:6333/test';
      process.env.GITHUB_ACTIONS = 'true';
      process.env.CODECOV_TOKEN = 'test-token';
      process.env.GITHUB_SHA = 'abc123';
      process.env.GITHUB_REF_NAME = 'main';

      const env = Environment.getInstance();
      const testingConfig = env.getTestingConfig();

      expect(testingConfig.testDatabaseUrl).toBe('http://localhost:6333/test');
      expect(testingConfig.isCiCd).toBe(true);
      expect(testingConfig.codecovToken).toBe('test-token');
      expect(testingConfig.githubSha).toBe('abc123');
      expect(testingConfig.githubRefName).toBe('main');
    });

    it('should require test database URL in test mode', () => {
      process.env.NODE_ENV = 'test';
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'test-key';

      const env = Environment.getInstance();
      const validation = env.validateEnvironmentSpecificRequirements();

      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('TEST_DATABASE_URL or DATABASE_URL is required in test mode');
    });
  });

  describe('Performance Configuration Validation', () => {
    it('should validate pool configuration', () => {
      process.env.DB_POOL_MIN = '5';
      process.env.DB_POOL_MAX = '20';
      process.env.DB_IDLE_TIMEOUT_MS = '60000';
      process.env.DB_CONNECTION_TIMEOUT_MS = '15000';

      const env = Environment.getInstance();
      const batchConfig = env.getBatchConfig();

      expect(batchConfig.retryAttempts).toBeDefined();
      expect(batchConfig.retryDelay).toBeDefined();
    });

    it('should validate cache configuration', () => {
      process.env.CACHE_TTL = '7200';
      process.env.CACHE_MAX_SIZE = '2000';
      process.env.ENABLE_CACHING = 'true';

      const env = Environment.getInstance();
      const cacheConfig = env.getCacheConfig();

      expect(cacheConfig.enabled).toBe(true);
      expect(cacheConfig.ttl).toBe(7200);
      expect(cacheConfig.maxSize).toBe(2000);
    });

    it('should validate API configuration', () => {
      process.env.API_RATE_LIMIT = '200';
      process.env.API_TIMEOUT = '60000';
      process.env.ENABLE_AUTH = 'true';

      const env = Environment.getInstance();
      const apiConfig = env.getApiConfig();

      expect(apiConfig.rateLimit).toBe(200);
      expect(apiConfig.timeout).toBe(60000);
      expect(apiConfig.authEnabled).toBe(true);
    });
  });

  describe('Feature Flag Validation', () => {
    it('should validate feature flags', () => {
      process.env.ENABLE_AUTH = 'true';
      process.env.ENABLE_CACHING = 'false';
      process.env.ENABLE_METRICS = 'true';
      process.env.ENABLE_LOGGING = 'true';

      const env = Environment.getInstance();

      expect(env.getFeatureFlag('auth')).toBe(true);
      expect(env.getFeatureFlag('caching')).toBe(false);
      expect(env.getFeatureFlag('metrics')).toBe(true);
      expect(env.getFeatureFlag('logging')).toBe(true);
    });

    it('should handle unknown feature flags', () => {
      const env = Environment.getInstance();
      expect(env.getFeatureFlag('unknown')).toBe(false);
    });
  });

  describe('MCP Configuration Validation', () => {
    it('should validate MCP configuration', () => {
      process.env.MCP_SERVER_NAME = 'test-server';
      process.env.MCP_SERVER_VERSION = '1.0.0';
      process.env.MCP_TRANSPORT = 'http';

      const env = Environment.getInstance();
      const mcpConfig = env.getMcpConfig();

      expect(mcpConfig.serverName).toBe('test-server');
      expect(mcpConfig.serverVersion).toBe('1.0.0');
      expect(mcpConfig.transport).toBe('http');
    });

    it('should validate scope configuration', () => {
      process.env.CORTEX_ORG = 'test-org';
      process.env.CORTEX_PROJECT = 'test-project';
      process.env.CORTEX_BRANCH = 'test-branch';

      const env = Environment.getInstance();
      const scopeConfig = env.getScopeConfig();

      expect(scopeConfig.org).toBe('test-org');
      expect(scopeConfig.project).toBe('test-project');
      expect(scopeConfig.branch).toBe('test-branch');
    });
  });

  describe('Configuration Export Validation', () => {
    it('should export configuration for MCP', () => {
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'test-key';
      process.env.ENABLE_CACHING = 'true';
      process.env.METRICS_ENABLED = 'true';

      const env = Environment.getInstance();
      const exportedConfig = env.exportForMcp();

      expect(exportedConfig.database).toBeDefined();
      expect(exportedConfig.application).toBeDefined();
      expect(exportedConfig.features).toBeDefined();
      expect(exportedConfig.environment).toBeDefined();
      expect(exportedConfig.mcp).toBeDefined();
      expect(exportedConfig.scope).toBeDefined();

      expect(exportedConfig.features.caching).toBe(true);
      expect(exportedConfig.features.metrics).toBe(true);
    });

    it('should generate configuration hash', () => {
      const env = Environment.getInstance();
      const hash1 = env.generateConfigHash();
      const hash2 = env.generateConfigHash();

      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/); // SHA-256 hash
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid URLs', () => {
      process.env.QDRANT_URL = 'invalid-url';

      expect(() => {
        new Environment();
      }).toThrow();
    });

    it('should handle invalid numbers', () => {
      process.env.VECTOR_SIZE = 'not-a-number';

      expect(() => {
        new Environment();
      }).toThrow();
    });

    it('should handle invalid booleans', () => {
      process.env.ENABLE_CACHING = 'maybe';

      expect(() => {
        new Environment();
      }).toThrow();
    });

    it('should handle invalid enums', () => {
      process.env.NODE_ENV = 'invalid-env';
      process.env.VECTOR_DISTANCE = 'InvalidDistance';

      expect(() => {
        new Environment();
      }).toThrow();
    });
  });

  describe('Integration with Existing Code', () => {
    it('should be compatible with existing environment variable usage', () => {
      // Test all the environment variables found in the codebase
      process.env.DATABASE_URL = 'http://localhost:6333';
      process.env.DB_HOST = 'localhost';
      process.env.DB_PORT = '5433';
      process.env.DB_NAME = 'cortex_prod';
      process.env.DB_USER = 'cortex';
      process.env.DB_PASSWORD = 'password';
      process.env.DB_POOL_MIN = '5';
      process.env.DB_POOL_MAX = '20';
      process.env.DB_IDLE_TIMEOUT_MS = '30000';
      process.env.DB_CONNECTION_TIMEOUT_MS = '10000';
      process.env.DB_QUERY_TIMEOUT = '30000';
      process.env.DB_STATEMENT_TIMEOUT = '30000';
      process.env.DB_MAX_USES = '7500';
      process.env.DB_SSL = 'false';
      process.env.LOG_LEVEL = 'info';
      process.env.NODE_ENV = 'development';
      process.env.MCP_TRANSPORT = 'stdio';
      process.env.CORTEX_ORG = 'test-org';
      process.env.CORTEX_PROJECT = 'test-project';
      process.env.CORTEX_BRANCH = 'main';
      process.env.OPENAI_API_KEY = 'test-key';
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.QDRANT_API_KEY = 'qdrant-key';
      process.env.VECTOR_SIZE = '1536';
      process.env.VECTOR_DISTANCE = 'Cosine';
      process.env.QDRANT_COLLECTION_NAME = 'cortex-memory';
      process.env.JWT_SECRET = 'a'.repeat(32);
      process.env.JWT_REFRESH_SECRET = 'b'.repeat(32);
      process.env.ENCRYPTION_KEY = 'c'.repeat(32);
      process.env.TEST_DATABASE_URL = 'http://localhost:6333/test';
      process.env.CODECOV_TOKEN = 'codecov-token';
      process.env.GITHUB_SHA = 'abc123';
      process.env.GITHUB_REF_NAME = 'main';
      process.env.GITHUB_ACTIONS = 'false';

      expect(() => {
        const env = Environment.getInstance();
        const validation = env.validateRequiredConfig();
        expect(validation.valid).toBe(true);
      }).not.toThrow();
    });
  });
});