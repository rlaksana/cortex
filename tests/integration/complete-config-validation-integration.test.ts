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

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { Environment } from '../config/environment.ts';
import { configValidator } from '../config/validation.ts';
import {
  validateCompleteConfiguration,
  generateEnvironmentCoverageReport,
  validateEnvironmentTsCoverage,
  validateVariable
} from '../validation/config-test-helper.ts';

describe('Complete Configuration Validation Integration', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('Environment Variable Coverage', () => {
    it('should have complete environment.ts coverage of all codebase variables', () => {
      const coverage = validateEnvironmentTsCoverage();

      expect(coverage.valid).toBe(true);
      expect(coverage.missingInEnvironmentTs).toHaveLength(0);

      // Log any extra variables (these might be intentionally added)
      if (coverage.extraInEnvironmentTs.length > 0) {
        console.log('Extra variables in environment.ts:', coverage.extraInEnvironmentTs);
      }
    });

    it('should generate comprehensive coverage report', () => {
      const coverage = generateEnvironmentCoverageReport();

      expect(coverage.total).toBeGreaterThan(40); // Should track at least 40 variables
      expect(coverage.byCategory).toHaveProperty('database');
      expect(coverage.byCategory).toHaveProperty('security');
      expect(coverage.byCategory).toHaveProperty('performance');
      expect(coverage.byCategory).toHaveProperty('testing');
      expect(coverage.byCategory).toHaveProperty('cicd');
      expect(coverage.byCategory).toHaveProperty('general');

      // Database category should have the most variables
      expect(coverage.byCategory.database.total).toBeGreaterThan(10);

      console.log('Environment Variable Coverage Report:', JSON.stringify(coverage, null, 2));
    });
  });

  describe('Production Configuration Validation', () => {
    it('should validate complete production configuration', async () => {
      // Set up a complete production configuration
      process.env.NODE_ENV = 'production';
      process.env.QDRANT_URL = 'https://qdrant.production.example.com';
      process.env.QDRANT_API_KEY = 'prod-qdrant-key';
      process.env.OPENAI_API_KEY = 'prod-openai-key';
      process.env.JWT_SECRET = 'a'.repeat(64); // Strong secret
      process.env.JWT_REFRESH_SECRET = 'b'.repeat(64); // Strong refresh secret
      process.env.ENCRYPTION_KEY = 'c'.repeat(64); // Strong encryption key
      process.env.DB_HOST = 'prod-db.example.com';
      process.env.DB_PORT = '5432';
      process.env.DB_NAME = 'cortex_prod';
      process.env.DB_USER = 'cortex_prod_user';
      process.env.DB_PASSWORD = 'strong-prod-password';
      process.env.DB_SSL = 'true';
      process.env.VECTOR_SIZE = '1536';
      process.env.VECTOR_DISTANCE = 'Cosine';
      process.env.EMBEDDING_MODEL = 'text-embedding-ada-002';
      process.env.LOG_LEVEL = 'warn';
      process.env.ENABLE_AUTH = 'true';
      process.env.ENABLE_CACHING = 'true';
      process.env.METRICS_ENABLED = 'true';

      const validation = await validateCompleteConfiguration();

      expect(validation.allValid).toBe(true);
      expect(validation.summary.totalErrors).toBe(0);
      expect(validation.summary.criticalErrors).toHaveLength(0);

      // Verify production-specific settings
      const env = Environment.getInstance();
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

      const validation = await validateCompleteConfiguration();

      expect(validation.allValid).toBe(false);
      expect(validation.summary.totalErrors).toBeGreaterThan(0);
      expect(validation.summary.criticalErrors.length).toBeGreaterThan(0);
      expect(validation.environmentSpecific.warnings).toContain(
        'Debug logging enabled in production - consider setting LOG_LEVEL to warn or error'
      );
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

      const validation = await validateCompleteConfiguration();

      expect(validation.allValid).toBe(true);
      expect(validation.summary.totalErrors).toBe(0);

      const env = Environment.getInstance();
      expect(env.isDevelopmentMode()).toBe(true);
      expect(env.getFeatureFlag('auth')).toBe(false);

      const defaults = env.getEnvironmentSpecificDefaults();
      expect(defaults.LOG_LEVEL).toBe('debug');
      expect(defaults.DEBUG_MODE).toBe(true);
      expect(defaults.HOT_RELOAD).toBe(true);
    });

    it('should warn about missing development conveniences', async () => {
      process.env.NODE_ENV = 'development';
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'dev-key';
      process.env.DEBUG_MODE = 'false'; // Disabled in development

      const env = Environment.getInstance();
      const validation = env.validateEnvironmentSpecificRequirements();

      expect(validation.warnings).toContain(
        'Consider enabling DEBUG_MODE in development'
      );
    });
  });

  describe('Testing Configuration Validation', () => {
    it('should validate test configuration', async () => {
      process.env.NODE_ENV = 'test';
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'test-key';
      process.env.TEST_DATABASE_URL = 'http://localhost:6334/test';
      process.env.LOG_LEVEL = 'error';
      process.env.METRICS_ENABLED = 'false';
      process.env.ENABLE_AUTH = 'false';
      process.env.MOCK_EXTERNAL_SERVICES = 'true';

      const validation = await validateCompleteConfiguration();

      expect(validation.allValid).toBe(true);
      expect(validation.summary.totalErrors).toBe(0);

      const env = Environment.getInstance();
      expect(env.isTestMode()).toBe(true);

      const defaults = env.getEnvironmentSpecificDefaults();
      expect(defaults.LOG_LEVEL).toBe('error');
      expect(defaults.METRICS_ENABLED).toBe(false);
      expect(defaults.MOCK_EXTERNAL_SERVICES).toBe(true);
    });

    it('should require test database URL in test mode', async () => {
      process.env.NODE_ENV = 'test';
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'test-key';
      // TEST_DATABASE_URL not set

      const validation = await validateCompleteConfiguration();

      expect(validation.allValid).toBe(false);
      expect(validation.environmentSpecific.errors).toContain(
        'TEST_DATABASE_URL or DATABASE_URL is required in test mode'
      );
    });
  });

  describe('Database Configuration Integration', () => {
    it('should validate complete database configuration', async () => {
      process.env.QDRANT_URL = 'http://qdrant.example.com:6333';
      process.env.QDRANT_API_KEY = 'qdrant-key';
      process.env.OPENAI_API_KEY = 'openai-key';
      process.env.DB_HOST = 'db.example.com';
      process.env.DB_PORT = '5432';
      process.env.DB_NAME = 'cortex_db';
      process.env.DB_USER = 'cortex_user';
      process.env.DB_PASSWORD = 'secure_password';
      process.env.DB_SSL = 'true';
      process.env.DB_POOL_MIN = '5';
      process.env.DB_POOL_MAX = '25';
      process.env.DB_IDLE_TIMEOUT_MS = '60000';
      process.env.DB_CONNECTION_TIMEOUT_MS = '15000';
      process.env.DB_QUERY_TIMEOUT = '45000';
      process.env.DB_STATEMENT_TIMEOUT = '30000';
      process.env.DB_MAX_USES = '10000';

      const validation = await validateCompleteConfiguration();
      expect(validation.allValid).toBe(true);

      const env = Environment.getInstance();
      const dbConfig = env.getDatabaseConnectionConfig();

      expect(dbConfig.host).toBe('db.example.com');
      expect(dbConfig.port).toBe(5432);
      expect(dbConfig.ssl).toBe(true);
      expect(dbConfig.queryTimeout).toBe(45000);
      expect(dbConfig.statementTimeout).toBe(30000);
      expect(dbConfig.maxUses).toBe(10000);
    });

    it('should validate vector configuration consistency', async () => {
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'test-key';
      process.env.EMBEDDING_MODEL = 'text-embedding-ada-002';
      process.env.VECTOR_SIZE = '1536';
      process.env.VECTOR_DISTANCE = 'Cosine';

      const validation = await validateCompleteConfiguration();
      expect(validation.allValid).toBe(true);

      // Test inconsistency
      process.env.VECTOR_SIZE = '768'; // Wrong size for the model

      const env = Environment.getInstance();
      const validation2 = env.validateRequiredConfig();
      expect(validation2.valid).toBe(false);
      expect(validation2.errors).toContain(
        'VECTOR_SIZE must be 1536 for text-embedding-ada-002 model'
      );
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

      const validation = await validateCompleteConfiguration();
      expect(validation.allValid).toBe(true);

      const env = Environment.getInstance();
      const securityConfig = env.getSecurityConfig();

      expect(securityConfig.jwtSecret).toBe('a'.repeat(64));
      expect(securityConfig.jwtRefreshSecret).toBe('b'.repeat(64));
      expect(securityConfig.encryptionKey).toBe('c'.repeat(64));
      expect(env.getFeatureFlag('auth')).toBe(true);
    });

    it('should validate individual security variables', () => {
      // Test valid JWT secret
      expect(validateVariable('JWT_SECRET', 'a'.repeat(32)).valid).toBe(true);

      // Test invalid JWT secret
      const result = validateVariable('JWT_SECRET', 'short');
      expect(result.valid).toBe(false);
      expect(result.error).toContain('must be at least 32 characters');

      // Test required OpenAI API key
      expect(validateVariable('OPENAI_API_KEY').valid).toBe(false);
      expect(validateVariable('OPENAI_API_KEY', 'test-key').valid).toBe(true);
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

      const validation = await validateCompleteConfiguration();
      expect(validation.allValid).toBe(true);

      const env = Environment.getInstance();
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
      process.env.DB_HOST = 'postgres';
      process.env.DB_PORT = '5432';
      process.env.DB_NAME = 'cortex_dev';
      process.env.DB_USER = 'cortex';
      process.env.DB_PASSWORD = 'dev_password';
      process.env.ENABLE_CACHING = 'true';
      process.env.METRICS_ENABLED = 'true';

      const validation = await validateCompleteConfiguration();
      expect(validation.allValid).toBe(true);

      const env = Environment.getInstance();
      expect(env.isDevelopmentMode()).toBe(true);
    });

    it('should handle CI/CD environment', async () => {
      // Simulate GitHub Actions CI environment
      process.env.NODE_ENV = 'test';
      process.env.QDRANT_URL = 'http://localhost:6333';
      process.env.OPENAI_API_KEY = 'sk-test-key';
      process.env.TEST_DATABASE_URL = 'http://localhost:6334/ci_test';
      process.env.LOG_LEVEL = 'error';
      process.env.GITHUB_ACTIONS = 'true';
      process.env.GITHUB_SHA = 'abc123def456';
      process.env.GITHUB_REF_NAME = 'pull/123/head';
      process.env.CODECOV_TOKEN = 'test-codecov-token';

      const validation = await validateCompleteConfiguration();
      expect(validation.allValid).toBe(true);

      const env = Environment.getInstance();
      const testingConfig = env.getTestingConfig();
      expect(testingConfig.isCiCd).toBe(true);
      expect(testingConfig.githubSha).toBe('abc123def456');
      expect(testingConfig.githubRefName).toBe('pull/123/head');
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

      const validation = await validateCompleteConfiguration();
      expect(validation.allValid).toBe(true);

      const env = Environment.getInstance();
      expect(env.isProductionMode()).toBe(true);

      // Should use production defaults
      const defaults = env.getEnvironmentSpecificDefaults();
      expect(defaults.METRICS_ENABLED).toBe(true);
      expect(defaults.ENABLE_AUTH).toBe(true);
      expect(defaults.CACHE_TTL).toBe(7200);
    });
  });
});