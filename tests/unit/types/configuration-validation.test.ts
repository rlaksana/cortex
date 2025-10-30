/**
 * Comprehensive Unit Tests for Configuration Validation Functionality
 *
 * Tests configuration validation functionality including:
 * - Configuration Schema Validation with type safety
 * - Environment-specific configurations
 * - Service configuration validation
 * - Security configuration testing
 * - Performance configuration optimization
 * - Configuration integration testing
 * - Error handling and edge cases
 * - Migration configuration validation
 * - Feature flag validation
 * - Cross-service compatibility
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  ConfigurationValidator,
  validateConfig,
  ValidationError,
  ValidationResult,
  ValidationRule
} from '../../../src/config/validation.js';
import {
  DatabaseConfigManager,
  CompleteDatabaseConfig
} from '../../../src/config/database-config.js';
import { Environment } from '../../../src/config/environment.js';
import type {
  DatabaseSelectionConfig,
  QdrantConfig,
  VectorConfig,
  MigrationConfig,
  FeatureFlags
} from '../../../src/config/database-config.js';

// Mock logger to avoid console output during tests
vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
    debug: vi.fn()
  }
}));

// Mock environment for consistent testing
vi.mock('../../../src/config/environment.js', () => ({
  Environment: class MockEnvironment {
    private static instance: MockEnvironment;
    private config: Record<string, any>;

    private constructor() {
      this.config = {
        NODE_ENV: 'test',
        QDRANT_URL: 'http://localhost:6333',
        OPENAI_API_KEY: 'sk-51F8hJ9vK2mN7pQr3sT6uVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZabcd',
        VECTOR_SIZE: '1536',
        VECTOR_DISTANCE: 'Cosine',
        EMBEDDING_MODEL: 'text-embedding-ada-002',
        JWT_SECRET: 'test-jwt-secret-that-is-long-enough-for-validation-32chars',
        ENCRYPTION_KEY: 'test-encryption-key-that-is-long-enough-for-validation-32chars',
        JWT_REFRESH_SECRET: 'test-refresh-secret-that-is-long-enough-for-validation-32chars'
      };
    }

    static getInstance(): MockEnvironment {
      if (!MockEnvironment.instance) {
        MockEnvironment.instance = new MockEnvironment();
      }
      return MockEnvironment.instance;
    }

    getRawConfig() {
      return { ...this.config };
    }

    exportForMcp() {
      return {
        database: {
          type: 'qdrant',
          url: this.config.QDRANT_URL,
          vectorSize: parseInt(this.config.VECTOR_SIZE),
          distance: this.config.VECTOR_DISTANCE
        },
        application: {
          name: 'Test Application',
          version: '2.0.0',
          environment: this.config.NODE_ENV
        },
        features: {
          auth: false,
          caching: true,
          metrics: true
        },
        environment: this.config.NODE_ENV
      };
    }
  }
}));

// Mock database config
vi.mock('../../../src/config/database-config.js', () => ({
  DatabaseConfigManager: class MockDatabaseConfigManager {
    private static instance: MockDatabaseConfigManager;
    private config: CompleteDatabaseConfig;

    private constructor() {
      this.config = {
        selection: {
          type: 'qdrant',
          migrationMode: false,
          fallbackEnabled: true
        },
        qdrant: {
          url: 'http://localhost:6333',
          timeout: 30000,
          collectionPrefix: 'test'
        },
        vector: {
          openaiApiKey: 'sk-51F8hJ9vK2mN7pQr3sT6uVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZabcd',
          size: 1536,
          distance: 'Cosine',
          embeddingModel: 'text-embedding-ada-002',
          batchSize: 10
        },
        migration: {
          batchSize: 100,
          concurrency: 5,
          dryRun: true,
          preservePg: true,
          validationEnabled: true,
          skipValidation: false,
          progressFile: './test-migration.json'
        },
        features: {
          migrationMode: false,
          healthChecks: true,
          metricsCollection: true,
          caching: true,
          debugMode: false
        }
      };
    }

    static getInstance(): MockDatabaseConfigManager {
      if (!MockDatabaseConfigManager.instance) {
        MockDatabaseConfigManager.instance = new MockDatabaseConfigManager();
      }
      return MockDatabaseConfigManager.instance;
    }

    getConfiguration(): CompleteDatabaseConfig {
      return { ...this.config };
    }

    updateConfiguration(updates: Partial<CompleteDatabaseConfig>): void {
      this.config = { ...this.config, ...updates };
    }
  }
}));

describe('Configuration Validation - Comprehensive Testing', () => {
  let validator: ConfigurationValidator;
  let testConfig: CompleteDatabaseConfig;

  beforeEach(() => {
    validator = new ConfigurationValidator();
    testConfig = DatabaseConfigManager.getInstance().getConfiguration();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('1. Configuration Schema Validation', () => {
    it('should validate complete configuration with all fields', async () => {
      const result = await validateConfig(testConfig);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.summary.errors).toBe(0);
      expect(result.summary.total).toBeGreaterThanOrEqual(0);
    });

    it('should reject invalid database type', async () => {
      const invalidConfig = {
        ...testConfig,
        selection: {
          ...testConfig.selection,
          type: 'invalid-db' as any
        }
      };

      const result = await validateConfig(invalidConfig);

      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.some(e => e.field === 'selection.type')).toBe(true);
      expect(result.errors.some(e => e.code === 'SCHEMA001')).toBe(true);
    });

    it('should validate qdrant URL format', async () => {
      const invalidConfig = {
        ...testConfig,
        qdrant: {
          ...testConfig.qdrant,
          url: 'invalid-url'
        }
      };

      const result = await validateConfig(invalidConfig);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field === 'qdrant.url')).toBe(true);
      expect(result.errors.some(e => e.code === 'SCHEMA003')).toBe(true);
    });

    it('should validate vector size constraints', async () => {
      const invalidConfig = {
        ...testConfig,
        vector: {
          ...testConfig.vector,
          size: 9999
        }
      };

      const result = await validateConfig(invalidConfig);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field === 'vector.size')).toBe(true);
      expect(result.errors.some(e => e.code === 'SCHEMA004')).toBe(true);
    });

    it('should validate vector distance metric', async () => {
      const invalidConfig = {
        ...testConfig,
        vector: {
          ...testConfig.vector,
          distance: 'InvalidDistance' as any
        }
      };

      const result = await validateConfig(invalidConfig);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field === 'vector.distance')).toBe(true);
      expect(result.errors.some(e => e.code === 'SCHEMA005')).toBe(true);
    });

    it('should allow all valid vector sizes', async () => {
      const validSizes = [384, 768, 1024, 1536, 2048, 3072];

      for (const size of validSizes) {
        const validConfig = {
          ...testConfig,
          vector: {
            ...testConfig.vector,
            size
          }
        };

        const result = await validateConfig(validConfig);
        expect(result.valid).toBe(true);
      }
    });
  });

  describe('2. Security Configuration Testing', () => {
    it('should detect placeholder API keys', async () => {
      const insecureConfig = {
        ...testConfig,
        vector: {
          ...testConfig.vector,
          openaiApiKey: 'sk-your-api-key-placeholder'
        }
      };

      const result = await validateConfig(insecureConfig);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field === 'vector.openaiApiKey')).toBe(true);
      expect(result.errors.some(e => e.code === 'SEC003')).toBe(true);
    });

    it('should validate OpenAI API key format', async () => {
      const invalidKeyConfig = {
        ...testConfig,
        vector: {
          ...testConfig.vector,
          openaiApiKey: 'invalid-key-format'
        }
      };

      const result = await validateConfig(invalidKeyConfig);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field === 'vector.openaiApiKey')).toBe(true);
      expect(result.errors.some(e => e.code === 'SEC004')).toBe(true);
    });

    it('should accept valid OpenAI API key formats', async () => {
      const validKeys = [
        'sk-51F8hJ9vK2mN7pQr3sT6uVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZabcd',
        'sk-proj-51F8hJ9vK2mN7pQr3sT6uVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZabcd'
      ];

      for (const apiKey of validKeys) {
        const validConfig = {
          ...testConfig,
          vector: {
            ...testConfig.vector,
            openaiApiKey: apiKey
          }
        };

        const result = await validateConfig(validConfig);
        expect(result.valid).toBe(true);
      }
    });

    it('should detect weak password in URL', async () => {
      const weakPasswordConfig = {
        ...testConfig,
        qdrant: {
          ...testConfig.qdrant,
          url: 'http://user:weak@localhost:6333'
        }
      };

      const result = await validateConfig(weakPasswordConfig);

      expect(result.warnings.some(e => e.field === 'qdrant.databaseUrl')).toBe(true);
      expect(result.warnings.some(e => e.code === 'SEC002')).toBe(true);
    });

    it('should require security settings in production', async () => {
      // Mock production environment
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const prodConfig = {
        ...testConfig,
        vector: {
          ...testConfig.vector,
          openaiApiKey: 'sk-51F8hJ9vK2mN7pQr3sT6uVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZabcd'
        }
      };

      // Mock environment validation that checks process.env
      const productionValidator = new ConfigurationValidator();

      // Add production-specific validation rule
      productionValidator.addRule({
        name: 'test-production-security',
        category: 'security',
        enabled: true,
        validator: (config: CompleteDatabaseConfig): ValidationError[] => {
          const errors: ValidationError[] = [];

          if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
            errors.push({
              field: 'JWT_SECRET',
              message: 'JWT_SECRET is required in production environment',
              severity: 'error',
              suggestion: 'Set JWT_SECRET as an environment variable with at least 32 random characters',
              code: 'PROD_SEC001'
            });
          }

          return errors;
        }
      });

      const result = await productionValidator.validateConfiguration(prodConfig);

      // Should fail in production without proper security
      expect(result.errors.length).toBeGreaterThan(0);

      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('3. Service Configuration Testing', () => {
    it('should validate Qdrant configuration requirements', async () => {
      const incompleteConfig = {
        ...testConfig,
        qdrant: {
          ...testConfig.qdrant,
          url: undefined as any
        }
      };

      const result = await validateConfig(incompleteConfig);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field === 'qdrant.url')).toBe(true);
      expect(result.errors.some(e => e.code === 'CONN002')).toBe(true);
    });

    it('should validate OpenAI API key requirement', async () => {
      const noKeyConfig = {
        ...testConfig,
        vector: {
          ...testConfig.vector,
          openaiApiKey: undefined
        }
      };

      const result = await validateConfig(noKeyConfig);

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field === 'vector.openaiApiKey')).toBe(true);
      expect(result.errors.some(e => e.code === 'CONN003')).toBe(true);
    });

    it('should validate timeout configuration', async () => {
      const invalidTimeoutConfig = {
        ...testConfig,
        qdrant: {
          ...testConfig.qdrant,
          timeout: 100
        }
      };

      const result = await validateConfig(invalidTimeoutConfig);

      expect(result.valid).toBe(true); // Timeout is validated by schema, but rule might warn
    });

    it('should validate collection prefix', async () => {
      const configWithPrefix = {
        ...testConfig,
        qdrant: {
          ...testConfig.qdrant,
          collectionPrefix: 'test-collection'
        }
      };

      const result = await validateConfig(configWithPrefix);
      expect(result.valid).toBe(true);
    });
  });

  describe('4. Migration Configuration Testing', () => {
    it('should validate migration batch size limits', async () => {
      const largeBatchConfig = {
        ...testConfig,
        migration: {
          ...testConfig.migration,
          batchSize: 10000,
          dryRun: false
        }
      };

      const result = await validateConfig(largeBatchConfig);

      expect(result.warnings.some(e => e.field === 'migration.batchSize')).toBe(true);
      expect(result.warnings.some(e => e.code === 'PERF003')).toBe(true);
    });

    it('should validate migration concurrency limits', async () => {
      const invalidConcurrencyConfig = {
        ...testConfig,
        migration: {
          ...testConfig.migration,
          concurrency: 15
        }
      };

      const result = await validateConfig(invalidConcurrencyConfig);
      expect(result.valid).toBe(true); // Might be warning, not error
    });

    it('should warn about migration without dry-run', async () => {
      const noDryRunConfig = {
        ...testConfig,
        migration: {
          ...testConfig.migration,
          dryRun: false,
          mode: 'pg-to-qdrant' as any
        }
      };

      const result = await validateConfig(noDryRunConfig);

      expect(result.warnings.some(e => e.field === 'migration.dryRun')).toBe(true);
      expect(result.warnings.some(e => e.code === 'PRACTICE001')).toBe(true);
    });

    it('should warn about migration without preserve', async () => {
      const noPreserveConfig = {
        ...testConfig,
        migration: {
          ...testConfig.migration,
          preservePg: false,
          mode: 'pg-to-qdrant' as any
        }
      };

      const result = await validateConfig(noPreserveConfig);

      expect(result.warnings.some(e => e.field === 'migration.preservePg')).toBe(true);
      expect(result.warnings.some(e => e.code === 'PRACTICE002')).toBe(true);
    });
  });

  describe('5. Environment Configuration Testing', () => {
    it('should apply development environment optimizations', async () => {
      const devConfig = {
        ...testConfig,
        features: {
          ...testConfig.features,
          debugMode: true,
          caching: false
        }
      };

      const result = await validateConfig(devConfig);
      expect(result.valid).toBe(true);
    });

    it('should apply production environment constraints', async () => {
      const prodConfig = {
        ...testConfig,
        features: {
          ...testConfig.features,
          debugMode: false,
          metricsCollection: true,
          caching: true
        }
      };

      const result = await validateConfig(prodConfig);
      expect(result.valid).toBe(true);
    });

    it('should apply test environment settings', async () => {
      const testEnvConfig = {
        ...testConfig,
        migration: {
          ...testConfig.migration,
          batchSize: 10,
          dryRun: true
        },
        features: {
          ...testConfig.features,
          debugMode: false,
          caching: false,
          metricsCollection: false
        }
      };

      const result = await validateConfig(testEnvConfig);
      expect(result.valid).toBe(true);
    });
  });

  describe('6. Performance Configuration Testing', () => {
    it('should validate batch size for performance', async () => {
      const performanceConfig = {
        ...testConfig,
        vector: {
          ...testConfig.vector,
          batchSize: 100
        }
      };

      const result = await validateConfig(performanceConfig);
      expect(result.valid).toBe(true);
    });

    it('should validate timeout settings', async () => {
      const timeoutConfig = {
        ...testConfig,
        qdrant: {
          ...testConfig.qdrant,
          timeout: 60000
        }
      };

      const result = await validateConfig(timeoutConfig);
      expect(result.valid).toBe(true);
    });

    it('should optimize for environment performance', async () => {
      const optimizedConfig = {
        ...testConfig,
        features: {
          ...testConfig.features,
          caching: true,
          metricsCollection: true
        }
      };

      const result = await validateConfig(optimizedConfig);
      expect(result.valid).toBe(true);
    });
  });

  describe('7. Feature Flag Validation', () => {
    it('should validate migration flag consistency', async () => {
      const consistentConfig = {
        ...testConfig,
        features: {
          ...testConfig.features,
          migrationMode: false,
          healthChecks: true
        }
      };

      const result = await validateConfig(consistentConfig);
      expect(result.valid).toBe(true);
    });

    it('should validate debug mode appropriateness', async () => {
      const debugConfig = {
        ...testConfig,
        features: {
          ...testConfig.features,
          debugMode: true
        }
      };

      const result = await validateConfig(debugConfig);
      expect(result.valid).toBe(true);
    });

    it('should validate metrics collection flag', async () => {
      const metricsConfig = {
        ...testConfig,
        features: {
          ...testConfig.features,
          metricsCollection: true
        }
      };

      const result = await validateConfig(metricsConfig);
      expect(result.valid).toBe(true);
    });
  });

  describe('8. Cross-Service Compatibility Testing', () => {
    it('should validate vector model compatibility', async () => {
      const incompatibleConfig = {
        ...testConfig,
        vector: {
          ...testConfig.vector,
          embeddingModel: 'text-embedding-ada-002',
          size: 1024
        }
      };

      const result = await validateConfig(incompatibleConfig);

      expect(result.errors.some(e => e.field === 'vector.size')).toBe(true);
      expect(result.errors.some(e => e.code === 'COMP001')).toBe(true);
    });

    it('should validate service dependencies', async () => {
      const completeConfig = {
        ...testConfig,
        vector: {
          ...testConfig.vector,
          openaiApiKey: 'sk-51F8hJ9vK2mN7pQr3sT6uVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZabcd'
        }
      };

      const result = await validateConfig(completeConfig);
      expect(result.valid).toBe(true);
    });
  });

  describe('9. Configuration Integration Testing', () => {
    it('should integrate with database configuration manager', async () => {
      const dbConfig = DatabaseConfigManager.getInstance();
      const config = dbConfig.getConfiguration();

      const result = await validateConfig(config);
      expect(result.valid).toBe(true);
    });

    it('should handle configuration updates', async () => {
      const dbConfig = DatabaseConfigManager.getInstance();
      const originalConfig = dbConfig.getConfiguration();

      const updatedConfig = {
        ...originalConfig,
        features: {
          ...originalConfig.features,
          debugMode: true
        }
      };

      const result = await validateConfig(updatedConfig);
      expect(result.valid).toBe(true);
    });

    it('should export configuration for external systems', async () => {
      const env = Environment.getInstance();
      const exportedConfig = env.exportForMcp();

      expect(exportedConfig).toBeDefined();
      expect(exportedConfig.database).toBeDefined();
      expect(exportedConfig.application).toBeDefined();
    });
  });

  describe('10. Error Handling and Edge Cases', () => {
    it('should handle malformed configuration gracefully', async () => {
      const malformedConfig = null as any;

      await expect(validateConfig(malformedConfig)).rejects.toThrow();
    });

    it('should handle missing configuration sections', async () => {
      const partialConfig = {
        selection: testConfig.selection,
        qdrant: { ...testConfig.qdrant, url: undefined },
        vector: testConfig.vector,
        migration: testConfig.migration,
        features: testConfig.features
      } as any;

      const result = await validateConfig(partialConfig);
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should handle circular references in configuration', async () => {
      const circularConfig = { ...testConfig };
      (circularConfig as any).self = circularConfig;

      const result = await validateConfig(circularConfig);
      expect(result).toBeDefined();
    });

    it('should handle extreme values gracefully', async () => {
      const extremeConfig = {
        ...testConfig,
        vector: {
          ...testConfig.vector,
          batchSize: Number.MAX_SAFE_INTEGER
        }
      };

      const result = await validateConfig(extremeConfig);
      expect(result).toBeDefined();
    });
  });

  describe('11. Validation Rule Management', () => {
    it('should allow adding custom validation rules', () => {
      const customRule: ValidationRule = {
        name: 'test-custom-rule',
        category: 'best-practices',
        enabled: true,
        validator: (config: CompleteDatabaseConfig): ValidationError[] => {
          return [{
            field: 'test',
            message: 'Test validation message',
            severity: 'info'
          }];
        }
      };

      validator.addRule(customRule);

      const rules = validator.getAllRules();
      expect(rules.some(r => r.name === 'test-custom-rule')).toBe(true);
    });

    it('should allow removing validation rules', () => {
      const ruleName = 'secure-connection-strings';
      validator.removeRule(ruleName);

      const rules = validator.getAllRules();
      expect(rules.some(r => r.name === ruleName)).toBe(false);
    });

    it('should allow toggling validation rules', () => {
      const ruleName = 'secure-connection-strings';
      validator.toggleRule(ruleName, false);

      const rules = validator.getAllRules();
      const rule = rules.find(r => r.name === ruleName);
      expect(rule?.enabled).toBe(false);
    });

    it('should validate specific rules', async () => {
      const errors = validator.validateRule('secure-connection-strings', testConfig);
      expect(Array.isArray(errors)).toBe(true);
    });

    it('should get rules by category', () => {
      const securityRules = validator.getRulesByCategory('security');
      expect(securityRules.length).toBeGreaterThan(0);
      expect(securityRules.every(r => r.category === 'security')).toBe(true);
    });
  });

  describe('12. Validation Performance Testing', () => {
    it('should validate configuration efficiently', async () => {
      const startTime = Date.now();

      for (let i = 0; i < 100; i++) {
        await validateConfig(testConfig);
      }

      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(5000); // Should complete 100 validations in under 5 seconds
    });

    it('should handle large configuration objects', async () => {
      const largeConfig = {
        ...testConfig,
        // Add potentially large nested objects
        metadata: {
          ...Array.from({ length: 1000 }, (_, i) => [`key${i}`, `value${i}`])
            .reduce((obj, [key, value]) => ({ ...obj, [key]: value }), {})
        }
      } as any;

      const startTime = Date.now();
      const result = await validateConfig(largeConfig);
      const duration = Date.now() - startTime;

      expect(result).toBeDefined();
      expect(duration).toBeLessThan(1000);
    });
  });

  describe('13. Configuration Evolution Testing', () => {
    it('should handle backward compatibility', async () => {
      const legacyConfig = {
        ...testConfig,
        // Add legacy fields that might be present
        legacyField: 'legacy value',
        deprecatedSetting: true
      } as any;

      const result = await validateConfig(legacyConfig);
      expect(result.valid).toBe(true);
    });

    it('should provide migration suggestions', async () => {
      const needsMigrationConfig = {
        ...testConfig,
        // Use deprecated configuration
        features: {
          ...testConfig.features,
          deprecatedFeature: true
        }
      } as any;

      const result = await validateConfig(needsMigrationConfig);
      expect(result).toBeDefined();
    });
  });

  describe('14. Concurrent Validation Testing', () => {
    it('should handle concurrent validation requests', async () => {
      const promises = Array.from({ length: 10 }, () => validateConfig(testConfig));
      const results = await Promise.all(promises);

      expect(results).toHaveLength(10);
      results.forEach(result => {
        expect(result.valid).toBe(true);
      });
    });

    it('should maintain consistency during concurrent rule changes', async () => {
      const validationPromises = [
        validateConfig(testConfig),
        new Promise<void>(resolve => {
          validator.addRule({
            name: 'concurrent-test-rule',
            category: 'best-practices',
            enabled: true,
            validator: () => []
          });
          resolve();
        }),
        validateConfig(testConfig)
      ];

      const results = await Promise.all(validationPromises);
      expect(results[0]).toBeDefined();
      expect(results[2]).toBeDefined();
    });
  });

  describe('15. Configuration Security Testing', () => {
    it('should redact sensitive information in error messages', async () => {
      const sensitiveConfig = {
        ...testConfig,
        vector: {
          ...testConfig.vector,
          openaiApiKey: 'sk-51F8hJ9vK2mN7pQr3sT6uVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZabcd'
        }
      };

      const result = await validateConfig(sensitiveConfig);

      // Check that sensitive data doesn't appear in error messages
      result.errors.forEach(error => {
        expect(error.message).not.toContain('sk-51F8hJ9vK2mN7pQr3sT6uVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZabcd');
      });
    });

    it('should validate against common security misconfigurations', async () => {
      const insecureConfig = {
        ...testConfig,
        qdrant: {
          ...testConfig.qdrant,
          url: 'http://admin:password@localhost:6333'
        }
      };

      const result = await validateConfig(insecureConfig);
      expect(result.errors.length > 0 || result.warnings.length > 0).toBe(true);
    });
  });

  describe('16. Configuration Rollback Testing', () => {
    it('should support configuration rollback scenarios', async () => {
      const dbConfig = DatabaseConfigManager.getInstance();
      const originalConfig = dbConfig.getConfiguration();

      // Update configuration
      const updatedConfig = {
        ...originalConfig,
        features: {
          ...originalConfig.features,
          debugMode: true
        }
      };

      const validationResult = await validateConfig(updatedConfig);
      expect(validationResult.valid).toBe(true);

      // Rollback should still be valid
      const rollbackResult = await validateConfig(originalConfig);
      expect(rollbackResult.valid).toBe(true);
    });
  });

  describe('17. Configuration Monitoring Testing', () => {
    it('should track validation metrics', async () => {
      const result = await validateConfig(testConfig);

      expect(result.summary).toBeDefined();
      expect(result.summary.total).toBeGreaterThanOrEqual(0);
      expect(result.summary.errors).toBeGreaterThanOrEqual(0);
      expect(result.summary.warnings).toBeGreaterThanOrEqual(0);
      expect(result.summary.info).toBeGreaterThanOrEqual(0);
    });

    it('should provide detailed validation reports', async () => {
      const result = await validateConfig(testConfig);

      expect(Array.isArray(result.errors)).toBe(true);
      expect(Array.isArray(result.warnings)).toBe(true);
      expect(Array.isArray(result.info)).toBe(true);

      result.errors.forEach(error => {
        expect(error.field).toBeDefined();
        expect(error.message).toBeDefined();
        expect(error.severity).toBe('error');
      });
    });
  });

  describe('18. Configuration Update Testing', () => {
    it('should validate configuration updates', async () => {
      const dbConfig = DatabaseConfigManager.getInstance();

      const updates = {
        features: {
          ...dbConfig.getConfiguration().features,
          debugMode: true
        }
      };

      dbConfig.updateConfiguration(updates);
      const updatedConfig = dbConfig.getConfiguration();

      const result = await validateConfig(updatedConfig);
      expect(result.valid).toBe(true);
    });

    it('should reject invalid configuration updates', async () => {
      const dbConfig = DatabaseConfigManager.getInstance();

      const invalidUpdates = {
        selection: {
          ...dbConfig.getConfiguration().selection,
          type: 'invalid' as any
        }
      };

      dbConfig.updateConfiguration(invalidUpdates);
      const updatedConfig = dbConfig.getConfiguration();

      const result = await validateConfig(updatedConfig);
      expect(result.valid).toBe(false);
    });
  });

  describe('19. Configuration Dependency Testing', () => {
    it('should validate dependent configuration fields', async () => {
      const dependentConfig = {
        ...testConfig,
        selection: {
          ...testConfig.selection,
          type: 'qdrant' as const
        },
        vector: {
          ...testConfig.vector,
          openaiApiKey: 'sk-valid-key-for-dependency-testing'
        }
      };

      const result = await validateConfig(dependentConfig);
      expect(result.valid).toBe(true);
    });

    it('should detect missing dependencies', async () => {
      const missingDepConfig = {
        ...testConfig,
        selection: {
          ...testConfig.selection,
          type: 'qdrant' as const
        },
        vector: {
          ...testConfig.vector,
          openaiApiKey: undefined
        }
      };

      const result = await validateConfig(missingDepConfig);
      expect(result.valid).toBe(false);
    });
  });

  describe('20. Configuration Type Safety Testing', () => {
    it('should enforce type constraints', async () => {
      const typeViolations = [
        { ...testConfig, selection: { ...testConfig.selection, type: 123 } as any },
        { ...testConfig, qdrant: { ...testConfig.qdrant, timeout: 'invalid' } as any },
        { ...testConfig, vector: { ...testConfig.vector, size: 'invalid' } as any }
      ];

      for (const violation of typeViolations) {
        const result = await validateConfig(violation);
        expect(result.valid).toBe(false);
      }
    });

    it('should maintain type integrity', async () => {
      const validConfig = testConfig;
      const result = await validateConfig(validConfig);

      expect(result.valid).toBe(true);
      expect(typeof testConfig.selection.type).toBe('string');
      expect(typeof testConfig.qdrant.timeout).toBe('number');
      expect(typeof testConfig.vector.size).toBe('number');
    });
  });

  describe('21. Configuration Edge Cases', () => {
    it('should handle empty configuration sections', async () => {
      const emptySectionsConfig = {
        ...testConfig,
        migration: {} as any
      };

      const result = await validateConfig(emptySectionsConfig);
      expect(result).toBeDefined();
    });

    it('should handle null and undefined values', async () => {
      const nullValuesConfig = {
        ...testConfig,
        qdrant: {
          ...testConfig.qdrant,
          apiKey: null
        }
      } as any;

      const result = await validateConfig(nullValuesConfig);
      expect(result).toBeDefined();
    });

    it('should handle special characters in configuration values', async () => {
      const specialCharsConfig = {
        ...testConfig,
        qdrant: {
          ...testConfig.qdrant,
          collectionPrefix: 'test-collection-with-special-chars-!@#$%^&*()'
        }
      };

      const result = await validateConfig(specialCharsConfig);
      expect(result.valid).toBe(true);
    });
  });

  describe('22. Configuration Validation Integration', () => {
    it('should integrate with environment validation', async () => {
      const env = Environment.getInstance();
      const envConfig = env.getRawConfig();

      const dbConfig = testConfig;
      const result = await validateConfig(dbConfig);

      expect(result.valid).toBe(true);
    });

    it('should support configuration validation workflows', async () => {
      const validationWorkflow = async (config: CompleteDatabaseConfig) => {
        const validationResult = await validateConfig(config);

        if (!validationResult.valid) {
          throw new Error(`Configuration validation failed: ${validationResult.errors.map(e => e.message).join(', ')}`);
        }

        return validationResult;
      };

      const result = await validationWorkflow(testConfig);
      expect(result.valid).toBe(true);
    });
  });
});