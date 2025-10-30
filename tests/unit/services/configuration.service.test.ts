/**
 * Comprehensive Unit Tests for Configuration Service
 *
 * Tests advanced configuration service functionality including:
 * - Configuration loading and validation
 * - Environment-specific configurations
 * - Configuration hot-reloading and versioning
 * - Schema validation and type checking
 * - Environment variable integration
 * - Sensitive data protection and encryption
 * - Performance and caching strategies
 * - Service configuration injection and integration
 * - Configuration change notifications
 * - Security and access control
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock dependencies
vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn()
  }
}));

// Mock environment module
const mockEnvironment = {
  getRawConfig: vi.fn(),
  exportForMcp: vi.fn(),
  validateEnvironment: vi.fn()
};

vi.mock('../../../src/config/environment', () => ({
  environment: mockEnvironment
}));

// Mock fetch for API calls
global.fetch = vi.fn();

// Import after mocking
import { ConfigurationService } from '../../../src/services/configuration.service';

// Test interfaces for configuration structure
interface TestConfigSchema {
  database: {
    url: string;
    timeout: number;
    retries: number;
    credentials?: {
      username?: string;
      password?: string;
    };
  };
  features: {
    analytics: boolean;
    caching: boolean;
    debug: boolean;
  };
  performance: {
    maxConnections: number;
    batchSizes: {
      default: number;
      large: number;
    };
  };
  security: {
    encryption: {
      enabled: boolean;
      algorithm: string;
      keyRotationDays: number;
    };
    access: {
      allowedOrigins: string[];
      rateLimiting: {
        enabled: boolean;
        requestsPerMinute: number;
      };
    };
  };
}

interface ConfigurationChangeEvent {
  key: string;
  oldValue: unknown;
  newValue: unknown;
  timestamp: Date;
  source: 'environment' | 'file' | 'api' | 'hot_reload';
  version: string;
}

// Mock encryption service
const mockEncryptionService = {
  encrypt: vi.fn(),
  decrypt: vi.fn(),
  rotateKey: vi.fn()
};

// Mock validation schemas
const mockValidationSchemas = {
  database: {
    type: 'object',
    required: ['url', 'timeout', 'retries'],
    properties: {
      url: { type: 'string', format: 'uri' },
      timeout: { type: 'number', minimum: 1000 },
      retries: { type: 'number', minimum: 0, maximum: 10 }
    }
  },
  features: {
    type: 'object',
    required: ['analytics', 'caching', 'debug'],
    properties: {
      analytics: { type: 'boolean' },
      caching: { type: 'boolean' },
      debug: { type: 'boolean' }
    }
  }
};

describe('ConfigurationService - Comprehensive Configuration Management', () => {
  let configService: ConfigurationService;

  beforeEach(() => {
    // Reset all mocks
    vi.clearAllMocks();

    // Setup default environment config
    mockEnvironment.getRawConfig.mockReturnValue({
      NODE_ENV: 'test',
      DATABASE_URL: 'http://localhost:6333',
      DATABASE_TIMEOUT: '30000',
      DATABASE_RETRIES: '3',
      FEATURES_ANALYTICS: 'true',
      FEATURES_CACHING: 'true',
      FEATURES_DEBUG: 'false',
      PERF_MAX_CONNECTIONS: '10',
      PERF_BATCH_DEFAULT: '100',
      PERF_BATCH_LARGE: '1000',
      SECURITY_ENCRYPTION_ENABLED: 'true',
      SECURITY_ENCRYPTION_ALGORITHM: 'AES-256-GCM',
      SECURITY_KEY_ROTATION_DAYS: '90',
      SECURITY_ALLOWED_ORIGINS: 'http://localhost:3000,http://localhost:8080',
      SECURITY_RATE_LIMIT_ENABLED: 'true',
      SECURITY_RATE_LIMIT_RPM: '60'
    });

    mockEnvironment.exportForMcp.mockReturnValue({
      databaseUrl: 'http://localhost:6333',
      features: {
        analytics: true,
        caching: true,
        debug: false
      }
    });

    // Create new service instance
    configService = new ConfigurationService({
      schema: mockValidationSchemas,
      encryption: mockEncryptionService,
      enableHotReload: true,
      enableCaching: true,
      enableValidation: true
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. Configuration Loading and Validation Tests
  describe('Configuration Loading and Validation', () => {
    it('should load configuration from environment variables', () => {
      const config = configService.getConfiguration<TestConfigSchema>();

      expect(config.database.url).toBe('http://localhost:6333');
      expect(config.database.timeout).toBe(30000);
      expect(config.database.retries).toBe(3);
      expect(config.features.analytics).toBe(true);
      expect(config.features.caching).toBe(true);
      expect(config.features.debug).toBe(false);
    });

    it('should validate configuration against schema', () => {
      expect(() => configService.getConfiguration<TestConfigSchema>()).not.toThrow();

      // Mock invalid configuration
      mockEnvironment.getRawConfig.mockReturnValue({
        DATABASE_URL: 'invalid-url', // Invalid URI
        DATABASE_TIMEOUT: '500', // Below minimum
        DATABASE_RETRIES: '15' // Above maximum
      });

      expect(() => configService.getConfiguration<TestConfigSchema>()).toThrow();
    });

    it('should handle missing required configuration values', () => {
      mockEnvironment.getRawConfig.mockReturnValue({
        // Missing required database.url
        DATABASE_TIMEOUT: '30000',
        DATABASE_RETRIES: '3'
      });

      expect(() => configService.getConfiguration<TestConfigSchema>()).toThrow('Missing required configuration');
    });

    it('should provide default values for optional fields', () => {
      const config = configService.getConfiguration<TestConfigSchema>();

      expect(config.database.credentials).toBeUndefined();
      expect(config.performance.maxConnections).toBe(10);
      expect(config.performance.batchSizes.default).toBe(100);
    });

    it('should convert string environment variables to correct types', () => {
      const config = configService.getConfiguration<TestConfigSchema>();

      expect(typeof config.database.timeout).toBe('number');
      expect(typeof config.database.retries).toBe('number');
      expect(typeof config.features.analytics).toBe('boolean');
      expect(typeof config.features.caching).toBe('boolean');
      expect(Array.isArray(config.security.access.allowedOrigins)).toBe(true);
    });

    it('should validate complex nested configurations', () => {
      const complexConfig = {
        nested: {
          deep: {
            value: 'test',
            numeric: 42,
            boolean: true,
            array: [1, 2, 3]
          }
        }
      };

      expect(() => configService.validateConfiguration(complexConfig, {
        type: 'object',
        properties: {
          nested: {
            type: 'object',
            properties: {
              deep: {
                type: 'object',
                required: ['value', 'numeric', 'boolean'],
                properties: {
                  value: { type: 'string' },
                  numeric: { type: 'number' },
                  boolean: { type: 'boolean' },
                  array: {
                    type: 'array',
                    items: { type: 'number' }
                  }
                }
              }
            }
          }
        }
      })).not.toThrow();
    });

    it('should handle configuration validation errors with detailed messages', () => {
      const invalidConfig = {
        database: {
          url: 'not-a-url',
          timeout: -100,
          retries: 20
        }
      };

      try {
        configService.validateConfiguration(invalidConfig, mockValidationSchemas.database);
        fail('Should have thrown validation error');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect(error.message).toContain('validation');
        expect(error.message).toContain('url');
        expect(error.message).toContain('timeout');
        expect(error.message).toContain('retries');
      }
    });
  });

  // 2. Environment-Specific Configurations Tests
  describe('Environment-Specific Configurations', () => {
    it('should load development environment configuration', () => {
      mockEnvironment.getRawConfig.mockReturnValue({
        NODE_ENV: 'development',
        DATABASE_URL: 'http://localhost:6333',
        FEATURES_DEBUG: 'true',
        FEATURES_CACHING: 'false',
        PERF_MAX_CONNECTIONS: '5'
      });

      const config = configService.getConfiguration<TestConfigSchema>();

      expect(config.features.debug).toBe(true);
      expect(config.features.caching).toBe(false);
      expect(config.performance.maxConnections).toBe(5);
    });

    it('should load production environment configuration', () => {
      mockEnvironment.getRawConfig.mockReturnValue({
        NODE_ENV: 'production',
        DATABASE_URL: 'https://prod.example.com',
        FEATURES_DEBUG: 'false',
        FEATURES_CACHING: 'true',
        SECURITY_ENCRYPTION_ENABLED: 'true',
        SECURITY_RATE_LIMIT_RPM: '120'
      });

      const config = configService.getConfiguration<TestConfigSchema>();

      expect(config.features.debug).toBe(false);
      expect(config.features.caching).toBe(true);
      expect(config.security.encryption.enabled).toBe(true);
      expect(config.security.access.rateLimiting.requestsPerMinute).toBe(120);
    });

    it('should load test environment configuration', () => {
      mockEnvironment.getRawConfig.mockReturnValue({
        NODE_ENV: 'test',
        DATABASE_URL: 'http://test:6333',
        PERF_MAX_CONNECTIONS: '2',
        PERF_BATCH_DEFAULT: '10',
        SECURITY_RATE_LIMIT_ENABLED: 'false'
      });

      const config = configService.getConfiguration<TestConfigSchema>();

      expect(config.performance.maxConnections).toBe(2);
      expect(config.performance.batchSizes.default).toBe(10);
      expect(config.security.access.rateLimiting.enabled).toBe(false);
    });

    it('should handle environment variable inheritance', () => {
      mockEnvironment.getRawConfig.mockReturnValue({
        NODE_ENV: 'development',
        DATABASE_URL: 'http://localhost:6333',
        DATABASE_TIMEOUT: '30000',
        // Should inherit default retries
        FEATURES_ANALYTICS: 'true'
        // Should inherit default caching and debug settings
      });

      const config = configService.getConfiguration<TestConfigSchema>();

      expect(config.database.url).toBe('http://localhost:6333');
      expect(config.database.timeout).toBe(30000);
      expect(config.database.retries).toBe(3); // Default value
      expect(config.features.analytics).toBe(true);
      expect(config.features.caching).toBe(true); // Default value
    });

    it('should handle environment-specific overrides', () => {
      const baseConfig = {
        database: { timeout: 30000, retries: 3 },
        features: { analytics: true, debug: false }
      };

      const productionOverrides = {
        database: { timeout: 60000 },
        features: { debug: false, caching: true }
      };

      configService.setBaseConfiguration(baseConfig);
      configService.setEnvironmentOverrides('production', productionOverrides);

      mockEnvironment.getRawConfig.mockReturnValue({ NODE_ENV: 'production' });

      const config = configService.getConfiguration<TestConfigSchema>();

      expect(config.database.timeout).toBe(60000); // Override applied
      expect(config.database.retries).toBe(3); // Base value preserved
      expect(config.features.debug).toBe(false); // Override applied
      expect(config.features.analytics).toBe(true); // Base value preserved
    });

    it('should validate environment-specific configurations', () => {
      const invalidOverrides = {
        database: { timeout: 'invalid' }, // Should be number
        features: { analytics: 'yes' } // Should be boolean
      };

      expect(() => configService.setEnvironmentOverrides('production', invalidOverrides as any))
        .toThrow('Invalid configuration override');
    });
  });

  // 3. Configuration Hot-Reloading and Versioning Tests
  describe('Configuration Hot-Reloading and Versioning', () => {
    it('should detect configuration changes', async () => {
      let changeCallback: (event: ConfigurationChangeEvent) => void;

      configService.onConfigurationChange((event) => {
        changeCallback = event;
      });

      const originalConfig = configService.getConfiguration<TestConfigSchema>();

      // Simulate configuration change
      mockEnvironment.getRawConfig.mockReturnValue({
        ...mockEnvironment.getRawConfig(),
        DATABASE_TIMEOUT: '60000', // Changed from 30000
        FEATURES_ANALYTICS: 'false' // Changed from true
      });

      await configService.reloadConfiguration();

      expect(changeCallback).toBeDefined();
      expect(changeCallback.key).toContain('timeout');
      expect(changeCallback.oldValue).toBe(30000);
      expect(changeCallback.newValue).toBe(60000);
      expect(changeCallback.source).toBe('environment');
      expect(changeCallback.timestamp).toBeInstanceOf(Date);

      const newConfig = configService.getConfiguration<TestConfigSchema>();
      expect(newConfig.database.timeout).toBe(60000);
      expect(newConfig.features.analytics).toBe(false);
    });

    it('should maintain configuration version history', () => {
      const initialVersion = configService.getCurrentVersion();

      configService.updateConfiguration({ features: { debug: true } });
      const version1 = configService.getCurrentVersion();

      configService.updateConfiguration({ database: { timeout: 45000 } });
      const version2 = configService.getCurrentVersion();

      expect(initialVersion).not.toBe(version1);
      expect(version1).not.toBe(version2);

      const history = configService.getVersionHistory();
      expect(history).toHaveLength(3);
      expect(history[0].version).toBe(initialVersion);
      expect(history[1].version).toBe(version1);
      expect(history[2].version).toBe(version2);
    });

    it('should rollback to previous configuration versions', () => {
      const originalConfig = configService.getConfiguration<TestConfigSchema>();

      configService.updateConfiguration({ features: { debug: true } });
      configService.updateConfiguration({ database: { timeout: 60000 } });

      const rollbackVersion = configService.getCurrentVersion();
      configService.rollbackToVersion(rollbackVersion);

      const rolledBackConfig = configService.getConfiguration<TestConfigSchema>();
      expect(rolledBackConfig.features.debug).toBe(true);
      expect(rolledBackConfig.database.timeout).toBe(60000);
    });

    it('should handle hot-reload failures gracefully', async () => {
      const originalConfig = configService.getConfiguration<TestConfigSchema>();

      // Mock validation failure during reload
      mockEnvironment.getRawConfig.mockReturnValue({
        DATABASE_URL: 'invalid-url'
      });

      await expect(configService.reloadConfiguration()).rejects.toThrow();

      // Configuration should remain unchanged
      const currentConfig = configService.getConfiguration<TestConfigSchema>();
      expect(currentConfig).toEqual(originalConfig);
    });

    it('should batch multiple configuration changes', async () => {
      const changeEvents: ConfigurationChangeEvent[] = [];

      configService.onConfigurationChange((event) => {
        changeEvents.push(event);
      });

      configService.batchUpdate([
        { path: 'features.debug', value: true },
        { path: 'database.timeout', value: 45000 },
        { path: 'security.encryption.enabled', value: false }
      ]);

      expect(changeEvents).toHaveLength(3);
      expect(changeEvents[0].path).toBe('features.debug');
      expect(changeEvents[1].path).toBe('database.timeout');
      expect(changeEvents[2].path).('security.encryption.enabled');
    });
  });

  // 4. Schema Validation and Type Checking Tests
  describe('Schema Validation and Type Checking', () => {
    it('should validate configuration structure against schemas', () => {
      const validConfig = {
        database: {
          url: 'http://localhost:6333',
          timeout: 30000,
          retries: 3
        },
        features: {
          analytics: true,
          caching: true,
          debug: false
        }
      };

      expect(() => configService.validateConfiguration(validConfig, {
        type: 'object',
        required: ['database', 'features'],
        properties: {
          database: mockValidationSchemas.database,
          features: mockValidationSchemas.features
        }
      })).not.toThrow();
    });

    it('should perform type checking and conversion', () => {
      const stringConfig = {
        timeout: '30000',
        retries: '3',
        enabled: 'true',
        percentage: '0.75'
      };

      const convertedConfig = configService.convertTypes(stringConfig, {
        timeout: 'number',
        retries: 'number',
        enabled: 'boolean',
        percentage: 'float'
      });

      expect(typeof convertedConfig.timeout).toBe('number');
      expect(typeof convertedConfig.retries).toBe('number');
      expect(typeof convertedConfig.enabled).toBe('boolean');
      expect(typeof convertedConfig.percentage).toBe('number');
      expect(convertedConfig.timeout).toBe(30000);
      expect(convertedConfig.retries).toBe(3);
      expect(convertedConfig.enabled).toBe(true);
      expect(convertedConfig.percentage).toBe(0.75);
    });

    it('should validate required fields', () => {
      const configWithMissingFields = {
        database: {
          url: 'http://localhost:6333'
          // Missing timeout and retries
        }
      };

      expect(() => configService.validateConfiguration(configWithMissingFields, {
        type: 'object',
        required: ['database'],
        properties: {
          database: {
            type: 'object',
            required: ['url', 'timeout', 'retries'],
            properties: {
              url: { type: 'string' },
              timeout: { type: 'number' },
              retries: { type: 'number' }
            }
          }
        }
      })).toThrow('Missing required field: timeout');
    });

    it('should handle default value application', () => {
      const partialConfig = {
        database: {
          url: 'http://localhost:6333'
          // Missing timeout and retries
        }
      };

      const configWithDefaults = configService.applyDefaults(partialConfig, {
        database: {
          timeout: { default: 30000 },
          retries: { default: 3 },
          ssl: { default: true }
        }
      });

      expect(configWithDefaults.database.timeout).toBe(30000);
      expect(configWithDefaults.database.retries).toBe(3);
      expect(configWithDefaults.database.ssl).toBe(true);
      expect(configWithDefaults.database.url).toBe('http://localhost:6333');
    });

    it('should validate array types and constraints', () => {
      const configWithArrays = {
        allowedOrigins: ['http://localhost:3000', 'https://example.com'],
        batchSizes: [10, 50, 100, 200],
        tags: ['production', 'api', 'v2']
      };

      const arraySchema = {
        type: 'object',
        properties: {
          allowedOrigins: {
            type: 'array',
            items: { type: 'string', format: 'uri' },
            minItems: 1,
            maxItems: 10
          },
          batchSizes: {
            type: 'array',
            items: { type: 'number', minimum: 1 },
            uniqueItems: true
          },
          tags: {
            type: 'array',
            items: { type: 'string', pattern: '^[a-z0-9_-]+$' }
          }
        }
      };

      expect(() => configService.validateConfiguration(configWithArrays, arraySchema)).not.toThrow();

      // Test invalid array configurations
      const invalidArrays = {
        allowedOrigins: [], // Empty array
        batchSizes: [10, 10, 20], // Duplicate items
        tags: ['invalid-tag!', 'tag2'] // Invalid pattern
      };

      expect(() => configService.validateConfiguration(invalidArrays, arraySchema)).toThrow();
    });
  });

  // 5. Environment Variable Integration Tests
  describe('Environment Variable Integration', () => {
    it('should read configuration from environment variables', () => {
      const envConfig = configService.getEnvironmentConfiguration(['DATABASE_URL', 'FEATURES_ANALYTICS']);

      expect(envConfig.DATABASE_URL).toBe('http://localhost:6333');
      expect(envConfig.FEATURES_ANALYTICS).toBe('true');
    });

    it('should handle nested environment variable structures', () => {
      const nestedEnvVars = {
        'DATABASE_URL': 'http://localhost:6333',
        'DATABASE_TIMEOUT': '30000',
        'DATABASE_RETRIES': '3',
        'FEATURES_ANALYTICS': 'true',
        'FEATURES_CACHING': 'true',
        'SECURITY_ENCRYPTION_ENABLED': 'true',
        'SECURITY_ENCRYPTION_ALGORITHM': 'AES-256-GCM'
      };

      mockEnvironment.getRawConfig.mockReturnValue(nestedEnvVars);

      const flatConfig = configService.flattenEnvironmentVariables(nestedEnvVars);
      const nestedConfig = configService.expandEnvironmentVariables(flatConfig);

      expect(nestedConfig.database.url).toBe('http://localhost:6333');
      expect(nestedConfig.database.timeout).toBe('30000');
      expect(nestedConfig.features.analytics).toBe('true');
      expect(nestedConfig.security.encryption.enabled).toBe('true');
      expect(nestedConfig.security.encryption.algorithm).toBe('AES-256-GCM');
    });

    it('should handle environment variable precedence', () => {
      // Set base configuration
      configService.setBaseConfiguration({
        database: { timeout: 30000, retries: 3 },
        features: { analytics: false }
      });

      // Environment variables should override base configuration
      mockEnvironment.getRawConfig.mockReturnValue({
        DATABASE_TIMEOUT: '60000', // Override base
        FEATURES_ANALYTICS: 'true' // Override base
        // DATABASE_RETRIES not specified, should use base value
      });

      const config = configService.getConfiguration<TestConfigSchema>();

      expect(config.database.timeout).toBe(60000); // Environment override
      expect(config.features.analytics).toBe(true); // Environment override
      expect(config.database.retries).toBe(3); // Base configuration
    });

    it('should handle environment variable lists and arrays', () => {
      mockEnvironment.getRawConfig.mockReturnValue({
        ALLOWED_ORIGINS: 'http://localhost:3000,https://example.com,http://localhost:8080',
        BATCH_SIZES: '10,50,100,200',
        TAGS: 'production,api,v2'
      });

      const config = configService.getConfiguration<any>();

      expect(Array.isArray(config.allowedOrigins)).toBe(true);
      expect(config.allowedOrigins).toContain('http://localhost:3000');
      expect(config.allowedOrigins).toContain('https://example.com');

      expect(Array.isArray(config.batchSizes)).toBe(true);
      expect(config.batchSizes).toEqual([10, 50, 100, 200]);

      expect(Array.isArray(config.tags)).toBe(true);
      expect(config.tags).toEqual(['production', 'api', 'v2']);
    });

    it('should handle environment variable validation', () => {
      mockEnvironment.getRawConfig.mockReturnValue({
        DATABASE_URL: 'not-a-valid-url',
        DATABASE_TIMEOUT: 'not-a-number',
        FEATURES_ANALYTICS: 'not-a-boolean'
      });

      expect(() => configService.getConfiguration<TestConfigSchema>()).toThrow();
    });
  });

  // 6. Sensitive Data Protection and Encryption Tests
  describe('Sensitive Data Protection and Encryption', () => {
    it('should identify sensitive configuration fields', () => {
      const configWithSensitive = {
        database: {
          url: 'http://localhost:6333',
          credentials: {
            username: 'admin',
            password: 'secret123',
            apiKey: 'sk-1234567890'
          }
        },
        security: {
          encryption: {
            key: 'encryption-key-123',
            secret: 'super-secret'
          }
        },
        public: {
          apiUrl: 'https://api.example.com',
          version: '1.0.0'
        }
      };

      const sensitiveFields = configService.identifySensitiveFields(configWithSensitive);

      expect(sensitiveFields).toContain('database.credentials.password');
      expect(sensitiveFields).toContain('database.credentials.apiKey');
      expect(sensitiveFields).toContain('security.encryption.key');
      expect(sensitiveFields).toContain('security.encryption.secret');
      expect(sensitiveFields).not.toContain('database.url');
      expect(sensitiveFields).not.toContain('public.apiUrl');
      expect(sensitiveFields).not.toContain('public.version');
    });

    it('should encrypt sensitive configuration values', async () => {
      mockEncryptionService.encrypt.mockResolvedValue('encrypted-value-123');

      const sensitiveConfig = {
        database: {
          credentials: {
            password: 'secret123',
            apiKey: 'sk-1234567890'
          }
        }
      };

      const encryptedConfig = await configService.encryptSensitiveValues(sensitiveConfig);

      expect(mockEncryptionService.encrypt).toHaveBeenCalledWith('secret123');
      expect(mockEncryptionService.encrypt).toHaveBeenCalledWith('sk-1234567890');
      expect(encryptedConfig.database.credentials.password).toBe('encrypted-value-123');
      expect(encryptedConfig.database.credentials.apiKey).toBe('encrypted-value-123');
    });

    it('should decrypt sensitive configuration values', async () => {
      mockEncryptionService.decrypt.mockResolvedValue('secret123');

      const encryptedConfig = {
        database: {
          credentials: {
            password: 'encrypted-value-123',
            apiKey: 'encrypted-api-key'
          }
        }
      };

      const decryptedConfig = await configService.decryptSensitiveValues(encryptedConfig);

      expect(mockEncryptionService.decrypt).toHaveBeenCalledWith('encrypted-value-123');
      expect(mockEncryptionService.decrypt).toHaveBeenCalledWith('encrypted-api-key');
      expect(decryptedConfig.database.credentials.password).toBe('secret123');
      expect(decryptedConfig.database.credentials.apiKey).toBe('secret123');
    });

    it('should mask sensitive values in logs and exports', () => {
      const configWithSensitive = {
        database: {
          url: 'http://localhost:6333',
          credentials: {
            username: 'admin',
            password: 'secret123',
            apiKey: 'sk-1234567890'
          }
        },
        features: {
          analytics: true
        }
      };

      const maskedConfig = configService.maskSensitiveValues(configWithSensitive);

      expect(maskedConfig.database.url).toBe('http://localhost:6333');
      expect(maskedConfig.database.credentials.username).toBe('admin');
      expect(maskedConfig.database.credentials.password).toBe('***');
      expect(maskedConfig.database.credentials.apiKey).toBe('***');
      expect(maskedConfig.features.analytics).toBe(true);
    });

    it('should handle encryption key rotation', async () => {
      mockEncryptionService.rotateKey.mockResolvedValue('new-key-123');

      await configService.rotateEncryptionKey();

      expect(mockEncryptionService.rotateKey).toHaveBeenCalled();

      // Verify all sensitive values are re-encrypted with new key
      const config = configService.getConfiguration<TestConfigSchema>();
      expect(mockEncryptionService.encrypt).toHaveBeenCalled();
    });

    it('should validate encryption service availability', () => {
      const configWithoutEncryption = new ConfigurationService({
        encryption: null,
        enableEncryption: true
      });

      expect(() => configWithoutEncryption.getConfiguration<TestConfigSchema>())
        .toThrow('Encryption service is required but not available');
    });

    it('should handle encryption failures gracefully', async () => {
      mockEncryptionService.encrypt.mockRejectedValue(new Error('Encryption failed'));

      const sensitiveConfig = {
        database: {
          credentials: {
            password: 'secret123'
          }
        }
      };

      await expect(configService.encryptSensitiveValues(sensitiveConfig))
        .rejects.toThrow('Encryption failed');
    });
  });

  // 7. Performance and Caching Tests
  describe('Performance and Caching', () => {
    it('should cache configuration values for fast access', () => {
      const startTime = Date.now();
      const config1 = configService.getConfiguration<TestConfigSchema>();
      const firstAccessTime = Date.now() - startTime;

      const secondStartTime = Date.now();
      const config2 = configService.getConfiguration<TestConfigSchema>();
      const secondAccessTime = Date.now() - secondStartTime;

      expect(config1).toEqual(config2);
      expect(secondAccessTime).toBeLessThan(firstAccessTime);
      expect(mockEnvironment.getRawConfig).toHaveBeenCalledTimes(1);
    });

    it('should invalidate cache on configuration changes', () => {
      const config1 = configService.getConfiguration<TestConfigSchema>();

      configService.updateConfiguration({ features: { debug: true } });

      const config2 = configService.getConfiguration<TestConfigSchema>();

      expect(config1.features.debug).toBe(false);
      expect(config2.features.debug).toBe(true);
      expect(mockEnvironment.getRawConfig).toHaveBeenCalledTimes(2);
    });

    it('should provide cache statistics', () => {
      configService.getConfiguration<TestConfigSchema>();
      configService.getConfiguration<TestConfigSchema>();
      configService.getConfiguration<string>('features.analytics');
      configService.getConfiguration<string>('features.caching');

      const stats = configService.getCacheStatistics();

      expect(stats.hits).toBe(3); // 3 cache hits after first access
      expect(stats.misses).toBe(1); // 1 initial miss
      expect(stats.hitRate).toBe(0.75); // 3/4 hit rate
      expect(stats.size).toBeGreaterThan(0);
    });

    it('should handle cache size limits', () => {
      const configServiceWithSmallCache = new ConfigurationService({
        cacheSize: 2,
        enableCaching: true
      });

      // Access multiple different configuration paths
      configServiceWithSmallCache.getConfiguration<string>('database.url');
      configServiceWithSmallCache.getConfiguration<string>('database.timeout');
      configServiceWithSmallCache.getConfiguration<string>('features.analytics');
      configServiceWithSmallCache.getConfiguration<string>('features.caching');

      const stats = configServiceWithSmallCache.getCacheStatistics();
      expect(stats.size).toBeLessThanOrEqual(2);
    });

    it('should clear cache on demand', () => {
      configService.getConfiguration<TestConfigSchema>();

      let stats = configService.getCacheStatistics();
      expect(stats.size).toBeGreaterThan(0);

      configService.clearCache();

      stats = configService.getCacheStatistics();
      expect(stats.size).toBe(0);
      expect(stats.hits).toBe(0);
      expect(stats.misses).toBe(0);
    });

    it('should handle cache expiration', async () => {
      const configServiceWithExpiration = new ConfigurationService({
        cacheExpirationMs: 100, // 100ms expiration
        enableCaching: true
      });

      configServiceWithExpiration.getConfiguration<TestConfigSchema>();

      // Wait for cache to expire
      await new Promise(resolve => setTimeout(resolve, 150));

      configServiceWithExpiration.getConfiguration<TestConfigSchema>();

      expect(mockEnvironment.getRawConfig).toHaveBeenCalledTimes(2);
    });

    it('should work with caching disabled', () => {
      const configServiceWithoutCache = new ConfigurationService({
        enableCaching: false
      });

      configServiceWithoutCache.getConfiguration<TestConfigSchema>();
      configServiceWithoutCache.getConfiguration<TestConfigSchema>();

      expect(mockEnvironment.getRawConfig).toHaveBeenCalledTimes(2);
    });
  });

  // 8. Service Configuration Injection Tests
  describe('Service Configuration Injection', () => {
    it('should inject configuration into services', () => {
      const mockService = {
        configure: vi.fn()
      };

      configService.injectConfiguration('mockService', mockService, {
        databaseUrl: 'database.url',
        features: 'features',
        timeout: 'database.timeout'
      });

      expect(mockService.configure).toHaveBeenCalledWith({
        databaseUrl: 'http://localhost:6333',
        features: {
          analytics: true,
          caching: true,
          debug: false
        },
        timeout: 30000
      });
    });

    it('should handle service-specific configuration sections', () => {
      const analyticsService = {
        setConfig: vi.fn()
      };

      configService.injectConfiguration('analyticsService', analyticsService, {
        enabled: 'features.analytics',
        caching: 'features.caching',
        debug: 'features.debug'
      });

      expect(analyticsService.setConfig).toHaveBeenCalledWith({
        enabled: true,
        caching: true,
        debug: false
      });
    });

    it('should handle configuration mapping and transformation', () => {
      const databaseService = {
        initialize: vi.fn()
      };

      configService.injectConfiguration('databaseService', databaseService, {
        host: { path: 'database.url', transform: (url: string) => new URL(url).hostname },
        port: { path: 'database.url', transform: (url: string) => new URL(url).port || 6333 },
        timeout: 'database.timeout',
        retries: { path: 'database.retries', transform: (r: number) => r + 1 }
      });

      expect(databaseService.initialize).toHaveBeenCalledWith({
        host: 'localhost',
        port: '6333',
        timeout: 30000,
        retries: 4 // 3 + 1
      });
    });

    it('should handle service configuration dependencies', () => {
      const authService = {
        configure: vi.fn()
      };

      const userService = {
        configure: vi.fn()
      };

      // Configure auth service first
      configService.injectConfiguration('authService', authService, {
        enabled: 'features.analytics',
        encryption: 'security.encryption.enabled'
      });

      // User service depends on auth service configuration
      configService.injectConfiguration('userService', userService, {
        authEnabled: { path: 'features.analytics', dependency: 'authService' },
        userCache: 'features.caching'
      });

      expect(authService.configure).toHaveBeenCalledBefore(userService.configure);
    });

    it('should handle configuration injection errors', () => {
      const faultyService = {
        configure: vi.fn().mockImplementation(() => {
          throw new Error('Service configuration failed');
        })
      };

      expect(() => configService.injectConfiguration('faultyService', faultyService, {
        databaseUrl: 'database.url'
      })).toThrow('Service configuration failed');
    });

    it('should validate service configuration requirements', () => {
      const serviceWithRequirements = {
        configure: vi.fn(),
        getRequiredConfig: () => ['database.url', 'security.encryption.enabled']
      };

      configService.injectConfiguration('serviceWithRequirements', serviceWithRequirements, {
        databaseUrl: 'database.url'
        // Missing required security.encryption.enabled
      });

      expect(serviceWithRequirements.configure).not.toHaveBeenCalled();
    });
  });

  // 9. Configuration Change Notifications Tests
  describe('Configuration Change Notifications', () => {
    it('should notify listeners of configuration changes', () => {
      const listener1 = vi.fn();
      const listener2 = vi.fn();

      configService.onConfigurationChange(listener1);
      configService.onConfigurationChange(listener2);

      configService.updateConfiguration({ features: { debug: true } });

      expect(listener1).toHaveBeenCalledWith({
        key: 'features.debug',
        oldValue: false,
        newValue: true,
        timestamp: expect.any(Date),
        source: 'api',
        version: expect.any(String)
      });

      expect(listener2).toHaveBeenCalledWith(expect.objectContaining({
        key: 'features.debug',
        oldValue: false,
        newValue: true
      }));
    });

    it('should support selective change notifications', () => {
      const dbListener = vi.fn();
      const featuresListener = vi.fn();

      configService.onConfigurationChange(dbListener, { path: 'database' });
      configService.onConfigurationChange(featuresListener, { path: 'features' });

      configService.updateConfiguration({ features: { debug: true } });
      configService.updateConfiguration({ database: { timeout: 60000 } });

      expect(featuresListener).toHaveBeenCalledTimes(1);
      expect(dbListener).toHaveBeenCalledTimes(1);
      expect(featuresListener).toHaveBeenCalledWith(expect.objectContaining({
        key: 'features.debug'
      }));
      expect(dbListener).toHaveBeenCalledWith(expect.objectContaining({
        key: 'database.timeout'
      }));
    });

    it('should handle change notification filtering', () => {
      const listener = vi.fn();

      configService.onConfigurationChange(listener, {
        filter: (change) => change.oldValue !== change.newValue
      });

      // Update with same value (should not trigger notification)
      configService.updateConfiguration({ features: { analytics: true } });

      // Update with different value (should trigger notification)
      configService.updateConfiguration({ features: { analytics: false } });

      expect(listener).toHaveBeenCalledTimes(1);
      expect(listener).toHaveBeenCalledWith(expect.objectContaining({
        key: 'features.analytics',
        oldValue: true,
        newValue: false
      }));
    });

    it('should support one-time change notifications', async () => {
      const listener = vi.fn();

      const promise = configService.onceConfigurationChange('features.debug');

      setTimeout(() => {
        configService.updateConfiguration({ features: { debug: true } });
      }, 10);

      const change = await promise;

      expect(change.key).toBe('features.debug');
      expect(change.newValue).toBe(true);
    });

    it('should handle notification listener errors', () => {
      const faultyListener = vi.fn().mockImplementation(() => {
        throw new Error('Listener error');
      });

      const workingListener = vi.fn();

      configService.onConfigurationChange(faultyListener);
      configService.onConfigurationChange(workingListener);

      // Should not throw even if one listener fails
      expect(() => configService.updateConfiguration({ features: { debug: true } }))
        .not.toThrow();

      expect(faultyListener).toHaveBeenCalled();
      expect(workingListener).toHaveBeenCalled();
    });

    it('should support listener removal', () => {
      const listener = vi.fn();

      const removeListener = configService.onConfigurationChange(listener);

      configService.updateConfiguration({ features: { debug: true } });
      expect(listener).toHaveBeenCalledTimes(1);

      removeListener();

      configService.updateConfiguration({ features: { caching: false } });
      expect(listener).toHaveBeenCalledTimes(1); // Should not be called again
    });
  });

  // 10. Security and Access Control Tests
  describe('Security and Access Control', () => {
    it('should enforce configuration access controls', () => {
      const configServiceWithACL = new ConfigurationService({
        accessControl: {
          roles: {
            admin: ['*'],
            user: ['features.*', 'database.url'],
            readonly: ['features.*']
          },
          defaultRole: 'readonly'
        }
      });

      configServiceWithACL.setCurrentRole('user');

      // User should be able to access allowed fields
      expect(() => configServiceWithACL.get('features.analytics')).not.toThrow();
      expect(() => configServiceWithACL.get('database.url')).not.toThrow();

      // User should not be able to access restricted fields
      expect(() => configServiceWithACL.get('database.credentials.password'))
        .toThrow('Access denied');
    });

    it('should audit configuration access and changes', () => {
      const auditLog = [];

      configService.setAuditLogger((event) => {
        auditLog.push(event);
      });

      configService.get('features.analytics');
      configService.updateConfiguration({ features: { debug: true } });

      expect(auditLog).toHaveLength(2);
      expect(auditLog[0].action).toBe('read');
      expect(auditLog[0].path).toBe('features.analytics');
      expect(auditLog[1].action).toBe('update');
      expect(auditLog[1].path).toBe('features.debug');
    });

    it('should validate configuration update permissions', () => {
      const configServiceWithPermissions = new ConfigurationService({
        permissions: {
          read: ['features.*', 'database.url'],
          write: ['features.*'],
          admin: ['database.credentials.*']
        }
      });

      configServiceWithPermissions.setCurrentUser('user1', ['read', 'write']);

      // Should be able to update features
      expect(() => configServiceWithPermissions.updateConfiguration({ features: { debug: true } }))
        .not.toThrow();

      // Should not be able to update database credentials
      expect(() => configServiceWithPermissions.updateConfiguration({
        database: { credentials: { password: 'newpass' } }
      })).toThrow('Insufficient permissions');
    });

    it('should handle configuration backup and restore', async () => {
      const originalConfig = configService.getConfiguration<TestConfigSchema>();

      const backup = await configService.createBackup();
      expect(backup.id).toBeDefined();
      expect(backup.timestamp).toBeInstanceOf(Date);
      expect(backup.configuration).toEqual(originalConfig);

      // Modify configuration
      configService.updateConfiguration({ features: { debug: true } });

      // Restore from backup
      await configService.restoreFromBackup(backup.id);

      const restoredConfig = configService.getConfiguration<TestConfigSchema>();
      expect(restoredConfig).toEqual(originalConfig);
    });

    it('should validate configuration signatures', () => {
      const configServiceWithSigning = new ConfigurationService({
        signing: {
          enabled: true,
          key: 'signing-key-123',
          algorithm: 'HS256'
        }
      });

      const config = { features: { analytics: true } };
      const signature = configServiceWithSigning.signConfiguration(config);

      expect(signature).toBeDefined();
      expect(typeof signature).toBe('string');

      const isValid = configServiceWithSigning.verifyConfigurationSignature(config, signature);
      expect(isValid).toBe(true);

      // Tampered configuration should fail verification
      const tamperedConfig = { features: { analytics: false } };
      const isValidTampered = configServiceWithSigning.verifyConfigurationSignature(tamperedConfig, signature);
      expect(isValidTampered).toBe(false);
    });
  });

  // 11. Integration and Error Handling Tests
  describe('Integration and Error Handling', () => {
    it('should handle complex configuration workflows', async () => {
      // Step 1: Load base configuration
      const baseConfig = configService.getConfiguration<TestConfigSchema>();

      // Step 2: Apply environment-specific overrides
      configService.setEnvironmentOverrides('production', {
        features: { debug: false },
        security: { encryption: { enabled: true } }
      });

      // Step 3: Inject configuration into services
      const mockService = { configure: vi.fn() };
      configService.injectConfiguration('testService', mockService, {
        databaseUrl: 'database.url',
        debug: 'features.debug'
      });

      // Step 4: Listen for changes
      const changeListener = vi.fn();
      configService.onConfigurationChange(changeListener);

      // Step 5: Update configuration
      configService.updateConfiguration({ database: { timeout: 60000 } });

      expect(baseConfig).toBeDefined();
      expect(mockService.configure).toHaveBeenCalled();
      expect(changeListener).toHaveBeenCalled();
    });

    it('should handle concurrent configuration operations', async () => {
      const operations = Array.from({ length: 10 }, (_, i) =>
        configService.updateConfiguration({
          [`test${i}`]: `value${i}`
        })
      );

      await Promise.all(operations);

      const history = configService.getVersionHistory();
      expect(history.length).toBeGreaterThan(10);
    });

    it('should handle configuration service failures gracefully', () => {
      // Mock environment failure
      mockEnvironment.getRawConfig.mockImplementation(() => {
        throw new Error('Environment access failed');
      });

      expect(() => configService.getConfiguration<TestConfigSchema>())
        .toThrow('Environment access failed');

      // Service should remain functional after environment is restored
      mockEnvironment.getRawConfig.mockReturnValue({
        DATABASE_URL: 'http://localhost:6333'
      });

      expect(() => configService.getConfiguration<TestConfigSchema>())
        .not.toThrow();
    });

    it('should handle memory pressure scenarios', () => {
      // Create many configuration updates
      for (let i = 0; i < 1000; i++) {
        configService.updateConfiguration({ [`test${i}`]: `value${i}` });
      }

      // Service should still be functional
      const config = configService.getConfiguration<TestConfigSchema>();
      expect(config).toBeDefined();

      // Cache should not grow unbounded
      const stats = configService.getCacheStatistics();
      expect(stats.size).toBeLessThan(10000);
    });

    it('should handle invalid configuration gracefully', () => {
      const invalidConfigs = [
        null,
        undefined,
        'string-instead-of-object',
        123,
        [],
        { invalid: 'structure' }
      ];

      invalidConfigs.forEach(config => {
        expect(() => configService.validateConfiguration(config as any, {}))
          .toThrow();
      });
    });

    it('should provide comprehensive error information', () => {
      try {
        configService.validateConfiguration({ invalid: 'config' }, {
          type: 'object',
          required: ['requiredField'],
          properties: {
            requiredField: { type: 'string' }
          }
        });
        fail('Should have thrown validation error');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect(error.message).toContain('validation');
        expect(error.message).toContain('requiredField');
        expect(error.details).toBeDefined();
        expect(error.path).toBeDefined();
      }
    });
  });
});