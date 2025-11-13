/**
 * Configuration Migration System Tests
 *
 * Comprehensive test suite for the configuration migration system,
 * ensuring proper handling of legacy and standard configuration properties.
 */

import { beforeEach,describe, expect, it } from 'vitest';

import {
  _HealthCheckConfigBuilder,
  _HttpClientBuilder,
  _validateHealthCheckConfig,
  _validateHttpClientConfig,
  healthCheckConfig,
  httpClientConfig,
  isStandardHealthCheckConfig,
  isStandardHttpClientConfig,
  type LegacyHealthCheckConfig,
  type LegacyHttpClientConfig,
  migrateHealthCheckConfig,
  migrateHttpClientConfig,
  type StandardHealthCheckConfig,
  type StandardHttpClientConfig,
} from '../configuration-migration.js';
import {
  type _ValidationResult,
  ConfigurationValidator,
  isValidConfiguration,
  validateConfigurationPermissive,
  validateConfigurationStrict,
} from '../configuration-validator.js';

describe('Configuration Migration', () => {
  describe('Health Check Configuration Migration', () => {
    it('should migrate legacy properties to standard format', () => {
      const legacyConfig: LegacyHealthCheckConfig = {
        enabled: true,
        timeout: 10000,
        retries: 3,
        retryDelay: 1000,
        interval: 30000,
      };

      const standardConfig = migrateHealthCheckConfig(legacyConfig);

      expect(standardConfig).toEqual({
        enabled: true,
        intervalMs: 30000,
        timeoutMs: 10000,
        failureThreshold: 3,
        successThreshold: 2,
        retryAttempts: 3,
        retryDelayMs: 1000,
      });
    });

    it('should handle standard properties without migration', () => {
      const standardConfigInput: Partial<StandardHealthCheckConfig> = {
        enabled: true,
        intervalMs: 30000,
        timeoutMs: 10000,
        retryAttempts: 3,
        retryDelayMs: 1000,
      };

      const standardConfig = migrateHealthCheckConfig(standardConfigInput);

      expect(standardConfig).toEqual({
        enabled: true,
        intervalMs: 30000,
        timeoutMs: 10000,
        failureThreshold: 3,
        successThreshold: 2,
        retryAttempts: 3,
        retryDelayMs: 1000,
      });
    });

    it('should prefer standard properties over legacy ones', () => {
      const mixedConfig: LegacyHealthCheckConfig = {
        timeout: 5000, // Legacy
        timeoutMs: 10000, // Standard (should take precedence)
        retries: 2, // Legacy
        retryAttempts: 5, // Standard (should take precedence)
      };

      const standardConfig = migrateHealthCheckConfig(mixedConfig);

      expect(standardConfig.timeoutMs).toBe(10000);
      expect(standardConfig.retryAttempts).toBe(5);
    });

    it('should handle empty configuration with defaults', () => {
      const emptyConfig = {};
      const standardConfig = migrateHealthCheckConfig(emptyConfig);

      expect(standardConfig.enabled).toBe(true);
      expect(standardConfig.intervalMs).toBe(30000);
      expect(standardConfig.timeoutMs).toBe(10000);
      expect(standardConfig.retryAttempts).toBe(3);
      expect(standardConfig.retryDelayMs).toBe(1000);
    });
  });

  describe('HTTP Client Configuration Migration', () => {
    it('should migrate legacy properties to standard format', () => {
      const legacyConfig: LegacyHttpClientConfig = {
        timeout: 10000,
        retries: 3,
        retryDelay: 1000,
        headers: { 'User-Agent': 'Test' },
      };

      const standardConfig = migrateHttpClientConfig(legacyConfig);

      expect(standardConfig).toEqual({
        timeoutMs: 10000,
        retryAttempts: 3,
        retryDelayMs: 1000,
        headers: { 'User-Agent': 'Test' },
      });
    });

    it('should handle standard properties without migration', () => {
      const standardConfigInput: Partial<StandardHttpClientConfig> = {
        timeoutMs: 10000,
        retryAttempts: 3,
        retryDelayMs: 1000,
        headers: { 'User-Agent': 'Test' },
      };

      const standardConfig = migrateHttpClientConfig(standardConfigInput);

      expect(standardConfig).toEqual({
        timeoutMs: 10000,
        retryAttempts: 3,
        retryDelayMs: 1000,
        headers: { 'User-Agent': 'Test' },
      });
    });

    it('should prefer standard properties over legacy ones', () => {
      const mixedConfig: LegacyHttpClientConfig = {
        timeout: 5000, // Legacy
        timeoutMs: 10000, // Standard (should take precedence)
        retries: 2, // Legacy
        retryAttempts: 5, // Standard (should take precedence)
      };

      const standardConfig = migrateHttpClientConfig(mixedConfig);

      expect(standardConfig.timeoutMs).toBe(10000);
      expect(standardConfig.retryAttempts).toBe(5);
    });

    it('should handle empty configuration with defaults', () => {
      const emptyConfig = {};
      const standardConfig = migrateHttpClientConfig(emptyConfig);

      expect(standardConfig.timeoutMs).toBe(10000);
      expect(standardConfig.retryAttempts).toBe(0);
      expect(standardConfig.retryDelayMs).toBe(1000);
      expect(standardConfig.headers).toEqual({});
    });
  });

  describe('Time Value Normalization', () => {
    it('should convert seconds to milliseconds for small values', () => {
      const config = {
        timeout: 5, // Should be treated as 5 seconds -> 5000ms
        retryDelay: 2, // Should be treated as 2 seconds -> 2000ms
      };

      const standardConfig = migrateHealthCheckConfig(config);

      expect(standardConfig.timeoutMs).toBe(5000);
      expect(standardConfig.retryDelayMs).toBe(2000);
    });

    it('should keep millisecond values for large values', () => {
      const config = {
        timeout: 5000, // Should be kept as 5000ms
        retryDelay: 1000, // Should be kept as 1000ms
      };

      const standardConfig = migrateHealthCheckConfig(config);

      expect(standardConfig.timeoutMs).toBe(5000);
      expect(standardConfig.retryDelayMs).toBe(1000);
    });
  });
});

describe('Configuration Validation', () => {
  let validator: ConfigurationValidator;

  beforeEach(() => {
    validator = new ConfigurationValidator();
  });

  describe('Health Check Configuration Validation', () => {
    it('should validate correct standard configuration', () => {
      const config: StandardHealthCheckConfig = {
        enabled: true,
        intervalMs: 30000,
        timeoutMs: 10000,
        failureThreshold: 3,
        successThreshold: 2,
        retryAttempts: 3,
        retryDelayMs: 1000,
      };

      const result = validator.validateHealthCheckConfig(config);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.warnings).toHaveLength(0);
    });

    it('should warn about deprecated properties', () => {
      const config = {
        timeout: 10000, // Deprecated
        retries: 3, // Deprecated
        retryDelay: 1000, // Deprecated
        timeoutMs: 10000, // Standard
        retryAttempts: 3, // Standard
        retryDelayMs: 1000, // Standard
      };

      const result = validator.validateHealthCheckConfig(config);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings.some((w) => w.code === 'DEPRECATED_PROPERTY')).toBe(true);
    });

    it('should detect missing required properties', () => {
      const config = {
        enabled: true,
        // Missing timeoutMs, retryAttempts, retryDelayMs
      };

      const result = validator.validateHealthCheckConfig(config);

      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.some((e) => e.code === 'MISSING_REQUIRED_PROPERTY')).toBe(true);
    });

    it('should validate value constraints', () => {
      const config = {
        enabled: true,
        intervalMs: 30000,
        timeoutMs: -1000, // Invalid: negative value
        retryAttempts: 15, // Warning: high value
        retryDelayMs: 120000, // Warning: high value
        failureThreshold: 3,
        successThreshold: 2,
      };

      const result = validator.validateHealthCheckConfig(config);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.code === 'INVALID_VALUE')).toBe(true);
      expect(result.warnings.some((w) => w.code === 'HIGH_RETRY_COUNT')).toBe(true);
      expect(result.warnings.some((w) => w.code === 'HIGH_RETRY_DELAY')).toBe(true);
    });

    it('should validate types', () => {
      const config = {
        enabled: true,
        intervalMs: '30000', // Invalid: should be number
        timeoutMs: 10000,
        retryAttempts: '3', // Invalid: should be number
        retryDelayMs: 1000,
        failureThreshold: 3,
        successThreshold: 2,
      };

      const result = validator.validateHealthCheckConfig(config);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.code === 'INVALID_TYPE')).toBe(true);
    });
  });

  describe('HTTP Client Configuration Validation', () => {
    it('should validate correct standard configuration', () => {
      const config: StandardHttpClientConfig = {
        timeoutMs: 10000,
        retryAttempts: 3,
        retryDelayMs: 1000,
        headers: { 'User-Agent': 'Test' },
      };

      const result = validator.validateHttpClientConfig(config);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.warnings).toHaveLength(0);
    });

    it('should warn about deprecated properties', () => {
      const config = {
        timeout: 10000, // Deprecated
        retries: 3, // Deprecated
        retryDelay: 1000, // Deprecated
        timeoutMs: 10000, // Standard
        retryAttempts: 3, // Standard
        retryDelayMs: 1000, // Standard
      };

      const result = validator.validateHttpClientConfig(config);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.warnings.length).toBeGreaterThan(0);
    });

    it('should detect missing required properties', () => {
      const config = {
        headers: { 'User-Agent': 'Test' },
        // Missing timeoutMs, retryAttempts, retryDelayMs
      };

      const result = validator.validateHttpClientConfig(config);

      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.some((e) => e.code === 'MISSING_REQUIRED_PROPERTY')).toBe(true);
    });
  });

  describe('Strict vs Permissive Validation', () => {
    it('should pass permissive validation with warnings', () => {
      const config = {
        timeout: 10000, // Deprecated
        retries: 3, // Deprecated
        timeoutMs: 10000, // Standard
        retryAttempts: 3, // Standard
      };

      const permissiveResult = validateConfigurationPermissive(config, 'http-client');
      const strictResult = validateConfigurationStrict(config, 'http-client');

      expect(permissiveResult.valid).toBe(true);
      expect(permissiveResult.warnings.length).toBeGreaterThan(0);

      expect(strictResult.valid).toBe(false);
      expect(strictResult.errors.length).toBeGreaterThan(0);
    });
  });
});

describe('Builder Patterns', () => {
  describe('HealthCheckConfigBuilder', () => {
    it('should build valid configuration', () => {
      const config = healthCheckConfig()
        .enabled(true)
        .timeoutMs(10000)
        .retryAttempts(3)
        .retryDelayMs(1000)
        .intervalMs(30000)
        .failureThreshold(3)
        .successThreshold(2)
        .build();

      expect(config).toEqual({
        enabled: true,
        intervalMs: 30000,
        timeoutMs: 10000,
        failureThreshold: 3,
        successThreshold: 2,
        retryAttempts: 3,
        retryDelayMs: 1000,
      });
    });

    it('should provide convenience methods for time values', () => {
      const config = healthCheckConfig()
        .timeoutSeconds(10) // 10 seconds -> 10000ms
        .retryDelaySeconds(1) // 1 second -> 1000ms
        .intervalSeconds(30) // 30 seconds -> 30000ms
        .build();

      expect(config.timeoutMs).toBe(10000);
      expect(config.retryDelayMs).toBe(1000);
      expect(config.intervalMs).toBe(30000);
    });

    it('should throw error for invalid configuration', () => {
      expect(() => {
        healthCheckConfig()
          .timeoutMs(-1000) // Invalid: negative timeout
          .build();
      }).toThrow('Invalid health check configuration');
    });

    it('should build unsafe configuration without validation', () => {
      const config = healthCheckConfig()
        .timeoutMs(-1000) // Invalid
        .buildUnsafe();

      expect(config.timeoutMs).toBe(-1000);
    });
  });

  describe('HttpClientBuilder', () => {
    it('should build valid configuration', () => {
      const config = httpClientConfig()
        .timeoutMs(10000)
        .retryAttempts(3)
        .retryDelayMs(1000)
        .header('User-Agent', 'Test')
        .header('Authorization', 'Bearer token')
        .build();

      expect(config).toEqual({
        timeoutMs: 10000,
        retryAttempts: 3,
        retryDelayMs: 1000,
        headers: {
          'User-Agent': 'Test',
          Authorization: 'Bearer token',
        },
      });
    });

    it('should provide convenience methods for time values', () => {
      const config = httpClientConfig()
        .timeoutSeconds(10) // 10 seconds -> 10000ms
        .retryDelaySeconds(1) // 1 second -> 1000ms
        .build();

      expect(config.timeoutMs).toBe(10000);
      expect(config.retryDelayMs).toBe(1000);
    });

    it('should merge headers correctly', () => {
      const config = httpClientConfig()
        .headers({ 'User-Agent': 'Test' })
        .header('Authorization', 'Bearer token')
        .build();

      expect(config.headers).toEqual({
        'User-Agent': 'Test',
        Authorization: 'Bearer token',
      });
    });

    it('should throw error for invalid configuration', () => {
      expect(() => {
        httpClientConfig()
          .timeoutMs(-1000) // Invalid: negative timeout
          .build();
      }).toThrow('Invalid HTTP client configuration');
    });
  });
});

describe('Type Guards', () => {
  describe('Health Check Configuration Type Guards', () => {
    it('should identify standard health check configuration', () => {
      const standardConfig: StandardHealthCheckConfig = {
        enabled: true,
        intervalMs: 30000,
        timeoutMs: 10000,
        failureThreshold: 3,
        successThreshold: 2,
        retryAttempts: 3,
        retryDelayMs: 1000,
      };

      expect(isStandardHealthCheckConfig(standardConfig)).toBe(true);
    });

    it('should reject non-standard health check configuration', () => {
      const legacyConfig = {
        enabled: true,
        timeout: 10000,
        retries: 3,
        retryDelay: 1000,
      };

      expect(isStandardHealthCheckConfig(legacyConfig)).toBe(false);
    });

    it('should reject invalid objects', () => {
      expect(isStandardHealthCheckConfig(null)).toBe(false);
      expect(isStandardHealthCheckConfig(undefined)).toBe(false);
      expect(isStandardHealthCheckConfig('string')).toBe(false);
      expect(isStandardHealthCheckConfig(123)).toBe(false);
    });
  });

  describe('HTTP Client Configuration Type Guards', () => {
    it('should identify standard HTTP client configuration', () => {
      const standardConfig: StandardHttpClientConfig = {
        timeoutMs: 10000,
        retryAttempts: 3,
        retryDelayMs: 1000,
        headers: {},
      };

      expect(isStandardHttpClientConfig(standardConfig)).toBe(true);
    });

    it('should reject non-standard HTTP client configuration', () => {
      const legacyConfig = {
        timeout: 10000,
        retries: 3,
        retryDelay: 1000,
      };

      expect(isStandardHttpClientConfig(legacyConfig)).toBe(false);
    });

    it('should reject invalid objects', () => {
      expect(isStandardHttpClientConfig(null)).toBe(false);
      expect(isStandardHttpClientConfig(undefined)).toBe(false);
      expect(isStandardHttpClientConfig('string')).toBe(false);
      expect(isStandardHttpClientConfig(123)).toBe(false);
    });
  });
});

describe('Utility Functions', () => {
  describe('Quick Validation', () => {
    it('should return boolean for valid configuration', () => {
      const validConfig: StandardHealthCheckConfig = {
        enabled: true,
        intervalMs: 30000,
        timeoutMs: 10000,
        failureThreshold: 3,
        successThreshold: 2,
        retryAttempts: 3,
        retryDelayMs: 1000,
      };

      expect(isValidConfiguration(validConfig, 'health-check')).toBe(true);
    });

    it('should return boolean for invalid configuration', () => {
      const invalidConfig = {
        enabled: 'true', // Wrong type
        timeoutMs: -1000, // Invalid value
      };

      expect(isValidConfiguration(invalidConfig, 'health-check')).toBe(false);
    });
  });

  describe('Auto-detection', () => {
    it('should auto-detect health check configuration', () => {
      const config = {
        enabled: true,
        timeoutMs: 10000,
        retryAttempts: 3,
      };

      const result = validateConfigurationPermissive(config, 'auto');

      expect(result.valid).toBe(true);
      expect(result.metadata?.migrationPerformed).toBeDefined();
    });

    it('should auto-detect HTTP client configuration', () => {
      const config = {
        timeoutMs: 10000,
        retryAttempts: 3,
        headers: {},
      };

      const result = validateConfigurationPermissive(config, 'auto');

      expect(result.valid).toBe(true);
      expect(result.metadata?.migrationPerformed).toBeDefined();
    });

    it('should fail for unknown configuration type', () => {
      const config = {
        unknownProperty: 'value',
      };

      const result = validateConfigurationPermissive(config, 'auto');

      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.code === 'UNKNOWN_CONFIGURATION_TYPE')).toBe(true);
    });
  });
});
