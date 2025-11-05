/**
 * HTTP Configuration Tests
 *
 * Tests for the HTTP configuration management system including
 * timeout management, retry logic, and environment-specific settings.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  HttpConfigManager,
  httpConfigManager,
  getHttpTimeout,
  getHttpRetryConfig,
  isRetryableHttpStatusCode,
  isRetryableHttpError,
  calculateHttpRetryDelay,
  DEFAULT_HTTP_CONFIG,
  ENVIRONMENT_HTTP_CONFIGS
} from '../../../src/config/http-config.js';

describe('HTTP Configuration Manager', () => {
  let manager: HttpConfigManager;

  beforeEach(() => {
    manager = new HttpConfigManager();
  });

  afterEach(() => {
    // Reset to default environment
    manager = new HttpConfigManager('development');
  });

  describe('Basic Configuration', () => {
    it('should load default configuration', () => {
      const config = manager.getConfig();

      expect(config.timeouts.default).toBe(30000);
      expect(config.retries.maxAttempts).toBe(3);
      expect(config.headers['User-Agent']).toContain('MCP-Cortex');
      expect(config.enableCompression).toBe(true);
      expect(config.keepAlive).toBe(true);
    });

    it('should load environment-specific configuration', () => {
      const testManager = new HttpConfigManager('test');
      const config = testManager.getConfig();

      expect(config.timeouts.default).toBe(5000); // Test environment timeout
      expect(config.retries.maxAttempts).toBe(1);   // Test environment retries
    });

    it('should load production configuration', () => {
      const prodManager = new HttpConfigManager('production');
      const config = prodManager.getConfig();

      expect(config.timeouts.default).toBe(30000);
      expect(config.maxRequestSize).toBe(5 * 1024 * 1024); // Smaller in production
      expect(config.maxResponseSize).toBe(25 * 1024 * 1024); // Smaller in production
    });
  });

  describe('Timeout Management', () => {
    it('should get timeout for specific operation type', () => {
      expect(manager.getTimeout('default')).toBe(30000);
      expect(manager.getTimeout('short')).toBe(5000);
      expect(manager.getTimeout('medium')).toBe(15000);
      expect(manager.getTimeout('long')).toBe(60000);
      expect(manager.getTimeout('upload')).toBe(120000);
      expect(manager.getTimeout('download')).toBe(300000);
    });

    it('should return default timeout for unknown type', () => {
      expect(manager.getTimeout('unknown' as any)).toBe(30000);
    });

    it('should set custom timeout for operation type', () => {
      manager.setTimeout('custom' as any, 45000);
      expect(manager.getTimeout('custom' as any)).toBe(45000);
    });

    it('should update existing timeouts', () => {
      manager.setTimeout('short', 10000);
      expect(manager.getTimeout('short')).toBe(10000);
    });
  });

  describe('Retry Configuration', () => {
    it('should get retry configuration', () => {
      const retryConfig = manager.getRetryConfig();

      expect(retryConfig.maxAttempts).toBe(3);
      expect(retryConfig.baseDelay).toBe(1000);
      expect(retryConfig.maxDelay).toBe(30000);
      expect(retryConfig.backoffMultiplier).toBe(2);
      expect(retryConfig.retryableStatusCodes).toContain(500);
      expect(retryConfig.retryableStatusCodes).toContain(503);
    });

    it('should check if status code is retryable', () => {
      expect(manager.isRetryableStatusCode(500)).toBe(true);
      expect(manager.isRetryableStatusCode(503)).toBe(true);
      expect(manager.isRetryableStatusCode(429)).toBe(true);
      expect(manager.isRetryableStatusCode(408)).toBe(true);
      expect(manager.isRetryableStatusCode(200)).toBe(false);
      expect(manager.isRetryableStatusCode(404)).toBe(false);
    });

    it('should check if error is retryable by name', () => {
      const retryableError = new Error('Test error');
      retryableError.name = 'ECONNRESET';
      expect(manager.isRetryableError(retryableError)).toBe(true);

      const nonRetryableError = new Error('Test error');
      nonRetryableError.name = 'ValidationError';
      expect(manager.isRetryableError(nonRetryableError)).toBe(false);
    });

    it('should check if error is retryable by message', () => {
      const retryableError = new Error('NETWORK_ERROR occurred');
      expect(manager.isRetryableError(retryableError)).toBe(true);

      const nonRetryableError = new Error('Invalid input data');
      expect(manager.isRetryableError(nonRetryableError)).toBe(false);
    });

    it('should calculate retry delay with exponential backoff', () => {
      expect(manager.calculateRetryDelay(1)).toBe(1000);  // 1st attempt
      expect(manager.calculateRetryDelay(2)).toBe(2000);  // 2nd attempt
      expect(manager.calculateRetryDelay(3)).toBe(4000);  // 3rd attempt
    });

    it('should cap retry delay at maximum', () => {
      // Should not exceed maxDelay of 30000
      expect(manager.calculateRetryDelay(10)).toBeLessThanOrEqual(30000);
    });

    it('should update retry configuration', () => {
      const newRetryConfig = {
        maxAttempts: 5,
        baseDelay: 500,
        backoffMultiplier: 1.5,
      };

      manager.setRetryConfig(newRetryConfig);
      const updatedConfig = manager.getRetryConfig();

      expect(updatedConfig.maxAttempts).toBe(5);
      expect(updatedConfig.baseDelay).toBe(500);
      expect(updatedConfig.backoffMultiplier).toBe(1.5);
      expect(updatedConfig.maxDelay).toBe(30000); // Should preserve existing value
    });
  });

  describe('Header Management', () => {
    it('should get default headers', () => {
      const headers = manager.getHeaders();

      expect(headers['User-Agent']).toContain('MCP-Cortex');
      expect(headers['Accept']).toBe('application/json');
      expect(headers['Accept-Encoding']).toBe('gzip, deflate, br');
      expect(headers['Connection']).toBe('keep-alive');
    });

    it('should set custom header', () => {
      manager.setHeader('X-Custom-Header', 'custom-value');
      const headers = manager.getHeaders();

      expect(headers['X-Custom-Header']).toBe('custom-value');
    });

    it('should override existing header', () => {
      manager.setHeader('User-Agent', 'Custom-Agent/1.0');
      const headers = manager.getHeaders();

      expect(headers['User-Agent']).toBe('Custom-Agent/1.0');
    });

    it('should remove header', () => {
      manager.removeHeader('Accept-Encoding');
      const headers = manager.getHeaders();

      expect(headers['Accept-Encoding']).toBeUndefined();
    });
  });

  describe('Configuration Updates', () => {
    it('should update partial configuration', () => {
      const updates = {
        timeouts: {
          default: 45000,
          short: 10000,
        },
        retries: {
          maxAttempts: 5,
        },
        maxRedirects: 10,
      };

      manager.updateConfig(updates);
      const config = manager.getConfig();

      expect(config.timeouts.default).toBe(45000);
      expect(config.timeouts.short).toBe(10000);
      expect(config.timeouts.medium).toBe(15000); // Should remain unchanged
      expect(config.retries.maxAttempts).toBe(5);
      expect(config.retries.baseDelay).toBe(1000); // Should remain unchanged
      expect(config.maxRedirects).toBe(10);
    });

    it('should update headers in configuration', () => {
      const updates = {
        headers: {
          'X-API-Key': 'secret-key',
          'Authorization': 'Bearer token',
        },
      };

      manager.updateConfig(updates);
      const headers = manager.getHeaders();

      expect(headers['X-API-Key']).toBe('secret-key');
      expect(headers['Authorization']).toBe('Bearer token');
      expect(headers['User-Agent']).toContain('MCP-Cortex'); // Should preserve existing
    });
  });

  describe('Configuration Validation', () => {
    it('should validate correct configuration', () => {
      const validation = manager.validateConfig();

      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    it('should detect invalid timeouts', () => {
      manager.setTimeout('short', -1000);
      const validation = manager.validateConfig();

      expect(validation.isValid).toBe(false);
      expect(validation.errors.some(e => e.includes('Invalid timeout for short'))).toBe(true);
    });

    it('should detect invalid retry configuration', () => {
      manager.setRetryConfig({
        maxAttempts: -1,
        baseDelay: 0,
        maxDelay: -100,
        backoffMultiplier: 0.5,
      });

      const validation = manager.validateConfig();

      expect(validation.isValid).toBe(false);
      expect(validation.errors.length).toBeGreaterThan(3);
      expect(validation.errors.some(e => e.includes('Max retry attempts must be non-negative'))).toBe(true);
      expect(validation.errors.some(e => e.includes('Base retry delay must be positive'))).toBe(true);
      expect(validation.errors.some(e => e.includes('Backoff multiplier must be greater than 1'))).toBe(true);
    });

    it('should detect invalid numeric values', () => {
      manager.updateConfig({
        maxRedirects: -5,
        maxRequestSize: 0,
        maxResponseSize: -100,
      });

      const validation = manager.validateConfig();

      expect(validation.isValid).toBe(false);
      expect(validation.errors.some(e => e.includes('Max redirects must be non-negative'))).toBe(true);
      expect(validation.errors.some(e => e.includes('Max request size must be positive'))).toBe(true);
      expect(validation.errors.some(e => e.includes('Max response size must be positive'))).toBe(true);
    });
  });

  describe('Configuration Import/Export', () => {
    it('should export configuration to JSON', () => {
      const exported = manager.exportConfig();
      const data = JSON.parse(exported);

      expect(data.environment).toBe('development');
      expect(data.config.timeouts.default).toBe(30000);
      expect(data.validation.isValid).toBe(true);
    });

    it('should import configuration from JSON', () => {
      const customConfig = {
        environment: 'custom',
        config: {
          timeouts: { default: 60000 },
          retries: { maxAttempts: 5 },
          headers: { 'X-Custom': 'value' },
        },
      };

      const configJson = JSON.stringify(customConfig);
      manager.importConfig(configJson);

      const config = manager.getConfig();
      expect(config.timeouts.default).toBe(60000);
      expect(config.retries.maxAttempts).toBe(5);
      expect(config.headers['X-Custom']).toBe('value');
    });

    it('should handle invalid JSON gracefully', () => {
      expect(() => {
        manager.importConfig('invalid json');
      }).toThrow('Failed to import HTTP configuration');
    });
  });

  describe('Configuration Summary', () => {
    it('should provide configuration summary', () => {
      const summary = manager.getSummary();

      expect(summary.environment).toBe('development');
      expect(summary.defaultTimeout).toBe(30000);
      expect(summary.maxRetries).toBe(3);
      expect(summary.headerCount).toBeGreaterThan(0);
      expect(summary.compressionEnabled).toBe(true);
      expect(summary.keepAliveEnabled).toBe(true);
    });
  });
});

describe('Global HTTP Configuration Functions', () => {
  describe('getHttpTimeout', () => {
    it('should return timeout from global manager', () => {
      expect(getHttpTimeout('default')).toBe(30000);
      expect(getHttpTimeout('short')).toBe(5000);
    });

    it('should return default timeout for unknown type', () => {
      expect(getHttpTimeout('unknown' as any)).toBe(30000);
    });
  });

  describe('getHttpRetryConfig', () => {
    it('should return retry config from global manager', () => {
      const config = getHttpRetryConfig();

      expect(config.maxAttempts).toBe(3);
      expect(config.baseDelay).toBe(1000);
      expect(config.backoffMultiplier).toBe(2);
    });
  });

  describe('isRetryableHttpStatusCode', () => {
    it('should check retryable status codes', () => {
      expect(isRetryableHttpStatusCode(500)).toBe(true);
      expect(isRetryableHttpStatusCode(503)).toBe(true);
      expect(isRetryableHttpStatusCode(200)).toBe(false);
      expect(isRetryableHttpStatusCode(404)).toBe(false);
    });
  });

  describe('isRetryableHttpError', () => {
    it('should check retryable errors by name', () => {
      const retryableError = new Error('Test');
      retryableError.name = 'ECONNRESET';
      expect(isRetryableHttpError(retryableError)).toBe(true);

      const nonRetryableError = new Error('Test');
      nonRetryableError.name = 'ValidationError';
      expect(isRetryableHttpError(nonRetryableError)).toBe(false);
    });

    it('should check retryable errors by message', () => {
      const retryableError = new Error('NETWORK_ERROR occurred');
      expect(isRetryableHttpError(retryableError)).toBe(true);

      const nonRetryableError = new Error('Invalid data');
      expect(isRetryableHttpError(nonRetryableError)).toBe(false);
    });
  });

  describe('calculateHttpRetryDelay', () => {
    it('should calculate retry delay with exponential backoff', () => {
      expect(calculateHttpRetryDelay(1)).toBe(1000);
      expect(calculateHttpRetryDelay(2)).toBe(2000);
      expect(calculateHttpRetryDelay(3)).toBe(4000);
    });

    it('should cap delay at maximum', () => {
      expect(calculateHttpRetryDelay(20)).toBeLessThanOrEqual(30000);
    });
  });
});

describe('Default Configuration Constants', () => {
  it('should have valid default configuration', () => {
    expect(DEFAULT_HTTP_CONFIG.timeouts.default).toBe(30000);
    expect(DEFAULT_HTTP_CONFIG.retries.maxAttempts).toBe(3);
    expect(DEFAULT_HTTP_CONFIG.headers['User-Agent']).toContain('MCP-Cortex');
  });

  it('should have valid environment configurations', () => {
    expect(ENVIRONMENT_HTTP_CONFIGS.test).toBeDefined();
    expect(ENVIRONMENT_HTTP_CONFIGS.production).toBeDefined();
    expect(ENVIRONMENT_HTTP_CONFIGS.development).toBeDefined();

    // Test environment should have shorter timeouts
    expect(ENVIRONMENT_HTTP_CONFIGS.test?.timeouts?.default).toBeLessThan(
      DEFAULT_HTTP_CONFIG.timeouts.default
    );

    // Production should have smaller size limits
    expect(ENVIRONMENT_HTTP_CONFIGS.production?.maxRequestSize).toBeLessThan(
      DEFAULT_HTTP_CONFIG.maxRequestSize
    );
  });
});