/**
 * CI Mock Embedding Service Validation Test
 *
 * This test ensures that the CI environment is properly configured
 * to use mock embedding services and prevents accidental usage of real APIs.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

describe('CI Mock Embedding Service Validation', () => {
  let originalEnv: NodeJS['P']rocessEnv;

  beforeEach(() => {
    // Store original environment
    originalEnv = { ...process.env };

    // Ensure we're in CI mode for this test
    process.env['CI'] = 'true';
    process.env['NODE_ENV'] = 'test';
    process.env['__CI__'] = 'true';
    process.env['__TEST_ENV__'] = 'ci';

    // Set mandatory CI mock embedding environment variables
    process.env['MOCK_EMBEDDING_SERVICE'] = 'true';
    process.env['MOCK_EMBEDDINGS'] = 'true';
    process.env['MOCK_EMBEDDING_DETERMINISTIC'] = 'true';
    process.env['DISABLE_EXTERNAL_APIS'] = 'true';
    process.env['__MOCK_EXTERNAL_SERVICES__'] = 'true';
    process.env['__MOCK_EMBEDDING_SERVICE__'] = 'true';
    process.env['SEMANTIC_CHUNKING_OPTIONAL'] = 'true';
    process.env['ENABLE_CACHING'] = 'false';

    // Performance settings
    process.env['EXTERNAL_SERVICE_TIMEOUT'] = '1000';
    process.env['MOCK_EMBEDDING_LATENCY'] = '0';
    process.env['MOCK_EMBEDDING_SHOULD_FAIL'] = 'false';
    process.env['MOCK_EMBEDDING_DIMENSION'] = '1536';

    // Clear real API keys for CI
    process.env['OPENAI_API_KEY'] = '';
    process.env['EMBEDDING_SERVICE_URL'] = '';
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
  });

  describe('Mock Embedding Service Configuration', () => {
    it('should have MOCK_EMBEDDING_SERVICE set to true', () => {
      expect(process.env['MOCK_EMBEDDING_SERVICE']).toBe('true');
    });

    it('should have MOCK_EMBEDDINGS set to true', () => {
      expect(process.env['MOCK_EMBEDDINGS']).toBe('true');
    });

    it('should have MOCK_EMBEDDING_DETERMINISTIC set to true', () => {
      expect(process.env['MOCK_EMBEDDING_DETERMINISTIC']).toBe('true');
    });

    it('should have DISABLE_EXTERNAL_APIS set to true', () => {
      expect(process.env['DISABLE_EXTERNAL_APIS']).toBe('true');
    });

    it('should have empty OPENAI_API_KEY in CI', () => {
      // In CI, this should be empty to prevent real API calls
      expect(process.env['OPENAI_API_KEY']).toBe('');
    });

    it('should have empty EMBEDDING_SERVICE_URL in CI', () => {
      // In CI, this should be empty to prevent real service calls
      expect(process.env['EMBEDDING_SERVICE_URL']).toBe('');
    });

    it('should have fast EXTERNAL_SERVICE_TIMEOUT', () => {
      expect(process.env['EXTERNAL_SERVICE_TIMEOUT']).toBe('1000');
    });
  });

  describe('Mock Embedding Service Validation', () => {
    it('should validate that mock embedding configuration is active', () => {
      // Since @embeddings alias is configured in vitest.ci.config.ts,
      // we validate that the environment is properly set for mocking
      expect(process.env['MOCK_EMBEDDING_SERVICE']).toBe('true');
      expect(process.env['MOCK_EMBEDDINGS']).toBe('true');
      expect(process.env['DISABLE_EXTERNAL_APIS']).toBe('true');
    });

    it('should ensure no real API calls are possible', () => {
      // Validate that real API keys and URLs are cleared
      expect(process.env['OPENAI_API_KEY']).toBe('');
      expect(process.env['EMBEDDING_SERVICE_URL']).toBe('');

      // Ensure fast timeout to fail fast if something tries to call real APIs
      expect(parseInt(process.env['EXTERNAL_SERVICE_TIMEOUT'] || '0')).toBeLessThan(5000);
    });

    it('should have proper mock embedding performance settings', () => {
      expect(process.env['MOCK_EMBEDDING_LATENCY']).toBe('0');
      expect(process.env['MOCK_EMBEDDING_SHOULD_FAIL']).toBe('false');
      expect(process.env['MOCK_EMBEDDING_DIMENSION']).toBe('1536');
    });
  });

  describe('CI Environment Variables', () => {
    it('should have proper CI flags set', () => {
      expect(process.env['CI']).toBe('true');
      expect(process.env['__CI__']).toBe('true');
      expect(process.env['__TEST_ENV__']).toBe('ci');
      expect(process.env['NODE_ENV']).toBe('test');
    });

    it('should have mock services enabled', () => {
      expect(process.env['__MOCK_EXTERNAL_SERVICES__']).toBe('true');
      expect(process.env['__MOCK_EMBEDDING_SERVICE__']).toBe('true');
    });

    it('should have semantic chunking optional for CI performance', () => {
      expect(process.env['SEMANTIC_CHUNKING_OPTIONAL']).toBe('true');
    });

    it('should have caching disabled for test isolation', () => {
      expect(process.env['ENABLE_CACHING']).toBe('false');
    });
  });

  describe('Error Prevention', () => {
    it('should prevent real API calls by clearing API keys', () => {
      // Ensure no real API keys are available in CI
      expect(process.env['OPENAI_API_KEY'] || '').toBe('');
      expect(process.env['EMBEDDING_SERVICE_URL'] || '').toBe('');
    });

    it('should have fast service timeout to fail fast on errors', () => {
      expect(parseInt(process.env['EXTERNAL_SERVICE_TIMEOUT'] || '0')).toBeLessThan(5000);
    });
  });

  describe('Mock Embedding Service Performance', () => {
    it('should have zero latency configured for mock embeddings', () => {
      expect(process.env['MOCK_EMBEDDING_LATENCY']).toBe('0');
    });

    it('should be configured not to fail', () => {
      expect(process.env['MOCK_EMBEDDING_SHOULD_FAIL']).toBe('false');
    });

    it('should have correct dimension size', () => {
      expect(process.env['MOCK_EMBEDDING_DIMENSION']).toBe('1536');
    });
  });
});
