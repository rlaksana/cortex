/**
 * Vitest Configuration for CI Environment
 *
 * This configuration defines the mandatory test and mocking profile for CI/CD pipelines.
 * It ensures consistent, fast, and reliable testing in automated environments.
 */

import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  // Test environment
  testEnvironment: 'node',

  // CI-specific settings
  ci: true,
  isolate: true,
  singleThread: true, // Ensure predictable test execution in CI

  // Global setup and teardown
  globalSetup: ['./tests/setup/global-setup.ts'],
  setupFiles: ['./tests/setup/test-setup.ts'],

  // Coverage configuration for CI
  coverage: {
    provider: 'v8',
    reporter: ['text', 'json', 'lcov'],
    include: [
      'src/**/*.ts',
      '!src/**/*.d.ts',
      '!src/**/*.test.ts',
      '!src/**/*.spec.ts',
      '!src/index.ts', // Main entry point has side effects
    ],
    exclude: [
      'tests/**',
      'node_modules/**',
      '**/*.config.*',
      'src/types/**', // Type definitions don't need coverage
      'src/constants/**', // Constants are trivial
    ],
    thresholds: {
      global: {
        branches: 75,
        functions: 80,
        lines: 80,
        statements: 80,
      },
      // Critical files need higher coverage
      'src/services/**': {
        branches: 85,
        functions: 85,
        lines: 85,
        statements: 85,
      },
      // Core utilities are critical
      'src/utils/**': {
        branches: 90,
        functions: 90,
        lines: 90,
        statements: 90,
      },
    },
    clean: true,
    cleanOnRerun: true,
  },

  // Test timeout (shorter for CI)
  testTimeout: 30000,
  hookTimeout: 10000,

  // Include patterns
  include: ['tests/**/*.test.ts', 'tests/**/*.spec.ts'],

  // Exclude patterns
  exclude: [
    'node_modules/**',
    'dist/**',
    '**/*.disabled', // Disabled test files
    'tests/**/*.performance.test.ts', // Performance tests run separately
    'tests/**/*.integration.test.ts', // Integration tests run separately
  ],

  // Reporter configuration
  reporter: ['verbose', 'json', 'junit'],
  outputFile: {
    json: './test-results/test-results.json',
    junit: './test-results/test-results.xml',
  },

  // Mocking configuration
  alias: {
    // Core services that should be mocked in CI
    '@core-services': resolve('./tests/mocks/core-services.ts'),
    '@database': resolve('./tests/mocks/database.ts'),
    '@embeddings': resolve('./tests/mocks/embeddings.ts'),
    '@monitoring': resolve('./tests/mocks/monitoring.ts'),
  },

  // Global variables for test environment
  define: {
    __CI__: JSON.stringify(true),
    __TEST_ENV__: JSON.stringify('ci'),
    __MOCK_EXTERNAL_SERVICES__: JSON.stringify(true),
    __MOCK_EMBEDDING_SERVICE__: JSON.stringify(true),
  },

  // Performance settings for CI
  maxConcurrency: 1, // Reduce flakiness in CI
  logHeapUsage: false,

  // Test organization
  sequence: {
    // Define test execution order for consistency
    shuffle: false,
    concurrent: false,
  },

  // Environment variables
  env: {
    NODE_ENV: 'test',
    CI: 'true',
    // Disable external service calls
    DISABLE_EXTERNAL_APIS: 'true',
    // Use test database
    DATABASE_URL: 'memory://test',
    // Mock embeddings - MANDATORY for CI
    MOCK_EMBEDDINGS: 'true',
    MOCK_EMBEDDING_SERVICE: 'true',
    MOCK_EMBEDDING_DETERMINISTIC: 'true',
    // Fast timeout for external services
    EXTERNAL_SERVICE_TIMEOUT: '1000',
    // Ensure no real API calls are made
    OPENAI_API_KEY: '',
    EMBEDDING_SERVICE_URL: '',
  },

  // Watch mode (disabled in CI)
  watch: false,

  // Retry configuration for flaky tests
  retry: 1,

  // Additional Vitest plugins
  plugins: [],
});

/**
 * Test Categories and Their Requirements
 *
 * 1. Unit Tests (fast, no external dependencies)
 *    - Must run in under 100ms each
 *    - All external services mocked
 *    - 100% coverage for critical paths
 *
 * 2. Integration Tests (slower, controlled dependencies)
 *    - Can use test containers or in-memory databases
 *    - Maximum 5 second timeout
 *    - Must cleanup all resources
 *
 * 3. Performance Tests (separate from unit tests)
 *    - Run only on performance branches
 *    - Must have baseline measurements
 *    - Use real data sizes
 *
 * 4. Security Tests (separate execution)
 *    - Test authentication and authorization
 *    - Validate input sanitization
 *    - Check for common vulnerabilities
 */
