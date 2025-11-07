import { defineConfig } from 'vitest/config';

/**
 * Contract Test Configuration - T22 Implementation
 *
 * Specialized configuration for API contract testing including:
 * - Input/output validation testing
 * - Tool response format verification
 * - Error handling contract compliance
 * - Backward compatibility verification
 *
 * @version 2.0.1
 */

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/contract/**/*.test.ts'],
    exclude: [
      'tests/e2e/**',
      'tests/integration/**',
      'tests/unit/**',
      'tests/performance/**',
      'tests/security/**',
      'tests/validation/**',
      'node_modules',
      'dist/',
      'coverage/',
      '**/*.d.ts',
      'scripts/**',
    ],

    // Contract test specific configuration
    testTimeout: 30000, // Longer timeout for comprehensive contract tests
    hookTimeout: 10000,
    isolate: true, // Isolate tests for consistent contract validation

    // Enhanced reporting for contract tests
    reporters: ['verbose', 'json', 'html'],
    outputFile: {
      json: 'test-results/contract-tests.json',
      junit: 'test-results/contract-tests-junit.xml',
    },

    // Setup files for contract testing
    setupFiles: ['tests/contract/contract-setup.ts'],

    // Test execution settings
    watch: false,
    retry: 0, // No retries for contract tests - failures should be explicit
    bail: 1, // Stop on first failure for contract tests
    maxConcurrency: 2, // Lower concurrency for consistent validation

    // Environment for contract testing
    env: {
      NODE_ENV: 'test',
      CONTRACT_TESTING: 'true',
      API_VERSION: '2.0.1',
    },

    // Coverage for contract tests
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      reportsDirectory: 'coverage/contract',
      enabled: false, // Disabled by default, can be enabled with --coverage flag

      // Focus coverage on contract-related files
      include: [
        'src/schemas/**/*.ts',
        'src/types/**/*.ts',
        'src/utils/error-handler.ts',
        'src/types/unified-response.interface.ts',
      ],

      exclude: [
        'tests/**',
        'dist/**',
        'node_modules/**',
        'coverage/**',
        'scripts/**',
        '**/*.d.ts',
        '**/*.config.ts',
        '**/*.test.ts',
        '**/*.spec.ts',
      ],

      // No specific thresholds for contract tests (focus on validation, not coverage)
      thresholds: {
        global: {
          branches: 0,
          functions: 0,
          lines: 0,
          statements: 0,
        },
      },

      all: true,
      clean: true,
      cleanOnRerun: true,
    },

    // Verbose output for contract test debugging
    logHeapUsage: true,
    includeTaskLocation: true,
    verbose: true,
  },

  // TypeScript configuration for contract tests
  esbuild: {
    target: 'node18',
    format: 'esm',
  },

  // Path resolution
  resolve: {
    alias: {
      '@': '/src',
      '@fixtures': '/tests/fixtures',
      '@contract': '/tests/contract',
    },
  },

  // Dependencies optimization
  optimizeDeps: {
    include: ['zod', 'ajv', 'ajv-formats', '@modelcontextprotocol/sdk', 'uuid'],
  },
});
