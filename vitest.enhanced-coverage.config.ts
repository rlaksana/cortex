import { defineConfig } from 'vitest/config';

/**
 * Enhanced Coverage Configuration - T09 Implementation
 *
 * Dual-threshold coverage system:
 * - ≥85% global coverage across all components
 * - ≥90% critical path coverage for core services
 *
 * Critical paths include MCP tools, authentication, and database components
 */

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: [
      'tests/unit/**/*.test.ts',
      'tests/integration/**/*.test.ts',
      'tests/contract/**/*.test.ts',
      'tests/validation/**/*.test.ts',
      'tests/**/*.spec.ts',
      'src/**/__tests__/**/*.test.ts',
    ],
    exclude: ['tests/e2e/**', 'node_modules', 'dist/', 'coverage/', '**/*.d.ts', 'scripts/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov', 'clover', 'text-summary'],
      reportsDirectory: 'coverage/enhanced',

      // Enhanced exclusion patterns
      exclude: [
        'tests/',
        'dist/',
        'node_modules/',
        'coverage/',
        'scripts/',
        'migrations/',
        'docker/',
        '.github/',
        '.husky/',
        '.claude/',
        '.serena/',
        '.specify/',
        '*.test.ts',
        '*.spec.ts',
        '*.config.ts',
        '*.config.js',
        '**/*.d.ts',
      ],

      // Dual threshold configuration
      thresholds: {
        // Global minimum thresholds (≥85%)
        global: {
          branches: 85,
          functions: 85,
          lines: 85,
          statements: 85,
        },

        // Critical path thresholds (≥90%) - Core MCP tools and services
        'src/index.ts': {
          // Main MCP server
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90,
        },

        // Core MCP tools (memory_store, memory_find)
        'src/services/memory-store.ts': {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90,
        },
        'src/services/memory-find.ts': {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90,
        },

        // Memory orchestrators (critical for MCP tool functionality)
        'src/services/orchestrators/memory-store-orchestrator.ts': {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90,
        },
        'src/services/orchestrators/memory-find-orchestrator.ts': {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90,
        },

        // Database layer (critical for data persistence)
        'src/db/database-manager.ts': {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90,
        },
        'src/db/qdrant-client.ts': {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90,
        },
        'src/db/qdrant.ts': {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90,
        },

        // Authentication and security (critical for production)
        'src/services/auth/auth-service.ts': {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90,
        },
        'src/services/auth/authorization-service.ts': {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90,
        },
        'src/middleware/auth-middleware.ts': {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90,
        },

        // Core memory functionality
        'src/services/core-memory-find.ts': {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90,
        },

        // Schema validation (critical for MCP input validation)
        'src/schemas/json-schemas.ts': {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90,
        },
        'src/schemas/mcp-inputs.ts': {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90,
        },

        // Important directories (85% threshold)
        'src/services/**': {
          branches: 85,
          functions: 85,
          lines: 85,
          statements: 85,
        },
        'src/db/**': {
          branches: 85,
          functions: 85,
          lines: 85,
          statements: 85,
        },
        'src/utils/**': {
          branches: 85,
          functions: 85,
          lines: 85,
          statements: 85,
        },
        'src/middleware/**': {
          branches: 85,
          functions: 85,
          lines: 85,
          statements: 85,
        },

        // Types and interfaces (reasonable thresholds)
        'src/types/**': {
          branches: 80,
          functions: 80,
          lines: 80,
          statements: 80,
        },

        // Configuration and monitoring (important but less critical)
        'src/config/**': {
          branches: 80,
          functions: 80,
          lines: 80,
          statements: 80,
        },
        'src/monitoring/**': {
          branches: 80,
          functions: 80,
          lines: 80,
          statements: 80,
        },
      },

      // Enhanced coverage collection options
      all: true,
      clean: true,
      cleanOnRerun: true,
      enabled: true,

      // Watermarks for visual indicators (85% minimum, 95% excellent)
      watermarks: {
        statements: [85, 95],
        functions: [85, 95],
        branches: [85, 95],
        lines: [85, 95],
      },

      // Comprehensive coverage collection
      skipFull: false,
      allowExternal: false,
      include: ['src/**/*.ts'],

      // Per-file coverage tracking for critical path analysis
      perFile: true,
      functions: true,
      branches: true,
      statements: true,
      lines: true,
    },

    // Enhanced test configuration for coverage collection
    testTimeout: 120000, // Increased timeout for comprehensive coverage
    setupFiles: ['tests/setup.ts'],
    globalSetup: ['tests/global-setup.ts'],

    // Multiple reporters for comprehensive coverage analysis
    reporters: ['verbose', 'json', 'html'],
    outputFile: {
      json: 'test-results/enhanced-coverage.json',
      junit: 'test-results/enhanced-coverage-junit.xml',
    },

    // Coverage-optimized execution settings
    watch: false,
    isolate: false, // Reduce overhead for coverage collection
    pool: 'threads',
    poolOptions: {
      threads: {
        singleThread: false,
        maxThreads: 4, // Balanced threading for coverage collection
        minThreads: 2,
        isolate: false,
      },
    },

    // Robust test execution
    retry: 1,
    bail: 10, // Allow more failures before stopping
    maxConcurrency: 4,

    // Environment for coverage collection
    env: {
      NODE_ENV: 'test',
      COVERAGE: 'true',
      VITEST_COVERAGE: 'true',
    },

    // Enhanced logging for coverage analysis
    logHeapUsage: true,
    includeTaskLocation: true,
    verbose: true,
  },

  // Optimized configuration for coverage collection
  esbuild: {
    target: 'node18',
  },

  // Dependencies configuration
  resolve: {
    alias: {
      '@': '/src',
    },
  },
});
