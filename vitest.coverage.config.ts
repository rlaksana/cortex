import { defineConfig } from 'vitest/config';

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
    ],
    exclude: ['tests/e2e/**', 'node_modules', 'dist/', 'coverage/', '**/*.d.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov', 'clover', 'text-summary'],
      reportsDirectory: 'coverage/comprehensive',
      exclude: [
        'tests/',
        'dist/',
        'node_modules/',
        'coverage/',
        '**/*.d.ts',
        '**/*.config.ts',
        '**/*.config.js',
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
      ],
      thresholds: {
        global: {
          branches: 85, // ≥85% coverage requirement
          functions: 85,
          lines: 85,
          statements: 85,
        },
        // Critical paths with higher thresholds for quality assurance
        'src/core/**': {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90,
        },
        'src/db/**': {
          branches: 85,
          functions: 85,
          lines: 85,
          statements: 85,
        },
        'src/services/**': {
          branches: 85,
          functions: 85,
          lines: 85,
          statements: 85,
        },
        'src/mcp/**': {
          branches: 85,
          functions: 85,
          lines: 85,
          statements: 85,
        },
        // Utility functions still meet minimum thresholds
        'src/utils/**': {
          branches: 85,
          functions: 85,
          lines: 85,
          statements: 85,
        },
        // Types and interfaces have slightly lower but still reasonable thresholds
        'src/types/**': {
          branches: 80,
          functions: 80,
          lines: 80,
          statements: 80,
        },
      },
      all: true,
      clean: true,
      cleanOnRerun: true,
      enabled: true,
      // Custom coverage configuration with ≥85% watermarks
      watermarks: {
        statements: [85, 95],
        functions: [85, 95],
        branches: [85, 95],
        lines: [85, 95],
      },
      // Additional coverage options
      skipFull: false,
      allowExternal: false,
      include: ['src/**/*.ts'],
      // Per-file coverage reporting
      perFile: true,
      // Function coverage details
      functions: true,
      // Branch coverage details
      branches: true,
      // Statement coverage details
      statements: true,
      // Line coverage details
      lines: true,
    },
    testTimeout: 90000, // Increased timeout for coverage collection
    setupFiles: ['tests/setup.ts'],
    globalSetup: ['tests/global-setup.ts'],
    reporters: ['verbose', 'json'],
    outputFile: {
      json: 'test-results/comprehensive.json',
      junit: 'test-results/junit.xml',
    },
    watch: false, // Disabled to reduce file handles
    isolate: false, // Reduce overhead for coverage
    pool: 'threads',
    poolOptions: {
      threads: {
        singleThread: false,
        maxThreads: 2, // Conservative threading for coverage
        minThreads: 1,
        isolate: false, // Reduce overhead
      },
    },
    // Test retry configuration
    retry: 1,
    // Test failure handling
    bail: 5, // Early failure stopping
    // Concurrency settings
    maxConcurrency: 2, // Conservative concurrency for coverage
    // Environment variables for tests
    env: {
      NODE_ENV: 'test',
      COVERAGE: 'true',
    },
    // Verbose output for detailed coverage
    logHeapUsage: true,
    // Include test locations in output
    includeTaskLocation: true,
  },
});
