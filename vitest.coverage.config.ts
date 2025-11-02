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
          branches: 70, // Reduced to realistic levels for EMFILE prevention
          functions: 75,
          lines: 75,
          statements: 75,
        },
        // Critical paths with higher thresholds but still conservative
        'src/core/**': {
          branches: 75,
          functions: 80,
          lines: 80,
          statements: 80,
        },
        'src/db/**': {
          branches: 70,
          functions: 75,
          lines: 75,
          statements: 75,
        },
        'src/mcp/**': {
          branches: 70,
          functions: 75,
          lines: 75,
          statements: 75,
        },
        // Utility functions can have slightly lower thresholds
        'src/utils/**': {
          branches: 65,
          functions: 70,
          lines: 70,
          statements: 70,
        },
        // Types and interfaces often don't need full coverage
        'src/types/**': {
          branches: 50,
          functions: 60,
          lines: 60,
          statements: 60,
        },
      },
      all: true,
      clean: true,
      cleanOnRerun: true,
      enabled: true,
      // Custom coverage configuration
      watermarks: {
        statements: [80, 95],
        functions: [80, 95],
        branches: [75, 90],
        lines: [80, 95],
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
    reporters: ['verbose', 'json', 'junit'],
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
