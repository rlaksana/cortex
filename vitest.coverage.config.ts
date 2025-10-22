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
      'tests/**/*.spec.ts'
    ],
    exclude: [
      'tests/e2e/**',
      'node_modules',
      'dist/',
      'coverage/',
      '**/*.d.ts'
    ],
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
        '*.spec.ts'
      ],
      thresholds: {
        global: {
          branches: 90,
          functions: 95,
          lines: 95,
          statements: 95
        },
        // Critical paths with higher thresholds
        'src/core/**': {
          branches: 95,
          functions: 98,
          lines: 98,
          statements: 98
        },
        'src/db/**': {
          branches: 90,
          functions: 95,
          lines: 95,
          statements: 95
        },
        'src/mcp/**': {
          branches: 90,
          functions: 95,
          lines: 95,
          statements: 95
        },
        // Utility functions can have slightly lower thresholds
        'src/utils/**': {
          branches: 85,
          functions: 90,
          lines: 90,
          statements: 90
        },
        // Types and interfaces often don't need full coverage
        'src/types/**': {
          branches: 70,
          functions: 80,
          lines: 80,
          statements: 80
        }
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
        lines: [80, 95]
      },
      // Additional coverage options
      skipFull: false,
      allowExternal: false,
      include: [
        'src/**/*.ts'
      ],
      // Per-file coverage reporting
      perFile: true,
      // Function coverage details
      functions: true,
      // Branch coverage details
      branches: true,
      // Statement coverage details
      statements: true,
      // Line coverage details
      lines: true
    },
    testTimeout: 15000,
    setupFiles: ['tests/setup.ts'],
    globalSetup: ['tests/global-setup.ts'],
    reporters: ['verbose', 'json', 'junit'],
    outputFile: {
      json: 'test-results/comprehensive.json',
      junit: 'test-results/junit.xml'
    },
    watch: false,
    isolate: true,
    pool: 'threads',
    poolOptions: {
      threads: {
        singleThread: false,
        maxThreads: 6,
        minThreads: 1,
        isolate: true
      }
    },
    // Test retry configuration
    retry: 1,
    // Test failure handling
    bail: 10,
    // Concurrency settings
    maxConcurrency: 6,
    // Environment variables for tests
    env: {
      NODE_ENV: 'test',
      COVERAGE: 'true'
    },
    // Verbose output for detailed coverage
    logHeapUsage: true,
    // Include test locations in output
    includeTaskLocation: true
  },
});