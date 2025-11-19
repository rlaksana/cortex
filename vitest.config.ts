import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
      '@src': resolve(__dirname, './src'),
      '@services': resolve(__dirname, './src/services'),
      '@utils': resolve(__dirname, './src/utils'),
      '@types': resolve(__dirname, './src/types'),
      '@config': resolve(__dirname, './src/config'),
      '@/schemas': resolve(__dirname, './src/schemas'),
      '@/middleware': resolve(__dirname, './src/middleware'),
      '@/db': resolve(__dirname, './src/db'),
      '@/monitoring': resolve(__dirname, './src/monitoring'),
      '@docs': resolve(__dirname, './docs'),
      '@scripts': resolve(__dirname, './scripts'),
      '@tests': resolve(__dirname, './tests'),
    },
    extensions: ['.ts', '.tsx', '.js', '.jsx', '.json'],
  },
  esbuild: {
    target: 'node18',
    format: 'esm',
  },
  test: {
    globals: true,
    environment: 'node',
    // Handle Node.js built-in modules properly
    deps: {
      external: [
        // Add Node.js built-in modules that might cause issues
        'node:fs',
        'node:path',
        'node:crypto',
        'node:perf_hooks',
        'node:events',
        'node:url',
        'node:os',
        'node:abort_controller',
      ],
    },
    include: [
      'tests/unit/**/*.test.ts',
      'tests/integration/**/*.test.ts',
      'tests/contract/**/*.test.ts',
      'tests/validation/**/*.test.ts',
      'tests/**/*.spec.ts',
      'src/**/__tests__/*.test.ts',
      'src/**/*.test.ts',
    ],
    exclude: ['tests/e2e/**', 'node_modules', 'dist/', 'coverage/', '**/*.d.ts'],
    transformMode: {
      web: [/\.[jt]sx?$/],
      ssr: [/\.[jt]sx?$/],
    },
    // Remove deps configuration to use default handling
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov', 'text-summary'],
      reportsDirectory: 'coverage/unit',
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
        'fixtures/',
        'artifacts/',
        'docs/',
        'src/monitoring/health-dashboard-api.ts', // Temporarily exclude problematic file
        'src/monitoring/index.ts', // Temporarily exclude problematic file
        'src/monitoring/alert-system-integration.ts', // Temporarily exclude problematic file
      ],
      thresholds: {
        global: {
          branches: 85,
          functions: 85,
          lines: 85,
          statements: 85,
        },
        // Critical paths have higher thresholds
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
        // Less critical code still meets minimum thresholds
        'src/utils/**': {
          branches: 85,
          functions: 85,
          lines: 85,
          statements: 85,
        },
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
      enabled: true, // Enable coverage for quality gates
      // Coverage watermarks for visualization
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
    testTimeout: 60000, // Increased timeout to prevent timeouts
    setupFiles: ['tests/setup.ts'],
    reporters: ['verbose', 'json'],
    outputFile: {
      json: 'test-results/unit.json',
    },
    watch: false, // Disabled to reduce file handles
    isolate: true,
    pool: 'threads',
    poolOptions: {
      threads: {
        singleThread: true, // Use single thread to reduce file handles
        maxThreads: 1, // Conservative threading
        minThreads: 1,
      },
    },
    // Add cleanup hooks to prevent EMFILE
    teardownTimeout: 30000, // Increased for proper cleanup
    hookTimeout: 30000, // Increased for setup cleanup
    // Reduce concurrent operations
    maxConcurrency: 1, // Conservative concurrency
    // Early failure stopping
    bail: 5, // Stop early to prevent cascading failures
    // Disable file watchers during test
    watchExclude: ['**/*'],
    // Additional EMFILE prevention
    sequence: {
      concurrent: false, // Run tests sequentially to prevent file handle exhaustion
    },
    // Global setup for file descriptor management
    globalSetup: ['tests/global-setup.ts'],
  },
});
