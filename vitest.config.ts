import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: [
      'tests/unit/**/*.test.ts',
      'tests/contract/**/*.test.ts',
      'tests/validation/**/*.test.ts',
      'tests/**/*.spec.ts'
    ],
    exclude: [
      'tests/integration/**',
      'tests/e2e/**',
      'node_modules',
      'dist/',
      'coverage/',
      '**/*.d.ts'
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov', 'clover'],
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
        '.specify/'
      ],
      thresholds: {
        global: {
          branches: 90,
          functions: 95,
          lines: 95,
          statements: 95
        },
        // Critical paths have higher thresholds
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
        // Less critical code can have lower thresholds
        'src/utils/**': {
          branches: 85,
          functions: 90,
          lines: 90,
          statements: 90
        }
      },
      all: true,
      clean: true,
      cleanOnRerun: true,
      enabled: true
    },
    testTimeout: 10000,
    setupFiles: ['tests/setup.ts'],
    reporters: ['verbose', 'json'],
    outputFile: {
      json: 'test-results/unit.json'
    },
    watch: false,
    isolate: true,
    pool: 'threads',
    poolOptions: {
      threads: {
        singleThread: false,
        maxThreads: 4,
        minThreads: 1
      }
    }
  },
});
