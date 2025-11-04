import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/e2e/**/*.test.ts'],
    exclude: ['tests/unit/**', 'tests/integration/**', 'node_modules'],
    testTimeout: 60000, // E2E tests can be slow
    hookTimeout: 120000, // Allow time for full server startup
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov', 'text-summary'],
      reportsDirectory: 'coverage/e2e',
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
      ],
      thresholds: {
        global: {
          branches: 80, // Slightly lower for E2E as they test integration points
          functions: 80,
          lines: 80,
          statements: 80,
        },
      },
      all: true,
      clean: true,
      cleanOnRerun: true,
      enabled: true,
      watermarks: {
        statements: [80, 90],
        functions: [80, 90],
        branches: [80, 90],
        lines: [80, 90],
      },
      skipFull: false,
      allowExternal: false,
      include: ['src/**/*.ts'],
      perFile: false, // E2E tests focus on overall coverage
      functions: true,
      branches: true,
      statements: true,
      lines: true,
    },
    setupFiles: ['tests/setup.ts'],
    globalSetup: ['tests/global-setup.ts'],
    reporters: ['verbose', 'json'],
    outputFile: {
      json: 'test-results/e2e.json',
    },
    watch: false,
    isolate: true,
    pool: 'threads',
    poolOptions: {
      threads: {
        singleThread: true,
        maxThreads: 1,
        minThreads: 1,
      },
    },
    maxConcurrency: 1,
    bail: 3, // E2E tests fail fast
  },
});
