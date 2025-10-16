import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/unit/**/*.test.ts', 'tests/contract/**/*.test.ts', 'tests/validation/**/*.test.ts'],
    exclude: ['tests/integration/**', 'tests/e2e/**', 'node_modules'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: ['tests/', 'dist/', 'node_modules/'],
    },
    testTimeout: 10000,
  },
});
