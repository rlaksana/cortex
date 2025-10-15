import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/e2e/**/*.test.ts'],
    exclude: ['tests/unit/**', 'tests/integration/**', 'node_modules'],
    testTimeout: 60000, // E2E tests can be slow
    hookTimeout: 120000, // Allow time for full server startup
  },
});
