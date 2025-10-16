import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/integration/**/*.test.ts'],
    exclude: ['tests/unit/**', 'tests/e2e/**', 'node_modules'],
    testTimeout: 30000, // Integration tests may take longer
    hookTimeout: 60000, // Allow time for Testcontainers startup
  },
});
