import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/integration/**/*.test.ts'],
    exclude: ['tests/unit/**', 'tests/e2e/**', 'node_modules'],
    testTimeout: 60000, // Integration tests may take longer
    hookTimeout: 120000, // Allow time for database setup
  },
});
