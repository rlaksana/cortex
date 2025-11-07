import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vitest-tsconfig-paths';

export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    globals: true,
    environment: 'node',
    include: [
      'tests/mcp-server/**/*.test.ts',
      'tests/integration/mcp-*.test.ts',
      'test-mcp-*.ts',
      'tests/unit/mcp-server/**/*.test.ts'
    ],
    exclude: [
      'node_modules',
      'dist',
      '**/*.e2e.test.ts'
    ],
    timeout: 30000,
    hookTimeout: 30000,
    testTimeout: 60000,
    // Setup files for MCP testing
    setupFiles: [
      './tests/setup/mcp-test-setup.ts'
    ],
    // Global test environment setup
    globalSetup: [
      './tests/setup/global-mcp-setup.ts'
    ],
    // Coverage configuration
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'dist/',
        'tests/',
        'test-*.ts',
        'test-*.js',
        'vitest.config.ts',
        '**/*.d.ts',
        '**/*.config.ts',
        '**/*.setup.ts'
      ],
      thresholds: {
        global: {
          branches: 80,
          functions: 80,
          lines: 80,
          statements: 80
        },
        // MCP-specific thresholds
        './src/index.ts': {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90
        }
      }
    },
    // Test reporters
    reporter: ['verbose', 'json', 'junit'],
    outputFile: {
      json: './artifacts/mcp-test-results.json',
      junit: './artifacts/mcp-test-results.xml'
    },
    // Retry failed tests (useful for integration tests)
    retry: 2,
    // Watch mode configuration
    watchExclude: [
      'node_modules',
      'dist',
      'artifacts'
    ]
  },
  // Resolve path aliases
  resolve: {
    alias: {
      '@': './src',
      '@/types': './src/types',
      '@/services': './src/services',
      '@/config': './src/config',
      '@/utils': './src/utils',
      '@/schemas': './src/schemas',
      '@/middleware': './src/middleware',
      '@/db': './src/db',
      '@docs': './docs',
      '@scripts': './scripts',
      '@tests': './tests'
    }
  }
});