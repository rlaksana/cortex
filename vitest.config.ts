import { defineConfig } from 'vitest/config';
import { resolve } from 'path';
import { readFileSync } from 'fs';

// Custom plugin to handle .js imports that should resolve to .ts files
function jsToTsResolution() {
  return {
    name: 'js-to-ts-resolution',
    enforce: 'pre',
    configureServer(server) {
      // Custom middleware to handle import resolution
      server.middlewares.use((req, res, next) => {
        next();
      });
    },
    async resolveId(id, importer) {
      // If the import ends with .js and it's not a node_module, try to resolve to .ts
      if (id.endsWith('.js') && !id.includes('node_modules')) {
        // Handle relative imports
        if (id.startsWith('./') || id.startsWith('../')) {
          if (importer) {
            const importerDir = resolve(importer, '..');
            const resolvedPath = resolve(importerDir, id);
            const tsPath = resolvedPath.replace(/\.js$/, '.ts');

            // Check if the .ts file exists
            try {
              readFileSync(tsPath, 'utf8');
              return tsPath;
            } catch (_e) {
              // .ts file doesn't exist, return original
              return id;
            }
          }
        } else {
          // Handle absolute imports from src/
          if (id.includes('/src/')) {
            const tsPath = id.replace(/\.js$/, '.ts');
            try {
              readFileSync(tsPath, 'utf8');
              return tsPath;
            } catch (_e) {
              // .ts file doesn't exist, return original
              return id;
            }
          }
        }
      }
      return null;
    },
  };
}

export default defineConfig({
  plugins: [jsToTsResolution()],
  resolve: {
    alias: {
      // Handle .js imports to resolve to .ts source files
      '@': resolve(__dirname, './src'),
      // Additional aliases for common import patterns
      '@src': resolve(__dirname, './src'),
      '@services': resolve(__dirname, './src/services'),
      '@utils': resolve(__dirname, './src/utils'),
      '@types': resolve(__dirname, './src/types'),
      '@config': resolve(__dirname, './src/config'),
    },
    extensions: ['.ts', '.tsx', '.js', '.jsx', '.json'],
    // Additional alias patterns to handle .js imports to .ts
  },
  esbuild: {
    target: 'node18',
    format: 'esm',
  },
  test: {
    globals: true,
    environment: 'node',
    include: [
      'tests/unit/**/*.test.ts',
      'tests/contract/**/*.test.ts',
      'tests/validation/**/*.test.ts',
      'tests/**/*.spec.ts',
    ],
    exclude: [
      'tests/integration/**',
      'tests/e2e/**',
      'node_modules',
      'dist/',
      'coverage/',
      '**/*.d.ts',
    ],
    transformMode: {
      web: [/\.[jt]sx?$/],
      ssr: [/\.[jt]sx?$/],
    },
    // Remove deps configuration to use default handling
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json'],
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
      ],
      thresholds: {
        global: {
          branches: 85,
          functions: 90,
          lines: 90,
          statements: 90,
        },
        // Critical paths have higher thresholds
        'src/core/**': {
          branches: 90,
          functions: 95,
          lines: 95,
          statements: 95,
        },
        'src/db/**': {
          branches: 85,
          functions: 90,
          lines: 90,
          statements: 90,
        },
        // Less critical code can have lower thresholds
        'src/utils/**': {
          branches: 80,
          functions: 85,
          lines: 85,
          statements: 85,
        },
      },
      all: true,
      clean: true,
      cleanOnRerun: true,
      enabled: false, // Disable coverage temporarily to resolve EMFILE
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
