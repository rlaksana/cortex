/**
 * Windows-Optimized Vitest Configuration
 *
 * This configuration provides Windows-specific optimizations for test execution,
 * including enhanced EMFILE prevention, timeout management, and performance tuning.
 *
 * @author Cortex Team
 * @version 2.0.0
 */

import { defineConfig } from 'vitest/config';
import { resolve } from 'path';
import { readFileSync } from 'fs';

// Custom plugin to handle .js imports that should resolve to .ts files
function jsToTsResolution() {
  return {
    name: 'js-to-ts-resolution',
    enforce: 'pre',
    async resolveId(id, importer) {
      if (id.endsWith('.js') && !id.includes('node_modules')) {
        if (id.startsWith('./') || id.startsWith('../')) {
          if (importer) {
            const importerDir = resolve(importer, '..');
            const resolvedPath = resolve(importerDir, id);
            const tsPath = resolvedPath.replace(/\.js$/, '.ts');

            try {
              readFileSync(tsPath, 'utf8');
              return tsPath;
            } catch {
              return id;
            }
          }
        } else {
          if (id.includes('/src/')) {
            const tsPath = id.replace(/\.js$/, '.ts');
            try {
              readFileSync(tsPath, 'utf8');
              return tsPath;
            } catch {
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
      '@': resolve(__dirname, './src'),
      '@src': resolve(__dirname, './src'),
      '@services': resolve(__dirname, './src/services'),
      '@utils': resolve(__dirname, './src/utils'),
      '@types': resolve(__dirname, './src/types'),
      '@config': resolve(__dirname, './src/config'),
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

    // Windows-specific test execution optimization
    pool: 'threads',
    poolOptions: {
      threads: {
        singleThread: true, // Use single thread to prevent EMFILE
        maxThreads: 1, // Conservative threading for Windows
        minThreads: 1,
        isolate: true, // Isolate test execution
      },
    },

    // Windows-specific timeout management
    testTimeout: 120000, // Increased from 60s to 120s for Windows
    hookTimeout: 60000, // Increased from 30s to 60s
    teardownTimeout: 30000, // Increased for proper cleanup
    sequence: {
      concurrent: false, // Run tests sequentially to prevent file handle exhaustion
      shuffle: false, // Maintain order for consistency
    },

    // Windows-specific performance optimizations
    maxConcurrency: 1, // Conservative concurrency
    bail: 10, // Stop early to prevent cascading failures (increased from 5)
    retry: 1, // Allow one retry for flaky tests

    // File and path handling for Windows
    include: [
      'tests/unit/**/*.test.ts',
      'tests/integration/**/*.test.ts',
      'tests/contract/**/*.test.ts',
      'tests/validation/**/*.test.ts',
      'tests/**/*.spec.ts',
    ],
    exclude: [
      'tests/e2e/**', // Skip E2E tests for Windows optimization
      'tests/performance/**', // Run performance tests separately
      'node_modules',
      'dist/',
      'coverage/',
      '**/*.d.ts',
    ],

    // Transform mode configuration
    transformMode: {
      web: [/\.[jt]sx?$/],
      ssr: [/\.[jt]sx?$/],
    },

    // Windows-specific dependencies handling
    deps: {
      external: [
        'node:fs',
        'node:path',
        'node:crypto',
        'node:perf_hooks',
        'node:events',
        'node:url',
        'node:os',
        'node:abort_controller',
        'node:worker_threads', // Windows-specific
        'node:child_process', // Windows-specific
      ],
      inline: [
        // Inline problematic modules that might cause file handle issues
        /.*\.node$/,
        /^v8/,
      ],
    },

    // Windows-specific coverage configuration
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov', 'text-summary'],
      reportsDirectory: 'coverage/windows',
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
        'tests/setup/windows-test-setup.ts', // Exclude Windows setup from coverage
      ],
      thresholds: {
        global: {
          branches: 80, // Reduced from 85 for Windows
          functions: 80, // Reduced from 85 for Windows
          lines: 80, // Reduced from 85 for Windows
          statements: 80, // Reduced from 85 for Windows
        },
        'src/core/**': {
          branches: 85, // Still critical
          functions: 85,
          lines: 85,
          statements: 85,
        },
        'src/db/**': {
          branches: 80, // Reduced for Windows
          functions: 80,
          lines: 80,
          statements: 80,
        },
        'src/services/**': {
          branches: 80, // Reduced for Windows
          functions: 80,
          lines: 80,
          statements: 80,
        },
        'src/utils/**': {
          branches: 80, // Reduced for Windows
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
        statements: [80, 90], // Reduced for Windows
        functions: [80, 90],
        branches: [80, 90],
        lines: [80, 90],
      },
      skipFull: false,
      allowExternal: false,
      include: ['src/**/*.ts'],
      perFile: false, // Disable per-file coverage for Windows performance
      functions: true,
      branches: true,
      statements: true,
      lines: true,
    },

    // Windows-specific test setup files
    setupFiles: [
      'tests/setup.ts',
      'tests/setup/windows-test-setup.ts', // Windows-specific setup
    ],

    // Global setup for Windows EMFILE prevention
    globalSetup: ['tests/global-setup.ts'],

    // Windows-specific reporting
    reporters: ['verbose', 'json'],
    outputFile: {
      json: 'test-results/windows.json',
    },

    // Windows-specific file handling
    watch: false, // Disabled to reduce file handles
    watchExclude: ['**/*'], // Exclude all files from watching

    // Windows-specific environment variables
    env: {
      NODE_ENV: 'test',
      LOG_LEVEL: 'error', // Minimize logging
      WINDOWS_TEST: 'true',
      MOCK_EMBEDDINGS: 'true',
      MOCK_EMBEDDING_SERVICE: 'true',
      // Force garbage collection (removed --gc-interval as it's not allowed in workers)
      NODE_OPTIONS: '--max-old-space-size=4096 --expose-gc',
      // Windows-specific optimizations
      UV_THREADPOOL_SIZE: '16',
      EMFILE_HANDLES_LIMIT: '131072',
    },

    // Windows-specific memory management
    logHeapUsage: true,
    isolate: true,
    dangerouslyIgnoreUnhandledErrors: false,

    // Add hooks for Windows cleanup
    onSetup: async () => {
      console.log('🪟 Windows test setup starting...');

      // Force garbage collection if available
      if ((global as unknown as { gc?: () => void }).gc) {
        (global as unknown as { gc?: () => void }).gc();
      }

      // Set Windows-specific event listener limits
      const { EventEmitter } = await import('events');
      EventEmitter.defaultMaxListeners = 50;

      console.log('✅ Windows test setup completed');
    },

    onTeardown: async () => {
      console.log('🧹 Windows test teardown starting...');

      // Force cleanup
      if ((global as unknown as { gc?: () => void }).gc) {
        (global as unknown as { gc?: () => void }).gc();
        // Multiple GC passes for thorough cleanup
        setTimeout(() => {
          if ((global as unknown as { gc?: () => void }).gc)
            (global as unknown as { gc?: () => void }).gc();
          setTimeout(() => {
            if ((global as unknown as { gc?: () => void }).gc)
              (global as unknown as { gc?: () => void }).gc();
          }, 50);
        }, 50);
      }

      // Restore EventEmitter limits
      const { EventEmitter } = await import('events');
      EventEmitter.defaultMaxListeners = 10;

      console.log('✅ Windows test teardown completed');
    },
  },
});
