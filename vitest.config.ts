import { defineConfig } from 'vitest/config';
import { resolve } from 'path';
import { readFileSync } from 'fs';

// Custom plugin to handle .js imports that should resolve to .ts files
function jsToTsResolution() {
  return {
    name: 'js-to-ts-resolution',
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
            } catch (e) {
              // .ts file doesn't exist, return original
              return id;
            }
          }
        }
      }
      return null;
    }
  };
}

export default defineConfig({
  plugins: [jsToTsResolution()],
  resolve: {
    alias: {
      // Handle .js imports to resolve to .ts source files
      '@': resolve(__dirname, './src'),
    },
    extensions: ['.ts', '.tsx', '.js', '.jsx', '.json']
  },
  esbuild: {
    target: 'node18',
    format: 'esm'
  },
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
    transformMode: {
      web: [/\.[jt]sx?$/],
      ssr: [/\.[jt]sx?$/]
    },
    deps: {
      inline: [
        // Inline dependencies that might cause issues
        /vitest/,
        /@vitest/,
        /tsx/
      ]
    },
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
    testTimeout: 30000,
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