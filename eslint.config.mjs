// @ts-check
import js from '@eslint/js';
import { defineConfig } from 'eslint/config';
import { configs } from 'typescript-eslint';
import { importX, createNodeResolver } from 'eslint-plugin-import-x';
import { createTypeScriptImportResolver } from 'eslint-import-resolver-typescript';
import simpleImportSort from 'eslint-plugin-simple-import-sort';
import unusedImports from 'eslint-plugin-unused-imports';

export default defineConfig([
  // Global ignores
  {
    ignores: [
      'src/chaos-testing/**/*', // Skip chaos-testing files with many any types
      'src/di/__tests__/**/*', // Skip broken typed-di-container tests
      'src/services/__tests__/**/*', // Skip problematic service tests
      'src/services/ai/__tests__/**/*', // Skip problematic AI integration tests
      'examples/**/*', // Skip example/demo files from strict linting
      'ts-fix/**/*', // Skip temporary TypeScript fix files
      'scripts/**/*', // Skip build/utility scripts from strict linting
      'complexity-report/**/*', // Skip generated complexity report files
      'coverage/**/*', // Skip coverage report files
      'dist/**/*', // Skip build output
      'node_modules/**/*', // Skip dependencies
      '.nyc_output/**/*', // Skip coverage output
      '*.log', // Skip log files
      'tests/**/*', // Skip test files from strict linting
      'test-*.js', // Skip root-level test files
      'test-*.ts', // Skip root-level test files
      'test-*.mjs', // Skip root-level test files
      'test-*.cjs', // Skip root-level test files
      'html/**/*', // Skip generated HTML files
      'eslint.*.config.*', // Skip ESLint config files from linting themselves
      'fix-*.js', // Skip fix scripts
      'fixed-*.ts', // Skip fixed temporary files
      'inspector-test-client.js', // Skip inspector test client
      'run-performance-security-tests.ts', // Skip performance test runner
      'security-test-suite.js', // Skip security test suite
      'simple-mcp-entry.js', // Skip simple MCP entry
    ]
  },

  // Base presets
  js.configs.recommended,

  // Project-level settings & ignores
  {
    ignores: [
      'dist/**',
      'build/**',
      'coverage/**',
      '**/*.d.ts',
      'node_modules/**/*',
      'temp/**/*',
      '.tmp/**/*',
      '.cache/**/*',
      '.nyc_output/**/*',
      '.vitest/**/*',
      '.github/**/*',
      '.husky/**/*',
      '.claude/**/*',
      '.serena/**/*',
      'artifacts/**/*',
      'scripts/**/*',
      'scripts/legacy/**/*',
      'bench/**/*',
      'html/**/*',
      'docs/**/*',
      'migrations/**/*',
      'docker/**/*',
      'ts-fix/**/*',
      'ts-fix/dist/**/*',
      '*.min.js',
      '*.bundle.js',
      '*.log',
      '*.pid',
      '*.swp',
      '*.orig',
      '.vscode/**/*',
      '.git/**/*',
      'examples/**/*.ts',
      'vitest.config.ts',
      '**/*.bak',
      '**/*.test.ts',
      '**/*.spec.ts',
      'src/**/__tests__/**/*',
      'src/test/**/*',
    ],
    settings: {
      // Flat-config resolver API (caches, fast, TS paths aware)
      'import-x/resolver-next': [
        createTypeScriptImportResolver({
          // Adjust if you have multiple tsconfigs or monorepo:
          project: ['tsconfig.base.json'],
          alwaysTryTypes: true,
        }),
        createNodeResolver({
          extensions: ['.ts', '.tsx', '.js']
        }),
      ],
      // Optional: mark your internal packages as "internal" for grouping
      // 'import-x/internal-regex': '^@cortex/|^@app/|^@shared/',
    },
  },

  // TypeScript config for src files (excluding test files)
  [...configs.recommended, importX.flatConfigs.recommended, importX.flatConfigs.typescript],
  {
    files: ['src/**/*.{ts,tsx}'],
    ignores: [
      'src/**/__tests__/**/*',
      'src/test/**/*',
      'src/**/*.test.ts',
      'src/**/*.spec.ts',
    ],
    languageOptions: {
      parserOptions: {
        // Enable typed linting with projectService for better performance
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
      globals: {
        // Node.js globals
        console: 'readonly',
        process: 'readonly',
        Buffer: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        global: 'readonly',
        module: 'readonly',
        require: 'readonly',
        exports: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        NodeJS: 'readonly',
        fetch: 'readonly',
        URL: 'readonly',
        AbortSignal: 'readonly',
        TextEncoder: 'readonly',
        TextDecoder: 'readonly',
        URLSearchParams: 'readonly',
        crypto: 'readonly',
        // Test globals
        describe: 'readonly',
        it: 'readonly',
        test: 'readonly',
        expect: 'readonly',
        beforeAll: 'readonly',
        afterAll: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
        vi: 'readonly',
        jest: 'readonly',
      },
    },
    plugins: {
      'simple-import-sort': simpleImportSort,
      'unused-imports': unusedImports,
    },
    rules: {

      // Use inline type-only imports consistently
      '@typescript-eslint/consistent-type-imports': [
        'warn',
        { prefer: 'type-imports', fixStyle: 'inline-type-imports' },
      ],

      // Import sorting with groups for better organization
      'simple-import-sort/imports': [
        'warn',
        {
          groups: [
            // Node.js builtins
            ['^node:', '^fs', '^path', '^url', '^process', '^os', '^crypto'],
            // External packages
            ['^@?\\w'],
            // Internal aliases (project-specific)
            [
              '^@/*',
              '^@types/*',
              '^@services/*',
              '^@config/*',
              '^@utils/*',
              '^@schemas/*',
              '^@middleware/*',
              '^@db/*',
              '^@monitoring/*',
            ],
            // Relative imports
            ['^\\.', '^\\.\\.'],
          ],
        },
      ],
      'simple-import-sort/exports': 'warn',

      // Import extensions already correct (.js for ESM compatibility in TS source)
      'import-x/extensions': 'off',

      // Enforce architectural boundaries
      'import-x/no-relative-packages': 'error',

      // Note: no-restricted-imports rule disabled for now - requires ESLint v10 syntax
      // Will be re-enabled when project is upgraded to ESLint v10

      // Keep existing permissive rules from original config
      'no-console': 'off',
      'no-debugger': 'off',
      'prefer-const': 'off',

      // Modern ts-eslint v8 best practices
      '@typescript-eslint/ban-ts-comment': [
        'warn',
        {
          'ts-expect-error': 'allow-with-description',
          'ts-ignore': 'allow-with-description',
          'ts-nocheck': 'allow-with-description',
        },
      ],
      '@typescript-eslint/no-unused-expressions': [
        'warn',
        {
          allowShortCircuit: true,
          allowTernary: true,
          allowTaggedTemplates: true,
        },
      ],
      '@typescript-eslint/no-unnecessary-type-assertion': 'off',
      '@typescript-eslint/no-require-imports': 'off',
      'no-case-declarations': 'off',
      '@typescript-eslint/no-namespace': 'off',
      'no-control-regex': 'off',
      'no-constant-binary-expression': 'off',
      'no-useless-escape': 'off',
      '@typescript-eslint/no-unsafe-function-type': 'off',
      '@typescript-eslint/no-wrapper-object-types': 'off',
      // Production-ready TypeScript strict checking
      '@typescript-eslint/no-unsafe-assignment': 'warn',
      '@typescript-eslint/no-unsafe-member-access': 'warn',
      '@typescript-eslint/no-unsafe-call': 'warn',
      '@typescript-eslint/no-unsafe-argument': 'warn',
      '@typescript-eslint/no-unsafe-return': 'warn',
      '@typescript-eslint/require-await': 'error',
      '@typescript-eslint/no-misused-promises': 'warn',
      // Enable unused imports detection with auto-fix
      'unused-imports/no-unused-imports': 'warn',
      'unused-imports/no-unused-vars': [
        'warn',
        {
          'vars': 'all',
          'varsIgnorePattern': '^_',
          'args': 'after-used',
          'argsIgnorePattern': '^_',
        },
      ],
      // Enable unreachable code detection
      'no-unreachable': 'warn',
      'no-constant-condition': [
        'warn',
        {
          'checkLoops': false,
        },
      ],
    },
  },

  // JS files (kept minimal from original config)
  {
    files: ['**/*.js', '**/*.mjs', '**/*.cjs'],
    languageOptions: {
      globals: {
        // Node.js globals
        console: 'readonly',
        process: 'readonly',
        Buffer: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        global: 'readonly',
        module: 'readonly',
        require: 'readonly',
        exports: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        NodeJS: 'readonly',
        fetch: 'readonly',
        URL: 'readonly',
        AbortSignal: 'readonly',
        TextEncoder: 'readonly',
        TextDecoder: 'readonly',
        URLSearchParams: 'readonly',
        crypto: 'readonly',
      },
    },
    rules: {
      'no-console': 'off',
      'no-debugger': 'error',
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',
      'no-with': 'error',
      'no-delete-var': 'error',
      'no-unused-vars': 'off',
      'no-undef': 'off',
      'no-useless-escape': 'off',
    },
  },

  // TypeScript config for test files (non-typed)
  [...configs.recommended, importX.flatConfigs.recommended, importX.flatConfigs.typescript],
  {
    files: [
      'tests/**/*.ts',
      '**/*.test.ts',
      '**/*.spec.ts',
      'src/**/__tests__/**/*.ts',
      'src/test/**/*.ts',
    ],
    languageOptions: {
      parserOptions: {
        project: false, // Disable project parsing for test files
      },
      globals: {
        // Test globals
        describe: 'readonly',
        it: 'readonly',
        test: 'readonly',
        expect: 'readonly',
        beforeAll: 'readonly',
        afterAll: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
        vi: 'readonly',
        jest: 'readonly',
        // Node.js globals
        console: 'readonly',
        process: 'readonly',
        Buffer: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        global: 'readonly',
        module: 'readonly',
        require: 'readonly',
        exports: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        NodeJS: 'readonly',
        fetch: 'readonly',
        URL: 'readonly',
        AbortSignal: 'readonly',
        TextEncoder: 'readonly',
        TextDecoder: 'readonly',
        URLSearchParams: 'readonly',
        crypto: 'readonly',
      },
    },
    rules: {
      // Very permissive for test files
      'no-console': 'off',
      'no-debugger': 'off',
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unnecessary-type-assertion': 'off',
      'prefer-const': 'off',
      '@typescript-eslint/no-require-imports': 'off',
      '@typescript-eslint/no-wrapper-object-types': 'off',
      '@typescript-eslint/no-namespace': 'off',
      'no-useless-escape': 'off',
    },
  },

  // TypeScript config for bench files (non-typed)
  [...configs.recommended, importX.flatConfigs.recommended, importX.flatConfigs.typescript],
  {
    files: ['bench/**/*.{ts,js}'],
    languageOptions: {
      parserOptions: {
        project: false, // Disable project parsing for bench files
      },
      globals: {
        // Node.js globals
        console: 'readonly',
        process: 'readonly',
        Buffer: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        global: 'readonly',
        module: 'readonly',
        require: 'readonly',
        exports: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        NodeJS: 'readonly',
        fetch: 'readonly',
        URL: 'readonly',
        AbortSignal: 'readonly',
        TextEncoder: 'readonly',
        TextDecoder: 'readonly',
        URLSearchParams: 'readonly',
        crypto: 'readonly',
      },
    },
    rules: {
      // Permissive rules for benchmark files
      'no-console': 'off',
      'no-debugger': 'off',
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unnecessary-type-assertion': 'off',
      'prefer-const': 'off',
      '@typescript-eslint/no-require-imports': 'off',
      '@typescript-eslint/no-wrapper-object-types': 'off',
      '@typescript-eslint/no-namespace': 'off',
      'no-useless-escape': 'off',
    },
  },

  // Final override for specific TypeScript rules (ensure these are applied last)
  {
    files: ['src/**/*.{ts,tsx}'],
    rules: {
      '@typescript-eslint/no-unused-vars': 'off',
      '@typescript-eslint/no-explicit-any': [
        'warn',
        {
          fixToUnknown: true,
          ignoreRestArgs: true,
        },
      ],
    }
  }
]);
