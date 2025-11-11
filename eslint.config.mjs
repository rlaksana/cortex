// @ts-check
import js from '@eslint/js';
import { defineConfig } from 'eslint/config';
import { configs } from 'typescript-eslint';
import { importX, createNodeResolver } from 'eslint-plugin-import-x';
import { createTypeScriptImportResolver } from 'eslint-import-resolver-typescript';
import simpleImportSort from 'eslint-plugin-simple-import-sort';
import unusedImports from 'eslint-plugin-unused-imports';

export default defineConfig(
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
      'bench/**/*',
      'html/**/*',
      'docs/**/*',
      'migrations/**/*',
      'docker/**/*',
      'ts-fix/**/*',
      'ts-fix/dist/**/*',
      '*.min.js',
      '*.bundle.js',
      'examples/**/*.ts',
      'vitest.config.ts',
      'src/chaos-testing/**/*',
    ],
    settings: {
      // Flat-config resolver API (caches, fast, TS paths aware)
      'import-x/resolver-next': [
        createTypeScriptImportResolver({
          // Adjust if you have multiple tsconfigs or monorepo:
          // project: ['tsconfig.json', 'packages/*/tsconfig.json'],
          // alwaysTryTypes: true,
        }),
        createNodeResolver(),
      ],
      // Optional: mark your internal packages as "internal" for grouping
      // 'import-x/internal-regex': '^@cortex/|^@app/|^@shared/',
    },
  },

  // TypeScript config for src files
  [...configs.recommended, importX.flatConfigs.recommended, importX.flatConfigs.typescript],
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: {
      parserOptions: {
        // disable typed rules to avoid TypeScript project parsing issues
        projectService: false,
        project: false,
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

      // Enforce file extensions for relative imports (.js in TS source)
      'import-x/extensions': ['error', 'always', { ignorePackages: true }],

      // Enforce architectural boundaries
      'import-x/no-relative-packages': 'error',

      // Note: no-restricted-imports rule disabled for now - requires ESLint v10 syntax
      // Will be re-enabled when project is upgraded to ESLint v10

      // Keep existing permissive rules from original config
      'no-console': 'off',
      'no-debugger': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      'prefer-const': 'off',
      '@typescript-eslint/no-unnecessary-type-assertion': 'off',
      '@typescript-eslint/no-require-imports': 'off',
      'no-case-declarations': 'off',
      '@typescript-eslint/no-namespace': 'off',
      'no-control-regex': 'off',
      'no-constant-binary-expression': 'off',
      'no-useless-escape': 'off',
      '@typescript-eslint/ban-ts-comment': 'off',
      '@typescript-eslint/no-unused-expressions': 'off',
      '@typescript-eslint/no-unsafe-function-type': 'off',
      '@typescript-eslint/no-wrapper-object-types': 'off',
      // Additional permissive rules for development/experimental code
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/require-await': 'off',
      '@typescript-eslint/no-misused-promises': 'off',
      'unused-imports/no-unused-vars': 'off',
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
    files: ['tests/**/*.ts', '**/*.test.ts', '**/*.spec.ts'],
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
      '@typescript-eslint/ban-ts-comment': 'off',
      '@typescript-eslint/no-unused-expressions': 'off',
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
      '@typescript-eslint/ban-ts-comment': 'off',
      '@typescript-eslint/no-unused-expressions': 'off',
      '@typescript-eslint/no-namespace': 'off',
      'no-useless-escape': 'off',
    },
  }
);
