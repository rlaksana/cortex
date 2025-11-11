/**
 * Development-focused ESLint Configuration
 *
 * This config is more permissive than security config, optimized for:
 * - Fast development iteration
 * - Productivity-focused rules
 * - Auto-fix friendly policies
 * - Integration with IDE and watch mode
 */

const js = require('@eslint/js');
const tseslint = require('typescript-eslint');

module.exports = [
  js.configs.recommended,
  ...tseslint.configs.recommended,

  // Global settings for all files
  {
    files: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.mjs'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
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
      // Permissive development rules (non-critical errors only)
      'no-console': 'off', // Allow console in development
      'no-debugger': 'warn', // Warn but don't error on debugger
      'no-unused-vars': 'warn', // Warn instead of error for unused vars
      '@typescript-eslint/no-unused-vars': 'warn',
      '@typescript-eslint/no-explicit-any': 'off', // Allow any for flexibility
      'prefer-const': 'warn', // Suggest const but allow let
      '@typescript-eslint/no-non-null-assertion': 'off', // Allow ! operator
      '@typescript-eslint/no-unnecessary-type-assertion': 'off', // Allow type assertions
      'no-case-declarations': 'off', // Allow declarations in case blocks
      'no-control-regex': 'off', // Allow control characters
      'no-constant-binary-expression': 'off', // Allow constant expressions
      '@typescript-eslint/ban-ts-comment': 'off', // Allow @ts-ignore
      '@typescript-eslint/no-unused-expressions': 'off', // Allow unused expressions
      '@typescript-eslint/no-unsafe-function-type': 'off', // Allow Function type
      '@typescript-eslint/no-wrapper-object-types': 'off', // Allow wrapper types

      // Productivity-friendly rules (auto-fixable)
      'semi': ['error', 'always', { omitLastInOneLineBlock: true }],
      'quotes': ['error', 'single', { avoidEscape: false }],
      'comma-dangle': ['error', 'always-multiline'],
      'object-curly-spacing': ['error', 'always'],
      'array-bracket-spacing': ['error', 'never'],
      'space-before-blocks': 'error',
      'keyword-spacing': 'error',
      'space-in-parens': 'error',
      'space-infix-ops': 'error',
      'eol-last': 'error',
      'no-trailing-spaces': 'error',

      // Prevent common mistakes but not too strict
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',
      'no-delete-var': 'error',

      // Performance and best practices (warnings)
      'no-var': 'warn',
      'eqeqeq': 'error', // Prefer ===
      'no-empty': 'warn',
      'no-multiple-empty-lines': ['warn', { max: 2 }],
    },
  },

  // TypeScript-specific rules
  {
    files: ['src/**/*.ts', 'src/**/*.tsx'],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: __dirname,
        ecmaVersion: 2022,
        sourceType: 'module',
      },
    },
    rules: {
      '@typescript-eslint/no-empty-interface': 'warn',
      '@typescript-eslint/no-empty-function': 'warn',
      '@typescript-eslint/prefer-optional-chain': 'error',
      '@typescript-eslint/prefer-nullish-coalescing': 'error',
      '@typescript-eslint/no-unnecessary-type-assertion': 'warn',
      '@typescript-eslint/prefer-string-starts-ends': 'warn',
    },
  },

  // Test files - very permissive
  {
    files: ['tests/**/*.ts', '**/*.test.ts', '**/*.spec.ts'],
    languageOptions: {
      globals: {
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
    rules: {
      'no-console': 'off',
      'no-debugger': 'off',
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      'no-empty': 'off',
      'no-magic-numbers': 'off',
    },
  },

  // Scripts - allow more flexibility
  {
    files: ['scripts/**/*.js', 'scripts/**/*.mjs'],
    rules: {
      'no-console': 'off',
      'no-process-exit': 'off',
      'no-empty': 'off',
      '@typescript-eslint/no-var-requires': 'off',
    },
  },

  // Config files - very permissive
  {
    files: ['*.config.js', '*.config.cjs', '*.config.ts'],
    rules: {
      'no-console': 'off',
      'no-process-exit': 'off',
      '@typescript-eslint/no-var-requires': 'off',
    },
  },

  // Ignore patterns
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'coverage/**',
      'test-output/**',
      'artifacts/**',
      'build/**',
      'temp/**',
      '.cache/**',
      '.nyc_output/**',
      '.vitest/**',
      'src/generated/**/*',
      '*.d.ts',
      '*.min.js',
      '*.bundle.js',
    ]
  }
];