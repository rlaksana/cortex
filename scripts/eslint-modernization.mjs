#!/usr/bin/env node

/**
 * ESLint Modernization Script
 *
 * Implements automated fixes for typescript-eslint v8 migration
 * and addresses common lint issues with modern best practices.
 */

import { execSync } from 'child_process';
import { readFileSync, writeFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, '..');

// Configuration for automated fixes
const FIX_CONFIG = {
  // Enable automatic fixes where safe
  autoFix: true,

  // Dry run mode (check what would be fixed)
  dryRun: process.argv.includes('--dry-run'),

  // Specific fix categories
  categories: {
    anyTypes: {
      enabled: true,
      rule: '@typescript-eslint/no-explicit-any',
      fixOptions: '--fix',
    },
    banTsComments: {
      enabled: true,
      rule: '@typescript-eslint/ban-ts-comment',
      fixOptions: '--fix',
    },
    unusedExpressions: {
      enabled: true,
      rule: '@typescript-eslint/no-unused-expressions',
      fixOptions: '--fix',
    },
    unsafeFunctionTypes: {
      enabled: true,
      rule: '@typescript-eslint/no-unsafe-function-type',
      fixOptions: '--fix',
    },
  },
};

/**
 * Run ESLint with specific rules and options
 */
function runEslint(rules, options = '') {
  const ruleString = Array.isArray(rules) ? rules.join(',') : rules;
  const cmd = `cd "${projectRoot}" && pnpm run lint --quiet --rule "${ruleString}" ${options}`;

  if (FIX_CONFIG.dryRun) {
    console.log(`[DRY RUN] Would run: ${cmd}`);
    return;
  }

  try {
    console.log(`Running: ${cmd}`);
    const result = execSync(cmd, {
      encoding: 'utf8',
      stdio: 'inherit',
      maxBuffer: 1024 * 1024 * 10, // 10MB buffer
    });
    return result;
  } catch (error) {
    console.error(`Error running ESLint: ${error.message}`);
    return null;
  }
}

/**
 * Analyze lint errors and provide recommendations
 */
function analyzeLintErrors() {
  console.log('🔍 Analyzing current lint errors...');

  try {
    // Get detailed error report
    const cmd = `cd "${projectRoot}" && pnpm run lint --format=json`;
    const result = execSync(cmd, {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024 * 10,
    });

    const lintResults = JSON.parse(result);
    const errorSummary = {};

    lintResults.forEach(file => {
      file.messages.forEach(message => {
        const rule = message.ruleId;
        errorSummary[rule] = (errorSummary[rule] || 0) + 1;
      });
    });

    console.log('\n📊 Error Summary:');
    Object.entries(errorSummary)
      .sort(([,a], [,b]) => b - a)
      .forEach(([rule, count]) => {
        console.log(`  ${rule}: ${count} occurrences`);
      });

    return errorSummary;
  } catch (error) {
    console.error('Error analyzing lint results:', error.message);
    return {};
  }
}

/**
 * Apply fixes in phases for safer migration
 */
async function applyPhasedFixes() {
  console.log('🚀 Starting ESLint modernization...\n');

  // Phase 1: Analyze current state
  const errorSummary = analyzeLintErrors();

  // Phase 2: Apply safe automated fixes
  console.log('\n🔧 Phase 2: Applying safe automated fixes...');

  if (FIX_CONFIG.categories.anyTypes.enabled) {
    console.log('  • Fixing any types with unknown conversion...');
    runEslint(FIX_CONFIG.categories.anyTypes.rule, FIX_CONFIG.categories.anyTypes.fixOptions);
  }

  if (FIX_CONFIG.categories.banTsComments.enabled) {
    console.log('  • Fixing ts-ignore comments...');
    runEslint(FIX_CONFIG.categories.banTsComments.rule, FIX_CONFIG.categories.banTsComments.fixOptions);
  }

  if (FIX_CONFIG.categories.unusedExpressions.enabled) {
    console.log('  • Fixing unused expressions...');
    runEslint(FIX_CONFIG.categories.unusedExpressions.rule, FIX_CONFIG.categories.unusedExpressions.fixOptions);
  }

  // Phase 3: Manual fix recommendations
  console.log('\n📝 Phase 3: Generating manual fix recommendations...');

  const remainingErrors = analyzeLintErrors();
  const manualFixes = [];

  Object.entries(remainingErrors).forEach(([rule, count]) => {
    const recommendation = getRecommendation(rule);
    if (recommendation) {
      manualFixes.push({ rule, count, ...recommendation });
    }
  });

  if (manualFixes.length > 0) {
    console.log('\n🛠️  Manual fixes needed:');
    manualFixes.forEach(({ rule, count, action, example }) => {
      console.log(`\n  ${rule} (${count} occurrences):`);
      console.log(`    Action: ${action}`);
      if (example) {
        console.log(`    Example: ${example}`);
      }
    });
  }

  console.log('\n✅ ESLint modernization completed!');
  console.log('\nNext steps:');
  console.log('1. Review and apply manual fixes');
  console.log('2. Run pnpm run lint:fix to catch remaining issues');
  console.log('3. Gradually tighten rules from warn to error');
}

/**
 * Get manual fix recommendations for specific rules
 */
function getRecommendation(rule) {
  const recommendations = {
    '@typescript-eslint/no-namespace': {
      action: 'Replace namespace with ES modules',
      example: 'namespace X { export const Y = 1; } → export const Y = 1;',
    },
    '@typescript-eslint/no-unsafe-function-type': {
      action: 'Replace Function with explicit function signature',
      example: 'Function → (...args: unknown[]) => unknown',
    },
    'import-x/no-unresolved': {
      action: 'Fix import paths or update tsconfig paths',
      example: "Update path mappings or fix file extensions",
    },
    'import-x/export': {
      action: 'Resolve duplicate exports',
      example: 'Rename or consolidate duplicate exports',
    },
  };

  return recommendations[rule] || null;
}

/**
 * Main execution
 */
async function main() {
  console.log('🔧 ESLint Modernization Script');
  console.log('=====================================\n');

  if (FIX_CONFIG.dryRun) {
    console.log('🔍 DRY RUN MODE - No changes will be made\n');
  }

  try {
    await applyPhasedFixes();
  } catch (error) {
    console.error('❌ Modernization failed:', error.message);
    process.exit(1);
  }
}

// Run the script
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}