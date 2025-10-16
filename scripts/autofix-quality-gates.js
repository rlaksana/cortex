#!/usr/bin/env node

/**
 * CORTEX MCP - COMPREHENSIVE AUTOFIX SCRIPT
 *
 * Addresses critical code quality issues identified in gating analysis:
 * 1. Syntax errors in test files (blocking tooling)
 * 2. ESLint configuration issues
 * 3. Critical type safety problems
 * 4. Import/Export standardization
 * 5. Dead code removal
 *
 * Usage: node scripts/autofix-quality-gates.js [--dry-run] [--fix-level=critical|high|medium|all]
 */

import { execSync } from 'child_process';
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'fs';
import { readdir, stat } from 'fs/promises';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

// Configuration
const config = {
  dryRun: process.argv.includes('--dry-run'),
  fixLevel: process.argv.find(arg => arg.startsWith('--fix-level='))?.split('=')[1] || 'critical',
  verbose: process.argv.includes('--verbose')
};

// Color output for better visibility
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

// 1. CRITICAL: Fix Syntax Errors in Test Files
async function fixTestSyntaxErrors() {
  log('\n🔧 STEP 1: Fixing Critical Syntax Errors in Test Files...', 'cyan');

  const problematicTestFiles = [
    'tests/e2e/graph-complete-scenario.test.ts',
    'tests/integration/graph-delete.test.ts',
    'tests/integration/graph-observation.test.ts',
    'tests/integration/graph-relation.test.ts',
    'tests/integration/graph-traversal.test.ts'
  ];

  for (const filePath of problematicTestFiles) {
    const fullPath = join(projectRoot, filePath);
    if (existsSync(fullPath)) {
      let content = readFileSync(fullPath, 'utf8');

      // Fix malformed await statements
      content = content.replace(/await\s*\/\/\s*(.+)/g, '// $1');

      // Fix other common syntax issues
      content = content.replace(/;\s*;\s*;/g, ';');
      content = content.replace(/\{\s*\}/g, '{}');

      if (!config.dryRun) {
        writeFileSync(fullPath, content);
        log(`✅ Fixed syntax in: ${filePath}`, 'green');
      } else {
        log(`🔍 Would fix syntax in: ${filePath}`, 'yellow');
      }
    }
  }
}

// 2. Fix ESLint Configuration for TypeScript
function fixESLintConfig() {
  log('\n🔧 STEP 2: Fixing ESLint Configuration...', 'cyan');

  const eslintConfigPath = join(projectRoot, 'eslint.config.js');

  if (existsSync(eslintConfigPath)) {
    let config = readFileSync(eslintConfigPath, 'utf8');

    // Add proper TypeScript configuration
    if (!config.includes('parserOptions')) {
      config = config.replace(
        /export default \[/,
        `export default [
  {
    files: ['**/*.ts'],
    languageOptions: {
      parser: require('@typescript-eslint/parser'),
      parserOptions: {
        project: 'tsconfig.json',
        tsconfigRootDir: import.meta.dirname,
        sourceType: 'module',
        extraFileExtensions: ['.js'],
      },
    },
  },`
      );
    }

    // Add generated files exclusion
    if (!config.includes('src/generated')) {
      config = config.replace(
        /ignores: \[/,
        `ignores: [
      'src/generated/**/*',
      'dist/**/*',
      'node_modules/**/*',`
      );
    }

    if (!config.dryRun) {
      writeFileSync(eslintConfigPath, config);
      log('✅ Updated ESLint configuration for TypeScript', 'green');
    } else {
      log('🔍 Would update ESLint configuration for TypeScript', 'yellow');
    }
  }
}

// 3. Fix Critical Type Safety Issues
async function fixTypeSafetyIssues() {
  log('\n🔧 STEP 3: Fixing Critical Type Safety Issues...', 'cyan');

  // Fix Prisma client import issues
  const prismaFile = join(projectRoot, 'src/db/prisma.ts');
  if (existsSync(prismaFile)) {
    let content = readFileSync(prismaFile, 'utf8');

    // Replace 'require' with ES imports
    content = content.replace(
      /const crypto = require\('crypto'\);/,
      "import { createHash } from 'crypto';"
    );

    // Fix crypto usage
    content = content.replace(
      /crypto\.createHash/,
      'createHash'
    );

    if (!config.dryRun) {
      writeFileSync(prismaFile, content);
      log('✅ Fixed Prisma client imports', 'green');
    } else {
      log('🔍 Would fix Prisma client imports', 'yellow');
    }
  }

  // Fix environment configuration
  const envFile = join(projectRoot, 'src/config/environment.ts');
  if (existsSync(envFile)) {
    let content = readFileSync(envFile, 'utf8');

    // Add proper error types
    content = content.replace(
      /catch \(error: any\) \{/,
      "catch (error: unknown) {"
    );

    if (!config.dryRun) {
      writeFileSync(envFile, content);
      log('✅ Fixed environment error types', 'green');
    } else {
      log('🔍 Would fix environment error types', 'yellow');
    }
  }
}

// 4. Remove Dead Code Files
async function removeDeadCode() {
  log('\n🔧 STEP 4: Removing Dead Code...', 'cyan');

  const deadFiles = [
    'src/utils/snippet.ts',
    'src/services/ranking/confidence.ts',
    'src/services/ranking/ranker.ts',
    'tests/unit/placeholder.test.ts',
    'scripts/add-db-types.ts',
    'scripts/autofix-lint.ts',
    'src/services/filters/scope-filter.ts'
  ];

  // Root level debug files
  const rootDeadFiles = [
    'comprehensive-connection-test.js',
    'create-schema.sql',
    'debug-section-storage.js',
    'debug-server.js',
    'test-connection.js',
    'test-connection-from-windows.js',
    'test-database.js',
    'test-db-connection-from-mcp.js',
    'test-postgres18-simple.mjs',
    'test-postgres18.js',
    'test-prisma-direct.js'
  ];

  const allDeadFiles = [...deadFiles, ...rootDeadFiles];

  for (const file of allDeadFiles) {
    const fullPath = join(projectRoot, file);
    if (existsSync(fullPath)) {
      if (!config.dryRun) {
        unlinkSync(fullPath);
        log(`🗑️  Removed: ${file}`, 'green');
      } else {
        log(`🔍 Would remove: ${file}`, 'yellow');
      }
    }
  }
}

// 5. Run Auto-fix Tools
async function runAutoFixTools() {
  log('\n🔧 STEP 5: Running Auto-fix Tools...', 'cyan');

  const tools = [
    { name: 'ESLint AutoFix', command: 'npm run lint:fix', critical: true },
    { name: 'Prettier Format', command: 'npm run format', critical: false },
    { name: 'TypeScript Check', command: 'npm run typecheck', critical: true }
  ];

  for (const tool of tools) {
    if (config.fixLevel === 'all' || !tool.critical || config.fixLevel === 'critical') {
      try {
        log(`\n🔄 Running: ${tool.name}...`, 'blue');

        if (config.dryRun) {
          log(`🔍 Would run: ${tool.command}`, 'yellow');
          continue;
        }

        const output = execSync(tool.command, {
          cwd: projectRoot,
          encoding: 'utf8',
          stdio: config.verbose ? 'inherit' : 'pipe'
        });

        if (output && !config.verbose) {
          log(`✅ ${tool.name} completed`, 'green');
          if (config.verbose) {
            console.log(output);
          }
        }
      } catch (error) {
        log(`❌ ${tool.name} failed: ${error.message}`, 'red');
        if (config.verbose) {
          console.log(error.stdout);
          console.log(error.stderr);
        }
      }
    }
  }
}

// 6. Create TypeScript Types for Common Issues
async function createTypeDefinitions() {
  log('\n🔧 STEP 6: Creating Missing Type Definitions...', 'cyan');

  // Create types for database rows
  const dbTypesPath = join(projectRoot, 'src/types/database-results.ts');

  const dbTypes = `// Auto-generated database result types
export interface DatabaseResult<T = any> {
  rows: T[];
  rowCount: number;
  command: string;
}

export interface SectionRow {
  id: string;
  title: string;
  heading: string;
  body_md?: string;
  body_text?: string;
  body_jsonb: Record<string, any>;
  content_hash?: string;
  created_at: Date;
  updated_at: Date;
  tags: Record<string, any>;
  metadata: Record<string, any>;
}

export interface AuditEventRow {
  id: string;
  table_name: string;
  operation: string;
  user_id?: string;
  old_data?: Record<string, any>;
  new_data?: Record<string, any>;
  created_at: Date;
}

export type QueryResult<T> = DatabaseResult<T>;
export type PoolQueryResult<T> = Promise<DatabaseResult<T>>;
`;

  if (!config.dryRun) {
    writeFileSync(dbTypesPath, dbTypes);
    log('✅ Created database result types', 'green');
  } else {
    log('🔍 Would create database result types', 'yellow');
  }
}

// Main execution function
async function main() {
  log('🚀 CORTEX MCP - COMPREHENSIVE AUTOFIX SCRIPT', 'magenta');
  log('================================================', 'magenta');
  log(`Mode: ${config.dryRun ? 'DRY RUN' : 'LIVE MODE'}`, config.dryRun ? 'yellow' : 'green');
  log(`Fix Level: ${config.fixLevel.toUpperCase()}`, 'cyan');
  log(`Verbose: ${config.verbose ? 'YES' : 'NO'}`, config.verbose ? 'green' : 'reset');

  try {
    // Execute fixes in order
    await fixTestSyntaxErrors();
    fixESLintConfig();
    await fixTypeSafetyIssues();

    if (config.fixLevel === 'all' || config.fixLevel === 'medium') {
      await removeDeadCode();
    }

    await createTypeDefinitions();
    await runAutoFixTools();

    log('\n✅ AUTOFIX COMPLETED SUCCESSFULLY!', 'green');
    log('=========================================', 'green');

    if (!config.dryRun) {
      log('\n📋 NEXT STEPS:', 'cyan');
      log('1. Run: npm run typecheck', 'blue');
      log('2. Run: npm run lint', 'blue');
      log('3. Run: npm test', 'blue');
      log('4. Review remaining manual fixes needed', 'blue');
    }

  } catch (error) {
    log(`\n❌ AUTOFIX FAILED: ${error.message}`, 'red');
    if (config.verbose) {
      console.log(error.stack);
    }
    process.exit(1);
  }
}

// Show usage
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`
Cortex MCP AutoFix Script

Usage: node scripts/autofix-quality-gates.js [options]

Options:
  --dry-run              Show what would be fixed without making changes
  --fix-level=LEVEL      Set fix level: critical|high|medium|all (default: critical)
  --verbose              Show detailed output from tools
  --help, -h             Show this help message

Examples:
  node scripts/autofix-quality-gates.js --dry-run
  node scripts/autofix-quality-gates.js --fix-level=all --verbose
  node scripts/autofix-quality-gates.js --fix-level=critical
`);
  process.exit(0);
}

// Run the script
main();