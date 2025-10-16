#!/usr/bin/env node

/**
 * Systematic elimination of 'any' types in source code
 *
 * This script replaces the most common 'any' types with proper TypeScript types
 */

import fs from 'fs';

console.log('🔧 Eliminating "any" types in source code...\n');

// Define proper type replacements
const TYPE_REPLACEMENTS = {
  // Database connection types
  'pool: any,': 'pool: import("pg").PoolClient,',
  'client: any,': 'client: import("pg").PoolClient,',

  // Database parameters and query results
  'params?: any[]': 'params?: unknown[]',
  'const params: any[]': 'const params: unknown[]',

  // Error handling
  'error: any)': 'error: unknown)',
  'error: any': 'error: unknown',

  // Migration data
  'oldData?: any': 'oldData?: Record<string, unknown>',
  'newData?: any': 'newData?: Record<string, unknown>',

  // Data processing
  'data: any': 'data: Record<string, unknown>',
  'updateData: any': 'updateData: Record<string, unknown>',

  // Scope and filter types
  'Record<string, string>': 'Scope', // Use existing Scope interface
  'hitScope: any': 'hitScope: Scope',
  'queryScope: any': 'queryScope: Scope',

  // Graph traversal
  'edge: any)': 'edge: Record<string, unknown>)',

  // Validation functions
  'item: any': 'item: Record<string, unknown>',
};

// Function to fix a specific file
function fixFileTypes(filePath, replacements) {
  console.log(`📝 Processing: ${filePath}`);

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    let fixed = content;

    // Apply all replacements
    Object.entries(replacements).forEach(([oldType, newType]) => {
      fixed = fixed.replace(new RegExp(oldType.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), newType);
    });

    if (fixed !== content) {
      fs.writeFileSync(filePath, fixed);
      console.log(`  ✅ Fixed type issues in ${filePath}`);
    } else {
      console.log(`  ℹ️  No type changes needed for ${filePath}`);
    }
  } catch (error) {
    console.error(`  ❌ Error processing ${filePath}:`, error.message);
  }
}

// Special fixes for specific files
function fixAuditTypes(content) {
  let fixed = content;

  // Fix filterSensitiveData method
  fixed = fixed.replace(
    /private filterSensitiveData\(tableName: string, data: any\): any {/,
    'private filterSensitiveData(tableName: string, data: Record<string, unknown>): Record<string, unknown> {'
  );

  // Fix arrayToObject method
  fixed = fixed.replace(
    /private arrayToObject\(rows: any\[\], key: string, value: string\): Record<string, number> {/,
    'private arrayToObject(rows: Record<string, unknown>[], key: string, value: string): Record<string, number> {'
  );

  return fixed;
}

function fixPoolTypes(content) {
  let fixed = content;

  // Fix query method parameters
  fixed = fixed.replace(
    /async query\(text: string, params\?\: any\[\]\): Promise<QueryResult> {/,
    'async query(text: string, params?: unknown[]): Promise<QueryResult> {'
  );

  // Fix isConnectionError method
  fixed = fixed.replace(
    /private isConnectionError\(error: any\): boolean {/,
    'private isConnectionError(error: unknown): boolean {'
  );

  return fixed;
}

function fixValidationTypes(content) {
  let fixed = content;

  // Fix validation functions
  fixed = fixed.replace(
    /function generateContentHash\(item: any\): string {/,
    'function generateContentHash(item: Record<string, unknown>): string {'
  );

  fixed = fixed.replace(
    /function getValidationWarnings\(item: any\): string\[\] {/,
    'function getValidationWarnings(item: Record<string, unknown>): string[] {'
  );

  return fixed;
}

// Process each critical file
console.log('🔧 Fixing audit.ts...');
const auditContent = fs.readFileSync('src/db/audit.ts', 'utf-8');
const fixedAudit = fixAuditTypes(auditContent);
fs.writeFileSync('src/db/audit.ts', fixedAudit);
console.log('  ✅ Fixed audit.ts type issues');

console.log('\n🔧 Fixing pool.ts...');
const poolContent = fs.readFileSync('src/db/pool.ts', 'utf-8');
const fixedPool = fixPoolTypes(poolContent);
fs.writeFileSync('src/db/pool.ts', fixedPool);
console.log('  ✅ Fixed pool.ts type issues');

console.log('\n🔧 Fixing enhanced-validation.ts...');
const validationContent = fs.readFileSync('src/schemas/enhanced-validation.ts', 'utf-8');
const fixedValidation = fixValidationTypes(validationContent);
fs.writeFileSync('src/schemas/enhanced-validation.ts', fixedValidation);
console.log('  ✅ Fixed enhanced-validation.ts type issues');

// Apply general replacements to remaining files
const filesToFix = [
  'src/db/prisma.ts',
  'src/db/migrate.ts',
  'src/services/filters/scope-filter.ts',
  'src/services/graph-traversal.ts',
  'src/services/knowledge/runbook.ts'
];

console.log('\n🔧 Applying general type fixes...');
filesToFix.forEach(file => {
  if (fs.existsSync(file)) {
    fixFileTypes(file, TYPE_REPLACEMENTS);
  } else {
    console.log(`⚠️  File not found: ${file}`);
  }
});

console.log('\n🎯 "Any" type elimination completed!');
console.log('💡 Next steps:');
console.log('   1. Run `npm run build` to check for remaining type issues');
console.log('   2. Run `npm run lint` to check code quality');
console.log('   3. Test functionality to ensure types are correct');