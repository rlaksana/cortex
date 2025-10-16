#!/usr/bin/env node

/**
 * Fix remaining type safety issues with targeted patterns
 * Focuses on error handling, database transactions, and complex type assertions
 */

import fs from 'fs';
import { execSync } from 'child_process';

console.log('🔧 Fixing remaining type safety issues...');

// Key files that need targeted fixes
const priorityFiles = [
  'src/db/pool.ts',
  'src/db/migrate.ts',
  'src/services/memory-store.ts',
  'src/services/memory-find.ts',
  'src/utils/logger.ts'
];

let totalFixes = 0;

priorityFiles.forEach(filePath => {
  if (!fs.existsSync(filePath)) {
    console.log(`⚠️  File not found: ${filePath}`);
    return;
  }

  try {
    let content = fs.readFileSync(filePath, 'utf8');
    const originalContent = content;

    // Targeted fixes for error handling
    content = content.replace(/catch\s*\(\s*(\w+)\s*:\s*any\s*\)/g, 'catch ($1: unknown)');
    content = content.replace(/catch\s*\(\s*(\w+)\s*\)/g, 'catch ($1: unknown)');

    // Error type assertions
    content = content.replace(/(\w+)\.message/g, '($1 as Error).message');
    content = content.replace(/(\w+)\.stack/g, '($1 as Error).stack');

    // Database client types
    content = content.replace(/client:\s*any/g, 'client: PoolClient');
    content = content.replace(/transaction:\s*any/g, 'transaction: PoolClient');

    // Database query parameters
    content = content.replace(/params:\s*any\[\]/g, 'params: unknown[]');
    content = content.replace(/\[...\s*([^.]+?)\]/g, '[...($1 as unknown[])]');

    // Function return type assertions
    content = content.replace(/return\s+([^;]+);(?=\s*})/g, 'return $1 as $1;');

    if (content !== originalContent) {
      fs.writeFileSync(filePath, content);
      totalFixes++;
      console.log(`  ✅ Fixed: ${filePath}`);
    } else {
      console.log(`  ℹ️  No changes needed for ${filePath}`);
    }
  } catch (error) {
    console.error(`  ❌ Error processing ${filePath}:`, error.message);
  }
});

console.log(`\n🎉 Completed! Total files fixed: ${totalFixes}`);

// Verify progress
console.log('\n📊 Checking remaining issues...');
try {
  const lintOutput = execSync('npm run lint 2>&1', { encoding: 'utf8' });
  const typeSafetyIssues = lintOutput.split('\n').filter(line => line.includes('no-unsafe')).length;
  const promiseIssues = lintOutput.split('\n').filter(line => line.includes('no-floating-promises')).length;
  const explicitAnyIssues = lintOutput.split('\n').filter(line => line.includes('no-explicit-any')).length;
  const totalIssues = lintOutput.split('\n').filter(line => line.includes('error') || line.includes('warning')).length;

  console.log(`📈 Remaining issues:`);
  console.log(`   - Type safety: ${typeSafetyIssues}`);
  console.log(`   - Promise handling: ${promiseIssues}`);
  console.log(`   - Explicit any: ${explicitAnyIssues}`);
  console.log(`   - Total: ${totalIssues}`);
} catch (error) {
  console.error('❌ Could not check remaining issues:', error.message);
}