#!/usr/bin/env node

/**
 * Final comprehensive syntax error fix
 * Targets all remaining parsing errors systematically
 */

import fs from 'fs';
import { execSync } from 'child_process';

console.log('🔧 Final syntax error cleanup...');

// Get all TypeScript files
const output = execSync('find src -name "*.ts" -type f', { encoding: 'utf8' });
const allTsFiles = output.trim().split('\n').filter(Boolean);

let totalFixes = 0;

allTsFiles.forEach(filePath => {
  if (!fs.existsSync(filePath)) {
    return;
  }

  try {
    let content = fs.readFileSync(filePath, 'utf8');
    const originalContent = content;

    // Fix pattern: result.(rows[0] as Record<string, unknown>).property
    content = content.replace(/(\w+)\.?\(rows\[0\]\s+as\s+Record<string,\s*unknown>\)\.?(\w+)/g, '$1.rows[0] as Record<string, unknown>.$2');

    // Fix pattern: existing.(rows[0] as Record<string, unknown>).property
    content = content.replace(/existing\.?\(rows\[0\]\s+as\s+Record<string,\s*unknown>\)\.?(\w+)/g, 'existing.rows[0] as Record<string, unknown>.$2');

    // Fix pattern: totalResult.(rows[0] as Record<string, unknown>).property
    content = content.replace(/(\w+Result)\.?\(rows\[0\]\s+as\s+Record<string,\s*unknown>\)\.?(\w+)/g, '$1.rows[0] as Record<string, unknown>.$2');

    // Fix pattern: result.rows[0] as Record<string, unknown>.property (missing parentheses)
    content = content.replace(/(\w+)\.rows\[0\]\s+as\s+Record<string,\s*unknown>\.(\w+)/g, '($1.rows[0] as Record<string, unknown>).$2');

    // Fix broken array/object access patterns
    content = content.replace(/as\s+Record<string,\s*unknown>\[\s*\]/g, 'as Record<string, unknown>[]');
    content = content.replace(/as\s+unknown\[\s*\]/g, 'as unknown[]');

    // Fix broken generic syntax
    content = content.replace(/<\[\.\.\.([^]]*)\]>/g, '<$1>');
    content = content.replace(/<\s+as\s+unknown\[\s*>/g, '<>');

    // Fix broken type assertions in function calls
    content = content.replace(/\(\s*([^)]+)\s+as\s+unknown\[\s*\]\s*\)/g, '($1 as unknown[])');

    if (content !== originalContent) {
      fs.writeFileSync(filePath, content);
      totalFixes++;
      console.log(`  ✅ Fixed: ${filePath}`);
    }
  } catch (error) {
    console.error(`  ❌ Error processing ${filePath}:`, error.message);
  }
});

console.log(`\n🎉 Completed! Total files fixed: ${totalFixes}`);

// Check progress
console.log('\n📊 Checking progress...');
try {
  const lintOutput = execSync('npm run lint 2>&1', { encoding: 'utf8' });
  const parsingErrors = lintOutput.split('\n').filter(line => line.includes('Parsing error')).length;
  const totalIssues = lintOutput.split('\n').filter(line => line.includes('error') || line.includes('warning')).length;

  console.log(`📈 Status update:`);
  console.log(`   - Parsing errors: ${parsingErrors}`);
  console.log(`   - Total issues: ${totalIssues}`);

  if (totalIssues < 50) {
    console.log(`\n🔥 Excellent! Under 50 issues remaining!`);
  }
} catch (error) {
  console.error('❌ Could not check status:', error.message);
}