#!/usr/bin/env node

/**
 * Fix the specific pattern: rows[0] as Record<string, unknown>.property
 * Should be: (rows[0] as Record<string, unknown>).property
 */

import fs from 'fs';
import { execSync } from 'child_process';

console.log('🔧 Fixing type assertion syntax...');

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

    // Fix the pattern: rows[0] as Record<string, unknown>.property
    content = content.replace(/rows\[0\]\s+as\s+Record<string,\s*unknown>\.(\w+)/g, '(rows[0] as Record<string, unknown>).$1');
    content = content.replace(/result\.rows\[0\]\s+as\s+Record<string,\s*unknown>\.(\w+)/g, '(result.rows[0] as Record<string, unknown>).$1');
    content = content.replace(/existing\.rows\[0\]\s+as\s+Record<string,\s*unknown>\.(\w+)/g, '(existing.rows[0] as Record<string, unknown>).$1');

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

// Check current ESLint status
console.log('\n📊 Checking current ESLint status...');
try {
  const lintOutput = execSync('npm run lint 2>&1', { encoding: 'utf8' });
  const parsingErrors = lintOutput.split('\n').filter(line => line.includes('Parsing error')).length;
  const totalIssues = lintOutput.split('\n').filter(line => line.includes('error') || line.includes('warning')).length;

  console.log(`📈 Current status:`);
  console.log(`   - Parsing errors: ${parsingErrors}`);
  console.log(`   - Total issues: ${totalIssues}`);

  if (totalIssues < 100) {
    console.log(`\n🎉 Excellent progress! Under 100 issues remaining.`);
  }
} catch (error) {
  console.error('❌ Could not check issues:', error.message);
}