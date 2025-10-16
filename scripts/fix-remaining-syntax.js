#!/usr/bin/env node

/**
 * Fix the specific syntax error pattern: result.(rows[0] as Record<string, unknown>)
 */

import fs from 'fs';
import { execSync } from 'child_process';

console.log('🔧 Fixing remaining syntax errors...');

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

    // Fix the specific pattern: result.(rows[0] as Record<string, unknown>)
    content = content.replace(/result\.?\(rows\[0\] as Record<string, unknown>\)/g, 'result.rows[0] as Record<string, unknown>');
    content = content.replace(/existing\.?\(rows\[0\] as Record<string, unknown>\)/g, 'existing.rows[0] as Record<string, unknown>');
    content = content.replace(/totalResult\.?\(rows\[0\] as Record<string, unknown>\)/g, 'totalResult.rows[0] as Record<string, unknown>');
    content = content.replace(/actorResult\.?\(rows\[0\] as Record<string, unknown>\)/g, 'actorResult.rows[0] as Record<string, unknown>');
    content = content.replace(/countResult\.?\(rows\[0\] as Record<string, unknown>\)/g, 'countResult.rows[0] as Record<string, unknown>');

    // Fix similar patterns with optional chaining
    content = content.replace(/result\.?\(rows\[0\] as Record<string, unknown>\)\?\.(\w+)/g, '(result.rows[0] as Record<string, unknown>)?.$1');
    content = content.replace(/existing\.?\(rows\[0\] as Record<string, unknown>\)\?\.(\w+)/g, '(existing.rows[0] as Record<string, unknown>)?.$1');

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

// Verify progress
console.log('\n📊 Checking remaining issues...');
try {
  const lintOutput = execSync('npm run lint 2>&1', { encoding: 'utf8' });
  const parsingErrors = lintOutput.split('\n').filter(line => line.includes('Parsing error')).length;
  const totalIssues = lintOutput.split('\n').filter(line => line.includes('error') || line.includes('warning')).length;

  console.log(`📈 Remaining issues:`);
  console.log(`   - Parsing errors: ${parsingErrors}`);
  console.log(`   - Total issues: ${totalIssues}`);

  if (parsingErrors === 0) {
    console.log(`\n✅ All syntax errors fixed! Ready to continue with remaining ESLint issues.`);
  }
} catch (error) {
  console.error('❌ Could not check remaining issues:', error.message);
}