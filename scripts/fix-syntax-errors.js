#!/usr/bin/env node

/**
 * Fix syntax errors introduced by automated type safety fixes
 * Focuses on common incorrect type assertion patterns
 */

import fs from 'fs';
import { execSync } from 'child_process';

console.log('🔧 Fixing syntax errors...');

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

    // Fix common syntax error patterns
    const patterns = [
      // Fix incorrect type assertions: rows[0] as Record<string, unknown>.property
      {
        regex: /rows\[0\]\s+as\s+Record<string,\s*unknown>\.(\w+)/g,
        replacement: '(rows[0] as Record<string, unknown>).$1'
      },
      // Fix incorrect type assertions with optional chaining: rows[0] as Record<string, unknown>?.property
      {
        regex: /rows\[0\]\s+as\s+Record<string,\s*unknown>\?\.(\w+)/g,
        replacement: '(rows[0] as Record<string, unknown>)?.$1'
      },
      // Fix broken array type syntax: ArrayType[...({ or ArrayType[ as unknown[])]
      {
        regex: /(\w+\[\])\[\.\.\.\([^)]*\)|\[\s+as\s+unknown\[\]\]/g,
        replacement: '$1[]'
      },
      // Fix broken generic syntax: Generic[...({ or Generic[ as unknown[])
      {
        regex: /(\w+)<\[\.\.\.\([^)]*\)|<\s+as\s+unknown\[\]>/g,
        replacement: '$1<>'
      },
      // Fix broken type assertions: as Record<string, unknown> as Record<string, unknown>
      {
        regex: /as\s+Record<string,\s*unknown>\s+as\s+Record<string,\s*unknown>/g,
        replacement: 'as Record<string, unknown>'
      },
      // Fix broken return type assertions: as result as result
      {
        regex: /as\s+(\w+)\s+as\s+\1/g,
        replacement: 'as $1'
      },
      // Fix broken boolean assertions: as true as true
      {
        regex: /as\s+(true|false)\s+as\s+\1/g,
        replacement: ''
      }
    ];

    patterns.forEach(({ regex, replacement }) => {
      content = content.replace(regex, replacement);
    });

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
console.log('\n📊 Checking remaining parsing errors...');
try {
  const lintOutput = execSync('npm run lint 2>&1', { encoding: 'utf8' });
  const parsingErrors = lintOutput.split('\n').filter(line => line.includes('Parsing error')).length;
  const totalIssues = lintOutput.split('\n').filter(line => line.includes('error') || line.includes('warning')).length;

  console.log(`📈 Remaining issues:`);
  console.log(`   - Parsing errors: ${parsingErrors}`);
  console.log(`   - Total issues: ${totalIssues}`);
} catch (error) {
  console.error('❌ Could not check remaining issues:', error.message);
}