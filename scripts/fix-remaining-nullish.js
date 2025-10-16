#!/usr/bin/env node

/**
 * Fix remaining nullish coalescing issues with more comprehensive patterns
 */

import fs from 'fs';
import { execSync } from 'child_process';

console.log('🔧 Fixing remaining nullish coalescing issues...');

// Get all TypeScript files
try {
  const output = execSync('find src -name "*.ts" -type f', { encoding: 'utf8' });
  const allTsFiles = output.trim().split('\n').filter(Boolean);

  let totalFixes = 0;

  allTsFiles.forEach(filePath => {
    try {
      let content = fs.readFileSync(filePath, 'utf8');
      const originalContent = content;

      // More comprehensive patterns
      const patterns = [
        // Basic variable pattern: a || b -> a ?? b
        {
          regex: /(\b\w+(?:\.\w+)*(?:\[\w+\])?)\s*\|\|\s*([^,\)\];}\n]+?)(?=[,\)\];}\n]|$)/g,
          replacement: '$1 ?? $2'
        },
        // Property access pattern: obj.prop || val -> obj.prop ?? val
        {
          regex: /(\b\w+(?:\.\w+)+(?:\[\w+\])?)\s*\|\|\s*([^,\)\];}\n]+?)(?=[,\)\];}\n]|$)/g,
          replacement: '$1 ?? $2'
        },
        // Array/object literal pattern: arr || [] -> arr ?? []
        {
          regex: /(\w+(?:\.\w+)*(?:\[\w+\])?)\s*\|\|\s*(\[\]|\{\}|\{\s*[^}]*\s*\}|\[\s*[^]]*\s*\])/g,
          replacement: '$1 ?? $2'
        },
        // String literal pattern: str || "" -> str ?? ""
        {
          regex: /(\w+(?:\.\w+)*(?:\[\w+\])?)\s*\|\|\s*("[^"]*"|'[^']*')/g,
          replacement: '$1 ?? $2'
        },
        // Number literal pattern: num || 0 -> num ?? 0
        {
          regex: /(\w+(?:\.\w+)*(?:\[\w+\])?)\s*\|\|\s*(\d+)/g,
          replacement: '$1 ?? $2'
        },
        // Function call pattern: result || defaultValue
        {
          regex: /(\w+\([^)]*\)|\w+(?:\.\w+)*(?:\[\w+\])?)\s*\|\|\s*([^,\)\];}\n]+?)(?=[,\)\];}\n]|$)/g,
          replacement: '$1 ?? $2'
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
  console.log('\n📊 Checking remaining issues...');
  try {
    const lintOutput = execSync('npm run lint 2>&1', { encoding: 'utf8' });
    const remainingIssues = lintOutput.split('\n').filter(line => line.includes('prefer-nullish-coalescing')).length;
    console.log(`📈 Remaining nullish coalescing issues: ${remainingIssues}`);
  } catch (error) {
    console.error('❌ Could not check remaining issues:', error.message);
  }

} catch (error) {
  console.error('❌ Error finding TypeScript files:', error.message);
  process.exit(1);
}