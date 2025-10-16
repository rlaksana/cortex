#!/usr/bin/env node

/**
 * Fix nullish coalescing issues systematically
 * Replaces `||` with `??` for safer null/undefined checks
 */

import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

console.log('🔧 Fixing nullish coalescing issues...');

// Get list of files with nullish coalescing issues
try {
  const output = execSync('npm run lint 2>&1', { encoding: 'utf8' });
  const lines = output.split('\n');

  // Extract unique files with nullish coalescing issues
  const filesWithIssues = new Set();
  const issueDetails = [];

  lines.forEach(line => {
    if (line.includes('prefer-nullish-coalescing')) {
      const match = line.match(/^([^(]+):(\d+):\d+/);
      if (match) {
        const filePath = match[1];
        const lineNumber = parseInt(match[2]);
        filesWithIssues.add(filePath);

        // Extract the error message to understand the context
        const message = line.substring(line.indexOf('error') + 6);
        issueDetails.push({ filePath, lineNumber, message });
      }
    }
  });

  console.log(`Found ${filesWithIssues.size} files with nullish coalescing issues`);

  // Process each file
  for (const filePath of filesWithIssues) {
    console.log(`Processing: ${filePath}`);

    try {
      let content = fs.readFileSync(filePath, 'utf8');
      const originalContent = content;

      // Fix patterns: replace `||` with `??` for nullish coalescing
      // This is a conservative approach - we only replace obvious cases
      const lines = content.split('\n');

      issueDetails
        .filter(issue => issue.filePath === filePath)
        .forEach(issue => {
          const { lineNumber } = issue;
          if (lines[lineNumber - 1]) {
            let line = lines[lineNumber - 1];

            // Simple pattern: value || defaultValue -> value ?? defaultValue
            // Be conservative: only replace when the right side is a literal or simple expression
            line = line.replace(/(\w+(?:\.\w+)*(?:\[\w+\])?)\s*\|\|\s*([^,\)\];}]+)/g, '$1 ?? $2');

            lines[lineNumber - 1] = line;
          }
        });

      content = lines.join('\n');

      if (content !== originalContent) {
        fs.writeFileSync(filePath, content);
        console.log(`  ✅ Fixed nullish coalescing in ${filePath}`);
      } else {
        console.log(`  ⚠️  No changes made to ${filePath}`);
      }
    } catch (error) {
      console.error(`  ❌ Error processing ${filePath}:`, error.message);
    }
  }

  console.log('\n🎉 Nullish coalescing fixes completed!');

} catch (error) {
  console.error('❌ Error running lint:', error.message);
  process.exit(1);
}