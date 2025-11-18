#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

console.log('🔥 REMOVING ALL @ts-nocheck DIRECTIVES FOR TRUE ERROR ASSESSMENT\n');

// Find all TypeScript files with @ts-nocheck
try {
  const result = execSync('rg "@ts-nocheck" --type ts -l', {
    encoding: 'utf8',
    cwd: process.cwd(),
    stdio: 'pipe'
  });

  const files = result.trim().split('\n').filter(Boolean);
  console.log(`Found ${files.length} files with @ts-nocheck directives`);

  let removedCount = 0;

  files.forEach(file => {
    try {
      const content = fs.readFileSync(file, 'utf8');
      const lines = content.split('\n');

      const newLines = lines.filter(line => {
        const trimmed = line.trim();
        return trimmed !== '// @ts-nocheck' &&
               trimmed !== '//@ts-nocheck' &&
               trimmed !== '/* @ts-nocheck */' &&
               trimmed !== '/* @ts-nocheck */;' &&
               !trimmed.includes('@ts-nocheck');
      });

      if (newLines.length !== lines.length) {
        fs.writeFileSync(file, newLines.join('\n'), 'utf8');
        console.log(`✅ Removed @ts-nocheck from: ${file}`);
        removedCount++;
      }
    } catch (error) {
      console.error(`❌ Error processing ${file}:`, error.message);
    }
  });

  console.log(`\n📊 SUMMARY:`);
  console.log(`   Files processed: ${files.length}`);
  console.log(`   Files modified: ${removedCount}`);
  console.log(`   @ts-nocheck directives removed: ALL OF THEM`);

} catch (error) {
  console.log('No @ts-nocheck directives found or error occurred:', error.message);
}

console.log('\n🎯 READY FOR TRUE ERROR ASSESSMENT!');