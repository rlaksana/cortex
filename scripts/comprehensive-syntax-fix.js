#!/usr/bin/env node

import fs from 'fs';
import path from 'path';

console.log('🔧 Running comprehensive syntax fixes...');

// Get all TypeScript files in src and tests
function getAllTsFiles(dir, fileList = []) {
  const files = fs.readdirSync(dir);

  files.forEach((file) => {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);

    if (stat.isDirectory() && !file.includes('node_modules')) {
      getAllTsFiles(filePath, fileList);
    } else if (file.endsWith('.ts')) {
      fileList.push(filePath);
    }
  });

  return fileList;
}

const files = getAllTsFiles('./src').concat(getAllTsFiles('./tests'));

let fixedCount = 0;

files.forEach((filePath) => {
  try {
    let content = fs.readFileSync(filePath, 'utf8');
    let modified = false;

    // Common syntax fixes
    const fixes = [
      // Fix property assignment syntax
      { pattern: /(\w+): (\w+),/g, replacement: '$1: $2,' },
      { pattern: /(\w+) = (\w+),/g, replacement: '$1: $2,' },
      { pattern: /(\w+): (\w+);/g, replacement: '$1: $2;' },

      // Fix object property syntax
      { pattern: /(\w+)\s*:\s*/g, replacement: '$1: ' },

      // Fix array/object syntax
      { pattern: /return \[\],/g, replacement: 'return [];' },
      { pattern: /\[\s*(\w+)\s*;\s*\]/g, replacement: '[$1]' },

      // Fix arrow function syntax
      { pattern: /\(([^)]+):\s*([^)]+)\)/g, replacement: '($1, $2)' },

      // Fix parameter types
      { pattern: /(\w+)\?,\s*(\w+)/g, replacement: '$1?: $2' },

      // Fix semicolon issues
      { pattern: /(\w+)\s*,\s*$/gm, replacement: '$1;' },
      { pattern: /}\s*,\s*$/gm, replacement: '};' },

      // Fix element access
      { pattern: /(\w+)\s*(\w+)\s*\[/g, replacement: '$1[$2' },

      // Fix generic syntax
      { pattern: /<(\w+);\s*(\w+)>/g, replacement: '<$1, $2>' },

      // Fix undefined pattern
      { pattern: /\bundefined\b/g, replacement: 'undefined' },
    ];

    fixes.forEach((fix) => {
      const before = content;
      content = content.replace(fix.pattern, fix.replacement);
      if (before !== content) modified = true;
    });

    // Special fix for common patterns
    content = content.replace(/(\w+)\s*=\s*([^,;]+),/g, '$1 = $2;');
    content = content.replace(/(\w+)\s*=\s*([^,;]+);/g, '$1 = $2;');

    if (modified) {
      fs.writeFileSync(filePath, content);
      fixedCount++;
      console.log(`✅ Fixed: ${filePath}`);
    }
  } catch (error) {
    console.error(`❌ Error processing ${filePath}:`, error.message);
  }
});

console.log(`\n🎉 Fixed ${fixedCount} files!`);
