#!/usr/bin/env node

import fs from 'fs';
import path from 'path';

console.log('🔧 Running simple syntax fixes...');

// Files that need specific fixes based on lint output
const filesToFix = [
  'src/services/audit/audit-service.ts',
  'src/services/ranking/result-ranker.ts',
  'src/services/search/entity-matching-service.ts',
  'src/services/search/graph-expansion-service.ts',
  'src/services/search/hybrid-search-service.ts',
  'src/services/search/query-parser.ts',
  'src/services/search/search-optimization.ts',
  'src/services/search/search-service.ts',
  'src/services/search/search-strategy.ts',
  'src/types/mcp-sdk.d.ts',
  'src/utils/mcp-error-logger.ts',
];

let fixedCount = 0;

filesToFix.forEach((filePath) => {
  try {
    const fullPath = path.resolve(filePath);
    if (!fs.existsSync(fullPath)) {
      console.log(`❌ File not found: ${filePath}`);
      return;
    }

    let content = fs.readFileSync(fullPath, 'utf8');
    let modified = false;

    // Most common syntax fixes
    const originalContent = content;

    // Fix semicolon vs comma in object properties
    content = content.replace(/(\w+):\s*([^,;]+);/g, '$1: $2,');

    // Fix parameter type annotations
    content = content.replace(/(\w+),\s*(\w+):\s*([^)]+)/g, '$1, $2: $3');

    // Fix function parameter separators
    content = content.replace(/(\w+:\s*[^,]+);(\s*\w+:)/g, '$1,$2');

    // Fix array/object syntax
    content = content.replace(/\[(\w+);\s*/g, '[$1, ');
    content = content.replace(/(\w+);\s*\]/g, '$1 ]');

    // Fix generic syntax
    content = content.replace(/<(\w+);\s*(\w+)>/g, '<$1, $2>');

    if (content !== originalContent) {
      fs.writeFileSync(fullPath, content);
      fixedCount++;
      console.log(`✅ Fixed: ${filePath}`);
    }
  } catch (error) {
    console.error(`❌ Error fixing ${filePath}:`, error.message);
  }
});

console.log(`\n🎉 Fixed ${fixedCount} files!`);
