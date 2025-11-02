#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// List of files to fix
const filesToFix = [
  'src/services/audit/audit-service.ts',
  'src/services/ranking/result-ranker.ts',
  'src/services/search/entity-matching-service.ts',
  'src/services/search/graph-expansion-service.ts',
  'src/services/search/hybrid-search-service.ts',
  'src/services/search/query-parser.ts',
  'src/services/search/search-service.ts',
  'src/services/search/search-strategy.ts',
  'src/types/mcp-sdk.d.ts',
  'src/utils/mcp-error-logger.ts',
];

console.log('🔧 Fixing critical syntax errors...');

filesToFix.forEach((filePath) => {
  try {
    const fullPath = path.resolve(__dirname, '..', filePath);
    if (!fs.existsSync(fullPath)) {
      console.log(`❌ File not found: ${filePath}`);
      return;
    }

    let content = fs.readFileSync(fullPath, 'utf8');

    // Common syntax fixes
    content = content.replace(/return \[\],/g, 'return [];');
    content = content.replace(/(\w+): (\w+),/g, '$1: $2;');
    content = content.replace(/(\w+): (\w+)$\s*$/gm, '$1: $2;');
    content = content.replace(/\(\s*\.\.\./g, '(');
    content = content.replace(/\.\.\./g, '...');
    content = content.replace(/\bany\b/g, 'any');
    content = content.replace(/\berror\b/g, '_error');
    content = content.replace(/\bresult\b/g, '_result');

    fs.writeFileSync(fullPath, content, 'utf8');
    console.log(`✅ Fixed: ${filePath}`);
  } catch (error) {
    console.error(`❌ Error fixing ${filePath}:`, error.message);
  }
});

console.log('🎉 Syntax error fixing completed!');
