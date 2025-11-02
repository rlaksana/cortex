#!/usr/bin/env node

import fs from 'fs';
import path from 'path';

// Specific line-by-line fixes based on lint output
const lineFixes = [
  {
    file: 'tests/array-serialization-test.ts',
    line: 275,
    old: '  _error',
    new: '  // _error',
  },
  {
    file: 'tests/fixtures/test-data-factory.ts',
    line: 8,
    old: "import { KnowledgeItem } from '../../src/services/memory-store/types.js';",
    new: "import type { KnowledgeItem } from '../../src/services/memory-store/types.js';",
  },
  {
    file: 'tests/framework/helpers/database-test-helper.ts',
    line: 10,
    old: 'import { qdrantSchemaManager } from',
    new: 'import { _qdrantSchemaManager } from',
  },
];

console.log('🔧 Applying targeted lint fixes...');

lineFixes.forEach((fix) => {
  const filePath = path.resolve(fix.file);

  if (!fs.existsSync(filePath)) {
    console.log(`❌ File not found: ${fix.file}`);
    return;
  }

  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');

    if (lines[fix.line - 1] && lines[fix.line - 1].includes(fix.old)) {
      lines[fix.line - 1] = lines[fix.line - 1].replace(fix.old, fix.new);
      fs.writeFileSync(filePath, lines.join('\n'));
      console.log(`✅ Fixed line ${fix.line} in ${fix.file}`);
    } else {
      console.log(`ℹ️  Line ${fix.line} in ${fix.file} doesn't match expected content`);
    }
  } catch (error) {
    console.log(`❌ Error fixing ${fix.file}: ${error.message}`);
  }
});

console.log('✅ Targeted fixes completed!');
