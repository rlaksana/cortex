#!/usr/bin/env node

/**
 * Class Property Fix Script
 *
 * This script fixes trailing commas in class property declarations.
 */

const fs = require('fs');
const path = require('path');

function fixFile(filePath) {
  try {
    let content = fs.readFileSync(filePath, 'utf8');
    let modified = false;

    // Fix trailing commas in class property declarations
    content = content.replace(
      /(private|public|protected)\s+(static\s+)?(\w+):\s*[^,;\n=]+=[^,;\n]*,\s*/g,
      '$1$2$3: $4;'
    );

    // Fix trailing commas in variable declarations within classes
    content = content.replace(/(const|let|var)\s+(\w+):\s*[^,;\n=]+=[^,;\n]*,\s*/g, '$1 $2: $3;');

    // Fix Map and other generic type declarations with trailing commas
    content = content.replace(/Map<[^>]+>\s*=\s*new Map\(\),\s*/g, 'Map<$1> = new Map();');
    content = content.replace(/Record<[^>]+>\s*=\s*[^,;\n]+,\s*/g, 'Record<$1> = {};');

    // Fix variable declarations with union types
    content = content.replace(/let\s+(\w+):\s*[^=;]+=\s*[^,;\n]+,\s*/g, 'let $1: $2 = $3;');

    if (content !== fs.readFileSync(filePath, 'utf8')) {
      fs.writeFileSync(filePath, content);
      console.log(`✓ Fixed ${filePath}`);
      return true;
    }

    return false;
  } catch (error) {
    console.error(`Error processing ${filePath}:`, error.message);
    return false;
  }
}

// Fix specific files that are causing issues
const filesToFix = [
  'src/config/database-config.ts',
  'src/config/migration-config.ts',
  'src/config/validation.ts',
];

let fixedCount = 0;
for (const file of filesToFix) {
  const filePath = path.join(process.cwd(), file);
  if (fs.existsSync(filePath)) {
    if (fixFile(filePath)) {
      fixedCount++;
    }
  }
}

console.log(`\nComplete! Fixed ${fixedCount} files.`);
