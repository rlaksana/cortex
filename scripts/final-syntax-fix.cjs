#!/usr/bin/env node

/**
 * Final Syntax Fix Script
 *
 * This script fixes the remaining specific syntax errors.
 */

const fs = require('fs');
const path = require('path');

function fixFile(filePath) {
  try {
    let content = fs.readFileSync(filePath, 'utf8');
    let modified = false;

    // Fix 1: Class property declarations - remove commas after type annotations
    content = content.replace(
      /(private|public|protected)\s+static\s+(\w+):\s*([^,;\n]+),/g,
      '$1 static $2: $3;'
    );
    content = content.replace(/(private|public|protected)\s+(\w+):\s*([^,;\n]+),/g, '$1 $2: $3;');

    // Fix 2: Import statements - convert trailing commas to semicolons
    content = content.replace(/import\s+(?:(?:[^;]*?from\s+['"][^'"]+['"]))?\s*,\s*$/gm, (match) =>
      match.replace(/,\s*$/, ';')
    );

    // Fix 3: Remove trailing commas from import statements
    content = content.replace(
      /import\s+([^{]*?)\s+from\s+['"][^'"]+['"],\s*/g,
      "import $1 from '$2';"
    );

    // Fix 4: Remove trailing commas from wildcard imports
    content = content.replace(
      /import\s+\*\s+as\s+(\w+)\s+from\s+['"][^'"]+['"],\s*/g,
      "import * as $1 from '$2';"
    );

    // Fix 5: Generic type parameters - ensure proper comma separation
    content = content.replace(/Map<(\w+);\s*(\w+)>/g, 'Map<$1, $2>');
    content = content.replace(/Record<(\w+);\s*(\w+)>/g, 'Record<$1, $2>');
    content = content.replace(/Promise<(\w+);\s*(\w+)>/g, 'Promise<$1, $2>');

    // Fix 6: Function parameter type annotations in object methods
    content = content.replace(/(\w+)\(([^)]*?)\):\s*(\w+(?:<[^>]*>)?)(?=\s*[{;])/g, '$1($2): $3');

    // Fix 7: Array type declarations
    content = content.replace(/(\w+):\s*(\w+\[\])\s*,/g, '$1: $2;');

    // Fix 8: Object destructuring with type annotations
    content = content.replace(/\{([^}]*?)\}:\s*([^,;\n]+),/g, '{$1}: $2;');

    // Fix 9: Remove trailing commas from export declarations
    content = content.replace(
      /export\s+(type|interface|class|function|const|let|var)\s+([^,;\n]+),\s*$/gm,
      'export $1 $2;'
    );

    // Fix 10: Fix property initializers that need '='
    content = content.replace(/private\s+(\w+):\s*([^=,;\n]+)\s*=/g, 'private $1: $2 =');

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

function findTypeScriptFiles(dir) {
  const files = [];

  function traverse(currentDir) {
    const items = fs.readdirSync(currentDir);

    for (const item of items) {
      const fullPath = path.join(currentDir, item);
      const stat = fs.statSync(fullPath);

      if (stat.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
        traverse(fullPath);
      } else if (item.endsWith('.ts') && !item.endsWith('.d.ts')) {
        files.push(fullPath);
      }
    }
  }

  traverse(dir);
  return files;
}

// Main execution
const srcDir = path.join(process.cwd(), 'src');
const tsFiles = findTypeScriptFiles(srcDir);

console.log(`Found ${tsFiles.length} TypeScript files to check...`);

let fixedCount = 0;
for (const file of tsFiles) {
  if (fixFile(file)) {
    fixedCount++;
  }
}

console.log(`\nComplete! Fixed ${fixedCount} files.`);
