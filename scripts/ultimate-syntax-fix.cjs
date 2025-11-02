#!/usr/bin/env node

/**
 * Ultimate Syntax Fix Script
 *
 * This script fixes the final remaining syntax errors.
 */

const fs = require('fs');
const path = require('path');

function fixFile(filePath) {
  try {
    let content = fs.readFileSync(filePath, 'utf8');
    let modified = false;

    // Fix 1: Function calls with trailing commas (remove them)
    content = content.replace(/(\w+\([^)]*)\),\s*/g, '$1;');

    // Fix 2: Object/array literals with trailing commas in return statements
    content = content.replace(/return\s*\{([^}]*)\},\s*;/g, 'return {$1};');
    content = content.replace(/return\s*\[([^\]]*)\],\s*;/g, 'return [$1];');

    // Fix 3: Array literals with trailing commas
    content = content.replace(/\[([^\]]*?)\],\s*(?=[^,;\n]*|\s*[)}])]/g, '[$1]');

    // Fix 4: Object literals with trailing commas
    content = content.replace(/\{([^}]*)\},\s*(?=[^,;\n]*|\s*[)}])]/g, '{$1}');

    // Fix 5: Union type exports - remove trailing commas
    content = content.replace(/export type \w+ = [^;]*?[^,]\|[^,]*\|[^,],\s*$/gm, (match) =>
      match.replace(/,\s*$/, ';')
    );

    // Fix 6: Class readonly properties - remove trailing commas
    content = content.replace(/readonly\s+(\w+):\s*[^,;\n]+,\s*/g, 'readonly $1: $2;');

    // Fix 7: Interface properties - remove trailing commas
    content = content.replace(/(\w+):\s*[^,;\n]+,\s*(?=\n|\s*}|$)/g, '$1: $2;');

    // Fix 8: Object property assignments - simple approach
    content = content.replace(/\w+:\s*[^,;\n]+,\s*/g, (match) => {
      // Replace trailing comma with semicolon for property type annotations
      return match.replace(/,$/, ';');
    });

    // Fix 9: Specific issues in validation.ts
    content = content.replace(/},\s*catch \{/, '} catch {');
    content = content.replace(
      /return\s*\[\s*'http:\s*',\s*'https:\s*'\]\s*\.\s*includes\(parsed\.protocol\),\s*\}/g,
      "return ['http:', 'https:'].includes(parsed.protocol); }"
    );
    content = content.replace(/}\s*,\s*/g, '} catch {');

    // Fix 10: Array return statements
    content = content.replace(
      /\[\s*'[^']*'\s*,\s*'[^']*'\s*\]\s*\.\s*includes\([^)]+\)\s*,\s*/g,
      (match) => match.replace(/,\s*$/, ';')
    );

    // Fix 11: Function parameter lists with type annotations
    content = content.replace(/\(([^)]*)\):\s*\w+[^,;\n]*,\s*/g, '($1): $2;');

    // Fix 12: Const/let declarations with trailing commas
    content = content.replace(/(const|let)\s+(\w+):\s*[^=;]+=\s*[^,;\n]+,\s*/g, '$1 $2: $3 = $4;');

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
  'src/config/migration-config.ts',
  'src/config/validation.ts',
  'src/constants/expiry-times.ts',
  'src/constants/supported-kinds.ts',
  'src/db/adapters/qdrant-adapter.ts',
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
