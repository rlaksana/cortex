#!/usr/bin/env node

/**
 * Critical Error Fix Script
 *
 * Fixes critical no-undef errors by properly defining variables
 */

import fs from 'fs';
import path from 'path';

console.log('🔧 Fixing critical no-undef errors...');

// Files with critical no-undef errors
const criticalFiles = [
  'tests/framework/helpers/error-test-helper.ts',
  'tests/framework/helpers/performance-test-helper.ts',
  'tests/framework/helpers/validation-test-helper.ts',
  'tests/framework/test-validation.ts',
  'tests/global-setup.ts',
  'tests/array-serialization-test.ts',
];

console.log(`Processing ${criticalFiles.length} critical files...`);

let totalFixed = 0;

for (const file of criticalFiles) {
  if (!fs.existsSync(file)) {
    console.log(`⚠️  File not found: ${file}`);
    continue;
  }

  try {
    let content = fs.readFileSync(file, 'utf8');
    let modified = false;

    // Fix pattern: _result is assigned but result is used
    content = content.replace(/const\s+_(result|error|item|stats|status)\s*=/g, 'const $1 =');

    // Fix pattern: _result in assignment but result used in subsequent lines
    // Look for patterns where variable is assigned with underscore but used without
    const lines = content.split('\n');
    const fixedLines = lines.map((line, index) => {
      let fixedLine = line;

      // Check for assignments with underscore that are referenced later without underscore
      if (/const\s+_(\w+)\s*=/.test(line)) {
        const varName = line.match(/const\s+_(\w+)\s*=/)[1];

        // Look ahead to see if this variable is referenced without underscore in next few lines
        for (let i = index + 1; i < Math.min(index + 10, lines.length); i++) {
          const nextLine = lines[i];
          if (
            new RegExp(`\\b${varName}\\b`).test(nextLine) &&
            !new RegExp(`\\b_${varName}\\b`).test(nextLine)
          ) {
            // Variable is referenced without underscore, fix the assignment
            fixedLine = line.replace(`const _${varName}`, `const ${varName}`);
            break;
          }
        }
      }

      return fixedLine;
    });

    content = fixedLines.join('\n');

    // Fix specific patterns for undefined variables
    if (file.includes('error-test-helper.ts')) {
      // Fix the item reference issue
      content = content.replace(
        /const\s+_item\s*=\s*context\.dataFactory\.createEntity\(\{[\s\S]*?\}\);\s*\n\s*const\s+_result\s*=\s*await\s*memoryStore\(\[item\]\);/g,
        'const item = context.dataFactory.createEntity({\n        properties: circular, });\n\n      const result = await memoryStore([item]);'
      );
    }

    // Fix undefined error variables in catch blocks
    content = content.replace(
      /catch\s*\(\s*\)\s*{\s*throw new Error\(error\.message\);/g,
      'catch (error) {\n      throw new Error(error.message);'
    );

    // Fix undefined stats references
    content = content.replace(/console\.log\(`.*?\${stats\.}.*?`\);/g, (match) => {
      return match.replace(/\${stats\.}/g, '${_stats.');
    });

    if (modified || content !== fs.readFileSync(file, 'utf8')) {
      fs.writeFileSync(file, content);
      console.log(`✅ Fixed: ${file}`);
      totalFixed++;
    } else {
      console.log(`ℹ️  No changes needed: ${file}`);
    }
  } catch (error) {
    console.log(`❌ Error fixing ${file}: ${error.message}`);
  }
}

console.log(`\n✅ Critical error fix completed! Fixed ${totalFixed} files.`);
console.log('\n📝 Next steps:');
console.log('   1. Run: npm run lint');
console.log('   2. Check remaining errors');
