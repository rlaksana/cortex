#!/usr/bin/env node

/**
 * Fix Undefined Variables Script
 *
 * Fixes remaining no-undef errors by correcting variable references
 */

import fs from 'fs';
import path from 'path';

console.log('🔧 Fixing remaining undefined variable errors...');

// Files with remaining no-undef errors
const filesToFix = [
  'tests/array-serialization-test.ts',
  'tests/framework/helpers/database-test-helper.ts',
  'tests/framework/helpers/error-test-helper.ts',
  'tests/framework/helpers/performance-test-helper.ts',
  'tests/framework/test-validation.ts',
  'tests/global-setup.ts',
];

console.log(`Processing ${filesToFix.length} files...`);

let totalFixed = 0;

for (const file of filesToFix) {
  if (!fs.existsSync(file)) {
    console.log(`⚠️  File not found: ${file}`);
    continue;
  }

  try {
    let content = fs.readFileSync(file, 'utf8');
    let modified = false;

    // Fix catch block parameter references
    content = content.replace(
      /catch\s*\(\s*_(error|result|item)\s*\)\s*{([^}]*)}/g,
      (match, varName, blockContent) => {
        let fixed = `catch (${varName}) {${blockContent}}`;
        // Replace references to _varName with varName
        fixed = fixed.replace(new RegExp(`_${varName}`, 'g'), varName);
        return fixed;
      }
    );

    // Fix catch block without parameter but using error
    content = content.replace(
      /catch\s*\(\s*\)\s*{([^}]*)error\.([^}]*?)}/g,
      'catch (error) {$1error.$2}'
    );

    // Fix undefined variable references that should be underscored
    const specificFixes = [
      // _result not defined - should be result or vice versa
      { pattern: /if\s*\(_result\s*!==\s*null\)/g, replacement: 'if (result !== null)' },
      { pattern: /if\s*\(_result\s*===\s*null\)/g, replacement: 'if (result === null)' },
      { pattern: /return\s*_result;/g, replacement: 'return result;' },
      { pattern: /console\.log\(_result\)/g, replacement: 'console.log(result)' },

      // result assigned but _result used
      {
        pattern: /const\s+result\s*=[\s\S]*?if\s*\(_result/g,
        replacement: (match) => match.replace(/_result/g, 'result'),
      },

      // Fix error in array-serialization-test.ts
      {
        pattern:
          /}\s*catch\s*\(_error\)\s*{\s*logError\(`.*?:.*?\$\{\(error as Error\)\.message\}`\);/g,
        replacement: (match) => match.replace('_error', 'error'),
      },
    ];

    for (const fix of specificFixes) {
      const newContent = content.replace(fix.pattern, fix.replacement);
      if (newContent !== content) {
        content = newContent;
        modified = true;
      }
    }

    // Fix specific file issues
    if (file.includes('array-serialization-test.ts')) {
      // Fix the _result references
      content = content.replace(
        /const\s+result\s*=\s*serializeArray\(\[\]\);\s*if\s*\(_result/g,
        'const result = serializeArray([]);\n    if (result'
      );
      content = content.replace(/const\s+result\s*=[\s\S]*?if\s*\(_result/g, (match) =>
        match.replace(/_result/g, 'result')
      );
    }

    if (file.includes('database-test-helper.ts')) {
      // Fix the undefined error in catch block
      content = content.replace(
        /throw new Error\(`Database setup failed: \$\{error\.message\}`\);/,
        'throw new Error(`Database setup failed: ${error?.message || "Unknown error"}`);'
      );
    }

    if (file.includes('error-test-helper.ts')) {
      // Fix error references in catch blocks
      content = content.replace(
        /} catch \(_error\) {\s*throw new Error\(error\.message\);/g,
        '} catch (error) {\n      throw new Error(error.message);'
      );
    }

    if (file.includes('performance-test-helper.ts')) {
      // Fix undefined item references
      content = content.replace(/\.push\(\{\s*id:\s*item\./g, '.push({\n        id: _item.');
      content = content.replace(/\.push\(\{\s*name:\s*item\./g, '.push({\n        name: _item.');
      content = content.replace(/for \(const item of _items\)/g, 'for (const item of items)');
    }

    if (modified) {
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

console.log(`\n✅ Undefined variable fix completed! Fixed ${totalFixed} files.`);
console.log('\n📝 Next steps:');
console.log('   1. Run: npm run lint');
console.log('   2. Check remaining errors');
