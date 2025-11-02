#!/usr/bin/env node

/**
 * Manual Lint Fix Script
 *
 * Manually fixes specific critical issues without breaking existing code
 */

import fs from 'fs';
import path from 'path';

console.log('🔧 Running manual lint fix...');

// Critical fixes needed
const criticalFixes = [
  // Fix array-serialization-test.ts no-undef errors
  {
    file: 'tests/array-serialization-test.ts',
    fixes: [
      {
        pattern:
          / {2}} catch \(_error\) {\s*\n {4}logError\(`\${testName} - FAILED: \${\(error as Error\)\.message}`\);\s*\n {4}console\.error\((error as Error)\.stack\);/g,
        replacement:
          '  } catch (error) {\n    logError(`${testName} - FAILED: ${(error as Error).message}`);\n    console.error((error as Error).stack);',
      },
      {
        pattern: /const storedArray = result\.rows\[0\]\.alternatives_considered;/g,
        replacement: 'const storedArray = _result.rows[0].alternatives_considered;',
      },
      {
        pattern:
          /await pool\.query\('DELETE FROM knowledge_base WHERE id = \$1', \[result\.rows\[0\]\.id\]\);/g,
        replacement:
          "await pool.query('DELETE FROM knowledge_base WHERE id = $1', [_result.rows[0].id]);",
      },
    ],
  },
];

let totalFixed = 0;

for (const fix of criticalFixes) {
  if (!fs.existsSync(fix.file)) {
    console.log(`⚠️  File not found: ${fix.file}`);
    continue;
  }

  try {
    let content = fs.readFileSync(fix.file, 'utf8');
    let modified = false;

    for (const patternFix of fix.fixes) {
      const newContent = content.replace(patternFix.pattern, patternFix.replacement);
      if (newContent !== content) {
        content = newContent;
        modified = true;
        console.log(`✅ Applied pattern fix in ${fix.file}`);
      }
    }

    if (modified) {
      fs.writeFileSync(fix.file, content);
      totalFixed++;
      console.log(`✅ Fixed: ${fix.file}`);
    }
  } catch (error) {
    console.log(`❌ Error fixing ${fix.file}: ${error.message}`);
  }
}

console.log(`\n✅ Manual lint fix completed! Fixed ${totalFixed} files.`);
