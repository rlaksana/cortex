#!/usr/bin/env node

/**
 * Type Guard Automation Script
 *
 * This script automatically applies type guards to files with unknown type errors.
 * It focuses on common patterns like database rows, where clauses, and API responses.
 */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Common patterns and their type guard solutions
const TYPE_GUARD_PATTERNS = [
  {
    name: 'Database Result with created_at',
    regex: /(\w+\.created_at\..*\.toISOString\(\))/g,
    replacement: (match, variable) => {
      return `(() => {
        const createdAt = ${variable.split('.')[0]}.created_at;
        if (createdAt instanceof Date) {
          return createdAt.toISOString();
        }
        if (typeof createdAt === 'string') {
          return createdAt;
        }
        return new Date().toISOString();
      })()`;
    },
    importGuard: 'isDatabaseResult',
    description: 'Safe handling of created_at timestamps'
  },
  {
    name: 'Unknown Where Clause',
    regex: /(:\s*unknown)\s*(?=\{)/g,
    replacement: ': Record<string, unknown>',
    importGuard: 'isWhereClause',
    description: 'Type whereClause as Record<string, unknown>'
  },
  {
    name: 'Unknown Database Row Access',
    regex: /(\w+)\.(\w+)(?=\s*[,\]\}\.\?])/g,
    replacement: (match, obj, prop) => {
      return `safePropertyAccess(${obj}, '${prop}', isString)`;
    },
    importGuard: 'safePropertyAccess, isString',
    description: 'Safe property access for database rows'
  },
  {
    name: 'Unknown Array Access',
    regex: /(\w+)\[(\d+)\](?=\.)/g,
    replacement: (match, arr, index) => {
      return `safeArrayAccess(${arr}, ${index}, isUnknown)`;
    },
    importGuard: 'safeArrayAccess, isUnknown',
    description: 'Safe array access with type guard'
  },
  {
    name: 'Unknown Function Parameter',
    regex: /\((\w+):\s*unknown\)/g,
    replacement: (match, param) => {
      // Only apply if it looks like a database row or result
      if (param.includes('row') || param.includes('result') || param.includes('item')) {
        return `(${param}: unknown)`;
      }
      return match;
    },
    importGuard: null,
    description: 'Handle unknown function parameters'
  }
];

// Type guard imports mapping
const TYPE_GUARD_IMPORTS = {
  isDatabaseResult: 'isDatabaseResult',
  isWhereClause: 'isWhereClause',
  isDatabaseRow: 'isDatabaseRow',
  isString: 'isString',
  isDict: 'isDict',
  safePropertyAccess: 'safePropertyAccess',
  safeArrayAccess: 'safeArrayAccess',
  isUnknown: 'isUnknown'
};

/**
 * Get the list of files with the most TS18046 errors
 */
async function getTopErrorFiles(limit = 10) {
  try {
    const { execSync } = await import('child_process');
    const output = execSync('npx tsc --noEmit --pretty false 2>&1', { encoding: 'utf8' });

    const errors = output
      .split('\n')
      .filter(line => line.includes('TS18046'))
      .map(line => {
        const match = line.match(/^(.+?)\(/);
        return match ? match[1] : null;
      })
      .filter(Boolean);

    const errorCounts = {};
    errors.forEach(file => {
      errorCounts[file] = (errorCounts[file] || 0) + 1;
    });

    return Object.entries(errorCounts)
      .sort(([,a], [,b]) => b - a)
      .slice(0, limit)
      .map(([file]) => file);
  } catch (error) {
    console.error('Error getting TypeScript errors:', error.message);
    return [];
  }
}

/**
 * Apply type guards to a file
 */
async function applyTypeGuards(filePath) {
  try {
    let content = await fs.readFile(filePath, 'utf8');
    const originalContent = content;
    const neededImports = new Set();

    // Apply each pattern
    for (const pattern of TYPE_GUARD_PATTERNS) {
      if (pattern.importGuard) {
        pattern.importGuard.split(',').forEach(guard => {
          neededImports.add(guard.trim());
        });
      }

      // Apply the pattern with a custom replacer function
      content = content.replace(pattern.regex, (...args) => {
        if (typeof pattern.replacement === 'function') {
          return pattern.replacement(...args);
        }
        return pattern.replacement;
      });

      if (content !== originalContent) {
        console.log(`✓ Applied pattern: ${pattern.description} to ${filePath}`);
      }
    }

    // Add type guard imports if needed
    if (neededImports.size > 0) {
      content = addTypeGuardImports(content, neededImports, filePath);
    }

    // Write the updated content
    if (content !== originalContent) {
      await fs.writeFile(filePath, content, 'utf8');
      return true;
    }

    return false;
  } catch (error) {
    console.error(`Error applying type guards to ${filePath}:`, error.message);
    return false;
  }
}

/**
 * Add type guard imports to a file
 */
function addTypeGuardImports(content, neededImports, filePath) {
  // Check if type guards are already imported
  const hasTypeGuardImport = content.includes('from \'../../utils/type-guards.js\'') ||
                           content.includes('from "../utils/type-guards.js"') ||
                           content.includes('from \'./utils/type-guards.js\'');

  if (!hasTypeGuardImport && neededImports.size > 0) {
    // Find the last import statement
    const importRegex = /import[^;]+;/g;
    const imports = content.match(importRegex) || [];
    const lastImport = imports[imports.length - 1];

    if (lastImport) {
      const insertPosition = content.lastIndexOf(lastImport) + lastImport.length;

      // Determine the relative path to type-guards
      let importPath = '../../utils/type-guards.js';
      if (filePath.includes('/src/')) {
        importPath = '../../utils/type-guards.js';
      } else if (filePath.includes('/services/')) {
        importPath = '../../utils/type-guards.js';
      }

      const importStatement = `
import {
  ${Array.from(neededImports).join(',\n  ')}
} from '${importPath}';`;

      content = content.slice(0, insertPosition) + importStatement + content.slice(insertPosition);
    }
  }

  return content;
}

/**
 * Validate the fixes by running TypeScript compiler
 */
async function validateFixes() {
  try {
    const { execSync } = await import('child_process');
    const output = execSync('npx tsc --noEmit --pretty false 2>&1', { encoding: 'utf8' });

    const errorCount = (output.match(/TS18046/g) || []).length;
    return errorCount;
  } catch (error) {
    console.error('Error validating fixes:', error.message);
    return -1;
  }
}

/**
 * Main execution function
 */
async function main() {
  console.log('🔧 Type Guard Automation Script');
  console.log('================================');

  // Get initial error count
  console.log('\n📊 Analyzing TypeScript errors...');
  const initialErrors = await validateFixes();
  console.log(`Initial TS18046 errors: ${initialErrors}`);

  if (initialErrors === 0) {
    console.log('✅ No TS18046 errors found!');
    return;
  }

  // Get top error files
  console.log('\n🎯 Identifying high-impact files...');
  const topFiles = await getTopErrorFiles();
  console.log(`Found ${topFiles.length} files with the most errors`);

  // Process each file
  let processedCount = 0;
  let modifiedCount = 0;

  for (const filePath of topFiles) {
    console.log(`\n📝 Processing: ${filePath}`);

    try {
      const modified = await applyTypeGuards(filePath);
      processedCount++;

      if (modified) {
        modifiedCount++;
        console.log(`  ✓ Modified and saved`);
      } else {
        console.log(`  ⏭️  No changes needed`);
      }
    } catch (error) {
      console.error(`  ❌ Error: ${error.message}`);
    }
  }

  // Validate results
  console.log('\n🔍 Validating fixes...');
  const finalErrors = await validateFixes();
  const errorsReduced = initialErrors - finalErrors;

  console.log('\n📈 Results Summary:');
  console.log(`===================`);
  console.log(`Files processed: ${processedCount}`);
  console.log(`Files modified: ${modifiedCount}`);
  console.log(`Errors reduced: ${errorsReduced}`);
  console.log(`Initial errors: ${initialErrors}`);
  console.log(`Remaining errors: ${finalErrors}`);
  console.log(`Reduction percentage: ${((errorsReduced / initialErrors) * 100).toFixed(1)}%`);

  if (errorsReduced > 0) {
    console.log('\n✅ Type guard automation completed successfully!');
    console.log('💡 Run the script again to continue processing remaining files.');
  } else {
    console.log('\n⚠️  No errors were reduced in this run.');
    console.log('💡 Consider manually reviewing the remaining errors.');
  }
}

// Run the script
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}

export { applyTypeGuards, getTopErrorFiles, validateFixes };