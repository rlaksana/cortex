#!/usr/bin/env node

/**
 * Systematic TypeScript Strict Mode Fixes
 *
 * This script fixes the most common TypeScript strict mode issues:
 * 1. Exact optional property types (undefined vs null)
 * 2. Unknown error type handling
 * 3. Null safety and type guards
 */

import fs from 'fs';
import path from 'path';

const FILES_TO_FIX = [
  'src/db/prisma.ts',
  'src/services/memory-find.ts',
  'src/services/similarity.ts'
];

console.log('🔧 Applying systematic TypeScript strict mode fixes...\n');

// Fix 1: Replace undefined with null for optional properties where appropriate
function fixOptionalProperties(content) {
  let fixed = content;

  // Replace undefined with null for optional string properties
  fixed = fixed.replace(/bodyMd:\s*string\s*\|\s*undefined/g, 'bodyMd: string | null');
  fixed = fixed.replace(/bodyText:\s*string\s*\|\s*undefined/g, 'bodyText: string | null');
  fixed = fixed.replace(/content_hash:\s*string\s*\|\s*undefined/g, 'content_hash: string');

  // Fix undefined values in object creation
  fixed = fixed.replace(/changedBy:\s*changedBy,/g, 'changedBy: changedBy || null,');

  // Fix undefined values passed to functions
  fixed = fixed.replace(/targetVersion:\s*targetVersion,/g, 'targetVersion: targetVersion || undefined,');
  fixed = fixed.replace(/step:\s*step,/g, 'step: step || undefined,');

  return fixed;
}

// Fix 2: Add proper error type guards
function fixErrorHandling(content) {
  let fixed = content;

  // Add type guard for unknown error types
  fixed = fixed.replace(
    /error:\s*error\.message/g,
    'error: error instanceof Error ? error.message : String(error)'
  );

  // Add proper error type annotations
  fixed = fixed.replace(/\bcatch\s*\(\s*error\s*\)/g, 'catch (error: unknown)');
  fixed = fixed.replace(/function\s*\([^)]*error[^)]*\)/g, (match) => {
    if (!match.includes(':')) {
      return match.replace('error', 'error: unknown');
    }
    return match;
  });

  return fixed;
}

// Fix 3: Fix null safety issues
function fixNullSafety(content) {
  let fixed = content;

  // Add proper null checks
  fixed = fixed.replace(/if\s*\(\s*cachedScope\s*\)/g, 'if (cachedScope !== null)');
  fixed = fixed.replace(/if\s*\(\s*!\s*cachedScope\.\w+\s*\)/g, (match) => {
    const prop = match.match(/!\s*(cachedScope\.\w+)/)?.[1];
    return `if (${prop} === undefined || ${prop} === '')`;
  });

  return fixed;
}

// Fix 4: Fix array and type safety issues
function fixArrayTypes(content) {
  let fixed = content;

  // Fix any[] returns
  fixed = fixed.replace(/return\s*\[\s*\.\.\.\w+\s*\]/g, 'return [...$&]');

  // Fix undefined values in arrays
  fixed = fixed.replace(/\[\s*\.\.\.\w+\s*\|\s*undefined\s*\]/g, '[...$&]');

  return fixed;
}

function processFile(filePath) {
  console.log(`📝 Processing: ${filePath}`);

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    let fixed = content;

    // Apply all fixes
    fixed = fixOptionalProperties(fixed);
    fixed = fixErrorHandling(fixed);
    fixed = fixNullSafety(fixed);
    fixed = fixArrayTypes(fixed);

    if (fixed !== content) {
      fs.writeFileSync(filePath, fixed);
      console.log(`  ✅ Fixed issues in ${filePath}`);
    } else {
      console.log(`  ℹ️  No changes needed for ${filePath}`);
    }
  } catch (error) {
    console.error(`  ❌ Error processing ${filePath}:`, error.message);
  }
}

// Process all files
FILES_TO_FIX.forEach(processFile);

console.log('\n🎯 TypeScript strict mode fixes completed!');
console.log('💡 Next steps:');
console.log('   1. Run `npm run build` to check for remaining errors');
console.log('   2. Address any remaining type issues manually');
console.log('   3. Run `npm run lint` to check code quality');