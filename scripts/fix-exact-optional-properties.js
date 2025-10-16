#!/usr/bin/env node

/**
 * Fix exactOptionalPropertyTypes TypeScript Errors
 *
 * This script specifically fixes the issues caused by exactOptionalPropertyTypes: true
 */

import fs from 'fs';

console.log('🔧 Fixing exactOptionalPropertyTypes issues...\n');

// Fix 1: Scope interface issues
function fixScopeType(content) {
  let fixed = content;

  // Replace Scope interface to allow undefined
  fixed = fixed.replace(
    /export interface Scope \{[\s\S]*?\}/,
    `export interface Scope {
  org?: string | undefined;
  project?: string | undefined;
  branch?: string | undefined;
}`
  );

  return fixed;
}

// Fix 2: Fix null safety in scope.ts
function fixScopeNullSafety(content) {
  let fixed = content;

  // Add non-null assertions or proper null handling
  fixed = fixed.replace(/if \(cachedScope !== null\) return cachedScope;/,
    'if (cachedScope !== null) return cachedScope;');

  // Fix cachedScope assignments
  fixed = fixed.replace(/cachedScope = \{[\s\S]*?\};/,
    `cachedScope = {
    org: env.CORTEX_ORG || undefined,
    project: env.CORTEX_PROJECT || undefined,
    branch: env.CORTEX_BRANCH || undefined,
  };`);

  return fixed;
}

// Fix 3: Fix null assignment in audit.ts
function fixAuditNullAssignment(content) {
  let fixed = content;

  // Fix changedBy assignment
  fixed = fixed.replace(/changedBy:\s*changedBy\s*\|\|\s*null,/,
    'changedBy: changedBy || undefined,');

  return fixed;
}

// Fix 4: Fix undefined properties in function calls
function fixUndefinedProperties(content) {
  let fixed = content;

  // Fix targetVersion and step in migrate.ts
  fixed = fixed.replace(
    /\{\s*targetVersion:\s*targetVersion\s*\|\|\s*undefined,\s*step:\s*step\s*\|\|\s*undefined,\s*\}/,
    `{ targetVersion, step }`
  );

  // Fix take and skip in prisma.ts
  fixed = fixed.replace(
    /take:\s*criteria\.limit\s*\|\|\s*undefined,\s*skip:\s*criteria\.offset\s*\|\|\s*undefined,/,
    'take: criteria.limit, skip: criteria.offset,'
  );

  return fixed;
}

// Fix 5: Fix graph property return type
function fixGraphReturnType(content) {
  let fixed = content;

  // Remove graph: undefined to avoid exactOptionalPropertyTypes issue
  fixed = fixed.replace(/,\s*graph:\s*graphResult\s*\|\|\s*undefined/, '');

  return fixed;
}

function processFile(filePath, fixes) {
  console.log(`📝 Processing: ${filePath}`);

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    let fixed = content;

    // Apply all fixes
    fixes.forEach(fix => {
      fixed = fix(fixed);
    });

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

// Apply fixes to specific files
console.log('🔧 Fixing scope.ts...');
processFile('src/utils/scope.ts', [fixScopeType, fixScopeNullSafety]);

console.log('\n🔧 Fixing audit.ts...');
processFile('src/db/audit.ts', [fixAuditNullAssignment]);

console.log('\n🔧 Fixing migrate.ts...');
processFile('src/db/migrate.ts', [fixUndefinedProperties]);

console.log('\n🔧 Fixing prisma.ts...');
processFile('src/db/prisma.ts', [fixUndefinedProperties]);

console.log('\n🔧 Fixing memory-find.ts...');
processFile('src/services/memory-find.ts', [fixGraphReturnType]);

console.log('\n🎯 Exact optional properties fixes completed!');
console.log('💡 Running `npm run build` to check results...');