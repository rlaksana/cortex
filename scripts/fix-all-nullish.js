#!/usr/bin/env node

/**
 * Fix all nullish coalescing issues by replacing || with ??
 * Uses a systematic approach to identify and fix patterns safely
 */

import fs from 'fs';
import path from 'path';

console.log('🔧 Fixing all nullish coalescing issues...');

// Files that commonly have nullish coalescing issues
const filesToCheck = [
  'src/db/migrate.ts',
  'src/db/prisma.ts',
  'src/services/filters/scope-filter.ts',
  'src/services/graph-traversal.ts',
  'src/services/memory-find.ts',
  'src/services/similarity.ts',
  'src/utils/logger.ts',
  'src/utils/scope.ts',
  'src/utils/snippet.ts',
  'src/config/environment.ts',
  'src/schemas/enhanced-validation.ts'
];

let totalFixes = 0;

filesToCheck.forEach(filePath => {
  if (!fs.existsSync(filePath)) {
    console.log(`⚠️  File not found: ${filePath}`);
    return;
  }

  try {
    let content = fs.readFileSync(filePath, 'utf8');
    const originalContent = content;

    // Fix nullish coalescing patterns
    // Pattern 1: variable || defaultValue -> variable ?? defaultValue
    content = content.replace(/(\w+(?:\.\w+)*(?:\[\w+\])?)\s*\|\|\s*([^,\)\];}]+?)(?=[,\)\];}]|$)/g, '$1 ?? $2');

    // Pattern 2: this.property || defaultValue -> this.property ?? defaultValue
    content = content.replace(/(this\.\w+(?:\(\))?|\w+\[\w+\])\s*\|\|\s*([^,\)\];}]+?)(?=[,\)\];}]|$)/g, '$1 ?? $2');

    // Pattern 3: expression || {} -> expression ?? {}
    content = content.replace(/(\w+(?:\.\w+)*(?:\[\w+\])?)\s*\|\|\s*\{[^}]*\}/g, '$1 ?? {}');

    // Pattern 4: expression || "" -> expression ?? ""
    content = content.replace(/(\w+(?:\.\w+)*(?:\[\w+\])?)\s*\|\|\s*["'][^"']*["']/g, '$1 ?? $2');

    if (content !== originalContent) {
      fs.writeFileSync(filePath, content);
      const changes = (content.match(/\?\?/g) || []).length - (originalContent.match(/\?\?/g) || []).length;
      totalFixes += Math.max(0, changes);
      console.log(`  ✅ Fixed ${filePath} (${changes} changes)`);
    } else {
      console.log(`  ℹ️  No changes needed for ${filePath}`);
    }
  } catch (error) {
    console.error(`  ❌ Error processing ${filePath}:`, error.message);
  }
});

console.log(`\n🎉 Completed! Total fixes applied: ${totalFixes}`);