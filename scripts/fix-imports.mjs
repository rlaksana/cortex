#!/usr/bin/env node

import { readFileSync, writeFileSync, readdirSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Fix dynamic imports in dist files to include .js extensions
 * This script runs after TypeScript compilation to fix module resolution
 */

function fixDynamicImports(dir = 'dist') {
  console.log('🔧 Fixing dynamic imports in dist files...');

  const distPath = join(__dirname, '..', dir);

  // Find all JavaScript files recursively
  function findJsFiles(currentPath) {
    const results = [];
    const items = readdirSync(currentPath);

    for (const item of items) {
      const fullPath = join(currentPath, item);
      const stat = statSync(fullPath);

      if (stat.isDirectory()) {
        results.push(...findJsFiles(fullPath));
      } else if (item.endsWith('.js') && !item.endsWith('.d.ts')) {
        results.push(fullPath);
      }
    }

    return results;
  }

  const jsFiles = findJsFiles(distPath);
  console.log(`Found ${jsFiles.length} JavaScript files`);

  let fixedCount = 0;

  for (const filePath of jsFiles) {
    try {
      let content = readFileSync(filePath, 'utf-8');
      const originalContent = content;

      // Fix dynamic imports for unified-database-layer-v2
      content = content.replace(
        /import\('([^']*)unified-database-layer-v2'\)/g,
        "import('$1unified-database-layer-v2.js')"
      );

      // Fix other common dynamic imports
      content = content.replace(
        /import\('([^']+\.js)'\)/g,
        "import('$1')"
      );

      // Fix relative imports that don't have extensions
      content = content.replace(
        /import\('([^']+)'\)/g,
        (match, path) => {
          // Skip if already has extension or is node module
          if (path.includes('.') && !path.startsWith('./') && !path.startsWith('../')) {
            return match;
          }

          // Skip if already has .js extension
          if (path.endsWith('.js')) {
            return match;
          }

          // Add .js extension to relative imports
          if (path.startsWith('./') || path.startsWith('../')) {
            return `import('${path}.js')`;
          }

          return match;
        }
      );

      if (content !== originalContent) {
        writeFileSync(filePath, content);
        fixedCount++;
        console.log(`✅ Fixed: ${filePath.replace(process.cwd(), '')}`);
      }
    } catch (error) {
      console.error(`❌ Error processing ${filePath}:`, error.message);
    }
  }

  console.log(`\n🎉 Fixed dynamic imports in ${fixedCount} files`);
  return fixedCount;
}

// Run the fix
console.log('Script executed, checking conditions:', {
  importMeta: import.meta.url,
  argv1: process.argv[1],
  condition: import.meta.url === `file://${process.argv[1]}`
});

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log('Running fixDynamicImports...');
  fixDynamicImports();
} else {
  console.log('Condition not met, running directly...');
  fixDynamicImports();
}

export { fixDynamicImports };