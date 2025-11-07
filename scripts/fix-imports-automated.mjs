#!/usr/bin/env node

import { readFileSync, writeFileSync, readdirSync, statSync } from 'fs';
import { join, dirname, extname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Fix import extensions in TypeScript source files to prepare for ESM build
 * This eliminates the need for post-build fix scripts
 */

function fixImportExtensions(dir = 'src') {
  console.log('🔧 Fixing import extensions in TypeScript source files...');

  const srcPath = join(__dirname, '..', dir);

  function findTsFiles(currentPath) {
    const results = [];
    const items = readdirSync(currentPath);
    for (const item of items) {
      const fullPath = join(currentPath, item);
      const stat = statSync(fullPath);
      if (stat.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
        results.push(...findTsFiles(fullPath));
      } else if (item.endsWith('.ts')) {
        results.push(fullPath);
      }
    }
    return results;
  }

  const tsFiles = findTsFiles(srcPath);
  console.log(`Found ${tsFiles.length} TypeScript files`);

  // List first few files for debugging
  console.log('Sample files found:');
  tsFiles.slice(0, 5).forEach(file => {
    console.log(`  - ${file}`);
  });

  let fixedCount = 0;
  const isRelative = (p) => p.startsWith('./') || p.startsWith('../');
  const hasJsExtension = (p) => p.endsWith('.js');
  const hasTsExtension = (p) => p.endsWith('.ts');
  const isNodeModule = (p) => p.startsWith('node:') || !p.startsWith('.') && p.includes('/');

  for (const filePath of tsFiles) {
    try {
      let content = readFileSync(filePath, 'utf-8');
      const originalContent = content;

      // Fix static imports: from './module' -> from './module.js'
      content = content.replace(
        /(from\s+['"])([^'"]+)(['"])/g,
        (match, prefix, importPath, suffix) => {
          // Skip if it's already a .js extension
          if (hasJsExtension(importPath)) return match;

          // Skip if it's a .ts extension (shouldn't happen but just in case)
          if (hasTsExtension(importPath)) return match;

          // Only fix relative imports that don't have extensions
          if (isRelative(importPath) && !hasJsExtension(importPath)) {
            return `${prefix}${importPath}.js${suffix}`;
          }

          // Skip node_modules and absolute imports
          return match;
        }
      );

      // Fix re-exports: export * from './module' -> export * from './module.js'
      content = content.replace(
        /(export\s+\*\s+from\s+['"])([^'"]+)(['"])/g,
        (match, prefix, importPath, suffix) => {
          if (hasJsExtension(importPath) || hasTsExtension(importPath)) return match;
          if (isRelative(importPath) && !hasJsExtension(importPath)) {
            return `${prefix}${importPath}.js${suffix}`;
          }
          return match;
        }
      );

      // Fix named re-exports: export { X } from './module' -> export { X } from './module.js'
      content = content.replace(
        /(export\s+\{[^}]*\}\s+from\s+['"])([^'"]+)(['"])/g,
        (match, prefix, importPath, suffix) => {
          if (hasJsExtension(importPath) || hasTsExtension(importPath)) return match;
          if (isRelative(importPath) && !hasJsExtension(importPath)) {
            return `${prefix}${importPath}.js${suffix}`;
          }
          return match;
        }
      );

      // Fix dynamic imports: import('./module') -> import('./module.js')
      content = content.replace(
        /import\(\s*['"]([^'"]+)['"]\s*\)/g,
        (match, importPath) => {
          if (hasJsExtension(importPath) || hasTsExtension(importPath)) return match;
          if (isRelative(importPath) && !hasJsExtension(importPath)) {
            return `import('${importPath}.js')`;
          }
          return match;
        }
      );

      if (content !== originalContent) {
        writeFileSync(filePath, content);
        fixedCount++;
        console.log(`✅ Fixed imports in: ${filePath.replace(process.cwd(), '')}`);
      }
    } catch (error) {
      console.error(`❌ Error processing ${filePath}:`, error.message);
    }
  }

  console.log(`\n🎉 Fixed import extensions in ${fixedCount} files`);
  return fixedCount;
}

// Run the fix if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  fixImportExtensions();
}

export { fixImportExtensions };