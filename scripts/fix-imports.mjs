#!/usr/bin/env node

import { readFileSync, writeFileSync, readdirSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Post-build fixer for ESM: ensures relative import/export specifiers include .js
 * Works on dist output so TS source may remain extensionless.
 */

function fixDynamicImports(dir = 'dist') {
  console.log('🔧 Fixing imports/exports in dist files...');

  const distPath = join(__dirname, '..', dir);

  function findJsFiles(currentPath) {
    const results = [];
    const items = readdirSync(currentPath);
    for (const item of items) {
      const fullPath = join(currentPath, item);
      const stat = statSync(fullPath);
      if (stat.isDirectory()) results.push(...findJsFiles(fullPath));
      else if (item.endsWith('.js')) results.push(fullPath);
    }
    return results;
  }

  const jsFiles = findJsFiles(distPath);
  console.log(`Found ${jsFiles.length} JavaScript files`);

  let fixedCount = 0;
  const isRelative = (p) => p.startsWith('./') || p.startsWith('../');
  const hasKnownExtension = (p) => /\.(mjs|cjs|js|jsx|json)$/i.test(p);

  for (const filePath of jsFiles) {
    try {
      let content = readFileSync(filePath, 'utf-8');
      const originalContent = content;

      // Special-case dynamic import for unified-database-layer-v2
      content = content.replace(
        /import\('([^']*)unified-database-layer-v2'\)/g,
        "import('$1unified-database-layer-v2.js')"
      );

      // Normalize dynamic imports that already have .js (noop)
      content = content.replace(/import\('([^']+\.js)'\)/g, "import('$1')");

      // Static imports
      content = content.replace(/(from\s+['"])([^'\"]+)(['"])/g, (m, pre, p, suf) =>
        !isRelative(p) || hasKnownExtension(p) ? m : `${pre}${p}.js${suf}`
      );

      // Re-exports: export * from '...'
      content = content.replace(/(export\s+\*\s+from\s+['"])([^'\"]+)(['"])/g, (m, pre, p, suf) =>
        !isRelative(p) || hasKnownExtension(p) ? m : `${pre}${p}.js${suf}`
      );

      // Re-exports: export { X } from '...'
      content = content.replace(
        /(export\s+\{[^}]*\}\s+from\s+['"])([^'\"]+)(['"])/g,
        (m, pre, p, suf) => (!isRelative(p) || hasKnownExtension(p) ? m : `${pre}${p}.js${suf}`)
      );

      // Dynamic imports generic
      content = content.replace(/import\(\s*['"]([^'\"]+)['"]\s*\)/g, (m, p) =>
        !isRelative(p) || hasKnownExtension(p) ? m : `import('${p}.js')`
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

  console.log(`\n🎉 Fixed import/export specifiers in ${fixedCount} files`);
  return fixedCount;
}

// Run the fix if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  fixDynamicImports();
}

export { fixDynamicImports };
