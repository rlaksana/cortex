#!/usr/bin/env node

/**
 * Fix remaining test compilation issues
 */

const fs = require('fs');
const path = require('path');

function processDirectory(dir) {
  const files = fs.readdirSync(dir);

  for (const file of files) {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);

    if (stat.isDirectory() && !file.startsWith('.') && file !== 'node_modules' && file !== 'dist') {
      processDirectory(fullPath);
    } else if (stat.isFile() && (file.endsWith('.test.ts') || file.endsWith('.spec.ts'))) {
      processFile(fullPath);
    }
  }
}

function processFile(filePath) {
  let content = fs.readFileSync(filePath, 'utf8');
  let modified = false;

  // Fix error.message property access
  if (content.includes('error.message') || content.includes('error.name')) {
    content = content.replace(/error\.message/g, '(error as Error).message');
    content = content.replace(/error\.name/g, '(error as Error).name');
    content = content.replace(/error\.stack/g, '(error as Error).stack');
    modified = true;
  }

  // Fix fail() calls
  if (content.includes('fail(')) {
    content = content.replace(/fail\(/g, 'expect.fail(');
    modified = true;
  }

  // Fix import paths with @/ aliases to use proper relative paths
  if (content.includes('@/')) {
    // This is complex and would require knowledge of file structure, skip for now
    // content = content.replace(/from\s+['"]@\/([^'"]+)['"]/g, 'from \'../../$1\'');
  }

  // Add proper type assertions for unknown in catch blocks when specific error types are expected
  if (content.includes('catch (error)')) {
    // Add type assertions where needed
    const lines = content.split('\n');
    let inCatchBlock = false;
    let catchBlockIndent = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.includes('catch (error)')) {
        inCatchBlock = true;
        catchBlockIndent = line.match(/^\s*/)[0].length;
        continue;
      }

      if (inCatchBlock) {
        const currentIndent = line.match(/^\s*/)[0].length;
        if (currentIndent <= catchBlockIndent && line.trim()) {
          inCatchBlock = false;
          continue;
        }

        // Add type assertions in catch blocks
        if (line.includes('error.') && !line.includes('(error as')) {
          lines[i] = line.replace(/error\./g, '(error as Error).');
          modified = true;
        }
      }
    }

    content = lines.join('\n');
  }

  // Fix ServiceLifetime export issues (import from value instead of type)
  if (content.includes('ServiceLifetime')) {
    content = content.replace(
      /import\s*{\s*([^}]*ServiceLifetime[^}]*)\s*}\s*from\s*['"][^'"]*['"];?/g,
      (match, imports) => {
        // Split imports and replace ServiceLifetime with proper import
        const importList = imports.split(',').map(imp => imp.trim());
        const lifetimeIndex = importList.findIndex(imp => imp.includes('ServiceLifetime'));

        if (lifetimeIndex !== -1) {
          // Remove ServiceLifetime from type imports and add it as a value import
          importList.splice(lifetimeIndex, 1);
          const cleanImports = importList.filter(Boolean).join(', ');
          const valueImports = cleanImports ? cleanImports + ', ' : '';
          return `import { ${valueImports}ServiceLifetime } from '${match.match(/from\s*['"]([^'"]+)['"]/)[1]}';`;
        }
        return match;
      }
    );
    modified = true;
  }

  if (modified) {
    fs.writeFileSync(filePath, content);
    console.log(`✅ Fixed: ${filePath}`);
  }
}

const srcDir = path.resolve(__dirname, '../src');
console.log('🔧 Fixing remaining test issues...');
processDirectory(srcDir);
console.log('✅ Done!');