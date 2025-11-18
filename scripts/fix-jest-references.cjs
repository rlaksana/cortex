#!/usr/bin/env node

/**
 * Simple script to replace Jest references with Vitest in test files
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

  // Replace Jest imports
  if (content.includes('@jest/globals')) {
    content = content.replace(
      /import\s*{\s*([^}]+)\s*}\s*from\s*['"]@jest\/globals['"];?/g,
      (match, imports) => {
        const cleanImports = imports.replace(/jest/g, 'vi').replace(/\s+/g, ' ').trim();
        return `import { ${cleanImports} } from 'vitest';`;
      }
    );
    modified = true;
  }

  if (content.includes("'jest'")) {
    content = content.replace(
      /import\s*{\s*([^}]+)\s*}\s*from\s*['"]jest['"];?/g,
      (match, imports) => {
        const cleanImports = imports.replace(/jest/g, 'vi').replace(/\s+/g, ' ').trim();
        return `import { ${cleanImports} } from 'vitest';`;
      }
    );
    modified = true;
  }

  // Replace jest.fn with vi.fn
  if (content.includes('jest.fn')) {
    content = content.replace(/jest\.fn/g, 'vi.fn');
    modified = true;
  }

  // Replace jest.mock with vi.mock
  if (content.includes('jest.mock')) {
    content = content.replace(/jest\.mock/g, 'vi.mock');
    modified = true;
  }

  // Replace jest.clearAllMocks with vi.clearAllMocks
  if (content.includes('jest.clearAllMocks')) {
    content = content.replace(/jest\.clearAllMocks/g, 'vi.clearAllMocks');
    modified = true;
  }

  // Replace jest.restoreAllMocks with vi.restoreAllMocks
  if (content.includes('jest.restoreAllMocks')) {
    content = content.replace(/jest\.restoreAllMocks/g, 'vi.restoreAllMocks');
    modified = true;
  }

  // Replace fail() with expect.fail()
  if (content.includes('fail(')) {
    content = content.replace(/fail\(/g, 'expect.fail(');
    modified = true;
  }

  // Remove .js extensions from imports
  if (content.includes(".js'") || content.includes('.js"')) {
    content = content.replace(/from\s+['"]([^'"]+)\.js['"]/g, "from '$1'");
    modified = true;
  }

  if (modified) {
    fs.writeFileSync(filePath, content);
    console.log(`✅ Fixed: ${filePath}`);
  }
}

const srcDir = path.resolve(__dirname, '../src');
console.log('🔧 Fixing Jest references in test files...');
processDirectory(srcDir);
console.log('✅ Done!');