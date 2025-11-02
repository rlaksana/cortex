#!/usr/bin/env node

/**
 * Comprehensive Syntax Fix Script
 *
 * This script systematically fixes common syntax errors across the codebase:
 * 1. Array type declarations: ValidationError[] = [] -> ValidationError[] = []
 * 2. Type annotations: config: Type, -> config: Type;
 * 3. Import statements: import from 'module', -> import from 'module';
 * 4. Object properties: prop = value, -> prop: value,
 * 5. Type exports: export type T = ..., -> export type T = ...;
 * 6. Parameter types: param, Type -> param: Type
 */

const fs = require('fs');
const path = require('path');

function fixFile(filePath) {
  try {
    let content = fs.readFileSync(filePath, 'utf8');
    let modified = false;

    // Fix 1: Array type declarations with commas
    content = content.replace(/(\w+)\[\]\s*=\s*\[\],/g, '$1[] = [];');

    // Fix 2: Type annotations ending with comma instead of semicolon
    content = content.replace(/(\w+):\s*([^,}\n]+),/g, '$1: $2;');

    // Fix 3: Import statements ending with comma
    content = content.replace(/import\s+.*?\s+from\s+['"][^'"]+['"],/g, (match) =>
      match.replace(/,$/, ';')
    );

    // Fix 4: Property assignments with colon instead of semicolon in objects
    content = content.replace(/(\w+):\s*([^,}\n]+),/g, (match, prop, value) => {
      // Don't fix if it looks like a type annotation in interface or type
      if (match.includes('interface') || match.includes('type') || match.includes('extends')) {
        return match;
      }
      return `${prop}: ${value},`;
    });

    // Fix 5: Parameter type annotations with comma (simplified)
    content = content.replace(/\(\s*(\w+),\s*(\w+(?:\[\])?)\s*\)/g, '($1: $2)');

    // Fix 6: Class property type annotations with comma
    content = content.replace(/(private|public|protected)\s+(\w+):\s*([^,;\n]+),/g, '$1 $2: $3;');

    // Fix 7: Object property assignment vs type annotation
    content = content.replace(/(\w+):\s*([^,;\n]+),/g, (match, prop, value) => {
      // Check if this is in a type definition context
      const lines = content.split('\n');
      const currentLineIndex = lines.findIndex((line) => line.includes(match));
      if (currentLineIndex === -1) return match;

      const context = lines
        .slice(Math.max(0, currentLineIndex - 5), currentLineIndex + 5)
        .join('\n');

      // If in type definition context, keep as type annotation
      if (
        context.includes('interface ') ||
        context.includes('type ') ||
        context.includes('extends ') ||
        context.includes('implements ')
      ) {
        return match;
      }

      // Otherwise, it might be object property assignment, keep comma
      return match;
    });

    // Fix 8: Variable assignments with colon
    content = content.replace(/const\s+(\w+)\s*:\s*([^=;,]+),/g, 'const $1: $2 =');

    // Fix 9: Fix specific patterns
    content = content.replace(/minLength\s*=\s*(\d+)/g, 'minLength: $1');
    content = content.replace(/message\s*=\s*(`[^`]*`)/g, 'message: $1');
    content = content.replace(
      /errors:\s*ValidationError\[\]\s*=\s*\[\],/g,
      'errors: ValidationError[] = [];'
    );
    content = content.replace(
      /warnings:\s*ValidationError\[\]\s*=\s*\[\],/g,
      'warnings: ValidationError[] = [];'
    );

    // Fix 10: Method parameter type annotations
    content = content.replace(/(\w+),\s*(\w+(?:\[\])?)\s*=>/g, '$1: $2 =>');

    // Fix 11: Object literal property shorthand
    content = content.replace(/\{\s*(\w+),\s*\}/g, '{ $1 }');

    if (content !== fs.readFileSync(filePath, 'utf8')) {
      fs.writeFileSync(filePath, content);
      console.log(`✓ Fixed ${filePath}`);
      return true;
    }

    return false;
  } catch (error) {
    console.error(`Error processing ${filePath}:`, error.message);
    return false;
  }
}

function findTypeScriptFiles(dir) {
  const files = [];

  function traverse(currentDir) {
    const items = fs.readdirSync(currentDir);

    for (const item of items) {
      const fullPath = path.join(currentDir, item);
      const stat = fs.statSync(fullPath);

      if (stat.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
        traverse(fullPath);
      } else if (item.endsWith('.ts') && !item.endsWith('.d.ts')) {
        files.push(fullPath);
      }
    }
  }

  traverse(dir);
  return files;
}

// Main execution
const srcDir = path.join(process.cwd(), 'src');
const tsFiles = findTypeScriptFiles(srcDir);

console.log(`Found ${tsFiles.length} TypeScript files to check...`);

let fixedCount = 0;
for (const file of tsFiles) {
  if (fixFile(file)) {
    fixedCount++;
  }
}

console.log(`\nComplete! Fixed ${fixedCount} files.`);
