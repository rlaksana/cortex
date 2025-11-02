#!/usr/bin/env node

/**
 * Targeted Syntax Fix Script
 *
 * This script fixes the remaining syntax errors that the comprehensive script missed.
 */

const fs = require('fs');
const path = require('path');

function fixFile(filePath) {
  try {
    let content = fs.readFileSync(filePath, 'utf8');
    let modified = false;

    // Fix 1: Type annotations with semicolons in objects (should be commas)
    content = content.replace(/(\w+):\s*([^,{}\n]+);/g, '$1: $2,');

    // Fix 2: Generic type parameters with semicolons
    content = content.replace(/Map<([^>]+);\s*([^>]+)>/g, 'Map<$1, $2>');
    content = content.replace(/Record<([^>]+);\s*([^>]+)>/g, 'Record<$1, $2>');

    // Fix 3: Array and function type parameters
    content = content.replace(/ValidationError\[\];\s*unknown>/g, 'ValidationError[], unknown>');
    content = content.replace(/string; unknown>/g, 'string, unknown>');

    // Fix 4: Object property assignments with semicolons
    content = content.replace(/(\w+):\s*([^,{}\n]+);/g, (match, prop, value) => {
      // Check if we're in an object literal context
      const lines = content.split('\n');
      const currentLineIndex = lines.findIndex((line) => line.includes(match));
      if (currentLineIndex === -1) return match;

      // Look for object literal context (brace before and assignment)
      let inObjectLiteral = false;
      let braceCount = 0;

      for (let i = currentLineIndex; i >= 0; i--) {
        const line = lines[i].trim();

        if (line.includes('{')) {
          braceCount++;
        }
        if (line.includes('}')) {
          braceCount--;
        }

        // If we find an opening brace without a closing brace, and it looks like an object literal
        if (
          braceCount > 0 &&
          !line.includes('interface') &&
          !line.includes('type') &&
          !line.includes('class')
        ) {
          inObjectLiteral = true;
          break;
        }

        // Stop looking if we hit a function definition, class, interface, or type
        if (
          line.includes('function') ||
          line.includes('class ') ||
          line.includes('interface ') ||
          line.includes('type ')
        ) {
          break;
        }
      }

      if (inObjectLiteral) {
        return match.replace(/;$/, ',');
      }

      return match;
    });

    // Fix 5: Zod schema object properties (should have commas, not semicolons)
    content = content.replace(/z\.object\(\{[^}]*\}/g, (match) => {
      return match.replace(/(\w+):\s*z\.[^;,{}]+;/g, '$1: $2,');
    });

    // Fix 6: Function parameter type annotations
    content = content.replace(/\(([^)]*?)\):\s*([^,;\n]+);/g, '($1): $2');

    // Fix 7: Enum arrays - convert semicolons to commas in arrays
    content = content.replace(/\[([^;'\]]+);/g, '[$1,');

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
