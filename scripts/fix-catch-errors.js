#!/usr/bin/env node

/**
 * Fix Catch Error Variables Script
 *
 * Fixes catch blocks where the script broke error variable references
 */

import fs from 'fs';
import path from 'path';

console.log('🔧 Fixing catch block error variable issues...');

// Get all TypeScript files that might have been affected
const allTsFiles = [];
function findTsFiles(dir) {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory() && !file.startsWith('.') && file !== 'node_modules') {
      findTsFiles(fullPath);
    } else if (file.endsWith('.ts')) {
      allTsFiles.push(fullPath);
    }
  }
}

findTsFiles('src');
findTsFiles('tests');

console.log(`Checking ${allTsFiles.length} files for catch block issues...`);

let totalFixed = 0;

for (const file of allTsFiles) {
  try {
    let content = fs.readFileSync(file, 'utf8');
    let modified = false;

    // Fix pattern: catch (_error) { ... error. ... }
    content = content.replace(
      /catch\s*\(\s*_error\s*\)\s*{([^}]*?)error\.([^}]*?)}/g,
      (match, blockContent, property) => {
        // Replace error references with _error
        const fixedBlock = blockContent.replace(/error\./g, '_error.');
        return `catch (_error) {${fixedBlock}}`;
      }
    );

    // Fix pattern: catch (_error) { ... error instanceof ... }
    content = content.replace(
      /catch\s*\(\s*_error\s*\)\s*{([^}]*?)error\s+instanceof([^}]*?)}/g,
      (match, blockContent) => {
        // Replace error references with _error
        const fixedBlock = blockContent.replace(/error\s+instanceof/g, '_error instanceof');
        return `catch (_error) {${fixedBlock}}`;
      }
    );

    // Fix pattern: catch (_error) { ... String(error) ... }
    content = content.replace(
      /catch\s*\(\s*_error\s*\)\s*{([^}]*?)String\(error\)}/g,
      (match, blockContent) => {
        // Replace error references with _error
        const fixedBlock = blockContent.replace(/String\(error\)/g, 'String(_error)');
        return `catch (_error) {${fixedBlock}}`;
      }
    );

    // Fix response references in src files
    content = content.replace(/const\s+_result\s*=\s*[^;]*;[\s\S]*?response\./g, (match) =>
      match.replace(/response\./g, '_result.')
    );

    if (modified || content !== fs.readFileSync(file, 'utf8')) {
      fs.writeFileSync(file, content);
      console.log(`✅ Fixed: ${file}`);
      totalFixed++;
    }
  } catch (error) {
    console.log(`❌ Error checking ${file}: ${error.message}`);
  }
}

console.log(`\n✅ Catch block error fix completed! Fixed ${totalFixed} files.`);
console.log('\n📝 Next steps:');
console.log('   1. Run: npm run lint');
console.log('   2. Check remaining errors');
