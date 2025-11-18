#!/usr/bin/env node

/**
 * Convert Jest test files to Vitest
 * Updates import statements and mock syntax
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');

// Patterns to replace
const replacements = [
  // Import statements
  {
    pattern: /import\s*{\s*([^}]+)\s*}\s*from\s*['"]@jest\/globals['"];?/g,
    replacement: (match, imports) => {
      const cleanImports = imports.replace(/jest/g, 'vi').replace(/\s+/g, ' ').trim();
      return `import { ${cleanImports} } from 'vitest';`;
    }
  },
  {
    pattern: /import\s*{\s*([^}]+)\s*}\s*from\s*['"]jest['"];?/g,
    replacement: (match, imports) => {
      const cleanImports = imports.replace(/jest/g, 'vi').replace(/\s+/g, ' ').trim();
      return `import { ${cleanImports} } from 'vitest';`;
    }
  },
  // Mock statements
  {
    pattern: /jest\.mock\s*\(/g,
    replacement: 'vi.mock('
  },
  {
    pattern: /jest\.unmock\s*\(/g,
    replacement: 'vi.unmock('
  },
  {
    pattern: /jest\.fn\s*\(/g,
    replacement: 'vi.fn('
  },
  {
    pattern: /jest\.spyOn\s*\(/g,
    replacement: 'vi.spyOn('
  },
  // Mock function calls
  {
    pattern: /\.mockRejectedValueOnce\s*\(/g,
    replacement: '.mockRejectedValueOnce('
  },
  {
    pattern: /\.mockResolvedValueOnce\s*\(/g,
    replacement: '.mockResolvedValueOnce('
  },
  {
    pattern: /\.mockRejectedValue\s*\(/g,
    replacement: '.mockRejectedValue('
  },
  {
    pattern: /\.mockResolvedValue\s*\(/g,
    replacement: '.mockResolvedValue('
  },
  {
    pattern: /\.mockReturnValue\s*\(/g,
    replacement: '.mockReturnValue('
  },
  {
    pattern: /\.mockReturnValueOnce\s*\(/g,
    replacement: '.mockReturnValueOnce('
  },
  {
    pattern: /\.mockImplementation\s*\(/g,
    replacement: '.mockImplementation('
  },
  {
    pattern: /\.mockImplementationOnce\s*\(/g,
    replacement: '.mockImplementationOnce('
  },
  // File extensions in imports
  {
    pattern: /from\s*['"]([^'"]+)\.js['"]/g,
    replacement: 'from \'$1\''
  },
  {
    pattern: /vi\.mock\([^,]+,\s*\(\)\s*=>\s*require\(/g,
    replacement: (match) => {
      // This is more complex, skip for now
      return match;
    }
  }
];

function convertFile(filePath) {
  try {
    let content = fs.readFileSync(filePath, 'utf8');
    let changed = false;

    for (const { pattern, replacement } of replacements) {
      const originalContent = content;
      if (typeof replacement === 'string') {
        content = content.replace(pattern, replacement);
      } else {
        content = content.replace(pattern, replacement);
      }
      if (content !== originalContent) {
        changed = true;
      }
    }

    // Handle complex require statements in mocks (manual fix needed)
    content = content.replace(
      /vi\.mock\(([^,]+),\s*\(\)\s*=>\s*require\(([^)]+)\)\)/g,
      (match, mockPath, requirePath) => {
        return `vi.mock(${mockPath}, () => ({ default: ${requirePath} }))`;
      }
    );

    if (changed) {
      fs.writeFileSync(filePath, content);
      console.log(`✅ Converted: ${filePath}`);
      return true;
    }
    return false;
  } catch (error) {
    console.error(`❌ Error converting ${filePath}:`, error.message);
    return false;
  }
}

function findTestFiles(dir) {
  const testFiles = [];

  function traverse(currentDir) {
    try {
      const entries = fs.readdirSync(currentDir);

      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry);
        const stat = fs.statSync(fullPath);

        if (stat.isDirectory() && !entry.startsWith('.') && entry !== 'node_modules') {
          traverse(fullPath);
        } else if (stat.isFile() && (entry.endsWith('.test.ts') || entry.endsWith('.spec.ts'))) {
          testFiles.push(fullPath);
        }
      }
    } catch (error) {
      // Skip directories we can't read
    }
  }

  traverse(dir);
  return testFiles;
}

function main() {
  const srcDir = path.join(projectRoot, 'src');
  const testFiles = findTestFiles(srcDir);

  console.log(`Found ${testFiles.length} test files to convert...`);

  let convertedCount = 0;
  for (const file of testFiles) {
    if (convertFile(file)) {
      convertedCount++;
    }
  }

  console.log(`\nConversion complete!`);
  console.log(`✅ Converted: ${convertedCount} files`);
  console.log(`⚪ Skipped: ${testFiles.length - convertedCount} files`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { convertFile, findTestFiles };