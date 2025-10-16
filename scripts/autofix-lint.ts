#!/usr/bin/env tsx
/**
 * Intelligent Autofix for TypeScript ESLint Errors
 *
 * Fixes common patterns:
 * 1. Untyped pool.query() → pool.query<T>()
 * 2. Missing interface definitions for DB rows
 * 3. Unsafe any access → proper type guards
 *
 * Usage: npm run autofix
 */

import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { glob } from 'glob';

interface Fix {
  file: string;
  pattern: RegExp;
  replacement: string | ((match: string, ...args: string[]) => string);
  description: string;
}

const fixes: Fix[] = [
  // Fix 1: Add type to pool.query for metadata queries
  {
    file: 'src/services/**/*.ts',
    pattern: /pool\.query\('SELECT \* FROM _purge_metadata WHERE id = 1'\)/g,
    replacement: "pool.query<PurgeMetadata>('SELECT * FROM _purge_metadata WHERE id = 1')",
    description: 'Add PurgeMetadata type to purge queries'
  },

  // Fix 2: Add type guard for row access
  {
    file: 'src/**/*.ts',
    pattern: /const meta = result\.rows\[0\];(\s+)\/\/ Check if purge is enabled/g,
    replacement: (match, whitespace) =>
      `const meta = result.rows[0];${whitespace}if (!meta) return;${whitespace}// Check if purge is enabled`,
    description: 'Add null check for database rows'
  },

  // Fix 3: Type error callbacks
  {
    file: 'src/**/*.ts',
    pattern: /\.catch\(\(err\) =>/g,
    replacement: '.catch((err: unknown) =>',
    description: 'Type error parameters as unknown'
  },

  // Fix 4: Add await to async handlers
  {
    file: 'src/index.ts',
    pattern: /server\.setRequestHandler\(ListToolsRequestSchema, async \(\) => \(\{/g,
    replacement: 'server.setRequestHandler(ListToolsRequestSchema, () => ({',
    description: 'Remove unnecessary async from non-async handlers'
  }
];

async function autofixFile(filePath: string, fixes: Fix[]): Promise<number> {
  let content = readFileSync(filePath, 'utf8');
  let fixCount = 0;

  for (const fix of fixes) {
    const before = content;
    if (typeof fix.replacement === 'string') {
      content = content.replace(fix.pattern, fix.replacement);
    } else {
      content = content.replace(fix.pattern, fix.replacement);
    }

    if (content !== before) {
      fixCount++;
      console.log(`  ✓ ${fix.description}`);
    }
  }

  if (fixCount > 0) {
    writeFileSync(filePath, content, 'utf8');
  }

  return fixCount;
}

async function main() {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('INTELLIGENT AUTOFIX');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  let totalFixes = 0;

  // Get all TypeScript files
  const files = await glob('src/**/*.ts', { cwd: process.cwd(), absolute: true });

  for (const file of files) {
    const relativePath = file.replace(process.cwd(), '.');
    const applicableFixes = fixes.filter(f => {
      const pattern = f.file.replace('**', '.*').replace('*', '[^/]*');
      const regex = new RegExp(pattern);
      return regex.test(relativePath);
    });

    if (applicableFixes.length > 0) {
      const fileFixCount = await autofixFile(file, applicableFixes);
      if (fileFixCount > 0) {
        console.log(`\n📝 ${relativePath}`);
        totalFixes += fileFixCount;
      }
    }
  }

  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`✅ Applied ${totalFixes} automatic fixes`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  if (totalFixes > 0) {
    console.log('Run: npm run lint -- to verify fixes');
    console.log('Run: npm run build to verify compilation');
  } else {
    console.log('No automatic fixes needed.');
  }
}

main().catch(console.error);
