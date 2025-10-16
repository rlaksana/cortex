#!/usr/bin/env node

/**
 * TARGETED LOGGER PATTERN FIX
 *
 * Fixes specific logger patterns found in the codebase:
 * Pattern: logger.info('message', { data }) → logger.info({ data }, 'message')
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
};

const success = (msg) => console.log(`${colors.green}✅ ${msg}${colors.reset}`);
const info = (msg) => console.log(`${colors.cyan}🔍 ${msg}${colors.reset}`);

// Files that need logger fixes
const targetFiles = [
  'src/db/migrate.ts',
  'src/db/pool.ts',
  'src/config/environment.ts'
];

// Specific logger patterns to fix
const patterns = [
  // Pattern: logger.info('message', { data })
  {
    regex: /logger\.(info|warn|error|debug|fatal|trace)\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*(\{[^}]*\})\s*\)/gs,
    replacement: 'logger.$1($3, "$2")',
  },
  // Pattern: logger.info('message', error)
  {
    regex: /logger\.(info|warn|error|debug|fatal|trace)\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*([^)]+)\s*\)/gs,
    replacement: 'logger.$1({ error: $3 }, "$2")',
  },
  // Pattern: logger.error('message', unknown)
  {
    regex: /logger\.(error|warn|info|debug|fatal|trace)\s*\(\s*["'`]([^"'`]+):?["'`]?\s*,\s*([^)]+)\s*\)/gs,
    replacement: 'logger.$1({ data: $3 }, "$2")',
  }
];

function fixFile(filePath) {
  try {
    const content = readFileSync(join(projectRoot, filePath), 'utf8');
    let modifiedContent = content;
    let changesMade = 0;

    for (const pattern of patterns) {
      const before = modifiedContent;
      modifiedContent = modifiedContent.replace(pattern.regex, pattern.replacement);
      const changes = modifiedContent !== before;
      if (changes) {
        const matches = before.match(pattern.regex);
        changesMade += matches ? matches.length : 0;
        info(`  Fixed ${matches ? matches.length : 0} occurrences`);
      }
    }

    if (changesMade > 0) {
      writeFileSync(join(projectRoot, filePath), modifiedContent, 'utf8');
      success(`Fixed ${changesMade} logger patterns in ${filePath}`);
    } else {
      info(`  No changes needed`);
    }

    return changesMade;
  } catch (err) {
    console.error(`Error processing ${filePath}:`, err.message);
    return 0;
  }
}

function main() {
  console.log(`${colors.bright}🔧 TARGETED LOGGER PATTERN FIX${colors.reset}\n`);

  let totalChanges = 0;
  let filesFixed = 0;

  for (const file of targetFiles) {
    console.log(`${colors.cyan}Processing:${colors.reset} ${file}`);
    const changes = fixFile(file);
    if (changes > 0) {
      totalChanges += changes;
      filesFixed++;
    }
    console.log('');
  }

  console.log(`${colors.bright}📊 SUMMARY${colors.reset}`);
  console.log(`Files processed: ${targetFiles.length}`);
  console.log(`Files fixed: ${filesFixed}`);
  console.log(`Total changes: ${totalChanges}`);

  if (totalChanges > 0) {
    console.log(`\n${colors.green}✨ Logger patterns fixed!${colors.reset}`);
    console.log(`${colors.cyan}📝 Next steps:${colors.reset}`);
    console.log('  1. Run: npm run build');
    console.log('  2. Run: npm run lint:fix');
  } else {
    console.log(`\n${colors.yellow}No logger patterns found to fix${colors.reset}`);
  }
}

// Run the script
main();