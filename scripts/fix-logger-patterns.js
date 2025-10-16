#!/usr/bin/env node

/**
 * AUTOFIX SCRIPT - LOGGER PATTERN CONVERSION
 *
 * Automatically fixes Pino logger interface patterns:
 * FROM: logger.info("message", { data })
 * TO:   logger.info({ data }, "message")
 *
 * Usage: node scripts/fix-logger-patterns.js [--dry-run]
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
const error = (msg) => console.log(`${colors.red}❌ ${msg}${colors.reset}`);
const info = (msg) => console.log(`${colors.cyan}🔍 ${msg}${colors.reset}`);
const warning = (msg) => console.log(`${colors.yellow}⚠️  ${msg}${colors.reset}`);

// Logger method patterns to fix
const loggerPatterns = [
  // Pattern: logger.method("message", { object })
  {
    regex: /logger\.(info|warn|error|debug|fatal|trace)\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*(\{[^}]*\})\s*\)/g,
    replacement: 'logger.$1($3, "$2")',
    description: 'Message first, object second'
  },
  // Pattern: logger.method("message", data) where data is variable
  {
    regex: /logger\.(info|warn|error|debug|fatal|trace)\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*([^,)]+)\s*\)/g,
    replacement: 'logger.$1({ data: $3 }, "$2")',
    description: 'Message first, variable second'
  },
  // Pattern: logger.method(variable, { object })
  {
    regex: /logger\.(info|warn|error|debug|fatal|trace)\s*\(\s*([^,)]+)\s*,\s*(\{[^}]*\})\s*\)/g,
    replacement: 'logger.$1($2, $3)',
    description: 'Variable first, object second (already correct)'
  }
];

function findLoggerFiles(directory) {
  const files = [];

  function scan(dir) {
    const items = readdirSync(dir);

    for (const item of items) {
      const fullPath = join(dir, item);
      const stat = statSync(fullPath);

      if (stat.isDirectory() && !item.startsWith('.') && item !== 'node_modules' && item !== 'dist') {
        scan(fullPath);
      } else if (item.endsWith('.ts') && !item.includes('.d.ts')) {
        files.push(fullPath);
      }
    }
  }

  scan(directory);
  return files;
}

function fixFile(filePath, dryRun = false) {
  try {
    const content = readFileSync(filePath, 'utf8');
    let modifiedContent = content;
    let changesMade = 0;

    for (const pattern of loggerPatterns) {
      const matches = modifiedContent.match(pattern.regex);
      if (matches) {
        modifiedContent = modifiedContent.replace(pattern.regex, pattern.replacement);
        changesMade += matches.length;
        info(`  Fixed ${matches.length} occurrences of ${pattern.description}`);
      }
    }

    if (changesMade > 0 && !dryRun) {
      writeFileSync(filePath, modifiedContent, 'utf8');
      success(`Fixed ${changesMade} logger patterns in ${filePath}`);
    } else if (changesMade > 0 && dryRun) {
      warning(`Would fix ${changesMade} logger patterns in ${filePath}`);
    } else {
      info(`  No logger pattern fixes needed`);
    }

    return changesMade;
  } catch (err) {
    error(`Error processing ${filePath}: ${err.message}`);
    return 0;
  }
}

function main() {
  const args = process.argv.slice(2);
  const dryRun = args.includes('--dry-run');

  console.log(`${colors.bright}🔧 LOGGER PATTERN AUTOFIX TOOL${colors.reset}\n`);

  if (dryRun) {
    warning('DRY RUN MODE - No files will be modified\n');
  } else {
    warning('LIVE MODE - Files will be modified\n');
  }

  const srcDir = join(projectRoot, 'src');
  const files = findLoggerFiles(srcDir);

  if (files.length === 0) {
    error('No TypeScript files found to process');
    process.exit(1);
  }

  info(`Found ${files.length} TypeScript files to check`);
  console.log('');

  let totalChanges = 0;
  let filesWithChanges = 0;

  for (const file of files) {
    console.log(`${colors.cyan}Processing:${colors.reset} ${file}`);
    const changes = fixFile(file, dryRun);

    if (changes > 0) {
      totalChanges += changes;
      filesWithChanges++;
    }
    console.log('');
  }

  console.log(`${colors.bright}📊 SUMMARY${colors.reset}`);
  console.log(`Files processed: ${files.length}`);
  console.log(`Files with changes: ${filesWithChanges}`);
  console.log(`Total pattern fixes: ${totalChanges}`);

  if (dryRun) {
    console.log(`\n${colors.yellow}💡 Run without --dry-run to apply these fixes${colors.reset}`);
  } else {
    console.log(`\n${colors.green}✨ All logger patterns have been converted!${colors.reset}`);
    console.log(`${colors.cyan}📝 Next steps:${colors.reset}`);
    console.log('  1. Run: npm run build');
    console.log('  2. Run: npm run lint:fix');
    console.log('  3. Test with: npm run dev');
  }
}

// Check if this script is being run directly
const isMainModule = import.meta.url === `file://${process.argv[1]}`;

if (isMainModule) {
  main();
}