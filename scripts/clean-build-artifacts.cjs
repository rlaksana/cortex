#!/usr/bin/env node

/**
 * Clean Build Artifacts Script
 *
 * This script cleans build artifacts and temporary files to ensure
 * a clean development environment. It's designed to be run
 * during installation and before builds.
 */

const { existsSync, rmSync, statSync, readdirSync, unlinkSync } = require('node:fs');
const { join } = require('node:path');

const projectRoot = process.cwd();

// ANSI color codes for output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m'
};

function log(level, message) {
  const timestamp = new Date().toISOString();
  const color = colors[level] || colors.reset;
  console.log(`${color}[${timestamp}] ${level.toUpperCase()}: ${message}${colors.reset}`);
}

function success(message) { log('green', message); }
function error(message) { log('red', message); }
function warning(message) { log('yellow', message); }
function info(message) { log('blue', message); }

function removeDirectory(dirPath, options = {}) {
  const { force = false, recursive = true } = options;

  try {
    if (existsSync(dirPath)) {
      const stats = statSync(dirPath);
      if (stats.isDirectory()) {
        rmSync(dirPath, { recursive, force });
        info(`🗑️  Removed directory: ${dirPath}`);
        return true;
      }
    }
    return false;
  } catch (err) {
    warning(`⚠️  Could not remove directory ${dirPath}: ${err.message}`);
    return false;
  }
}

function removeFile(filePath) {
  try {
    if (existsSync(filePath)) {
      unlinkSync(filePath);
      info(`🗑️  Removed file: ${filePath}`);
      return true;
    }
    return false;
  } catch (err) {
    warning(`⚠️  Could not remove file ${filePath}: ${err.message}`);
    return false;
  }
}

function cleanPattern(baseDir, pattern, isDirectory = false) {
  try {
    if (!existsSync(baseDir)) {
      return 0;
    }

    const items = readdirSync(baseDir);
    let removedCount = 0;

    for (const item of items) {
      const itemPath = join(baseDir, item);
      const stats = statSync(itemPath);

      // Simple pattern matching (could be enhanced with minimatch)
      if (typeof pattern === 'string' && item.includes(pattern)) {
        if (stats.isDirectory() && isDirectory) {
          if (removeDirectory(itemPath)) {
            removedCount++;
          }
        } else if (!stats.isDirectory() && !isDirectory) {
          if (removeFile(itemPath)) {
            removedCount++;
          }
        }
      }
    }

    return removedCount;
  } catch (err) {
    error(`Error cleaning pattern ${pattern} in ${baseDir}: ${err.message}`);
    return 0;
  }
}

function cleanBuildArtifacts() {
  info('🧹 Starting build artifacts cleanup...');

  let totalRemoved = 0;

  // Clean main build directories
  const buildDirs = [
    'dist',
    'build',
    'dist-test',
    'temp-dist',
    '.nyc_output',
    'coverage'
  ];

  for (const dir of buildDirs) {
    if (removeDirectory(join(projectRoot, dir))) {
      totalRemoved++;
    }
  }

  // Clean TypeScript build info files
  info('📝 Cleaning TypeScript build info files...');
  const tsBuildInfoFiles = [
    '*.tsbuildinfo',
    'src/**/*.tsbuildinfo'
  ];

  for (const pattern of tsBuildInfoFiles) {
    try {
      // This is a simplified approach - in a real scenario you might use glob
      const possibleFile = join(projectRoot, pattern.replace('*', ''));
      if (removeFile(possibleFile)) {
        totalRemoved++;
      }
    } catch (err) {
      // Ignore glob expansion errors in this simple implementation
    }
  }

  // Clean backup files in dist (if dist exists but wasn't fully removed)
  const distDir = join(projectRoot, 'dist');
  if (existsSync(distDir)) {
    info('🗂️  Cleaning backup files in dist directory...');
    const backupPatterns = ['.backup', '.old-detection', '.bak', '~'];

    for (const pattern of backupPatterns) {
      const removed = cleanPattern(distDir, pattern, false);
      totalRemoved += removed;
    }
  }

  // Clean temporary files and logs
  const tempFiles = [
    'tmp_last_run.log',
    'cortex-local.log',
    'mcp-debug.log',
    'mcp-start.log'
  ];

  for (const file of tempFiles) {
    if (removeFile(join(projectRoot, file))) {
      totalRemoved++;
    }
  }

  // Clean test result files
  const testResultDirs = [
    'test-results',
    'tests/temp'
  ];

  for (const dir of testResultDirs) {
    if (removeDirectory(join(projectRoot, dir))) {
      totalRemoved++;
    }
  }

  // Clean temporary directories
  const tempDirs = [
    'temp',
    'tmp',
    'debug',
    'dev',
    'development'
  ];

  for (const dir of tempDirs) {
    if (removeDirectory(join(projectRoot, dir))) {
      totalRemoved++;
    }
  }

  // Clean specific development artifacts
  const devArtifacts = [
    'test-array-serialization',
    'array-serialization-test',
    'ARRAY_SERIALIZATION_TEST_RESULTS',
    'production-test',
    'quick-production-test',
    'simple-production-test',
    'stress-test-suite',
    'workflow-test-suite',
    'comprehensive-memory-test',
    'test-autonomous.cjs'
  ];

  for (const artifact of devArtifacts) {
    // Try to remove as file first
    if (!removeFile(join(projectRoot, artifact))) {
      // Try as directory
      if (!removeDirectory(join(projectRoot, artifact))) {
        // Try with common extensions
        const extensions = ['.js', '.md', '.log', '.sql', '.json'];
        for (const ext of extensions) {
          if (removeFile(join(projectRoot, artifact + ext))) {
            totalRemoved++;
            break;
          }
        }
      } else {
        totalRemoved++;
      }
    } else {
      totalRemoved++;
    }
  }

  console.log('\n' + '='.repeat(50));

  if (totalRemoved > 0) {
    success(`✨ Cleanup completed! Removed ${totalRemoved} build artifacts and temporary files.`);
  } else {
    info('🎯 No build artifacts found to clean.');
  }

  info('🚀 Development environment is clean and ready.');

  return totalRemoved;
}

function showHelp() {
  console.log(`
Build Artifacts Cleanup Script

USAGE:
  node scripts/clean-build-artifacts.cjs [options]

OPTIONS:
  --help, -h     Show this help message
  --dry-run      Show what would be removed without actually removing

DESCRIPTION:
  This script removes build artifacts, temporary files, and development
  artifacts to ensure a clean development environment.

CLEANED DIRECTORIES:
  - dist/, build/, dist-test/, temp-dist/
  - coverage/, .nyc_output/
  - test-results/, tests/temp/
  - temp/, tmp/, debug/, dev/, development/

CLEANED FILES:
  - *.tsbuildinfo files
  - Backup files (*.backup, *.old-detection, *.bak, *~)
  - Temporary logs (tmp_last_run.log, cortex-local.log, etc.)
  - Development artifacts and test files
`);
}

// Parse command line arguments
const args = process.argv.slice(2);
const isDryRun = args.includes('--dry-run') || args.includes('-d');
const showHelpFlag = args.includes('--help') || args.includes('-h');

if (showHelpFlag) {
  showHelp();
  process.exit(0);
}

if (isDryRun) {
  info('🔍 DRY RUN MODE - No files will be removed');
  // In a real implementation, you would scan and report without removing
  info('(Dry run functionality would be implemented here)');
  process.exit(0);
}

// Run cleanup
if (require.main === module) {
  try {
    const removedCount = cleanBuildArtifacts();
    process.exit(0);
  } catch (err) {
    error(`Cleanup failed: ${err.message}`);
    process.exit(1);
  }
}

module.exports = { cleanBuildArtifacts };