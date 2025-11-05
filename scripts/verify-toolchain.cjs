#!/usr/bin/env node

/**
 * Toolchain Verification Script
 *
 * This script verifies that the current development environment
 * matches the expected toolchain versions and configuration.
 */

const { readFileSync } = require('node:fs');
const { execSync } = require('node:child_process');
const { join } = require('node:path');

const projectRoot = join(__dirname, '..');

// ANSI color codes for output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
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

function execCommand(command) {
  try {
    return execSync(command, { encoding: 'utf8' }).trim();
  } catch (err) {
    throw new Error(`Failed to execute: ${command}`);
  }
}

function compareVersions(actual, expected) {
  const actualParts = actual.replace(/[^\d.]/g, '').split('.').map(Number);
  const expectedParts = expected.replace(/[^\d.]/g, '').split('.').map(Number);

  const maxLength = Math.max(actualParts.length, expectedParts.length);

  for (let i = 0; i < maxLength; i++) {
    const actualPart = actualParts[i] || 0;
    const expectedPart = expectedParts[i] || 0;

    if (actualPart > expectedPart) return 1;
    if (actualPart < expectedPart) return -1;
  }

  return 0;
}

function checkVersion(tool, actual, expected, minimum = null) {
  info(`Checking ${tool} version...`);

  const actualClean = actual.startsWith('v') ? actual.slice(1) : actual;
  const expectedClean = expected.startsWith('v') ? expected.slice(1) : expected;

  const comparison = compareVersions(actualClean, expectedClean);

  if (comparison === 0) {
    success(`✓ ${tool} ${actual} matches expected ${expected}`);
    return true;
  } else if (comparison > 0) {
    warning(`⚠ ${tool} ${actual} is newer than expected ${expected}`);
    return true;
  } else {
    error(`✗ ${tool} ${actual} is older than expected ${expected}`);
    return false;
  }
}

function checkMinimumVersion(tool, actual, minimum) {
  if (!minimum) return true;

  const actualClean = actual.startsWith('v') ? actual.slice(1) : actual;
  const minimumClean = minimum.startsWith('v') ? minimum.slice(1) : minimum;

  const comparison = compareVersions(actualClean, minimumClean);

  if (comparison >= 0) {
    success(`✓ ${tool} ${actual} meets minimum requirement ${minimum}`);
    return true;
  } else {
    error(`✗ ${tool} ${actual} does not meet minimum requirement ${minimum}`);
    return false;
  }
}

function verifyToolchain() {
  info('Starting toolchain verification...');

  let allChecksPassed = true;

  try {
    // Load toolchain configuration
    const toolchainConfigPath = join(projectRoot, '.toolchainrc');
    const toolchainConfig = JSON.parse(readFileSync(toolchainConfigPath, 'utf8'));
    success('Loaded toolchain configuration');

    // Verify Node.js
    try {
      const nodeVersion = execCommand('node --version');
      const nodeCheck = checkVersion('Node.js', nodeVersion, toolchainConfig.node.version);
      const nodeMinCheck = checkMinimumVersion('Node.js', nodeVersion, toolchainConfig.node.minimum);

      if (!nodeCheck || !nodeMinCheck) {
        allChecksPassed = false;
      }
    } catch (err) {
      error('Node.js not found or not executable');
      allChecksPassed = false;
    }

    // Verify PNPM
    try {
      const pnpmVersion = execCommand('pnpm --version');
      const pnpmCheck = checkVersion('PNPM', pnpmVersion, toolchainConfig.pnpm.version);
      const pnpmMinCheck = checkMinimumVersion('PNPM', pnpmVersion, toolchainConfig.pnpm.minimum);

      if (!pnpmCheck || !pnpmMinCheck) {
        allChecksPassed = false;
      }
    } catch (err) {
      error('PNPM not found or not executable');
      allChecksPassed = false;
    }

    // Verify TypeScript
    try {
      const tscVersion = execCommand('npx tsc --version');
      const versionMatch = tscVersion.match(/Version (\d+\.\d+\.\d+)/);
      if (versionMatch) {
        const tsCheck = checkVersion('TypeScript', versionMatch[1], toolchainConfig.typescript.version);
        const tsMinCheck = checkMinimumVersion('TypeScript', versionMatch[1], toolchainConfig.typescript.minimum);

        if (!tsCheck || !tsMinCheck) {
          allChecksPassed = false;
        }
      } else {
        error('Could not parse TypeScript version');
        allChecksPassed = false;
      }
    } catch (err) {
      error('TypeScript not found or not executable');
      allChecksPassed = false;
    }

    // Verify development tools
    const tools = toolchainConfig.tools;

    // Check ESLint
    try {
      const eslintVersion = execCommand('npx eslint --version');
      if (eslintVersion.includes(tools.eslint)) {
        success(`✓ ESLint ${tools.eslint} found`);
      } else {
        warning(`⚠ ESLint version mismatch: found ${eslintVersion}, expected ${tools.eslint}`);
      }
    } catch (err) {
      error('ESLint not found or not executable');
      allChecksPassed = false;
    }

    // Check Prettier
    try {
      const prettierVersion = execCommand('npx prettier --version');
      if (prettierVersion.includes(tools.prettier)) {
        success(`✓ Prettier ${tools.prettier} found`);
      } else {
        warning(`⚠ Prettier version mismatch: found ${prettierVersion}, expected ${tools.prettier}`);
      }
    } catch (err) {
      error('Prettier not found or not executable');
      allChecksPassed = false;
    }

    // Check Vitest
    try {
      const vitestVersion = execCommand('npx vitest --version');
      if (vitestVersion.includes(tools.vitest)) {
        success(`✓ Vitest ${tools.vitest} found`);
      } else {
        warning(`⚠ Vitest version mismatch: found ${vitestVersion}, expected ${tools.vitest}`);
      }
    } catch (err) {
      error('Vitest not found or not executable');
      allChecksPassed = false;
    }

    // Verify package.json engines
    try {
      const packageJson = JSON.parse(readFileSync(join(projectRoot, 'package.json'), 'utf8'));
      if (packageJson.engines && packageJson.engines.node) {
        success(`✓ package.json engines.node configured: ${packageJson.engines.node}`);
      } else {
        warning('⚠ package.json engines.node not configured');
      }
    } catch (err) {
      error('Could not read package.json');
      allChecksPassed = false;
    }

    // Final summary
    console.log('\n' + '='.repeat(50));
    if (allChecksPassed) {
      success('✓ All toolchain checks passed!');
      info('Development environment is properly configured.');
    } else {
      error('✗ Some toolchain checks failed!');
      warning('Please update your development environment to match the expected versions.');
      process.exit(1);
    }

  } catch (err) {
    error(`Toolchain verification failed: ${err.message}`);
    process.exit(1);
  }
}

// Run verification if called directly
if (require.main === module) {
  verifyToolchain();
}

module.exports = { verifyToolchain };