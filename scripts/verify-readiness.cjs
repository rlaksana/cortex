#!/usr/bin/env node

/**
 * Production Readiness Verification Script
 *
 * This script performs the core verification checks to determine
 * if the repository is ready for production deployment.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🔍 Production Readiness Verification');
console.log('=====================================\n');

const checks = [
  {
    name: 'TypeScript Compilation',
    command: 'npm run type-check',
    expected: 0,
    critical: true,
  },
  {
    name: 'ESLint Linting',
    command: 'npm run lint',
    expected: 0,
    critical: true,
  },
  {
    name: 'Code Formatting',
    command: 'npm run format:check',
    expected: 0,
    critical: false,
  },
  {
    name: 'Build Process',
    command: 'npm run build',
    expected: 0,
    critical: true,
  },
];

let passedChecks = 0;
let totalChecks = checks.length;
let criticalFailures = 0;

checks.forEach((check, index) => {
  console.log(`${index + 1}. ${check.name}...`);

  try {
    const result = execSync(check.command, {
      encoding: 'utf8',
      stdio: 'pipe',
      timeout: 30000, // 30 second timeout
    });

    if (result.includes('error') || result.includes('Error')) {
      console.log(`   ❌ Failed - Contains errors in output`);
      if (check.critical) criticalFailures++;
    } else {
      console.log(`   ✅ Passed`);
      passedChecks++;
    }
  } catch (error) {
    console.log(`   ❌ Failed - Exit code: ${error.status}`);
    if (check.critical) criticalFailures++;
  }
});

console.log('\n📊 Summary');
console.log('==========');
console.log(`Passed: ${passedChecks}/${totalChecks}`);
console.log(`Critical Failures: ${criticalFailures}`);

// Additional file system checks
console.log('\n📁 File System Checks');
console.log('====================');

const requiredFiles = ['src/index.ts', 'package.json', 'tsconfig.json', 'README.md'];

const optionalFiles = ['.env.example', 'docs/README.md', 'LICENSE'];

let requiredFilesFound = 0;
requiredFiles.forEach((file) => {
  if (fs.existsSync(file)) {
    console.log(`✅ ${file}`);
    requiredFilesFound++;
  } else {
    console.log(`❌ ${file} (Missing)`);
  }
});

console.log(`Required files: ${requiredFilesFound}/${requiredFiles.length}`);

// Package.json checks
console.log('\n📦 Package Configuration');
console.log('=========================');

try {
  const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));

  const requiredScripts = ['start', 'build', 'test', 'lint', 'type-check'];
  let scriptsFound = 0;

  requiredScripts.forEach((script) => {
    if (packageJson.scripts && packageJson.scripts[script]) {
      console.log(`✅ ${script}`);
      scriptsFound++;
    } else {
      console.log(`❌ ${script} (Missing)`);
    }
  });

  console.log(`Scripts: ${scriptsFound}/${requiredScripts.length}`);
} catch (error) {
  console.log('❌ Could not read package.json');
}

// Final determination
console.log('\n🎯 Production Readiness Status');
console.log('==============================');

if (criticalFailures > 0) {
  console.log('🔴 NOT READY FOR PRODUCTION');
  console.log(`Reason: ${criticalFailures} critical check(s) failed`);
  console.log('\nRequired actions:');
  console.log('- Fix all critical failures');
  console.log('- Ensure all tests pass');
  console.log('- Verify build process works');
} else if (passedChecks === totalChecks && requiredFilesFound === requiredFiles.length) {
  console.log('🟢 READY FOR PRODUCTION');
  console.log('All critical checks passed');
} else {
  console.log('🟡 PARTIALLY READY');
  console.log('Some non-critical issues need attention');
}

console.log('\n✨ Verification complete!');
