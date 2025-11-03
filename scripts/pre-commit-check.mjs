#!/usr/bin/env node

/**
 * Pre-commit Quality Gate Check
 *
 * This script runs a lightweight version of the quality gate pipeline
 * before commits are made. It focuses on fast checks to avoid slowing
 * down the development workflow while still catching common issues.
 */

import { execSync } from 'child_process';
import { readFileSync } from 'fs';

const FAST_CHECKS = [
  {
    name: 'Type Check',
    command: 'npm run type-check',
    critical: true
  },
  {
    name: 'Lint Check',
    command: 'npm run lint:quiet',
    critical: true
  },
  {
    name: 'Quick Unit Tests',
    command: 'npm run test:unit -- --run --reporter=basic',
    critical: false
  }
];

function runFastCheck(check) {
  try {
    console.log(`🔍 Running ${check.name}...`);
    const output = execSync(check.command, {
      encoding: 'utf8',
      stdio: 'pipe',
      timeout: 60000 // 1 minute timeout
    });
    console.log(`✅ ${check.name} passed`);
    return { passed: true, output };
  } catch (error) {
    console.log(`❌ ${check.name} failed`);
    console.log(error.stdout || error.message);
    return {
      passed: false,
      output: error.stdout || '',
      error: error.stderr || error.message
    };
  }
}

function main() {
  console.log('🚀 Running pre-commit quality checks...\n');

  const results = [];
  const startTime = Date.now();

  for (const check of FAST_CHECKS) {
    const result = runFastCheck(check);
    results.push({ ...result, name: check.name, critical: check.critical });

    // Fail fast for critical failures
    if (!result.passed && check.critical) {
      console.log(`\n💥 Critical check '${check.name}' failed. Commit blocked.`);
      break;
    }
  }

  const duration = Date.now() - startTime;
  const failed = results.filter(r => !r.passed);
  const criticalFailed = failed.filter(r => r.critical);

  console.log(`\n📊 Pre-commit check summary (${(duration / 1000).toFixed(1)}s):`);
  results.forEach(result => {
    const status = result.passed ? '✅' : '❌';
    const critical = result.critical ? ' (critical)' : '';
    console.log(`  ${status} ${result.name}${critical}`);
  });

  if (criticalFailed.length > 0) {
    console.log('\n🔧 Commit blocked due to critical failures:');
    criticalFailed.forEach(failure => {
      console.log(`  • ${failure.name}: ${failure.error || 'Check failed'}`);
    });
    console.log('\n💡 To fix:');
    console.log('  1. Run: npm run quality-check');
    console.log('  2. Fix the issues above');
    console.log('  3. Try committing again');
    process.exit(1);
  }

  if (failed.length > 0) {
    console.log('\n⚠️  Some non-critical checks failed, but commit allowed:');
    failed.forEach(failure => {
      console.log(`  • ${failure.name}`);
    });
    console.log('\n💡 Consider fixing these issues before pushing.');
  }

  console.log('\n✅ Pre-commit checks passed! Ready to commit.');
  process.exit(0);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}