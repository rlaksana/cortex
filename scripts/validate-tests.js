#!/usr/bin/env node

/**
 * Test Validation Script
 *
 * Validates test files against standardized patterns and best practices.
 * Can be run as part of CI/CD pipeline or locally during development.
 */

import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import { join, extname, basename } from 'path';
import {
  TestValidator,
  TestMetrics,
  ValidationReporter,
} from '../tests/framework/test-validation.js';

// Configuration
const CONFIG = {
  testDirectories: ['tests'],
  excludePatterns: ['node_modules', '.git', 'dist', 'coverage', 'temp'],
  filePatterns: ['*.test.ts', '*.test.js', '*.spec.ts', '*.spec.js'],
  validationRules: {
    'mock-cleanup': { enabled: true, severity: 'error' },
    'standardized-setup': { enabled: true, severity: 'warning' },
    'test-isolation': { enabled: true, severity: 'error' },
    'async-handling': { enabled: true, severity: 'error' },
    'mock-best-practices': { enabled: true, severity: 'warning' },
    'error-handling': { enabled: true, severity: 'suggestion' },
    'performance-testing': { enabled: true, severity: 'warning' },
  },
};

/**
 * Recursively find test files
 */
function findTestFiles(dir, foundFiles = []) {
  if (!existsSync(dir)) {
    return foundFiles;
  }

  const items = readdirSync(dir);

  for (const item of items) {
    const fullPath = join(dir, item);
    const stat = statSync(fullPath);

    if (stat.isDirectory()) {
      // Skip excluded directories
      if (!CONFIG.excludePatterns.some((pattern) => item.includes(pattern))) {
        findTestFiles(fullPath, foundFiles);
      }
    } else if (stat.isFile()) {
      // Check if file matches test patterns
      const extension = extname(item);
      const _name = basename(item, extension);

      const isTestFile = CONFIG.filePatterns.some((pattern) => {
        const regex = new RegExp(pattern.replace('*', '.*'));
        return regex.test(item);
      });

      if (isTestFile && (extension === '.ts' || extension === '.js')) {
        foundFiles.push(fullPath);
      }
    }
  }

  return foundFiles;
}

/**
 * Validate a single test file
 */
function validateFile(filePath) {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const result = TestValidator.validateFile(filePath);

    // Add file metadata
    result.filePath = filePath;
    result.lines = content.split('\n').length;

    return result;
  } catch (error) {
    return {
      filePath,
      valid: false,
      errors: [`Failed to read file: ${error.message}`],
      warnings: [],
      suggestions: [],
      lines: 0,
    };
  }
}

/**
 * Generate comprehensive report
 */
function generateReport(validationResults, metrics) {
  console.log('\n📋 Test Validation Report');
  console.log('='.repeat(80));

  // Summary statistics
  const totalFiles = validationResults.length;
  const validFiles = validationResults.filter((r) => r.valid).length;
  const totalErrors = validationResults.reduce((sum, r) => sum + r.errors.length, 0);
  const totalWarnings = validationResults.reduce((sum, r) => sum + r.warnings.length, 0);
  const totalSuggestions = validationResults.reduce((sum, r) => sum + r.suggestions.length, 0);

  console.log(`\n📊 Summary:`);
  console.log(`  Total files: ${totalFiles}`);
  console.log(`  Valid files: ${validFiles} ✅`);
  console.log(`  Invalid files: ${totalFiles - validFiles} ❌`);
  console.log(`  Total errors: ${totalErrors}`);
  console.log(`  Total warnings: ${totalWarnings}`);
  console.log(`  Total suggestions: ${totalSuggestions}`);

  // File-by-file results
  console.log(`\n📁 File Details:`);
  console.log('-'.repeat(80));

  validationResults.forEach((result) => {
    const status = result.valid ? '✅' : '❌';
    console.log(`\n${status} ${result.filePath}`);
    console.log(`   Lines: ${result.lines}`);

    if (result.errors.length > 0) {
      console.log('   Errors:');
      result.errors.forEach((error) => {
        console.log(`     ❌ ${error}`);
      });
    }

    if (result.warnings.length > 0) {
      console.log('   Warnings:');
      result.warnings.forEach((warning) => {
        console.log(`     ⚠️  ${warning}`);
      });
    }

    if (result.suggestions.length > 0) {
      console.log('   Suggestions:');
      result.suggestions.forEach((suggestion) => {
        console.log(`     💡 ${suggestion}`);
      });
    }
  });

  // Metrics summary
  if (metrics && Object.keys(metrics).length > 0) {
    console.log(`\n📈 Test Metrics:`);
    console.log('-'.repeat(80));

    const summary = TestMetrics.generateSummary(Object.keys(metrics));
    console.log(`  Total tests: ${summary.totalTests}`);
    console.log(`  Average tests per file: ${summary.averageTestsPerFile.toFixed(1)}`);
    console.log(
      `  Files using standardized setup: ${summary.filesWithStandardizedSetup}/${summary.totalFiles}`
    );
    console.log(
      `  Files with proper cleanup: ${summary.filesWithProperCleanup}/${summary.totalFiles}`
    );
    console.log(`  Files with mocks: ${summary.filesWithMocks}/${summary.totalFiles}`);
  }

  // Recommendations
  console.log(`\n💡 Recommendations:`);
  console.log('-'.repeat(80));

  if (totalErrors > 0) {
    console.log('  🔧 Fix errors before merging changes');
  }

  if (totalWarnings > 0) {
    console.log('  ⚠️  Address warnings to improve test quality');
  }

  if (totalSuggestions > 0) {
    console.log('  💡 Consider suggestions for better test practices');
  }

  const invalidFiles = totalFiles - validFiles;
  if (invalidFiles > 0) {
    console.log(`  📋 Review and update ${invalidFiles} file(s) to meet standards`);
  }

  if (metrics && summary.filesWithStandardizedSetup < summary.totalFiles) {
    const filesToUpdate = summary.totalFiles - summary.filesWithStandardizedSetup;
    console.log(`  🏗️  Update ${filesToUpdate} file(s) to use standardized setup patterns`);
  }

  return {
    totalFiles,
    validFiles,
    totalErrors,
    totalWarnings,
    totalSuggestions,
    success: totalErrors === 0 && invalidFiles === 0,
  };
}

/**
 * Write JSON report for CI/CD
 */
function writeJsonReport(results, outputPath) {
  const report = ValidationReporter.generateJsonReport(results);

  try {
    require('fs').writeFileSync(outputPath, JSON.stringify(report, null, 2));
    console.log(`\n📄 JSON report written to: ${outputPath}`);
  } catch (error) {
    console.error(`Failed to write JSON report: ${error.message}`);
  }
}

/**
 * Main execution function
 */
async function main() {
  const args = process.argv.slice(2);
  const jsonOutput = args.includes('--json');
  const outputPath =
    args.find((arg) => arg.startsWith('--output='))?.split('=')[1] || 'test-validation-report.json';

  console.log('🔍 Starting test validation...');

  // Find all test files
  console.log('\n📁 Scanning for test files...');
  const testFiles = [];

  for (const dir of CONFIG.testDirectories) {
    const files = findTestFiles(dir);
    testFiles.push(...files);
  }

  console.log(`Found ${testFiles.length} test files`);

  if (testFiles.length === 0) {
    console.log('⚠️  No test files found');
    process.exit(0);
  }

  // Validate all files
  console.log('\n🔍 Validating test files...');
  const validationResults = [];
  const metrics = {};

  for (const filePath of testFiles) {
    console.log(`  Validating: ${filePath}`);
    const result = validateFile(filePath);
    validationResults.push(result);

    // Calculate metrics for the file
    metrics[filePath] = TestMetrics.calculateMetrics(filePath);
  }

  // Generate report
  const summary = generateReport(validationResults, metrics);

  // Write JSON report if requested
  if (jsonOutput) {
    writeJsonReport(validationResults, outputPath);
  }

  // Exit with appropriate code
  if (summary.success) {
    console.log('\n✅ All tests passed validation!');
    process.exit(0);
  } else {
    console.log('\n❌ Test validation failed!');
    process.exit(1);
  }
}

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught exception:', error.message);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Run the script
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { main as validateTests };
