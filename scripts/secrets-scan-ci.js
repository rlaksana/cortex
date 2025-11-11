#!/usr/bin/env node

/**
 * CI Secrets Scanner - P0-CRITICAL Implementation
 *
 * CI/CD integration script for secrets detection.
 * Scans codebase and fails build if critical/high severity secrets are found.
 *
 * Usage:
 *   node scripts/secrets-scan-ci.js [options]
 *
 * Options:
 *   --path <directory>     Scan specific directory (default: .)
 *   --output <file>        Save report to file (default: secrets-scan-report.md)
 *   --fail-on <level>      Fail level (critical|high|medium|low, default: high)
 *   --format <format>      Output format (markdown|json|junit, default: markdown)
 *   --include-binary       Include binary files in scan
 *   --max-file-size <size> Maximum file size in bytes (default: 1048576)
 *   --help                 Show help
 *
 * @author Cortex Team
 * @version 2.0.1
 * @since 2025
 */

import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import { writeFileSync } from 'fs';
import { SecretsScanner } from '../dist/security/secrets-scanner.js';

const __filename = fileURLToPath(import.meta.url);

// Parse command line arguments
function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    path: '.',
    output: 'secrets-scan-report.md',
    failOn: 'high',
    format: 'markdown',
    includeBinary: false,
    maxFileSize: 1024 * 1024, // 1MB
    help: false
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--path':
        options.path = args[++i];
        break;
      case '--output':
        options.output = args[++i];
        break;
      case '--fail-on':
        options.failOn = args[++i];
        break;
      case '--format':
        options.format = args[++i];
        break;
      case '--include-binary':
        options.includeBinary = true;
        break;
      case '--max-file-size':
        options.maxFileSize = parseInt(args[++i], 10);
        break;
      case '--help':
        options.help = true;
        break;
      default:
        if (args[i].startsWith('-')) {
          console.error(`Unknown option: ${args[i]}`);
          process.exit(1);
        }
    }
  }

  return options;
}

// Show help
function showHelp() {
  console.log(`
CI Secrets Scanner - P0-CRITICAL Implementation

Scans codebase for hardcoded secrets and fails build if critical/high severity secrets are found.

USAGE:
  node scripts/secrets-scan-ci.js [options]

OPTIONS:
  --path <directory>     Scan specific directory (default: .)
  --output <file>        Save report to file (default: secrets-scan-report.md)
  --fail-on <level>      Fail level (critical|high|medium|low, default: high)
  --format <format>      Output format (markdown|json|junit, default: markdown)
  --include-binary       Include binary files in scan
  --max-file-size <size> Maximum file size in bytes (default: 1048576)
  --help                 Show this help

EXIT CODES:
  0     Success (no critical/high severity findings)
  1     Critical or high severity secrets found
  2     Error occurred during scan

EXAMPLES:
  # Basic scan
  node scripts/secrets-scan-ci.js

  # Scan with custom output
  node scripts/secrets-scan-ci.js --output security-report.md

  # Include binary files and fail on medium severity
  node scripts/secrets-scan-ci.js --include-binary --fail-on medium

  # JSON output for CI integration
  node scripts/secrets-scan-ci.js --format json --output secrets-scan-results.json
`);
}

// Format output based on requested format
function formatOutput(results, format) {
  switch (format) {
    case 'json':
      return JSON.stringify(results, null, 2);

    case 'junit':
      return formatJUnit(results);

    case 'markdown':
    default:
      return SecretsScanner.generateReport(results);
  }
}

// Format results as JUnit XML for CI systems
function formatJUnit(results) {
  const failures = results.findings.filter(f =>
    ['critical', 'high'].includes(f.pattern.severity)
  ).length;

  const xml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuites tests="1" failures="${failures}" time="${results.duration / 1000}">`,
    '  <testsuite name="secrets-scan" tests="1" failures="${failures}" time="${results.duration / 1000}">',
    '    <testcase classname="secrets-scan" name="scan-codebase" time="${results.duration / 1000}">'
  ];

  if (failures > 0) {
    xml.push('      <failure message="Secrets found in codebase">');
    xml.push('        <![CDATA[');

    // Group findings by severity
    const criticalFindings = results.findings.filter(f => f.pattern.severity === 'critical');
    const highFindings = results.findings.filter(f => f.pattern.severity === 'high');

    if (criticalFindings.length > 0) {
      xml.push('');
      xml.push('CRITICAL SECRETS FOUND:');
      criticalFindings.forEach(finding => {
        xml.push(`${finding.file}:${finding.line} - ${finding.pattern.name}`);
        xml.push(`  Match: ${finding.match}`);
        xml.push(`  Remediation: ${finding.pattern.remediation}`);
        xml.push('');
      });
    }

    if (highFindings.length > 0) {
      xml.push('HIGH SEVERITY SECRETS FOUND:');
      highFindings.forEach(finding => {
        xml.push(`${finding.file}:${finding.line} - ${finding.pattern.name}`);
        xml.push(`  Match: ${finding.match}`);
        xml.push(`  Remediation: ${finding.pattern.remediation}`);
        xml.push('');
      });
    }

    xml.push('        ]]>');
    xml.push('      </failure>');
  }

  xml.push([
    '    </testcase>',
    '  </testsuite>',
    '</testsuites>'
  ]);

  return xml.join('\n');
}

// Determine if scan should fail based on findings
function shouldFail(results, failOn) {
  const severityLevels = ['low', 'medium', 'high', 'critical'];
  const failThreshold = severityLevels.indexOf(failOn);

  return results.findings.some(finding =>
    severityLevels.indexOf(finding.pattern.severity) >= failThreshold
  );
}

// Main execution
async function main() {
  const options = parseArgs();

  if (options.help) {
    showHelp();
    process.exit(0);
  }

  console.log('🔍 Starting CI Secrets Scanner - P0-CRITICAL Implementation');
  console.log(`📁 Scan path: ${resolve(options.path)}`);
  console.log(`📊 Fail level: ${options.failOn}`);
  console.log(`📄 Output format: ${options.format}`);
  console.log('');

  try {
    // Perform scan
    const results = await SecretsScanner.scanDirectory(options.path, {
      maxFileSize: options.maxFileSize,
      includeBinary: options.includeBinary
    });

    // Generate report
    const report = formatOutput(results, options.format, options.output);

    // Save report
    if (options.output) {
      writeFileSync(options.output, report, 'utf8');
      console.log(`📄 Report saved to: ${options.output}`);
    }

    // Display summary
    console.log('');
    console.log('📊 Scan Results Summary:');
    console.log(`   Files scanned: ${results.scannedFiles}/${results.totalFiles}`);
    console.log(`   Critical: ${results.summary.critical}`);
    console.log(`   High: ${results.summary.high}`);
    console.log(`   Medium: ${results.summary.medium}`);
    console.log(`   Low: ${results.summary.low}`);
    console.log(`   Total findings: ${results.findings.length}`);
    console.log(`   Duration: ${results.duration}ms`);

    if (results.errors.length > 0) {
      console.log(`   Errors: ${results.errors.length}`);
    }

    // Show findings in console for quick visibility
    if (results.findings.length > 0) {
      console.log('');
      console.log('🔍 Findings Summary:');

      // Group by severity
      const bySeverity = results.findings.reduce((acc, finding) => {
        if (!acc[finding.pattern.severity]) {
          acc[finding.pattern.severity] = [];
        }
        acc[finding.pattern.severity].push(finding);
        return acc;
      }, {});

      ['critical', 'high', 'medium', 'low'].forEach(severity => {
        const findings = bySeverity[severity] || [];
        if (findings.length > 0) {
          console.log(`   ${severity.toUpperCase()}: ${findings.length} findings`);

          // Show top 3 findings for each severity
          findings.slice(0, 3).forEach(finding => {
            const relativePath = finding.file.replace(process.cwd() + '/', '');
            console.log(`     - ${relativePath}:${finding.line} - ${finding.pattern.name}`);
          });

          if (findings.length > 3) {
            console.log(`     ... and ${findings.length - 3} more`);
          }
        }
      });
    }

    // Check if should fail
    if (shouldFail(results, options.failOn)) {
      console.log('');
      console.log('❌ SCAN FAILED - Secrets detected that exceed threshold');
      console.log(`🚨 Fail level: ${options.failOn}`);

      if (results.summary.critical > 0) {
        console.log(`💀 Critical secrets: ${results.summary.critical} - URGENT REMOVAL REQUIRED`);
      }
      if (results.summary.high > 0) {
        console.log(`⚠️  High severity secrets: ${results.summary.high} - Immediate removal recommended`);
      }

      console.log('');
      console.log('🔧 REMEDIATION STEPS:');
      console.log('1. Remove all detected secrets from the codebase');
      console.log('2. Replace with environment variables');
      console.log('3. Invalidate any exposed credentials');
      console.log('4. Review the detailed report for specific fixes');
      console.log('5. Update .gitignore to prevent future commits');

      if (options.output) {
        console.log(`📄 Detailed report available: ${options.output}`);
      }

      process.exit(1);
    } else {
      console.log('');
      console.log('✅ SCAN PASSED - No critical/high severity secrets found');
      console.log('🎉 Your codebase passed secrets hygiene check');

      if (results.summary.medium > 0) {
        console.log(`💡 ${results.summary.medium} medium severity findings found - consider reviewing`);
      }

      process.exit(0);
    }

  } catch (error) {
    console.error('❌ SCAN ERROR:', error.message);
    console.error('');
    console.error('🔧 TROUBLESHOOTING:');
    console.error('1. Check if the scan path exists and is accessible');
    console.error('2. Ensure you have read permissions for all files');
    console.error('3. Try scanning with --max-file-size for large files');
    console.error('4. Use --include-binary if needed for your project');

    process.exit(2);
  }
}

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  console.error('❌ UNCAUGHT EXCEPTION:', error.message);
  process.exit(2);
});

process.on('unhandledRejection', (reason) => {
  console.error('❌ UNHANDLED REJECTION:', reason);
  process.exit(2);
});

// Run main function
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(error => {
    console.error('❌ FATAL ERROR:', error);
    process.exit(2);
  });
}

export { main as scanSecretsCI };