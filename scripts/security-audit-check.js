#!/usr/bin/env node

/**
 * Security Audit Checker for CI/CD Pipeline
 *
 * This script processes npm audit output and fails the build if
 * high or critical vulnerabilities are found.
 */

import { createReadStream } from 'fs';
import { createInterface } from 'readline';

async function processAuditResults() {
  const vulnerabilities = {
    critical: 0,
    high: 0,
    moderate: 0,
    low: 0,
    info: 0,
    total: 0,
  };

  const details = [];

  const rl = createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
  });

  let auditData = '';

  for await (const line of rl) {
    auditData += line;
  }

  try {
    const audit = JSON.parse(auditData);

    if (audit.vulnerabilities) {
      for (const [packageName, vuln] of Object.entries(audit.vulnerabilities)) {
        const vulnerability = vuln;

        vulnerabilities.total++;

        switch (vulnerability.severity) {
          case 'critical':
            vulnerabilities.critical++;
            break;
          case 'high':
            vulnerabilities.high++;
            break;
          case 'moderate':
            vulnerabilities.moderate++;
            break;
          case 'low':
            vulnerabilities.low++;
            break;
          case 'info':
            vulnerabilities.info++;
            break;
        }

        details.push({
          package: packageName,
          severity: vulnerability.severity,
          title: vulnerability.title,
          url: vulnerability.url,
          fixAvailable: vulnerability.fixAvailable,
        });
      }
    }

    // Print summary
    console.log('\n🔒 Security Audit Results');
    console.log('========================');
    console.log(`Critical:  ${vulnerabilities.critical}`);
    console.log(`High:      ${vulnerabilities.high}`);
    console.log(`Moderate:  ${vulnerabilities.moderate}`);
    console.log(`Low:       ${vulnerabilities.low}`);
    console.log(`Info:      ${vulnerabilities.info}`);
    console.log(`Total:     ${vulnerabilities.total}`);

    // Print details for high/critical vulnerabilities
    const highCriticalVulns = details.filter(
      (d) => d.severity === 'critical' || d.severity === 'high'
    );

    if (highCriticalVulns.length > 0) {
      console.log('\n🚨 High/Critical Vulnerabilities:');
      console.log('=================================');

      highCriticalVulns.forEach((vuln) => {
        console.log(`\n📦 Package: ${vuln.package}`);
        console.log(`   Severity: ${vuln.severity.toUpperCase()}`);
        console.log(`   Title: ${vuln.title}`);
        console.log(`   Fix Available: ${vuln.fixAvailable ? 'Yes' : 'No'}`);
        if (vuln.url) {
          console.log(`   Details: ${vuln.url}`);
        }
      });
    }

    // Check if we should fail the build
    const shouldFail = vulnerabilities.critical > 0 || vulnerabilities.high > 0;

    if (shouldFail) {
      console.log('\n❌ SECURITY CHECK FAILED');
      console.log(
        `Found ${vulnerabilities.critical} critical and ${vulnerabilities.high} high severity vulnerabilities.`
      );
      console.log('Please fix these vulnerabilities before proceeding with deployment.');

      // Suggest remediation steps
      console.log('\n💡 Remediation Suggestions:');
      console.log('  1. Run "npm audit fix" to automatically fix fixable vulnerabilities');
      console.log('  2. Manually update packages that cannot be auto-fixed');
      console.log('  3. Consider using "npm audit fix --force" for breaking changes');
      console.log('  4. Review and accept risk for any remaining vulnerabilities');

      process.exit(1);
    } else {
      console.log('\n✅ SECURITY CHECK PASSED');
      console.log('No critical or high severity vulnerabilities found.');

      if (vulnerabilities.moderate > 0) {
        console.log(`\n⚠️  Note: ${vulnerabilities.moderate} moderate vulnerabilities found.`);
        console.log('Consider addressing these in a future update.');
      }
    }
  } catch (error) {
    console.error('❌ Error processing audit results:', error.message);
    process.exit(1);
  }
}

// Check if we're running in CI mode
if (process.env.CI || process.env.GITHUB_ACTIONS) {
  console.log('🔍 Running security audit in CI mode...');
}

// Process audit results from stdin
processAuditResults().catch((error) => {
  console.error('❌ Security audit check failed:', error);
  process.exit(1);
});
