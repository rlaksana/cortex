#!/usr/bin/env node

/**
 * Enhanced Quality Gate Implementation with Iterative Validation
 *
 * This script provides comprehensive validation with:
 * - TypeScript type checking across all configurations
 * - Build verification and optimization
 * - Performance regression detection
 * - Security vulnerability scanning
 * - Code coverage validation
 * - Production readiness validation
 */

import { execSync } from 'child_process';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

class QualityGateValidator {
  constructor(options = {}) {
    this.strict = options.strict || false;
    this.ci = options.ci || false;
    this.verbose = options.verbose || false;
    this.errors = [];
    this.warnings = [];
    this.metrics = {};
  }

  log(message, level = 'info') {
    const timestamp = new Date().toISOString();
    const prefix = `[${timestamp}] [${level.toUpperCase()}]`;

    if (this.verbose || level === 'error' || level === 'warn') {
      console.log(`${prefix} ${message}`);
    }
  }

  executeCommand(command, description) {
    try {
      this.log(`Executing: ${description}`);
      const result = execSync(command, {
        encoding: 'utf8',
        stdio: this.verbose ? 'inherit' : 'pipe',
        maxBuffer: 1024 * 1024 * 10 // 10MB buffer
      });
      this.log(`✅ ${description} completed successfully`);
      return { success: true, output: result };
    } catch (error) {
      this.log(`❌ ${description} failed: ${error.message}`, 'error');
      this.errors.push(`${description}: ${error.message}`);
      return { success: false, error: error.message };
    }
  }

  validateTypeScript() {
    this.log('🔍 Validating TypeScript configurations...');

    const configs = [
      { file: 'tsconfig.json', description: 'Development TypeScript' },
      { file: 'tsconfig.build.json', description: 'Build TypeScript' },
      { file: 'tsconfig.test.json', description: 'Test TypeScript' },
      { file: 'tsconfig.production.json', description: 'Production TypeScript' }
    ];

    configs.forEach(config => {
      if (existsSync(config.file)) {
        const result = this.executeCommand(
          `tsc --noEmit -p ${config.file}`,
          config.description
        );
        this.metrics[`${config.description}_type_check`] = result.success;
      }
    });

    // Additional type checking
    const allTypeCheck = this.executeCommand(
      'npm run type-check:all',
      'All configurations type check'
    );
    this.metrics.all_type_checks_pass = allTypeCheck.success;
  }

  validateBuild() {
    this.log('🏗️  Validating build system...');

    // Clean build validation
    const cleanBuild = this.executeCommand(
      'npm run build:production',
      'Production build'
    );
    this.metrics.production_build_success = cleanBuild.success;

    // Incremental build validation
    const incrementalBuild = this.executeCommand(
      'npm run build:dev',
      'Development build'
    );
    this.metrics.development_build_success = incrementalBuild.success;
  }

  validateLinting() {
    this.log('🔧 Validating code quality...');

    const maxWarnings = this.strict ? 0 : 10;
    const lintResult = this.executeCommand(
      `npm run lint:hard -- --max-warnings ${maxWarnings}`,
      'ESLint validation'
    );
    this.metrics.linting_pass = lintResult.success;

    // Security linting
    const securityLint = this.executeCommand(
      'npm run lint:security',
      'Security linting'
    );
    this.metrics.security_linting_pass = securityLint.success;
  }

  validateTesting() {
    this.log('🧪 Validating test coverage...');

    try {
      // Unit tests
      const unitTestResult = this.executeCommand(
        'npm run test:unit -- --run',
        'Unit tests'
      );
      this.metrics.unit_tests_pass = unitTestResult.success;

      // Type checking tests
      const typeTestResult = this.executeCommand(
        'npm run type-check:test',
        'Test type checking'
      );
      this.metrics.test_type_check_pass = typeTestResult.success;

      // Coverage validation (if coverage reports exist)
      if (existsSync('coverage/coverage-summary.json')) {
        const coverageData = JSON.parse(
          readFileSync('coverage/coverage-summary.json', 'utf8')
        );

        const totalCoverage = coverageData.total?.lines?.pct || 0;
        this.metrics.test_coverage_percentage = totalCoverage;

        const minCoverage = this.strict ? 90 : 85;
        if (totalCoverage < minCoverage) {
          this.errors.push(`Test coverage ${totalCoverage}% is below minimum ${minCoverage}%`);
          this.metrics.coverage_threshold_pass = false;
        } else {
          this.metrics.coverage_threshold_pass = true;
        }
      }
    } catch (error) {
      this.log(`Test validation failed: ${error.message}`, 'error');
      this.metrics.test_validation_pass = false;
    }
  }

  validateSecurity() {
    this.log('🔒 Validating security...');

    // Audit dependencies
    const auditResult = this.executeCommand(
      'npm audit --audit-level=moderate --json',
      'Security audit'
    );

    if (auditResult.success) {
      try {
        const auditData = JSON.parse(auditResult.output);
        const vulnerabilities = auditData.vulnerabilities || {};
        const moderateVulns = Object.keys(vulnerabilities).filter(
          key => vulnerabilities[key].severity === 'moderate'
        ).length;

        this.metrics.moderate_vulnerabilities = moderateVulns;

        if (moderateVulns > 0 && this.strict) {
          this.errors.push(`Found ${moderateVulns} moderate security vulnerabilities`);
          this.metrics.security_audit_pass = false;
        } else {
          this.metrics.security_audit_pass = true;
        }
      } catch (parseError) {
        this.log(`Failed to parse security audit output: ${parseError.message}`, 'warn');
        this.metrics.security_audit_pass = auditResult.success;
      }
    } else {
      this.metrics.security_audit_pass = false;
    }
  }

  validatePerformance() {
    this.log('⚡ Validating performance...');

    // Build time performance
    const buildStartTime = Date.now();
    const buildResult = this.executeCommand(
      'npm run build:clean && npm run build:parallel',
      'Build performance test'
    );
    const buildTime = Date.now() - buildStartTime;

    this.metrics.build_time_ms = buildTime;
    this.metrics.build_performance_pass = buildResult.success && buildTime < 30000; // 30 seconds

    if (buildTime > 30000) {
      this.warnings.push(`Build time ${buildTime}ms exceeds 30 second threshold`);
    }

    // Memory usage validation (if available)
    try {
      if (existsSync('dist')) {
        const packageJson = JSON.parse(readFileSync('package.json', 'utf8'));
        this.metrics.package_size_kb = packageJson.dependencies ?
          Object.keys(packageJson.dependencies).length * 50 : 0; // Rough estimate
      }
    } catch (error) {
      this.log(`Could not calculate package size: ${error.message}`, 'warn');
    }
  }

  validateProductionReadiness() {
    this.log('🚀 Validating production readiness...');

    // Check essential files
    const essentialFiles = [
      'dist/index.js',
      'dist/silent-mcp-entry.js',
      'package.json',
      'README.md'
    ];

    let missingFiles = [];
    essentialFiles.forEach(file => {
      if (!existsSync(file)) {
        missingFiles.push(file);
      }
    });

    if (missingFiles.length > 0) {
      this.errors.push(`Missing essential files: ${missingFiles.join(', ')}`);
      this.metrics.essential_files_present = false;
    } else {
      this.metrics.essential_files_present = true;
    }

    // Validate package.json scripts
    try {
      const packageJson = JSON.parse(readFileSync('package.json', 'utf8'));
      const requiredScripts = ['start', 'build', 'test', 'lint'];
      const missingScripts = requiredScripts.filter(script => !packageJson.scripts[script]);

      if (missingScripts.length > 0) {
        this.errors.push(`Missing required scripts: ${missingScripts.join(', ')}`);
        this.metrics.required_scripts_present = false;
      } else {
        this.metrics.required_scripts_present = true;
      }
    } catch (error) {
      this.errors.push(`Failed to validate package.json: ${error.message}`);
      this.metrics.required_scripts_present = false;
    }
  }

  generateReport() {
    this.log('📊 Generating quality gate report...');

    const report = {
      timestamp: new Date().toISOString(),
      strict: this.strict,
      ci: this.ci,
      summary: {
        total_errors: this.errors.length,
        total_warnings: this.warnings.length,
        overall_status: this.errors.length === 0 ? 'PASS' : 'FAIL'
      },
      errors: this.errors,
      warnings: this.warnings,
      metrics: this.metrics
    };

    // Write report to file
    const reportPath = 'artifacts/quality-gate-report.json';
    try {
      const reportData = JSON.stringify(report, null, 2);
      if (!existsSync('artifacts')) {
        execSync('mkdir -p artifacts');
      }
      require('fs').writeFileSync(reportPath, reportData);
      this.log(`📄 Quality gate report saved to ${reportPath}`);
    } catch (error) {
      this.log(`Failed to save report: ${error.message}`, 'warn');
    }

    return report;
  }

  async run() {
    this.log('🚀 Starting Enhanced Quality Gate Validation...');

    const startTime = Date.now();

    try {
      // Run all validations
      this.validateTypeScript();
      this.validateBuild();
      this.validateLinting();
      this.validateTesting();
      this.validateSecurity();
      this.validatePerformance();
      this.validateProductionReadiness();

      // Generate report
      const report = this.generateReport();

      const duration = Date.now() - startTime;
      this.log(`✅ Quality gate validation completed in ${duration}ms`);

      // Print summary
      console.log('\n📋 Quality Gate Summary:');
      console.log(`   Errors: ${report.summary.total_errors}`);
      console.log(`   Warnings: ${report.summary.total_warnings}`);
      console.log(`   Status: ${report.summary.overall_status}`);

      if (report.summary.total_errors > 0) {
        console.log('\n❌ Errors:');
        this.errors.forEach(error => console.log(`   - ${error}`));
      }

      if (report.summary.total_warnings > 0) {
        console.log('\n⚠️  Warnings:');
        this.warnings.forEach(warning => console.log(`   - ${warning}`));
      }

      return report.summary.overall_status === 'PASS';

    } catch (error) {
      this.log(`Quality gate validation failed: ${error.message}`, 'error');
      return false;
    }
  }
}

// CLI interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const options = {
    strict: process.argv.includes('--strict'),
    ci: process.env.CI === 'true' || process.argv.includes('--ci'),
    verbose: process.argv.includes('--verbose')
  };

  const validator = new QualityGateValidator(options);
  validator.run()
    .then(success => {
      process.exit(success ? 0 : 1);
    })
    .catch(error => {
      console.error('Quality gate validation error:', error);
      process.exit(1);
    });
}

export { QualityGateValidator };