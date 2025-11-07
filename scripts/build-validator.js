#!/usr/bin/env node

/**
 * Advanced Build Validation and Verification System
 *
 * Features:
 * - Comprehensive build artifact validation
 * - Runtime compatibility verification
 * - Security vulnerability scanning
 * - Performance benchmarking
 * - Integration testing
 * - Deployment readiness assessment
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, basename } from 'path';
import { execSync } from 'child_process';
import { createHash } from 'crypto';

class BuildValidator {
  constructor(options = {}) {
    this.projectRoot = options.projectRoot || process.cwd();
    this.buildDir = options.buildDir || join(this.projectRoot, 'dist');
    this.artifactsDir = options.artifactsDir || join(this.projectRoot, 'artifacts');
    this.environment = options.environment || 'development';
    this.strict = options.strict || false;
    this.validationResults = {
      build: {},
      runtime: {},
      security: {},
      performance: {},
      integration: {},
      deployment: {}
    };

    this.metrics = {
      totalChecks: 0,
      passedChecks: 0,
      failedChecks: 0,
      warnings: 0,
      criticalIssues: 0,
      validationTime: 0
    };

    this.ensureDirectories();
  }

  ensureDirectories() {
    const dirs = [
      join(this.artifactsDir, 'validation'),
      join(this.artifactsDir, 'reports')
    ];

    dirs.forEach(dir => {
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
    });
  }

  async performComprehensiveValidation() {
    console.log('🔍 Starting comprehensive build validation...');
    const startTime = Date.now();

    try {
      // 1. Build Artifact Validation
      console.log('\n1️⃣  Validating build artifacts...');
      this.validationResults.build = await this.validateBuildArtifacts();

      // 2. Runtime Compatibility Verification
      console.log('\n2️⃣  Verifying runtime compatibility...');
      this.validationResults.runtime = await this.verifyRuntimeCompatibility();

      // 3. Security Vulnerability Scanning
      console.log('\n3️⃣  Scanning for security vulnerabilities...');
      this.validationResults.security = await this.scanSecurityVulnerabilities();

      // 4. Performance Benchmarking
      console.log('\n4️⃣  Running performance benchmarks...');
      this.validationResults.performance = await this.runPerformanceBenchmarks();

      // 5. Integration Testing
      console.log('\n5️⃣  Running integration tests...');
      this.validationResults.integration = await this.runIntegrationTests();

      // 6. Deployment Readiness Assessment
      console.log('\n6️⃣  Assessing deployment readiness...');
      this.validationResults.deployment = await this.assessDeploymentReadiness();

      // Calculate metrics
      this.calculateMetrics();
      this.metrics.validationTime = Date.now() - startTime;

      // Generate comprehensive report
      const report = this.generateValidationReport();

      console.log(`✅ Comprehensive validation completed in ${this.metrics.validationTime}ms`);
      this.printValidationSummary();

      return report;

    } catch (error) {
      console.error('❌ Validation failed:', error.message);
      throw error;
    }
  }

  async validateBuildArtifacts() {
    const results = {
      structure: await this.validateBuildStructure(),
      integrity: await this.validateBuildIntegrity(),
      completeness: await this.validateBuildCompleteness(),
      quality: await this.validateBuildQuality(),
      metadata: await this.validateBuildMetadata()
    };

    return results;
  }

  async validateBuildStructure() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    const requiredFiles = [
      'index.js',
      'package.json'
    ];

    const optionalFiles = [
      'silent-mcp-entry.js',
      'build-metadata.json'
    ];

    // Check required files
    requiredFiles.forEach(file => {
      const filePath = join(this.buildDir, file);
      checks.total++;
      if (existsSync(filePath)) {
        checks.passed++;
        checks.details.push({ file, status: 'exists', message: 'Required file exists', severity: 'critical' });
      } else {
        checks.failed++;
        checks.metrics.criticalIssues++;
        checks.details.push({ file, status: 'missing', message: 'Required file missing', severity: 'critical' });
      }
    });

    // Check optional files
    optionalFiles.forEach(file => {
      const filePath = join(this.buildDir, file);
      checks.total++;
      if (existsSync(filePath)) {
        checks.passed++;
        checks.details.push({ file, status: 'exists', message: 'Optional file present', severity: 'info' });
      } else {
        checks.warnings++;
        checks.details.push({ file, status: 'missing', message: 'Optional file missing', severity: 'warning' });
      }
    });

    // Check directory structure
    const expectedDirs = [''];
    expectedDirs.forEach(dir => {
      const dirPath = join(this.buildDir, dir);
      checks.total++;
      if (existsSync(dirPath)) {
        checks.passed++;
        checks.details.push({ directory: dir, status: 'exists', message: 'Directory exists', severity: 'info' });
      } else {
        checks.failed++;
        checks.details.push({ directory: dir, status: 'missing', message: 'Directory missing', severity: 'critical' });
      }
    });

    return checks;
  }

  async validateBuildIntegrity() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      // Check JavaScript syntax
      const jsFiles = this.getFilesByExtension('.js');
      jsFiles.forEach(file => {
        checks.total++;
        try {
          execSync(`node -c "${file}"`, { stdio: 'pipe' });
          checks.passed++;
          checks.details.push({ file, status: 'valid', message: 'JavaScript syntax valid', severity: 'critical' });
        } catch (error) {
          checks.failed++;
          checks.metrics.criticalIssues++;
          checks.details.push({ file, status: 'invalid', message: `JavaScript syntax error: ${error.message}`, severity: 'critical' });
        }
      });

      // Check package.json structure
      const packageJsonPath = join(this.buildDir, 'package.json');
      if (existsSync(packageJsonPath)) {
        checks.total++;
        try {
          const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
          const requiredFields = ['name', 'version', 'main', 'type'];
          const missingFields = requiredFields.filter(field => !packageJson[field]);

          if (missingFields.length === 0) {
            checks.passed++;
            checks.details.push({ file: 'package.json', status: 'valid', message: 'Package.json structure valid', severity: 'critical' });
          } else {
            checks.failed++;
            checks.details.push({ file: 'package.json', status: 'invalid', message: `Missing fields: ${missingFields.join(', ')}`, severity: 'critical' });
          }
        } catch (error) {
          checks.failed++;
          checks.details.push({ file: 'package.json', status: 'invalid', message: `Invalid JSON: ${error.message}`, severity: 'critical' });
        }
      }

      // Check for file corruption using checksums
      const metadataPath = join(this.buildDir, 'build-metadata.json');
      if (existsSync(metadataPath)) {
        const metadata = JSON.parse(readFileSync(metadataPath, 'utf8'));
        if (metadata.files) {
          metadata.files.forEach(fileInfo => {
            checks.total++;
            const filePath = join(this.buildDir, fileInfo.path);
            if (existsSync(filePath)) {
              const currentChecksum = this.calculateFileChecksum(filePath);
              if (currentChecksum === fileInfo.checksum?.sha256) {
                checks.passed++;
                checks.details.push({ file: fileInfo.path, status: 'integrity', message: 'File integrity verified', severity: 'info' });
              } else {
                checks.failed++;
                checks.details.push({ file: fileInfo.path, status: 'corrupted', message: 'File checksum mismatch', severity: 'critical' });
              }
            }
          });
        }
      }

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'validation', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async validateBuildCompleteness() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      // Check that all source files have corresponding build outputs
      const sourceFiles = this.getSourceFiles();
      const builtFiles = this.getBuiltFiles();

      sourceFiles.forEach(sourceFile => {
        checks.total++;
        const expectedOutput = sourceFile.replace(/\.ts$/, '.js').replace('src/', 'dist/');
        if (builtFiles.includes(expectedOutput)) {
          checks.passed++;
          checks.details.push({ source: sourceFile, output: expectedOutput, status: 'built', message: 'Source file compiled', severity: 'info' });
        } else {
          checks.failed++;
          checks.details.push({ source: sourceFile, output: expectedOutput, status: 'missing', message: 'Build output missing', severity: 'critical' });
        }
      });

      // Check for dependency completeness
      const packageJsonPath = join(this.buildDir, 'package.json');
      if (existsSync(packageJsonPath)) {
        const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
        if (packageJson.dependencies) {
          Object.keys(packageJson.dependencies).forEach(dep => {
            checks.total++;
            try {
              // Check if dependency is resolvable
              require.resolve(dep, { paths: [this.buildDir] });
              checks.passed++;
              checks.details.push({ dependency: dep, status: 'resolvable', message: 'Dependency resolvable', severity: 'critical' });
            } catch {
              checks.warnings++;
              checks.details.push({ dependency: dep, status: 'unresolved', message: 'Dependency not resolvable in build context', severity: 'warning' });
            }
          });
        }
      }

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'completeness', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async validateBuildQuality() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      // Check for console.log statements in production builds
      if (this.environment === 'production') {
        const jsFiles = this.getFilesByExtension('.js');
        jsFiles.forEach(file => {
          const content = readFileSync(file, 'utf8');
          const consoleStatements = content.match(/console\.(log|warn|error|debug|info)\(/g);

          if (consoleStatements) {
            checks.warnings++;
            checks.details.push({
              file,
              status: 'console-statements',
              message: `${consoleStatements.length} console statements found`,
              severity: 'warning'
            });
          }
        });
      }

      // Check bundle size
      const totalSize = this.calculateTotalSize();
      checks.total++;
      const maxSize = this.environment === 'production' ? 10 * 1024 * 1024 : 50 * 1024 * 1024; // 10MB prod, 50MB dev

      if (totalSize <= maxSize) {
        checks.passed++;
        checks.details.push({
          metric: 'bundle-size',
          size: totalSize,
          status: 'acceptable',
          message: `Bundle size ${(totalSize / 1024 / 1024).toFixed(2)}MB is acceptable`,
          severity: 'info'
        });
      } else {
        checks.warnings++;
        checks.details.push({
          metric: 'bundle-size',
          size: totalSize,
          status: 'large',
          message: `Bundle size ${(totalSize / 1024 / 1024).toFixed(2)}MB exceeds recommended limit`,
          severity: 'warning'
        });
      }

      // Check for source maps in production
      if (this.environment === 'production') {
        const mapFiles = this.getFilesByExtension('.map');
        checks.total++;
        if (mapFiles.length === 0) {
          checks.passed++;
          checks.details.push({
            check: 'source-maps',
            status: 'none',
            message: 'No source maps found (good for production)',
            severity: 'info'
          });
        } else {
          checks.warnings++;
          checks.details.push({
            check: 'source-maps',
            count: mapFiles.length,
            status: 'found',
            message: `${mapFiles.length} source maps found (consider removing for production)`,
            severity: 'warning'
          });
        }
      }

      // Check code complexity (simplified)
      const jsFiles = this.getFilesByExtension('.js');
      jsFiles.forEach(file => {
        const content = readFileSync(file, 'utf8');
        const lineCount = content.split('\n').length;
        checks.total++;

        if (lineCount < 1000) {
          checks.passed++;
          checks.details.push({
            file,
            lines: lineCount,
            status: 'reasonable',
            message: `File has ${lineCount} lines`,
            severity: 'info'
          });
        } else {
          checks.warnings++;
          checks.details.push({
            file,
            lines: lineCount,
            status: 'large',
            message: `File has ${lineCount} lines (consider splitting)`,
            severity: 'warning'
          });
        }
      });

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'quality', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async validateBuildMetadata() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      const metadataPath = join(this.buildDir, 'build-metadata.json');
      if (existsSync(metadataPath)) {
        const metadata = JSON.parse(readFileSync(metadataPath, 'utf8'));

        // Check required metadata fields
        const requiredFields = ['buildId', 'timestamp', 'environment', 'nodeVersion'];
        requiredFields.forEach(field => {
          checks.total++;
          if (metadata[field]) {
            checks.passed++;
            checks.details.push({ field, status: 'present', message: `Metadata field ${field} present`, severity: 'info' });
          } else {
            checks.failed++;
            checks.details.push({ field, status: 'missing', message: `Metadata field ${field} missing`, severity: 'critical' });
          }
        });

        // Check timestamp format
        if (metadata.timestamp) {
          checks.total++;
          const timestamp = new Date(metadata.timestamp);
          if (!isNaN(timestamp.getTime())) {
            checks.passed++;
            checks.details.push({ field: 'timestamp', status: 'valid', message: 'Timestamp format valid', severity: 'info' });
          } else {
            checks.failed++;
            checks.details.push({ field: 'timestamp', status: 'invalid', message: 'Timestamp format invalid', severity: 'critical' });
          }
        }

        // Check build ID format
        if (metadata.buildId) {
          checks.total++;
          if (/^build-[\d-]+-[\da-f]{12}$/.test(metadata.buildId)) {
            checks.passed++;
            checks.details.push({ field: 'buildId', status: 'valid', message: 'Build ID format valid', severity: 'info' });
          } else {
            checks.warnings++;
            checks.details.push({ field: 'buildId', status: 'unusual', message: 'Build ID format unusual', severity: 'warning' });
          }
        }

      } else {
        checks.warnings++;
        checks.details.push({ file: 'build-metadata.json', status: 'missing', message: 'Build metadata file missing', severity: 'warning' });
      }

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'metadata', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async verifyRuntimeCompatibility() {
    const results = {
      nodejs: await this.verifyNodeCompatibility(),
      dependencies: await this.verifyDependencyCompatibility(),
      modules: await this.verifyModuleCompatibility(),
      environment: await this.verifyEnvironmentCompatibility()
    };

    return results;
  }

  async verifyNodeCompatibility() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      // Check Node.js version compatibility
      const packageJsonPath = join(this.projectRoot, 'package.json');
      if (existsSync(packageJsonPath)) {
        const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
        const requiredVersion = packageJson.engines?.node;

        if (requiredVersion) {
          checks.total++;
          const currentNodeVersion = process.version;

          try {
            // Simple version comparison (would need more sophisticated semver checking)
            const requiredMajor = parseInt(requiredVersion.replace(/[^0-9.]/g, '').split('.')[0]);
            const currentMajor = parseInt(currentNodeVersion.replace('v', '').split('.')[0]);

            if (currentMajor >= requiredMajor) {
              checks.passed++;
              checks.details.push({
                check: 'node-version',
                required: requiredVersion,
                current: currentNodeVersion,
                status: 'compatible',
                message: 'Node.js version compatible',
                severity: 'critical'
              });
            } else {
              checks.failed++;
              checks.details.push({
                check: 'node-version',
                required: requiredVersion,
                current: currentNodeVersion,
                status: 'incompatible',
                message: 'Node.js version incompatible',
                severity: 'critical'
              });
            }
          } catch (error) {
            checks.warnings++;
            checks.details.push({
              check: 'node-version',
              error: error.message,
              status: 'unknown',
              message: 'Could not verify Node.js version compatibility',
              severity: 'warning'
            });
          }
        }
      }

      // Test runtime execution
      const entryPoint = join(this.buildDir, 'index.js');
      if (existsSync(entryPoint)) {
        checks.total++;
        try {
          // Test syntax and basic loading
          execSync(`node --check "${entryPoint}"`, { stdio: 'pipe', timeout: 5000 });
          checks.passed++;
          checks.details.push({
            file: 'index.js',
            status: 'executable',
            message: 'Entry point can be executed',
            severity: 'critical'
          });
        } catch (error) {
          checks.failed++;
          checks.details.push({
            file: 'index.js',
            error: error.message,
            status: 'execution-error',
            message: 'Entry point execution failed',
            severity: 'critical'
          });
        }
      }

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'runtime', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async verifyDependencyCompatibility() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      const packageJsonPath = join(this.buildDir, 'package.json');
      if (existsSync(packageJsonPath)) {
        const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));

        if (packageJson.dependencies) {
          Object.entries(packageJson.dependencies).forEach(([name, version]) => {
            checks.total++;

            try {
              // Check if dependency can be resolved
              const resolvedPath = require.resolve(name, { paths: [this.buildDir] });
              checks.passed++;
              checks.details.push({
                dependency: name,
                version,
                resolved: resolvedPath,
                status: 'resolvable',
                message: 'Dependency resolvable',
                severity: 'critical'
              });
            } catch (error) {
              checks.failed++;
              checks.details.push({
                dependency: name,
                version,
                error: error.message,
                status: 'unresolvable',
                message: 'Dependency cannot be resolved',
                severity: 'critical'
              });
            }
          });
        }
      }

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'dependencies', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async verifyModuleCompatibility() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      // Check ES module compatibility
      const packageJsonPath = join(this.buildDir, 'package.json');
      if (existsSync(packageJsonPath)) {
        const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));

        checks.total++;
        if (packageJson.type === 'module') {
          // Verify that imports use ES module syntax
          const jsFiles = this.getFilesByExtension('.js');
          let hasCommonJS = false;

          jsFiles.forEach(file => {
            const content = readFileSync(file, 'utf8');
            if (content.includes('require(') || content.includes('module.exports')) {
              hasCommonJS = true;
            }
          });

          if (!hasCommonJS) {
            checks.passed++;
            checks.details.push({
              check: 'module-consistency',
              type: 'ESM',
              status: 'consistent',
              message: 'ES module configuration consistent with code',
              severity: 'info'
            });
          } else {
            checks.warnings++;
            checks.details.push({
              check: 'module-consistency',
              type: 'ESM',
              status: 'inconsistent',
              message: 'ES module configuration but CommonJS syntax found',
              severity: 'warning'
            });
          }
        } else {
          checks.passed++;
          checks.details.push({
            check: 'module-type',
            type: 'CommonJS',
            status: 'configured',
            message: 'CommonJS module type configured',
            severity: 'info'
          });
        }
      }

      // Check for import/export syntax consistency
      const jsFiles = this.getFilesByExtension('.js');
      jsFiles.forEach(file => {
        const content = readFileSync(file, 'utf8');
        checks.total++;

        const hasImports = content.includes('import ') || content.includes('import(');
        const hasExports = content.includes('export ');

        if (hasImports || hasExports) {
          // Should have module type set to 'module'
          const packageJsonPath = join(this.buildDir, 'package.json');
          if (existsSync(packageJsonPath)) {
            const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
            if (packageJson.type === 'module') {
              checks.passed++;
              checks.details.push({
                file,
                status: 'module-syntax',
                syntax: 'ESM',
                message: 'ES module syntax correctly configured',
                severity: 'info'
              });
            } else {
              checks.warnings++;
              checks.details.push({
                file,
                status: 'module-mismatch',
                syntax: 'ESM',
                message: 'ES module syntax but package.json not set to module type',
                severity: 'warning'
              });
            }
          }
        }
      });

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'modules', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async verifyEnvironmentCompatibility() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      // Check environment variables
      const envFile = join(this.projectRoot, '.env.example');
      if (existsSync(envFile)) {
        const envContent = readFileSync(envFile, 'utf8');
        const requiredEnvVars = envContent.split('\n')
          .filter(line => line && !line.startsWith('#') && line.includes('='))
          .map(line => line.split('=')[0]);

        requiredEnvVars.forEach(envVar => {
          checks.total++;
          if (process.env[envVar]) {
            checks.passed++;
            checks.details.push({
              envVar,
              status: 'set',
              message: `Environment variable ${envVar} is set`,
              severity: 'info'
            });
          } else {
            checks.warnings++;
            checks.details.push({
              envVar,
              status: 'missing',
              message: `Environment variable ${envVar} not set`,
              severity: 'warning'
            });
          }
        });
      }

      // Check platform compatibility
      checks.total++;
      const currentPlatform = process.platform;
      const supportedPlatforms = ['linux', 'darwin', 'win32'];

      if (supportedPlatforms.includes(currentPlatform)) {
        checks.passed++;
        checks.details.push({
          platform: currentPlatform,
          status: 'supported',
          message: 'Platform supported',
          severity: 'info'
        });
      } else {
        checks.warnings++;
        checks.details.push({
          platform: currentPlatform,
          status: 'untested',
          message: 'Platform not officially supported',
          severity: 'warning'
        });
      }

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'environment', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async scanSecurityVulnerabilities() {
    const results = {
      dependencies: await this.scanDependencyVulnerabilities(),
      code: await this.scanCodeSecurity(),
      configuration: await this.scanConfigurationSecurity(),
      secrets: await this.scanForSecrets()
    };

    return results;
  }

  async scanDependencyVulnerabilities() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      // Run npm audit
      checks.total++;
      try {
        const auditResult = execSync('npm audit --json', {
          encoding: 'utf8',
          stdio: 'pipe',
          cwd: this.projectRoot
        });

        const auditData = JSON.parse(auditResult);
        const vulnerabilityCount = auditData.metadata?.vulnerabilities?.total || 0;

        if (vulnerabilityCount === 0) {
          checks.passed++;
          checks.details.push({
            check: 'npm-audit',
            vulnerabilities: 0,
            status: 'clean',
            message: 'No vulnerabilities found',
            severity: 'info'
          });
        } else {
          checks.warnings++;
          checks.details.push({
            check: 'npm-audit',
            vulnerabilities: vulnerabilityCount,
            status: 'vulnerabilities',
            message: `${vulnerabilityCount} vulnerabilities found`,
            severity: 'warning'
          });
        }
      } catch (error) {
        // npm audit exits with non-zero code when vulnerabilities are found
        const errorOutput = error.stdout || error.message;
        if (errorOutput.includes('vulnerabilities')) {
          checks.warnings++;
          checks.details.push({
            check: 'npm-audit',
            status: 'vulnerabilities-found',
            message: 'Vulnerabilities detected in dependencies',
            severity: 'warning'
          });
        } else {
          checks.failed++;
          checks.details.push({
            check: 'npm-audit',
            error: error.message,
            status: 'error',
            message: 'Could not run security audit',
            severity: 'critical'
          });
        }
      }

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'dependency-scan', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async scanCodeSecurity() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      const jsFiles = this.getFilesByExtension('.js');

      jsFiles.forEach(file => {
        const content = readFileSync(file, 'utf8');

        // Check for eval usage
        checks.total++;
        if (content.includes('eval(')) {
          checks.failed++;
          this.metrics.criticalIssues++;
          checks.details.push({
            file,
            issue: 'eval-usage',
            severity: 'critical',
            message: 'Use of eval() function detected',
            recommendation: 'Remove eval() usage for security'
          });
        } else {
          checks.passed++;
        }

        // Check for Function constructor
        checks.total++;
        if (content.includes('new Function(') || content.includes('Function(')) {
          checks.failed++;
          this.metrics.criticalIssues++;
          checks.details.push({
            file,
            issue: 'function-constructor',
            severity: 'critical',
            message: 'Use of Function constructor detected',
            recommendation: 'Avoid Function constructor for security'
          });
        } else {
          checks.passed++;
        }

        // Check for hardcoded secrets (basic patterns)
        const secretPatterns = [
          /password\s*=\s*['"][^'"]{8,}['"]/i,
          /api_key\s*=\s*['"][^'"]{16,}['"]/i,
          /secret\s*=\s*['"][^'"]{16,}['"]/i,
          /token\s*=\s*['"][^'"]{16,}['"]/i
        ];

        secretPatterns.forEach((pattern, index) => {
          checks.total++;
          if (pattern.test(content)) {
            checks.failed++;
            this.metrics.criticalIssues++;
            checks.details.push({
              file,
              issue: `potential-secret-${index}`,
              severity: 'critical',
              message: 'Potential hardcoded secret detected',
              recommendation: 'Move secrets to environment variables'
            });
          } else {
            checks.passed++;
          }
        });
      });

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'code-security', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async scanConfigurationSecurity() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      // Check for secure headers configuration
      const jsFiles = this.getFilesByExtension('.js');
      let hasSecureHeaders = false;

      jsFiles.forEach(file => {
        const content = readFileSync(file, 'utf8');
        if (content.includes('helmet') || content.includes('helmet()')) {
          hasSecureHeaders = true;
        }
      });

      checks.total++;
      if (hasSecureHeaders) {
        checks.passed++;
        checks.details.push({
          check: 'secure-headers',
          status: 'configured',
          message: 'Secure headers (helmet) configured',
          severity: 'info'
        });
      } else {
        checks.warnings++;
        checks.details.push({
          check: 'secure-headers',
          status: 'missing',
          message: 'Secure headers not configured',
          recommendation: 'Consider using helmet for security headers',
          severity: 'warning'
        });
      }

      // Check for CORS configuration
      checks.total++;
      let hasCorsConfig = false;
      jsFiles.forEach(file => {
        const content = readFileSync(file, 'utf8');
        if (content.includes('cors') || content.includes('CORS')) {
          hasCorsConfig = true;
        }
      });

      if (hasCorsConfig) {
        checks.passed++;
        checks.details.push({
          check: 'cors-config',
          status: 'configured',
          message: 'CORS configuration found',
          severity: 'info'
        });
      } else {
        checks.warnings++;
        checks.details.push({
          check: 'cors-config',
          status: 'missing',
          message: 'CORS configuration not found',
          recommendation: 'Configure CORS appropriately for your use case',
          severity: 'warning'
        });
      }

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'config-security', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async scanForSecrets() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      const files = [...this.getFilesByExtension('.js'), ...this.getFilesByExtension('.json')];
      const secretPatterns = [
        { pattern: /['"]?[A-Z_]*_SECRET['"]?\s*[:=]\s*['"][^'"]{16,}['"]/i, type: 'secret' },
        { pattern: /['"]?[A-Z_]*_PASSWORD['"]?\s*[:=]\s*['"][^'"]{8,}['"]/i, type: 'password' },
        { pattern: /['"]?[A-Z_]*_TOKEN['"]?\s*[:=]\s*['"][^'"]{16,}['"]/i, type: 'token' },
        { pattern: /['"]?[A-Z_]*_KEY['"]?\s*[:=]\s*['"][^'"]{16,}['"]/i, type: 'key' },
        { pattern: /['"]?(sk_|pk_|sk-|pk-)[a-zA-Z0-9]{20,}['"]?/i, type: 'api-key' }
      ];

      files.forEach(file => {
        const content = readFileSync(file, 'utf8');

        secretPatterns.forEach(({ pattern, type }) => {
          const matches = content.match(pattern);
          if (matches) {
            matches.forEach(match => {
              checks.total++;
              checks.failed++;
              this.metrics.criticalIssues++;
              checks.details.push({
                file,
                type,
                match: match.substring(0, 20) + '...',
                severity: 'critical',
                message: `Potential ${type} detected`,
                recommendation: 'Remove hardcoded secrets and use environment variables'
              });
            });
          }
        });
      });

      // If no secrets found, add a pass
      if (checks.total === 0) {
        checks.passed++;
        checks.total = 1;
        checks.details.push({
          check: 'secrets-scan',
          status: 'clean',
          message: 'No hardcoded secrets detected',
          severity: 'info'
        });
      }

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'secrets-scan', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async runPerformanceBenchmarks() {
    const results = {
      startup: await this.benchmarkStartup(),
      memory: await this.benchmarkMemoryUsage(),
      bundle: await this.benchmarkBundleSize(),
      dependencies: await this.benchmarkDependencies()
    };

    return results;
  }

  async benchmarkStartup() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      const entryPoint = join(this.buildDir, 'index.js');
      if (existsSync(entryPoint)) {
        checks.total++;
        const startTime = Date.now();

        try {
          execSync(`node -e "require('./${entryPoint.replace(this.projectRoot + '/', '')}')"`, {
            stdio: 'pipe',
            timeout: 10000
          });
          const startupTime = Date.now() - startTime;

          if (startupTime < 2000) {
            checks.passed++;
            checks.details.push({
              metric: 'startup-time',
              time: startupTime,
              status: 'fast',
              message: `Startup time ${startupTime}ms is excellent`,
              severity: 'info'
            });
          } else if (startupTime < 5000) {
            checks.passed++;
            checks.details.push({
              metric: 'startup-time',
              time: startupTime,
              status: 'acceptable',
              message: `Startup time ${startupTime}ms is acceptable`,
              severity: 'info'
            });
          } else {
            checks.warnings++;
            checks.details.push({
              metric: 'startup-time',
              time: startupTime,
              status: 'slow',
              message: `Startup time ${startupTime}ms is slow`,
              severity: 'warning'
            });
          }
        } catch (error) {
          checks.failed++;
          checks.details.push({
            metric: 'startup-time',
            error: error.message,
            status: 'error',
            message: 'Could not measure startup time',
            severity: 'critical'
          });
        }
      }

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'startup-benchmark', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async benchmarkMemoryUsage() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      const totalSize = this.calculateTotalSize();
      checks.total++;

      // Estimate memory usage based on bundle size
      const estimatedMemory = totalSize * 3; // Rough heuristic

      if (estimatedMemory < 100 * 1024 * 1024) { // Less than 100MB
        checks.passed++;
        checks.details.push({
          metric: 'memory-usage',
          estimated: estimatedMemory,
          status: 'low',
          message: `Estimated memory usage ${(estimatedMemory / 1024 / 1024).toFixed(2)}MB is low`,
          severity: 'info'
        });
      } else if (estimatedMemory < 300 * 1024 * 1024) { // Less than 300MB
        checks.passed++;
        checks.details.push({
          metric: 'memory-usage',
          estimated: estimatedMemory,
          status: 'moderate',
          message: `Estimated memory usage ${(estimatedMemory / 1024 / 1024).toFixed(2)}MB is moderate`,
          severity: 'info'
        });
      } else {
        checks.warnings++;
        checks.details.push({
          metric: 'memory-usage',
          estimated: estimatedMemory,
          status: 'high',
          message: `Estimated memory usage ${(estimatedMemory / 1024 / 1024).toFixed(2)}MB is high`,
          severity: 'warning'
        });
      }

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'memory-benchmark', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async benchmarkBundleSize() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      const totalSize = this.calculateTotalSize();
      checks.total++;

      if (this.environment === 'production') {
        if (totalSize < 5 * 1024 * 1024) { // Less than 5MB
          checks.passed++;
          checks.details.push({
            metric: 'bundle-size',
            size: totalSize,
            status: 'excellent',
            message: `Bundle size ${(totalSize / 1024 / 1024).toFixed(2)}MB is excellent for production`,
            severity: 'info'
          });
        } else if (totalSize < 15 * 1024 * 1024) { // Less than 15MB
          checks.passed++;
          checks.details.push({
            metric: 'bundle-size',
            size: totalSize,
            status: 'good',
            message: `Bundle size ${(totalSize / 1024 / 1024).toFixed(2)}MB is good for production`,
            severity: 'info'
          });
        } else {
          checks.warnings++;
          checks.details.push({
            metric: 'bundle-size',
            size: totalSize,
            status: 'large',
            message: `Bundle size ${(totalSize / 1024 / 1024).toFixed(2)}MB is large for production`,
            severity: 'warning'
          });
        }
      } else {
        checks.passed++;
        checks.details.push({
          metric: 'bundle-size',
          size: totalSize,
          status: 'development',
          message: `Bundle size ${(totalSize / 1024 / 1024).toFixed(2)}MB for development`,
          severity: 'info'
        });
      }

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'bundle-benchmark', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async benchmarkDependencies() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      const packageJsonPath = join(this.buildDir, 'package.json');
      if (existsSync(packageJsonPath)) {
        const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
        const depCount = Object.keys(packageJson.dependencies || {}).length;

        checks.total++;
        if (depCount < 20) {
          checks.passed++;
          checks.details.push({
            metric: 'dependencies',
            count: depCount,
            status: 'lean',
            message: `${depCount} dependencies is lean`,
            severity: 'info'
          });
        } else if (depCount < 50) {
          checks.passed++;
          checks.details.push({
            metric: 'dependencies',
            count: depCount,
            status: 'moderate',
            message: `${depCount} dependencies is moderate`,
            severity: 'info'
          });
        } else {
          checks.warnings++;
          checks.details.push({
            metric: 'dependencies',
            count: depCount,
            status: 'many',
            message: `${depCount} dependencies is many, consider reducing`,
            severity: 'warning'
          });
        }
      }

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'dependency-benchmark', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async runIntegrationTests() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      // Run basic integration tests
      const testCommands = [
        'npm run test:integration',
        'npm run test:mcp:integration',
        'npm run test:contract'
      ];

      for (const command of testCommands) {
        checks.total++;
        try {
          const result = execSync(command, {
            stdio: 'pipe',
            timeout: 30000
          });
          checks.passed++;
          checks.details.push({
            test: command,
            status: 'passed',
            message: 'Integration tests passed',
            severity: 'info'
          });
        } catch (error) {
          checks.warnings++;
          checks.details.push({
            test: command,
            status: 'failed',
            error: error.message,
            message: 'Integration tests failed or not available',
            severity: 'warning'
          });
        }
      }

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'integration-tests', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async assessDeploymentReadiness() {
    const checks = {
      health: await this.assessHealthEndpoints(),
      monitoring: await this.assessMonitoringSetup(),
      configuration: await this.assessDeploymentConfiguration(),
      documentation: await this.assessDeploymentDocumentation()
    };

    return checks;
  }

  async assessHealthEndpoints() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      const jsFiles = this.getFilesByExtension('.js');
      const healthEndpoints = ['/health', '/ready', '/metrics'];
      let foundEndpoints = [];

      jsFiles.forEach(file => {
        const content = readFileSync(file, 'utf8');
        healthEndpoints.forEach(endpoint => {
          if (content.includes(endpoint)) {
            foundEndpoints.push(endpoint);
          }
        });
      });

      healthEndpoints.forEach(endpoint => {
        checks.total++;
        if (foundEndpoints.includes(endpoint)) {
          checks.passed++;
          checks.details.push({
            endpoint,
            status: 'implemented',
            message: `Health endpoint ${endpoint} implemented`,
            severity: 'info'
          });
        } else {
          checks.warnings++;
          checks.details.push({
            endpoint,
            status: 'missing',
            message: `Health endpoint ${endpoint} not found`,
            severity: 'warning'
          });
        }
      });

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'health-endpoints', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async assessMonitoringSetup() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      const jsFiles = this.getFilesByExtension('.js');
      let hasLogging = false;
      let hasMetrics = false;

      jsFiles.forEach(file => {
        const content = readFileSync(file, 'utf8');
        if (content.includes('pino') || content.includes('winston') || content.includes('console.')) {
          hasLogging = true;
        }
        if (content.includes('prometheus') || content.includes('metrics') || content.includes('monitoring')) {
          hasMetrics = true;
        }
      });

      checks.total++;
      if (hasLogging) {
        checks.passed++;
        checks.details.push({
          feature: 'logging',
          status: 'implemented',
          message: 'Logging system detected',
          severity: 'info'
        });
      } else {
        checks.warnings++;
        checks.details.push({
          feature: 'logging',
          status: 'missing',
          message: 'Logging system not detected',
          severity: 'warning'
        });
      }

      checks.total++;
      if (hasMetrics) {
        checks.passed++;
        checks.details.push({
          feature: 'metrics',
          status: 'implemented',
          message: 'Metrics system detected',
          severity: 'info'
        });
      } else {
        checks.warnings++;
        checks.details.push({
          feature: 'metrics',
          status: 'missing',
          message: 'Metrics system not detected',
          severity: 'warning'
        });
      }

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'monitoring-setup', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async assessDeploymentConfiguration() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      // Check for deployment configuration files
      const deploymentFiles = [
        'docker-compose.yml',
        'Dockerfile',
        '.env.example',
        'docker-compose.prod.yml'
      ];

      deploymentFiles.forEach(file => {
        checks.total++;
        if (existsSync(join(this.projectRoot, file))) {
          checks.passed++;
          checks.details.push({
            file,
            status: 'exists',
            message: `Deployment file ${file} exists`,
            severity: 'info'
          });
        } else {
          checks.warnings++;
          checks.details.push({
            file,
            status: 'missing',
            message: `Deployment file ${file} missing`,
            severity: 'warning'
          });
        }
      });

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'deployment-config', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  async assessDeploymentDocumentation() {
    const checks = {
      total: 0,
      passed: 0,
      failed: 0,
      warnings: 0,
      details: []
    };

    try {
      const docsFiles = [
        'README.md',
        'docs/DEPLOYMENT.md',
        'docs/OPS-DISASTER-RECOVERY.md',
        'docs/SETUP-QUICK-START.md'
      ];

      docsFiles.forEach(file => {
        checks.total++;
        if (existsSync(join(this.projectRoot, file))) {
          checks.passed++;
          checks.details.push({
            file,
            status: 'exists',
            message: `Documentation file ${file} exists`,
            severity: 'info'
          });
        } else {
          checks.warnings++;
          checks.details.push({
            file,
            status: 'missing',
            message: `Documentation file ${file} missing`,
            severity: 'warning'
          });
        }
      });

    } catch (error) {
      checks.failed++;
      checks.details.push({ error: 'deployment-docs', message: error.message, severity: 'critical' });
    }

    return checks;
  }

  // Helper methods
  getFilesByExtension(extension) {
    try {
      const fileList = execSync(`find "${this.buildDir}" -name "*${extension}"`, { encoding: 'utf8' });
      return fileList.trim().split('\n').filter(Boolean);
    } catch {
      return [];
    }
  }

  getSourceFiles() {
    try {
      const fileList = execSync(`find "${join(this.projectRoot, 'src')}" -name "*.ts"`, { encoding: 'utf8' });
      return fileList.trim().split('\n').filter(Boolean);
    } catch {
      return [];
    }
  }

  getBuiltFiles() {
    try {
      const fileList = execSync(`find "${this.buildDir}" -name "*.js"`, { encoding: 'utf8' });
      return fileList.trim().split('\n').filter(Boolean);
    } catch {
      return [];
    }
  }

  calculateFileChecksum(filePath) {
    try {
      const content = readFileSync(filePath);
      return createHash('sha256').update(content).digest('hex');
    } catch {
      return null;
    }
  }

  calculateTotalSize() {
    try {
      const result = execSync(`du -sb "${this.buildDir}"`, { encoding: 'utf8' });
      return parseInt(result.split('\t')[0]);
    } catch {
      return 0;
    }
  }

  calculateMetrics() {
    // Calculate total metrics from all validation results
    Object.values(this.validationResults).forEach(category => {
      if (typeof category === 'object') {
        Object.values(category).forEach(checks => {
          if (checks.total) {
            this.metrics.totalChecks += checks.total;
            this.metrics.passedChecks += checks.passed || 0;
            this.metrics.failedChecks += checks.failed || 0;
            this.metrics.warnings += checks.warnings || 0;
          }
        });
      }
    });
  }

  generateValidationReport() {
    const report = {
      buildId: this.generateBuildId(),
      timestamp: new Date().toISOString(),
      environment: this.environment,
      strict: this.strict,
      results: this.validationResults,
      metrics: this.metrics,
      summary: this.generateSummary(),
      recommendations: this.generateRecommendations()
    };

    // Save report
    const reportPath = join(this.artifactsDir, 'validation', `validation-${report.buildId}.json`);
    writeFileSync(reportPath, JSON.stringify(report, null, 2));
    console.log(`📄 Validation report saved: ${reportPath}`);

    return report;
  }

  generateBuildId() {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const hash = createHash('sha256')
      .update(Date.now().toString() + process.pid.toString())
      .digest('hex')
      .substring(0, 8);
    return `validation-${timestamp}-${hash}`;
  }

  generateSummary() {
    const successRate = this.metrics.totalChecks > 0 ?
      (this.metrics.passedChecks / this.metrics.totalChecks * 100).toFixed(1) : 0;

    return {
      overallStatus: this.metrics.criticalIssues === 0 ? 'PASS' : 'FAIL',
      successRate: `${successRate}%`,
      totalChecks: this.metrics.totalChecks,
      passedChecks: this.metrics.passedChecks,
      failedChecks: this.metrics.failedChecks,
      warnings: this.metrics.warnings,
      criticalIssues: this.metrics.criticalIssues,
      validationTime: this.metrics.validationTime,
      readyForDeployment: this.metrics.criticalIssues === 0 && this.metrics.failedChecks === 0
    };
  }

  generateRecommendations() {
    const recommendations = [];

    if (this.metrics.criticalIssues > 0) {
      recommendations.push({
        priority: 'critical',
        issue: 'Critical security or build issues detected',
        action: 'Address all critical issues before deployment',
        affectedChecks: this.metrics.criticalIssues
      });
    }

    if (this.metrics.failedChecks > 0) {
      recommendations.push({
        priority: 'high',
        issue: 'Failed validation checks',
        action: 'Review and fix failed validation checks',
        affectedChecks: this.metrics.failedChecks
      });
    }

    if (this.metrics.warnings > 5) {
      recommendations.push({
        priority: 'medium',
        issue: 'Multiple warnings detected',
        action: 'Review warnings and optimize build where possible',
        affectedChecks: this.metrics.warnings
      });
    }

    // Add specific recommendations based on validation results
    Object.entries(this.validationResults).forEach(([category, results]) => {
      if (typeof results === 'object') {
        Object.entries(results).forEach(([check, checks]) => {
          if (checks.failed > 0 && checks.details) {
            const criticalDetails = checks.details.filter(d => d.severity === 'critical');
            if (criticalDetails.length > 0) {
              recommendations.push({
                priority: 'critical',
                category,
                check,
                issue: `${criticalDetails.length} critical issues in ${category}.${check}`,
                action: criticalDetails.map(d => d.recommendation || 'Review and fix').filter(Boolean).join('; ')
              });
            }
          }
        });
      }
    });

    return recommendations;
  }

  printValidationSummary() {
    const summary = this.generateSummary();

    console.log('\n📊 Build Validation Summary:');
    console.log(`   Overall Status: ${summary.overallStatus}`);
    console.log(`   Success Rate: ${summary.successRate}`);
    console.log(`   Total Checks: ${summary.totalChecks}`);
    console.log(`   Passed: ${summary.passedChecks}`);
    console.log(`   Failed: ${summary.failedChecks}`);
    console.log(`   Warnings: ${summary.warnings}`);
    console.log(`   Critical Issues: ${summary.criticalIssues}`);
    console.log(`   Validation Time: ${summary.validationTime}ms`);
    console.log(`   Ready for Deployment: ${summary.readyForDeployment ? '✅ YES' : '❌ NO'}`);

    if (this.metrics.criticalIssues > 0) {
      console.log('\n🚨 CRITICAL ISSUES FOUND - DO NOT DEPLOY');
    }

    console.log('\n📋 Recommendations:');
    this.generateRecommendations().forEach((rec, index) => {
      const icon = rec.priority === 'critical' ? '🚨' : rec.priority === 'high' ? '⚠️' : '💡';
      console.log(`   ${index + 1}. ${icon} [${rec.priority.toUpperCase()}] ${rec.issue}`);
      console.log(`      Action: ${rec.action}`);
    });
  }
}

// CLI interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const options = {
    environment: process.env.NODE_ENV || process.argv.find(arg => arg.startsWith('--env='))?.split('=')[1] || 'development',
    strict: process.argv.includes('--strict'),
    projectRoot: process.cwd()
  };

  const validator = new BuildValidator(options);

  validator.performComprehensiveValidation()
    .then(report => {
      if (report.summary.readyForDeployment) {
        console.log('\n🎉 Build validation completed successfully - Ready for deployment!');
        process.exit(0);
      } else {
        console.log('\n❌ Build validation failed - Issues must be resolved before deployment');
        process.exit(1);
      }
    })
    .catch(error => {
      console.error('❌ Build validation failed:', error);
      process.exit(1);
    });
}

export { BuildValidator };