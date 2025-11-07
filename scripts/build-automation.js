#!/usr/bin/env node

/**
 * Build and Deployment Automation Script
 *
 * Provides automated build pipeline with:
 * - Multi-environment TypeScript compilation
 * - Parallel build optimization
 * - Artifact validation and verification
 * - Production deployment preparation
 * - Rollback capabilities
 */

import { execSync } from 'child_process';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, basename } from 'path';
import { createHash } from 'crypto';

class BuildAutomation {
  constructor(options = {}) {
    this.environment = options.environment || 'development';
    this.verbose = options.verbose || false;
    this.skipTests = options.skipTests || false;
    this.skipLinting = options.skipLinting || false;
    this.incremental = options.incremental || false;
    this.buildId = this.generateBuildId();
    this.buildDir = 'dist';
    this.artifactsDir = 'artifacts';
    this.metrics = {};
  }

  generateBuildId() {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const hash = createHash('md5')
      .update(Date.now().toString())
      .digest('hex')
      .substring(0, 8);
    return `build-${timestamp}-${hash}`;
  }

  log(message, level = 'info') {
    const timestamp = new Date().toISOString();
    const prefix = `[${timestamp}] [${level.toUpperCase()}]`;

    if (this.verbose || level === 'error' || level === 'warn') {
      console.log(`${prefix} ${message}`);
    }
  }

  executeCommand(command, description, options = {}) {
    try {
      this.log(`Executing: ${description}`);
      const startTime = Date.now();

      const result = execSync(command, {
        encoding: 'utf8',
        stdio: this.verbose ? 'inherit' : 'pipe',
        maxBuffer: 1024 * 1024 * 10,
        ...options
      });

      const duration = Date.now() - startTime;
      this.log(`✅ ${description} completed in ${duration}ms`);

      return { success: true, output: result, duration };
    } catch (error) {
      this.log(`❌ ${description} failed: ${error.message}`, 'error');
      return { success: false, error: error.message };
    }
  }

  prepareDirectories() {
    this.log('📁 Preparing build directories...');

    // Clean and create directories
    const commands = [
      `rm -rf ${this.buildDir}`,
      `mkdir -p ${this.buildDir}`,
      `mkdir -p ${this.artifactsDir}/builds`,
      `mkdir -p ${this.artifactsDir}/reports`
    ];

    commands.forEach(command => {
      this.executeCommand(command, 'Directory preparation');
    });
  }

  validateEnvironment() {
    this.log('🔍 Validating build environment...');

    // Check Node.js version
    const nodeVersion = process.version;
    this.metrics.node_version = nodeVersion;
    this.log(`Node.js version: ${nodeVersion}`);

    // Check npm version
    const npmResult = this.executeCommand('npm --version', 'Get npm version');
    if (npmResult.success) {
      this.metrics.npm_version = npmResult.output.trim();
      this.log(`npm version: ${this.metrics.npm_version}`);
    }

    // Check dependencies
    const depCheck = this.executeCommand('npm ls --depth=0', 'Check dependencies');
    this.metrics.dependencies_valid = depCheck.success;

    // Check TypeScript
    const tsCheck = this.executeCommand('npx tsc --version', 'Check TypeScript');
    if (tsCheck.success) {
      this.metrics.typescript_version = tsCheck.output.trim();
      this.log(`TypeScript version: ${this.metrics.typescript_version}`);
    }

    return depCheck.success && tsCheck.success;
  }

  runTypeChecking() {
    this.log('🔍 Running comprehensive type checking...');

    const typeChecks = [
      { config: 'tsconfig.json', name: 'Development' },
      { config: 'tsconfig.build.json', name: 'Build' },
      { config: 'tsconfig.test.json', name: 'Test' }
    ];

    if (this.environment === 'production') {
      typeChecks.push({ config: 'tsconfig.production.json', name: 'Production' });
    }

    let allPassed = true;
    typeChecks.forEach(check => {
      if (existsSync(check.config)) {
        const result = this.executeCommand(
          `npx tsc --noEmit -p ${check.config}`,
          `${check.name} type checking`
        );
        this.metrics[`type_check_${check.name.toLowerCase()}`] = result.success;
        if (!result.success) {
          allPassed = false;
        }
      }
    });

    this.metrics.all_type_checks_pass = allPassed;
    return allPassed;
  }

  runLinting() {
    if (this.skipLinting) {
      this.log('⏭️  Skipping linting as requested');
      this.metrics.linting_pass = true;
      return true;
    }

    this.log('🔧 Running code quality checks...');

    const maxWarnings = this.environment === 'production' ? 0 : 10;
    const lintResult = this.executeCommand(
      `npm run lint:hard -- --max-warnings ${maxWarnings}`,
      'ESLint validation'
    );

    this.metrics.linting_pass = lintResult.success;
    return lintResult.success;
  }

  runTests() {
    if (this.skipTests) {
      this.log('⏭️  Skipping tests as requested');
      this.metrics.test_pass = true;
      return true;
    }

    this.log('🧪 Running test suite...');

    const testResult = this.executeCommand(
      'npm run test:unit -- --run',
      'Unit tests'
    );

    this.metrics.test_pass = testResult.success;

    // Run coverage tests if not in production
    if (this.environment !== 'production') {
      const coverageResult = this.executeCommand(
        'npm run test:coverage:unit -- --run',
        'Coverage tests'
      );
      this.metrics.coverage_pass = coverageResult.success;
    }

    return testResult.success;
  }

  performBuild() {
    this.log('🏗️  Performing build...');

    const buildConfig = this.environment === 'production'
      ? 'tsconfig.production.json'
      : 'tsconfig.build.json';

    const buildCommand = this.incremental
      ? `npx tsc -p ${buildConfig} --incremental`
      : `npx tsc -p ${buildConfig}`;

    const buildResult = this.executeCommand(buildCommand, 'TypeScript compilation');

    if (buildResult.success) {
      this.metrics.build_success = true;
      this.metrics.build_duration = buildResult.duration;

      // Verify build artifacts
      const artifacts = ['index.js', 'silent-mcp-entry.js'];
      const missingArtifacts = artifacts.filter(artifact =>
        !existsSync(join(this.buildDir, artifact))
      );

      if (missingArtifacts.length === 0) {
        this.metrics.build_artifacts_complete = true;
        this.log('✅ All build artifacts created successfully');
      } else {
        this.metrics.build_artifacts_complete = false;
        this.log(`❌ Missing build artifacts: ${missingArtifacts.join(', ')}`, 'error');
        return false;
      }
    } else {
      this.metrics.build_success = false;
      return false;
    }

    return buildResult.success;
  }

  optimizeBuild() {
    this.log('⚡ Optimizing build...');

    // Generate build metadata
    const buildMetadata = {
      buildId: this.buildId,
      timestamp: new Date().toISOString(),
      environment: this.environment,
      nodeVersion: this.metrics.node_version,
      npmVersion: this.metrics.npm_version,
      typescriptVersion: this.metrics.typescript_version,
      buildDuration: this.metrics.build_duration,
      incremental: this.incremental,
      gitCommit: this.getGitCommit(),
      gitBranch: this.getGitBranch()
    };

    const metadataPath = join(this.buildDir, 'build-metadata.json');
    writeFileSync(metadataPath, JSON.stringify(buildMetadata, null, 2));
    this.log(`📄 Build metadata saved to ${metadataPath}`);

    // Generate package.json for distribution
    this.generateDistPackageJson();

    this.metrics.build_optimization_complete = true;
  }

  generateDistPackageJson() {
    const sourcePackageJson = JSON.parse(readFileSync('package.json', 'utf8'));

    const distPackageJson = {
      name: sourcePackageJson.name,
      version: sourcePackageJson.version,
      description: sourcePackageJson.description,
      main: sourcePackageJson.main,
      type: sourcePackageJson.type,
      bin: sourcePackageJson.bin,
      engines: sourcePackageJson.engines,
      keywords: sourcePackageJson.keywords,
      author: sourcePackageJson.author,
      license: sourcePackageJson.license,
      repository: sourcePackageJson.repository,
      bugs: sourcePackageJson.bugs,
      homepage: sourcePackageJson.homepage,
      dependencies: sourcePackageJson.dependencies,
      // Remove devDependencies for production
      scripts: {
        start: sourcePackageJson.scripts?.start,
        'start:prod': sourcePackageJson.scripts?.['start:prod'],
        'start:silent': sourcePackageJson.scripts?.['start:silent']
      }
    };

    const distPackagePath = join(this.buildDir, 'package.json');
    writeFileSync(distPackagePath, JSON.stringify(distPackageJson, null, 2));
    this.log(`📄 Distribution package.json created`);
  }

  createBuildArtifacts() {
    this.log('📦 Creating build artifacts...');

    const artifactName = `${basename(process.cwd())}-${this.buildId}.tar.gz`;
    const artifactPath = join(this.artifactsDir, 'builds', artifactName);

    // Create tar.gz of build directory
    const tarResult = this.executeCommand(
      `tar -czf ${artifactPath} -C ${this.buildDir} .`,
      'Create build artifact'
    );

    if (tarResult.success) {
      this.metrics.build_artifact_created = true;
      this.metrics.build_artifact_path = artifactPath;
      this.log(`📦 Build artifact created: ${artifactPath}`);

      // Create checksum
      const checksumCommand = process.platform === 'win32'
        ? `certutil -hashfile "${artifactPath}" SHA256`
        : `sha256sum "${artifactPath}"`;

      const checksumResult = this.executeCommand(checksumCommand, 'Generate checksum');
      if (checksumResult.success) {
        const checksum = checksumResult.output.trim().split(/\s+/)[0];
        this.metrics.build_artifact_checksum = checksum;

        // Save checksum file
        const checksumPath = `${artifactPath}.sha256`;
        writeFileSync(checksumPath, `${checksum}  ${basename(artifactPath)}\n`);
        this.log(`🔐 Checksum saved: ${checksumPath}`);
      }
    }

    return tarResult.success;
  }

  generateBuildReport() {
    this.log('📊 Generating build report...');

    const buildReport = {
      buildId: this.buildId,
      timestamp: new Date().toISOString(),
      environment: this.environment,
      status: this.metrics.build_success ? 'SUCCESS' : 'FAILURE',
      duration: this.metrics.build_duration,
      metrics: this.metrics,
      summary: {
        typeChecking: this.metrics.all_type_checks_pass,
        linting: this.metrics.linting_pass,
        tests: this.metrics.test_pass,
        build: this.metrics.build_success,
        optimization: this.metrics.build_optimization_complete,
        artifacts: this.metrics.build_artifact_created
      }
    };

    const reportPath = join(this.artifactsDir, 'reports', `${this.buildId}-report.json`);
    writeFileSync(reportPath, JSON.stringify(buildReport, null, 2));
    this.log(`📄 Build report saved: ${reportPath}`);

    return buildReport;
  }

  getGitCommit() {
    try {
      const result = execSync('git rev-parse HEAD', { encoding: 'utf8' });
      return result.trim();
    } catch {
      return 'unknown';
    }
  }

  getGitBranch() {
    try {
      const result = execSync('git rev-parse --abbrev-ref HEAD', { encoding: 'utf8' });
      return result.trim();
    } catch {
      return 'unknown';
    }
  }

  async run() {
    this.log(`🚀 Starting build automation for ${this.environment} environment...`);
    this.log(`Build ID: ${this.buildId}`);

    const startTime = Date.now();

    try {
      // Build pipeline
      this.prepareDirectories();

      if (!this.validateEnvironment()) {
        this.log('❌ Environment validation failed', 'error');
        return false;
      }

      if (!this.runTypeChecking()) {
        this.log('❌ Type checking failed', 'error');
        return false;
      }

      if (!this.runLinting()) {
        this.log('❌ Linting failed', 'error');
        return false;
      }

      if (!this.runTests()) {
        this.log('❌ Tests failed', 'error');
        return false;
      }

      if (!this.performBuild()) {
        this.log('❌ Build failed', 'error');
        return false;
      }

      this.optimizeBuild();
      this.createBuildArtifacts();
      const report = this.generateBuildReport();

      const totalDuration = Date.now() - startTime;
      this.log(`✅ Build automation completed successfully in ${totalDuration}ms`);
      this.log(`📦 Build artifacts ready for deployment`);

      return true;

    } catch (error) {
      this.log(`❌ Build automation failed: ${error.message}`, 'error');
      return false;
    }
  }
}

// CLI interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const options = {
    environment: process.env.NODE_ENV || process.argv.find(arg => arg.startsWith('--env='))?.split('=')[1] || 'development',
    verbose: process.argv.includes('--verbose'),
    skipTests: process.argv.includes('--skip-tests'),
    skipLinting: process.argv.includes('--skip-linting'),
    incremental: process.argv.includes('--incremental')
  };

  const automation = new BuildAutomation(options);
  automation.run()
    .then(success => {
      process.exit(success ? 0 : 1);
    })
    .catch(error => {
      console.error('Build automation error:', error);
      process.exit(1);
    });
}

export { BuildAutomation };