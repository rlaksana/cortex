#!/usr/bin/env node

/**
 * Quality Gate Setup Script
 *
 * Sets up the complete quality gate pipeline including:
 * - Git hooks configuration
 * - Dependencies installation
 * - Configuration files
 * - CI/CD integration
 */

import { execSync } from 'child_process';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';

class QualityGateSetup {
  constructor() {
    this.projectRoot = process.cwd();
    this.errors = [];
    this.warnings = [];
  }

  async setup() {
    console.log('🚀 Setting up Cortex MCP Quality Gate Pipeline...\n');

    try {
      await this.checkPrerequisites();
      await this.setupGitHooks();
      await this.createConfigFiles();
      await this.updatePackageJson();
      await this.setupDependencies();
      await this.verifyInstallation();

      this.printSummary();
    } catch (error) {
      console.error('❌ Setup failed:', error.message);
      process.exit(1);
    }
  }

  async checkPrerequisites() {
    console.log('🔍 Checking prerequisites...');

    // Check Node.js version
    try {
      const nodeVersion = execSync('node --version', { encoding: 'utf8' }).trim();
      const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);

      if (majorVersion < 20) {
        throw new Error(`Node.js version 20+ required, found ${nodeVersion}`);
      }
      console.log('  ✅ Node.js version:', nodeVersion);
    } catch (error) {
      if (error.message.includes('required')) throw error;
      throw new Error('Node.js not found. Please install Node.js 20+');
    }

    // Check npm
    try {
      const npmVersion = execSync('npm --version', { encoding: 'utf8' }).trim();
      console.log('  ✅ npm version:', npmVersion);
    } catch (error) {
      throw new Error('npm not found');
    }

    // Check git
    try {
      const gitVersion = execSync('git --version', { encoding: 'utf8' }).trim();
      console.log('  ✅ Git version:', gitVersion);
    } catch (error) {
      this.warnings.push('Git not found - pre-commit hooks will not be installed');
    }

    // Check if we're in a git repository
    try {
      execSync('git rev-parse --git-dir', { stdio: 'ignore' });
      console.log('  ✅ Git repository detected');
    } catch (error) {
      this.warnings.push('Not in a git repository - pre-commit hooks will not be installed');
    }

    console.log('');
  }

  async setupGitHooks() {
    console.log('🔧 Setting up git hooks...');

    try {
      // Install husky if not present
      try {
        execSync('npx husky -v', { stdio: 'ignore' });
      } catch (error) {
        console.log('  📦 Installing husky...');
        execSync('npm install --save-dev husky', { stdio: 'inherit' });
        execSync('npx husky install', { stdio: 'inherit' });
      }

      // Create .husky directory if it doesn't exist
      const huskyDir = join(this.projectRoot, '.husky');
      if (!existsSync(huskyDir)) {
        mkdirSync(huskyDir, { recursive: true });
      }

      // Create pre-commit hook
      const preCommitHook = `#!/bin/sh
. "$(dirname "$0")/_/husky.sh"

echo "🔍 Running enhanced pre-commit quality gate..."

# Run the enhanced pre-commit quality gate check
node scripts/pre-commit-check.mjs

# Check if the pre-commit check passed
if [ $? -ne 0 ]; then
    echo ""
    echo "🔧 Pre-commit quality gate failed!"
    echo ""
    echo "💡 To fix and retry:"
    echo "   1. Run: npm run quality-check (quick fix check)"
    echo "   2. Run: npm run quality-gate (full pipeline)"
    echo "   3. Fix the issues shown above"
    echo "   4. Try committing again"
    echo ""
    echo "❌ Commit blocked by quality gate"
    exit 1
fi

echo ""
echo "🎉 Pre-commit quality gate passed!"
echo "✅ Ready to commit with confidence!"
`;

      const preCommitPath = join(huskyDir, 'pre-commit');
      writeFileSync(preCommitPath, preCommitHook);

      // Make pre-commit hook executable
      if (process.platform !== 'win32') {
        execSync(`chmod +x "${preCommitPath}"`, { stdio: 'inherit' });
      }

      console.log('  ✅ Pre-commit hook configured');
    } catch (error) {
      this.warnings.push(`Failed to setup git hooks: ${error.message}`);
    }

    console.log('');
  }

  async createConfigFiles() {
    console.log('📁 Creating configuration files...');

    // Create directories
    const directories = ['scripts', '.github/workflows', '.husky', 'coverage', 'test-results'];

    directories.forEach((dir) => {
      const fullPath = join(this.projectRoot, dir);
      if (!existsSync(fullPath)) {
        mkdirSync(fullPath, { recursive: true });
        console.log(`  📁 Created directory: ${dir}`);
      }
    });

    // Create quality gate configuration
    const qualityConfig = {
      thresholds: {
        coverage: 90,
        performance: {
          operations: 100,
          timeLimit: 1000,
          maxPerOperation: 100,
        },
        memory: {
          limitMB: 100,
        },
      },
      stages: [
        { name: 'Type Check', command: 'npm run type-check', critical: true },
        { name: 'Lint Check', command: 'npm run lint', critical: true },
        { name: 'Unit Tests', command: 'npm run test:unit', critical: true },
        { name: 'Integration Tests', command: 'npm run test:integration', critical: true },
        { name: 'Coverage Check', command: 'npm run test:coverage:ci', critical: true },
        {
          name: 'Performance Smoke Test',
          command: 'npm run test:integration:performance',
          critical: true,
        },
      ],
    };

    const configPath = join(this.projectRoot, 'quality-gate.config.json');
    writeFileSync(configPath, JSON.stringify(qualityConfig, null, 2));
    console.log('  ✅ Created quality-gate.config.json');

    // Create .gitignore additions
    const gitignoreAdditions = `
# Quality Gate artifacts
quality-gate-report.json
quality-gate-badge.svg
coverage-badge.svg
coverage-summary-badge.json
performance-metrics.json
benchmark-results/

# Coverage reports
coverage/
*.lcov

# Test results
test-results/
junit.xml
test-results.xml
`;

    const gitignorePath = join(this.projectRoot, '.gitignore');
    let gitignoreContent = '';
    if (existsSync(gitignorePath)) {
      gitignoreContent = readFileSync(gitignorePath, 'utf8');
    }

    if (!gitignoreContent.includes('quality-gate-report.json')) {
      gitignoreContent += gitignoreAdditions;
      writeFileSync(gitignorePath, gitignoreContent);
      console.log('  ✅ Updated .gitignore');
    }

    console.log('');
  }

  async updatePackageJson() {
    console.log('📦 Updating package.json...');

    const packageJsonPath = join(this.projectRoot, 'package.json');
    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));

    // Add quality gate scripts
    const scripts = {
      'quality-check': 'node scripts/pre-commit-check.mjs',
      'quality-gate': 'node scripts/quality-gate.mjs',
      'quality-gate:strict': 'node scripts/quality-gate.mjs --strict',
      'quality-gate:ci': 'node scripts/quality-gate.mjs --strict',
      'pre-commit': 'node scripts/pre-commit-check.mjs',
      'quality:dashboard': 'open scripts/quality-gate-dashboard.html',
      'setup:quality-gate': 'node scripts/setup-quality-gate.mjs',
    };

    // Merge with existing scripts
    packageJson.scripts = { ...packageJson.scripts, ...scripts };

    // Add husky configuration
    if (!packageJson.devDependencies) {
      packageJson.devDependencies = {};
    }

    if (!packageJson.devDependencies.husky) {
      packageJson.devDependencies.husky = '^8.0.0';
    }

    // Ensure Node.js engine requirement
    packageJson.engines = {
      ...packageJson.engines,
      node: '>=20.0.0',
    };

    writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2));
    console.log('  ✅ Updated package.json with quality gate scripts');
    console.log('');
  }

  async setupDependencies() {
    console.log('📦 Installing dependencies...');

    try {
      // Install additional dev dependencies if needed
      const additionalDeps = ['husky@^8.0.0'];

      try {
        execSync(`npm install --save-dev ${additionalDeps.join(' ')}`, { stdio: 'inherit' });
        console.log('  ✅ Additional dependencies installed');
      } catch (error) {
        this.warnings.push(`Failed to install additional dependencies: ${error.message}`);
      }

      // Install all dependencies
      execSync('npm install', { stdio: 'inherit' });
      console.log('  ✅ Dependencies installed');
    } catch (error) {
      throw new Error(`Failed to install dependencies: ${error.message}`);
    }

    console.log('');
  }

  async verifyInstallation() {
    console.log('🔍 Verifying installation...');

    // Check if scripts exist and are executable
    const requiredScripts = [
      'scripts/quality-gate.mjs',
      'scripts/pre-commit-check.mjs',
      'scripts/generate-coverage-badge.js',
      'scripts/quality-gate-dashboard.html',
    ];

    for (const script of requiredScripts) {
      const scriptPath = join(this.projectRoot, script);
      if (!existsSync(scriptPath)) {
        this.errors.push(`Missing required script: ${script}`);
      } else {
        console.log(`  ✅ ${script}`);
      }
    }

    // Check if configuration files exist
    const requiredConfigs = [
      'quality-gate.config.json',
      '.github/workflows/quality-gate.yml',
      '.husky/pre-commit',
    ];

    for (const config of requiredConfigs) {
      const configPath = join(this.projectRoot, config);
      if (!existsSync(configPath)) {
        this.warnings.push(`Missing configuration file: ${config}`);
      } else {
        console.log(`  ✅ ${config}`);
      }
    }

    // Test if quality gate script runs (dry run)
    try {
      execSync('node scripts/quality-gate.mjs --help', { stdio: 'ignore', timeout: 5000 });
      console.log('  ✅ Quality gate script is functional');
    } catch (error) {
      // Don't fail setup if script test fails
      this.warnings.push('Quality gate script test failed');
    }

    console.log('');
  }

  printSummary() {
    console.log('='.repeat(80));
    console.log('🎉 QUALITY GATE SETUP COMPLETE');
    console.log('='.repeat(80));

    if (this.errors.length === 0) {
      console.log('✅ All components installed successfully!');
    } else {
      console.log(`⚠️  ${this.errors.length} error(s) occurred during setup:`);
      this.errors.forEach((error) => console.log(`   ❌ ${error}`));
    }

    if (this.warnings.length > 0) {
      console.log(`\n⚠️  ${this.warnings.length} warning(s):`);
      this.warnings.forEach((warning) => console.log(`   ⚠️  ${warning}`));
    }

    console.log('\n🚀 Next steps:');
    console.log('   1. Run quality gate: npm run quality-gate');
    console.log('   2. Quick check: npm run quality-check');
    console.log('   3. View dashboard: npm run quality:dashboard');
    console.log('   4. Commit changes - quality gate will run automatically');

    console.log('\n📊 Quality gate features:');
    console.log('   • TypeScript compilation checking');
    console.log('   • ESLint linting validation');
    console.log('   • Unit and integration test execution');
    console.log('   • Code coverage analysis (90%+ target)');
    console.log('   • Performance smoke testing (N=100 <1s)');
    console.log('   • Pre-commit hook enforcement');
    console.log('   • CI/CD pipeline integration');
    console.log('   • Interactive dashboard monitoring');

    console.log('\n🔧 Configuration:');
    console.log('   • Edit quality-gate.config.json to customize thresholds');
    console.log('   • Modify .husky/pre-commit for custom pre-commit logic');
    console.log('   • Update .github/workflows/quality-gate.yml for CI/CD');

    console.log('='.repeat(80));

    if (this.errors.length > 0) {
      process.exit(1);
    }
  }
}

// Run setup if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const setup = new QualityGateSetup();
  setup.setup().catch((error) => {
    console.error('❌ Setup failed:', error);
    process.exit(1);
  });
}

export default QualityGateSetup;
