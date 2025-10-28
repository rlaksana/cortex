#!/usr/bin/env node

/**
 * Dependency Audit Script for Cortex MCP
 * Analyzes dependencies for security vulnerabilities, outdated packages, and unused dependencies
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class DependencyAuditor {
  constructor() {
    this.packageJsonPath = path.join(process.cwd(), 'package.json');
    this.packageLockJsonPath = path.join(process.cwd(), 'package-lock.json');
    this.results = {
      outdated: [],
      vulnerabilities: [],
      unused: [],
      missingLicenses: [],
      recommendations: []
    };
  }

  async runAudit() {
    console.log('🔍 Starting dependency audit...\n');

    try {
      // Read package.json
      const packageJson = this.readPackageJson();

      // Run different audit checks
      await this.checkOutdatedDependencies();
      await this.checkSecurityVulnerabilities();
      await this.checkUnusedDependencies(packageJson);
      await this.checkLicenses(packageJson);
      await this.analyzeDependencyHealth(packageJson);

      // Generate report
      this.generateReport();

    } catch (error) {
      console.error('❌ Audit failed:', error.message);
      process.exit(1);
    }
  }

  readPackageJson() {
    if (!fs.existsSync(this.packageJsonPath)) {
      throw new Error('package.json not found');
    }

    return JSON.parse(fs.readFileSync(this.packageJsonPath, 'utf8'));
  }

  async checkOutdatedDependencies() {
    console.log('📦 Checking for outdated dependencies...');

    try {
      const output = execSync('npm outdated --json', { encoding: 'utf8' });
      const outdated = JSON.parse(output);

      for (const [name, info] of Object.entries(outdated)) {
        this.results.outdated.push({
          name,
          current: info.current,
          wanted: info.wanted,
          latest: info.latest,
          type: info.type || 'dependency',
          severity: this.getOutdatedSeverity(info.current, info.latest)
        });
      }

      console.log(`✅ Found ${this.results.outdated.length} outdated packages`);
    } catch (error) {
      if (error.status === 1) {
        // npm outdated returns 1 when packages are outdated
        try {
          const output = error.stdout;
          if (output) {
            const outdated = JSON.parse(output);
            for (const [name, info] of Object.entries(outdated)) {
              this.results.outdated.push({
                name,
                current: info.current,
                wanted: info.wanted,
                latest: info.latest,
                type: info.type || 'dependency',
                severity: this.getOutdatedSeverity(info.current, info.latest)
              });
            }
            console.log(`✅ Found ${this.results.outdated.length} outdated packages`);
          }
        } catch (parseError) {
          console.log('ℹ️  No outdated packages found');
        }
      } else {
        console.log('⚠️  Could not check outdated packages:', error.message);
      }
    }
  }

  async checkSecurityVulnerabilities() {
    console.log('🔒 Checking for security vulnerabilities...');

    try {
      const output = execSync('npm audit --json', { encoding: 'utf8' });
      const audit = JSON.parse(output);

      if (audit.vulnerabilities) {
        for (const [name, vuln] of Object.entries(audit.vulnerabilities)) {
          this.results.vulnerabilities.push({
            name,
            severity: vuln.severity,
            title: vuln.title,
            url: vuln.url,
            fixAvailable: vuln.fixAvailable,
            patchedVersions: vuln.patchedVersions,
            recommendation: vuln.fixAvailable ? 'Update available' : 'Manual review required'
          });
        }
      }

      console.log(`✅ Found ${this.results.vulnerabilities.length} vulnerabilities`);
    } catch (error) {
      console.log('⚠️  Could not run security audit:', error.message);
    }
  }

  async checkUnusedDependencies(packageJson) {
    console.log('🗑️  Checking for unused dependencies...');

    // Get all imported modules from source code
    const sourceFiles = this.getSourceFiles('src');
    const importedModules = new Set();

    for (const file of sourceFiles) {
      const imports = this.extractImports(file);
      imports.forEach(imp => importedModules.add(imp));
    }

    // Check each dependency
    const allDeps = {
      ...packageJson.dependencies,
      ...packageJson.devDependencies
    };

    for (const [name, version] of Object.entries(allDeps)) {
      if (!this.isModuleUsed(name, importedModules, sourceFiles)) {
        this.results.unused.push({
          name,
          version,
          type: packageJson.dependencies[name] ? 'dependency' : 'devDependency'
        });
      }
    }

    console.log(`✅ Found ${this.results.unused.length} potentially unused packages`);
  }

  async checkLicenses(packageJson) {
    console.log('📄 Checking license compliance...');

    try {
      // Check each dependency's license
      const allDeps = {
        ...packageJson.dependencies,
        ...packageJson.devDependencies
      };

      for (const [name, version] of Object.entries(allDeps)) {
        try {
          const packageInfo = this.getPackageInfo(name);
          if (!packageInfo.license || this.isProblematicLicense(packageInfo.license)) {
            this.results.missingLicenses.push({
              name,
              version,
              license: packageInfo.license || 'Unknown',
              issue: !packageInfo.license ? 'Missing license' : 'Problematic license'
            });
          }
        } catch (error) {
          // Skip if we can't get package info
        }
      }

      console.log(`✅ Found ${this.results.missingLicenses.length} license issues`);
    } catch (error) {
      console.log('⚠️  Could not check licenses:', error.message);
    }
  }

  async analyzeDependencyHealth(packageJson) {
    console.log('💊 Analyzing dependency health...');

    const allDeps = {
      ...packageJson.dependencies,
      ...packageJson.devDependencies
    };

    // Check for deprecated packages
    for (const [name, version] of Object.entries(allDeps)) {
      try {
        const packageInfo = this.getPackageInfo(name);

        if (packageInfo.deprecated) {
          this.results.recommendations.push({
            type: 'deprecated',
            name,
            version,
            message: packageInfo.deprecated,
            action: 'Replace with alternative'
          });
        }

        // Check for packages with few downloads (potentially unmaintained)
        if (packageInfo.weeklyDownloads && packageInfo.weeklyDownloads < 1000) {
          this.results.recommendations.push({
            type: 'low_downloads',
            name,
            version,
            weeklyDownloads: packageInfo.weeklyDownloads,
            message: 'Package has low download count, may be unmaintained',
            action: 'Consider alternatives'
          });
        }

        // Check for packages without recent updates
        if (packageInfo.lastUpdate) {
          const daysSinceUpdate = (Date.now() - new Date(packageInfo.lastUpdate).getTime()) / (1000 * 60 * 60 * 24);
          if (daysSinceUpdate > 365) {
            this.results.recommendations.push({
              type: 'stale_package',
              name,
              version,
              daysSinceUpdate: Math.floor(daysSinceUpdate),
              message: `Package hasn't been updated in ${Math.floor(daysSinceUpdate)} days`,
              action: 'Check for alternatives or fork if necessary'
            });
          }
        }
      } catch (error) {
        // Skip if we can't get package info
      }
    }

    console.log(`✅ Generated ${this.results.recommendations.length} recommendations`);
  }

  generateReport() {
    console.log('\n📊 DEPENDENCY AUDIT REPORT\n');
    console.log('=====================================\n');

    // Outdated dependencies
    if (this.results.outdated.length > 0) {
      console.log('📦 OUTDATED DEPENDENCIES:');
      console.log('----------------------------');
      this.results.outdated.forEach(dep => {
        const icon = dep.severity === 'high' ? '🔴' : dep.severity === 'medium' ? '🟡' : '🟢';
        console.log(`${icon} ${dep.name}: ${dep.current} → ${dep.latest} (${dep.type})`);
      });
      console.log();
    }

    // Security vulnerabilities
    if (this.results.vulnerabilities.length > 0) {
      console.log('🔒 SECURITY VULNERABILITIES:');
      console.log('----------------------------');
      this.results.vulnerabilities.forEach(vuln => {
        const icon = vuln.severity === 'high' ? '🔴' : vuln.severity === 'moderate' ? '🟡' : '🟢';
        console.log(`${icon} ${vuln.name}: ${vuln.title}`);
        console.log(`   Severity: ${vuln.severity}`);
        console.log(`   Fix Available: ${vuln.fixAvailable ? 'Yes' : 'No'}`);
        if (vuln.url) console.log(`   Details: ${vuln.url}`);
        console.log();
      });
    }

    // Unused dependencies
    if (this.results.unused.length > 0) {
      console.log('🗑️  UNUSED DEPENDENCIES:');
      console.log('------------------------');
      this.results.unused.forEach(dep => {
        console.log(`📋 ${dep.name}@${dep.version} (${dep.type})`);
      });
      console.log();
    }

    // License issues
    if (this.results.missingLicenses.length > 0) {
      console.log('📄 LICENSE ISSUES:');
      console.log('-------------------');
      this.results.missingLicenses.forEach(lic => {
        console.log(`⚠️  ${lic.name}@${lic.version}: ${lic.issue}`);
        if (lic.license) console.log(`   License: ${lic.license}`);
      });
      console.log();
    }

    // Recommendations
    if (this.results.recommendations.length > 0) {
      console.log('💊 RECOMMENDATIONS:');
      console.log('-------------------');
      this.results.recommendations.forEach(rec => {
        const icon = rec.type === 'deprecated' ? '🚫' : rec.type === 'low_downloads' ? '📉' : '⏰';
        console.log(`${icon} ${rec.name}@${rec.version}`);
        console.log(`   Issue: ${rec.message}`);
        console.log(`   Action: ${rec.action}`);
        if (rec.weeklyDownloads) console.log(`   Weekly Downloads: ${rec.weeklyDownloads}`);
        if (rec.daysSinceUpdate) console.log(`   Days Since Update: ${rec.daysSinceUpdate}`);
        console.log();
      });
    }

    // Summary
    console.log('📈 SUMMARY:');
    console.log('-----------');
    console.log(`Outdated packages: ${this.results.outdated.length}`);
    console.log(`Security vulnerabilities: ${this.results.vulnerabilities.length}`);
    console.log(`Unused dependencies: ${this.results.unused.length}`);
    console.log(`License issues: ${this.results.missingLicenses.length}`);
    console.log(`Recommendations: ${this.results.recommendations.length}`);

    // Generate commands to fix issues
    if (this.results.outdated.length > 0 || this.results.vulnerabilities.length > 0) {
      console.log('\n🔧 SUGGESTED COMMANDS:');
      console.log('----------------------');

      if (this.results.outdated.length > 0) {
        console.log('# Update outdated packages:');
        console.log('npm update');
      }

      if (this.results.vulnerabilities.length > 0) {
        console.log('\n# Fix security vulnerabilities:');
        console.log('npm audit fix');
      }

      if (this.results.unused.length > 0) {
        console.log('\n# Remove unused dependencies (review first):');
        this.results.unused.forEach(dep => {
          console.log(`npm uninstall ${dep.name}`);
        });
      }
    }

    // Save detailed report
    this.saveDetailedReport();
  }

  saveDetailedReport() {
    const reportPath = path.join(process.cwd(), 'dependency-audit-report.json');
    const report = {
      timestamp: new Date().toISOString(),
      results: this.results,
      summary: {
        outdated: this.results.outdated.length,
        vulnerabilities: this.results.vulnerabilities.length,
        unused: this.results.unused.length,
        licenseIssues: this.results.missingLicenses.length,
        recommendations: this.results.recommendations.length
      }
    };

    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    console.log(`\n💾 Detailed report saved to: ${reportPath}`);
  }

  getSourceFiles(dir) {
    const files = [];

    if (!fs.existsSync(dir)) return files;

    const items = fs.readdirSync(dir);

    for (const item of items) {
      const fullPath = path.join(dir, item);
      const stat = fs.statSync(fullPath);

      if (stat.isDirectory()) {
        files.push(...this.getSourceFiles(fullPath));
      } else if (item.endsWith('.js') || item.endsWith('.ts') || item.endsWith('.jsx') || item.endsWith('.tsx')) {
        files.push(fullPath);
      }
    }

    return files;
  }

  extractImports(filePath) {
    const content = fs.readFileSync(filePath, 'utf8');
    const imports = [];

    // Match import statements
    const importRegex = /import.*from\s+['"]([^'"]+)['"]/g;
    let match;

    while ((match = importRegex.exec(content)) !== null) {
      imports.push(match[1]);
    }

    // Match require statements
    const requireRegex = /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;

    while ((match = requireRegex.exec(content)) !== null) {
      imports.push(match[1]);
    }

    return imports;
  }

  isModuleUsed(moduleName, importedModules, sourceFiles) {
    // Direct import check
    if (importedModules.has(moduleName)) {
      return true;
    }

    // Check for scoped packages
    if (moduleName.startsWith('@')) {
      for (const imported of importedModules) {
        if (imported.startsWith(moduleName + '/')) {
          return true;
        }
      }
    }

    // Check for common patterns and CLI tools
    const commonPatterns = [
      'typescript', 'eslint', 'prettier', 'vitest',
      'rollup', 'webpack', 'babel', 'nodemon', 'ts-node'
    ];

    if (commonPatterns.includes(moduleName)) {
      return true; // These are commonly used via CLI or config
    }

    return false;
  }

  getPackageInfo(packageName) {
    try {
      const packagePath = path.join(process.cwd(), 'node_modules', packageName, 'package.json');
      if (fs.existsSync(packagePath)) {
        const packageInfo = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
        return {
          license: packageInfo.license,
          deprecated: packageInfo.deprecated,
          lastUpdate: packageInfo._lastModified || new Date().toISOString()
        };
      }
    } catch (error) {
      // Fall back to npm registry if local package info not available
    }

    return { license: 'Unknown' };
  }

  getOutdatedSeverity(current, latest) {
    const currentParts = current.split('.').map(Number);
    const latestParts = latest.split('.').map(Number);

    // Compare major version
    if (latestParts[0] > currentParts[0]) {
      return 'high';
    }

    // Compare minor version
    if (latestParts[1] > currentParts[1]) {
      return 'medium';
    }

    return 'low';
  }

  isProblematicLicense(license) {
    const problematicLicenses = ['GPL-2.0', 'GPL-3.0', 'AGPL', 'LGPL', 'UNLICENSED'];
    return problematicLicenses.some(lic => license.toUpperCase().includes(lic));
  }
}

// Run the audit
if (require.main === module) {
  const auditor = new DependencyAuditor();
  auditor.runAudit().catch(error => {
    console.error('❌ Audit failed:', error);
    process.exit(1);
  });
}

module.exports = DependencyAuditor;