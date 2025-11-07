#!/usr/bin/env node

/**
 * TypeScript Implementation Validation Script
 *
 * Validates the harmonized TypeScript configuration implementation:
 * - Configuration file consistency
 * - Path mapping validation
 * - Build system integration
 * - Type checking across environments
 */

import { execSync } from 'child_process';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

class TypeScriptImplementationValidator {
  constructor() {
    this.errors = [];
    this.warnings = [];
    this.validations = {};
  }

  log(message, level = 'info') {
    const timestamp = new Date().toISOString();
    const prefix = `[${timestamp}] [${level.toUpperCase()}]`;
    console.log(`${prefix} ${message}`);
  }

  validateConfigurationFiles() {
    this.log('🔍 Validating TypeScript configuration files...');

    const requiredConfigs = [
      'tsconfig.base.json',
      'tsconfig.json',
      'tsconfig.build.json',
      'tsconfig.test.json',
      'tsconfig.production.json'
    ];

    requiredConfigs.forEach(config => {
      if (existsSync(config)) {
        this.validations[`${config}_exists`] = true;
        this.log(`✅ ${config} exists`);

        try {
          const configData = JSON.parse(readFileSync(config, 'utf8'));
          this.validateConfigStructure(config, configData);
        } catch (error) {
          this.errors.push(`${config} has invalid JSON: ${error.message}`);
          this.validations[`${config}_valid_json`] = false;
        }
      } else {
        this.errors.push(`Missing required configuration: ${config}`);
        this.validations[`${config}_exists`] = false;
      }
    });
  }

  validateConfigStructure(configFile, configData) {
    // Check if configuration extends base (except for base itself)
    if (configFile !== 'tsconfig.base.json') {
      if (configData.extends) {
        this.validations[`${configFile}_extends_base`] = true;
        this.log(`✅ ${configFile} extends base configuration`);
      } else {
        this.warnings.push(`${configFile} should extend tsconfig.base.json`);
        this.validations[`${configFile}_extends_base`] = false;
      }
    }

    // Validate path mappings
    if (configData.compilerOptions?.paths) {
      const expectedPaths = [
        '@/*',
        '@/types/*',
        '@/services/*',
        '@/config/*',
        '@/utils/*',
        '@/schemas/*',
        '@/middleware/*',
        '@/db/*',
        '@/monitoring/*',
        '@docs/*',
        '@scripts/*',
        '@tests/*'
      ];

      const actualPaths = Object.keys(configData.compilerOptions.paths);
      const missingPaths = expectedPaths.filter(path => !actualPaths.includes(path));

      if (missingPaths.length === 0) {
        this.validations[`${configFile}_complete_paths`] = true;
        this.log(`✅ ${configFile} has complete path mappings`);
      } else {
        this.warnings.push(`${configFile} missing path mappings: ${missingPaths.join(', ')}`);
        this.validations[`${configFile}_complete_paths`] = false;
      }
    }
  }

  validateTypeChecking() {
    this.log('🔍 Validating type checking across configurations...');

    const configs = [
      { file: 'tsconfig.json', name: 'Development' },
      { file: 'tsconfig.build.json', name: 'Build' },
      { file: 'tsconfig.test.json', name: 'Test' },
      { file: 'tsconfig.production.json', name: 'Production' }
    ];

    configs.forEach(config => {
      if (existsSync(config.file)) {
        try {
          this.log(`  Checking ${config.name} configuration...`);
          execSync(`npx tsc --noEmit -p ${config.file}`, { stdio: 'pipe' });
          this.validations[`${config.name.toLowerCase()}_type_check`] = true;
          this.log(`  ✅ ${config.name} type checking passed`);
        } catch (error) {
          this.errors.push(`${config.name} type checking failed: ${error.message}`);
          this.validations[`${config.name.toLowerCase()}_type_check`] = false;
        }
      }
    });
  }

  validateBuildSystem() {
    this.log('🔍 Validating build system integration...');

    // Check if build scripts exist
    const packageJson = JSON.parse(readFileSync('package.json', 'utf8'));
    const requiredScripts = [
      'build',
      'build:dev',
      'build:prod',
      'build:ci',
      'build:fast',
      'type-check',
      'type-check:all'
    ];

    requiredScripts.forEach(script => {
      if (packageJson.scripts[script]) {
        this.validations[`script_${script.replace(/:/g, '_')}_exists`] = true;
        this.log(`✅ Script '${script}' exists`);
      } else {
        this.errors.push(`Missing required script: ${script}`);
        this.validations[`script_${script.replace(/:/g, '_')}_exists`] = false;
      }
    });

    // Validate build automation script
    if (existsSync('scripts/build-automation.js')) {
      this.validations.build_automation_script_exists = true;
      this.log('✅ Build automation script exists');
    } else {
      this.errors.push('Build automation script not found');
      this.validations.build_automation_script_exists = false;
    }
  }

  validateQualityGates() {
    this.log('🔍 Validating quality gate implementation...');

    // Check enhanced quality gate script
    if (existsSync('scripts/enhanced-quality-gate.js')) {
      this.validations.enhanced_quality_gate_exists = true;
      this.log('✅ Enhanced quality gate script exists');
    } else {
      this.errors.push('Enhanced quality gate script not found');
      this.validations.enhanced_quality_gate_exists = false;
    }

    // Check quality gate scripts in package.json
    const packageJson = JSON.parse(readFileSync('package.json', 'utf8'));
    const qualityGateScripts = [
      'quality-gate',
      'quality-gate:strict',
      'quality-gate:ci',
      'quality-gate:enhanced'
    ];

    qualityGateScripts.forEach(script => {
      if (packageJson.scripts[script]) {
        this.validations[`quality_gate_script_${script.replace(/:/g, '_')}_exists`] = true;
        this.log(`✅ Quality gate script '${script}' exists`);
      } else {
        this.warnings.push(`Quality gate script '${script}' not found`);
        this.validations[`quality_gate_script_${script.replace(/:/g, '_')}_exists`] = false;
      }
    });
  }

  validateEntryPoints() {
    this.log('🔍 Validating dual entry points...');

    const entryPoints = ['src/index.ts', 'src/silent-mcp-entry.ts'];

    entryPoints.forEach(entryPoint => {
      if (existsSync(entryPoint)) {
        this.validations[`entry_point_${entryPoint.split('/').pop().replace('.', '_')}_exists`] = true;
        this.log(`✅ Entry point ${entryPoint} exists`);
      } else {
        this.errors.push(`Entry point ${entryPoint} not found`);
        this.validations[`entry_point_${entryPoint.split('/').pop().replace('.', '_')}_exists`] = false;
      }
    });

    // Validate silent entry point doesn't import compiled files
    try {
      const silentEntryContent = readFileSync('src/silent-mcp-entry.ts', 'utf8');
      if (silentEntryContent.includes("import('./index.js')")) {
        this.warnings.push('Silent entry point imports compiled JavaScript - may cause issues');
        this.validations.silent_entry_imports_correct = false;
      } else {
        this.validations.silent_entry_imports_correct = true;
        this.log('✅ Silent entry point has correct imports');
      }
    } catch (error) {
      this.log(`Could not validate silent entry point imports: ${error.message}`, 'warn');
    }
  }

  generateReport() {
    this.log('📊 Generating validation report...');

    const totalValidations = Object.keys(this.validations).length;
    const passedValidations = Object.values(this.validations).filter(Boolean).length;
    const successRate = totalValidations > 0 ? (passedValidations / totalValidations * 100).toFixed(2) : 0;

    const report = {
      timestamp: new Date().toISOString(),
      summary: {
        total_validations: totalValidations,
        passed_validations: passedValidations,
        failed_validations: totalValidations - passedValidations,
        success_rate: `${successRate}%`,
        total_errors: this.errors.length,
        total_warnings: this.warnings.length,
        overall_status: this.errors.length === 0 ? 'PASS' : 'FAIL'
      },
      validations: this.validations,
      errors: this.errors,
      warnings: this.warnings,
      recommendations: this.generateRecommendations()
    };

    // Save report
    const reportPath = 'artifacts/typescript-validation-report.json';
    try {
      if (!existsSync('artifacts')) {
        execSync('mkdir -p artifacts');
      }
      require('fs').writeFileSync(reportPath, JSON.stringify(report, null, 2));
      this.log(`📄 Validation report saved to ${reportPath}`);
    } catch (error) {
      this.log(`Failed to save report: ${error.message}`, 'warn');
    }

    return report;
  }

  generateRecommendations() {
    const recommendations = [];

    if (this.errors.length > 0) {
      recommendations.push('Fix all errors before proceeding to production');
    }

    if (this.warnings.length > 0) {
      recommendations.push('Review and address warnings for optimal performance');
    }

    const allTypeChecksPass = [
      'development_type_check',
      'build_type_check',
      'test_type_check',
      'production_type_check'
    ].every(check => this.validations[check]);

    if (!allTypeChecksPass) {
      recommendations.push('Ensure type checking passes across all configurations');
    }

    if (!this.validations.build_automation_script_exists) {
      recommendations.push('Implement build automation script for consistent builds');
    }

    if (!this.validations.enhanced_quality_gate_exists) {
      recommendations.push('Implement enhanced quality gates for comprehensive validation');
    }

    return recommendations;
  }

  run() {
    this.log('🚀 Starting TypeScript Implementation Validation...');

    try {
      this.validateConfigurationFiles();
      this.validateTypeChecking();
      this.validateBuildSystem();
      this.validateQualityGates();
      this.validateEntryPoints();

      const report = this.generateReport();

      // Print summary
      console.log('\n📋 TypeScript Implementation Validation Summary:');
      console.log(`   Validations: ${report.summary.passed_validations}/${report.summary.total_validations} (${report.summary.success_rate})`);
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

      if (report.recommendations.length > 0) {
        console.log('\n💡 Recommendations:');
        report.recommendations.forEach(rec => console.log(`   - ${rec}`));
      }

      return report.summary.overall_status === 'PASS';

    } catch (error) {
      this.log(`Validation failed: ${error.message}`, 'error');
      return false;
    }
  }
}

// CLI interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const validator = new TypeScriptImplementationValidator();
  validator.run()
    .then(success => {
      process.exit(success ? 0 : 1);
    })
    .catch(error => {
      console.error('TypeScript validation error:', error);
      process.exit(1);
    });
}

export { TypeScriptImplementationValidator };