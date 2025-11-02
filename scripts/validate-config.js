#!/usr/bin/env node

/**
 * Configuration Validation Script
 *
 * Validates the complete environment configuration and provides detailed
 * feedback about missing variables, validation errors, and recommendations.
 *
 * Usage:
 *   node scripts/validate-config.js
 *   NODE_ENV=production node scripts/validate-config.js
 *
 * Exit codes:
 *   0 - Success
 *   1 - Validation errors
 *   2 - Critical configuration errors
 */

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import chalk from 'chalk';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Add src to the path for imports
const srcPath = join(dirname(__dirname), 'src');
process.env.NODE_PATH = srcPath;

// Import the configuration modules
try {
  await import('./src/config/environment.js');
  await import('./src/config/validation.js');
  await import('./tests/validation/config-test-helper.js');
} catch (error) {
  console.error(chalk.red('Error importing configuration modules:'));
  console.error(error.message);
  process.exit(2);
}

const { Environment } = await import('./src/config/environment.js');
const { configValidator } = await import('./src/config/validation.js');
const {
  validateCompleteConfiguration,
  generateEnvironmentCoverageReport,
  validateEnvironmentTsCoverage,
} = await import('./tests/validation/config-test-helper.js');

/**
 * Print validation results with colors
 */
function printValidationResults(results, title) {
  console.log(chalk.blue.bold(`\n🔍 ${title}`));
  console.log(chalk.blue('─'.repeat(50)));

  if (results.valid) {
    console.log(chalk.green('✅ PASSED'));
  } else {
    console.log(chalk.red('❌ FAILED'));
  }

  if (results.errors && results.errors.length > 0) {
    console.log(chalk.red.bold('\n🚨 Errors:'));
    results.errors.forEach((error) => {
      if (typeof error === 'string') {
        console.log(chalk.red(`  • ${error}`));
      } else {
        console.log(chalk.red(`  • ${error.field}: ${error.message}`));
        if (error.suggestion) {
          console.log(chalk.yellow(`    💡 ${error.suggestion}`));
        }
      }
    });
  }

  if (results.warnings && results.warnings.length > 0) {
    console.log(chalk.yellow.bold('\n⚠️  Warnings:'));
    results.warnings.forEach((warning) => {
      if (typeof warning === 'string') {
        console.log(chalk.yellow(`  • ${warning}`));
      } else {
        console.log(chalk.yellow(`  • ${warning.field}: ${warning.message}`));
        if (warning.suggestion) {
          console.log(chalk.blue(`    💡 ${warning.suggestion}`));
        }
      }
    });
  }

  if (results.info && results.info.length > 0) {
    console.log(chalk.blue.bold('\nℹ️  Info:'));
    results.info.forEach((info) => {
      console.log(chalk.blue(`  • ${info.field}: ${info.message}`));
      if (info.suggestion) {
        console.log(chalk.dim(`    💡 ${info.suggestion}`));
      }
    });
  }
}

/**
 * Print environment coverage report
 */
function printCoverageReport(coverage) {
  console.log(chalk.blue.bold('\n📊 Environment Variable Coverage Report'));
  console.log(chalk.blue('─'.repeat(50)));

  console.log(`Total variables tracked: ${chalk.bold(coverage.total)}`);
  console.log(`Configured: ${chalk.green(coverage.configured)}`);
  console.log(`Missing required: ${chalk.red(coverage.missing)}`);

  console.log(chalk.bold('\nBy Category:'));
  Object.entries(coverage.byCategory).forEach(([category, stats]) => {
    const status = stats.missing === 0 ? chalk.green('✅') : chalk.red('❌');
    console.log(
      `  ${status} ${category.padEnd(12)}: ${stats.configured}/${stats.total} configured`
    );
  });

  if (coverage.missingVariables.length > 0) {
    console.log(chalk.red.bold('\n🚨 Missing Required Variables:'));
    coverage.missingVariables.forEach((variable) => {
      console.log(chalk.red(`  • ${variable}`));
    });
  }
}

/**
 * Print environment-specific configuration
 */
function printEnvironmentSpecificConfig(env) {
  console.log(chalk.blue.bold('\n⚙️  Environment-Specific Configuration'));
  console.log(chalk.blue('─'.repeat(50)));

  const defaults = env.getEnvironmentSpecificDefaults();
  const mode = env.isProductionMode() ? 'Production' : env.isTestMode() ? 'Test' : 'Development';

  console.log(`${chalk.bold('Mode:')} ${mode}`);
  console.log(`${chalk.bold('Log Level:')} ${defaults.LOG_LEVEL}`);
  console.log(`${chalk.bold('Metrics:')} ${defaults.METRICS_ENABLED ? 'Enabled' : 'Disabled'}`);
  console.log(`${chalk.bold('Auth:')} ${defaults.ENABLE_AUTH ? 'Enabled' : 'Disabled'}`);
  console.log(`${chalk.bold('Caching:')} ${defaults.ENABLE_CACHING ? 'Enabled' : 'Disabled'}`);
  console.log(`${chalk.bold('Pool Size:')} ${defaults.DB_POOL_MIN}-${defaults.DB_POOL_MAX}`);
  console.log(`${chalk.bold('Batch Size:')} ${defaults.BATCH_SIZE}`);
}

/**
 * Main validation function
 */
async function validateConfiguration() {
  console.log(chalk.blue.bold('🔧 Cortex Configuration Validation'));
  console.log(chalk.blue('═'.repeat(50)));

  const env = Environment.getInstance();
  let hasErrors = false;
  let hasCriticalErrors = false;

  try {
    // 1. Environment variable coverage
    const coverage = generateEnvironmentCoverageReport();
    printCoverageReport(coverage);

    if (coverage.missing > 0) {
      hasErrors = true;
    }

    // 2. Environment.ts coverage validation
    const envTsCoverage = validateEnvironmentTsCoverage();
    printValidationResults(envTsCoverage, 'Environment.ts Coverage Validation');

    if (!envTsCoverage.valid) {
      hasErrors = true;
    }

    // 3. Required configuration validation
    const requiredConfigValidation = env.validateRequiredConfig();
    printValidationResults(requiredConfigValidation, 'Required Configuration Validation');

    if (!requiredConfigValidation.valid) {
      hasCriticalErrors = true;
    }

    // 4. Environment-specific requirements
    const envSpecificValidation = env.validateEnvironmentSpecificRequirements();
    printValidationResults(envSpecificValidation, 'Environment-Specific Requirements');

    if (!envSpecificValidation.valid) {
      hasErrors = true;
    }

    // 5. Complete configuration validation
    const completeValidation = await validateCompleteConfiguration();
    printValidationResults(completeValidation.environment, 'Complete Configuration Validation');

    if (!completeValidation.allValid) {
      hasErrors = true;
      if (completeValidation.summary.criticalErrors.length > 0) {
        hasCriticalErrors = true;
      }
    }

    // 6. Environment-specific configuration
    printEnvironmentSpecificConfig(env);

    // Summary
    console.log(chalk.blue.bold('\n📋 Summary'));
    console.log(chalk.blue('─'.repeat(50)));

    if (hasCriticalErrors) {
      console.log(chalk.red.bold('🚨 CRITICAL CONFIGURATION ERRORS FOUND'));
      console.log(chalk.red('The application cannot start safely with the current configuration.'));
      console.log(chalk.red('\nPlease fix the critical errors before starting the application.'));
      process.exit(2);
    } else if (hasErrors) {
      console.log(chalk.yellow.bold('⚠️  CONFIGURATION ISSUES FOUND'));
      console.log(chalk.yellow('The application may function but some features may be limited.'));
      console.log(chalk.yellow('\nConsider addressing the warnings for optimal operation.'));
      process.exit(1);
    } else {
      console.log(chalk.green.bold('✅ CONFIGURATION VALIDATION PASSED'));
      console.log(chalk.green('All environment variables are properly configured.'));
      console.log(chalk.green('The application can start safely.'));

      // Export configuration hash for caching
      const configHash = env.generateConfigHash();
      console.log(chalk.dim(`\nConfiguration hash: ${configHash}`));

      process.exit(0);
    }
  } catch (error) {
    console.error(chalk.red.bold('\n💥 Configuration validation failed:'));
    console.error(chalk.red(error.message));

    if (process.env.NODE_ENV === 'development') {
      console.error(chalk.gray(error.stack));
    }

    process.exit(2);
  }
}

// Run validation if this script is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  validateConfiguration();
}

export { validateConfiguration };
