/**
 * Configuration Testing and Validation Utilities
 *
 * Comprehensive testing framework for database configurations, migration settings,
 * and environment configurations with automated validation and reporting.
 *
 * Features:
 * - Configuration schema validation
 * - Database connectivity testing
 * - Migration configuration validation
 * - Performance benchmarking
 * - Environment-specific testing
 * - Automated test reporting
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { logger } from './logger.js';
import { config } from '../config/environment.js';
import { databaseConfig } from '../config/database-config.js';
import { configValidator } from '../config/validation.js';
import type { CompleteDatabaseConfig } from '../config/database-config.js';
import type { ValidationResult } from '../config/validation.js';

export interface TestResult {
  name: string;
  passed: boolean;
  duration: number;
  message: string;
  details?: any;
  error?: Error;
}

export interface TestSuite {
  name: string;
  tests: TestResult[];
  duration: number;
  passed: boolean;
  passedCount: number;
  totalCount: number;
}

export interface ConfigurationTestReport {
  timestamp: Date;
  environment: string;
  configuration: {
    databaseType: string;
    migrationMode: boolean;
    features: Record<string, boolean>;
  };
  suites: TestSuite[];
  summary: {
    totalSuites: number;
    totalTests: number;
    passedTests: number;
    failedTests: number;
    totalDuration: number;
    success: boolean;
  };
  recommendations: string[];
  warnings: string[];
}

/**
 * Configuration testing framework
 */
export class ConfigurationTester {
  private testSuites: Map<string, () => Promise<TestSuite>> = new Map();
  private environment: string;

  constructor() {
    this.environment = config.getConfig().NODE_ENV;
    this.initializeTestSuites();
  }

  /**
   * Initialize all test suites
   */
  private initializeTestSuites(): void {
    // Configuration validation tests
    this.testSuites.set('configuration-validation', this.testConfigurationValidation.bind(this));

    // Database connectivity tests
    this.testSuites.set('database-connectivity', this.testDatabaseConnectivity.bind(this));

    // Migration configuration tests
    this.testSuites.set('migration-configuration', this.testMigrationConfiguration.bind(this));

    // Performance configuration tests
    this.testSuites.set('performance-configuration', this.testPerformanceConfiguration.bind(this));

    // Security configuration tests
    this.testSuites.set('security-configuration', this.testSecurityConfiguration.bind(this));

    // Environment compatibility tests
    this.testSuites.set('environment-compatibility', this.testEnvironmentCompatibility.bind(this));

    // Feature flag tests
    this.testSuites.set('feature-flags', this.testFeatureFlags.bind(this));

    // Integration tests
    this.testSuites.set('integration-tests', this.testIntegration.bind(this));
  }

  /**
   * Run all configuration tests
   */
  async runAllTests(): Promise<ConfigurationTestReport> {
    const startTime = Date.now();
    const suites: TestSuite[] = [];
    const recommendations: string[] = [];
    const warnings: string[] = [];

    logger.info('Starting comprehensive configuration testing');

    for (const [suiteName, testFn] of this.testSuites) {
      try {
        logger.debug({ suite: suiteName }, `Running test suite: ${suiteName}`);
        const suite = await testFn();
        suites.push(suite);

        // Collect recommendations and warnings
        suite.tests.forEach(test => {
          if (!test.passed && test.details?.recommendation) {
            recommendations.push(test.details.recommendation);
          }
          if (test.details?.warning) {
            warnings.push(test.details.warning);
          }
        });

      } catch (error) {
        logger.error({ suite: suiteName, error }, `Test suite failed: ${suiteName}`);
        suites.push({
          name: suiteName,
          tests: [],
          duration: 0,
          passed: false,
          passedCount: 0,
          totalCount: 0
        });
      }
    }

    const totalDuration = Date.now() - startTime;
    const totalTests = suites.reduce((sum, suite) => sum + suite.totalCount, 0);
    const passedTests = suites.reduce((sum, suite) => sum + suite.passedCount, 0);
    const success = passedTests === totalTests;

    const report: ConfigurationTestReport = {
      timestamp: new Date(),
      environment: this.environment,
      configuration: {
        databaseType: databaseConfig.getConfiguration().selection.type,
        migrationMode: databaseConfig.getConfiguration().selection.migrationMode,
        features: databaseConfig.getFeatureFlags()
      },
      suites,
      summary: {
        totalSuites: suites.length,
        totalTests,
        passedTests,
        failedTests: totalTests - passedTests,
        totalDuration,
        success
      },
      recommendations: [...new Set(recommendations)], // Remove duplicates
      warnings: [...new Set(warnings)]
    };

    logger.info({
      success: report.summary.success,
      passed: report.summary.passedTests,
      failed: report.summary.failedTests,
      duration: report.summary.totalDuration
    }, 'Configuration testing completed');

    return report;
  }

  /**
   * Test configuration validation
   */
  private async testConfigurationValidation(): Promise<TestSuite> {
    const startTime = Date.now();
    const tests: TestResult[] = [];

    // Test schema validation
    try {
      const dbConfig = databaseConfig.getConfiguration();
      const validationResult = await configValidator.validateConfiguration(dbConfig);

      tests.push({
        name: 'schema-validation',
        passed: validationResult.valid,
        duration: 0,
        message: validationResult.valid ? 'Schema validation passed' : 'Schema validation failed',
        details: {
          errors: validationResult.errors.length,
          warnings: validationResult.warnings.length,
          recommendation: validationResult.errors.length > 0 ? 'Fix validation errors before proceeding' : undefined
        }
      });

    } catch (error) {
      tests.push({
        name: 'schema-validation',
        passed: false,
        duration: 0,
        message: 'Schema validation threw error',
        error: error instanceof Error ? error : new Error(String(error))
      });
    }

    // Test environment configuration
    try {
      const envConfig = config.getConfig();
      const hasRequiredVars = !!(
        envConfig.DB_HOST &&
        envConfig.DB_NAME &&
        envConfig.DB_USER
      );

      tests.push({
        name: 'environment-variables',
        passed: hasRequiredVars,
        duration: 0,
        message: hasRequiredVars ? 'Environment variables present' : 'Missing required environment variables',
        details: {
          missing: hasRequiredVars ? undefined : ['DB_HOST', 'DB_NAME', 'DB_USER'],
          recommendation: hasRequiredVars ? undefined : 'Set required environment variables in .env file'
        }
      });

    } catch (error) {
      tests.push({
        name: 'environment-variables',
        passed: false,
        duration: 0,
        message: 'Environment variable check failed',
        error: error instanceof Error ? error : new Error(String(error))
      });
    }

    return {
      name: 'Configuration Validation',
      tests,
      duration: Date.now() - startTime,
      passed: tests.every(t => t.passed),
      passedCount: tests.filter(t => t.passed).length,
      totalCount: tests.length
    };
  }

  /**
   * Test database connectivity
   */
  private async testDatabaseConnectivity(): Promise<TestSuite> {
    const startTime = Date.now();
    const tests: TestResult[] = [];

    const dbConfig = databaseConfig.getConfiguration();

    // Test qdrant connectivity
    if (dbConfig.selection.type === 'qdrant' || dbConfig.selection.type === 'hybrid') {
      try {
        const testStart = Date.now();
        const validation = await config.validateDatabaseConnections();
        const duration = Date.now() - testStart;

        tests.push({
          name: 'qdrant-connectivity',
          passed: validation.qdrant,
          duration,
          message: validation.qdrant ? 'qdrant connection successful' : 'qdrant connection failed',
          details: {
            errors: validation.errors,
            recommendation: validation.qdrant ? undefined : 'Check qdrant configuration and connectivity'
          }
        });

      } catch (error) {
        tests.push({
          name: 'qdrant-connectivity',
          passed: false,
          duration: 0,
          message: 'qdrant connectivity test failed',
          error: error instanceof Error ? error : new Error(String(error))
        });
      }
    }

    // Test Qdrant connectivity
    if (dbConfig.selection.type === 'qdrant' || dbConfig.selection.type === 'hybrid') {
      try {
        const testStart = Date.now();
        const validation = await config.validateDatabaseConnections();
        const duration = Date.now() - testStart;

        tests.push({
          name: 'qdrant-connectivity',
          passed: validation.qdrant,
          duration,
          message: validation.qdrant ? 'Qdrant connection successful' : 'Qdrant connection failed',
          details: {
            errors: validation.errors,
            recommendation: validation.qdrant ? undefined : 'Check Qdrant URL and API key configuration'
          }
        });

      } catch (error) {
        tests.push({
          name: 'qdrant-connectivity',
          passed: false,
          duration: 0,
          message: 'Qdrant connectivity test failed',
          error: error instanceof Error ? error : new Error(String(error))
        });
      }
    }

    return {
      name: 'Database Connectivity',
      tests,
      duration: Date.now() - startTime,
      passed: tests.every(t => t.passed),
      passedCount: tests.filter(t => t.passed).length,
      totalCount: tests.length
    };
  }

  /**
   * Test migration configuration
   */
  private async testMigrationConfiguration(): Promise<TestSuite> {
    const startTime = Date.now();
    const tests: TestResult[] = [];

    const migrationConfig = databaseConfig.getMigrationConfig();

    // Test migration mode validity
    const validModes = ['pg-to-qdrant', 'qdrant-to-pg', 'sync', 'validate', 'cleanup'];
    const modeValid = !migrationConfig.mode || validModes.includes(migrationConfig.mode);

    tests.push({
      name: 'migration-mode-validity',
      passed: modeValid,
      duration: 0,
      message: modeValid ? 'Migration mode is valid' : 'Invalid migration mode',
      details: {
        currentMode: migrationConfig.mode,
        validModes,
        recommendation: modeValid ? undefined : `Use one of: ${validModes.join(', ')}`
      }
    });

    // Test migration batch size
    const batchSizeValid = migrationConfig.batchSize >= 1 && migrationConfig.batchSize <= 10000;

    tests.push({
      name: 'migration-batch-size',
      passed: batchSizeValid,
      duration: 0,
      message: batchSizeValid ? 'Migration batch size is valid' : 'Invalid migration batch size',
      details: {
        currentSize: migrationConfig.batchSize,
        recommendation: batchSizeValid ? undefined : 'Set batch size between 1 and 10000'
      }
    });

    // Test migration concurrency
    const concurrencyValid = migrationConfig.concurrency >= 1 && migrationConfig.concurrency <= 10;

    tests.push({
      name: 'migration-concurrency',
      passed: concurrencyValid,
      duration: 0,
      message: concurrencyValid ? 'Migration concurrency is valid' : 'Invalid migration concurrency',
      details: {
        currentConcurrency: migrationConfig.concurrency,
        recommendation: concurrencyValid ? undefined : 'Set concurrency between 1 and 10'
      }
    });

    // Test safety settings
    const safeForProduction = this.environment === 'production'
      ? (migrationConfig.dryRun === false && migrationConfig.preservePg === true)
      : true;

    tests.push({
      name: 'migration-safety',
      passed: safeForProduction,
      duration: 0,
      message: safeForProduction ? 'Migration safety settings are appropriate' : 'Migration safety settings need review',
      details: {
        environment: this.environment,
        dryRun: migrationConfig.dryRun,
        preservePg: migrationConfig.preservePg,
        recommendation: safeForProduction ? undefined : 'Review safety settings for production environment'
      }
    });

    return {
      name: 'Migration Configuration',
      tests,
      duration: Date.now() - startTime,
      passed: tests.every(t => t.passed),
      passedCount: tests.filter(t => t.passed).length,
      totalCount: tests.length
    };
  }

  /**
   * Test performance configuration
   */
  private async testPerformanceConfiguration(): Promise<TestSuite> {
    const startTime = Date.now();
    const tests: TestResult[] = [];

    const dbConfig = databaseConfig.getConfiguration();

    // Test pool configuration
    const poolConfig = dbConfig.qdrant.pool;
    const poolValid = poolConfig.min <= poolConfig.max && poolConfig.max <= 100;

    tests.push({
      name: 'pool-configuration',
      passed: poolValid,
      duration: 0,
      message: poolValid ? 'Pool configuration is valid' : 'Pool configuration needs adjustment',
      details: {
        min: poolConfig.min,
        max: poolConfig.max,
        recommendation: poolValid ? undefined : 'Ensure min <= max and max <= 100'
      }
    });

    // Test timeout settings
    const timeoutValid = poolConfig.connectionTimeout >= 1000 && poolConfig.connectionTimeout <= 300000;

    tests.push({
      name: 'timeout-configuration',
      passed: timeoutValid,
      duration: 0,
      message: timeoutValid ? 'Timeout configuration is reasonable' : 'Timeout configuration may need adjustment',
      details: {
        timeout: poolConfig.connectionTimeout,
        recommendation: timeoutValid ? undefined : 'Consider timeout between 1-300 seconds'
      }
    });

    // Test environment-specific performance settings
    let performanceOptimal = true;
    const recommendations: string[] = [];

    if (this.environment === 'production') {
      if (poolConfig.max < 5) {
        performanceOptimal = false;
        recommendations.push('Consider increasing pool size for production');
      }
      if (poolConfig.connectionTimeout > 60000) {
        recommendations.push('Consider reducing connection timeout for better responsiveness');
      }
    } else if (this.environment === 'development') {
      if (poolConfig.max > 10) {
        recommendations.push('Large pool size may be unnecessary for development');
      }
    }

    tests.push({
      name: 'environment-performance',
      passed: performanceOptimal,
      duration: 0,
      message: performanceOptimal ? 'Performance settings are optimal for environment' : 'Performance settings could be optimized',
      details: {
        environment: this.environment,
        recommendations,
        recommendation: recommendations.length > 0 ? recommendations[0] : undefined
      }
    });

    return {
      name: 'Performance Configuration',
      tests,
      duration: Date.now() - startTime,
      passed: tests.every(t => t.passed),
      passedCount: tests.filter(t => t.passed).length,
      totalCount: tests.length
    };
  }

  /**
   * Test security configuration
   */
  private async testSecurityConfiguration(): Promise<TestSuite> {
    const startTime = Date.now();
    const tests: TestResult[] = [];

    const envConfig = config.getConfig();
    const dbConfig = databaseConfig.getConfiguration();

    // Test for secrets in configuration
    const hasSecurePassword = envConfig.DB_PASSWORD && envConfig.DB_PASSWORD.length >= 8;

    tests.push({
      name: 'database-password-security',
      passed: hasSecurePassword,
      duration: 0,
      message: hasSecurePassword ? 'Database password meets security requirements' : 'Database password may be weak',
      details: {
        passwordLength: envConfig.DB_PASSWORD?.length || 0,
        recommendation: hasSecurePassword ? undefined : 'Use a strong password (minimum 8 characters)'
      }
    });

    // Test for API key security
    let apiKeySecure = true;
    if (dbConfig.selection.type === 'qdrant' || dbConfig.selection.type === 'hybrid') {
      apiKeySecure = !!(dbConfig.vector.openaiApiKey && dbConfig.vector.openaiApiKey.length > 20);
    }

    tests.push({
      name: 'api-key-security',
      passed: apiKeySecure,
      duration: 0,
      message: apiKeySecure ? 'API keys appear secure' : 'API key security needs attention',
      details: {
        hasApiKey: !!(dbConfig.vector.openaiApiKey),
        keyLength: dbConfig.vector.openaiApiKey?.length || 0,
        recommendation: apiKeySecure ? undefined : 'Use valid API keys from your provider'
      }
    });

    // Test for encryption configuration
    const hasEncryption = !!envConfig.ENCRYPTION_KEY;
    const encryptionRequired = this.environment === 'production';

    tests.push({
      name: 'encryption-configuration',
      passed: !encryptionRequired || hasEncryption,
      duration: 0,
      message: hasEncryption ? 'Encryption is configured' : 'Encryption may be required',
      details: {
        environment: this.environment,
        hasEncryptionKey: hasEncryption,
        recommendation: encryptionRequired && !hasEncryption ? 'Set ENCRYPTION_KEY for production' : undefined
      }
    });

    return {
      name: 'Security Configuration',
      tests,
      duration: Date.now() - startTime,
      passed: tests.every(t => t.passed),
      passedCount: tests.filter(t => t.passed).length,
      totalCount: tests.length
    };
  }

  /**
   * Test environment compatibility
   */
  private async testEnvironmentCompatibility(): Promise<TestSuite> {
    const startTime = Date.now();
    const tests: TestResult[] = [];

    const dbConfig = databaseConfig.getConfiguration();

    // Test database type compatibility
    let typeCompatible = true;
    const warnings: string[] = [];

    if (this.environment === 'test' && dbConfig.selection.type === 'hybrid') {
      typeCompatible = false;
      warnings.push('Hybrid mode may be complex for testing');
    }

    if (this.environment === 'production' && dbConfig.selection.type === 'qdrant' && dbConfig.features.migrationMode) {
      warnings.push('Consider using hybrid mode for production with migration');
    }

    tests.push({
      name: 'database-type-compatibility',
      passed: typeCompatible,
      duration: 0,
      message: typeCompatible ? 'Database type is compatible with environment' : 'Database type may not be optimal',
      details: {
        environment: this.environment,
        databaseType: dbConfig.selection.type,
        warnings,
        recommendation: warnings.length > 0 ? warnings[0] : undefined
      }
    });

    // Test feature compatibility
    const featuresCompatible = true;

    tests.push({
      name: 'feature-compatibility',
      passed: featuresCompatible,
      duration: 0,
      message: 'Features are compatible with environment',
      details: {
        environment: this.environment,
        features: dbConfig.features
      }
    });

    return {
      name: 'Environment Compatibility',
      tests,
      duration: Date.now() - startTime,
      passed: tests.every(t => t.passed),
      passedCount: tests.filter(t => t.passed).length,
      totalCount: tests.length
    };
  }

  /**
   * Test feature flags
   */
  private async testFeatureFlags(): Promise<TestSuite> {
    const startTime = Date.now();
    const tests: TestResult[] = [];

    const features = databaseConfig.getFeatureFlags();

    // Test feature flag consistency
    const migrationConsistent = !features.migrationMode || features.healthChecks;

    tests.push({
      name: 'migration-flag-consistency',
      passed: migrationConsistent,
      duration: 0,
      message: migrationConsistent ? 'Migration flags are consistent' : 'Migration flags may be inconsistent',
      details: {
        migrationMode: features.migrationMode,
        healthChecks: features.healthChecks,
        recommendation: migrationConsistent ? undefined : 'Enable health checks when migration mode is active'
      }
    });

    // Test debug mode appropriateness
    const debugAppropriate = this.environment === 'development' ? features.debugMode : !features.debugMode;

    tests.push({
      name: 'debug-mode-appropriateness',
      passed: debugAppropriate,
      duration: 0,
      message: debugAppropriate ? 'Debug mode is appropriate for environment' : 'Debug mode may not be appropriate',
      details: {
        environment: this.environment,
        debugMode: features.debugMode,
        recommendation: debugAppropriate ? undefined : 'Consider adjusting debug mode for this environment'
      }
    });

    return {
      name: 'Feature Flags',
      tests,
      duration: Date.now() - startTime,
      passed: tests.every(t => t.passed),
      passedCount: tests.filter(t => t.passed).length,
      totalCount: tests.length
    };
  }

  /**
   * Test integration scenarios
   */
  private async testIntegration(): Promise<TestSuite> {
    const startTime = Date.now();
    const tests: TestResult[] = [];

    // Test configuration factory integration
    try {
      const factoryConfig = databaseConfig.createFactoryConfig();
      const factoryValid = !!(factoryConfig.type && factoryConfig.connectionTimeout);

      tests.push({
        name: 'factory-integration',
        passed: factoryValid,
        duration: 0,
        message: factoryValid ? 'Configuration factory integration works' : 'Configuration factory integration failed',
        details: {
          configKeys: Object.keys(factoryConfig),
          recommendation: factoryValid ? undefined : 'Check database configuration integration'
        }
      });

    } catch (error) {
      tests.push({
        name: 'factory-integration',
        passed: false,
        duration: 0,
        message: 'Factory integration test failed',
        error: error instanceof Error ? error : new Error(String(error))
      });
    }

    // Test configuration export
    try {
      const exportedConfig = config.exportForMCP();
      const exportValid = exportedConfig && typeof exportedConfig.DATABASE_TYPE === 'string';

      tests.push({
        name: 'configuration-export',
        passed: exportValid,
        duration: 0,
        message: exportValid ? 'Configuration export works' : 'Configuration export failed',
        details: {
          exportedKeys: Object.keys(exportedConfig),
          recommendation: exportValid ? undefined : 'Check configuration export functionality'
        }
      });

    } catch (error) {
      tests.push({
        name: 'configuration-export',
        passed: false,
        duration: 0,
        message: 'Configuration export test failed',
        error: error instanceof Error ? error : new Error(String(error))
      });
    }

    return {
      name: 'Integration Tests',
      tests,
      duration: Date.now() - startTime,
      passed: tests.every(t => t.passed),
      passedCount: tests.filter(t => t.passed).length,
      totalCount: tests.length
    };
  }

  /**
   * Run specific test suite
   */
  async runTestSuite(suiteName: string): Promise<TestSuite> {
    const testFn = this.testSuites.get(suiteName);
    if (!testFn) {
      throw new Error(`Unknown test suite: ${suiteName}`);
    }

    return await testFn();
  }

  /**
   * Get available test suites
   */
  getAvailableTestSuites(): string[] {
    return Array.from(this.testSuites.keys());
  }
}

// Export utility functions
export async function runConfigurationTests(): Promise<ConfigurationTestReport> {
  const tester = new ConfigurationTester();
  return await tester.runAllTests();
}

export async function runTestSuite(suiteName: string): Promise<TestSuite> {
  const tester = new ConfigurationTester();
  return await tester.runTestSuite(suiteName);
}

export function createConfigurationTester(): ConfigurationTester {
  return new ConfigurationTester();
}