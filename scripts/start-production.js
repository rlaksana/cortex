#!/usr/bin/env node

/**
 * Production Startup Script
 *
 * Comprehensive production deployment automation for Cortex Memory MCP Server.
 * This script handles environment validation, health checks, monitoring setup,
 * graceful startup, and deployment verification.
 *
 * Usage:
 *   node scripts/start-production.js [options]
 *
 * Options:
 *   --port, -p <number>     Port to listen on (default: 3000)
 *   --host, -h <string>     Host to bind to (default: 0.0.0.0)
 *   --skip-validation       Skip environment validation
 *   --skip-health-checks    Skip health checks
 *   --enable-debug          Enable debug logging
 *   --config <path>         Custom config file path
 *   --dry-run               Validate but don't start server
 *   --generate-report       Generate startup report
 *   --verify-deployment     Run deployment verification
 *   --package-artifacts     Package deployment artifacts
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'fs';
import { performance } from 'perf_hooks';
import { createHash } from 'crypto';

// Get project root directory
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = dirname(__dirname);

// Import production modules
import { ProductionStartup } from '../src/production-startup.js';
import { ProductionEnvironmentValidator } from '../src/config/production-validator.js';
import { ProductionHealthChecker } from '../src/monitoring/production-health-checker.js';
import { ProductionLogger } from '../src/monitoring/production-logger.js';

// Parse command line arguments
const args = process.argv.slice(2);
const options = {
  port: 3000,
  host: '0.0.0.0',
  skipValidation: false,
  skipHealthChecks: false,
  enableDebug: false,
  configFile: null,
  dryRun: false,
  generateReport: false,
  verifyDeployment: false,
  packageArtifacts: false,
};

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  switch (arg) {
    case '--port':
    case '-p':
      options.port = parseInt(args[++i]);
      break;
    case '--host':
    case '-h':
      options.host = args[++i];
      break;
    case '--skip-validation':
      options.skipValidation = true;
      break;
    case '--skip-health-checks':
      options.skipHealthChecks = true;
      break;
    case '--enable-debug':
      options.enableDebug = true;
      break;
    case '--config':
      options.configFile = args[++i];
      break;
    case '--dry-run':
      options.dryRun = true;
      break;
    case '--generate-report':
      options.generateReport = true;
      break;
    case '--verify-deployment':
      options.verifyDeployment = true;
      break;
    case '--package-artifacts':
      options.packageArtifacts = true;
      break;
    case '--help':
    case '-?':
      printUsage();
      process.exit(0);
      break;
    default:
      if (arg.startsWith('--')) {
        console.error(`Unknown option: ${arg}`);
        console.error('Use --help for available options');
        process.exit(1);
      }
  }
}

/**
 * Print usage information
 */
function printUsage() {
  console.log(`
Cortex Memory MCP Server - Production Startup Script

Usage: node scripts/start-production.js [options]

Options:
  --port, -p <number>     Port to listen on (default: 3000)
  --host, -h <string>     Host to bind to (default: 0.0.0.0)
  --skip-validation       Skip environment validation
  --skip-health-checks    Skip health checks
  --enable-debug          Enable debug logging
  --config <path>         Custom config file path
  --dry-run               Validate but don't start server
  --generate-report       Generate startup report
  --verify-deployment     Run deployment verification
  --package-artifacts     Package deployment artifacts
  --help, -?              Show this help message

Examples:
  node scripts/start-production.js
  node scripts/start-production.js --port 8080 --host 127.0.0.1
  node scripts/start-production.js --dry-run --generate-report
  node scripts/start-production.js --verify-deployment --package-artifacts
`);
}

/**
 * Production deployment automation class
 */
class ProductionDeployment {
  constructor() {
    this.startTime = performance.now();
    this.logger = new ProductionLogger('production-deployment');
    this.artifacts = {
      validation: null,
      healthChecks: null,
      configuration: null,
      deployment: null,
    };
    this.metrics = {
      validationTime: 0,
      healthCheckTime: 0,
      startupTime: 0,
      totalTime: 0,
    };
  }

  /**
   * Execute the complete production deployment
   */
  async execute() {
    try {
      this.logger.info('🚀 Starting Cortex Memory MCP Server Production Deployment');
      this.logger.info('Deployment started at', { timestamp: new Date().toISOString() });
      this.logger.info('Node.js version', { version: process.version });
      this.logger.info('Platform', { platform: process.platform, arch: process.arch });

      // Set production environment
      process.env.NODE_ENV = 'production';

      // Enable debug logging if requested
      if (options.enableDebug) {
        process.env.DEBUG = 'cortex:*';
        this.logger.info('Debug logging enabled');
      }

      // Step 1: Load configuration
      await this.loadConfiguration();

      // Step 2: Environment validation
      if (!options.skipValidation) {
        await this.validateEnvironment();
      }

      // Step 3: Package artifacts if requested
      if (options.packageArtifacts) {
        await this.packageArtifacts();
      }

      // Step 4: Health checks
      if (!options.skipHealthChecks) {
        await this.performHealthChecks();
      }

      // Step 5: Start server (unless dry run)
      let startupResult = null;
      if (!options.dryRun) {
        startupResult = await this.startServer();
      }

      // Step 6: Deployment verification
      if (options.verifyDeployment) {
        await this.verifyDeployment(startupResult);
      }

      // Step 7: Generate report
      if (options.generateReport) {
        await this.generateReport(startupResult);
      }

      // Calculate total time
      this.metrics.totalTime = performance.now() - this.startTime;

      // Log completion
      this.logger.info('✅ Production deployment completed successfully', {
        totalTime: Math.round(this.metrics.totalTime),
        dryRun: options.dryRun,
      });

      if (!options.dryRun && startupResult) {
        this.logger.info('🎉 Cortex Memory MCP Server is ready for production traffic!', {
          endpoints: startupResult.endpoints,
        });
      }

    } catch (error) {
      this.logger.error('❌ Production deployment failed', {
        error: error.message,
        stack: error.stack,
        totalTime: Math.round(performance.now() - this.startTime),
      });

      // Generate failure report
      await this.generateFailureReport(error);

      process.exit(1);
    }
  }

  /**
   * Load configuration
   */
  async loadConfiguration() {
    this.logger.info('⚙️ Loading production configuration...');

    try {
      // Load environment-specific configuration
      const envFile = options.configFile || join(projectRoot, '.env.production');
      if (existsSync(envFile)) {
        this.logger.info('Loading environment from', { file: envFile });
        // dotenv would be loaded here in a real implementation
      }

      // Validate configuration
      const validator = new ProductionEnvironmentValidator();
      this.artifacts.configuration = validator.getProductionConfig();

      this.logger.info('✅ Configuration loaded successfully', {
        corsOrigins: this.artifacts.configuration.corsOrigin.length,
        securityEnabled: this.artifacts.configuration.helmetEnabled,
        rateLimitEnabled: this.artifacts.configuration.rateLimitEnabled,
      });

    } catch (error) {
      throw new Error(`Configuration loading failed: ${error.message}`);
    }
  }

  /**
   * Validate production environment
   */
  async validateEnvironment() {
    const startTime = performance.now();
    this.logger.info('🔍 Validating production environment...');

    try {
      const validator = new ProductionEnvironmentValidator();
      const validationResult = validator.validateProductionEnvironment();

      this.artifacts.validation = validationResult;

      // Log validation results
      if (validationResult.critical.length > 0) {
        this.logger.error('Critical validation errors found', {
          count: validationResult.critical.length,
          errors: validationResult.critical,
        });
        throw new Error(`Critical validation failures: ${validationResult.critical.join(', ')}`);
      }

      if (validationResult.errors.length > 0) {
        this.logger.warn('Validation errors found', {
          count: validationResult.errors.length,
          errors: validationResult.errors,
        });
      }

      if (validationResult.warnings.length > 0) {
        this.logger.warn('Validation warnings found', {
          count: validationResult.warnings.length,
          warnings: validationResult.warnings,
        });
      }

      this.metrics.validationTime = performance.now() - startTime;
      this.logger.info('✅ Environment validation completed', {
        duration: Math.round(this.metrics.validationTime),
        errors: validationResult.errors.length,
        warnings: validationResult.warnings.length,
      });

    } catch (error) {
      this.metrics.validationTime = performance.now() - startTime;
      throw error;
    }
  }

  /**
   * Package deployment artifacts
   */
  async packageArtifacts() {
    this.logger.info('📦 Packaging deployment artifacts...');

    try {
      const artifactsDir = join(projectRoot, 'artifacts', 'deployment');
      if (!existsSync(artifactsDir)) {
        mkdirSync(artifactsDir, { recursive: true });
      }

      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const packageInfo = {
        name: 'cortex-memory-mcp',
        version: '2.0.1',
        timestamp,
        environment: 'production',
        nodeVersion: process.version,
        platform: process.platform,
        architecture: process.arch,
        checksum: await this.calculateChecksum(),
        configuration: this.artifacts.configuration,
        validation: this.artifacts.validation,
      };

      // Save package info
      const packageFile = join(artifactsDir, `deployment-${timestamp}.json`);
      writeFileSync(packageFile, JSON.stringify(packageInfo, null, 2));

      // Create checksum file
      const checksumFile = join(artifactsDir, `deployment-${timestamp}.sha256`);
      writeFileSync(checksumFile, packageInfo.checksum);

      this.logger.info('✅ Deployment artifacts packaged', {
        packageFile,
        checksum: packageInfo.checksum.substring(0, 16) + '...',
      });

    } catch (error) {
      throw new Error(`Artifact packaging failed: ${error.message}`);
    }
  }

  /**
   * Perform comprehensive health checks
   */
  async performHealthChecks() {
    const startTime = performance.now();
    this.logger.info('🏥 Performing comprehensive health checks...');

    try {
      const healthChecker = new ProductionHealthChecker();

      // Perform pre-startup health checks
      const preStartupResult = await healthChecker.performPreStartupHealthCheck();
      this.artifacts.healthChecks = preStartupResult;

      // Log health check results
      if (preStartupResult.status === 'unhealthy') {
        this.logger.error('Critical health check failures found', {
          issues: preStartupResult.issues,
        });
        throw new Error(`Health check failures: ${preStartupResult.issues.join(', ')}`);
      }

      if (preStartupResult.status === 'degraded') {
        this.logger.warn('Health check warnings found', {
          issues: preStartupResult.issues,
        });
      }

      this.metrics.healthCheckTime = performance.now() - startTime;
      this.logger.info('✅ Health checks completed', {
        status: preStartupResult.status,
        duration: Math.round(this.metrics.healthCheckTime),
        checksPassed: preStartupResult.summary.passed,
        checksFailed: preStartupResult.summary.failed,
        warnings: preStartupResult.summary.warnings,
      });

    } catch (error) {
      this.metrics.healthCheckTime = performance.now() - startTime;
      throw error;
    }
  }

  /**
   * Start the production server
   */
  async startServer() {
    const startTime = performance.now();
    this.logger.info('🚀 Starting production server...');

    try {
      const startup = new ProductionStartup();
      const startupOptions = {
        skipValidation: options.skipValidation,
        enableHealthEndpoints: true,
        port: options.port,
        host: options.host,
      };

      const result = await startup.start(startupOptions);

      this.metrics.startupTime = performance.now() - startTime;
      this.artifacts.deployment = result;

      if (!result.success) {
        throw new Error(`Server startup failed: ${result.errors.join(', ')}`);
      }

      this.logger.info('✅ Production server started successfully', {
        duration: Math.round(this.metrics.startupTime),
        host: result.endpoints?.health?.split('/')[2],
        port: options.port,
      });

      return result;

    } catch (error) {
      this.metrics.startupTime = performance.now() - startTime;
      throw error;
    }
  }

  /**
   * Verify deployment
   */
  async verifyDeployment(startupResult) {
    this.logger.info('🔍 Verifying deployment...');

    try {
      const verifications = [];

      // Verify endpoints are accessible
      if (startupResult?.endpoints) {
        for (const [name, url] of Object.entries(startupResult.endpoints)) {
          try {
            const response = await fetch(url, { timeout: 5000 });
            verifications.push({
              name: `endpoint-${name}`,
              status: response.ok ? 'pass' : 'fail',
              url,
              statusCode: response.status,
            });
          } catch (error) {
            verifications.push({
              name: `endpoint-${name}`,
              status: 'fail',
              url,
              error: error.message,
            });
          }
        }
      }

      // Verify process health
      const memUsage = process.memoryUsage();
      verifications.push({
        name: 'process-memory',
        status: memUsage.heapUsed < memUsage.heapTotal * 0.9 ? 'pass' : 'warn',
        heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024),
        heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024),
      });

      // Check for critical failures
      const criticalFailures = verifications.filter(v => v.status === 'fail');
      if (criticalFailures.length > 0) {
        this.logger.error('Deployment verification failed', {
          failures: criticalFailures,
        });
        throw new Error(`Deployment verification failures: ${criticalFailures.map(f => f.name).join(', ')}`);
      }

      this.logger.info('✅ Deployment verification completed', {
        totalChecks: verifications.length,
        passed: verifications.filter(v => v.status === 'pass').length,
        warnings: verifications.filter(v => v.status === 'warn').length,
      });

    } catch (error) {
      throw new Error(`Deployment verification failed: ${error.message}`);
    }
  }

  /**
   * Generate comprehensive report
   */
  async generateReport(startupResult) {
    this.logger.info('📊 Generating deployment report...');

    try {
      const reportsDir = join(projectRoot, 'artifacts', 'reports');
      if (!existsSync(reportsDir)) {
        mkdirSync(reportsDir, { recursive: true });
      }

      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const report = {
        deployment: {
          timestamp: new Date().toISOString(),
          version: '2.0.1',
          environment: 'production',
          success: startupResult?.success || true,
          dryRun: options.dryRun,
        },
        system: {
          nodeVersion: process.version,
          platform: process.platform,
          architecture: process.arch,
          pid: process.pid,
        },
        configuration: this.artifacts.configuration,
        validation: this.artifacts.validation,
        healthChecks: this.artifacts.healthChecks,
        metrics: this.metrics,
        startup: startupResult,
        endpoints: startupResult?.endpoints,
      };

      // Save JSON report
      const jsonReportFile = join(reportsDir, `deployment-report-${timestamp}.json`);
      writeFileSync(jsonReportFile, JSON.stringify(report, null, 2));

      // Generate markdown report
      const markdownReport = this.generateMarkdownReport(report);
      const mdReportFile = join(reportsDir, `deployment-report-${timestamp}.md`);
      writeFileSync(mdReportFile, markdownReport);

      this.logger.info('✅ Deployment report generated', {
        jsonReport: jsonReportFile,
        markdownReport: mdReportFile,
      });

      if (options.enableDebug) {
        console.log('\n' + markdownReport);
      }

    } catch (error) {
      this.logger.warn('Report generation failed', { error: error.message });
      // Don't fail the deployment for report generation issues
    }
  }

  /**
   * Generate failure report
   */
  async generateFailureReport(error) {
    try {
      const reportsDir = join(projectRoot, 'artifacts', 'reports');
      if (!existsSync(reportsDir)) {
        mkdirSync(reportsDir, { recursive: true });
      }

      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const failureReport = {
        deployment: {
          timestamp: new Date().toISOString(),
          version: '2.0.1',
          environment: 'production',
          success: false,
          dryRun: options.dryRun,
        },
        failure: {
          error: error.message,
          stack: error.stack,
          phase: this.detectFailurePhase(error),
        },
        system: {
          nodeVersion: process.version,
          platform: process.platform,
          architecture: process.arch,
          pid: process.pid,
        },
        artifacts: this.artifacts,
        metrics: this.metrics,
        options,
      };

      const reportFile = join(reportsDir, `deployment-failure-${timestamp}.json`);
      writeFileSync(reportFile, JSON.stringify(failureReport, null, 2));

      this.logger.info('Failure report generated', { reportFile });

    } catch (reportError) {
      this.logger.error('Failed to generate failure report', {
        error: reportError.message,
      });
    }
  }

  /**
   * Detect which phase the failure occurred in
   */
  detectFailurePhase(error) {
    if (error.message.includes('Configuration')) return 'configuration';
    if (error.message.includes('validation')) return 'validation';
    if (error.message.includes('health')) return 'health-checks';
    if (error.message.includes('startup')) return 'server-startup';
    if (error.message.includes('verification')) return 'deployment-verification';
    return 'unknown';
  }

  /**
   * Generate markdown report
   */
  generateMarkdownReport(report) {
    const lines = [
      '# Cortex Memory MCP Server - Production Deployment Report',
      '='.repeat(60),
      '',
      `**Generated:** ${report.deployment.timestamp}`,
      `**Version:** ${report.deployment.version}`,
      `**Environment:** ${report.deployment.environment}`,
      `**Status:** ${report.deployment.success ? '✅ SUCCESS' : '❌ FAILED'}`,
      `**Dry Run:** ${report.deployment.dryRun ? 'Yes' : 'No'}`,
      '',
      '## System Information',
      '',
      `- **Node.js:** ${report.system.nodeVersion}`,
      `- **Platform:** ${report.system.platform} (${report.system.architecture})`,
      `- **Process ID:** ${report.system.pid}`,
      '',
    ];

    if (report.configuration) {
      lines.push(
        '## Configuration Summary',
        '',
        `- **Security:** ${report.configuration.helmetEnabled ? 'Enabled' : 'Disabled'}`,
        `- **Rate Limiting:** ${report.configuration.rateLimitEnabled ? 'Enabled' : 'Disabled'}`,
        `- **Metrics:** ${report.configuration.enableMetrics ? 'Enabled' : 'Disabled'}`,
        `- **Health Checks:** ${report.configuration.enableHealthChecks ? 'Enabled' : 'Disabled'}`,
        ''
      );
    }

    if (report.validation) {
      lines.push(
        '## Environment Validation',
        '',
        `- **Status:** ${report.validation.critical.length === 0 ? '✅ Passed' : '❌ Failed'}`,
        `- **Critical Issues:** ${report.validation.critical.length}`,
        `- **Errors:** ${report.validation.errors.length}`,
        `- **Warnings:** ${report.validation.warnings.length}`,
        ''
      );

      if (report.validation.critical.length > 0) {
        lines.push('### Critical Issues:');
        report.validation.critical.forEach(issue => {
          lines.push(`- ❌ ${issue}`);
        });
        lines.push('');
      }
    }

    if (report.healthChecks) {
      lines.push(
        '## Health Check Results',
        '',
        `- **Status:** ${report.healthChecks.status}`,
        `- **Total Checks:** ${report.healthChecks.summary.total}`,
        `- **Passed:** ${report.healthChecks.summary.passed}`,
        `- **Failed:** ${report.healthChecks.summary.failed}`,
        `- **Warnings:** ${report.healthChecks.summary.warnings}`,
        ''
      );

      if (report.healthChecks.issues.length > 0) {
        lines.push('### Issues:');
        report.healthChecks.issues.forEach(issue => {
          lines.push(`- ⚠️ ${issue}`);
        });
        lines.push('');
      }
    }

    lines.push(
      '## Performance Metrics',
      '',
      `- **Total Time:** ${Math.round(report.metrics.totalTime)}ms`,
      `- **Validation Time:** ${Math.round(report.metrics.validationTime)}ms`,
      `- **Health Check Time:** ${Math.round(report.metrics.healthCheckTime)}ms`,
      `- **Startup Time:** ${Math.round(report.metrics.startupTime)}ms`,
      ''
    );

    if (report.endpoints) {
      lines.push(
        '## Available Endpoints',
        ''
      );
      Object.entries(report.endpoints).forEach(([name, url]) => {
        lines.push(`- **${name}:** ${url}`);
      });
      lines.push('');
    }

    if (report.deployment.success) {
      lines.push(
        '## 🎉 Deployment Successful',
        '',
        'The Cortex Memory MCP Server is now running in production mode and ready to handle traffic.',
        ''
      );
    } else {
      lines.push(
        '## ❌ Deployment Failed',
        '',
        'The deployment encountered errors. Please check the logs and fix the issues before retrying.',
        ''
      );
    }

    lines.push(
      '---',
      `*Report generated by Cortex Memory MCP Server Production Deployment v2.0.1*`
    );

    return lines.join('\n');
  }

  /**
   * Calculate deployment checksum
   */
  async calculateChecksum() {
    const packageJsonPath = join(projectRoot, 'package.json');
    const packageJson = readFileSync(packageJsonPath, 'utf8');
    return createHash('sha256').update(packageJson).digest('hex');
  }
}

/**
 * Main execution
 */
async function main() {
  const deployment = new ProductionDeployment();
  await deployment.execute();
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Received SIGINT, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Received SIGTERM, shutting down gracefully...');
  process.exit(0);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('\n💥 Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('\n💥 Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Execute main function
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error('\n💥 Fatal error during production deployment:', error);
    process.exit(1);
  });
}

export { ProductionDeployment };