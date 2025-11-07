#!/usr/bin/env node

/**
 * Enhanced Build System Orchestrator
 *
 * This is the main entry point for the enhanced build system that coordinates:
 * - Incremental compilation with dependency tracking
 * - Parallel compilation when beneficial
 * - Build artifact generation with metadata
 * - Comprehensive validation and verification
 * - Cache management and optimization
 * - Performance monitoring and reporting
 */

import { BuildAutomation } from './build-automation.js';
import { DependencyTracker } from './dependency-tracker.js';
import { ParallelCompiler } from './parallel-compiler.js';
import { ArtifactGenerator } from './artifact-generator.js';
import { BuildValidator } from './build-validator.js';
import { BuildCacheManager } from './build-cache-manager.js';
import { performance } from 'perf_hooks';

class EnhancedBuildSystem {
  constructor(options = {}) {
    this.projectRoot = options.projectRoot || process.cwd();
    this.environment = options.environment || process.env.NODE_ENV || 'development';
    this.verbose = options.verbose || process.argv.includes('--verbose');
    this.parallel = options.parallel || process.argv.includes('--parallel');
    this.incremental = options.incremental !== false; // Default to true
    this.artifacts = options.artifacts !== false; // Default to true
    this.validation = options.validation !== false; // Default to true
    this.cache = options.cache !== false; // Default to true
    this.strict = options.strict || process.argv.includes('--strict');

    this.components = {};
    this.metrics = {
      totalBuildTime: 0,
      componentTimes: {},
      cacheHitRate: 0,
      filesProcessed: 0,
      artifactsGenerated: 0,
      validationChecks: 0,
      buildSuccess: false,
      warnings: 0,
      errors: 0
    };

    this.startTime = performance.now();
  }

  async initialize() {
    console.log('🚀 Initializing Enhanced Build System...');
    console.log(`   Environment: ${this.environment}`);
    console.log(`   Incremental: ${this.incremental}`);
    console.log(`   Parallel: ${this.parallel}`);
    console.log(`   Artifacts: ${this.artifacts}`);
    console.log(`   Validation: ${this.validation}`);
    console.log(`   Cache: ${this.cache}`);
    console.log(`   Strict Mode: ${this.strict}`);

    try {
      // Initialize cache manager first (other components depend on it)
      if (this.cache) {
        this.components.cache = new BuildCacheManager({
          projectRoot: this.projectRoot
        });
        console.log('✅ Cache manager initialized');
      }

      // Initialize other components
      this.components.buildAutomation = new BuildAutomation({
        environment: this.environment,
        verbose: this.verbose,
        incremental: this.incremental
      });

      if (this.incremental) {
        this.components.dependencyTracker = new DependencyTracker({
          projectRoot: this.projectRoot
        });
        console.log('✅ Dependency tracker initialized');
      }

      if (this.parallel) {
        this.components.parallelCompiler = new ParallelCompiler({
          projectRoot: this.projectRoot
        });
        console.log('✅ Parallel compiler initialized');
      }

      if (this.artifacts) {
        this.components.artifactGenerator = new ArtifactGenerator({
          projectRoot: this.projectRoot,
          environment: this.environment
        });
        console.log('✅ Artifact generator initialized');
      }

      if (this.validation) {
        this.components.buildValidator = new BuildValidator({
          projectRoot: this.projectRoot,
          environment: this.environment,
          strict: this.strict
        });
        console.log('✅ Build validator initialized');
      }

      console.log('✅ Enhanced build system initialized successfully');

    } catch (error) {
      console.error('❌ Build system initialization failed:', error.message);
      throw error;
    }
  }

  async executeBuild() {
    console.log('\n🏗️  Starting enhanced build process...');

    const buildStartTime = performance.now();

    try {
      // 1. Dependency Analysis (if incremental)
      if (this.incremental && this.components.dependencyTracker) {
        console.log('\n1️⃣  Analyzing dependencies for incremental build...');
        const depStartTime = performance.now();

        const sourceFiles = this.getSourceFiles();
        const incrementalResult = await this.components.dependencyTracker.performIncrementalBuild(sourceFiles);

        this.metrics.componentTimes.dependencyAnalysis = performance.now() - depStartTime;

        if (incrementalResult.success && incrementalResult.incremental) {
          console.log(`✅ Incremental build completed in ${this.metrics.componentTimes.dependencyAnalysis.toFixed(0)}ms`);
          console.log(`   Changed files: ${incrementalResult.changedFiles}`);
          console.log(`   Affected files: ${incrementalResult.affectedFiles}`);
          this.metrics.filesProcessed = incrementalResult.affectedFiles;
        } else if (incrementalResult.reason === 'no-changes') {
          console.log('✅ No changes detected - build up to date');
          this.metrics.buildSuccess = true;
          return await this.finalizeBuild();
        } else {
          console.log('⚠️  Incremental build failed, falling back to full build');
        }
      }

      // 2. Parallel Compilation (if enabled and beneficial)
      if (this.parallel && this.components.parallelCompiler) {
        console.log('\n2️⃣  Executing parallel compilation...');
        const compStartTime = performance.now();

        const sourceFiles = this.getSourceFiles();
        const dependencyGraph = this.components.dependencyTracker?.dependencyGraph || new Map();

        const parallelResult = await this.components.parallelCompiler.performParallelCompilation(sourceFiles, dependencyGraph);

        this.metrics.componentTimes.parallelCompilation = performance.now() - compStartTime;

        if (parallelResult.success) {
          console.log(`✅ Parallel compilation completed in ${this.metrics.componentTimes.parallelCompilation.toFixed(0)}ms`);
          console.log(`   Files processed: ${parallelResult.results.length}`);
          console.log(`   Parallel efficiency: ${parallelResult.metrics.parallelEfficiency}%`);
          this.metrics.filesProcessed = Math.max(this.metrics.filesProcessed, parallelResult.results.length);
        } else {
          console.log('⚠️  Parallel compilation failed, falling back to standard build');
        }
      }

      // 3. Standard Build (fallback or primary)
      if (!this.metrics.filesProcessed) {
        console.log('\n3️⃣  Executing standard build process...');
        const buildStartTime = performance.now();

        const buildResult = await this.components.buildAutomation.run();

        this.metrics.componentTimes.standardBuild = performance.now() - buildStartTime;

        if (buildResult) {
          console.log(`✅ Standard build completed in ${this.metrics.componentTimes.standardBuild.toFixed(0)}ms`);
          this.metrics.buildSuccess = true;
        } else {
          console.log('❌ Standard build failed');
          this.metrics.errors++;
          throw new Error('Build process failed');
        }
      }

      // 4. Artifact Generation
      if (this.artifacts && this.components.artifactGenerator) {
        console.log('\n4️⃣  Generating build artifacts...');
        const artifactStartTime = performance.now();

        const artifactResult = await this.components.artifactGenerator.generateCompleteArtifactSet();

        this.metrics.componentTimes.artifactGeneration = performance.now() - artifactStartTime;

        if (artifactResult) {
          console.log(`✅ Artifact generation completed in ${this.metrics.componentTimes.artifactGeneration.toFixed(0)}ms`);
          console.log(`   Artifacts generated: ${artifactResult.artifacts.metadata.totalFiles}`);
          this.metrics.artifactsGenerated = artifactResult.artifacts.metadata.totalFiles;
        } else {
          console.log('⚠️  Artifact generation failed');
          this.metrics.warnings++;
        }
      }

      // 5. Build Validation
      if (this.validation && this.components.buildValidator) {
        console.log('\n5️⃣  Performing comprehensive build validation...');
        const validationStartTime = performance.now();

        const validationResult = await this.components.buildValidator.performComprehensiveValidation();

        this.metrics.componentTimes.buildValidation = performance.now() - validationStartTime;
        this.metrics.validationChecks = validationResult.metrics.totalChecks;

        if (validationResult.summary.readyForDeployment) {
          console.log(`✅ Build validation completed in ${this.metrics.componentTimes.buildValidation.toFixed(0)}ms`);
          console.log(`   Checks passed: ${validationResult.metrics.passedChecks}/${validationResult.metrics.totalChecks}`);
        } else {
          console.log('❌ Build validation failed');
          this.metrics.errors += validationResult.metrics.criticalIssues;
          if (this.strict) {
            throw new Error('Build validation failed in strict mode');
          }
        }
      }

      this.metrics.buildSuccess = true;
      this.metrics.totalBuildTime = performance.now() - buildStartTime;

      console.log(`\n🎉 Enhanced build completed successfully in ${this.metrics.totalBuildTime.toFixed(0)}ms`);
      return await this.finalizeBuild();

    } catch (error) {
      this.metrics.buildSuccess = false;
      this.metrics.totalBuildTime = performance.now() - buildStartTime;
      console.error(`\n❌ Enhanced build failed after ${this.metrics.totalBuildTime.toFixed(0)}ms:`, error.message);
      throw error;
    }
  }

  async finalizeBuild() {
    console.log('\n🔧 Finalizing build...');

    try {
      // Update cache statistics
      if (this.components.cache) {
        const cacheReport = this.components.cache.generateCacheReport();
        this.metrics.cacheHitRate = parseFloat(cacheReport.performance.hitRate);

        if (this.cache) {
          await this.components.cache.performMaintenance();
        }
      }

      // Generate comprehensive build report
      const buildReport = this.generateBuildReport();

      // Save build report
      const reportPath = await this.saveBuildReport(buildReport);

      // Print build summary
      this.printBuildSummary();

      console.log(`\n📊 Build report saved: ${reportPath}`);
      console.log('🎉 Build process finalized successfully!');

      return {
        success: this.metrics.buildSuccess,
        metrics: this.metrics,
        report: buildReport,
        reportPath
      };

    } catch (error) {
      console.error('❌ Build finalization failed:', error.message);
      throw error;
    }
  }

  getSourceFiles() {
    try {
      const { execSync } = require('child_process');
      const fileList = execSync('find src -name "*.ts" -not -path "*/node_modules/*" -not -name "*.test.ts" -not -name "*.spec.ts"', { encoding: 'utf8' });
      return fileList.trim().split('\n').filter(Boolean);
    } catch {
      return [];
    }
  }

  generateBuildReport() {
    return {
      buildId: this.generateBuildId(),
      timestamp: new Date().toISOString(),
      environment: this.environment,
      configuration: {
        incremental: this.incremental,
        parallel: this.parallel,
        artifacts: this.artifacts,
        validation: this.validation,
        cache: this.cache,
        strict: this.strict
      },
      metrics: this.metrics,
      components: Object.fromEntries(
        Object.entries(this.components).map(([name, component]) => [
          name,
          typeof component.generateCacheReport === 'function' ?
            component.generateCacheReport() :
            { type: component.constructor.name, status: 'active' }
        ])
      ),
      performance: {
        totalBuildTime: this.metrics.totalBuildTime,
        averageComponentTime: Object.values(this.metrics.componentTimes).reduce((sum, time) => sum + time, 0) / Object.keys(this.metrics.componentTimes).length || 0,
        bottleneckComponent: this.findBottleneckComponent(),
        efficiency: this.calculateBuildEfficiency()
      },
      quality: {
        success: this.metrics.buildSuccess,
        warnings: this.metrics.warnings,
        errors: this.metrics.errors,
        validationPassed: this.metrics.errors === 0,
        readyForDeployment: this.metrics.buildSuccess && this.metrics.errors === 0
      }
    };
  }

  async saveBuildReport(report) {
    const { writeFileSync, mkdirSync } = require('fs');
    const { join } = require('path');

    const reportsDir = join(this.projectRoot, 'artifacts', 'reports');
    if (!require('fs').existsSync(reportsDir)) {
      mkdirSync(reportsDir, { recursive: true });
    }

    const reportPath = join(reportsDir, `enhanced-build-${report.buildId}.json`);
    writeFileSync(reportPath, JSON.stringify(report, null, 2));

    return reportPath;
  }

  generateBuildId() {
    const { createHash } = require('crypto');
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const hash = createHash('sha256')
      .update(Date.now().toString() + process.pid.toString())
      .digest('hex')
      .substring(0, 8);
    return `enhanced-build-${timestamp}-${hash}`;
  }

  findBottleneckComponent() {
    const componentTimes = Object.entries(this.metrics.componentTimes);
    if (componentTimes.length === 0) return null;

    return componentTimes.reduce((slowest, [name, time]) =>
      time > (slowest?.time || 0) ? { name, time } : slowest,
      null
    );
  }

  calculateBuildEfficiency() {
    if (this.metrics.totalBuildTime === 0) return 100;

    // Simple efficiency calculation based on parallel utilization and cache hits
    let efficiency = 100;

    // Reduce efficiency for each warning
    efficiency -= this.metrics.warnings * 2;

    // Reduce efficiency significantly for each error
    efficiency -= this.metrics.errors * 20;

    // Increase efficiency for good cache hit rate
    efficiency += this.metrics.cacheHitRate * 0.1;

    // Increase efficiency for parallel processing
    if (this.parallel && this.metrics.componentTimes.parallelCompilation) {
      efficiency += 10;
    }

    return Math.max(0, Math.min(100, efficiency)).toFixed(1);
  }

  printBuildSummary() {
    console.log('\n📊 Enhanced Build Summary:');
    console.log(`   Status: ${this.metrics.buildSuccess ? '✅ SUCCESS' : '❌ FAILED'}`);
    console.log(`   Total Time: ${this.metrics.totalBuildTime.toFixed(0)}ms`);
    console.log(`   Files Processed: ${this.metrics.filesProcessed}`);
    console.log(`   Artifacts Generated: ${this.metrics.artifactsGenerated}`);
    console.log(`   Validation Checks: ${this.metrics.validationChecks}`);
    console.log(`   Cache Hit Rate: ${this.metrics.cacheHitRate.toFixed(1)}%`);
    console.log(`   Build Efficiency: ${this.calculateBuildEfficiency()}%`);
    console.log(`   Warnings: ${this.metrics.warnings}`);
    console.log(`   Errors: ${this.metrics.errors}`);

    if (Object.keys(this.metrics.componentTimes).length > 0) {
      console.log('\n⏱️  Component Breakdown:');
      Object.entries(this.metrics.componentTimes).forEach(([component, time]) => {
        const percentage = ((time / this.metrics.totalBuildTime) * 100).toFixed(1);
        console.log(`   ${component}: ${time.toFixed(0)}ms (${percentage}%)`);
      });
    }

    const bottleneck = this.findBottleneckComponent();
    if (bottleneck) {
      console.log(`\n🐌 Bottleneck: ${bottleneck.name} (${bottleneck.time.toFixed(0)}ms)`);
    }

    if (this.metrics.buildSuccess && this.metrics.errors === 0) {
      console.log('\n🚀 Build is ready for deployment!');
    } else {
      console.log('\n⚠️  Build has issues that need to be addressed');
    }
  }

  async cleanup() {
    console.log('\n🧹 Performing cleanup...');

    try {
      // Save any pending cache data
      if (this.components.cache) {
        this.components.cache.saveCacheIndex();
      }

      // Clean up temporary files
      const { execSync } = require('child_process');
      try {
        execSync('rm -rf .build-temp', { stdio: 'pipe' });
      } catch {}

      console.log('✅ Cleanup completed');
    } catch (error) {
      console.warn('⚠️  Cleanup warning:', error.message);
    }
  }
}

// CLI interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const options = {
    environment: process.env.NODE_ENV || process.argv.find(arg => arg.startsWith('--env='))?.split('=')[1] || 'development',
    verbose: process.argv.includes('--verbose'),
    parallel: process.argv.includes('--parallel'),
    incremental: !process.argv.includes('--no-incremental'),
    artifacts: !process.argv.includes('--no-artifacts'),
    validation: !process.argv.includes('--no-validation'),
    cache: !process.argv.includes('--no-cache'),
    strict: process.argv.includes('--strict')
  };

  const buildSystem = new EnhancedBuildSystem(options);

  buildSystem.initialize()
    .then(() => buildSystem.executeBuild())
    .then(async (result) => {
      await buildSystem.cleanup();

      if (result.success) {
        console.log('\n🎉 Enhanced build system completed successfully!');
        process.exit(0);
      } else {
        console.log('\n❌ Enhanced build system completed with errors');
        process.exit(1);
      }
    })
    .catch(async (error) => {
      console.error('\n❌ Enhanced build system failed:', error);
      await buildSystem.cleanup();
      process.exit(1);
    });
}

export { EnhancedBuildSystem };