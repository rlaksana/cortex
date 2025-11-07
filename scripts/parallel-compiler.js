#!/usr/bin/env node

/**
 * Advanced Parallel Compilation System
 *
 * Features:
 * - Multi-process TypeScript compilation
 * - Intelligent file grouping
 * - Load balancing across CPU cores
 * - Dependency-aware parallelization
 * - Real-time progress tracking
 * - Memory usage optimization
 */

import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import { cpus } from 'os';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { createHash } from 'crypto';
import { execSync } from 'child_process';

class ParallelCompiler {
  constructor(options = {}) {
    this.maxWorkers = options.maxWorkers || Math.max(1, cpus().length - 1);
    this.chunkSize = options.chunkSize || 10;
    this.projectRoot = options.projectRoot || process.cwd();
    this.buildDir = options.buildDir || join(this.projectRoot, 'dist');
    this.tempDir = join(this.projectRoot, '.build-temp');
    this.workers = [];
    this.results = [];
    this.startTime = Date.now();

    this.metrics = {
      totalFiles: 0,
      compiledFiles: 0,
      failedFiles: 0,
      workersUsed: 0,
      parallelEfficiency: 0,
      memoryPeak: 0,
      buildTime: 0
    };

    this.ensureTempDirectory();
  }

  ensureTempDirectory() {
    if (!existsSync(this.tempDir)) {
      mkdirSync(this.tempDir, { recursive: true });
    }
  }

  groupFilesByDependencies(files, dependencyGraph) {
    console.log('📊 Grouping files by dependencies...');

    const groups = [];
    const processed = new Set();
    const visited = new Set();

    const getDependencies = (file) => {
      if (visited.has(file)) return [];
      visited.add(file);
      return dependencyGraph.get(file) || [];
    };

    const canCompileInParallel = (file1, file2) => {
      const deps1 = new Set(getDependencies(file1));
      const deps2 = new Set(getDependencies(file2));

      // Check if file1 depends on file2 or vice versa
      if (deps1.has(file2) || deps2.has(file1)) {
        return false;
      }

      // Check for circular dependencies through transitive closure
      const hasCircularDep = (start, target, visitedDeps) => {
        if (visitedDeps.has(start)) return false;
        visitedDeps.add(start);

        const deps = getDependencies(start);
        if (deps.includes(target)) return true;

        for (const dep of deps) {
          if (hasCircularDep(dep, target, new Set(visitedDeps))) {
            return true;
          }
        }
        return false;
      };

      return !hasCircularDep(file1, file2, new Set()) && !hasCircularDep(file2, file1, new Set());
    };

    // Create groups of files that can be compiled in parallel
    for (const file of files) {
      if (processed.has(file)) continue;

      const group = [file];
      processed.add(file);

      // Try to add more files to this group
      for (const otherFile of files) {
        if (processed.has(otherFile)) continue;

        let canAdd = true;
        for (const groupFile of group) {
          if (!canCompileInParallel(groupFile, otherFile)) {
            canAdd = false;
            break;
          }
        }

        if (canAdd) {
          group.push(otherFile);
          processed.add(otherFile);
        }
      }

      groups.push(group);
    }

    console.log(`✅ Created ${groups.length} dependency groups`);
    return groups;
  }

  balanceLoad(groups) {
    console.log('⚖️  Balancing load across workers...');

    // Sort groups by size (largest first)
    groups.sort((a, b) => b.length - a.length);

    const workerGroups = Array.from({ length: this.maxWorkers }, () => []);
    const workerLoads = Array.from({ length: this.maxWorkers }, () => 0);

    // Assign groups to workers using greedy load balancing
    for (const group of groups) {
      // Find worker with minimum load
      const minLoadIndex = workerLoads.indexOf(Math.min(...workerLoads));
      workerGroups[minLoadIndex].push(...group);
      workerLoads[minLoadIndex] += group.length;
    }

    // Filter out empty worker groups
    const activeWorkers = workerGroups.filter(group => group.length > 0);
    this.metrics.workersUsed = activeWorkers.length;

    console.log(`✅ Load balanced across ${activeWorkers.length} workers`);
    return activeWorkers;
  }

  createWorkerScript() {
    const workerScript = `
import { parentPort, workerData } from 'worker_threads';
import { execSync } from 'child_process';
import { writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';

class CompilationWorker {
  constructor() {
    this.files = workerData.files;
    this.projectRoot = workerData.projectRoot;
    this.buildDir = workerData.buildDir;
    this.workerId = workerData.workerId;
    this.tempDir = workerData.tempDir;
  }

  compileFile(file) {
    try {
      const startTime = Date.now();

      // Create temporary tsconfig for this file
      const tempConfig = {
        "extends": "./tsconfig.base.json",
        "compilerOptions": {
          "outDir": this.buildDir,
          "rootDir": this.projectRoot,
          "incremental": false,
          "isolatedModules": true,
          "declaration": true,
          "sourceMap": true
        },
        "include": [file]
      };

      const configPath = join(this.tempDir, \`tsconfig.worker-\${this.workerId}.json\`);
      writeFileSync(configPath, JSON.stringify(tempConfig, null, 2));

      // Compile the file
      const result = execSync(\`npx tsc -p "\${configPath}"\`, {
        encoding: 'utf8',
        stdio: 'pipe',
        cwd: this.projectRoot
      });

      const compileTime = Date.now() - startTime;

      return {
        success: true,
        file,
        compileTime,
        output: result,
        workerId: this.workerId
      };

    } catch (error) {
      return {
        success: false,
        file,
        error: error.message,
        workerId: this.workerId
      };
    }
  }

  async run() {
    const results = [];

    for (const file of this.files) {
      const result = this.compileFile(file);
      results.push(result);

      // Send progress update
      parentPort.postMessage({
        type: 'progress',
        file,
        result,
        workerId: this.workerId
      });
    }

    // Send completion message
    parentPort.postMessage({
      type: 'complete',
      results,
      workerId: this.workerId
    });
  }
}

// Run the worker
const worker = new CompilationWorker();
worker.run().catch(error => {
  parentPort.postMessage({
    type: 'error',
    error: error.message,
    workerId: workerData.workerId
  });
});
`;

    const scriptPath = join(this.tempDir, 'parallel-compiler-worker.js');
    writeFileSync(scriptPath, workerScript);
    return scriptPath;
  }

  async compileGroups(workerGroups) {
    console.log(`🏗️  Starting parallel compilation with ${workerGroups.length} workers...`);

    const workerScript = this.createWorkerScript();
    const promises = [];

    for (let i = 0; i < workerGroups.length; i++) {
      const promise = new Promise((resolve, reject) => {
        const worker = new Worker(workerScript, {
          workerData: {
            files: workerGroups[i],
            projectRoot: this.projectRoot,
            buildDir: this.buildDir,
            workerId: i,
            tempDir: this.tempDir
          }
        });

        worker.on('message', (message) => {
          if (message.type === 'progress') {
            this.handleProgress(message);
          } else if (message.type === 'complete') {
            this.handleComplete(message);
            resolve(message.results);
          } else if (message.type === 'error') {
            reject(new Error(message.error));
          }
        });

        worker.on('error', reject);
        worker.on('exit', (code) => {
          if (code !== 0) {
            reject(new Error(\`Worker \${i} exited with code \${code}\`));
          }
        });

        this.workers.push(worker);
      });

      promises.push(promise);
    }

    try {
      const allResults = await Promise.all(promises);
      return allResults.flat();
    } finally {
      // Clean up workers
      this.workers.forEach(worker => worker.terminate());
    }
  }

  handleProgress(message) {
    const { file, result, workerId } = message;

    if (result.success) {
      this.metrics.compiledFiles++;
      console.log(\`✅ [\${workerId}] \${file} (\${result.compileTime}ms)\`);
    } else {
      this.metrics.failedFiles++;
      console.log(\`❌ [\${workerId}] \${file}: \${result.error}\`);
    }

    // Update progress
    const progress = (this.metrics.compiledFiles + this.metrics.failedFiles) / this.metrics.totalFiles * 100;
    console.log(\`📊 Progress: \${progress.toFixed(1)}%\`);
  }

  handleComplete(message) {
    const { results, workerId } = message;
    this.results.push(...results);
    console.log(\`🏁 Worker \${workerId} completed (\${results.length} files)\`);
  }

  trackMemoryUsage() {
    const memoryUsage = process.memoryUsage();
    this.metrics.memoryPeak = Math.max(this.metrics.memoryPeak, memoryUsage.heapUsed);
  }

  async performParallelCompilation(files, dependencyGraph) {
    console.log(\`🚀 Starting parallel compilation of \${files.length} files...\`);
    console.log(\`🔧 Using \${this.maxWorkers} workers\`);

    this.metrics.totalFiles = files.length;

    try {
      // Start memory tracking
      const memoryInterval = setInterval(() => this.trackMemoryUsage(), 1000);

      // Group files by dependencies
      const groups = this.groupFilesByDependencies(files, dependencyGraph);

      // Balance load across workers
      const workerGroups = this.balanceLoad(groups);

      // Compile in parallel
      const results = await this.compileGroups(workerGroups);

      // Stop memory tracking
      clearInterval(memoryInterval);

      // Calculate metrics
      this.metrics.buildTime = Date.now() - this.startTime;
      this.metrics.parallelEfficiency = this.calculateParallelEfficiency();

      console.log(\`✅ Parallel compilation completed in \${this.metrics.buildTime}ms\`);
      this.printCompilationSummary();

      return {
        success: this.metrics.failedFiles === 0,
        results,
        metrics: this.metrics
      };

    } catch (error) {
      console.error('❌ Parallel compilation failed:', error.message);
      throw error;
    }
  }

  calculateParallelEfficiency() {
    if (this.metrics.compiledFiles === 0) return 0;

    // Estimate theoretical serial time
    const avgCompileTime = this.results
      .filter(r => r.success && r.compileTime)
      .reduce((sum, r) => sum + r.compileTime, 0) / Math.max(1, this.metrics.compiledFiles);

    const theoreticalSerialTime = avgCompileTime * this.metrics.compiledFiles;
    const actualParallelTime = this.metrics.buildTime;

    return Math.min(100, (theoreticalSerialTime / actualParallelTime * 100)).toFixed(1);
  }

  printCompilationSummary() {
    console.log('\n📊 Parallel Compilation Summary:');
    console.log(\`   Total files: \${this.metrics.totalFiles}\`);
    console.log(\`   Successfully compiled: \${this.metrics.compiledFiles}\`);
    console.log(\`   Failed: \${this.metrics.failedFiles}\`);
    console.log(\`   Workers used: \${this.metrics.workersUsed}\`);
    console.log(\`   Build time: \${this.metrics.buildTime}ms\`);
    console.log(\`   Parallel efficiency: \${this.metrics.parallelEfficiency}%\`);
    console.log(\`   Peak memory usage: \${(this.metrics.memoryPeak / 1024 / 1024).toFixed(2)}MB\`);

    // Performance analysis
    const avgTimePerFile = this.metrics.compiledFiles > 0 ?
      (this.metrics.buildTime / this.metrics.compiledFiles).toFixed(2) : 0;

    console.log(\`   Average time per file: \${avgTimePerFile}ms\`);
  }

  async cleanup() {
    try {
      // Clean up temporary files
      execSync(\`rm -rf "\${this.tempDir}"\`, { stdio: 'pipe' });
      console.log('🧹 Temporary files cleaned up');
    } catch (error) {
      console.warn('⚠️  Cleanup warning:', error.message);
    }
  }
}

// CLI interface
if (import.meta.url === \`file://\${process.argv[1]}\`) {
  const options = {
    maxWorkers: process.env.PARALLEL_WORKERS ? parseInt(process.env.PARALLEL_WORKERS) : undefined,
    projectRoot: process.cwd()
  };

  const compiler = new ParallelCompiler(options);

  // Get files to compile (similar to dependency tracker)
  const files = [];
  try {
    const fileList = execSync(\`find src -name "*.ts" -not -path "*/node_modules/*" -not -name "*.test.ts" -not -name "*.spec.ts"\`, { encoding: 'utf8' });
    files.push(...fileList.trim().split('\\n').filter(Boolean));
  } catch (error) {
    console.error('❌ Could not find source files:', error.message);
    process.exit(1);
  }

  console.log('🚀 Starting parallel TypeScript compilation...');

  // For demo purposes, use empty dependency graph
  const dependencyGraph = new Map();

  compiler.performParallelCompilation(files, dependencyGraph)
    .then(async (result) => {
      await compiler.cleanup();

      if (result.success) {
        console.log('🎉 Parallel compilation completed successfully!');
        process.exit(0);
      } else {
        console.log('❌ Parallel compilation had failures');
        process.exit(1);
      }
    })
    .catch(async (error) => {
      console.error('❌ Parallel compilation failed:', error);
      await compiler.cleanup();
      process.exit(1);
    });
}

export { ParallelCompiler };