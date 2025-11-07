#!/usr/bin/env node

/**
 * Advanced Dependency Tracking System for Incremental Builds
 *
 * Features:
 * - File dependency graph analysis
 * - Change impact detection
 * - Smart invalidation strategies
 * - Build cache management
 * - Performance metrics collection
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, statSync } from 'fs';
import { join, dirname, relative, extname } from 'path';
import { execSync } from 'child_process';
import { createHash } from 'crypto';

class DependencyTracker {
  constructor(options = {}) {
    this.projectRoot = options.projectRoot || process.cwd();
    this.cacheDir = options.cacheDir || join(this.projectRoot, '.build-cache');
    this.dependencyFile = join(this.cacheDir, 'dependencies.json');
    this.buildInfoFile = join(this.projectRoot, '.tsbuildinfo');
    this.maxCacheAge = options.maxCacheAge || 7 * 24 * 60 * 60 * 1000; // 7 days

    this.dependencyGraph = new Map();
    this.fileHashes = new Map();
    this.buildMetrics = {
      totalFiles: 0,
      changedFiles: 0,
      affectedFiles: 0,
      cacheHits: 0,
      buildTime: 0
    };

    this.ensureCacheDirectory();
    this.loadDependencyCache();
  }

  ensureCacheDirectory() {
    if (!existsSync(this.cacheDir)) {
      mkdirSync(this.cacheDir, { recursive: true });
    }
  }

  loadDependencyCache() {
    try {
      if (existsSync(this.dependencyFile)) {
        const cacheData = JSON.parse(readFileSync(this.dependencyFile, 'utf8'));
        const cacheAge = Date.now() - new Date(cacheData.timestamp).getTime();

        if (cacheAge < this.maxCacheAge) {
          this.dependencyGraph = new Map(Object.entries(cacheData.dependencies || {}));
          this.fileHashes = new Map(Object.entries(cacheData.fileHashes || {}));
          console.log(`📦 Loaded dependency cache with ${this.dependencyGraph.size} files`);
        } else {
          console.log('🗑️  Dependency cache expired, clearing...');
          this.clearCache();
        }
      }
    } catch (error) {
      console.warn('⚠️  Failed to load dependency cache:', error.message);
      this.clearCache();
    }
  }

  saveDependencyCache() {
    const cacheData = {
      timestamp: new Date().toISOString(),
      dependencies: Object.fromEntries(this.dependencyGraph),
      fileHashes: Object.fromEntries(this.fileHashes),
      buildMetrics: this.buildMetrics
    };

    writeFileSync(this.dependencyFile, JSON.stringify(cacheData, null, 2));
    console.log(`💾 Saved dependency cache for ${this.dependencyGraph.size} files`);
  }

  clearCache() {
    this.dependencyGraph.clear();
    this.fileHashes.clear();
    if (existsSync(this.dependencyFile)) {
      try {
        require('fs').unlinkSync(this.dependencyFile);
      } catch (error) {
        // Ignore deletion errors
      }
    }
  }

  calculateFileHash(filePath) {
    try {
      const content = readFileSync(filePath, 'utf8');
      const stat = statSync(filePath);
      const hashInput = `${content}:${stat.mtime.getTime()}:${stat.size}`;
      return createHash('md5').update(hashInput).digest('hex');
    } catch (error) {
      console.warn(`⚠️  Could not hash file ${filePath}:`, error.message);
      return null;
    }
  }

  hasFileChanged(filePath) {
    const currentHash = this.calculateFileHash(filePath);
    if (!currentHash) return true;

    const cachedHash = this.fileHashes.get(filePath);
    const changed = currentHash !== cachedHash;

    if (changed) {
      this.fileHashes.set(filePath, currentHash);
    }

    return changed;
  }

  extractDependenciesFromFile(filePath) {
    try {
      const content = readFileSync(filePath, 'utf8');
      const dependencies = new Set();

      // Extract import statements
      const importRegex = /import\s+.*?\s+from\s+['"]([^'"]+)['"]/g;
      let match;
      while ((match = importRegex.exec(content)) !== null) {
        const importPath = match[1];
        const resolvedPath = this.resolveImportPath(filePath, importPath);
        if (resolvedPath) {
          dependencies.add(resolvedPath);
        }
      }

      // Extract require statements
      const requireRegex = /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
      while ((match = requireRegex.exec(content)) !== null) {
        const requirePath = match[1];
        const resolvedPath = this.resolveImportPath(filePath, requirePath);
        if (resolvedPath) {
          dependencies.add(resolvedPath);
        }
      }

      // Extract TypeScript triple-slash directives
      const tsRegex = /\/\/\/\s*<reference\s+path=['"]([^'"]+)['"]\s*\/>/g;
      while ((match = tsRegex.exec(content)) !== null) {
        const refPath = match[1];
        const resolvedPath = this.resolveImportPath(filePath, refPath);
        if (resolvedPath) {
          dependencies.add(resolvedPath);
        }
      }

      return Array.from(dependencies);
    } catch (error) {
      console.warn(`⚠️  Could not extract dependencies from ${filePath}:`, error.message);
      return [];
    }
  }

  resolveImportPath(fromFile, importPath) {
    try {
      // Handle different path formats
      if (importPath.startsWith('.')) {
        // Relative path
        const fromDir = dirname(fromFile);
        const absolutePath = join(fromDir, importPath);

        // Try different extensions
        const extensions = ['.ts', '.js', '.json', '.tsx', '.jsx'];
        for (const ext of extensions) {
          const withExt = absolutePath + ext;
          if (existsSync(withExt)) {
            return relative(this.projectRoot, withExt);
          }
        }

        // Try index files
        for (const ext of extensions) {
          const indexPath = join(absolutePath, `index${ext}`);
          if (existsSync(indexPath)) {
            return relative(this.projectRoot, indexPath);
          }
        }
      } else if (!importPath.startsWith('/')) {
        // Node module or path alias - skip for now
        return null;
      }

      return null;
    } catch (error) {
      return null;
    }
  }

  buildDependencyGraph(sourceFiles) {
    console.log('🔗 Building dependency graph...');

    const visited = new Set();
    const processing = new Set();

    const processFile = (filePath) => {
      if (visited.has(filePath) || processing.has(filePath)) {
        return;
      }

      processing.add(filePath);

      try {
        const dependencies = this.extractDependenciesFromFile(filePath);
        this.dependencyGraph.set(filePath, dependencies);

        // Recursively process dependencies
        for (const dep of dependencies) {
          if (sourceFiles.includes(dep)) {
            processFile(dep);
          }
        }
      } catch (error) {
        console.warn(`⚠️  Error processing ${filePath}:`, error.message);
      } finally {
        processing.delete(filePath);
        visited.add(filePath);
      }
    };

    // Process all source files
    for (const file of sourceFiles) {
      processFile(file);
    }

    this.buildMetrics.totalFiles = this.dependencyGraph.size;
    console.log(`✅ Dependency graph built with ${this.buildMetrics.totalFiles} files`);
  }

  getChangedFiles(sourceFiles) {
    const changedFiles = [];

    for (const file of sourceFiles) {
      if (this.hasFileChanged(file)) {
        changedFiles.push(file);
      }
    }

    this.buildMetrics.changedFiles = changedFiles.length;
    return changedFiles;
  }

  getAffectedFiles(changedFiles) {
    const affectedFiles = new Set(changedFiles);
    const toProcess = [...changedFiles];

    while (toProcess.length > 0) {
      const currentFile = toProcess.shift();
      const dependents = this.findDependents(currentFile);

      for (const dependent of dependents) {
        if (!affectedFiles.has(dependent)) {
          affectedFiles.add(dependent);
          toProcess.push(dependent);
        }
      }
    }

    this.buildMetrics.affectedFiles = affectedFiles.size;
    return Array.from(affectedFiles);
  }

  findDependents(filePath) {
    const dependents = [];

    for (const [file, deps] of this.dependencyGraph) {
      if (deps.includes(filePath)) {
        dependents.push(file);
      }
    }

    return dependents;
  }

  generateIncrementalBuildCommand(affectedFiles) {
    if (affectedFiles.length === 0) {
      console.log('🎉 No files need rebuilding!');
      return null;
    }

    const fileList = affectedFiles.map(f => `"${f}"`).join(' ');
    const incrementalCommand = `npx tsc --incremental --tsBuildInfoFile "${this.buildInfoFile}" ${fileList}`;

    console.log(`📝 Building ${affectedFiles.length} affected files...`);
    return incrementalCommand;
  }

  analyzeBuildImpact() {
    const totalFiles = this.dependencyGraph.size;
    const changedFiles = this.buildMetrics.changedFiles;
    const affectedFiles = this.buildMetrics.affectedFiles;

    const impactRatio = totalFiles > 0 ? (affectedFiles / totalFiles * 100).toFixed(1) : 0;
    const changeRatio = totalFiles > 0 ? (changedFiles / totalFiles * 100).toFixed(1) : 0;

    console.log('\n📊 Build Impact Analysis:');
    console.log(`   Total files: ${totalFiles}`);
    console.log(`   Changed files: ${changedFiles} (${changeRatio}%)`);
    console.log(`   Affected files: ${affectedFiles} (${impactRatio}%)`);

    if (impactRatio < 20) {
      console.log('   🟢 Low impact - Fast incremental build expected');
    } else if (impactRatio < 50) {
      console.log('   🟡 Medium impact - Moderate build time expected');
    } else {
      console.log('   🔴 High impact - Consider full rebuild');
    }
  }

  async performIncrementalBuild(sourceFiles) {
    const startTime = Date.now();

    try {
      // Build dependency graph
      this.buildDependencyGraph(sourceFiles);

      // Find changed files
      const changedFiles = this.getChangedFiles(sourceFiles);

      if (changedFiles.length === 0) {
        console.log('✅ No changes detected - build up to date');
        this.buildMetrics.cacheHits = this.buildMetrics.totalFiles;
        return { success: true, incremental: false, reason: 'no-changes' };
      }

      // Get affected files
      const affectedFiles = this.getAffectedFiles(changedFiles);

      // Analyze impact
      this.analyzeBuildImpact();

      // Generate build command
      const buildCommand = this.generateIncrementalBuildCommand(affectedFiles);

      if (!buildCommand) {
        return { success: true, incremental: false, reason: 'no-build-needed' };
      }

      // Execute build
      console.log('🏗️  Executing incremental build...');
      execSync(buildCommand, { stdio: 'inherit' });

      // Save updated cache
      this.saveDependencyCache();

      const buildTime = Date.now() - startTime;
      this.buildMetrics.buildTime = buildTime;

      console.log(`✅ Incremental build completed in ${buildTime}ms`);

      return {
        success: true,
        incremental: true,
        changedFiles: changedFiles.length,
        affectedFiles: affectedFiles.length,
        buildTime
      };

    } catch (error) {
      console.error('❌ Incremental build failed:', error.message);
      console.log('🔄 Falling back to full build...');

      // Clear cache and fallback to full build
      this.clearCache();
      return { success: false, incremental: false, error: error.message };
    }
  }

  printDependencyStats() {
    console.log('\n📈 Dependency Statistics:');
    console.log(`   Files tracked: ${this.dependencyGraph.size}`);
    console.log(`   File hashes cached: ${this.fileHashes.size}`);

    // Calculate dependency depth
    let maxDepth = 0;
    let totalDeps = 0;

    for (const [file, deps] of this.dependencyGraph) {
      totalDeps += deps.length;
      maxDepth = Math.max(maxDepth, deps.length);
    }

    const avgDeps = this.dependencyGraph.size > 0 ? (totalDeps / this.dependencyGraph.size).toFixed(2) : 0;

    console.log(`   Average dependencies per file: ${avgDeps}`);
    console.log(`   Maximum dependency depth: ${maxDepth}`);
  }
}

// CLI interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const options = {
    projectRoot: process.cwd(),
    cacheDir: process.env.BUILD_CACHE_DIR || join(process.cwd(), '.build-cache')
  };

  const tracker = new DependencyTracker(options);

  // Get source files from TypeScript config
  const sourceFiles = [];
  try {
    const tsconfig = JSON.parse(readFileSync('tsconfig.json', 'utf8'));
    const includePatterns = tsconfig.include || ['src/**/*.ts'];

    // Simple glob expansion for demonstration
    const { execSync } = await import('child_process');
    const fileList = execSync(`find src -name "*.ts" -not -path "*/node_modules/*" -not -name "*.test.ts" -not -name "*.spec.ts"`, { encoding: 'utf8' });
    sourceFiles.push(...fileList.trim().split('\n').filter(Boolean));
  } catch (error) {
    console.error('❌ Could not read tsconfig.json:', error.message);
    process.exit(1);
  }

  console.log('🚀 Starting incremental build analysis...');

  tracker.performIncrementalBuild(sourceFiles)
    .then(result => {
      tracker.printDependencyStats();
      console.log('\n📋 Build Summary:');
      console.log(JSON.stringify(result, null, 2));
    })
    .catch(error => {
      console.error('❌ Build analysis failed:', error);
      process.exit(1);
    });
}

export { DependencyTracker };