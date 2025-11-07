#!/usr/bin/env node

/**
 * Advanced Build Cache Management System
 *
 * Features:
 * - Intelligent cache invalidation strategies
 * - Multi-tier caching (file, dependency, build info)
 * - Cache size management and cleanup
 * - Cache analytics and reporting
 * - Distributed cache support
 * - Cache security and integrity verification
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { execSync } from 'child_process';
import { createHash } from 'crypto';
import { readdir, rm } from 'fs/promises';

class BuildCacheManager {
  constructor(options = {}) {
    this.projectRoot = options.projectRoot || process.cwd();
    this.cacheRoot = options.cacheRoot || join(this.projectRoot, '.build-cache');
    this.maxCacheSize = options.maxCacheSize || 1024 * 1024 * 1024; // 1GB
    this.maxCacheAge = options.maxCacheAge || 7 * 24 * 60 * 60 * 1000; // 7 days
    this.compressionEnabled = options.compressionEnabled || false;
    this.verificationEnabled = options.verificationEnabled || true;

    this.cacheDirs = {
      files: join(this.cacheRoot, 'files'),
      dependencies: join(this.cacheRoot, 'dependencies'),
      metadata: join(this.cacheRoot, 'metadata'),
      buildInfo: join(this.cacheRoot, 'build-info'),
      analytics: join(this.cacheRoot, 'analytics')
    };

    this.cacheIndex = {
      files: new Map(),
      dependencies: new Map(),
      metadata: new Map(),
      buildInfo: new Map()
    };

    this.metrics = {
      cacheHits: 0,
      cacheMisses: 0,
      cacheSize: 0,
      cacheEntries: 0,
      cleanupRuns: 0,
      lastCleanup: null
    };

    this.initializeCache();
  }

  initializeCache() {
    console.log('🚀 Initializing build cache system...');

    // Create cache directories
    Object.values(this.cacheDirs).forEach(dir => {
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
    });

    // Load cache index
    this.loadCacheIndex();

    // Perform initial cleanup if needed
    this.performMaintenance().then(() => {
      console.log('✅ Build cache system initialized');
    });
  }

  loadCacheIndex() {
    try {
      const indexPath = join(this.cacheRoot, 'cache-index.json');
      if (existsSync(indexPath)) {
        const indexData = JSON.parse(readFileSync(indexPath, 'utf8'));

        // Rebuild Maps from stored data
        Object.entries(indexData.files || {}).forEach(([key, value]) => {
          this.cacheIndex.files.set(key, value);
        });
        Object.entries(indexData.dependencies || {}).forEach(([key, value]) => {
          this.cacheIndex.dependencies.set(key, value);
        });
        Object.entries(indexData.metadata || {}).forEach(([key, value]) => {
          this.cacheIndex.metadata.set(key, value);
        });
        Object.entries(indexData.buildInfo || {}).forEach(([key, value]) => {
          this.cacheIndex.buildInfo.set(key, value);
        });

        // Load metrics
        if (indexData.metrics) {
          this.metrics = { ...this.metrics, ...indexData.metrics };
        }

        console.log(`📦 Loaded cache index with ${this.getTotalCacheEntries()} entries`);
      }
    } catch (error) {
      console.warn('⚠️  Could not load cache index:', error.message);
    }
  }

  saveCacheIndex() {
    try {
      const indexPath = join(this.cacheRoot, 'cache-index.json');
      const indexData = {
        files: Object.fromEntries(this.cacheIndex.files),
        dependencies: Object.fromEntries(this.cacheIndex.dependencies),
        metadata: Object.fromEntries(this.cacheIndex.metadata),
        buildInfo: Object.fromEntries(this.cacheIndex.buildInfo),
        metrics: this.metrics,
        timestamp: new Date().toISOString()
      };

      writeFileSync(indexPath, JSON.stringify(indexData, null, 2));
    } catch (error) {
      console.warn('⚠️  Could not save cache index:', error.message);
    }
  }

  generateCacheKey(filePath, additionalData = {}) {
    const stats = statSync(filePath);
    const keyData = {
      path: filePath,
      size: stats.size,
      mtime: stats.mtime.getTime(),
      ...additionalData
    };

    return createHash('sha256')
      .update(JSON.stringify(keyData))
      .digest('hex');
  }

  // File-level caching
  async cacheFile(filePath, content, metadata = {}) {
    try {
      const cacheKey = this.generateCacheKey(filePath, metadata);
      const cachePath = join(this.cacheDirs.files, `${cacheKey}.cache`);

      // Prepare cache entry
      const cacheEntry = {
        key: cacheKey,
        originalPath: filePath,
        cachePath: cachePath,
        timestamp: new Date().toISOString(),
        size: content.length,
        checksum: createHash('sha256').update(content).digest('hex'),
        metadata: {
          ...metadata,
          nodeVersion: process.version,
          platform: process.platform
        }
      };

      // Write cached file
      writeFileSync(cachePath, content);

      // Update index
      this.cacheIndex.files.set(cacheKey, cacheEntry);

      console.log(`💾 Cached file: ${filePath} -> ${cacheKey}`);
      return cacheKey;

    } catch (error) {
      console.warn(`⚠️  Could not cache file ${filePath}:`, error.message);
      return null;
    }
  }

  async getCachedFile(filePath, metadata = {}) {
    try {
      const cacheKey = this.generateCacheKey(filePath, metadata);
      const cacheEntry = this.cacheIndex.files.get(cacheKey);

      if (!cacheEntry) {
        this.metrics.cacheMisses++;
        return null;
      }

      // Check if cache file exists and is valid
      if (!existsSync(cacheEntry.cachePath)) {
        this.cacheIndex.files.delete(cacheKey);
        this.metrics.cacheMisses++;
        return null;
      }

      // Verify cache integrity
      if (this.verificationEnabled) {
        const content = readFileSync(cacheEntry.cachePath);
        const currentChecksum = createHash('sha256').update(content).digest('hex');

        if (currentChecksum !== cacheEntry.checksum) {
          console.warn(`⚠️  Cache corruption detected for ${filePath}`);
          this.cacheIndex.files.delete(cacheKey);
          try { unlinkSync(cacheEntry.cachePath); } catch {}
          this.metrics.cacheMisses++;
          return null;
        }
      }

      this.metrics.cacheHits++;
      console.log(`📥 Cache hit for file: ${filePath}`);
      return {
        content: readFileSync(cacheEntry.cachePath),
        metadata: cacheEntry.metadata,
        cacheEntry
      };

    } catch (error) {
      console.warn(`⚠️  Could not retrieve cached file ${filePath}:`, error.message);
      this.metrics.cacheMisses++;
      return null;
    }
  }

  // Dependency-level caching
  async cacheDependencies(filePath, dependencies, metadata = {}) {
    try {
      const cacheKey = this.generateCacheKey(filePath, { type: 'dependencies', ...metadata });
      const cachePath = join(this.cacheDirs.dependencies, `${cacheKey}.json`);

      const cacheEntry = {
        key: cacheKey,
        originalPath: filePath,
        cachePath: cachePath,
        timestamp: new Date().toISOString(),
        dependencies: dependencies,
        dependencyCount: dependencies.length,
        checksum: createHash('sha256').update(JSON.stringify(dependencies)).digest('hex'),
        metadata
      };

      writeFileSync(cachePath, JSON.stringify(cacheEntry, null, 2));
      this.cacheIndex.dependencies.set(cacheKey, cacheEntry);

      console.log(`💾 Cached dependencies for: ${filePath} (${dependencies.length} deps)`);
      return cacheKey;

    } catch (error) {
      console.warn(`⚠️  Could not cache dependencies for ${filePath}:`, error.message);
      return null;
    }
  }

  async getCachedDependencies(filePath, metadata = {}) {
    try {
      const cacheKey = this.generateCacheKey(filePath, { type: 'dependencies', ...metadata });
      const cacheEntry = this.cacheIndex.dependencies.get(cacheKey);

      if (!cacheEntry) {
        this.metrics.cacheMisses++;
        return null;
      }

      if (!existsSync(cacheEntry.cachePath)) {
        this.cacheIndex.dependencies.delete(cacheKey);
        this.metrics.cacheMisses++;
        return null;
      }

      this.metrics.cacheHits++;
      console.log(`📥 Cache hit for dependencies: ${filePath}`);
      return {
        dependencies: cacheEntry.dependencies,
        metadata: cacheEntry.metadata,
        cacheEntry
      };

    } catch (error) {
      console.warn(`⚠️  Could not retrieve cached dependencies for ${filePath}:`, error.message);
      this.metrics.cacheMisses++;
      return null;
    }
  }

  // Build info caching
  async cacheBuildInfo(buildId, buildInfo) {
    try {
      const cachePath = join(this.cacheDirs.buildInfo, `${buildId}.json`);
      const cacheEntry = {
        buildId,
        cachePath,
        timestamp: new Date().toISOString(),
        buildInfo,
        checksum: createHash('sha256').update(JSON.stringify(buildInfo)).digest('hex')
      };

      writeFileSync(cachePath, JSON.stringify(cacheEntry, null, 2));
      this.cacheIndex.buildInfo.set(buildId, cacheEntry);

      console.log(`💾 Cached build info: ${buildId}`);
      return buildId;

    } catch (error) {
      console.warn(`⚠️  Could not cache build info ${buildId}:`, error.message);
      return null;
    }
  }

  async getCachedBuildInfo(buildId) {
    try {
      const cacheEntry = this.cacheIndex.buildInfo.get(buildId);

      if (!cacheEntry) {
        this.metrics.cacheMisses++;
        return null;
      }

      if (!existsSync(cacheEntry.cachePath)) {
        this.cacheIndex.buildInfo.delete(buildId);
        this.metrics.cacheMisses++;
        return null;
      }

      this.metrics.cacheHits++;
      console.log(`📥 Cache hit for build info: ${buildId}`);
      return {
        buildInfo: cacheEntry.buildInfo,
        metadata: { timestamp: cacheEntry.timestamp },
        cacheEntry
      };

    } catch (error) {
      console.warn(`⚠️  Could not retrieve cached build info ${buildId}:`, error.message);
      this.metrics.cacheMisses++;
      return null;
    }
  }

  // Cache invalidation
  invalidateFile(filePath) {
    let invalidated = 0;

    // Find and invalidate file cache entries
    for (const [key, entry] of this.cacheIndex.files) {
      if (entry.originalPath === filePath) {
        try {
          unlinkSync(entry.cachePath);
        } catch {}
        this.cacheIndex.files.delete(key);
        invalidated++;
      }
    }

    // Invalidate dependency caches for this file
    for (const [key, entry] of this.cacheIndex.dependencies) {
      if (entry.originalPath === filePath) {
        try {
          unlinkSync(entry.cachePath);
        } catch {}
        this.cacheIndex.dependencies.delete(key);
        invalidated++;
      }
    }

    if (invalidated > 0) {
      console.log(`🗑️  Invalidated ${invalidated} cache entries for: ${filePath}`);
    }

    return invalidated;
  }

  invalidatePattern(pattern) {
    let invalidated = 0;
    const regex = new RegExp(pattern);

    // Invalidate file caches matching pattern
    for (const [key, entry] of this.cacheIndex.files) {
      if (regex.test(entry.originalPath)) {
        try {
          unlinkSync(entry.cachePath);
        } catch {}
        this.cacheIndex.files.delete(key);
        invalidated++;
      }
    }

    // Invalidate dependency caches matching pattern
    for (const [key, entry] of this.cacheIndex.dependencies) {
      if (regex.test(entry.originalPath)) {
        try {
          unlinkSync(entry.cachePath);
        } catch {}
        this.cacheIndex.dependencies.delete(key);
        invalidated++;
      }
    }

    console.log(`🗑️  Invalidated ${invalidated} cache entries matching pattern: ${pattern}`);
    return invalidated;
  }

  clearCache() {
    console.log('🧹 Clearing all cache...');

    let cleared = 0;

    // Clear all cache directories
    Object.values(this.cacheDirs).forEach(async (dir) => {
      try {
        const files = await readdir(dir);
        for (const file of files) {
          const filePath = join(dir, file);
          await rm(filePath, { recursive: true, force: true });
          cleared++;
        }
      } catch (error) {
        console.warn(`⚠️  Could not clear cache directory ${dir}:`, error.message);
      }
    });

    // Clear in-memory index
    this.cacheIndex.files.clear();
    this.cacheIndex.dependencies.clear();
    this.cacheIndex.metadata.clear();
    this.cacheIndex.buildInfo.clear();

    // Reset metrics
    this.metrics = {
      cacheHits: 0,
      cacheMisses: 0,
      cacheSize: 0,
      cacheEntries: 0,
      cleanupRuns: this.metrics.cleanupRuns + 1,
      lastCleanup: new Date().toISOString()
    };

    console.log(`✅ Cleared ${cleared} cache entries`);
    return cleared;
  }

  // Cache maintenance
  async performMaintenance() {
    console.log('🔧 Performing cache maintenance...');

    const startTime = Date.now();
    let cleanedSize = 0;
    let cleanedEntries = 0;

    try {
      // Clean expired entries
      const now = Date.now();
      const expiredKeys = [];

      // Check file caches
      for (const [key, entry] of this.cacheIndex.files) {
        const entryAge = now - new Date(entry.timestamp).getTime();
        if (entryAge > this.maxCacheAge) {
          expiredKeys.push({ type: 'files', key, path: entry.cachePath });
        }
      }

      // Check dependency caches
      for (const [key, entry] of this.cacheIndex.dependencies) {
        const entryAge = now - new Date(entry.timestamp).getTime();
        if (entryAge > this.maxCacheAge) {
          expiredKeys.push({ type: 'dependencies', key, path: entry.cachePath });
        }
      }

      // Remove expired entries
      for (const { type, key, path } of expiredKeys) {
        try {
          const stats = statSync(path);
          cleanedSize += stats.size;
          unlinkSync(path);
          this.cacheIndex[type].delete(key);
          cleanedEntries++;
        } catch (error) {
          // File might already be gone
        }
      }

      // Check cache size and clean if necessary
      const currentSize = await this.calculateCacheSize();
      if (currentSize > this.maxCacheSize) {
        const sizeCleanup = await this.cleanupBySize(currentSize - this.maxCacheSize);
        cleanedSize += sizeCleanup.size;
        cleanedEntries += sizeCleanup.entries;
      }

      // Update metrics
      this.metrics.cleanupRuns++;
      this.metrics.lastCleanup = new Date().toISOString();
      this.metrics.cacheSize = await this.calculateCacheSize();
      this.metrics.cacheEntries = this.getTotalCacheEntries();

      // Save updated index
      this.saveCacheIndex();

      const duration = Date.now() - startTime;
      console.log(`✅ Cache maintenance completed in ${duration}ms`);
      console.log(`   Cleaned entries: ${cleanedEntries}`);
      console.log(`   Cleaned size: ${(cleanedSize / 1024 / 1024).toFixed(2)}MB`);

      return {
        duration,
        cleanedEntries,
        cleanedSize,
        currentSize: this.metrics.cacheSize,
        currentEntries: this.metrics.cacheEntries
      };

    } catch (error) {
      console.error('❌ Cache maintenance failed:', error.message);
      throw error;
    }
  }

  async cleanupBySize(targetSize) {
    console.log(`🗑️  Cleaning cache by size: ${(targetSize / 1024 / 1024).toFixed(2)}MB`);

    let cleanedSize = 0;
    let cleanedEntries = 0;

    // Collect all cache entries with their access info
    const allEntries = [];

    for (const entry of this.cacheIndex.files.values()) {
      try {
        const stats = statSync(entry.cachePath);
        allEntries.push({
          type: 'files',
          key: entry.key,
          path: entry.cachePath,
          size: stats.size,
          lastAccessed: stats.atime.getTime(),
          created: new Date(entry.timestamp).getTime()
        });
      } catch {}
    }

    for (const entry of this.cacheIndex.dependencies.values()) {
      try {
        const stats = statSync(entry.cachePath);
        allEntries.push({
          type: 'dependencies',
          key: entry.key,
          path: entry.cachePath,
          size: stats.size,
          lastAccessed: stats.atime.getTime(),
          created: new Date(entry.timestamp).getTime()
        });
      } catch {}
    }

    // Sort by last accessed time (oldest first)
    allEntries.sort((a, b) => a.lastAccessed - b.lastAccessed);

    // Remove entries until target size is reached
    for (const entry of allEntries) {
      if (cleanedSize >= targetSize) break;

      try {
        unlinkSync(entry.path);
        this.cacheIndex[entry.type].delete(entry.key);
        cleanedSize += entry.size;
        cleanedEntries++;
      } catch (error) {
        // File might already be gone
      }
    }

    return { size: cleanedSize, entries: cleanedEntries };
  }

  async calculateCacheSize() {
    let totalSize = 0;

    try {
      for (const cacheDir of Object.values(this.cacheDirs)) {
        if (existsSync(cacheDir)) {
          const result = execSync(`du -sb "${cacheDir}"`, { encoding: 'utf8' });
          totalSize += parseInt(result.split('\t')[0]);
        }
      }
    } catch (error) {
      console.warn('⚠️  Could not calculate cache size:', error.message);
    }

    return totalSize;
  }

  getTotalCacheEntries() {
    return this.cacheIndex.files.size +
           this.cacheIndex.dependencies.size +
           this.cacheIndex.metadata.size +
           this.cacheIndex.buildInfo.size;
  }

  // Analytics and reporting
  generateCacheReport() {
    const hitRate = this.metrics.cacheHits + this.metrics.cacheMisses > 0 ?
      (this.metrics.cacheHits / (this.metrics.cacheHits + this.metrics.cacheMisses) * 100).toFixed(2) : 0;

    return {
      timestamp: new Date().toISOString(),
      performance: {
        hitRate: `${hitRate}%`,
        cacheHits: this.metrics.cacheHits,
        cacheMisses: this.metrics.cacheMisses,
        totalRequests: this.metrics.cacheHits + this.metrics.cacheMisses
      },
      storage: {
        totalSize: this.metrics.cacheSize,
        totalSizeMB: (this.metrics.cacheSize / 1024 / 1024).toFixed(2),
        maxCacheSizeMB: (this.maxCacheSize / 1024 / 1024).toFixed(2),
        utilizationRate: this.maxCacheSize > 0 ?
          (this.metrics.cacheSize / this.maxCacheSize * 100).toFixed(2) : 0
      },
      entries: {
        total: this.metrics.cacheEntries,
        files: this.cacheIndex.files.size,
        dependencies: this.cacheIndex.dependencies.size,
        metadata: this.cacheIndex.metadata.size,
        buildInfo: this.cacheIndex.buildInfo.size
      },
      maintenance: {
        cleanupRuns: this.metrics.cleanupRuns,
        lastCleanup: this.metrics.lastCleanup,
        maxCacheAgeHours: this.maxCacheAge / (1000 * 60 * 60)
      },
      configuration: {
        compressionEnabled: this.compressionEnabled,
        verificationEnabled: this.verificationEnabled,
        cacheRoot: this.cacheRoot
      }
    };
  }

  printCacheStatus() {
    const report = this.generateCacheReport();

    console.log('\n📊 Build Cache Status:');
    console.log(`   Hit Rate: ${report.performance.hitRate}`);
    console.log(`   Total Requests: ${report.performance.totalRequests}`);
    console.log(`   Cache Size: ${report.storage.totalSizeMB}MB / ${report.storage.maxCacheSizeMB}MB (${report.storage.utilizationRate}%)`);
    console.log(`   Total Entries: ${report.entries.total}`);
    console.log(`   Files Cached: ${report.entries.files}`);
    console.log(`   Dependencies Cached: ${report.entries.dependencies}`);
    console.log(`   Cleanup Runs: ${report.maintenance.cleanupRuns}`);
    console.log(`   Last Cleanup: ${report.maintenance.lastCleanup || 'Never'}`);
  }

  // Advanced features
  async optimizeCache() {
    console.log('⚡ Optimizing cache...');

    const startTime = Date.now();

    try {
      // Perform maintenance
      const maintenanceResult = await this.performMaintenance();

      // Analyze cache patterns
      const analysis = this.analyzeCachePatterns();

      // Suggest optimizations
      const suggestions = this.generateOptimizationSuggestions(analysis);

      const duration = Date.now() - startTime;
      console.log(`✅ Cache optimization completed in ${duration}ms`);

      return {
        duration,
        maintenance: maintenanceResult,
        analysis,
        suggestions
      };

    } catch (error) {
      console.error('❌ Cache optimization failed:', error.message);
      throw error;
    }
  }

  analyzeCachePatterns() {
    const patterns = {
      fileTypes: {},
      cacheAge: { newest: null, oldest: null, average: 0 },
      sizeDistribution: { small: 0, medium: 0, large: 0 },
      accessPatterns: { frequent: 0, occasional: 0, rare: 0 }
    };

    const now = Date.now();
    let totalAge = 0;
    let ageCount = 0;

    // Analyze file caches
    for (const entry of this.cacheIndex.files.values()) {
      // File type analysis
      const ext = entry.originalPath.split('.').pop().toLowerCase();
      patterns.fileTypes[ext] = (patterns.fileTypes[ext] || 0) + 1;

      // Age analysis
      const age = now - new Date(entry.timestamp).getTime();
      totalAge += age;
      ageCount++;

      if (!patterns.cacheAge.oldest || age > patterns.cacheAge.oldest.age) {
        patterns.cacheAge.oldest = { file: entry.originalPath, age };
      }
      if (!patterns.cacheAge.newest || age < patterns.cacheAge.newest.age) {
        patterns.cacheAge.newest = { file: entry.originalPath, age };
      }

      // Size analysis
      try {
        const stats = statSync(entry.cachePath);
        if (stats.size < 1024 * 10) { // < 10KB
          patterns.sizeDistribution.small++;
        } else if (stats.size < 1024 * 1024) { // < 1MB
          patterns.sizeDistribution.medium++;
        } else {
          patterns.sizeDistribution.large++;
        }

        // Access pattern analysis
        const daysSinceAccess = (now - stats.atime.getTime()) / (1000 * 60 * 60 * 24);
        if (daysSinceAccess < 1) {
          patterns.accessPatterns.frequent++;
        } else if (daysSinceAccess < 7) {
          patterns.accessPatterns.occasional++;
        } else {
          patterns.accessPatterns.rare++;
        }
      } catch {}
    }

    if (ageCount > 0) {
      patterns.cacheAge.average = totalAge / ageCount;
    }

    return patterns;
  }

  generateOptimizationSuggestions(analysis) {
    const suggestions = [];

    // Cache size suggestions
    if (analysis.sizeDistribution.large > analysis.sizeDistribution.small) {
      suggestions.push({
        type: 'size',
        priority: 'medium',
        suggestion: 'Consider implementing compression for large cached files',
        impact: 'Reduce cache size by 30-50%'
      });
    }

    // Cache age suggestions
    if (analysis.cacheAge.average > this.maxCacheAge * 0.7) {
      suggestions.push({
        type: 'age',
        priority: 'low',
        suggestion: 'Consider reducing cache retention period',
        impact: 'Reduce cache size and improve freshness'
      });
    }

    // Access pattern suggestions
    if (analysis.accessPatterns.rare > analysis.accessPatterns.frequent) {
      suggestions.push({
        type: 'access',
        priority: 'high',
        suggestion: 'Many cached files are rarely accessed - consider more aggressive cleanup',
        impact: 'Improve cache efficiency and reduce storage'
      });
    }

    // File type suggestions
    const popularTypes = Object.entries(analysis.fileTypes)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 3);

    if (popularTypes.length > 0) {
      suggestions.push({
        type: 'content',
        priority: 'low',
        suggestion: `Most cached file types: ${popularTypes.map(([type]) => type).join(', ')}`,
        impact: 'Cache optimization focus areas'
      });
    }

    return suggestions;
  }

  async exportCache(exportPath) {
    console.log(`📤 Exporting cache to: ${exportPath}`);

    try {
      const exportData = {
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        cacheIndex: {
          files: Object.fromEntries(this.cacheIndex.files),
          dependencies: Object.fromEntries(this.cacheIndex.dependencies),
          metadata: Object.fromEntries(this.cacheIndex.metadata),
          buildInfo: Object.fromEntries(this.cacheIndex.buildInfo)
        },
        metrics: this.metrics,
        configuration: {
          maxCacheSize: this.maxCacheSize,
          maxCacheAge: this.maxCacheAge,
          compressionEnabled: this.compressionEnabled,
          verificationEnabled: this.verificationEnabled
        }
      };

      writeFileSync(exportPath, JSON.stringify(exportData, null, 2));
      console.log(`✅ Cache exported to: ${exportPath}`);

      return exportPath;

    } catch (error) {
      console.error('❌ Cache export failed:', error.message);
      throw error;
    }
  }

  async importCache(importPath) {
    console.log(`📥 Importing cache from: ${importPath}`);

    try {
      const importData = JSON.parse(readFileSync(importPath, 'utf8'));

      // Validate import data
      if (!importData.version || !importData.cacheIndex) {
        throw new Error('Invalid cache export format');
      }

      // Clear existing cache
      this.clearCache();

      // Import cache index
      Object.entries(importData.cacheIndex.files || {}).forEach(([key, value]) => {
        this.cacheIndex.files.set(key, value);
      });
      Object.entries(importData.cacheIndex.dependencies || {}).forEach(([key, value]) => {
        this.cacheIndex.dependencies.set(key, value);
      });
      Object.entries(importData.cacheIndex.metadata || {}).forEach(([key, value]) => {
        this.cacheIndex.metadata.set(key, value);
      });
      Object.entries(importData.cacheIndex.buildInfo || {}).forEach(([key, value]) => {
        this.cacheIndex.buildInfo.set(key, value);
      });

      // Import metrics if available
      if (importData.metrics) {
        this.metrics = { ...this.metrics, ...importData.metrics };
      }

      // Save imported index
      this.saveCacheIndex();

      console.log(`✅ Cache imported from: ${importPath}`);
      console.log(`   Imported entries: ${this.getTotalCacheEntries()}`);

      return {
        entriesImported: this.getTotalCacheEntries(),
        timestamp: importData.timestamp
      };

    } catch (error) {
      console.error('❌ Cache import failed:', error.message);
      throw error;
    }
  }
}

// CLI interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const command = process.argv[2];
  const options = {
    projectRoot: process.cwd(),
    maxCacheSize: process.env.CACHE_MAX_SIZE ? parseInt(process.env.CACHE_MAX_SIZE) : undefined,
    maxCacheAge: process.env.CACHE_MAX_AGE ? parseInt(process.env.CACHE_MAX_AGE) : undefined
  };

  const cacheManager = new BuildCacheManager(options);

  switch (command) {
    case 'status':
      cacheManager.printCacheStatus();
      break;

    case 'clear':
      cacheManager.clearCache()
        .then(() => console.log('✅ Cache cleared'))
        .catch(error => console.error('❌ Cache clear failed:', error));
      break;

    case 'maintenance':
      cacheManager.performMaintenance()
        .then(result => console.log('✅ Maintenance completed:', result))
        .catch(error => console.error('❌ Maintenance failed:', error));
      break;

    case 'optimize':
      cacheManager.optimizeCache()
        .then(result => console.log('✅ Optimization completed:', result))
        .catch(error => console.error('❌ Optimization failed:', error));
      break;

    case 'report':
      const report = cacheManager.generateCacheReport();
      console.log(JSON.stringify(report, null, 2));
      break;

    case 'export':
      const exportPath = process.argv[3] || 'cache-export.json';
      cacheManager.exportCache(exportPath)
        .then(() => console.log('✅ Export completed'))
        .catch(error => console.error('❌ Export failed:', error));
      break;

    case 'import':
      const importPath = process.argv[3];
      if (!importPath) {
        console.error('❌ Import path required');
        process.exit(1);
      }
      cacheManager.importCache(importPath)
        .then(result => console.log('✅ Import completed:', result))
        .catch(error => console.error('❌ Import failed:', error));
      break;

    default:
      console.log('Available commands:');
      console.log('  status     - Show cache status');
      console.log('  clear      - Clear all cache');
      console.log('  maintenance - Perform cache maintenance');
      console.log('  optimize   - Optimize cache');
      console.log('  report     - Generate cache report');
      console.log('  export     - Export cache to file');
      console.log('  import     - Import cache from file');
  }
}

export { BuildCacheManager };