#!/usr/bin/env node

/**
 * Comprehensive Artifact Collection and Reporting System
 *
 * Collects, organizes, and packages all CI/CD artifacts for:
 * - Audit and compliance
 * - Release management
 * - Historical analysis
 * - Debugging and troubleshooting
 */

import { readFileSync, existsSync, mkdirSync, writeFileSync, copyFileSync } from 'fs';
import { join, dirname, basename } from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

// Configuration
const CONFIG = {
  // Artifact source directories
  SOURCE_DIRS: {
    build: 'dist',
    coverage: 'coverage',
    testResults: 'test-results',
    benchmarks: 'artifacts/bench',
    security: 'security-reports',
    readinessGates: 'artifacts/readiness-gates',
    releaseGates: 'artifacts/release-gates',
    performanceGates: 'artifacts/performance-gates',
    qualityGates: 'artifacts/quality-gates',
    alertingMonitoring: 'artifacts/alerting-monitoring',
    logs: 'logs'
  },

  // File patterns to collect
  FILE_PATTERNS: {
    testResults: ['**/*.json', '**/*.xml', '**/*.junit'],
    coverage: ['**/*.json', '**/*.html', '**/*.lcov'],
    benchmarks: ['**/*.json', '**/*.html', '**/*.csv'],
    security: ['**/*.json', '**/*.html', '**/*.txt'],
    reports: ['**/*.json', '**/*.html', '**/*.md'],
    logs: ['**/*.log', '**/*.txt'],
    artifacts: ['**/*.tar.gz', '**/*.zip']
  },

  // Output configuration
  OUTPUT_DIR: join(projectRoot, 'artifacts', 'collected'),
  ARCHIVE_DIR: join(projectRoot, 'artifacts', 'archives'),
  REPORTS_DIR: join(projectRoot, 'artifacts', 'reports'),

  // Artifact retention
  RETENTION: {
    days: 90,
    maxArchives: 50
  }
};

// Colors for console output
const COLORS = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m'
};

function log(message, color = COLORS.reset) {
  console.log(`${color}${message}${COLORS.reset}`);
}

function logSuccess(message) {
  log(`✅ ${message}`, COLORS.green);
}

function logInfo(message) {
  log(`ℹ️  ${message}`, COLORS.blue);
}

function logHeader(message) {
  log(`\n${COLORS.bold}${message}${COLORS.reset}`);
  log('='.repeat(message.length), COLORS.cyan);
}

/**
 * Get current build metadata
 */
function getBuildMetadata() {
  try {
    const packageJson = JSON.parse(readFileSync(join(projectRoot, 'package.json'), 'utf8'));

    let gitCommit = 'unknown';
    let gitBranch = 'unknown';
    let gitTag = 'unknown';

    try {
      gitCommit = execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim();
      gitBranch = execSync('git rev-parse --abbrev-ref HEAD', { encoding: 'utf8' }).trim();
      gitTag = execSync('git describe --tags --exact-match 2>/dev/null || echo "no-tag"', { encoding: 'utf8' }).trim();
    } catch (error) {
      // Git commands failed, use defaults
    }

    return {
      version: packageJson.version,
      name: packageJson.name,
      description: packageJson.description,
      buildTime: new Date().toISOString(),
      buildNumber: process.env.BUILD_NUMBER || process.env.GITHUB_RUN_NUMBER || 'local',
      gitCommit,
      gitBranch,
      gitTag,
      nodeVersion: process.version,
      platform: process.platform,
      environment: process.env.NODE_ENV || 'development',
      ci: process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true'
    };
  } catch (error) {
    return {
      version: 'unknown',
      name: 'cortex-memory-mcp',
      buildTime: new Date().toISOString(),
      buildNumber: 'local',
      gitCommit: 'unknown',
      gitBranch: 'unknown',
      gitTag: 'unknown',
      nodeVersion: process.version,
      platform: process.platform,
      environment: 'development',
      ci: false
    };
  }
}

/**
 * Collect artifacts from source directories
 */
function collectArtifacts(metadata) {
  logHeader('📦 Collecting Artifacts');

  const artifacts = {
    metadata,
    collected: [],
    summaries: {},
    totalSize: 0,
    totalFiles: 0
  };

  // Ensure output directory exists
  mkdirSync(CONFIG.OUTPUT_DIR, { recursive: true });
  mkdirSync(CONFIG.ARCHIVE_DIR, { recursive: true });

  const artifactId = `${metadata.name}-${metadata.version}-${metadata.buildNumber}`;
  const artifactDir = join(CONFIG.OUTPUT_DIR, artifactId);
  mkdirSync(artifactDir, { recursive: true });

  Object.entries(CONFIG.SOURCE_DIRS).forEach(([category, sourceDir]) => {
    const fullSourceDir = join(projectRoot, sourceDir);

    if (existsSync(fullSourceDir)) {
      const categoryResult = collectCategoryArtifacts(category, fullSourceDir, artifactDir);
      artifacts.collected.push(categoryResult);
      artifacts.summaries[category] = categoryResult.summary;
      artifacts.totalSize += categoryResult.summary.totalSize;
      artifacts.totalFiles += categoryResult.summary.fileCount;

      logInfo(`  ${category}: ${categoryResult.summary.fileCount} files, ${(categoryResult.summary.totalSize / 1024 / 1024).toFixed(1)}MB`);
    } else {
      artifacts.summaries[category] = {
        exists: false,
        fileCount: 0,
        totalSize: 0,
        files: []
      };
      logInfo(`  ${category}: Not found`);
    }
  });

  // Create artifact manifest
  const manifest = {
    artifactId,
    metadata,
    summary: artifacts.summaries,
    collection: {
      totalFiles: artifacts.totalFiles,
      totalSize: artifacts.totalSize,
      categories: Object.keys(artifacts.summaries).length,
      collectedAt: new Date().toISOString()
    }
  };

  writeFileSync(join(artifactDir, 'artifact-manifest.json'), JSON.stringify(manifest, null, 2));
  writeFileSync(join(artifactDir, 'build-metadata.json'), JSON.stringify(metadata, null, 2));

  logSuccess(`Artifacts collected to: ${artifactDir}`);
  return { artifacts, manifest, artifactDir };
}

/**
 * Collect artifacts for a specific category
 */
function collectCategoryArtifacts(category, sourceDir, targetDir) {
  const categoryDir = join(targetDir, category);
  mkdirSync(categoryDir, { recursive: true });

  const summary = {
    exists: true,
    fileCount: 0,
    totalSize: 0,
    files: []
  };

  try {
    // Get list of files in source directory
    const files = execSync(`find "${sourceDir}" -type f | head -100`, { encoding: 'utf8' })
      .trim()
      .split('\n')
      .filter(file => file.length > 0);

    files.forEach(file => {
      try {
        const relativePath = file.replace(sourceDir + '/', '');
        const targetFile = join(categoryDir, relativePath);
        const targetFileDir = dirname(targetFile);

        // Ensure target directory exists
        mkdirSync(targetFileDir, { recursive: true });

        // Copy file
        copyFileSync(file, targetFile);

        // Get file stats
        const stats = require('fs').statSync(file);

        summary.files.push({
          originalPath: file,
          relativePath,
          size: stats.size,
          modified: stats.mtime.toISOString()
        });

        summary.fileCount++;
        summary.totalSize += stats.size;

      } catch (error) {
        logInfo(`    Warning: Failed to copy ${file}: ${error.message}`);
      }
    });

  } catch (error) {
    logInfo(`  Warning: Could not list files in ${sourceDir}: ${error.message}`);
  }

  return {
    category,
    sourceDir,
    targetDir: categoryDir,
    summary
  };
}

/**
 * Generate comprehensive collection report
 */
function generateCollectionReport(artifacts, manifest, artifactDir) {
  logHeader('📋 Generating Collection Report');

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const reportFile = join(CONFIG.REPORTS_DIR, `artifact-collection-report-${timestamp}.json`);
  const htmlReportFile = join(CONFIG.REPORTS_DIR, `artifact-collection-report-${timestamp}.html`);

  mkdirSync(CONFIG.REPORTS_DIR, { recursive: true });

  const report = {
    metadata: manifest.metadata,
    collection: manifest.collection,
    categories: artifacts.collected,
    summary: {
      totalCategories: Object.keys(artifacts.summaries).length,
      totalFiles: artifacts.totalFiles,
      totalSize: artifacts.totalSize,
      avgFileSize: artifacts.totalFiles > 0 ? artifacts.totalSize / artifacts.totalFiles : 0,
      largestCategory: Object.entries(artifacts.summaries)
        .filter(([_, summary]) => summary.exists)
        .sort(([_, a], [__, b]) => b.totalSize - a.totalSize)[0]?.[0] || 'none'
    },
    artifacts: {
      artifactId: manifest.artifactId,
      location: artifactDir,
      manifest: join(artifactDir, 'artifact-manifest.json'),
      buildMetadata: join(artifactDir, 'build-metadata.json')
    },
    recommendations: generateCollectionRecommendations(artifacts)
  };

  // Write JSON report
  writeFileSync(reportFile, JSON.stringify(report, null, 2));
  logSuccess(`JSON report generated: ${reportFile}`);

  // Write HTML report
  const htmlReport = generateHTMLCollectionReport(report);
  writeFileSync(htmlReportFile, htmlReport);
  logSuccess(`HTML report generated: ${htmlReportFile}`);

  return report;
}

/**
 * Generate HTML collection report
 */
function generateHTMLCollectionReport(report) {
  const { metadata, collection, summary, categories } = report;

  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Artifact Collection Report - ${metadata.version}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 40px; padding-bottom: 20px; border-bottom: 2px solid #e0e0e0; }
        .metadata { background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .metric-card { padding: 20px; border-radius: 8px; background: #f5f5f5; text-align: center; }
        .metric-value { font-size: 2em; font-weight: bold; color: #1976d2; }
        .categories-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 30px 0; }
        .category-card { padding: 20px; border-radius: 8px; border-left: 4px solid #ddd; background: #f8f9fa; }
        .category-present { border-left-color: #4CAF50; }
        .category-missing { border-left-color: #f44336; background: #ffebee; }
        .file-list { max-height: 200px; overflow-y: auto; margin: 10px 0; font-size: 0.9em; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📦 Artifact Collection Report</h1>
            <p>${metadata.name} v${metadata.version} | Build: ${metadata.buildNumber}</p>
            <p>Generated: ${new Date(metadata.buildTime).toLocaleString()}</p>
        </div>

        <div class="metadata">
            <h3>🔧 Build Metadata</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                <div><strong>Version:</strong> ${metadata.version}</div>
                <div><strong>Build:</strong> ${metadata.buildNumber}</div>
                <div><strong>Commit:</strong> ${metadata.gitCommit.substring(0, 8)}</div>
                <div><strong>Branch:</strong> ${metadata.gitBranch}</div>
                <div><strong>Node:</strong> ${metadata.nodeVersion}</div>
                <div><strong>Platform:</strong> ${metadata.platform}</div>
                <div><strong>Environment:</strong> ${metadata.environment}</div>
                <div><strong>CI:</strong> ${metadata.ci ? 'Yes' : 'No'}</div>
            </div>
        </div>

        <div class="summary-grid">
            <div class="metric-card">
                <div class="metric-value">${summary.totalFiles}</div>
                <div>Total Files</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${(summary.totalSize / 1024 / 1024).toFixed(1)}MB</div>
                <div>Total Size</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${summary.totalCategories}</div>
                <div>Categories</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${(summary.avgFileSize / 1024).toFixed(1)}KB</div>
                <div>Avg File Size</div>
            </div>
        </div>

        <div class="categories-grid">
            ${categories.map(category => `
            <div class="category-card ${category.summary.exists ? 'category-present' : 'category-missing'}">
                <h3>${category.category.charAt(0).toUpperCase() + category.category.slice(1)}</h3>
                ${category.summary.exists ? `
                <p><strong>Files:</strong> ${category.summary.fileCount}</p>
                <p><strong>Size:</strong> ${(category.summary.totalSize / 1024 / 1024).toFixed(1)}MB</p>
                ${category.summary.files.length > 0 ? `
                <div class="file-list">
                    ${category.summary.files.slice(0, 10).map(file =>
                      `<div style="padding: 2px 0; border-bottom: 1px solid #eee;">
                        📄 ${file.relativePath} (${(file.size / 1024).toFixed(1)}KB)
                      </div>`
                    ).join('')}
                    ${category.summary.files.length > 10 ? `<div style="text-align: center; color: #666; padding: 5px;">... and ${category.summary.files.length - 10} more files</div>` : ''}
                </div>
                ` : ''}
                ` : `
                <p style="color: #f44336;">❌ Not found</p>
                `}
            </div>
            `).join('')}
        </div>

        <div class="footer">
            <p>Generated by Cortex Memory MCP Artifact Collector</p>
            <p>Artifact ID: ${report.artifacts.artifactId}</p>
            <p>Location: ${report.artifacts.location}</p>
        </div>
    </div>
</body>
</html>`;
}

/**
 * Generate collection recommendations
 */
function generateCollectionRecommendations(artifacts) {
  const recommendations = [];
  const { summaries } = artifacts;

  // Check for missing critical artifacts
  const criticalCategories = ['coverage', 'testResults', 'build'];
  criticalCategories.forEach(category => {
    if (!summaries[category]?.exists) {
      recommendations.push({
        priority: 'high',
        category: 'missing-artifacts',
        issue: `Critical artifact category missing: ${category}`,
        action: `Ensure ${category} are generated before collection`
      });
    }
  });

  // Check for empty categories
  Object.entries(summaries).forEach(([category, summary]) => {
    if (summary.exists && summary.fileCount === 0) {
      recommendations.push({
        priority: 'medium',
        category: 'empty-artifacts',
        issue: `Artifact category exists but empty: ${category}`,
        action: `Verify ${category} generation process`
      });
    }
  });

  // Check total size
  const totalSizeMB = artifacts.totalSize / 1024 / 1024;
  if (totalSizeMB > 500) {
    recommendations.push({
      priority: 'medium',
      category: 'size-optimization',
      issue: `Large artifact collection: ${totalSizeMB.toFixed(1)}MB`,
      action: 'Consider cleaning up large files or implementing compression'
    });
  }

  // Check for coverage artifacts
  if (summaries.coverage?.exists && summaries.coverage.fileCount < 3) {
    recommendations.push({
      priority: 'low',
      category: 'coverage-completeness',
      issue: 'Limited coverage artifacts detected',
      action: 'Ensure HTML, JSON, and LCOV coverage reports are generated'
    });
  }

  return recommendations;
}

/**
 * Create compressed archive
 */
function createArchive(artifactDir, metadata) {
  logHeader('📦 Creating Archive');

  const archiveName = `${metadata.name}-${metadata.version}-${metadata.buildNumber}.tar.gz`;
  const archivePath = join(CONFIG.ARCHIVE_DIR, archiveName);

  try {
    // Create compressed archive
    execSync(`tar -czf "${archivePath}" -C "$(dirname "${artifactDir}")" "$(basename "${artifactDir}")"`, {
      cwd: projectRoot,
      stdio: 'pipe'
    });

    const archiveSize = require('fs').statSync(archivePath).size;
    const archiveSizeMB = archiveSize / 1024 / 1024;

    logSuccess(`Archive created: ${archivePath} (${archiveSizeMB.toFixed(1)}MB)`);

    return {
      archivePath,
      archiveName,
      size: archiveSize,
      sizeMB: archiveSizeMB
    };

  } catch (error) {
    logError(`Failed to create archive: ${error.message}`);
    return null;
  }
}

/**
 * Clean up old artifacts
 */
function cleanupOldArtifacts() {
  logHeader('🧹 Cleaning Up Old Artifacts');

  try {
    // Clean old archives
    const archives = execSync(`find "${CONFIG.ARCHIVE_DIR}" -name "*.tar.gz" -type f -printf "%T@ %p\\n" | sort -n | head -n -${CONFIG.RETENTION.maxArchives}`, { encoding: 'utf8' })
      .trim()
      .split('\n')
      .filter(line => line.length > 0)
      .map(line => line.split(' ')[1]);

    if (archives.length > 0) {
      archives.forEach(archive => {
        try {
          require('fs').unlinkSync(archive);
          logInfo(`  Removed old archive: ${basename(archive)}`);
        } catch (error) {
          logInfo(`  Warning: Could not remove ${basename(archive)}: ${error.message}`);
        }
      });
    }

    // Clean old collected artifacts (older than retention period)
    const oldArtifacts = execSync(`find "${CONFIG.OUTPUT_DIR}" -type d -mtime +${Math.floor(CONFIG.RETENTION.days / 7)} -printf "%p\\n"`, { encoding: 'utf8' })
      .trim()
      .split('\n')
      .filter(line => line.length > 0 && line !== CONFIG.OUTPUT_DIR);

    if (oldArtifacts.length > 0) {
      oldArtifacts.forEach(artifact => {
        try {
          execSync(`rm -rf "${artifact}"`, { stdio: 'pipe' });
          logInfo(`  Removed old artifact: ${basename(artifact)}`);
        } catch (error) {
          logInfo(`  Warning: Could not remove ${basename(artifact)}: ${error.message}`);
        }
      });
    }

    logSuccess('Cleanup completed');

  } catch (error) {
    logInfo(`Cleanup warning: ${error.message}`);
  }
}

/**
 * Main artifact collection function
 */
function main() {
  try {
    logHeader('🎯 Comprehensive Artifact Collection System');
    logInfo('Collecting, organizing, and packaging CI/CD artifacts...\n');

    // Get build metadata
    const metadata = getBuildMetadata();
    logInfo(`Collecting artifacts for: ${metadata.name} v${metadata.version} (build ${metadata.buildNumber})`);

    // Collect artifacts
    const { artifacts, manifest, artifactDir } = collectArtifacts(metadata);

    // Generate collection report
    const report = generateCollectionReport(artifacts, manifest, artifactDir);

    // Create compressed archive
    const archive = createArchive(artifactDir, metadata);

    // Clean up old artifacts
    cleanupOldArtifacts();

    // Final summary
    logHeader('📊 Artifact Collection Summary');
    logInfo(`Total files collected: ${artifacts.totalFiles}`);
    logInfo(`Total size: ${(artifacts.totalSize / 1024 / 1024).toFixed(1)}MB`);
    logInfo(`Categories: ${Object.keys(artifacts.summaries).length}`);
    logInfo(`Artifact ID: ${manifest.artifactId}`);
    logInfo(`Collection location: ${artifactDir}`);

    if (archive) {
      logInfo(`Archive created: ${archive.archivePath}`);
      logInfo(`Archive size: ${archive.sizeMB.toFixed(1)}MB`);
    }

    if (report.recommendations.length > 0) {
      logInfo('\n📋 Recommendations:');
      report.recommendations.forEach(rec => {
        logInfo(`  ${rec.category}: ${rec.issue}`);
      });
    }

    logSuccess('\n✅ Artifact collection completed successfully');
    logInfo(`📄 Reports available in: ${CONFIG.REPORTS_DIR}`);
    logInfo(`📦 Archives available in: ${CONFIG.ARCHIVE_DIR}`);

  } catch (error) {
    logError(`Artifact collection failed: ${error.message}`);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { collectArtifacts, generateCollectionReport, createArchive };