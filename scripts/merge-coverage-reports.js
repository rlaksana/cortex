#!/usr/bin/env node

/**
 * Merge Coverage Reports
 * Merges multiple coverage reports into a single comprehensive report
 */

import fs from 'fs/promises';
import path from 'path';
import { glob } from 'glob';

class CoverageReportMerger {
  constructor() {
    this.projectRoot = process.cwd();
    this.coverageDir = path.join(this.projectRoot, 'coverage');
    this.reportsDir = path.join(this.coverageDir, 'reports');
  }

  async init() {
    console.log('🔀 Merging coverage reports...');
    await this.ensureDirectories();
    await this.mergeReports();
    console.log('✅ Coverage reports merged successfully!');
  }

  async ensureDirectories() {
    await fs.mkdir(this.reportsDir, { recursive: true });
    await fs.mkdir(this.coverageDir, { recursive: true });
  }

  async mergeReports() {
    try {
      // Find all coverage summary files
      const coverageFiles = await this.findCoverageFiles();

      if (coverageFiles.length === 0) {
        console.warn('⚠️  No coverage files found to merge');
        return;
      }

      console.log(`📁 Found ${coverageFiles.length} coverage files to merge`);

      let mergedSummary = null;
      const mergedJson = {};

      for (const file of coverageFiles) {
        try {
          const data = JSON.parse(await fs.readFile(file, 'utf8'));

          // Merge summary
          if (data.total) {
            if (!mergedSummary) {
              mergedSummary = JSON.parse(JSON.stringify(data));
            } else {
              mergedSummary = this.mergeSummaries(mergedSummary, data);
            }
          }

          // Merge detailed JSON
          Object.assign(mergedJson, data);

        } catch (error) {
          console.warn(`⚠️  Could not process ${file}:`, error.message);
        }
      }

      if (mergedSummary) {
        // Write merged summary
        await fs.writeFile(
          path.join(this.coverageDir, 'coverage-summary.json'),
          JSON.stringify(mergedSummary, null, 2)
        );

        // Write merged detailed report
        await fs.writeFile(
          path.join(this.coverageDir, 'coverage.json'),
          JSON.stringify(mergedJson, null, 2)
        );

        // Generate LCOV format
        await this.generateLcovReport(mergedJson);

        console.log('📊 Merged Coverage Summary:');
        if (mergedSummary.total) {
          console.log(`  Lines: ${mergedSummary.total.lines.pct}%`);
          console.log(`  Functions: ${mergedSummary.total.functions.pct}%`);
          console.log(`  Branches: ${mergedSummary.total.branches.pct}%`);
          console.log(`  Statements: ${mergedSummary.total.statements.pct}%`);
        }
      }

    } catch (error) {
      console.error('❌ Error merging coverage reports:', error);
      throw error;
    }
  }

  async findCoverageFiles() {
    const patterns = [
      'coverage/coverage-summary.json',
      'coverage/**/coverage-summary.json',
      'coverage/*/coverage-summary.json',
      'test-results/**/coverage-summary.json',
      'coverage/reports/**/coverage-summary.json'
    ];

    const files = [];
    for (const pattern of patterns) {
      try {
        const matches = await glob(pattern, { cwd: this.projectRoot });
        files.push(...matches.map(match => path.join(this.projectRoot, match)));
      } catch (error) {
        console.warn(`⚠️  Could not glob pattern ${pattern}:`, error.message);
      }
    }

    // Remove duplicates and return
    return [...new Set(files)];
  }

  mergeSummaries(summary1, summary2) {
    const merged = JSON.parse(JSON.stringify(summary1));

    // Merge total coverage
    if (summary2.total) {
      if (!merged.total) {
        merged.total = {};
      }

      for (const metric of ['lines', 'functions', 'branches', 'statements']) {
        if (summary2.total[metric]) {
          if (!merged.total[metric]) {
            merged.total[metric] = { total: 0, covered: 0, pct: 0 };
          }

          // Simple addition of totals and covered
          merged.total[metric].total += summary2.total[metric].total || 0;
          merged.total[metric].covered += summary2.total[metric].covered || 0;

          // Recalculate percentage
          if (merged.total[metric].total > 0) {
            merged.total[metric].pct = Math.round(
              (merged.total[metric].covered / merged.total[metric].total) * 100
            );
          }
        }
      }
    }

    return merged;
  }

  async generateLcovReport(coverageData) {
    try {
      let lcovContent = 'TN:\n'; // Test name

      for (const [filePath, fileData] of Object.entries(coverageData)) {
        if (!filePath.endsWith('.ts') && !filePath.endsWith('.js')) continue;
        if (!fileData.s) continue; // Skip files without statement coverage

        lcovContent += `SF:${filePath}\n`;

        // Add line coverage
        if (fileData.l) {
          for (const [lineNum, hitCount] of Object.entries(fileData.l)) {
            lcovContent += `DA:${lineNum},${hitCount}\n`;
          }
        }

        // Add function coverage
        if (fileData.f) {
          for (const [funcName, funcData] of Object.entries(fileData.f)) {
            // Extract line number from function name if possible
            const lineMatch = funcName.match(/:(\\d+):?\\d*$/);
            const lineNum = lineMatch ? lineMatch[1] : '0';
            lcovContent += `FN:${lineNum},${funcName}\n`;
          }

          for (const [funcName, hitCount] of Object.entries(fileData.f)) {
            lcovContent += `FNDA:${hitCount},${funcName}\n`;
          }
          lcovContent += `FNF:${Object.keys(fileData.f).length}\n`;
          lcovContent += `FNH:${Object.values(fileData.f).filter(h => h > 0).length}\n`;
        }

        // Add branch coverage
        if (fileData.b) {
          let branchCount = 0;
          let branchHits = 0;
          for (const branches of Object.values(fileData.b)) {
            branchCount += branches.length;
            branchHits += branches.filter(h => h > 0).length;
          }
          lcovContent += `BRF:${branchCount}\n`;
          lcovContent += `BRH:${branchHits}\n`;
        }

        // End of file
        const linesFound = fileData.l ? Object.keys(fileData.l).length : 0;
        const linesHit = fileData.l ? Object.values(fileData.l).filter(h => h > 0).length : 0;
        lcovContent += `LF:${linesFound}\n`;
        lcovContent += `LH:${linesHit}\n`;
        lcovContent += `end_of_record\n`;
      }

      await fs.writeFile(
        path.join(this.coverageDir, 'lcov.info'),
        lcovContent
      );

    } catch (error) {
      console.warn('⚠️  Could not generate LCOV report:', error.message);
    }
  }
}

// Run if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const merger = new CoverageReportMerger();
  merger.init().catch(console.error);
}

export default CoverageReportMerger;