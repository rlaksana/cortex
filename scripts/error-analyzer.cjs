#!/usr/bin/env node

const { execSync } = require('child_process');

class TypeScriptErrorAnalyzer {
  constructor(projectRoot) {
    this.projectRoot = projectRoot;
  }

  analyze() {
    console.log('🔍 Analyzing TypeScript compilation errors...');

    // Get all TypeScript errors
    const errors = this.getTypeScriptErrors();

    // Analyze error patterns
    const analysis = {
      totalErrors: errors.length,
      errorTypes: this.categorizeErrors(errors),
      fileDistribution: this.getDistributionByFile(errors),
      highErrorFiles: this.identifyHighErrorFiles(errors),
      quickWins: this.identifyQuickWins(errors),
      complexIssues: this.identifyComplexIssues(errors)
    };

    return analysis;
  }

  getTypeScriptErrors() {
    try {
      const output = execSync('npx tsc --noEmit', {
        cwd: this.projectRoot,
        encoding: 'utf8',
        maxBuffer: 10 * 1024 * 1024 // 10MB buffer
      });

      return output
        .split('\n')
        .filter(line => line.includes('error TS'))
        .map(line => line.trim());
    } catch (error) {
      // TypeScript compilation failed, extract errors from stderr
      const errorOutput = error.stderr?.toString() || error.stdout?.toString() || '';
      return errorOutput
        .split('\n')
        .filter(line => line.includes('error TS'))
        .map(line => line.trim());
    }
  }

  categorizeErrors(errors) {
    const categories = {};

    errors.forEach(error => {
      const errorCode = this.extractErrorCode(error);
      categories[errorCode] = (categories[errorCode] || 0) + 1;
    });

    return categories;
  }

  getDistributionByFile(errors) {
    const distribution = {};

    errors.forEach(error => {
      const filePath = this.extractFilePath(error);
      if (filePath) {
        distribution[filePath] = (distribution[filePath] || 0) + 1;
      }
    });

    return distribution;
  }

  identifyHighErrorFiles(errors) {
    const fileDistribution = this.getDistributionByFile(errors);

    return Object.entries(fileDistribution)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 20)
      .map(([file, count]) => ({
        file,
        count,
        complexity: this.assessFileComplexity(file, count)
      }));
  }

  identifyQuickWins(errors) {
    const quickWinPatterns = [
      { code: 'TS2345', category: 'Type Assertion', description: 'Simple type assertion needed' },
      { code: 'TS2339', category: 'Interface Mismatch', description: 'Missing interface property' },
      { code: 'TS18046', category: 'Implicit Any', description: 'Add type annotations' },
      { code: 'TS2304', category: 'Import/Export', description: 'Missing imports' },
      { code: 'TS2305', category: 'Import/Export', description: 'Incorrect export names' },
      { code: 'TS2322', category: 'Type Assignment', description: 'Type compatibility issue' }
    ];

    const quickWins = [];

    quickWinPatterns.forEach(pattern => {
      const matchingErrors = errors.filter(error => error.includes(pattern.code));
      if (matchingErrors.length > 0) {
        const file = this.extractFilePath(matchingErrors[0]);
        quickWins.push({
          file: file || 'unknown',
          errorType: pattern.category,
          count: matchingErrors.length,
          pattern: pattern.description
        });
      }
    });

    return quickWins.sort((a, b) => b.count - a.count);
  }

  identifyComplexIssues(errors) {
    const complexPatterns = [
      { code: 'TS2416', category: 'Interface Inheritance', description: 'Base interface changes' },
      { code: 'TS2698', category: 'Generic Types', description: 'Generic type constraints' },
      { code: 'TS2769', category: 'Method Overload', description: 'Method signature mismatch' }
    ];

    const complexIssues = [];

    complexPatterns.forEach(pattern => {
      const matchingErrors = errors.filter(error => error.includes(pattern.code));
      if (matchingErrors.length > 0) {
        const file = this.extractFilePath(matchingErrors[0]);
        complexIssues.push({
          file: file || 'unknown',
          errorType: pattern.category,
          count: matchingErrors.length,
          requiresRefactor: true
        });
      }
    });

    return complexIssues.sort((a, b) => b.count - a.count);
  }

  assessFileComplexity(filePath, errorCount) {
    if (errorCount > 50) return 'high';
    if (errorCount > 20) return 'medium';
    return 'low';
  }

  extractErrorCode(error) {
    const match = error.match(/error (TS\d+)/);
    return match ? match[1] : 'UNKNOWN';
  }

  extractFilePath(error) {
    const match = error.match(/^(.+)\(/);
    return match ? match[1] : null;
  }

  generateReport(analysis) {
    console.log('\n📊 TYPESCRIPT ERROR ANALYSIS REPORT');
    console.log('=====================================\n');

    // Summary
    console.log(`📈 SUMMARY:`);
    console.log(`   Total Errors: ${analysis.totalErrors.toLocaleString()}`);
    console.log(`   Files Affected: ${Object.keys(analysis.fileDistribution).length}`);
    console.log(`   Error Types: ${Object.keys(analysis.errorTypes).length}\n`);

    // Top Error Types
    console.log(`🔝 TOP ERROR TYPES:`);
    Object.entries(analysis.errorTypes)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .forEach(([code, count]) => {
        const percentage = ((count / analysis.totalErrors) * 100).toFixed(1);
        console.log(`   ${code}: ${count} (${percentage}%)`);
      });

    // High Error Files
    console.log(`\n🚨 HIGH ERROR FILES:`);
    analysis.highErrorFiles.slice(0, 10).forEach(({ file, count, complexity }) => {
      const complexityIcon = complexity === 'high' ? '🔥' : complexity === 'medium' ? '⚠️' : '📝';
      console.log(`   ${complexityIcon} ${file}: ${count} errors (${complexity} complexity)`);
    });

    // Quick Wins
    console.log(`\n⚡ QUICK WINS (${analysis.quickWins.length} categories):`);
    analysis.quickWins.slice(0, 10).forEach(({ file, errorType, count, pattern }) => {
      console.log(`   ✅ ${errorType}: ${count} instances`);
      console.log(`      ${pattern}`);
      console.log(`      Primary file: ${file}\n`);
    });

    // Complex Issues
    console.log(`🔧 COMPLEX ISSUES (${analysis.complexIssues.length} categories):`);
    analysis.complexIssues.slice(0, 5).forEach(({ file, errorType, count }) => {
      console.log(`   🛠️ ${errorType}: ${count} instances`);
      console.log(`      Primary file: ${file}\n`);
    });

    // Recommendations
    this.generateRecommendations(analysis);
  }

  generateRecommendations(analysis) {
    console.log(`💡 RECOMMENDATIONS:`);
    console.log(`\n🎯 PHASE 1: QUICK WINS (Target: 60-70% error reduction)`);
    console.log(`   1. Fix implicit any errors (TS18046) - ${analysis.errorTypes['TS18046'] || 0} instances`);
    console.log(`   2. Update interface properties (TS2339) - ${analysis.errorTypes['TS2339'] || 0} instances`);
    console.log(`   3. Fix type assertions (TS2345) - ${analysis.errorTypes['TS2345'] || 0} instances`);
    console.log(`   4. Resolve import/export issues - ${(analysis.errorTypes['TS2304'] || 0) + (analysis.errorTypes['TS2305'] || 0)} instances`);

    console.log(`\n🏗️ PHASE 2: MEDIUM COMPLEXITY (Target: 20-30% error reduction)`);
    console.log(`   1. Fix type assignment errors (TS2322) - ${analysis.errorTypes['TS2322'] || 0} instances`);
    console.log(`   2. Resolve destructuring errors (TS2571) - ${analysis.errorTypes['TS2571'] || 0} instances`);
    console.log(`   3. Fix nullable property access (TS2540) - ${analysis.errorTypes['TS2540'] || 0} instances`);

    console.log(`\n🔨 PHASE 3: COMPLEX REFACTORING (Target: remaining errors)`);
    console.log(`   1. Interface inheritance issues (TS2416) - ${analysis.errorTypes['TS2416'] || 0} instances`);
    console.log(`   2. Generic type constraints (TS2698) - ${analysis.errorTypes['TS2698'] || 0} instances`);
    console.log(`   3. Complex type system issues - ${analysis.totalErrors - this.getQuickWinTarget(analysis)} instances`);

    const quickWinTarget = this.getQuickWinTarget(analysis);
    const estimatedReduction = ((quickWinTarget / analysis.totalErrors) * 100).toFixed(1);

    console.log(`\n📈 EXPECTED IMPACT:`);
    console.log(`   Quick Wins Phase: ~${estimatedReduction}% error reduction`);
    console.log(`   Estimated time: ${Math.ceil(quickWinTarget / 20)} hours (assuming 20 errors/hour)`);
    console.log(`   Remaining work: ${Math.ceil((analysis.totalErrors - quickWinTarget) / 10)} hours`);
  }

  getQuickWinTarget(analysis) {
    return (analysis.errorTypes['TS18046'] || 0) +
           (analysis.errorTypes['TS2339'] || 0) +
           (analysis.errorTypes['TS2345'] || 0) +
           (analysis.errorTypes['TS2304'] || 0) +
           (analysis.errorTypes['TS2305'] || 0) +
           (analysis.errorTypes['TS2322'] || 0);
  }
}

// Main execution
function main() {
  const projectRoot = process.cwd();
  const analyzer = new TypeScriptErrorAnalyzer(projectRoot);

  try {
    const analysis = analyzer.analyze();
    analyzer.generateReport(analysis);

    // Exit with appropriate code
    process.exit(analysis.totalErrors > 0 ? 1 : 0);
  } catch (error) {
    console.error('❌ Analysis failed:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}