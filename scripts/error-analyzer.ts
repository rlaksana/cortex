#!/usr/bin/env node

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

interface ErrorAnalysis {
  totalErrors: number;
  errorTypes: Record<string, number>;
  fileDistribution: Record<string, number>;
  highErrorFiles: Array<{ file: string; count: number; complexity: 'high' | 'medium' | 'low' }>;
  quickWins: Array<{ file: string; errorType: string; count: number; pattern: string }>;
  complexIssues: Array<{ file: string; errorType: string; count: number; requiresRefactor: boolean }>;
}

interface ErrorPattern {
  regex: RegExp;
  category: string;
  priority: 'high' | 'medium' | 'low';
  quickWin: boolean;
  requiresRefactor: boolean;
  description: string;
}

const ERROR_PATTERNS: ErrorPattern[] = [
  // Type assertion errors (Quick wins)
  {
    regex: /TS2345.*Argument of type '.*' is not assignable to parameter of type/,
    category: 'Type Assertion',
    priority: 'high',
    quickWin: true,
    requiresRefactor: false,
    description: 'Simple type assertion or interface update needed'
  },

  // Property existence errors (Interface updates)
  {
    regex: /TS2339.*Property '.*' does not exist on type/,
    category: 'Interface Mismatch',
    priority: 'high',
    quickWin: true,
    requiresRefactor: false,
    description: 'Interface property missing or incorrectly typed'
  },

  // Implicit any errors (Type annotations needed)
  {
    regex: /TS18046.*'(.*)' is of type 'unknown'/,
    category: 'Implicit Any',
    priority: 'medium',
    quickWin: true,
    requiresRefactor: false,
    description: 'Add type annotations for unknown types'
  },

  // Import/export errors
  {
    regex: /TS2304.*Cannot find name|TS2305.*has no exported member/,
    category: 'Import/Export',
    priority: 'high',
    quickWin: true,
    requiresRefactor: false,
    description: 'Missing imports or incorrect export names'
  },

  // Assignment errors (Type compatibility)
  {
    regex: /TS2322.*Type '.*' is not assignable to type/,
    category: 'Type Assignment',
    priority: 'medium',
    quickWin: true,
    requiresRefactor: false,
    description: 'Type compatibility issues in assignments'
  },

  // Function signature errors (Complex refactoring)
  {
    regex: /TS2416.*Property '.*' in type '.*' is not assignable to the same property in base type/,
    category: 'Interface Inheritance',
    priority: 'low',
    quickWin: false,
    requiresRefactor: true,
    description: 'Base interface changes requiring systematic updates'
  },

  // Generic type errors (Complex)
  {
    regex: /TS2698.*Spread operators may only be applied to types implementing/,
    category: 'Generic Types',
    priority: 'low',
    quickWin: false,
    requiresRefactor: true,
    description: 'Generic type constraints requiring refactoring'
  }
];

class TypeScriptErrorAnalyzer {
  private projectRoot: string;

  constructor(projectRoot: string) {
    this.projectRoot = projectRoot;
  }

  async analyze(): Promise<ErrorAnalysis> {
    console.log('🔍 Analyzing TypeScript compilation errors...');

    // Get all TypeScript errors
    const errors = this.getTypeScriptErrors();

    // Analyze error patterns
    const analysis: ErrorAnalysis = {
      totalErrors: errors.length,
      errorTypes: this.categorizeErrors(errors),
      fileDistribution: this.getDistributionByFile(errors),
      highErrorFiles: this.identifyHighErrorFiles(errors),
      quickWins: this.identifyQuickWins(errors),
      complexIssues: this.identifyComplexIssues(errors)
    };

    return analysis;
  }

  private getTypeScriptErrors(): string[] {
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
    } catch (error: any) {
      // TypeScript compilation failed, extract errors from stderr
      const errorOutput = error.stderr?.toString() || error.stdout?.toString() || '';
      return errorOutput
        .split('\n')
        .filter(line => line.includes('error TS'))
        .map(line => line.trim());
    }
  }

  private categorizeErrors(errors: string[]): Record<string, number> {
    const categories: Record<string, number> = {};

    errors.forEach(error => {
      const errorCode = this.extractErrorCode(error);
      categories[errorCode] = (categories[errorCode] || 0) + 1;
    });

    return categories;
  }

  private getDistributionByFile(errors: string[]): Record<string, number> {
    const distribution: Record<string, number> = {};

    errors.forEach(error => {
      const filePath = this.extractFilePath(error);
      if (filePath) {
        distribution[filePath] = (distribution[filePath] || 0) + 1;
      }
    });

    return distribution;
  }

  private identifyHighErrorFiles(errors: string[]): Array<{ file: string; count: number; complexity: 'high' | 'medium' | 'low' }> {
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

  private identifyQuickWins(errors: string[]): Array<{ file: string; errorType: string; count: number; pattern: string }> {
    const quickWins: Array<{ file: string; errorType: string; count: number; pattern: string }> = [];
    const patternGroups: Record<string, string[]> = {};

    errors.forEach(error => {
      const pattern = ERROR_PATTERNS.find(p => p.regex.test(error));
      if (pattern && pattern.quickWin) {
        const key = `${pattern.category}:${pattern.description}`;
        if (!patternGroups[key]) {
          patternGroups[key] = [];
        }
        patternGroups[key].push(error);
      }
    });

    Object.entries(patternGroups).forEach(([key, errorList]) => {
      const [category, description] = key.split(':');
      const file = this.extractFilePath(errorList[0]);
      quickWins.push({
        file: file || 'unknown',
        errorType: category,
        count: errorList.length,
        pattern: description
      });
    });

    return quickWins.sort((a, b) => b.count - a.count);
  }

  private identifyComplexIssues(errors: string[]): Array<{ file: string; errorType: string; count: number; requiresRefactor: boolean }> {
    const complexIssues: Array<{ file: string; errorType: string; count: number; requiresRefactor: boolean }> = [];
    const patternGroups: Record<string, string[]> = {};

    errors.forEach(error => {
      const pattern = ERROR_PATTERNS.find(p => p.regex.test(error));
      if (pattern && pattern.requiresRefactor) {
        const key = `${pattern.category}:${pattern.description}`;
        if (!patternGroups[key]) {
          patternGroups[key] = [];
        }
        patternGroups[key].push(error);
      }
    });

    Object.entries(patternGroups).forEach(([key, errorList]) => {
      const [category, description] = key.split(':');
      const file = this.extractFilePath(errorList[0]);
      complexIssues.push({
        file: file || 'unknown',
        errorType: category,
        count: errorList.length,
        requiresRefactor: true
      });
    });

    return complexIssues.sort((a, b) => b.count - a.count);
  }

  private assessFileComplexity(filePath: string, errorCount: number): 'high' | 'medium' | 'low' {
    // Simple heuristic based on error count and file type
    if (errorCount > 50) return 'high';
    if (errorCount > 20) return 'medium';
    return 'low';
  }

  private extractErrorCode(error: string): string {
    const match = error.match(/error (TS\d+)/);
    return match ? match[1] : 'UNKNOWN';
  }

  private extractFilePath(error: string): string | null {
    const match = error.match(/^(.+)\(/);
    return match ? match[1] : null;
  }

  generateReport(analysis: ErrorAnalysis): void {
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
    analysis.complexIssues.slice(0, 5).forEach(({ file, errorType, count, pattern }) => {
      console.log(`   🛠️ ${errorType}: ${count} instances`);
      console.log(`      ${pattern}`);
      console.log(`      Primary file: ${file}\n`);
    });

    // Recommendations
    this.generateRecommendations(analysis);
  }

  private generateRecommendations(analysis: ErrorAnalysis): void {
    console.log(`💡 RECOMMENDATIONS:`);
    console.log(`\n🎯 PHASE 1: QUICK WINS (Target: 60-70% error reduction)`);
    console.log(`   1. Fix implicit any errors (TS18046) - ${analysis.errorTypes['TS18046'] || 0} instances`);
    console.log(`   2. Update interface properties (TS2339) - ${analysis.errorTypes['TS2339'] || 0} instances`);
    console.log(`   3. Fix type assertions (TS2345) - ${analysis.errorTypes['TS2345'] || 0} instances`);
    console.log(`   4. Resolve import/export issues (TS2304/TS2305) - ${(analysis.errorTypes['TS2304'] || 0) + (analysis.errorTypes['TS2305'] || 0)} instances`);

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

  private getQuickWinTarget(analysis: ErrorAnalysis): number {
    return (analysis.errorTypes['TS18046'] || 0) +
           (analysis.errorTypes['TS2339'] || 0) +
           (analysis.errorTypes['TS2345'] || 0) +
           (analysis.errorTypes['TS2304'] || 0) +
           (analysis.errorTypes['TS2305'] || 0) +
           (analysis.errorTypes['TS2322'] || 0);
  }
}

// Main execution
async function main() {
  const projectRoot = process.cwd();
  const analyzer = new TypeScriptErrorAnalyzer(projectRoot);

  try {
    const analysis = await analyzer.analyze();
    analyzer.generateReport(analysis);

    // Exit with appropriate code
    process.exit(analysis.totalErrors > 0 ? 1 : 0);
  } catch (error) {
    console.error('❌ Analysis failed:', error);
    process.exit(1);
  }
}

// Check if this file is being run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}