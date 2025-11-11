#!/usr/bin/env node

/**
 * Parameter Naming Compliance Report Generator
 *
 * This script generates comprehensive reports about parameter naming compliance
 * across the codebase, including trends, violations, and recommendations.
 */

const fs = require('fs');
const { execSync } = require('child_process');

class NamingReportGenerator {
  constructor() {
    this.reportData = {
      timestamp: new Date().toISOString(),
      summary: {
        filesScanned: 0,
        functionsAnalyzed: 0,
        parametersAnalyzed: 0,
        violations: 0,
        compliance: 0
      },
      errorAnalysis: {
        TS2304: 0,
        TS18046: 0,
        TS7006: 0,
        TS2551: 0,
        total: 0
      },
      violations: {
        PNC001: 0, // camelCase violations
        PNC002: 0, // non-descriptive names
        PNC003: 0, // generic names
        PNC004: 0, // inconsistent naming
        PNC005: 0  // missing type annotations
      },
      trends: {
        improvement: 0,
        regression: 0
      },
      recommendations: []
    };
  }

  async generateReport() {
    console.log('📝 Generating parameter naming compliance report...');

    await this.collectTypeScriptErrors();
    await this.analyzeNamingPatterns();
    await this.calculateComplianceMetrics();
    await this.generateRecommendations();
    await this.compareWithPreviousReport();

    const report = this.formatReport();
    console.log(report);
    return report;
  }

  async collectTypeScriptErrors() {
    try {
      const output = execSync('npx tsc --noEmit --project tsconfig.production.json', { encoding: 'utf8' });
      const lines = output.split('\n');

      for (const line of lines) {
        if (line.includes('error TS2304')) this.reportData.errorAnalysis.TS2304++;
        if (line.includes('error TS18046')) this.reportData.errorAnalysis.TS18046++;
        if (line.includes('error TS7006')) this.reportData.errorAnalysis.TS7006++;
        if (line.includes('error TS2551')) this.reportData.errorAnalysis.TS2551++;
      }

      this.reportData.errorAnalysis.total =
        this.reportData.errorAnalysis.TS2304 +
        this.reportData.errorAnalysis.TS18046 +
        this.reportData.errorAnalysis.TS7006 +
        this.reportData.errorAnalysis.TS2551;

    } catch (error) {
      // TypeScript compiler exits with error code when errors are found
      const output = error.stdout || error.message;
      const lines = output.split('\n');

      for (const line of lines) {
        if (line.includes('error TS2304')) this.reportData.errorAnalysis.TS2304++;
        if (line.includes('error TS18046')) this.reportData.errorAnalysis.TS18046++;
        if (line.includes('error TS7006')) this.reportData.errorAnalysis.TS7006++;
        if (line.includes('error TS2551')) this.reportData.errorAnalysis.TS2551++;
      }

      this.reportData.errorAnalysis.total =
        this.reportData.errorAnalysis.TS2304 +
        this.reportData.errorAnalysis.TS18046 +
        this.reportData.errorAnalysis.TS7006 +
        this.reportData.errorAnalysis.TS2551;
    }
  }

  async analyzeNamingPatterns() {
    try {
      const output = execSync('node scripts/validate-parameter-naming.cjs src/ 2>&1', { encoding: 'utf8' });
      const lines = output.split('\n');

      for (const line of lines) {
        if (line.includes('PNC001')) this.reportData.violations.PNC001++;
        if (line.includes('PNC002')) this.reportData.violations.PNC002++;
        if (line.includes('PNC003')) this.reportData.violations.PNC003++;
        if (line.includes('PNC004')) this.reportData.violations.PNC004++;
        if (line.includes('PNC005')) this.reportData.violations.PNC005++;
      }

      // Extract summary statistics
      const summaryMatch = output.match(/Files scanned: (\d+).*Functions scanned: (\d+).*Parameters scanned: (\d+).*Violations found: (\d+)/s);
      if (summaryMatch) {
        this.reportData.summary.filesScanned = parseInt(summaryMatch[1]);
        this.reportData.summary.functionsAnalyzed = parseInt(summaryMatch[2]);
        this.reportData.summary.parametersAnalyzed = parseInt(summaryMatch[3]);
        this.reportData.summary.violations = parseInt(summaryMatch[4]);
      }

    } catch (error) {
      console.warn('Could not analyze naming patterns:', error.message);
    }
  }

  async calculateComplianceMetrics() {
    const totalParams = this.reportData.summary.parametersAnalyzed;
    const totalViolations = Object.values(this.reportData.violations).reduce((sum, count) => sum + count, 0);

    if (totalParams > 0) {
      this.reportData.summary.compliance = Math.round(((totalParams - totalViolations) / totalParams) * 100);
    } else {
      this.reportData.summary.compliance = 0;
    }
  }

  async generateRecommendations() {
    const recommendations = [];

    // TypeScript error recommendations
    if (this.reportData.errorAnalysis.TS2304 > 50) {
      recommendations.push({
        priority: 'HIGH',
        category: 'Missing Imports',
        description: `High number of TS2304 errors (${this.reportData.errorAnalysis.TS2304}). Review missing imports and module exports.`,
        action: 'Run automated import detection and fix missing module declarations'
      });
    }

    if (this.reportData.errorAnalysis.TS18046 > 25) {
      recommendations.push({
        priority: 'MEDIUM',
        category: 'Type Safety',
        description: `Significant TS18046 errors (${this.reportData.errorAnalysis.TS18046}). Object possibly undefined issues.`,
        action: 'Add proper null checks and optional chaining: obj?.property'
      });
    }

    if (this.reportData.errorAnalysis.TS7006 > 30) {
      recommendations.push({
        priority: 'HIGH',
        category: 'Type Annotations',
        description: `Many implicit any types (${this.reportData.errorAnalysis.TS7006}). Parameter types not specified.`,
        action: 'Add explicit type annotations to all function parameters'
      });
    }

    if (this.reportData.errorAnalysis.TS2551 > 40) {
      recommendations.push({
        priority: 'HIGH',
        category: 'Property Access',
        description: `Property access errors (${this.reportData.errorAnalysis.TS2551}). Check object interfaces.`,
        action: 'Review interface definitions and ensure proper property names'
      });
    }

    // Naming convention recommendations
    if (this.reportData.violations.PNC001 > 10) {
      recommendations.push({
        priority: 'MEDIUM',
        category: 'Naming Conventions',
        description: `camelCase violations (${this.reportData.violations.PNC001}). Use consistent camelCase naming.`,
        action: 'Standardize parameter names to camelCase convention'
      });
    }

    if (this.reportData.violations.PNC002 > 5) {
      recommendations.push({
        priority: 'LOW',
        category: 'Code Quality',
        description: `Non-descriptive parameter names (${this.reportData.violations.PNC002}).`,
        action: 'Use meaningful parameter names that describe their purpose'
      });
    }

    if (this.reportData.violations.PNC005 > 15) {
      recommendations.push({
        priority: 'MEDIUM',
        category: 'Type Safety',
        description: `Missing type annotations (${this.reportData.violations.PNC005}).`,
        action: 'Add explicit TypeScript type annotations to all parameters'
      });
    }

    // Overall compliance recommendation
    if (this.reportData.summary.compliance < 80) {
      recommendations.push({
        priority: 'HIGH',
        category: 'Overall Compliance',
        description: `Low parameter naming compliance (${this.reportData.summary.compliance}%).`,
        action: 'Focus on fixing the highest-impact violations first'
      });
    }

    this.reportData.recommendations = recommendations.sort((a, b) => {
      const priorityOrder = { HIGH: 3, MEDIUM: 2, LOW: 1 };
      return priorityOrder[b.priority] - priorityOrder[a.priority];
    });
  }

  async compareWithPreviousReport() {
    const previousReportPath = '.naming-compliance-report-previous.md';

    if (fs.existsSync(previousReportPath)) {
      try {
        const previousContent = fs.readFileSync(previousReportPath, 'utf8');
        const previousErrors = this.extractErrorCount(previousContent);
        const currentErrors = this.reportData.errorAnalysis.total;

        if (currentErrors < previousErrors) {
          this.reportData.trends.improvement = previousErrors - currentErrors;
        } else if (currentErrors > previousErrors) {
          this.reportData.trends.regression = currentErrors - previousErrors;
        }
      } catch (error) {
        console.warn('Could not compare with previous report:', error.message);
      }
    }

    // Save current report for next comparison
    const currentReportPath = '.naming-compliance-report-previous.md';
    try {
      fs.copyFileSync('.naming-compliance-report.md', currentReportPath);
    } catch {
      // File might not exist yet, that's ok
    }
  }

  extractErrorCount(reportContent) {
    const match = reportContent.match(/Total TypeScript errors: (\d+)/);
    return match ? parseInt(match[1]) : 0;
  }

  formatReport() {
    const { timestamp, summary, errorAnalysis, violations, trends, recommendations } = this.reportData;

    let report = `# Parameter Naming Compliance Report

**Generated:** ${new Date(timestamp).toLocaleString()}

## 📊 Executive Summary

- **Compliance Rate:** ${summary.compliance}%
- **Files Scanned:** ${summary.filesScanned}
- **Functions Analyzed:** ${summary.functionsAnalyzed}
- **Parameters Analyzed:** ${summary.parametersAnalyzed}
- **Violations Found:** ${summary.violations}

`;

    if (trends.improvement > 0) {
      report += `📈 **Trend:** Improving (${trends.improvement} fewer errors than previous report)\n\n`;
    } else if (trends.regression > 0) {
      report += `📉 **Trend:** Regressing (${trends.regression} more errors than previous report)\n\n`;
    }

    report += `## 🔍 TypeScript Error Analysis

| Error Code | Count | Description |
|------------|-------|-------------|
| TS2304 | ${errorAnalysis.TS2304} | Cannot find name |
| TS18046 | ${errorAnalysis.TS18046} | Object is possibly undefined |
| TS7006 | ${errorAnalysis.TS7006} | Implicit 'any' type |
| TS2551 | ${errorAnalysis.TS2551} | Property does not exist |
| **Total** | **${errorAnalysis.total}** | **All TypeScript Errors** |

`;

    if (Object.values(violations).some(v => v > 0)) {
      report += `## 📋 Parameter Naming Violations

| Violation Code | Count | Description |
|----------------|-------|-------------|
| PNC001 | ${violations.PNC001} | camelCase naming violations |
| PNC002 | ${violations.PNC002} | Non-descriptive parameter names |
| PNC003 | ${violations.PNC003} | Generic parameter names |
| PNC004 | ${violations.PNC004} | Inconsistent naming patterns |
| PNC005 | ${violations.PNC005} | Missing type annotations |

`;
    }

    if (recommendations.length > 0) {
      report += `## 🎯 Recommendations

`;

      for (const rec of recommendations) {
        const priorityEmoji = {
          HIGH: '🔴',
          MEDIUM: '🟡',
          LOW: '🟢'
        };

        report += `### ${priorityEmoji[rec.priority]} ${rec.category} (${rec.priority})

**Issue:** ${rec.description}

**Action:** ${rec.action}

`;
      }
    }

    report += `## 📈 Compliance Metrics

- **TypeScript Errors:** ${errorAnalysis.total} errors detected
- **Parameter Violations:** ${summary.violations} violations found
- **Overall Compliance:** ${summary.compliance}%
- **Trend:** ${trends.improvement > 0 ? `↓ ${trends.improvement} errors` : trends.regression > 0 ? `↑ ${trends.regression} errors` : '→ No change'}

## 🛠️ Next Steps

1. **High Priority:** Address HIGH priority recommendations first
2. **TypeScript Errors:** Run \`npx tsc --noEmit\` for detailed error information
3. **Naming Validation:** Run \`node scripts/validate-parameter-naming.js src/\` for detailed violations
4. **Automated Fixes:** Use \`npm run codemod:types\` for automated type fixes
5. **Code Review:** Review new code for parameter naming compliance

## 📚 Resources

- [TypeScript Error Handbook](./docs/typescript-errors.md)
- [Parameter Naming Guidelines](./docs/parameter-naming.md)
- [ESLint Configuration](./eslint.config.cjs)

---

*This report is automatically generated as part of the parameter naming policy enforcement.*`;

    return report;
  }
}

// CLI interface
if (require.main === module) {
  const generator = new NamingReportGenerator();
  generator.generateReport()
    .then(report => {
      // Write report to file
      fs.writeFileSync('.naming-compliance-report.md', report);
      console.log('✅ Parameter naming compliance report generated: .naming-compliance-report.md');
    })
    .catch(error => {
      console.error('❌ Failed to generate report:', error.message);
      process.exit(1);
    });
}

module.exports = NamingReportGenerator;