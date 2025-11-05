#!/usr/bin/env node

/**
 * ESLint AI Agent
 *
 * An intelligent agent that combines ESLint with AI capabilities to
 * systematically analyze and fix code quality issues across the project.
 *
 * Features:
 * - Programmatic ESLint execution with JSON output
 * - Rule-based issue grouping and prioritization
 * - Interactive fix suggestions with context
 * - Batch processing with progress tracking
 * - Dry-run mode for safe testing
 */

import { ESLint } from 'eslint';
import fs from 'fs';
import path from 'path';
import chalk from 'chalk';

class ESLintAIAgent {
  constructor(options = {}) {
    this.options = {
      dryRun: options.dryRun || false,
      maxIssuesPerBatch: options.maxIssuesPerBatch || 20,
      outputDir: options.outputDir || path.join(process.cwd(), 'artifacts', 'eslint'),
      ...options
    };

    this.eslint = new ESLint({
      fix: true,
      overrideConfig: {
        extends: ['@typescript-eslint/recommended'],
        rules: this.options.ruleOverrides || {}
      }
    });

    this.results = {
      totalIssues: 0,
      fixedIssues: 0,
      processedFiles: 0,
      issueBreakdown: {},
      startTime: Date.now()
    };

    // Ensure output directory exists
    if (!fs.existsSync(this.options.outputDir)) {
      fs.mkdirSync(this.options.outputDir, { recursive: true });
    }
  }

  /**
   * Run ESLint on specified file patterns and return results
   */
  async runLint(filePatterns = ['.']) {
    console.log(chalk.blue('🔍 Running ESLint analysis...'));

    try {
      const results = await this.eslint.lintFiles(filePatterns);

      // Filter out files with no issues
      const filesWithIssues = results.filter(result =>
        result.errorCount > 0 || result.warningCount > 0
      );

      console.log(chalk.green(`✅ Found issues in ${filesWithIssues.length} files`));

      // Save detailed results to JSON
      const outputPath = path.join(this.options.outputDir, `eslint-results-${Date.now()}.json`);
      fs.writeFileSync(outputPath, JSON.stringify({
        metadata: {
          timestamp: new Date().toISOString(),
          totalFiles: results.length,
          filesWithIssues: filesWithIssues.length,
          options: this.options
        },
        results: filesWithIssues
      }, null, 2));

      return filesWithIssues;
    } catch (error) {
      console.error(chalk.red('❌ ESLint execution failed:'), error.message);
      throw error;
    }
  }

  /**
   * Parse ESLint results and group by rules
   */
  parseLintResults(results) {
    const ruleBreakdown = {};
    const fileBreakdown = {};
    let totalIssues = 0;

    results.forEach(fileResult => {
      const filePath = fileResult.filePath;
      fileBreakdown[filePath] = {
        errorCount: fileResult.errorCount,
        warningCount: fileResult.warningCount,
        fixableErrorCount: fileResult.fixableErrorCount,
        fixableWarningCount: fileResult.fixableWarningCount,
        messages: []
      };

      fileResult.messages.forEach(message => {
        const ruleId = message.ruleId || 'unknown';

        if (!ruleBreakdown[ruleId]) {
          ruleBreakdown[ruleId] = {
            count: 0,
            fixable: 0,
            severity: {},
            examples: []
          };
        }

        ruleBreakdown[ruleId].count++;
        ruleBreakdown[ruleId].severity[message.severity] =
          (ruleBreakdown[ruleId].severity[message.severity] || 0) + 1;

        if (message.fix) {
          ruleBreakdown[ruleId].fixable++;
        }

        // Store examples (limit to avoid bloat)
        if (ruleBreakdown[ruleId].examples.length < 3) {
          ruleBreakdown[ruleId].examples.push({
            file: filePath,
            line: message.line,
            column: message.column,
            message: message.message,
            fixable: !!message.fix
          });
        }

        fileBreakdown[filePath].messages.push({
          ruleId,
          line: message.line,
          column: message.column,
          message: message.message,
          severity: message.severity,
          fixable: !!message.fix
        });

        totalIssues++;
      });
    });

    this.results.totalIssues = totalIssues;
    this.results.issueBreakdown = ruleBreakdown;

    return {
      summary: {
        totalIssues,
        totalFiles: results.length,
        filesWithIssues: Object.keys(fileBreakdown).length,
        mostCommonRules: this.getTopRules(ruleBreakdown, 5)
      },
      ruleBreakdown,
      fileBreakdown
    };
  }

  /**
   * Get most frequently violated rules
   */
  getTopRules(ruleBreakdown, limit = 10) {
    return Object.entries(ruleBreakdown)
      .sort(([,a], [,b]) => b.count - a.count)
      .slice(0, limit)
      .map(([ruleId, data]) => ({
        ruleId,
        count: data.count,
        fixable: data.fixable,
        fixablePercentage: Math.round((data.fixable / data.count) * 100)
      }));
  }

  /**
   * Generate fix suggestions for specific rule violations
   */
  generateFixSuggestions(ruleBreakdown, fileBreakdown) {
    const suggestions = [];

    // Process rules in order of frequency (most common first)
    const sortedRules = this.getTopRules(ruleBreakdown);

    for (const rule of sortedRules) {
      const ruleId = rule.ruleId;
      const violations = [];

      // Collect all violations for this rule
      Object.entries(fileBreakdown).forEach(([filePath, fileData]) => {
        fileData.messages.forEach(msg => {
          if (msg.ruleId === ruleId) {
            violations.push({
              file: filePath,
              line: msg.line,
              column: msg.column,
              message: msg.message,
              fixable: msg.fixable
            });
          }
        });
      });

      // Generate fix strategy based on rule type
      const fixStrategy = this.generateFixStrategy(ruleId, violations);

      suggestions.push({
        ruleId,
        priority: this.getRulePriority(ruleId),
        count: rule.count,
        fixable: rule.fixable,
        fixStrategy,
        violations: violations.slice(0, this.options.maxIssuesPerBatch)
      });
    }

    return suggestions.sort((a, b) => b.priority - a.priority);
  }

  /**
   * Generate fix strategy for specific rule types
   */
  generateFixStrategy(ruleId, violations) {
    const strategies = {
      '@typescript-eslint/no-unused-vars': {
        type: 'removal',
        description: 'Remove unused variables and imports',
        action: 'delete-unused',
        confidence: 'high'
      },
      '@typescript-eslint/no-explicit-any': {
        type: 'refactor',
        description: 'Replace any types with proper TypeScript types',
        action: 'type-replacement',
        confidence: 'medium'
      },
      '@typescript-eslint/no-require-imports': {
        type: 'convert',
        description: 'Convert require() statements to ES6 imports',
        action: 'import-conversion',
        confidence: 'high'
      },
      '@typescript-eslint/no-wrapper-object-types': {
        type: 'refactor',
        description: 'Replace wrapper object types (String, Number) with primitives',
        action: 'type-primitive-conversion',
        confidence: 'high'
      }
    };

    return strategies[ruleId] || {
      type: 'manual',
      description: `Manual fix required for ${ruleId}`,
      action: 'manual-review',
      confidence: 'low'
    };
  }

  /**
   * Get priority score for rule violations
   */
  getRulePriority(ruleId) {
    const priorities = {
      '@typescript-eslint/no-unused-vars': 10, // Easy to fix, high impact
      '@typescript-eslint/no-require-imports': 9, // Easy to fix, improves code quality
      '@typescript-eslint/no-wrapper-object-types': 8, // Easy to fix, type safety
      '@typescript-eslint/ban-ts-comment': 7, // Code quality
      '@typescript-eslint/no-explicit-any': 6, // Type safety but requires thought
      'no-useless-escape': 8, // Easy to fix
      'default-case': 5, // Code safety
    };

    return priorities[ruleId] || 3; // Default priority
  }

  /**
   * Apply fixes for high-confidence issues
   */
  async applyAutoFixes(suggestions) {
    console.log(chalk.blue('🔧 Applying automatic fixes...'));

    let fixedCount = 0;

    for (const suggestion of suggestions) {
      if (suggestion.fixStrategy.confidence === 'high' && suggestion.fixable > 0) {
        try {
          console.log(chalk.yellow(`Applying fixes for ${suggestion.ruleId} (${suggestion.fixable} issues)`));

          if (!this.options.dryRun) {
            // Apply fixes using ESLint's built-in fixer
            const targetFiles = suggestion.violations.map(v => v.file);
            await this.eslint.lintFiles(targetFiles);

            // Write fixes to files
            const results = await this.eslint.lintFiles(targetFiles);
            await ESLint.outputFixes(results);
          }

          fixedCount += suggestion.fixable;
          console.log(chalk.green(`✅ Fixed ${suggestion.fixable} issues for ${suggestion.ruleId}`));

        } catch (error) {
          console.error(chalk.red(`❌ Failed to apply fixes for ${suggestion.ruleId}:`), error.message);
        }
      }
    }

    this.results.fixedIssues = fixedCount;
    return fixedCount;
  }

  /**
   * Generate comprehensive report
   */
  generateReport(suggestions) {
    const reportPath = path.join(this.options.outputDir, `eslint-report-${Date.now()}.md`);

    const report = `# ESLint AI Agent Report

## Summary
- **Total Issues Found**: ${this.results.totalIssues}
- **Issues Fixed**: ${this.results.fixedIssues}
- **Files Processed**: ${this.results.processedFiles}
- **Processing Time**: ${Math.round((Date.now() - this.results.startTime) / 1000)}s

## Top Issue Categories
${this.getTopRules(this.results.issueBreakdown, 10).map((rule, index) =>
  `${index + 1}. **${rule.ruleId}**: ${rule.count} issues (${rule.fixable} fixable)`
).join('\n')}

## Fix Suggestions by Priority
${suggestions.map((suggestion, index) => `
### ${index + 1}. ${suggestion.ruleId} (Priority: ${suggestion.priority})
- **Count**: ${suggestion.count} issues
- **Fixable**: ${suggestion.fixable} issues
- **Strategy**: ${suggestion.fixStrategy.description}
- **Confidence**: ${suggestion.fixStrategy.confidence}
- **Sample Issues**:
${suggestion.violations.slice(0, 3).map(v =>
  `  - \`${v.file}:${v.line}:${v.column}\`: ${v.message}`
).join('\n')}
`).join('\n')}

## Next Steps
1. Review high-priority fixable issues
2. Apply automatic fixes for high-confidence rules
3. Manually review medium and low-confidence issues
4. Re-run analysis to verify improvements

---
*Report generated by ESLint AI Agent on ${new Date().toISOString()}*
`;

    fs.writeFileSync(reportPath, report);
    console.log(chalk.green(`📄 Report saved to: ${reportPath}`));

    return reportPath;
  }

  /**
   * Execute the complete ESLint AI agent workflow
   */
  async execute(filePatterns = ['.']) {
    console.log(chalk.blue('🤖 ESLint AI Agent Starting...'));

    try {
      // Step 1: Run ESLint analysis
      const lintResults = await this.runLint(filePatterns);

      if (lintResults.length === 0) {
        console.log(chalk.green('🎉 No ESLint issues found!'));
        return { success: true, issues: 0 };
      }

      // Step 2: Parse and analyze results
      const parsedResults = this.parseLintResults(lintResults);
      console.log(chalk.yellow(`📊 Found ${parsedResults.summary.totalIssues} total issues`));

      // Step 3: Generate fix suggestions
      const suggestions = this.generateFixSuggestions(
        parsedResults.ruleBreakdown,
        parsedResults.fileBreakdown
      );

      console.log(chalk.blue(`💡 Generated ${suggestions.length} fix strategies`));

      // Step 4: Apply automatic fixes
      const fixedCount = await this.applyAutoFixes(suggestions);

      // Step 5: Generate report
      const reportPath = this.generateReport(suggestions);

      this.results.processedFiles = lintResults.length;

      console.log(chalk.green('🎯 ESLint AI Agent Complete!'));
      console.log(chalk.cyan(`📈 Fixed ${fixedCount} issues automatically`));
      console.log(chalk.cyan(`📄 Detailed report: ${reportPath}`));

      return {
        success: true,
        issues: parsedResults.summary.totalIssues,
        fixed: fixedCount,
        remaining: parsedResults.summary.totalIssues - fixedCount,
        reportPath,
        suggestions
      };

    } catch (error) {
      console.error(chalk.red('💥 ESLint AI Agent failed:'), error.message);
      throw error;
    }
  }
}

// CLI interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const options = {
    dryRun: args.includes('--dry-run'),
    maxIssuesPerBatch: 20
  };

  const filePatterns = args.filter(arg => !arg.startsWith('--')) || ['.'];

  const agent = new ESLintAIAgent(options);
  agent.execute(filePatterns).catch(console.error);
}

export { ESLintAIAgent };