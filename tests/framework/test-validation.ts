/**
 * Test Validation and Linting Utilities
 *
 * Provides validation rules, linting functions, and quality checks for test files.
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  suggestions: string[];
}

export interface TestFileMetrics {
  fileName: string;
  lines: number;
  testCount: number;
  describeBlocks: number;
  beforeEachCount: number;
  afterEachCount: number;
  mockCount: number;
  hasGlobalSetup: boolean;
  hasGlobalCleanup: boolean;
  usesStandardizedSetup: boolean;
}

export interface ValidationRule {
  name: string;
  description: string;
  severity: 'error' | 'warning' | 'suggestion';
  validate: (content: string, filePath: string) => ValidationResult;
}

/**
 * Test Validation Engine
 */
export class TestValidator {
  private static rules: ValidationRule[] = [
    // Mock usage validation
    {
      name: 'mock-cleanup',
      description: 'Tests should properly clean up mocks',
      severity: 'error',
      validate: (content: string) => {
        const result: ValidationResult = { valid: true, errors: [], warnings: [], suggestions: [] };

        const hasMocks = content.includes('vi.fn(') || content.includes('vi.mock(');
        const hasBeforeEach = content.includes('beforeEach(');
        const hasAfterEach = content.includes('afterEach(');
        const hasCleanup =
          content.includes('vi.clearAllMocks()') ||
          content.includes('vi.restoreAllMocks()') ||
          content.includes('MockManager') ||
          content.includes('StandardTestUtils.cleanupTestEnvironment');

        if (hasMocks && !hasCleanup) {
          result.valid = false;
          result.errors.push('Tests with mocks should include cleanup in afterEach or afterAll');
        }

        if (hasMocks && !hasBeforeEach && !hasAfterEach) {
          result.warnings.push('Consider using beforeEach/afterEach for proper test isolation');
        }

        return result;
      },
    },

    // Standardized setup validation
    {
      name: 'standardized-setup',
      description: 'Tests should use standardized setup patterns',
      severity: 'warning',
      validate: (content: string) => {
        const result: ValidationResult = { valid: true, errors: [], warnings: [], suggestions: [] };

        const hasStandardImport =
          content.includes('StandardTestUtils') ||
          content.includes('TestPatterns') ||
          content.includes('MockManager');

        const hasOldPattern =
          content.includes('beforeEach(() => {') &&
          !content.includes('TestPatterns') &&
          !content.includes('StandardTestUtils');

        if (!hasStandardImport && hasOldPattern) {
          result.suggestions.push(
            'Consider using standardized test patterns from framework/standard-test-setup.ts'
          );
        }

        return result;
      },
    },

    // Test isolation validation
    {
      name: 'test-isolation',
      description: 'Tests should be properly isolated',
      severity: 'error',
      validate: (content: string) => {
        const result: ValidationResult = { valid: true, errors: [], warnings: [], suggestions: [] };

        const hasDescribe = content.includes('describe(');
        const hasItOrTest = content.includes('it(') || content.includes('test(');
        const hasBeforeEach = content.includes('beforeEach(');
        const hasAfterEach = content.includes('afterEach(');

        if (hasDescribe && hasItOrTest && !hasBeforeEach) {
          result.warnings.push('Consider using beforeEach for test setup consistency');
        }

        // Check for shared state between tests
        const hasSharedVariables = content.match(/let\s+\w+\s*=\s*[^;]+;/g);
        if (hasSharedVariables && hasSharedVariables.length > 3 && !hasBeforeEach) {
          result.warnings.push('Multiple shared variables detected - ensure proper test isolation');
        }

        return result;
      },
    },

    // Async/await validation
    {
      name: 'async-handling',
      description: 'Async tests should properly handle promises',
      severity: 'error',
      validate: (content: string) => {
        const result: ValidationResult = { valid: true, errors: [], warnings: [], suggestions: [] };

        const hasAsyncTests = content.includes('async ()') || content.includes('async function');
        const hasAwaitInTests = content.includes('await ');
        const hasReturnPromises = content.includes('return ') && content.includes('Promise');

        // Check for async tests without await or return
        const asyncBlocks = content.match(/async\s*\(\s*\)\s*=>\s*{([^}]*)}/g);
        if (asyncBlocks) {
          asyncBlocks.forEach((block, index) => {
            if (!block.includes('await ') && !block.includes('return ')) {
              result.errors.push(
                `Async test block ${index + 1} should use await or return a promise`
              );
            }
          });
        }

        return result;
      },
    },

    // Mock validation
    {
      name: 'mock-best-practices',
      description: 'Mocks should follow best practices',
      severity: 'warning',
      validate: (content: string) => {
        const result: ValidationResult = { valid: true, errors: [], warnings: [], suggestions: [] };

        // Check for vi.mock before imports
        const viMockCalls = content.match(/vi\.mock\(/g);
        const importStatements = content.match(/import\s+.*\s+from\s+['"][^'"]+['"];?/g);

        if (viMockCalls && importStatements) {
          const firstImportIndex = content.indexOf(importStatements[0]);
          const firstMockIndex = content.indexOf(viMockCalls[0]);

          if (firstMockIndex > firstImportIndex) {
            result.warnings.push('vi.mock() calls should be placed before import statements');
          }
        }

        // Check for proper mock naming
        const mockAssignments = content.match(/(?:const|let|var)\s+(\w+)\s*=\s*vi\.fn/g);
        if (mockAssignments) {
          mockAssignments.forEach((assignment) => {
            const match = assignment.match(/(?:const|let|var)\s+(\w+)/);
            if (match && !match[1].includes('mock') && !match[1].includes('Mock')) {
              result.suggestions.push(
                `Consider prefixing mock variable names with 'mock': ${match[1]} -> mock${match[1].charAt(0).toUpperCase() + match[1].slice(1)}`
              );
            }
          });
        }

        return result;
      },
    },

    // Error handling validation
    {
      name: 'error-handling',
      description: 'Tests should properly test error cases',
      severity: 'suggestion',
      validate: (content: string) => {
        const result: ValidationResult = { valid: true, errors: [], warnings: [], suggestions: [] };

        const hasTestBlocks = content.match(/(?:it|test)\s*\(\s*['"][^'"]*['"]/g);
        const hasErrorTests =
          content.includes('toThrow') ||
          content.includes('rejects') ||
          content.includes('catch') ||
          content.includes('error');

        if (hasTestBlocks && hasTestBlocks.length > 3 && !hasErrorTests) {
          result.suggestions.push('Consider adding error case tests for better coverage');
        }

        return result;
      },
    },

    // Performance test validation
    {
      name: 'performance-testing',
      description: 'Performance tests should have thresholds',
      severity: 'warning',
      validate: (content: string) => {
        const result: ValidationResult = { valid: true, errors: [], warnings: [], suggestions: [] };

        const isPerformanceTest =
          content.includes('performance') ||
          content.includes('Performance') ||
          content.includes('measurePerformance');

        if (isPerformanceTest) {
          const hasThreshold =
            content.includes('expect.*toBeLessThan') ||
            content.includes('maxDuration') ||
            content.includes('timeout');

          if (!hasThreshold) {
            result.warnings.push('Performance tests should include duration thresholds');
          }
        }

        return result;
      },
    },
  ];

  /**
   * Validate a test file against all rules
   */
  static validateFile(filePath: string): ValidationResult {
    if (!existsSync(filePath)) {
      return {
        valid: false,
        errors: [`File not found: ${filePath}`],
        warnings: [],
        suggestions: [],
      };
    }

    const content = readFileSync(filePath, 'utf-8');
    const combinedResult: ValidationResult = {
      valid: true,
      errors: [],
      warnings: [],
      suggestions: [],
    };

    this.rules.forEach((rule) => {
      const result = rule.validate(content, filePath);

      if (!result.valid) {
        combinedResult.valid = false;
      }

      combinedResult.errors.push(...result.errors);
      combinedResult.warnings.push(...result.warnings);
      combinedResult.suggestions.push(...result.suggestions);
    });

    return combinedResult;
  }

  /**
   * Validate multiple test files
   */
  static validateFiles(filePaths: string[]): { [filePath: string]: ValidationResult } {
    const results: { [filePath: string]: ValidationResult } = {};

    filePaths.forEach((filePath) => {
      results[filePath] = this.validateFile(filePath);
    });

    return results;
  }

  /**
   * Add a custom validation rule
   */
  static addRule(rule: ValidationRule): void {
    this.rules.push(rule);
  }

  /**
   * Get all validation rules
   */
  static getRules(): ValidationRule[] {
    return [...this.rules];
  }
}

/**
 * Test Metrics Calculator
 */
export class TestMetrics {
  /**
   * Calculate metrics for a test file
   */
  static calculateMetrics(filePath: string): TestFileMetrics {
    const content = readFileSync(filePath, 'utf-8');
    const lines = content.split('\n').length;

    return {
      fileName: filePath,
      lines,
      testCount: (content.match(/(?:it|test)\s*\(/g) || []).length,
      describeBlocks: (content.match(/describe\s*\(/g) || []).length,
      beforeEachCount: (content.match(/beforeEach\s*\(/g) || []).length,
      afterEachCount: (content.match(/afterEach\s*\(/g) || []).length,
      mockCount: (content.match(/vi\.fn|vi\.mock/g) || []).length,
      hasGlobalSetup: content.includes('beforeAll('),
      hasGlobalCleanup: content.includes('afterAll('),
      usesStandardizedSetup:
        content.includes('StandardTestUtils') ||
        content.includes('TestPatterns') ||
        content.includes('MockManager'),
    };
  }

  /**
   * Generate a summary report for multiple test files
   */
  static generateSummary(filePaths: string[]): {
    totalFiles: number;
    totalTests: number;
    totalLines: number;
    averageTestsPerFile: number;
    filesWithStandardizedSetup: number;
    filesWithMocks: number;
    filesWithProperCleanup: number;
  } {
    const metrics = filePaths.map((path) => this.calculateMetrics(path));

    return {
      totalFiles: metrics.length,
      totalTests: metrics.reduce((sum, m) => sum + m.testCount, 0),
      totalLines: metrics.reduce((sum, m) => sum + m.lines, 0),
      averageTestsPerFile:
        metrics.length > 0 ? metrics.reduce((sum, m) => sum + m.testCount, 0) / metrics.length : 0,
      filesWithStandardizedSetup: metrics.filter((m) => m.usesStandardizedSetup).length,
      filesWithMocks: metrics.filter((m) => m.mockCount > 0).length,
      filesWithProperCleanup: metrics.filter((m) => m.afterEachCount > 0 || m.hasGlobalCleanup)
        .length,
    };
  }
}

/**
 * Test Linting Rules
 */
export const TestLintingRules = {
  /**
   * Check for proper test file naming
   */
  validateFileName: (filePath: string): ValidationResult => {
    const result: ValidationResult = { valid: true, errors: [], warnings: [], suggestions: [] };

    const fileName = filePath.split('/').pop() || '';
    const isValidNaming = /\.test\.(ts|js)$/.test(fileName) || /\.spec\.(ts|js)$/.test(fileName);

    if (!isValidNaming) {
      result.valid = false;
      result.errors.push('Test files should end with .test.ts or .spec.ts');
    }

    return result;
  },

  /**
   * Check for proper test structure
   */
  validateTestStructure: (content: string): ValidationResult => {
    const result: ValidationResult = { valid: true, errors: [], warnings: [], suggestions: [] };

    const hasDescribe = content.includes('describe(');
    const hasItOrTest = content.includes('it(') || content.includes('test(');

    if (!hasDescribe) {
      result.warnings.push('Consider grouping tests in describe blocks');
    }

    if (!hasItOrTest) {
      result.errors.push('Test files should contain at least one test case (it or test)');
      result.valid = false;
    }

    return result;
  },

  /**
   * Check for proper async/await usage
   */
  validateAsyncUsage: (content: string): ValidationResult => {
    const result: ValidationResult = { valid: true, errors: [], warnings: [], suggestions: [] };

    // Check for async functions without proper handling
    const asyncTestBlocks = content.match(
      /(?:it|test)\s*\(\s*['"][^'"]*['"]\s*,\s*async\s*\([^)]*\)\s*=>\s*{([^}]*)}/g
    );

    if (asyncTestBlocks) {
      asyncTestBlocks.forEach((block, index) => {
        if (!block.includes('await ') && !block.includes('return ')) {
          result.errors.push(`Async test ${index + 1} should use await or return a promise`);
          result.valid = false;
        }
      });
    }

    return result;
  },
};

/**
 * CLI-friendly validation reporter
 */
export class ValidationReporter {
  /**
   * Generate a human-readable report
   */
  static generateReport(results: { [filePath: string]: ValidationResult }): string {
    let report = '\n📋 Test Validation Report\n';
    report += '='.repeat(50) + '\n\n';

    let totalErrors = 0;
    let totalWarnings = 0;
    let totalSuggestions = 0;

    Object.entries(results).forEach(([filePath, result]) => {
      const status = result.valid ? '✅' : '❌';
      report += `${status} ${filePath}\n`;

      if (result.errors.length > 0) {
        totalErrors += result.errors.length;
        result.errors.forEach((error) => {
          report += `  ❌ Error: ${error}\n`;
        });
      }

      if (result.warnings.length > 0) {
        totalWarnings += result.warnings.length;
        result.warnings.forEach((warning) => {
          report += `  ⚠️  Warning: ${warning}\n`;
        });
      }

      if (result.suggestions.length > 0) {
        totalSuggestions += result.suggestions.length;
        result.suggestions.forEach((suggestion) => {
          report += `  💡 Suggestion: ${suggestion}\n`;
        });
      }

      report += '\n';
    });

    report += '='.repeat(50) + '\n';
    report += `Summary: ${totalErrors} errors, ${totalWarnings} warnings, ${totalSuggestions} suggestions\n`;

    return report;
  }

  /**
   * Generate JSON report for CI/CD integration
   */
  static generateJsonReport(results: { [filePath: string]: ValidationResult }): {
    summary: { errors: number; warnings: number; suggestions: number; totalFiles: number };
    files: { [filePath: string]: ValidationResult };
  } {
    const errors = Object.values(results).reduce((sum, r) => sum + r.errors.length, 0);
    const warnings = Object.values(results).reduce((sum, r) => sum + r.warnings.length, 0);
    const suggestions = Object.values(results).reduce((sum, r) => sum + r.suggestions.length, 0);

    return {
      summary: {
        errors,
        warnings,
        suggestions,
        totalFiles: Object.keys(results).length,
      },
      files: results,
    };
  }
}

export default TestValidator;
