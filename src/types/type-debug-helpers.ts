// FINAL TRIUMPHANT VICTORY EMERGENCY ROLLBACK: Complete the great migration rescue

/**
 * Debug Helpers for Type Issues and Validation
 *
 * Comprehensive debugging utilities for type validation issues,
 * performance analysis, and troubleshooting type-related problems.
 */

import { type ValidationResult } from './runtime-type-guard-framework';

/**
 * Debug levels for categorizing issues
 */
export enum DebugLevel {
  TRACE = 'trace',
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error',
  FATAL = 'fatal',
}

/**
 * Debug categories for organizing issues
 */
export enum DebugCategory {
  VALIDATION = 'validation',
  TYPE_CHECK = 'type_check',
  PERFORMANCE = 'performance',
  CONFIGURATION = 'configuration',
  RUNTIME = 'runtime',
  COMPILER = 'compiler',
}

/**
 * Debug issue information
 */
export interface DebugIssue {
  readonly id: string;
  readonly level: DebugLevel;
  readonly category: DebugCategory;
  readonly title: string;
  readonly description: string;
  readonly timestamp: Date;
  readonly context?: Record<string, unknown>;
  readonly stackTrace?: string;
  readonly relatedIssues?: string[];
  readonly suggestedFixes?: string[];
  readonly documentationLinks?: string[];
}

/**
 * Type analysis result
 */
export interface TypeAnalysisResult {
  readonly typeName: string;
  readonly actualType: string;
  readonly expectedType: string;
  readonly isMatch: boolean;
  readonly confidence: number;
  readonly issues: DebugIssue[];
  readonly suggestions: string[];
  readonly codeExamples?: CodeExample[];
}

/**
 * Code example for fixing type issues
 */
export interface CodeExample {
  readonly title: string;
  readonly description: string;
  readonly before: string;
  readonly after: string;
  readonly explanation: string;
}

/**
 * Performance metrics for validation operations
 */
export interface ValidationPerformanceMetrics {
  readonly operationId: string;
  readonly operation: string;
  readonly startTime: number;
  readonly endTime: number;
  readonly duration: number;
  readonly inputSize: number;
  readonly validationCount: number;
  readonly successCount: number;
  readonly errorCount: number;
  readonly memoryUsage?: MemoryUsageInfo;
  readonly bottleneck?: string;
}

/**
 * Memory usage information
 */
export interface MemoryUsageInfo {
  readonly heapUsed: number;
  readonly heapTotal: number;
  readonly external: number;
  readonly rss: number;
}

/**
 * Debug context for tracking validation flow
 */
export interface DebugContext {
  readonly sessionId: string;
  readonly flowId?: string;
  readonly parentContext?: string;
  readonly startTime: number;
  readonly metadata: Record<string, unknown>;
  readonly children: DebugContext[];
}

/**
 * Type debugger main class
 */
export class TypeDebugger {
  private static instance: TypeDebugger;
  private issues: Map<string, DebugIssue> = new Map();
  private performanceMetrics: ValidationPerformanceMetrics[] = [];
  private activeContexts: Map<string, DebugContext> = new Map();
  private sessionId: string;

  private constructor() {
    this.sessionId = this.generateSessionId();
  }

  /**
   * Get singleton instance
   */
  static getInstance(): TypeDebugger {
    if (!TypeDebugger.instance) {
      TypeDebugger.instance = new TypeDebugger();
    }
    return TypeDebugger.instance;
  }

  /**
   * Log a debug issue
   */
  logIssue(issue: Omit<DebugIssue, 'id' | 'timestamp'>): string {
    const id = this.generateIssueId();
    const fullIssue: DebugIssue = {
      id,
      timestamp: new Date(),
      ...issue,
    };

    this.issues.set(id, fullIssue);
    this.logToConsole(fullIssue);
    return id;
  }

  /**
   * Analyze type mismatch
   */
  analyzeTypeMismatch(
    value: unknown,
    expectedType: string,
    actualType?: string,
    context?: Record<string, unknown>
  ): TypeAnalysisResult {
    const actual = actualType || this.inferType(value);
    const isMatch = this.checkTypeCompatibility(actual, expectedType);

    const issues: DebugIssue[] = [];

    if (!isMatch) {
      issues.push(this.createTypeMismatchIssue(actual, expectedType, context));
    }

    // Check for common issues
    if (value === null || value === undefined) {
      issues.push(this.createNullUndefinedIssue(value, expectedType, context));
    }

    if (typeof value === 'object' && value !== null) {
      issues.push(
        ...this.analyzeObjectIssues(value as Record<string, unknown>, expectedType, context)
      );
    }

    const result: TypeAnalysisResult = {
      typeName: expectedType,
      actualType: actual,
      expectedType,
      isMatch,
      confidence: this.calculateMatchConfidence(actual, expectedType),
      issues,
      suggestions: this.generateTypeFixSuggestions(actual, expectedType, issues),
      codeExamples: this.generateCodeExamples(actual, expectedType),
    };

    return result;
  }

  /**
   * Validate configuration with detailed debugging
   */
  debugValidateConfig(
    config: Record<string, unknown>,
    schema: Record<string, unknown>
  ): { result: ValidationResult; debugInfo: DebugIssue[] } {
    const startTime = Date.now();
    const debugIssues: DebugIssue[] = [];
    const operationId = this.generateOperationId();

    this.startPerformanceTracking(operationId, 'config_validation');

    try {
      // Validate each property
      for (const [key, rule] of Object.entries(schema)) {
        const value = config[key];
        const propertyDebug = this.debugValidateProperty(key, value, rule);
        debugIssues.push(...propertyDebug);
      }

      // Check for missing required properties
      for (const [key, rule] of Object.entries(schema)) {
        if (rule.required && !(key in config)) {
          debugIssues.push(this.createMissingPropertyIssue(key, rule));
        }
      }

      // Check for extra properties
      for (const key of Object.keys(config)) {
        if (!(key in schema)) {
          debugIssues.push(this.createExtraPropertyIssue(key, config[key]));
        }
      }

      const hasErrors = debugIssues.some(
        (issue) => issue.level === DebugLevel.ERROR || issue.level === DebugLevel.FATAL
      );
      const validationResult: ValidationResult = {
        success: !hasErrors,
        errors: debugIssues
          .filter((issue) => issue.level === DebugLevel.ERROR || issue.level === DebugLevel.FATAL)
          .map((issue) => ({
            path: (issue.context?.path as string) || 'root',
            message: issue.description,
            code: issue.category,
            value: issue.context?.value,
            expected: 'valid configuration',
            actual: 'validation error',
          })),
        warnings: debugIssues
          .filter((issue) => issue.level === DebugLevel.WARN || issue.level === DebugLevel.INFO)
          .map((issue) => ({
            path: (issue.context?.path as string) || 'root',
            message: issue.description,
            code: issue.category,
            value: issue.context?.value,
            severity: 'low',
          })),
      };

      this.endPerformanceTracking(operationId, {
        validationCount: Object.keys(schema).length,
        successCount: debugIssues.filter(
          (issue) => issue.level !== DebugLevel.ERROR && issue.level !== DebugLevel.FATAL
        ).length,
        errorCount: debugIssues.filter(
          (issue) => issue.level === DebugLevel.ERROR || issue.level === DebugLevel.FATAL
        ).length,
        inputSize: JSON.stringify(config).length,
      });

      return { result: validationResult, debugInfo: debugIssues };
    } catch (error) {
      const errorId = this.logIssue({
        level: DebugLevel.FATAL,
        category: DebugCategory.RUNTIME,
        title: 'Configuration validation crashed',
        description: `Validation process threw an error: ${error instanceof Error ? error.message : String(error)}`,
        context: {
          config: JSON.stringify(config, null, 2),
          schema: JSON.stringify(schema, null, 2),
        },
        stackTrace: error instanceof Error ? error.stack : undefined,
      });

      this.endPerformanceTracking(operationId, {
        errorCount: 1,
        validationCount: 0,
        successCount: 0,
        inputSize: 0,
      });

      return {
        result: {
          success: false,
          errors: [{
            path: 'root',
            message: 'Validation process crashed',
            code: 'CRASH',
            value: error,
            expected: 'successful validation',
            actual: 'crash'
          }],
          warnings: [],
        },
        debugInfo: debugIssues,
      };
    }
  }

  /**
   * Debug validation of a single property
   */
  private debugValidateProperty(key: string, value: unknown, rule: unknown): DebugIssue[] {
    const issues: DebugIssue[] = [];
    const typedRule = rule as unknown; // Type assertion for rule properties

    try {
      // Type validation
      if (typedRule.type && !this.checkTypeCompatibility(this.inferType(value), typedRule.type)) {
        issues.push(
          this.createTypeMismatchIssue(this.inferType(value), typedRule.type, { key, value, path: key })
        );
      }

      // Range validation
      if (typedRule.min !== undefined && typeof value === 'number' && value < typedRule.min) {
        issues.push(this.createRangeIssue(key, value, 'below minimum', typedRule.min, typedRule.max));
      }

      if (typedRule.max !== undefined && typeof value === 'number' && value > typedRule.max) {
        issues.push(this.createRangeIssue(key, value, 'above maximum', typedRule.min, typedRule.max));
      }

      // Pattern validation
      if (typedRule.pattern && typeof value === 'string' && !new RegExp(typedRule.pattern).test(value)) {
        issues.push(this.createPatternIssue(key, value, typedRule.pattern));
      }

      // Enum validation
      if (typedRule.enum && Array.isArray(typedRule.enum) && !typedRule.enum.includes(value)) {
        issues.push(this.createEnumIssue(key, value, typedRule.enum));
      }
    } catch (error) {
      issues.push(this.createValidationRuleError(key, typedRule, error));
    }

    return issues;
  }

  /**
   * Generate debug report
   */
  generateDebugReport(): {
    summary: {
      totalIssues: number;
      issuesByLevel: Record<DebugLevel, number>;
      issuesByCategory: Record<DebugCategory, number>;
      performanceMetrics: {
        totalOperations: number;
        averageDuration: number;
        slowestOperation: ValidationPerformanceMetrics | null;
        errorRate: number;
      };
    };
    recentIssues: DebugIssue[];
    performanceIssues: ValidationPerformanceMetrics[];
    recommendations: string[];
  } {
    const issuesByLevel = Object.values(DebugLevel).reduce(
      (acc, level) => {
        acc[level] = Array.from(this.issues.values()).filter(
          (issue) => issue.level === level
        ).length;
        return acc;
      },
      {} as Record<DebugLevel, number>
    );

    const issuesByCategory = Object.values(DebugCategory).reduce(
      (acc, category) => {
        acc[category] = Array.from(this.issues.values()).filter(
          (issue) => issue.category === category
        ).length;
        return acc;
      },
      {} as Record<DebugCategory, number>
    );

    const totalOperations = this.performanceMetrics.length;
    const averageDuration =
      totalOperations > 0
        ? this.performanceMetrics.reduce((sum, metric) => sum + metric.duration, 0) /
          totalOperations
        : 0;

    const slowestOperation =
      totalOperations > 0
        ? this.performanceMetrics.reduce(
            (slowest, metric) => (metric.duration > (slowest?.duration || 0) ? metric : slowest),
            null as ValidationPerformanceMetrics | null
          )
        : null;

    const errorRate =
      totalOperations > 0
        ? (this.performanceMetrics.filter((metric) => metric.errorCount > 0).length /
            totalOperations) *
          100
        : 0;

    const recommendations = this.generateRecommendations();

    return {
      summary: {
        totalIssues: this.issues.size,
        issuesByLevel,
        issuesByCategory,
        performanceMetrics: {
          totalOperations,
          averageDuration,
          slowestOperation,
          errorRate,
        },
      },
      recentIssues: Array.from(this.issues.values())
        .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
        .slice(0, 10),
      performanceIssues: this.performanceMetrics
        .filter((metric) => metric.duration > 100 || metric.errorCount > 0)
        .sort((a, b) => b.duration - a.duration),
      recommendations,
    };
  }

  /**
   * Clear all debug data
   */
  clearDebugData(): void {
    this.issues.clear();
    this.performanceMetrics = [];
    this.activeContexts.clear();
    this.sessionId = this.generateSessionId();
  }

  /**
   * Export debug data for analysis
   */
  exportDebugData(): {
    sessionId: string;
    exportTime: Date;
    issues: DebugIssue[];
    performanceMetrics: ValidationPerformanceMetrics[];
    summary: unknown;
  } {
    return {
      sessionId: this.sessionId,
      exportTime: new Date(),
      issues: Array.from(this.issues.values()),
      performanceMetrics: [...this.performanceMetrics],
      summary: this.generateDebugReport().summary,
    };
  }

  // Private helper methods

  private generateSessionId(): string {
    return `debug_session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateIssueId(): string {
    return `issue_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateOperationId(): string {
    return `operation_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private inferType(value: unknown): string {
    if (value === null) return 'null';
    if (value === undefined) return 'undefined';
    if (Array.isArray(value)) return 'array';
    if (value instanceof Date) return 'date';
    if (typeof value === 'object') return 'object';
    return typeof value;
  }

  private checkTypeCompatibility(actual: string, expected: string): boolean {
    if (actual === expected) return true;

    // Handle some common compatible types
    if (actual === 'number' && expected === 'integer') {
      return Number.isInteger(Number(actual));
    }

    if (actual === 'object' && expected === 'record') {
      return true;
    }

    return false;
  }

  private calculateMatchConfidence(actual: string, expected: string): number {
    if (actual === expected) return 1.0;
    if (this.checkTypeCompatibility(actual, expected)) return 0.8;
    if (actual === 'object' && expected === 'array') return 0.3;
    if (actual === 'array' && expected === 'object') return 0.3;
    return 0.0;
  }

  private createTypeMismatchIssue(
    actual: string,
    expected: string,
    context?: Record<string, unknown>
  ): DebugIssue {
    return {
      id: this.generateIssueId(),
      level: DebugLevel.ERROR,
      category: DebugCategory.TYPE_CHECK,
      title: 'Type Mismatch',
      description: `Expected type '${expected}' but got '${actual}'`,
      timestamp: new Date(),
      context,
      suggestedFixes: [
        `Ensure the value matches the expected type: ${expected}`,
        'Check if the value was properly parsed or converted',
        'Verify the source of the value is providing the correct type',
      ],
      documentationLinks: [
        'https://www.typescriptlang.org/docs/handbook/basic-types.html',
        'https://www.typescriptlang.org/docs/handbook/type-compatibility.html',
      ],
    };
  }

  private createNullUndefinedIssue(
    value: unknown,
    expectedType: string,
    context?: Record<string, unknown>
  ): DebugIssue {
    const valueType = value === null ? 'null' : 'undefined';
    return {
      id: this.generateIssueId(),
      level: DebugLevel.WARN,
      category: DebugCategory.VALIDATION,
      title: `${valueType === 'null' ? 'Null' : 'Undefined'} Value`,
      description: `Received ${valueType} value when expecting '${expectedType}'`,
      timestamp: new Date(),
      context,
      suggestedFixes: [
        'Provide a default value',
        'Make the field optional',
        'Add null/undefined checks in your code',
        'Use optional chaining (?.) to safely access the value',
      ],
    };
  }

  private analyzeObjectIssues(
    obj: Record<string, unknown>,
    expectedType: string,
    context?: Record<string, unknown>
  ): DebugIssue[] {
    const issues: DebugIssue[] = [];

    // Check for empty object
    if (Object.keys(obj).length === 0) {
      issues.push({
        id: this.generateIssueId(),
        level: DebugLevel.WARN,
        category: DebugCategory.VALIDATION,
        title: 'Empty Object',
        description: 'Object has no properties',
        timestamp: new Date(),
        context,
        suggestedFixes: [
          'Verify the object should be empty',
          'Check if data was properly loaded',
          'Provide default properties',
        ],
      });
    }

    // Check for circular references
    try {
      JSON.stringify(obj);
    } catch (error) {
      if (error instanceof Error && error.message.includes('circular')) {
        issues.push({
          id: this.generateIssueId(),
          level: DebugLevel.ERROR,
          category: DebugCategory.RUNTIME,
          title: 'Circular Reference',
          description: 'Object contains circular references that cannot be serialized',
          timestamp: new Date(),
          context,
          suggestedFixes: [
            'Remove circular references',
            'Use a custom replacer function for JSON.stringify',
            'Restructure the data to avoid circular references',
          ],
        });
      }
    }

    return issues;
  }

  private createRangeIssue(
    key: string,
    value: number,
    issue: string,
    min?: number,
    max?: number
  ): DebugIssue {
    return {
      id: this.generateIssueId(),
      level: DebugLevel.ERROR,
      category: DebugCategory.VALIDATION,
      title: 'Value Out of Range',
      description: `Value ${value} for '${key}' is ${issue}${min !== undefined ? ` (min: ${min})` : ''}${max !== undefined ? ` (max: ${max})` : ''}`,
      timestamp: new Date(),
      context: { key, value, min, max },
      suggestedFixes: [
        `Ensure the value is within the allowed range`,
        'Add validation before setting the value',
        'Use clamp functions to constrain values',
      ],
    };
  }

  private createPatternIssue(key: string, value: string, pattern: string): DebugIssue {
    return {
      id: this.generateIssueId(),
      level: DebugLevel.ERROR,
      category: DebugCategory.VALIDATION,
      title: 'Pattern Mismatch',
      description: `Value '${value}' for '${key}' does not match pattern: ${pattern}`,
      timestamp: new Date(),
      context: { key, value, pattern },
      suggestedFixes: [
        'Update the value to match the expected pattern',
        'Verify the pattern is correct',
        'Use proper validation libraries for complex patterns',
      ],
    };
  }

  private createEnumIssue(key: string, value: unknown, enumValues: unknown[]): DebugIssue {
    return {
      id: this.generateIssueId(),
      level: DebugLevel.ERROR,
      category: DebugCategory.VALIDATION,
      title: 'Invalid Enum Value',
      description: `Value '${value}' for '${key}' is not one of the allowed values: ${enumValues.join(', ')}`,
      timestamp: new Date(),
      context: { key, value, enumValues },
      suggestedFixes: [
        `Use one of the allowed values: ${enumValues.join(', ')}`,
        'Check if the enum definition is up to date',
        'Verify the value source is providing valid options',
      ],
    };
  }

  private createMissingPropertyIssue(key: string, rule: unknown): DebugIssue {
    return {
      id: this.generateIssueId(),
      level: DebugLevel.ERROR,
      category: DebugCategory.VALIDATION,
      title: 'Missing Required Property',
      description: `Required property '${key}' is missing`,
      timestamp: new Date(),
      context: { key, rule },
      suggestedFixes: [
        `Provide a value for '${key}'`,
        'Add a default value in the configuration',
        'Make the property optional if appropriate',
      ],
    };
  }

  private createExtraPropertyIssue(key: string, value: unknown): DebugIssue {
    return {
      id: this.generateIssueId(),
      level: DebugLevel.WARN,
      category: DebugCategory.VALIDATION,
      title: 'Extra Property',
      description: `Unexpected property '${key}' found in configuration`,
      timestamp: new Date(),
      context: { key, value },
      suggestedFixes: [
        `Remove the extra property '${key}'`,
        'Add the property to the validation schema if it should be allowed',
        'Update the schema to accept additional properties',
      ],
    };
  }

  private createValidationRuleError(key: string, rule: unknown, error: unknown): DebugIssue {
    return {
      id: this.generateIssueId(),
      level: DebugLevel.ERROR,
      category: DebugCategory.RUNTIME,
      title: 'Validation Rule Error',
      description: `Error validating property '${key}': ${error instanceof Error ? error.message : String(error)}`,
      timestamp: new Date(),
      context: { key, rule, error: String(error) },
      suggestedFixes: [
        'Fix the validation rule definition',
        'Check for syntax errors in the rule',
        'Ensure rule validators are properly implemented',
      ],
    };
  }

  private generateTypeFixSuggestions(
    actual: string,
    expected: string,
    issues: DebugIssue[]
  ): string[] {
    const suggestions: string[] = [];

    if (actual === 'string' && expected === 'number') {
      suggestions.push('Use parseInt() or parseFloat() to convert string to number');
      suggestions.push('Ensure the string contains only numeric characters');
    }

    if (actual === 'number' && expected === 'string') {
      suggestions.push('Use toString() to convert number to string');
      suggestions.push('Use template literals for string formatting');
    }

    if (actual === 'object' && expected === 'array') {
      suggestions.push('Use Object.values() to convert object values to array');
      suggestions.push('Check if the data structure should be an array instead');
    }

    if (actual === 'array' && expected === 'object') {
      suggestions.push('Use Object.fromEntries() or array reduce to convert to object');
      suggestions.push('Verify the data structure should be an object instead');
    }

    suggestions.push(...issues.flatMap((issue) => issue.suggestedFixes || []));

    return suggestions;
  }

  private generateCodeExamples(actual: string, expected: string): CodeExample[] {
    const examples: CodeExample[] = [];

    if (actual === 'string' && expected === 'number') {
      examples.push({
        title: 'String to Number Conversion',
        description: 'Convert string to number safely',
        before: 'const age: string = "25";',
        after: 'const age: number = parseInt("25", 10);',
        explanation: 'Use parseInt() with radix to convert string to integer',
      });
    }

    if (actual === 'object' && expected === 'array') {
      examples.push({
        title: 'Object to Array Conversion',
        description: 'Extract values from object into array',
        before: 'const data = { a: 1, b: 2, c: 3 };',
        after: 'const data = [1, 2, 3]; // or const values = Object.values(data);',
        explanation: 'Use Object.values() to get array of object values',
      });
    }

    return examples;
  }

  private startPerformanceTracking(operationId: string, operation: string): void {
    const metric: ValidationPerformanceMetrics = {
      operationId,
      operation,
      startTime: Date.now(),
      endTime: 0,
      duration: 0,
      inputSize: 0,
      validationCount: 0,
      successCount: 0,
      errorCount: 0,
    };

    this.performanceMetrics.push(metric);
  }

  private endPerformanceTracking(
    operationId: string,
    details: {
      inputSize?: number;
      validationCount?: number;
      successCount?: number;
      errorCount?: number;
    }
  ): void {
    const metricIndex = this.performanceMetrics.findIndex((m) => m.operationId === operationId);
    if (metricIndex !== -1) {
      const metric = this.performanceMetrics[metricIndex];
      const endTime = Date.now();
      const updatedMetric: ValidationPerformanceMetrics = {
        ...metric,
        endTime,
        duration: endTime - metric.startTime,
        inputSize: details.inputSize || 0,
        validationCount: details.validationCount || 0,
        successCount: details.successCount || 0,
        errorCount: details.errorCount || 0,
      };
      this.performanceMetrics[metricIndex] = updatedMetric;
    }
  }

  private logToConsole(issue: DebugIssue): void {
    const logMethod = this.getConsoleMethod(issue.level);
    const message = `[${issue.category.toUpperCase()}] ${issue.title}: ${issue.description}`;

    logMethod(message, {
      id: issue.id,
      timestamp: issue.timestamp,
      context: issue.context,
      suggestions: issue.suggestedFixes,
    });
  }

  private getConsoleMethod(level: DebugLevel): (...args: any[]) => void {
    switch (level) {
      case DebugLevel.TRACE:
      case DebugLevel.DEBUG:
        return console.debug;
      case DebugLevel.INFO:
        return console.info;
      case DebugLevel.WARN:
        return console.warn;
      case DebugLevel.ERROR:
      case DebugLevel.FATAL:
        return console.error;
      default:
        return console.log;
    }
  }

  private generateRecommendations(): string[] {
    const recommendations: string[] = [];
    const issues = Array.from(this.issues.values());

    // Type-related recommendations
    const typeIssues = issues.filter((issue) => issue.category === DebugCategory.TYPE_CHECK);
    if (typeIssues.length > 0) {
      recommendations.push(
        'Consider adding stricter type definitions to catch type mismatches early'
      );
      recommendations.push(
        'Review type annotations and consider using generic types for better type safety'
      );
    }

    // Performance recommendations
    const slowOperations = this.performanceMetrics.filter((metric) => metric.duration > 100);
    if (slowOperations.length > 0) {
      recommendations.push(
        'Some validation operations are taking longer than expected. Consider optimization'
      );
      recommendations.push(
        'Review validation rules for complexity and potential caching opportunities'
      );
    }

    // Error rate recommendations
    const errorRate =
      issues.filter((issue) => issue.level === DebugLevel.ERROR || issue.level === DebugLevel.FATAL)
        .length / Math.max(issues.length, 1);

    if (errorRate > 0.1) {
      recommendations.push('High error rate detected. Review input validation and error handling');
      recommendations.push('Consider implementing input sanitization and pre-validation');
    }

    // Configuration recommendations
    const configIssues = issues.filter((issue) => issue.category === DebugCategory.CONFIGURATION);
    if (configIssues.length > 0) {
      recommendations.push('Review configuration schemas and ensure they match actual usage');
      recommendations.push('Consider adding configuration validation at startup');
    }

    return recommendations;
  }
}

/**
 * Convenience functions for common debugging tasks
 */

/**
 * Quick type analysis
 */
export function debugType(value: unknown, expectedType?: string): TypeAnalysisResult {
  const typeDebugger = TypeDebugger.getInstance();
  return typeDebugger.analyzeTypeMismatch(value, expectedType || 'unknown', undefined, {
    timestamp: new Date().toISOString(),
  });
}

/**
 * Quick configuration validation with debugging
 */
export function debugConfig(
  config: Record<string, unknown>,
  schema: Record<string, unknown>
): { result: ValidationResult; debugInfo: DebugIssue[] } {
  const typeDebugger = TypeDebugger.getInstance();
  return typeDebugger.debugValidateConfig(config, schema);
}

/**
 * Get debug summary
 */
export function getDebugSummary(): ReturnType<TypeDebugger['generateDebugReport']> {
  const typeDebugger = TypeDebugger.getInstance();
  return typeDebugger.generateDebugReport();
}

/**
 * Clear all debug data
 */
export function clearDebugData(): void {
  const typeDebugger = TypeDebugger.getInstance();
  typeDebugger.clearDebugData();
}

/**
 * Export debug data
 */
export function exportDebugData(): ReturnType<TypeDebugger['exportDebugData']> {
  const typeDebugger = TypeDebugger.getInstance();
  return typeDebugger.exportDebugData();
}
