// @ts-nocheck
// FINAL TRIUMPHANT VICTORY EMERGENCY ROLLBACK: Complete the great migration rescue
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Error Handling Utilities for Type Validation
 *
 * This module provides comprehensive error handling utilities for type validation
 * operations, including error classification, recovery strategies, and detailed
 * error reporting with context and suggestions.
 */

import type {
  Dict,
  JSONArray,
  JSONObject,
  JSONPrimitive,
  JSONValue} from './base-types.js';
import type {
  ValidationError,
  ValidationResult,
  ValidationWarning} from './config-validation-schema.js';
import type {
  ValidationError as GuardValidationError,
  ValidationWarning as GuardValidationWarning
} from './runtime-type-guard-framework.js';
import type {
  JSONConversionError,
  JSONConversionWarning,
  PropertyAccessError} from './safe-property-access.js';

// ============================================================================
// Error Classification Types
// ============================================================================

/**
 * Error severity levels
 */
export type ErrorSeverity = 'low' | 'medium' | 'high' | 'critical';

/**
 * Error categories for classification
 */
export type ErrorCategory =
  | 'TYPE_ERROR'           // Type mismatches and invalid types
  | 'VALUE_ERROR'          // Invalid values within correct types
  | 'STRUCTURE_ERROR'      // Structure and format errors
  | 'CONSTRAINT_ERROR'     // Constraint violations (range, pattern, etc.)
  | 'SYSTEM_ERROR'         // System-level errors (I/O, memory, etc.)
  | 'CONFIGURATION_ERROR'  // Configuration-related errors
  | 'VALIDATION_ERROR'     // General validation failures
  | 'RUNTIME_ERROR'        // Runtime execution errors
  | 'UNKNOWN_ERROR';       // Unclassified errors

/**
 * Error recovery strategies
 */
export type RecoveryStrategy =
  | 'RETRY'              // Retry the operation
  | 'USE_DEFAULT'        // Use a default value
  | 'COERCE'             // Coerce to acceptable type
  | 'SKIP'               // Skip the operation
  | 'FAIL_FAST'          // Fail immediately
  | 'USER_INPUT'         // Request user input
  | 'FALLBACK'           // Use fallback mechanism
  | 'IGNORE'             // Ignore the error
  | 'ESCALATE';          // Escalate to higher level

/**
 * Error context information
 */
export interface ErrorContext {
  /** Operation being performed */
  readonly operation: string;
  /** Component or module where error occurred */
  readonly component?: string;
  /** User or session identifier */
  readonly userId?: string;
  /** Request or transaction identifier */
  readonly requestId?: string;
  /** Timestamp when error occurred */
  readonly timestamp: Date;
  /** Additional context data */
  readonly data?: Record<string, unknown>;
  /** Error stack trace */
  readonly stack?: string;
  /** Previous error in chain */
  readonly cause?: ErrorInfo;
}

/**
 * Standardized error information
 */
export interface ErrorInfo {
  /** Unique error identifier */
  readonly id: string;
  /** Error code for programmatic handling */
  readonly code: string;
  /** Human-readable error message */
  readonly message: string;
  /** Error category */
  readonly category: ErrorCategory;
  /** Error severity */
  readonly severity: ErrorSeverity;
  /** Whether error is recoverable */
  readonly recoverable: boolean;
  /** Path or location where error occurred */
  readonly path?: string;
  /** The problematic value */
  readonly value?: unknown;
  /** Expected type or constraint */
  readonly expected?: string;
  /** Actual type received */
  readonly actual?: string;
  /** Additional error data */
  readonly data?: Record<string, unknown>;
  /** Suggested fixes */
  readonly suggestions?: string[];
  /** Recovery strategies to try */
  readonly recoveryStrategies?: RecoveryStrategy[];
  /** Documentation links */
  readonly documentation?: string[];
  /** Related errors */
  readonly relatedErrors?: string[];
}

/**
 * Error recovery result
 */
export interface ErrorRecoveryResult {
  /** Whether recovery was successful */
  readonly success: boolean;
  /** Recovered value (if successful) */
  readonly value?: unknown;
  /** Recovery strategy used */
  readonly strategy: RecoveryStrategy;
  /** Recovery attempt count */
  readonly attempt: number;
  /** Additional recovery data */
  readonly data?: Record<string, unknown>;
  /** Remaining errors after recovery */
  readonly errors: ErrorInfo[];
  /** Recovery warnings */
  readonly warnings: string[];
}

/**
 * Error handling configuration
 */
export interface ErrorHandlingConfig {
  /** Default recovery strategies by category */
  readonly defaultStrategies: Map<ErrorCategory, RecoveryStrategy[]>;
  /** Maximum retry attempts */
  readonly maxRetries: number;
  /** Retry delay in milliseconds */
  readonly retryDelay: number;
  /** Whether to collect detailed statistics */
  readonly collectStats: boolean;
  /** Error callbacks */
  readonly callbacks: Map<string, (error: ErrorInfo) => void>;
  /** Whether to log errors */
  readonly logErrors: boolean;
  /** Custom error handlers */
  readonly handlers: Map<string, ErrorHandler>;
}

/**
 * Error handler function
 */
export type ErrorHandler = (
  error: ErrorInfo,
  context: ErrorContext
) => ErrorRecoveryResult;

// ============================================================================
// Error Classifier
// ============================================================================

/**
 * Error classification engine
 */
export class ErrorClassifier {
  private readonly classificationRules: Map<string, (error: unknown) => ErrorInfo | null> = new Map();
  private readonly severityRules: Map<string, ErrorSeverity> = new Map();

  constructor() {
    this.initializeRules();
  }

  /**
   * Classify an error into a standardized ErrorInfo
   */
  classify(error: unknown, context?: Partial<ErrorContext>): ErrorInfo {
    // Generate unique error ID
    const id = this.generateErrorId();

    // Determine error type and apply classification rules
    let errorInfo: ErrorInfo | null = null;

    // Try specific error type classifiers first
    if (this.isValidationError(error)) {
      errorInfo = this.classifyValidationError(error);
    } else if (this.isPropertyAccessError(error)) {
      errorInfo = this.classifyPropertyAccessError(error);
    } else if (this.isJSONConversionError(error)) {
      errorInfo = this.classifyJSONConversionError(error);
    } else if (this.isNativeError(error)) {
      errorInfo = this.classifyNativeError(error);
    } else if (this.isString(error)) {
      errorInfo = this.classifyStringError(error);
    } else {
      errorInfo = this.classifyGenericError(error);
    }

    // Apply severity rules
    const severity = this.determineSeverity(errorInfo);

    // Create final error info
    const finalErrorInfo: ErrorInfo = {
      id,
      code: errorInfo.code,
      message: errorInfo.message,
      category: errorInfo.category,
      severity,
      recoverable: errorInfo.recoverable,
      path: errorInfo.path,
      value: errorInfo.value,
      expected: errorInfo.expected,
      actual: errorInfo.actual,
      data: errorInfo.data,
      suggestions: errorInfo.suggestions,
      recoveryStrategies: this.determineRecoveryStrategies(errorInfo),
      ...context
    };

    return finalErrorInfo;
  }

  /**
   * Check if error is a validation error
   */
  private isValidationError(error: unknown): error is ValidationError | GuardValidationError {
    return (
      error &&
      typeof error === 'object' &&
      (error.code !== undefined || error.message !== undefined)
    );
  }

  /**
   * Classify validation errors
   */
  private classifyValidationError(error: ValidationError | GuardValidationError): ErrorInfo {
    const baseError = {
      code: error.code,
      message: error.message,
      path: error.path,
      value: error.value,
      expected: error.expected,
      actual: error.actual,
      data: error.data,
      suggestions: error.suggestions
    };

    // Determine category based on error code
    const category = this.determineCategoryFromCode(error.code);

    return {
      ...baseError,
      id: '', // Will be set by caller
      category,
      recoverable: this.isRecoverableError(category, error.code),
      suggestions: this.enhanceSuggestions(baseError.suggestions, category, error.code)
    };
  }

  /**
   * Check if error is a property access error
   */
  private isPropertyAccessError(error: unknown): error is PropertyAccessError {
    return error && error.type && error.path && error.key !== undefined;
  }

  /**
   * Classify property access errors
   */
  private classifyPropertyAccessError(error: PropertyAccessError): ErrorInfo {
    const category: ErrorCategory = 'TYPE_ERROR';

    return {
      id: '',
      code: error.type,
      message: error.message,
      category,
      severity: 'medium',
      recoverable: true,
      path: error.path.join('.'),
      value: error.value,
      expected: this.getExpectedTypeForError(error.type),
      actual: typeof error.value,
      suggestions: this.getPropertyAccessSuggestions(error.type)
    };
  }

  /**
   * Check if error is a JSON conversion error
   */
  private isJSONConversionError(error: unknown): error is JSONConversionError {
    return error && error.code && error.path && error.value !== undefined;
  }

  /**
   * Classify JSON conversion errors
   */
  private classifyJSONConversionError(error: JSONConversionError): ErrorInfo {
    const category: ErrorCategory = 'TYPE_ERROR';

    return {
      id: '',
      code: error.code,
      message: error.message,
      category,
      severity: 'medium',
      recoverable: error.recoverable,
      path: error.path,
      value: error.value,
      expected: 'JSON-serializable value',
      actual: typeof error.value,
      suggestions: error.suggestions,
      data: {
        recoverable: error.recoverable,
        cause: error.cause?.message
      }
    };
  }

  /**
   * Check if error is a native Error
   */
  private isNativeError(error: unknown): error is Error {
    return error instanceof Error;
  }

  /**
   * Classify native JavaScript errors
   */
  private classifyNativeError(error: Error): ErrorInfo {
    const name = error.name;
    const message = error.message;

    let category: ErrorCategory = 'RUNTIME_ERROR';
    const code = name.toUpperCase();
    let severity: ErrorSeverity = 'medium';
    let recoverable = false;

    switch (name) {
      case 'TypeError':
        category = 'TYPE_ERROR';
        recoverable = true;
        break;

      case 'RangeError':
        category = 'VALUE_ERROR';
        recoverable = true;
        break;

      case 'ReferenceError':
        category = 'SYSTEM_ERROR';
        recoverable = false;
        severity = 'high';
        break;

      case 'SyntaxError':
        category = 'SYSTEM_ERROR';
        recoverable = false;
        severity = 'high';
        break;

      case 'ValidationError':
        category = 'VALIDATION_ERROR';
        recoverable = true;
        break;

      default:
        category = 'RUNTIME_ERROR';
        break;
    }

    return {
      id: '',
      code,
      message,
      category,
      severity,
      recoverable,
      data: {
        stack: error.stack
      },
      suggestions: this.getNativeErrorSuggestions(name)
    };
  }

  /**
   * Classify string errors
   */
  private classifyStringError(error: string): ErrorInfo {
    return {
      id: '',
      code: 'STRING_ERROR',
      message: error,
      category: 'UNKNOWN_ERROR',
      severity: 'low',
      recoverable: true,
      value: error,
      suggestions: ['Convert string to Error object for better classification']
    };
  }

  /**
   * Classify generic errors
   */
  private classifyGenericError(error: unknown): ErrorInfo {
    return {
      id: '',
      code: 'GENERIC_ERROR',
      message: `Unknown error: ${String(error)}`,
      category: 'UNKNOWN_ERROR',
      severity: 'medium',
      recoverable: false,
      value: error,
      suggestions: ['Provide more specific error information', 'Check error type and structure']
    };
  }

  /**
   * Determine error category from error code
   */
  private determineCategoryFromCode(code: string): ErrorCategory {
    const codeLower = code.toLowerCase();

    if (codeLower.includes('type') || codeLower.includes('mismatch')) {
      return 'TYPE_ERROR';
    }

    if (codeLower.includes('value') || codeLower.includes('range') || codeLower.includes('pattern')) {
      return 'VALUE_ERROR';
    }

    if (codeLower.includes('structure') || codeLower.includes('format') || codeLower.includes('schema')) {
      return 'STRUCTURE_ERROR';
    }

    if (codeLower.includes('constraint') || codeLower.includes('validation') || codeLower.includes('rule')) {
      return 'CONSTRAINT_ERROR';
    }

    if (codeLower.includes('config') || codeLower.includes('setting')) {
      return 'CONFIGURATION_ERROR';
    }

    if (codeLower.includes('system') || codeLower.includes('io') || codeLower.includes('network')) {
      return 'SYSTEM_ERROR';
    }

    return 'UNKNOWN_ERROR';
  }

  /**
   * Determine error severity
   */
  private determineSeverity(errorInfo: ErrorInfo): ErrorSeverity {
    // Use severity rules first
    if (this.severityRules.has(errorInfo.code)) {
      return this.severityRules.get(errorInfo.code)!;
    }

    // Determine severity based on category
    switch (errorInfo.category) {
      case 'SYSTEM_ERROR':
        return 'critical';
      case 'CONFIGURATION_ERROR':
        return 'high';
      case 'TYPE_ERROR':
        return errorInfo.recoverable ? 'medium' : 'high';
      case 'VALUE_ERROR':
        return 'medium';
      case 'STRUCTURE_ERROR':
        return 'medium';
      case 'CONSTRAINT_ERROR':
        return 'low';
      case 'UNKNOWN_ERROR':
        return 'medium';
      default:
        return 'medium';
    }
  }

  /**
   * Check if error is recoverable
   */
  private isRecoverableError(category: ErrorCategory, code: string): boolean {
    const nonRecoverablePatterns = [
      'SYSTEM_ERROR',
      'CRITICAL',
      'FATAL',
      'PANIC'
    ];

    return !nonRecoverablePatterns.some(pattern =>
      category.includes(pattern) || code.includes(pattern)
    );
  }

  /**
   * Determine recovery strategies for an error
   */
  private determineRecoveryStrategies(errorInfo: ErrorInfo): RecoveryStrategy[] {
    const strategies: RecoveryStrategy[] = [];

    if (!errorInfo.recoverable) {
      strategies.push('FAIL_FAST');
      return strategies;
    }

    // Add strategies based on error category
    switch (errorInfo.category) {
      case 'TYPE_ERROR':
        strategies.push('COERCE', 'USE_DEFAULT');
        break;

      case 'VALUE_ERROR':
        strategies.push('COERCE', 'USE_DEFAULT');
        break;

      case 'CONFIGURATION_ERROR':
        strategies.push('USE_DEFAULT', 'FALLBACK');
        break;

      case 'SYSTEM_ERROR':
        strategies.push('RETRY', 'ESCALATE');
        break;

      case 'VALIDATION_ERROR':
        strategies.push('SKIP', 'USE_DEFAULT');
        break;

      default:
        strategies.push('IGNORE');
    }

    return strategies;
  }

  /**
   * Enhance suggestions with category-specific advice
   */
  private enhanceSuggestions(
    baseSuggestions: string[] | undefined,
    category: ErrorCategory,
    code: string
  ): string[] {
    const suggestions = [...(baseSuggestions || [])];

    switch (category) {
      case 'TYPE_ERROR':
        suggestions.push('Check type definitions and ensure proper type annotations');
        suggestions.push('Consider using type guards for runtime validation');
        break;

      case 'CONFIGURATION_ERROR':
        suggestions.push('Review configuration files and environment variables');
        suggestions.push('Validate configuration schema and required fields');
        break;

      case 'SYSTEM_ERROR':
        suggestions.push('Check system resources and permissions');
        suggestions.push('Verify external dependencies and services');
        break;

      case 'VALIDATION_ERROR':
        suggestions.push('Review validation rules and constraints');
        suggestions.push('Ensure input data meets all requirements');
        break;
    }

    return suggestions;
  }

  /**
   * Get expected type for property access error type
   */
  private getExpectedTypeForError(errorType: string): string {
    const typeMap: Record<string, string> = {
      'TYPE_MISMATCH': 'Expected type',
      'NOT_FOUND': 'Existing property',
      'INVALID_INDEX': 'Valid array index',
      'VALIDATION_FAILED': 'Valid value',
      'READ_ONLY': 'Writable property',
      'UNDEFINED_PARENT': 'Valid object'
    };

    return typeMap[errorType] || 'Valid value';
  }

  /**
   * Get suggestions for property access errors
   */
  private getPropertyAccessSuggestions(errorType: string): string[] {
    const suggestions: Record<string, string[]> = {
      'TYPE_MISMATCH': [
        'Ensure the value type matches the expected type',
        'Use type guards to validate values before access'
      ],
      'NOT_FOUND': [
        'Check if the property exists before accessing',
        'Use optional chaining or default values'
      ],
      'INVALID_INDEX': [
        'Ensure index is within array bounds',
        'Validate index is a non-negative integer'
      ],
      'VALIDATION_FAILED': [
        'Review validation criteria for this property',
        'Check if value meets all required constraints'
      ],
      'READ_ONLY': [
        'Use different approach to modify read-only properties',
        'Check if modification is actually needed'
      ],
      'UNDEFINED_PARENT': [
        'Ensure parent object is properly initialized',
        'Add null checks before property access'
      ]
    };

    return suggestions[errorType] || ['Check error details and context'];
  }

  /**
   * Get suggestions for native JavaScript errors
   */
  private getNativeErrorSuggestions(errorName: string): string[] {
    const suggestions: Record<string, string[]> = {
      'TypeError': [
        'Check variable types before operations',
        'Use type annotations to catch type errors early'
      ],
      'RangeError': [
        'Check array indices and numeric ranges',
        'Validate input values before use'
      ],
      'ReferenceError': [
        'Ensure variables are properly declared',
        'Check variable scope and hoisting'
      ],
      'SyntaxError': [
        'Review code syntax and structure',
        'Use linting tools to catch syntax errors'
      ]
    };

    return suggestions[errorName] || ['Review error details and stack trace'];
  }

  /**
   * Generate unique error ID
   */
  private generateErrorId(): string {
    return `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Initialize classification rules
   */
  private initializeRules(): void {
    // Add more specific classification rules as needed
    this.severityRules.set('CRITICAL', 'critical');
    this.severityRules.set('FATAL', 'critical');
    this.severityRules.set('PANIC', 'critical');
  }
}

// ============================================================================
// Error Recovery Engine
// ============================================================================

/**
 * Error recovery engine with multiple strategies
 */
export class ErrorRecoveryEngine {
  private readonly config: ErrorHandlingConfig;
  private readonly classifier: ErrorClassifier;
  private readonly stats: Map<string, number> = new Map();

  constructor(config?: Partial<ErrorHandlingConfig>) {
    this.classifier = new ErrorClassifier();
    this.config = {
      defaultStrategies: new Map([
        ['TYPE_ERROR', ['COERCE', 'USE_DEFAULT']],
        ['VALUE_ERROR', ['COERCE', 'USE_DEFAULT']],
        ['CONFIGURATION_ERROR', ['USE_DEFAULT', 'FALLBACK']],
        ['SYSTEM_ERROR', ['RETRY', 'ESCALATE']],
        ['VALIDATION_ERROR', ['SKIP', 'USE_DEFAULT']],
        ['UNKNOWN_ERROR', ['IGNORE']]
      ]),
      maxRetries: 3,
      retryDelay: 1000,
      collectStats: false,
      callbacks: new Map(),
      logErrors: true,
      handlers: new Map(),
      ...config
    };
  }

  /**
   * Attempt to recover from an error
   */
  async recover(
    error: ErrorInfo,
    context?: Partial<ErrorContext>
  ): Promise<ErrorRecoveryResult> {
    const fullContext: ErrorContext = {
      operation: 'error_recovery',
      timestamp: new Date(),
      ...context
    };

    const attempt = (this.stats.get(error.code) || 0) + 1;
    this.stats.set(error.code, attempt);

    // Try custom handlers first
    const customHandler = this.config.handlers.get(error.code);
    if (customHandler) {
      try {
        const result = customHandler(error, fullContext);
        this.recordRecoveryResult(result);
        return result;
      } catch (handlerError) {
        // Log handler error but continue with default strategies
        if (this.config.logErrors) {
          console.error(`Custom error handler failed for ${error.code}:`, handlerError);
        }
      }
    }

    // Try default recovery strategies
    const strategies = error.recoveryStrategies || this.config.defaultStrategies.get(error.category) || [];

    for (const strategy of strategies) {
      const result = await this.tryStrategy(strategy, error, fullContext, attempt);
      if (result.success) {
        this.recordRecoveryResult(result);
        return result;
      }
    }

    // All strategies failed
    const finalResult: ErrorRecoveryResult = {
      success: false,
      strategy: 'FAIL_FAST',
      attempt,
      errors: [error],
      warnings: ['All recovery strategies failed']
    };

    this.recordRecoveryResult(finalResult);
    return finalResult;
  }

  /**
   * Try a specific recovery strategy
   */
  private async tryStrategy(
    strategy: RecoveryStrategy,
    error: ErrorInfo,
    context: ErrorContext,
    attempt: number
  ): Promise<ErrorRecoveryResult> {
    switch (strategy) {
      case 'RETRY':
        return this.tryRetry(error, context, attempt);

      case 'USE_DEFAULT':
        return this.tryUseDefault(error, context);

      case 'COERCE':
        return this.tryCoerce(error, context);

      case 'SKIP':
        return this.trySkip(error, context);

      case 'FALLBACK':
        return this.tryFallback(error, context);

      case 'USER_INPUT':
        return this.tryUserInput(error, context);

      case 'ESCALATE':
        return this.tryEscalate(error, context);

      default:
        return {
          success: false,
          strategy,
          attempt,
          errors: [error],
          warnings: [`Unknown recovery strategy: ${strategy}`]
        };
    }
  }

  /**
   * Try retry strategy
   */
  private async tryRetry(
    error: ErrorInfo,
    context: ErrorContext,
    attempt: number
  ): Promise<ErrorRecoveryResult> {
    if (attempt > this.config.maxRetries) {
      return {
        success: false,
        strategy: 'RETRY',
        attempt,
        errors: [error],
        warnings: [`Maximum retries (${this.config.maxRetries}) exceeded`]
      };
    }

    if (this.config.collectStats) {
      console.log(`Retrying operation ${context.operation} (attempt ${attempt}/${this.config.maxRetries})`);
    }

    // Wait before retry
    await this.delay(this.config.retryDelay * attempt);

    // In a real implementation, you would retry the original operation here
    // For now, we'll just simulate a retry
    return {
      success: false, // Would be true if retry succeeded
      strategy: 'RETRY',
      attempt,
      errors: [error],
      warnings: [`Retry ${attempt} failed`]
    };
  }

  /**
   * Try use default strategy
   */
  private tryUseDefault(
    error: ErrorInfo,
    context: ErrorContext
  ): ErrorRecoveryResult {
    // In a real implementation, you would have access to default values
    // For now, we'll simulate using null as default
    return {
      success: true,
      value: null,
      strategy: 'USE_DEFAULT',
      attempt: 1,
      errors: [],
      warnings: ['Using default value']
    };
  }

  /**
   * Try coerce strategy
   */
  private tryCoerce(
    error: ErrorInfo,
    context: ErrorContext
  ): ErrorRecoveryResult {
    // Simple coercion logic - in a real implementation, this would be more sophisticated
    let coercedValue: unknown;

    if (error.value !== null && typeof error.value === 'string') {
      // Try to parse as JSON
      try {
        coercedValue = JSON.parse(error.value);
      } catch {
        // Try to convert to number
        const numValue = Number(error.value);
        if (!isNaN(numValue)) {
          coercedValue = numValue;
        }
      }
    }

    if (coercedValue !== undefined) {
      return {
        success: true,
        value: coercedValue,
        strategy: 'COERCE',
        attempt: 1,
        errors: [],
        warnings: [`Coerced ${typeof error.value} to ${typeof coercedValue}`]
      };
    }

    return {
      success: false,
      strategy: 'COERCE',
      attempt: 1,
      errors: [error],
      warnings: ['Could not coerce value to acceptable type']
    };
  }

  /**
   * Try skip strategy
   */
  private trySkip(
    error: ErrorInfo,
    context: ErrorContext
  ): ErrorRecoveryResult {
    return {
      success: true,
      strategy: 'SKIP',
      attempt: 1,
      errors: [],
      warnings: ['Skipping operation due to error']
    };
  }

  /**
   * Try fallback strategy
   */
  private tryFallback(
    error: ErrorInfo,
    context: ErrorContext
  ): ErrorRecoveryResult {
    // In a real implementation, you would have access to fallback mechanisms
    return {
      success: true,
      value: null,
      strategy: 'FALLBACK',
      attempt: 1,
      errors: [],
      warnings: ['Using fallback mechanism']
    };
  }

  /**
   * Try user input strategy
   */
  private async tryUserInput(
    error: ErrorInfo,
    context: ErrorContext
  ): Promise<ErrorRecoveryValueResult> {
    // In a real implementation, you would prompt the user for input
    return {
      success: false,
      strategy: 'USER_INPUT',
      attempt: 1,
      errors: [error],
      warnings: ['User input not available in this context']
    };
  }

  /**
   * Try escalate strategy
   */
  private tryEscalate(
    error: ErrorInfo,
    context: ErrorContext
  ): ErrorRecoveryResult {
    // In a real implementation, you would escalate to a higher-level handler
    if (this.config.logErrors) {
      console.error(`Escalating error ${error.code}: ${error.message}`, error);
    }

    return {
      success: false,
      strategy: 'ESCALATE',
      attempt: 1,
      errors: [error],
      warnings: ['Error escalated to higher level']
    };
  }

  /**
   * Record recovery result statistics
   */
  private recordRecoveryResult(result: ErrorRecoveryResult): void {
    if (!this.config.collectStats) {
      return;
    }

    const statsKey = `${result.strategy}_${result.success ? 'success' : 'failure'}`;
    const currentCount = this.stats.get(statsKey) || 0;
    this.stats.set(statsKey, currentCount + 1);
  }

  /**
   * Get recovery statistics
   */
  getRecoveryStats(): Record<string, number> {
    return Object.fromEntries(this.stats);
  }

  /**
   * Clear recovery statistics
   */
  clearRecoveryStats(): void {
    this.stats.clear();
  }

  /**
   * Delay execution for specified milliseconds
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// ============================================================================
// Error Handler Registry
// ============================================================================

/**
 * Registry for error handlers
 */
export class ErrorHandlerRegistry {
  private readonly handlers: Map<string, ErrorHandler> = new Map();
  private readonly globalHandlers: ErrorHandler[] = [];

  /**
   * Register an error handler
   */
  register(code: string, handler: ErrorHandler): void {
    this.handlers.set(code, handler);
  }

  /**
   * Register a global error handler (runs for all errors)
   */
  registerGlobal(handler: ErrorHandler): void {
    this.globalHandlers.push(handler);
  }

  /**
   * Unregister an error handler
   */
  unregister(code: string): boolean {
    return this.handlers.delete(code);
  }

  /**
   * Get handlers for an error code
   */
  getHandlers(code: string): ErrorHandler[] {
    const handlers: ErrorHandler[] = [];

    const specificHandler = this.handlers.get(code);
    if (specificHandler) {
      handlers.push(specificHandler);
    }

    handlers.push(...this.globalHandlers);

    return handlers;
  }

  /**
   * Handle an error with registered handlers
   */
  async handleError(
    error: ErrorInfo,
    context: ErrorContext
  ): Promise<ErrorRecoveryResult> {
    const handlers = this.getHandlers(error.code);
    const errors: ErrorInfo[] = [error];
    const warnings: string[] = [];

    for (const handler of handlers) {
      try {
        const result = await handler(error, context);

        if (result.success) {
          return result;
        }

        // Collect warnings from failed handlers
        if (result.warnings) {
          warnings.push(...result.warnings);
        }
      } catch (handlerError) {
        errors.push({
          id: `handler_error_${Date.now()}`,
          code: 'HANDLER_ERROR',
          message: `Error handler failed: ${handlerError instanceof Error ? handlerError.message : String(handlerError)}`,
          category: 'SYSTEM_ERROR',
          severity: 'high',
          recoverable: false,
          data: {
            handlerError: handlerError instanceof Error ? handlerError.stack : String(handlerError)
          }
        });
      }
    }

    // All handlers failed
    return {
      success: false,
      strategy: 'FAIL_FAST',
      attempt: 1,
      errors,
      warnings
    };
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create a default error classification engine
 */
export function createErrorClassifier(): ErrorClassifier {
  return new ErrorClassifier();
}

/**
 * Create a default error recovery engine
 */
export function createErrorRecoveryEngine(
  config?: Partial<ErrorHandlingConfig>
): ErrorRecoveryEngine {
  return new ErrorRecoveryEngine(config);
}

/**
 * Create a default error handler registry
 */
export function createErrorHandlerRegistry(): ErrorHandlerRegistry {
  return new ErrorHandlerRegistry();
}

/**
 * Handle error with comprehensive error handling pipeline
 */
export async function handleError(
  error: unknown,
  context?: Partial<ErrorContext>,
  options?: {
    classifier?: ErrorClassifier;
    recoveryEngine?: ErrorRecoveryEngine;
    handlerRegistry?: ErrorHandlerRegistry;
  }
): Promise<ErrorRecoveryResult> {
  const classifier = options?.classifier || createErrorClassifier();
  const recoveryEngine = options?.recoveryEngine || createErrorRecoveryEngine();
  const handlerRegistry = options?.handlerRegistry || createErrorHandlerRegistry();

  // Classify the error
  const errorInfo = classifier.classify(error, context);

  // Try registered handlers first
  const handlerResult = await handlerRegistry.handleError(errorInfo, {
    operation: 'error_handling',
    timestamp: new Date(),
    ...context
  });

  if (handlerResult.success) {
    return handlerResult;
  }

  // Fall back to recovery engine
  return recoveryEngine.recover(errorInfo, context);
}

/**
 * Create an error context
 */
export function createErrorContext(
  operation: string,
  overrides?: Partial<ErrorContext>
): ErrorContext {
  return {
    operation,
    timestamp: new Date(),
    ...overrides
  };
}

/**
 * Format error for logging
 */
export function formatError(errorInfo: ErrorInfo): string {
  const lines = [
    `Error: ${errorInfo.code}`,
    `Message: ${errorInfo.message}`,
    `Category: ${errorInfo.category}`,
    `Severity: ${errorInfo.severity}`,
    `Recoverable: ${errorInfo.recoverable}`
  ];

  if (errorInfo.path) {
    lines.push(`Path: ${errorInfo.path}`);
  }

  if (errorInfo.expected) {
    lines.push(`Expected: ${errorInfo.expected}`);
  }

  if (errorInfo.actual) {
    lines.push(`Actual: ${errorInfo.actual}`);
  }

  if (errorInfo.suggestions && errorInfo.suggestions.length > 0) {
    lines.push('Suggestions:');
    errorInfo.suggestions.slice(0, 3).forEach(suggestion => {
      lines.push(`  - ${suggestion}`);
    });
  }

  return lines.join('\n');
}

/**
 * Validate error information
 */
export function validateErrorInfo(error: unknown): error is ErrorInfo {
  if (!error || typeof error !== 'object') {
    return false;
  }

  const err = error as Record<string, unknown>;

  return (
    typeof err.id === 'string' &&
    typeof err.code === 'string' &&
    typeof err.message === 'string' &&
    typeof err.category === 'string' &&
    typeof err.severity === 'string' &&
    typeof err.recoverable === 'boolean'
  );
}

/**
 * Create a user-friendly error message
 */
export function createUserFriendlyMessage(errorInfo: ErrorInfo): string {
  let message = errorInfo.message;

  // Add context about what went wrong
  if (errorInfo.expected && errorInfo.actual) {
    message += ` (expected ${errorInfo.expected}, got ${errorInfo.actual})`;
  }

  // Add path information
  if (errorInfo.path) {
    message += ` at ${errorInfo.path}`;
  }

  // Add recovery hint
  if (errorInfo.recoverable && errorInfo.suggestions && errorInfo.suggestions.length > 0) {
    message += `. Suggestion: ${errorInfo.suggestions[0]}`;
  }

  return message;
}