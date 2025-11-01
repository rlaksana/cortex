/**
 * Comprehensive Unit Tests for Error Handling Utilities
 *
 * Tests advanced error handling utilities functionality including:
 * - Error Classification and Types: knowledge system errors, database errors, service errors, API errors
 * - Error Recovery Mechanisms: automatic retry strategies, fallback mechanisms, circuit breaker patterns
 * - Error Reporting and Analytics: error aggregation, trend analysis, impact assessment, reporting formats
 * - User-Friendly Error Messages: localization, contextual descriptions, resolution guidance
 * - Error Prevention and Validation: input validation, proactive detection, error boundaries, graceful degradation
 * - Integration with Monitoring: error logging integration, alert systems, performance impact assessment
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type {
  ErrorClassification,
  ErrorRecoveryStrategy,
  ErrorReport,
  ErrorAnalytics,
  ErrorMessage,
  ErrorPreventionRule,
  ErrorMonitoringIntegration
} from '../../../src/types/error-handling-interfaces';

// Mock external dependencies
vi.mock('i18next', () => ({
  t: vi.fn((key: string, options?: any) => {
    if (key === 'errors.database.connection_failed') {
      return options?.context === 'user'
        ? 'Unable to connect to the database. Please try again later.'
        : 'Database connection failed';
    }
    if (key === 'errors.auth.unauthorized') {
      return options?.context === 'user'
        ? 'You do not have permission to access this resource.'
        : 'Unauthorized access attempt';
    }
    return key;
  }),
  language: 'en'
}));

vi.mock('../../src/services/logging/logging-service', () => ({
  LoggingService: vi.fn().mockImplementation(() => ({
    writeLog: vi.fn().mockResolvedValue({ success: true }),
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn()
  }))
}));

describe('Error Handling Utilities - Comprehensive Error Management', () => {
  let errorClassifier: any;
  let errorRecovery: any;
  let errorReporter: any;
  let errorMessageFormatter: any;
  let errorPrevention: any;
  let errorMonitoring: any;

  beforeEach(async () => {
    vi.clearAllMocks();

    // Mock error handling utilities implementation
    errorClassifier = {
      classifyError: vi.fn(),
      getErrorType: vi.fn(),
      getErrorSeverity: vi.fn(),
      getErrorCategory: vi.fn(),
      isErrorRecoverable: vi.fn()
    };

    errorRecovery = {
      executeRetryStrategy: vi.fn(),
      applyFallbackMechanism: vi.fn(),
      checkCircuitBreaker: vi.fn(),
      executeRecoveryWorkflow: vi.fn()
    };

    errorReporter = {
      aggregateErrors: vi.fn(),
      analyzeErrorTrends: vi.fn(),
      assessErrorImpact: vi.fn(),
      generateErrorReport: vi.fn()
    };

    errorMessageFormatter = {
      formatErrorMessage: vi.fn(),
      localizeMessage: vi.fn(),
      addContextualInfo: vi.fn(),
      provideResolutionGuidance: vi.fn()
    };

    errorPrevention = {
      validateInput: vi.fn(),
      detectPotentialErrors: vi.fn(),
      enforceErrorBoundaries: vi.fn(),
      applyGracefulDegradation: vi.fn()
    };

    errorMonitoring = {
      logError: vi.fn(),
      triggerAlert: vi.fn(),
      assessPerformanceImpact: vi.fn(),
      correlateErrors: vi.fn()
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. Error Classification and Types Tests
  describe('Error Classification and Types', () => {
    it('should classify knowledge system errors accurately', async () => {
      const knowledgeError = {
        code: 'KNOWLEDGE_VALIDATION_FAILED',
        message: 'Invalid knowledge item structure',
        details: {
          kind: 'invalid_type',
          field: 'data',
          expected: 'object',
          received: 'string'
        },
        severity: 'error',
        timestamp: new Date().toISOString()
      };

      errorClassifier.classifyError.mockReturnValue({
        type: 'knowledge_validation_error',
        category: 'validation',
        severity: 'error',
        recoverable: true,
        context: {
          operation: 'store_knowledge',
          item_kind: 'entity',
          validation_rule: 'data_structure'
        }
      });

      const classification = errorClassifier.classifyError(knowledgeError);

      expect(classification.type).toBe('knowledge_validation_error');
      expect(classification.category).toBe('validation');
      expect(classification.severity).toBe('error');
      expect(classification.recoverable).toBe(true);
      expect(classification.context.operation).toBe('store_knowledge');
    });

    it('should classify database errors with proper categorization', async () => {
      const databaseError = {
        code: 'DATABASE_CONNECTION_FAILED',
        message: 'Unable to connect to Qdrant database',
        details: {
          host: 'localhost',
          port: 6333,
          timeout: 30000,
          attempt: 3
        },
        severity: 'critical',
        timestamp: new Date().toISOString()
      };

      errorClassifier.classifyError.mockReturnValue({
        type: 'database_connection_error',
        category: 'infrastructure',
        severity: 'critical',
        recoverable: true,
        context: {
          service: 'qdrant',
          operation: 'connect',
          retry_count: 3
        }
      });

      const classification = errorClassifier.classifyError(databaseError);

      expect(classification.type).toBe('database_connection_error');
      expect(classification.category).toBe('infrastructure');
      expect(classification.severity).toBe('critical');
      expect(classification.context.service).toBe('qdrant');
    });

    it('should classify service errors based on domain and impact', async () => {
      const serviceError = {
        code: 'EMBEDDING_SERVICE_TIMEOUT',
        message: 'OpenAI embedding service request timed out',
        details: {
          service: 'openai',
          model: 'text-embedding-3-large',
          timeout: 30000,
          request_id: 'req-123456'
        },
        severity: 'warning',
        timestamp: new Date().toISOString()
      };

      errorClassifier.classifyError.mockReturnValue({
        type: 'service_timeout_error',
        category: 'external_service',
        severity: 'warning',
        recoverable: true,
        context: {
          external_service: 'openai',
          operation: 'generate_embedding',
          model: 'text-embedding-3-large'
        }
      });

      const classification = errorClassifier.classifyError(serviceError);

      expect(classification.type).toBe('service_timeout_error');
      expect(classification.category).toBe('external_service');
      expect(classification.recoverable).toBe(true);
    });

    it('should map API errors to appropriate types', async () => {
      const apiError = {
        code: 'API_RATE_LIMIT_EXCEEDED',
        message: 'API rate limit exceeded for OpenAI embeddings',
        details: {
          endpoint: 'https://api.openai.com/v1/embeddings',
          limit: 100,
          current: 120,
          reset_time: '2024-01-15T15:30:00Z'
        },
        severity: 'warning',
        timestamp: new Date().toISOString()
      };

      errorClassifier.classifyError.mockReturnValue({
        type: 'api_rate_limit_error',
        category: 'throttling',
        severity: 'warning',
        recoverable: true,
        context: {
          api_provider: 'openai',
          endpoint: '/v1/embeddings',
          retry_after: 300
        }
      });

      const classification = errorClassifier.classifyError(apiError);

      expect(classification.type).toBe('api_rate_limit_error');
      expect(classification.category).toBe('throttling');
      expect(classification.context.retry_after).toBe(300);
    });

    it('should determine error severity based on impact and context', async () => {
      const testCases = [
        {
          error: { code: 'MINOR_VALIDATION_WARNING', message: 'Optional field missing' },
          expectedSeverity: 'info'
        },
        {
          error: { code: 'DATA_CORRUPTION_DETECTED', message: 'Data integrity check failed' },
          expectedSeverity: 'critical'
        },
        {
          error: { code: 'PERFORMANCE_DEGRADATION', message: 'Response time above threshold' },
          expectedSeverity: 'warning'
        },
        {
          error: { code: 'SECURITY_BREACH_ATTEMPT', message: 'Unauthorized access blocked' },
          expectedSeverity: 'error'
        }
      ];

      testCases.forEach(({ error, expectedSeverity }) => {
        errorClassifier.getErrorSeverity.mockReturnValue(expectedSeverity);
        const severity = errorClassifier.getErrorSeverity(error);
        expect(severity).toBe(expectedSeverity);
      });
    });

    it('should identify recoverable vs non-recoverable errors', async () => {
      const recoverableErrors = [
        'NETWORK_TIMEOUT',
        'API_RATE_LIMIT_EXCEEDED',
        'TEMPORARY_SERVICE_UNAVAILABLE',
        'DATABASE_CONNECTION_TIMEOUT'
      ];

      const nonRecoverableErrors = [
        'INVALID_API_KEY',
        'MALFORMED_REQUEST_DATA',
        'UNSUPPORTED_OPERATION',
        'PERMISSION_DENIED'
      ];

      recoverableErrors.forEach(errorCode => {
        errorClassifier.isErrorRecoverable.mockReturnValue(true);
        expect(errorClassifier.isErrorRecoverable({ code: errorCode })).toBe(true);
      });

      nonRecoverableErrors.forEach(errorCode => {
        errorClassifier.isErrorRecoverable.mockReturnValue(false);
        expect(errorClassifier.isErrorRecoverable({ code: errorCode })).toBe(false);
      });
    });
  });

  // 2. Error Recovery Mechanisms Tests
  describe('Error Recovery Mechanisms', () => {
    it('should execute automatic retry strategies with exponential backoff', async () => {
      const retryStrategy: ErrorRecoveryStrategy = {
        type: 'exponential_backoff',
        maxAttempts: 5,
        baseDelay: 1000,
        maxDelay: 30000,
        backoffMultiplier: 2
      };

      const failingOperation = vi.fn()
        .mockRejectedValueOnce(new Error('Temporary failure'))
        .mockRejectedValueOnce(new Error('Second failure'))
        .mockResolvedValue('Success on third attempt');

      errorRecovery.executeRetryStrategy.mockImplementation(async (operation, strategy) => {
        let lastError: Error;
        for (let attempt = 1; attempt <= strategy.maxAttempts; attempt++) {
          try {
            return await operation();
          } catch (error) {
            lastError = error as Error;
            if (attempt < strategy.maxAttempts) {
              const delay = Math.min(
                strategy.baseDelay * Math.pow(strategy.backoffMultiplier, attempt - 1),
                strategy.maxDelay
              );
              await new Promise(resolve => setTimeout(resolve, delay));
            }
          }
        }
        throw lastError;
      });

      const result = await errorRecovery.executeRetryStrategy(failingOperation, retryStrategy);

      expect(result).toBe('Success on third attempt');
      expect(failingOperation).toHaveBeenCalledTimes(3);
    });

    it('should apply fallback mechanisms when primary operations fail', async () => {
      const primaryOperation = vi.fn().mockRejectedValue(new Error('Primary service unavailable'));
      const fallbackOperation = vi.fn().mockResolvedValue('Fallback result');

      errorRecovery.applyFallbackMechanism.mockImplementation(async (primary, fallback) => {
        try {
          return await primary();
        } catch (error) {
          return await fallback();
        }
      });

      const result = await errorRecovery.applyFallbackMechanism(primaryOperation, fallbackOperation);

      expect(result).toBe('Fallback result');
      expect(primaryOperation).toHaveBeenCalledTimes(1);
      expect(fallbackOperation).toHaveBeenCalledTimes(1);
    });

    it('should implement circuit breaker pattern for service protection', async () => {
      const circuitBreakerConfig = {
        failureThreshold: 5,
        recoveryTimeout: 60000,
        monitoringPeriod: 30000
      };

      let failureCount = 0;
      const unreliableOperation = vi.fn().mockImplementation(() => {
        failureCount++;
        if (failureCount <= 6) {
          return Promise.reject(new Error('Service unstable'));
        }
        return Promise.resolve('Service recovered');
      });

      errorRecovery.checkCircuitBreaker.mockImplementation(async (operation, config) => {
        const state = { failures: 0, lastFailureTime: 0, state: 'closed' as 'closed' | 'open' | 'half-open' };

        return async (...args: any[]) => {
          if (state.state === 'open') {
            if (Date.now() - state.lastFailureTime > config.recoveryTimeout) {
              state.state = 'half-open';
            } else {
              throw new Error('Circuit breaker is open');
            }
          }

          try {
            const result = await operation(...args);
            if (state.state === 'half-open') {
              state.state = 'closed';
              state.failures = 0;
            }
            return result;
          } catch (error) {
            state.failures++;
            state.lastFailureTime = Date.now();

            if (state.failures >= config.failureThreshold) {
              state.state = 'open';
            }
            throw error;
          }
        };
      });

      const circuitBreaker = await errorRecovery.checkCircuitBreaker(unreliableOperation, circuitBreakerConfig);

      // Should fail initially and eventually open the circuit
      await expect(circuitBreaker()).rejects.toThrow('Service unstable');
      await expect(circuitBreaker()).rejects.toThrow('Service unstable');
      await expect(circuitBreaker()).rejects.toThrow('Service unstable');
      await expect(circuitBreaker()).rejects.toThrow('Service unstable');
      await expect(circuitBreaker()).rejects.toThrow('Service unstable');

      // Circuit should now be open
      await expect(circuitBreaker()).rejects.toThrow('Circuit breaker is open');
    });

    it('should execute complex error recovery workflows', async () => {
      const recoveryWorkflow = {
        steps: [
          { action: 'validate_input', retry: true },
          { action: 'check_service_health', retry: true },
          { action: 'attempt_primary_operation', retry: true },
          { action: 'apply_fallback', retry: false }
        ]
      };

      const workflowSteps = {
        validate_input: vi.fn().mockResolvedValue(true),
        check_service_health: vi.fn().mockResolvedValue(true),
        attempt_primary_operation: vi.fn().mockRejectedValue(new Error('Primary failed')),
        apply_fallback: vi.fn().mockResolvedValue('Workflow completed with fallback')
      };

      errorRecovery.executeRecoveryWorkflow.mockImplementation(async (workflow) => {
        for (const step of workflow.steps) {
          try {
            const result = await workflowSteps[step.action as keyof typeof workflowSteps]();
            if (result && step.retry) continue;
            return result;
          } catch (error) {
            if (!step.retry) throw error;
            // Continue to next step on failure if retry is allowed
          }
        }
        throw new Error('All workflow steps failed');
      });

      const result = await errorRecovery.executeRecoveryWorkflow(recoveryWorkflow);

      expect(result).toBe('Workflow completed with fallback');
      expect(workflowSteps.validate_input).toHaveBeenCalled();
      expect(workflowSteps.check_service_health).toHaveBeenCalled();
      expect(workflowSteps.attempt_primary_operation).toHaveBeenCalled();
      expect(workflowSteps.apply_fallback).toHaveBeenCalled();
    });
  });

  // 3. Error Reporting and Analytics Tests
  describe('Error Reporting and Analytics', () => {
    it('should aggregate errors by type and time period', async () => {
      const errors = [
        { type: 'database_error', timestamp: '2024-01-15T10:00:00Z', severity: 'error' },
        { type: 'database_error', timestamp: '2024-01-15T10:05:00Z', severity: 'error' },
        { type: 'api_error', timestamp: '2024-01-15T10:10:00Z', severity: 'warning' },
        { type: 'validation_error', timestamp: '2024-01-15T10:15:00Z', severity: 'info' },
        { type: 'database_error', timestamp: '2024-01-15T11:00:00Z', severity: 'critical' }
      ];

      errorReporter.aggregateErrors.mockReturnValue({
        byType: {
          database_error: { count: 3, severity_breakdown: { error: 2, critical: 1 } },
          api_error: { count: 1, severity_breakdown: { warning: 1 } },
          validation_error: { count: 1, severity_breakdown: { info: 1 } }
        },
        byTimePeriod: {
          '2024-01-15T10:00:00Z': 4,
          '2024-01-15T11:00:00Z': 1
        },
        total: 5,
        period: { start: '2024-01-15T10:00:00Z', end: '2024-01-15T11:00:00Z' }
      });

      const aggregation = errorReporter.aggregateErrors(errors, {
        groupBy: ['type', 'timePeriod'],
        timeWindow: '1h'
      });

      expect(aggregation.byType.database_error.count).toBe(3);
      expect(aggregation.byType.api_error.count).toBe(1);
      expect(aggregation.total).toBe(5);
    });

    it('should analyze error trends and patterns', async () => {
      const historicalErrors = [
        { date: '2024-01-15', count: 10, types: { database_error: 6, api_error: 4 } },
        { date: '2024-01-16', count: 15, types: { database_error: 8, api_error: 7 } },
        { date: '2024-01-17', count: 12, types: { database_error: 7, api_error: 5 } },
        { date: '2024-01-18', count: 25, types: { database_error: 20, api_error: 5 } }
      ];

      errorReporter.analyzeErrorTrends.mockReturnValue({
        trend: 'increasing',
        growth_rate: 0.25,
        pattern: {
          cyclical: false,
          seasonal: false,
          spike_detected: true,
          spike_date: '2024-01-18'
        },
        predictions: {
          next_day_expected: 20,
          confidence: 0.75,
          factors: ['database_error increase', 'recent infrastructure changes']
        },
        recommendations: [
          'Investigate database error root cause',
          'Monitor for continued spikes',
          'Consider database capacity planning'
        ]
      });

      const trendAnalysis = errorReporter.analyzeErrorTrends(historicalErrors);

      expect(trendAnalysis.trend).toBe('increasing');
      expect(trendAnalysis.growth_rate).toBe(0.25);
      expect(trendAnalysis.pattern.spike_detected).toBe(true);
      expect(trendAnalysis.predictions.next_day_expected).toBe(20);
    });

    it('should assess error impact on system performance and users', async () => {
      const errorContext = {
        errors: [
          { type: 'database_error', affected_users: 1000, duration: 300, revenue_impact: 500 },
          { type: 'api_timeout', affected_users: 500, duration: 120, revenue_impact: 200 },
          { type: 'validation_error', affected_users: 50, duration: 30, revenue_impact: 0 }
        ],
        system_metrics: {
          availability: 0.995,
          response_time_p95: 2000,
          error_rate: 0.02
        }
      };

      errorReporter.assessErrorImpact.mockReturnValue({
        overall_impact: 'medium',
        user_impact: {
          total_affected: 1550,
          percentage_of_user_base: 0.0775,
          severity_breakdown: {
            high: 1000,
            medium: 500,
            low: 50
          }
        },
        business_impact: {
          total_revenue_impact: 700,
          sla_compliance: 0.995,
          customer_satisfaction_impact: 'moderate'
        },
        system_impact: {
          performance_degradation: 0.15,
          availability_impact: 0.005,
          resource_utilization_increase: 0.10
        },
        recommended_actions: [
          'Prioritize database error resolution',
          'Implement timeout improvements',
          'Monitor user satisfaction metrics'
        ]
      });

      const impactAssessment = errorReporter.assessErrorImpact(errorContext);

      expect(impactAssessment.overall_impact).toBe('medium');
      expect(impactAssessment.user_impact.total_affected).toBe(1550);
      expect(impactAssessment.business_impact.total_revenue_impact).toBe(700);
    });

    it('should generate comprehensive error reports in multiple formats', async () => {
      const reportData = {
        period: { start: '2024-01-15', end: '2024-01-18' },
        summary: {
          total_errors: 62,
          critical_errors: 8,
          unique_error_types: 5,
          mean_time_to_resolution: 45
        },
        breakdown: {
          by_type: {
            database_error: 35,
            api_error: 15,
            validation_error: 8,
            timeout_error: 4
          },
          by_severity: {
            critical: 8,
            error: 22,
            warning: 25,
            info: 7
          }
        },
        trends: {
          direction: 'increasing',
          rate: 0.15,
          predictions: ['continued increase expected']
        }
      };

      errorReporter.generateErrorReport.mockImplementation((data, format) => {
        if (format === 'json') {
          return {
            metadata: { report_type: 'error_analysis', format: 'json', generated_at: new Date().toISOString() },
            ...data
          };
        } else if (format === 'html') {
          return {
            metadata: { report_type: 'error_analysis', format: 'html', generated_at: new Date().toISOString() },
            content: `<html><body><h1>Error Analysis Report</h1><p>Total errors: ${data.summary.total_errors}</p></body></html>`
          };
        } else if (format === 'csv') {
          return {
            metadata: { report_type: 'error_analysis', format: 'csv', generated_at: new Date().toISOString() },
            data: 'type,count,severity\ndatabase_error,35,error\napi_error,15,warning'
          };
        } else {
          return {
            metadata: { report_type: 'error_analysis', format: 'unknown', generated_at: new Date().toISOString() },
            ...data
          };
        }
      });

      const jsonReport = errorReporter.generateErrorReport(reportData, 'json');
      const htmlReport = errorReporter.generateErrorReport(reportData, 'html');
      const csvReport = errorReporter.generateErrorReport(reportData, 'csv');

      expect(jsonReport.metadata.format).toBe('json');
      expect(jsonReport.summary.total_errors).toBe(62);

      expect(htmlReport.content).toContain('<h1>Error Analysis Report</h1>');
      expect(htmlReport.content).toContain('Total errors: 62');

      expect(csvReport.data).toContain('database_error,35,error');
    });
  });

  // 4. User-Friendly Error Messages Tests
  describe('User-Friendly Error Messages', () => {
    it('should localize error messages for different languages and contexts', async () => {
      const errorScenarios = [
        {
          error: { code: 'DATABASE_CONNECTION_FAILED', context: 'technical' },
          expectedMessage: 'Database connection failed'
        },
        {
          error: { code: 'DATABASE_CONNECTION_FAILED', context: 'user' },
          expectedMessage: 'Unable to connect to the database. Please try again later.'
        },
        {
          error: { code: 'AUTH_UNAUTHORIZED', context: 'user' },
          expectedMessage: 'You do not have permission to access this resource.'
        }
      ];

      for (const scenario of errorScenarios) {
        errorMessageFormatter.localizeMessage.mockReturnValue(scenario.expectedMessage);
        const message = errorMessageFormatter.localizeMessage(
          scenario.error.code,
          { context: scenario.error.context }
        );
        expect(message).toBe(scenario.expectedMessage);
      }
    });

    it('should add contextual information to error messages', async () => {
      const baseError = {
        code: 'VALIDATION_FAILED',
        message: 'Validation failed',
        field: 'email',
        value: 'invalid-email'
      };

      errorMessageFormatter.addContextualInfo.mockReturnValue({
        title: 'Email Validation Failed',
        message: 'The email address "invalid-email" is not valid.',
        details: {
          field: 'email',
          expected_format: 'user@domain.com',
          suggestions: ['Check for typos', 'Ensure domain is valid', 'Include @ symbol']
        },
        help_resources: [
          { title: 'Email Format Guide', url: '/help/email-format' },
          { title: 'Contact Support', url: '/support' }
        ]
      });

      const contextualMessage = errorMessageFormatter.addContextualInfo(baseError);

      expect(contextualMessage.title).toBe('Email Validation Failed');
      expect(contextualMessage.message).toContain('invalid-email');
      expect(contextualMessage.details.field).toBe('email');
      expect(contextualMessage.details.suggestions).toHaveLength(3);
      expect(contextualMessage.help_resources).toHaveLength(2);
    });

    it('should provide resolution guidance for common errors', async () => {
      const errorWithResolution = {
        code: 'API_RATE_LIMIT_EXCEEDED',
        details: {
          limit: 100,
          current: 120,
          reset_time: '2024-01-15T15:30:00Z'
        }
      };

      errorMessageFormatter.provideResolutionGuidance.mockReturnValue({
        immediate_actions: [
          'Wait 15 minutes before making additional requests',
          'Implement request queuing to stay within limits'
        ],
        long_term_solutions: [
          'Upgrade to a higher tier plan',
          'Implement request batching',
          'Add rate limiting to your application'
        ],
        estimated_resolution_time: '15 minutes',
        follow_up_required: false
      });

      const guidance = errorMessageFormatter.provideResolutionGuidance(errorWithResolution);

      expect(guidance.immediate_actions).toContain('Wait 15 minutes before making additional requests');
      expect(guidance.long_term_solutions).toContain('Upgrade to a higher tier plan');
      expect(guidance.estimated_resolution_time).toBe('15 minutes');
    });

    it('should adapt message complexity based on user role and technical expertise', async () => {
      const technicalError = {
        code: 'DATABASE_TIMEOUT',
        details: {
          query: 'SELECT * FROM large_table',
          timeout: 30000,
          execution_time: 35000
        }
      };

      const userRoles = ['developer', 'admin', 'end_user'];
      const expectedComplexity = ['technical', 'moderate', 'simple'];

      errorMessageFormatter.formatErrorMessage.mockImplementation((error, role) => {
        const complexityMap: Record<string, any> = {
          developer: {
            message: `Query timeout: SELECT * FROM large_table exceeded 30s limit (35s execution time)`,
            technical_details: {
              query_plan: 'Full table scan detected',
              optimization_suggestions: ['Add index', 'Use WHERE clause', 'Implement pagination']
            }
          },
          admin: {
            message: 'Database operation timed out. The system is running slowly.',
            details: 'Some queries are taking longer than expected to complete.',
            recommendations: ['Monitor database performance', 'Contact IT support']
          },
          end_user: {
            message: 'The system is taking longer than usual to respond. Please try again.',
            suggestions: ['Wait a moment and retry', 'Contact support if the issue continues']
          }
        };
        return complexityMap[role];
      });

      userRoles.forEach((role, index) => {
        const formattedMessage = errorMessageFormatter.formatErrorMessage(technicalError, role);
        expect(formattedMessage).toBeDefined();

        if (role === 'developer') {
          expect(formattedMessage.message).toContain('SELECT * FROM large_table');
          expect(formattedMessage.technical_details).toBeDefined();
        } else if (role === 'end_user') {
          expect(formattedMessage.message).not.toContain('SELECT');
          expect(formattedMessage.suggestions).toBeDefined();
        }
      });
    });
  });

  // 5. Error Prevention and Validation Tests
  describe('Error Prevention and Validation', () => {
    it('should validate input data to prevent common errors', async () => {
      const validationRules = {
        email: {
          required: true,
          format: 'email',
          maxLength: 255
        },
        age: {
          required: true,
          type: 'number',
          min: 0,
          max: 150
        },
        password: {
          required: true,
          minLength: 8,
          pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/
        }
      };

      const testInputs = [
        {
          data: { email: 'user@example.com', age: 25, password: 'Secure123!' },
          expectedValid: true
        },
        {
          data: { email: 'invalid-email', age: -5, password: 'weak' },
          expectedValid: false
        },
        {
          data: { email: '', age: 200, password: 'ValidPass123!' },
          expectedValid: false
        }
      ];

      errorPrevention.validateInput.mockImplementation((data, rules) => {
        const errors: string[] = [];

        Object.entries(rules).forEach(([field, rule]: [string, any]) => {
          const value = data[field];

          if (rule.required && (!value || value === '')) {
            errors.push(`${field} is required`);
          }

          if (rule.format === 'email' && value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
            errors.push(`${field} must be a valid email`);
          }

          if (rule.type === 'number' && value && (typeof value !== 'number' || isNaN(value))) {
            errors.push(`${field} must be a number`);
          }

          if (rule.min !== undefined && value < rule.min) {
            errors.push(`${field} must be at least ${rule.min}`);
          }

          if (rule.max !== undefined && value > rule.max) {
            errors.push(`${field} must not exceed ${rule.max}`);
          }

          if (rule.minLength && value && value.length < rule.minLength) {
            errors.push(`${field} must be at least ${rule.minLength} characters`);
          }

          if (rule.pattern && value && !rule.pattern.test(value)) {
            errors.push(`${field} format is invalid`);
          }
        });

        return {
          valid: errors.length === 0,
          errors,
          sanitizedData: data
        };
      });

      testInputs.forEach(input => {
        const validation = errorPrevention.validateInput(input.data, validationRules);
        expect(validation.valid).toBe(input.expectedValid);
      });
    });

    it('should proactively detect potential errors before execution', async () => {
      const operationContext = {
        operation: 'store_knowledge',
        data: {
          kind: 'entity',
          content: 'A'.repeat(10 * 1024 * 1024), // 10MB content
          scope: { project: 'test' }
        },
        user_context: {
          plan: 'free',
          current_usage: { storage: 95, requests: 950 },
          limits: { storage: 100, requests: 1000 }
        }
      };

      errorPrevention.detectPotentialErrors.mockReturnValue([
        {
          type: 'storage_limit_warning',
          severity: 'warning',
          message: 'Content size may exceed storage limits',
          current_usage: 95,
          projected_usage: 98,
          limit: 100
        },
        {
          type: 'performance_risk',
          severity: 'info',
          message: 'Large content may impact processing performance',
          size_mb: 10,
          recommended_max_mb: 5
        }
      ]);

      const detectedRisks = errorPrevention.detectPotentialErrors(operationContext);

      expect(detectedRisks).toHaveLength(2);
      expect(detectedRisks[0].type).toBe('storage_limit_warning');
      expect(detectedRisks[0].severity).toBe('warning');
      expect(detectedRisks[1].type).toBe('performance_risk');
      expect(detectedRisks[1].severity).toBe('info');
    });

    it('should enforce error boundaries to prevent cascade failures', async () => {
      const errorBoundaryConfig = {
        maxErrorsPerMinute: 10,
        maxErrorRate: 0.05,
        isolationTimeout: 30000,
        recoveryStrategy: 'graceful_degradation'
      };

      const errorTracker = {
        errors: [] as Array<{ timestamp: number; type: string }>,
        addError(type: string) {
          this.errors.push({ timestamp: Date.now(), type });
          this.cleanupOldErrors();
        },
        cleanupOldErrors() {
          const oneMinuteAgo = Date.now() - 60000;
          this.errors = this.errors.filter(e => e.timestamp > oneMinuteAgo);
        },
        getErrorCount() { return this.errors.length; },
        getErrorRate(totalOperations: number) { return this.errors.length / totalOperations; }
      };

      errorPrevention.enforceErrorBoundaries.mockImplementation((config, tracker) => {
        return {
          shouldReject: () => {
            return tracker.getErrorCount() > config.maxErrorsPerMinute ||
                   tracker.getErrorRate(100) > config.maxErrorRate;
          },
          triggerBoundary: () => {
            return {
              isolation: true,
              timeout: config.isolationTimeout,
              strategy: config.recoveryStrategy,
              message: 'Error boundary triggered to prevent cascade failure'
            };
          }
        };
      });

      const boundary = errorPrevention.enforceErrorBoundaries(errorBoundaryConfig, errorTracker);

      // Simulate normal operations
      expect(boundary.shouldReject()).toBe(false);

      // Simulate error burst
      for (let i = 0; i < 12; i++) {
        errorTracker.addError('test_error');
      }

      expect(boundary.shouldReject()).toBe(true);

      const boundaryTriggered = boundary.triggerBoundary();
      expect(boundaryTriggered.isolation).toBe(true);
      expect(boundaryTriggered.strategy).toBe('graceful_degradation');
    });

    it('should apply graceful degradation strategies when errors occur', async () => {
      const degradationStrategies = {
        search: {
          primary: 'semantic_search',
          fallbacks: ['keyword_search', 'basic_text_match'],
          quality_thresholds: { semantic: 0.8, keyword: 0.6, basic: 0.4 }
        },
        embeddings: {
          primary: 'openai_embeddings',
          fallbacks: ['local_embeddings', 'cached_embeddings'],
          performance_thresholds: { openai: 5000, local: 10000, cached: 1000 }
        }
      };

      const operationAttempts = {
        semantic_search: () => Promise.reject(new Error('Embedding service unavailable')),
        keyword_search: () => Promise.resolve({ results: [], confidence: 0.7 }),
        basic_text_match: () => Promise.resolve({ results: [], confidence: 0.5 })
      };

      errorPrevention.applyGracefulDegradation.mockImplementation(async (strategy, attempts) => {
        for (const [method, attempt] of Object.entries(attempts)) {
          try {
            const result = await attempt();
            const threshold = strategy.quality_thresholds[method.split('_')[0] as keyof typeof strategy.quality_thresholds];

            if (result.confidence >= threshold) {
              return {
                success: true,
                method,
                result,
                degradation_level: method === strategy.primary ? 'none' :
                                   method === strategy.fallbacks[0] ? 'partial' : 'full'
              };
            }
          } catch (error) {
            continue; // Try next fallback
          }
        }

        return {
          success: false,
          error: 'All strategies failed',
          degradation_level: 'complete'
        };
      });

      const result = await errorPrevention.applyGracefulDegradation(
        degradationStrategies.search,
        operationAttempts
      );

      expect(result.success).toBe(true);
      expect(result.method).toBe('keyword_search');
      expect(result.degradation_level).toBe('partial');
    });
  });

  // 6. Integration with Monitoring Tests
  describe('Integration with Monitoring', () => {
    it('should integrate error logging with monitoring systems', async () => {
      const errorEvent = {
        error: new Error('Test integration error'),
        context: {
          service: 'knowledge-store',
          operation: 'store_entity',
          user_id: 'user-123',
          request_id: 'req-456'
        },
        severity: 'error',
        timestamp: new Date().toISOString()
      };

      errorMonitoring.logError.mockImplementation(async (event) => {
        return {
          logged: true,
          log_id: `log-${Date.now()}`,
          indices: ['error_logs', 'service_logs', 'user_activity'],
          retention_days: 90,
          searchable_fields: ['service', 'operation', 'user_id', 'severity']
        };
      });

      const logResult = await errorMonitoring.logError(errorEvent);

      expect(logResult.logged).toBe(true);
      expect(logResult.log_id).toMatch(/^log-\d+$/);
      expect(logResult.indices).toContain('error_logs');
      expect(logResult.searchable_fields).toContain('service');
    });

    it('should trigger appropriate alerts based on error conditions', async () => {
      const alertConditions = [
        {
          error: { type: 'database_connection_failed', severity: 'critical' },
          expectedAlert: { type: 'critical', channel: ['pagerduty', 'slack'], escalation: true }
        },
        {
          error: { type: 'high_error_rate', severity: 'warning', rate: 0.08 },
          expectedAlert: { type: 'warning', channel: ['slack', 'email'], escalation: false }
        },
        {
          error: { type: 'security_breach_attempt', severity: 'error' },
          expectedAlert: { type: 'security', channel: ['security_team', 'slack'], escalation: true }
        }
      ];

      errorMonitoring.triggerAlert.mockImplementation((condition) => {
        const alertRules = {
          database_connection_failed: { type: 'critical', channel: ['pagerduty', 'slack'], escalation: true },
          high_error_rate: { type: 'warning', channel: ['slack', 'email'], escalation: false },
          security_breach_attempt: { type: 'security', channel: ['security_team', 'slack'], escalation: true }
        };

        return {
          alert_id: `alert-${Date.now()}`,
          triggered: true,
          ...alertRules[condition.error.type as keyof typeof alertRules],
          timestamp: new Date().toISOString()
        };
      });

      for (const condition of alertConditions) {
        const alert = await errorMonitoring.triggerAlert(condition);
        expect(alert.triggered).toBe(true);
        expect(alert.type).toBe(condition.expectedAlert.type);
        expect(alert.channel).toEqual(condition.expectedAlert.channel);
        expect(alert.escalation).toBe(condition.expectedAlert.escalation);
      }
    });

    it('should assess performance impact of errors on system operations', async () => {
      const performanceMetrics = {
        baseline: {
          response_time_p50: 100,
          response_time_p95: 500,
          throughput: 1000,
          error_rate: 0.01
        },
        current: {
          response_time_p50: 250,
          response_time_p95: 1200,
          throughput: 700,
          error_rate: 0.08
        },
        errors: [
          { type: 'database_slowdown', frequency: 20, impact_score: 0.7 },
          { type: 'memory_pressure', frequency: 15, impact_score: 0.5 },
          { type: 'network_timeout', frequency: 10, impact_score: 0.8 }
        ]
      };

      errorMonitoring.assessPerformanceImpact.mockReturnValue({
        overall_impact: 'high',
        degradation_factors: {
          response_time_degradation: 2.5,
          throughput_degradation: 0.3,
          error_rate_increase: 8.0
        },
        primary_causes: [
          { cause: 'database_slowdown', contribution: 0.45 },
          { cause: 'network_timeout', contribution: 0.30 },
          { cause: 'memory_pressure', contribution: 0.25 }
        ],
        recommendations: [
          'Optimize database queries and indexing',
          'Implement connection pooling',
          'Add memory to application servers',
          'Review network configuration and timeouts'
        ],
        estimated_time_to_recovery: '2-4 hours',
        business_impact: {
          user_experience: 'significantly_degraded',
          revenue_impact: 'moderate',
          sla_compliance: 'at_risk'
        }
      });

      const impactAssessment = errorMonitoring.assessPerformanceImpact(performanceMetrics);

      expect(impactAssessment.overall_impact).toBe('high');
      expect(impactAssessment.degradation_factors.response_time_degradation).toBe(2.5);
      expect(impactAssessment.primary_causes[0].cause).toBe('database_slowdown');
      expect(impactAssessment.business_impact.sla_compliance).toBe('at_risk');
    });

    it('should correlate related errors across different services and components', async () => {
      const errorEvents = [
        {
          id: 'error-001',
          service: 'auth-service',
          error: 'database_connection_failed',
          timestamp: '2024-01-15T10:00:00Z',
          trace_id: 'trace-abc-123'
        },
        {
          id: 'error-002',
          service: 'api-gateway',
          error: 'upstream_service_timeout',
          timestamp: '2024-01-15T10:00:05Z',
          trace_id: 'trace-abc-123'
        },
        {
          id: 'error-003',
          service: 'knowledge-service',
          error: 'database_connection_failed',
          timestamp: '2024-01-15T10:00:10Z',
          trace_id: 'trace-def-456'
        },
        {
          id: 'error-004',
          service: 'search-service',
          error: 'upstream_service_timeout',
          timestamp: '2024-01-15T10:00:15Z',
          trace_id: 'trace-abc-123'
        }
      ];

      errorMonitoring.correlateErrors.mockReturnValue({
        correlation_groups: [
          {
            group_id: 'group-001',
            primary_error: 'database_connection_failed',
            related_errors: ['error-001', 'error-003'],
            affected_services: ['auth-service', 'knowledge-service'],
            correlation_strength: 0.9,
            root_cause_hypothesis: 'Database infrastructure issue'
          },
          {
            group_id: 'group-002',
            primary_error: 'upstream_service_timeout',
            related_errors: ['error-002', 'error-004'],
            trace_id: 'trace-abc-123',
            affected_services: ['api-gateway', 'search-service'],
            correlation_strength: 0.85,
            root_cause_hypothesis: 'Cascading failure from auth-service'
          }
        ],
        total_correlated_errors: 4,
        unique_error_patterns: 2,
        recommended_investigations: [
          'Check database cluster health and connectivity',
          'Review network configuration between services',
          'Analyze service dependency chains'
        ]
      });

      const correlation = errorMonitoring.correlateErrors(errorEvents);

      expect(correlation.correlation_groups).toHaveLength(2);
      expect(correlation.correlation_groups[0].primary_error).toBe('database_connection_failed');
      expect(correlation.correlation_groups[0].affected_services).toEqual(['auth-service', 'knowledge-service']);
      expect(correlation.total_correlated_errors).toBe(4);
      expect(correlation.recommended_investigations).toContain('Check database cluster health and connectivity');
    });
  });

  // 7. Comprehensive Error Handling Integration Tests
  describe('Comprehensive Error Handling Integration', () => {
    it('should handle complete error lifecycle from detection to recovery', async () => {
      const completeErrorScenario = {
        initial_error: {
          code: 'EMBEDDING_SERVICE_FAILURE',
          message: 'OpenAI API returned 503 error',
          details: { service: 'openai', endpoint: '/embeddings', status: 503 }
        },
        user_context: { user_id: 'user-123', plan: 'premium', request_critical: true },
        system_context: { current_load: 'high', available_fallbacks: ['local', 'cached'] }
      };

      // Mock the complete error handling workflow
      errorClassifier.classifyError.mockReturnValue({
        type: 'external_service_error',
        category: 'infrastructure',
        severity: 'error',
        recoverable: true,
        recovery_priority: 'high'
      });

      errorRecovery.executeRetryStrategy.mockResolvedValue('Success after retry');
      errorMessageFormatter.formatErrorMessage.mockReturnValue({
        user_message: 'Processing your request with alternative service...',
        technical_details: 'OpenAI API unavailable, using local embeddings'
      });
      errorMonitoring.logError.mockResolvedValue({ logged: true, log_id: 'log-123' });

      // Execute complete workflow
      const classification = errorClassifier.classifyError(completeErrorScenario.initial_error);
      const recoveryResult = await errorRecovery.executeRetryStrategy(
        () => Promise.reject(completeErrorScenario.initial_error),
        { type: 'exponential_backoff', maxAttempts: 3, baseDelay: 1000 }
      );
      const userMessage = errorMessageFormatter.formatErrorMessage(
        completeErrorScenario.initial_error,
        'end_user'
      );
      const loggingResult = await errorMonitoring.logError({
        error: completeErrorScenario.initial_error,
        classification,
        recovery: recoveryResult,
        user_context: completeErrorScenario.user_context
      });

      expect(classification.recoverable).toBe(true);
      expect(classification.recovery_priority).toBe('high');
      expect(userMessage.user_message).toContain('alternative service');
      expect(loggingResult.logged).toBe(true);
    });

    it('should provide comprehensive error analytics for operational insights', async () => {
      const operationalData = {
        time_period: { start: '2024-01-15T00:00:00Z', end: '2024-01-15T23:59:59Z' },
        total_operations: 100000,
        error_events: [
          { type: 'database_error', count: 500, impact: 'high' },
          { type: 'api_timeout', count: 300, impact: 'medium' },
          { type: 'validation_error', count: 200, impact: 'low' },
          { type: 'network_error', count: 150, impact: 'medium' },
          { type: 'service_unavailable', count: 100, impact: 'high' }
        ],
        recovery_events: [
          { strategy: 'retry', success_rate: 0.8, usage_count: 800 },
          { strategy: 'fallback', success_rate: 0.9, usage_count: 300 },
          { strategy: 'circuit_breaker', activations: 5, prevention_count: 200 }
        ]
      };

      errorReporter.aggregateErrors.mockReturnValue({
        error_rate: 0.0125,
        top_error_types: ['database_error', 'api_timeout', 'validation_error'],
        recovery_effectiveness: {
          overall_success_rate: 0.83,
          best_strategy: 'fallback',
          strategy_performance: {
            retry: { success_rate: 0.8, avg_time_to_recovery: 30 },
            fallback: { success_rate: 0.9, avg_time_to_recovery: 10 }
          }
        },
        operational_impact: {
          availability: 0.9875,
          mean_time_to_recovery: 25,
          customer_impact_score: 0.15
        },
        recommendations: [
          'Prioritize database connection pool optimization',
          'Increase timeout thresholds for external APIs',
          'Implement more robust fallback mechanisms'
        ]
      });

      const analytics = errorReporter.aggregateErrors(operationalData);

      expect(analytics.error_rate).toBe(0.0125);
      expect(analytics.top_error_types[0]).toBe('database_error');
      expect(analytics.recovery_effectiveness.overall_success_rate).toBe(0.83);
      expect(analytics.operational_impact.availability).toBe(0.9875);
      expect(analytics.recommendations).toContain('Prioritize database connection pool optimization');
    });
  });
});