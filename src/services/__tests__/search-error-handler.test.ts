/**
 * Search Error Handler Test Suite - Phase 3 Enhanced
 *
 * Comprehensive tests for the search error handling system including:
 * - Error classification and categorization
 * - Recovery strategies (retry, fallback, degrade, circuit breaker)
 * - Circuit breaker functionality
 * - Error metrics and monitoring
 * - User-friendly error messages
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  ErrorCategory,
  ErrorSeverity,
  RecoveryStrategy,
  SearchErrorHandler,
} from '../search/search-error-handler';

// Mock the logger to avoid noise in tests
vi.mock('../../utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

describe('SearchErrorHandler', () => {
  let errorHandler: SearchErrorHandler;

  beforeEach(() => {
    errorHandler = new SearchErrorHandler();
  });

  afterEach(() => {
    errorHandler.resetMetrics();
    errorHandler.resetAllCircuitBreakers();
  });

  describe('Error Classification', () => {
    it('should classify timeout errors correctly', async () => {
      const timeoutError = new Error('Request timed out after 5000ms');
      const context = { operation: 'vector_search', query: 'test query' };

      const searchError = await errorHandler.handleError(timeoutError, context);

      expect(searchError.category).toBe(ErrorCategory.TIMEOUT);
      expect(searchError.severity).toBe(ErrorSeverity.HIGH);
      expect(searchError.retryable).toBe(true);
      expect(searchError.suggestedRecovery).toBe(RecoveryStrategy.RETRY);
      expect(searchError.code).toMatch(/^SRCH_TME_H_/);
      expect(searchError.userMessage).toContain('timed out');
    });

    it('should classify network errors correctly', async () => {
      const networkError = new Error('Network connection failed');
      const context = { operation: 'api_call' };

      const searchError = await errorHandler.handleError(networkError, context);

      expect(searchError.category).toBe(ErrorCategory.NETWORK);
      expect(searchError.severity).toBe(ErrorSeverity.MEDIUM);
      expect(searchError.retryable).toBe(true);
      expect(searchError.suggestedRecovery).toBe(RecoveryStrategy.RETRY);
      expect(searchError.userMessage).toContain('Network connection');
    });

    it('should classify database errors correctly', async () => {
      const dbError = new Error('Database connection lost');
      const context = { operation: 'query_execution' };

      const searchError = await errorHandler.handleError(dbError, context);

      expect(searchError.category).toBe(ErrorCategory.DATABASE);
      expect(searchError.severity).toBe(ErrorSeverity.HIGH);
      expect(searchError.retryable).toBe(false);
      expect(searchError.suggestedRecovery).toBe(RecoveryStrategy.DEGRADE);
      expect(searchError.userMessage).toContain('Database');
    });

    it('should classify vector backend errors correctly', async () => {
      const vectorError = new Error('Vector embedding service unavailable');
      const context = { operation: 'vector_search' };

      const searchError = await errorHandler.handleError(vectorError, context);

      expect(searchError.category).toBe(ErrorCategory.VECTOR_BACKEND);
      expect(searchError.severity).toBe(ErrorSeverity.MEDIUM);
      expect(searchError.retryable).toBe(true);
      expect(searchError.suggestedRecovery).toBe(RecoveryStrategy.DEGRADE);
      expect(searchError.userMessage).toContain('Advanced search');
    });

    it('should classify validation errors correctly', async () => {
      const validationError = new Error('Invalid query format');
      const context = { operation: 'query_validation' };

      const searchError = await errorHandler.handleError(validationError, context);

      expect(searchError.category).toBe(ErrorCategory.VALIDATION);
      expect(searchError.severity).toBe(ErrorSeverity.LOW);
      expect(searchError.retryable).toBe(false);
      expect(searchError.suggestedRecovery).toBe(RecoveryStrategy.ABORT);
      expect(searchError.userMessage).toContain('Invalid search query');
    });

    it('should classify rate limit errors correctly', async () => {
      const rateLimitError = new Error('Too many requests - rate limit exceeded');
      const context = { operation: 'api_request' };

      const searchError = await errorHandler.handleError(rateLimitError, context);

      expect(searchError.category).toBe(ErrorCategory.RATE_LIMIT);
      expect(searchError.severity).toBe(ErrorSeverity.MEDIUM);
      expect(searchError.retryable).toBe(true);
      expect(searchError.suggestedRecovery).toBe(RecoveryStrategy.RETRY);
      expect(searchError.userMessage).toContain('Too many requests');
    });

    it('should classify memory errors correctly', async () => {
      const memoryError = new Error('Out of memory');
      const context = { operation: 'search_processing' };

      const searchError = await errorHandler.handleError(memoryError, context);

      expect(searchError.category).toBe(ErrorCategory.MEMORY);
      expect(searchError.severity).toBe(ErrorSeverity.CRITICAL);
      expect(searchError.retryable).toBe(false);
      expect(searchError.suggestedRecovery).toBe(RecoveryStrategy.DEGRADE);
      expect(searchError.userMessage).toContain('System resources');
    });

    it('should classify authentication errors correctly', async () => {
      const authError = new Error('Unauthorized access');
      const context = { operation: 'secure_search' };

      const searchError = await errorHandler.handleError(authError, context);

      expect(searchError.category).toBe(ErrorCategory.AUTHENTICATION);
      expect(searchError.severity).toBe(ErrorSeverity.HIGH);
      expect(searchError.retryable).toBe(false);
      expect(searchError.suggestedRecovery).toBe(RecoveryStrategy.ABORT);
      expect(searchError.userMessage).toContain('Authentication required');
    });

    it('should classify unknown errors correctly', async () => {
      const unknownError = new Error('Something completely unexpected');
      const context = { operation: 'unknown_operation' };

      const searchError = await errorHandler.handleError(unknownError, context);

      expect(searchError.category).toBe(ErrorCategory.UNKNOWN);
      expect(searchError.severity).toBe(ErrorSeverity.MEDIUM);
      expect(searchError.retryable).toBe(true);
      expect(searchError.suggestedRecovery).toBe(RecoveryStrategy.RETRY);
    });

    it('should handle non-Error objects', async () => {
      const stringError = 'Just a string error';
      const context = { operation: 'string_error' };

      const searchError = await errorHandler.handleError(stringError, context);

      expect(searchError.category).toBe(ErrorCategory.UNKNOWN);
      expect(searchError.message).toBe(stringError);
      expect(searchError.code).toMatch(/^SRCH_UNK_M_/);
    });
  });

  describe('Recovery Strategies', () => {
    describe('Retry Strategy', () => {
      it('should retry successfully on retryable errors', async () => {
        const retryableError = new Error('Network timeout');
        const context = { operation: 'retry_test' };

        let attemptCount = 0;
        const retryFunction = vi.fn(async () => {
          attemptCount++;
          if (attemptCount < 3) {
            throw retryableError;
          }
          return { success: true, attempt: attemptCount };
        });

        const searchError = await errorHandler.handleError(retryableError, context);

        const result = await errorHandler.attemptRecovery(searchError, retryFunction, context);

        expect(result).toEqual({ success: true, attempt: 3 });
        expect(retryFunction).toHaveBeenCalledTimes(3);
        expect(attemptCount).toBe(3);
      });

      it('should fail after maximum retries', async () => {
        const persistentError = new Error('Persistent failure');
        const context = { operation: 'max_retry_test' };

        const retryFunction = vi.fn(async () => {
          throw persistentError;
        });

        const searchError = await errorHandler.handleError(persistentError, context);

        await expect(
          errorHandler.attemptRecovery(searchError, retryFunction, context)
        ).rejects.toThrow(persistentError);

        expect(retryFunction).toHaveBeenCalledTimes(3); // Default max retries
      });

      it('should not retry non-retryable errors', async () => {
        const nonRetryableError = new Error('Invalid format');
        const context = { operation: 'no_retry_test' };

        const retryFunction = vi.fn(async () => {
          throw nonRetryableError;
        });

        const searchError = await errorHandler.handleError(nonRetryableError, context);

        await expect(
          errorHandler.attemptRecovery(searchError, retryFunction, context)
        ).rejects.toThrow(nonRetryableError);

        expect(retryFunction).toHaveBeenCalledTimes(1); // Only initial attempt, no retries
      });

      it('should use exponential backoff for retries', async () => {
        const retryableError = new Error('Temporary failure');
        const context = { operation: 'backoff_test' };

        const startTime = Date.now();
        const delays: number[] = [];

        const retryFunction = vi.fn(() => {
          if (retryFunction.mock.calls.length > 0) {
            delays.push(Date.now() - startTime);
          }
          throw retryableError;
        });

        const searchError = await errorHandler.handleError(retryableError, context);

        try {
          await errorHandler.attemptRecovery(searchError, retryFunction, context);
        } catch (error) {
          // Expected to fail after retries
        }

        // Verify exponential backoff (delays should increase)
        expect(delays.length).toBeGreaterThan(1);
        for (let i = 1; i < delays.length; i++) {
          expect(delays[i]).toBeGreaterThan(delays[i - 1]);
        }
      });
    });

    describe('Fallback Strategy', () => {
      it('should execute fallback function when provided', async () => {
        const originalError = new Error('Primary service failed');
        const context = {
          operation: 'fallback_test',
          fallbackFunction: vi.fn(() => ({ fallback: true })),
        };

        const searchError = await errorHandler.handleError(originalError, context);

        // Mock the error handler to suggest fallback
        searchError.suggestedRecovery = RecoveryStrategy.FALLBACK;

        const result = await errorHandler.attemptRecovery(searchError, () => Promise.resolve(), context);

        expect(result).toEqual({ fallback: true });
        expect(context.fallbackFunction).toHaveBeenCalled();
      });

      it('should create basic fallback when no function provided', async () => {
        const originalError = new Error('Service unavailable');
        const context = { operation: 'basic_fallback_test' };

        const searchError = await errorHandler.handleError(originalError, context);
        searchError.suggestedRecovery = RecoveryStrategy.FALLBACK;

        const result = await errorHandler.attemptRecovery(searchError, () => Promise.resolve(), context);

        expect(result).toHaveProperty('results', []);
        expect(result).toHaveProperty('strategy', 'fallback');
        expect(result).toHaveProperty('degraded', true);
      });

      it('should handle fallback function failure', async () => {
        const originalError = new Error('Primary failed');
        const fallbackError = new Error('Fallback also failed');
        const context = {
          operation: 'fallback_fail_test',
          fallbackFunction: vi.fn(() => {
            throw fallbackError;
          }),
        };

        const searchError = await errorHandler.handleError(originalError, context);
        searchError.suggestedRecovery = RecoveryStrategy.FALLBACK;

        await expect(errorHandler.attemptRecovery(searchError, async () => {}, context)).rejects.toThrow(
          fallbackError
        );

        expect(context.fallbackFunction).toHaveBeenCalled();
      });
    });

    describe('Degradation Strategy', () => {
      it('should execute degradation function when provided', async () => {
        const originalError = new Error('Advanced features unavailable');
        const context = {
          operation: 'degradation_test',
          degradeFunction: vi.fn(() => ({ degraded: true, simple: true })),
        };

        const searchError = await errorHandler.handleError(originalError, context);
        searchError.suggestedRecovery = RecoveryStrategy.DEGRADE;

        const result = await errorHandler.attemptRecovery(searchError, () => Promise.resolve(), context);

        expect(result).toEqual({
          degraded: true,
          simple: true,
          fallbackReason: originalError.message,
        });
        expect(context.degradeFunction).toHaveBeenCalled();
      });

      it('should fall back to basic fallback when degradation fails', async () => {
        const originalError = new Error('Degradation failed');
        const context = {
          operation: 'degrade_fallback_test',
          degradeFunction: vi.fn(() => {
            throw new Error('Degradation implementation failed');
          }),
          fallbackFunction: vi.fn(() => ({ basic_fallback: true })),
        };

        const searchError = await errorHandler.handleError(originalError, context);
        searchError.suggestedRecovery = RecoveryStrategy.DEGRADE;

        const result = await errorHandler.attemptRecovery(searchError, () => Promise.resolve(), context);

        expect(result).toEqual({ basic_fallback: true });
        expect(context.degradeFunction).toHaveBeenCalled();
        expect(context.fallbackFunction).toHaveBeenCalled();
      });
    });

    describe('Circuit Breaker Strategy', () => {
      it('should activate circuit breaker on repeated failures', async () => {
        const operationKey = 'circuit_breaker_test';
        const persistentError = new Error('Service down');

        // Simulate multiple failures to trigger circuit breaker
        for (let i = 0; i < 5; i++) {
          const searchError = await errorHandler.handleError(persistentError, {
            operation: operationKey,
          });
          searchError.suggestedRecovery = RecoveryStrategy.CIRCUIT_BREAK;

          try {
            await errorHandler.attemptRecovery(searchError, async () => {}, { operation: operationKey });
          } catch (error) {
            // Expected to throw circuit breaker error
          }
        }

        const circuitBreakers = errorHandler.getCircuitBreakerStates();
        const circuitBreaker = circuitBreakers.get(operationKey);

        expect(circuitBreaker).toBeDefined();
        expect(circuitBreaker?.isOpen).toBe(true);
        expect(circuitBreaker?.failureCount).toBe(5);
      });

      it('should create circuit breaker error when circuit is open', async () => {
        const operationKey = 'already_open_test';
        const originalError = new Error('Some error');

        // Manually set circuit breaker as open
        const circuitBreakers = errorHandler.getCircuitBreakerStates();
        circuitBreakers.set(operationKey, {
          isOpen: true,
          failureCount: 5,
          lastFailureTime: new Date(),
          nextAttemptTime: new Date(Date.now() + 60000),
          halfOpenAttempts: 0,
        });

        const searchError = await errorHandler.handleError(originalError, {
          operation: operationKey,
        });

        const result = await errorHandler.handleError(originalError, { operation: operationKey });

        expect(result.code).toContain('CIRCUIT_BREAKER');
        expect(result.retryable).toBe(false);
        expect(result.suggestedRecovery).toBe(RecoveryStrategy.ABORT);
      });

      it('should reset circuit breaker after timeout', async () => {
        const operationKey = 'reset_test';

        // Create an expired circuit breaker
        const circuitBreakers = errorHandler.getCircuitBreakerStates();
        circuitBreakers.set(operationKey, {
          isOpen: true,
          failureCount: 5,
          lastFailureTime: new Date(Date.now() - 120000), // 2 minutes ago
          nextAttemptTime: new Date(Date.now() - 60000), // 1 minute ago (expired)
          halfOpenAttempts: 0,
        });

        const searchError = await errorHandler.handleError(new Error('Test'), {
          operation: operationKey,
        });

        // Should not create circuit breaker error since timeout has passed
        expect(searchError.code).not.toContain('CIRCUIT_BREAKER');
      });
    });
  });

  describe('Error Metrics', () => {
    it('should track error metrics correctly', async () => {
      const errors = [
        new Error('Network timeout'),
        new Error('Validation failed'),
        new Error('Database error'),
        new Error('Memory error'),
      ];

      // Generate errors of different categories
      for (const error of errors) {
        await errorHandler.handleError(error, { operation: 'metrics_test' });
      }

      const metrics = errorHandler.getErrorMetrics();

      expect(metrics.totalErrors).toBe(4);
      expect(metrics.errorsByCategory[ErrorCategory.TIMEOUT]).toBeGreaterThan(0);
      expect(metrics.errorsByCategory[ErrorCategory.VALIDATION]).toBeGreaterThan(0);
      expect(metrics.errorsByCategory[ErrorCategory.DATABASE]).toBeGreaterThan(0);
      expect(metrics.errorsByCategory[ErrorCategory.MEMORY]).toBeGreaterThan(0);
      expect(metrics.errorsBySeverity[ErrorSeverity.LOW]).toBeGreaterThan(0);
      expect(metrics.errorsBySeverity[ErrorSeverity.MEDIUM]).toBeGreaterThan(0);
      expect(metrics.errorsBySeverity[ErrorSeverity.HIGH]).toBeGreaterThan(0);
      expect(metrics.errorsBySeverity[ErrorSeverity.CRITICAL]).toBeGreaterThan(0);
    });

    it('should track recovery attempts and successes', async () => {
      const retryableError = new Error('Temporary failure');
      const context = { operation: 'recovery_metrics_test' };

      let attemptCount = 0;
      const retryFunction = vi.fn(async () => {
        attemptCount++;
        if (attemptCount < 2) {
          throw retryableError;
        }
        return { success: true };
      });

      const searchError = await errorHandler.handleError(retryableError, context);

      await errorHandler.attemptRecovery(searchError, retryFunction, context);

      const metrics = errorHandler.getErrorMetrics();

      expect(metrics.recoveryAttempts).toBeGreaterThan(0);
      expect(metrics.successfulRecoveries).toBeGreaterThan(0);
    });

    it('should reset metrics successfully', async () => {
      // Generate some errors
      await errorHandler.handleError(new Error('Test error 1'), { operation: 'reset_test' });
      await errorHandler.handleError(new Error('Test error 2'), { operation: 'reset_test' });

      let metrics = errorHandler.getErrorMetrics();
      expect(metrics.totalErrors).toBe(2);

      // Reset metrics
      errorHandler.resetMetrics();

      metrics = errorHandler.getErrorMetrics();
      expect(metrics.totalErrors).toBe(0);
      expect(metrics.recoveryAttempts).toBe(0);
      expect(metrics.successfulRecoveries).toBe(0);
      expect(Object.values(metrics.errorsByCategory).every((count) => count === 0)).toBe(true);
      expect(Object.values(metrics.errorsBySeverity).every((count) => count === 0)).toBe(true);
    });
  });

  describe('User Experience', () => {
    it('should generate appropriate user messages for different error types', async () => {
      const errorTests = [
        {
          error: new Error('Request timed out'),
          expectedMessage: 'timed out',
        },
        {
          error: new Error('Network connection failed'),
          expectedMessage: 'Network connection',
        },
        {
          error: new Error('Database connection lost'),
          expectedMessage: 'Database',
        },
        {
          error: new Error('Vector service unavailable'),
          expectedMessage: 'Advanced search',
        },
        {
          error: new Error('Too many requests'),
          expectedMessage: 'Too many requests',
        },
        {
          error: new Error('Invalid query'),
          expectedMessage: 'Invalid search query',
        },
        {
          error: new Error('Out of memory'),
          expectedMessage: 'System resources',
        },
        {
          error: new Error('Unauthorized'),
          expectedMessage: 'Authentication required',
        },
      ];

      for (const test of errorTests) {
        const searchError = await errorHandler.handleError(test.error, {
          operation: 'user_message_test',
        });
        expect(searchError.userMessage).toContain(test.expectedMessage);
      }
    });

    it('should include relevant context in error information', async () => {
      const originalError = new Error('Test error with stack');
      originalError.stack = 'Error: Test error\\n    at test.js:1:1';

      const context = {
        operation: 'context_test',
        query: 'test query',
        userId: 'user123',
        requestId: 'req-456',
      };

      const searchError = await errorHandler.handleError(originalError, context);

      expect(searchError.context.operation).toBe('context_test');
      expect(searchError.context.query).toBe('test query');
      expect(searchError.context.userId).toBe('user123');
      expect(searchError.context.requestId).toBe('req-456');
      expect(searchError.context.stack).toBe(originalError.stack);
    });

    it('should generate unique error codes', async () => {
      const errors = Array.from({ length: 10 }, (_, i) => new Error(`Error ${i}`));
      const codes = new Set<string>();

      for (const error of errors) {
        const searchError = await errorHandler.handleError(error, { operation: 'code_test' });
        codes.add(searchError.code);
      }

      // All error codes should be unique
      expect(codes.size).toBe(10);

      // All codes should follow the expected pattern
      codes.forEach((code) => {
        expect(code).toMatch(/^SRCH_[A-Z]{3}_[A-Z]_[a-z0-9]+$/);
      });
    });
  });

  describe('Concurrent Error Handling', () => {
    it('should handle concurrent errors safely', async () => {
      const concurrentErrors = Array.from({ length: 20 }, (_, i) =>
        errorHandler.handleError(new Error(`Concurrent error ${i}`), {
          operation: `concurrent_${i}`,
        })
      );

      const searchErrors = await Promise.all(concurrentErrors);

      expect(searchErrors).toHaveLength(20);
      searchErrors.forEach((error, index) => {
        expect((error as unknown as Error).message).toBe(`Concurrent error ${index}`);
        expect(error.code).toMatch(/^SRCH_[A-Z]{3}_[A-Z]_[a-z0-9]+$/);
      });

      const metrics = errorHandler.getErrorMetrics();
      expect(metrics.totalErrors).toBe(20);
    });

    it('should handle concurrent recovery attempts', async () => {
      const retryableError = new Error('Concurrent retry test');
      const retryFunction = vi.fn(async () => {
        return { success: true, timestamp: Date.now() };
      });

      const searchError = await errorHandler.handleError(retryableError, {
        operation: 'concurrent_retry',
      });

      const concurrentRecoveries = Array.from({ length: 5 }, () =>
        errorHandler.attemptRecovery(searchError, retryFunction, { operation: 'concurrent_retry' })
      );

      const results = await Promise.all(concurrentRecoveries);

      expect(results).toHaveLength(5);
      results.forEach((result) => {
        expect(result).toHaveProperty('success', true);
        expect(result).toHaveProperty('timestamp');
      });

      expect(retryFunction).toHaveBeenCalledTimes(5);
    });
  });
});
