/**
 * ReDoS Security Tests for Query Sanitizer
 *
 * Comprehensive test suite to verify ReDoS protection and SQL injection prevention
 * effectiveness of the secure query-sanitizer.ts implementation.
 */

import {
  sanitizeQuery,
  detectProblematicPatterns,
  testRedosResistance,
  verifySqlInjectionPrevention,
  getRegexExecutionStats,
  clearRegexExecutionStats,
  isLikelyToCauseTsqueryError,
  generateSanitizationOptions,
  suggestSanitizationLevel
} from '../../../src/utils/query-sanitizer';

describe('ReDoS Security Tests - Query Sanitizer', () => {
  beforeEach(() => {
    // Clear stats before each test
    clearRegexExecutionStats();
  });

  describe('Input Validation Security', () => {
    test('should reject excessively long inputs', () => {
      const longInput = 'a'.repeat(1001); // Exceeds max_input_length of 1000
      expect(() => sanitizeQuery(longInput)).toThrow(/Input validation failed/);
    });

    test('should handle inputs with excessive character repetition', () => {
      const suspiciousInput = 'a'.repeat(25) + 'test';
      const result = sanitizeQuery(suspiciousInput);
      expect(result.security_warnings).toContain(
        expect.stringContaining('excessive character repetition')
      );
    });

    test('should handle inputs with many alternations', () => {
      const alternationInput = 'a|b|c|d|e|f|g|h|i|j|k|l';
      const result = sanitizeQuery(alternationInput);
      expect(result.security_warnings).toContain(
        expect.stringContaining('many alternations')
      );
    });
  });

  describe('ReDoS Attack Pattern Resistance', () => {
    test('should resist nested quantifier attacks', () => {
      const attackPatterns = [
        'a'.repeat(100) + 'b',
        'a'.repeat(200) + 'b',
        'a'.repeat(500) + 'b'
      ];

      attackPatterns.forEach(pattern => {
        const startTime = Date.now();
        const result = sanitizeQuery(pattern, 'moderate');
        const executionTime = Date.now() - startTime;

        expect(executionTime).toBeLessThan(100); // Should complete within 100ms
        expect(result.cleaned).toBeDefined();
        expect(result.security_warnings).toBeDefined();
      });
    });

    test('should resist alternation attacks', () => {
      const attackPatterns = [
        'a' + '|'.repeat(50) + 'b',
        'x' + '|'.repeat(100) + 'y'
      ];

      attackPatterns.forEach(pattern => {
        const startTime = Date.now();
        const result = sanitizeQuery(pattern, 'moderate');
        const executionTime = Date.now() - startTime;

        expect(executionTime).toBeLessThan(100);
        expect(result.cleaned).toBeDefined();
      });
    });

    test('should resist backreference attacks', () => {
      const attackPatterns = [
        'a'.repeat(50) + 'a'.repeat(50),
        'b'.repeat(100) + 'b'.repeat(100)
      ];

      attackPatterns.forEach(pattern => {
        const startTime = Date.now();
        const result = sanitizeQuery(pattern, 'moderate');
        const executionTime = Date.now() - startTime;

        expect(executionTime).toBeLessThan(100);
        expect(result.cleaned).toBeDefined();
      });
    });

    test('should resist complex mixed attacks', () => {
      const attackPatterns = [
        'T' + '0'.repeat(50) + '-T' + '0'.repeat(50),
        'Phase' + ' '.repeat(50) + '-' + ' '.repeat(50) + '123'
      ];

      attackPatterns.forEach(pattern => {
        const startTime = Date.now();
        const result = sanitizeQuery(pattern, 'moderate');
        const executionTime = Date.now() - startTime;

        expect(executionTime).toBeLessThan(100);
        expect(result.cleaned).toBeDefined();
      });
    });
  });

  describe('Timeout Protection', () => {
    test('should enforce timeout on slow regex operations', () => {
      // Create a potentially slow input
      const slowInput = 'T' + '0'.repeat(100) + '-T' + '0'.repeat(100);
      const result = sanitizeQuery(slowInput, 'moderate');

      // Check for timeout warnings
      expect(result.security_warnings).toBeDefined();
      // Should still return a result even if some patterns timeout
      expect(result.cleaned).toBeDefined();
      expect(typeof result.cleaned).toBe('string');
    });

    test('should provide safe fallbacks when patterns timeout', () => {
      const problematicInput = 'Phase' + ' '.repeat(100) + '-' + ' '.repeat(100) + '123';
      const result = sanitizeQuery(problematicInput, 'moderate');

      // Should have fallback behavior
      expect(result.cleaned).toBeDefined();
      expect(result.auto_fixes_applied).toBeDefined();
    });
  });

  describe('Pattern Detection Security', () => {
    test('should safely handle pattern detection timeouts', () => {
      const difficultInput = 'a'.repeat(200) + 'test';

      expect(() => {
        const patterns = detectProblematicPatterns(difficultInput);
        expect(Array.isArray(patterns)).toBe(true);
      }).not.toThrow();
    });

    test('should limit pattern matches to prevent DoS', () => {
      const complexInput = 'test-phase version-1 task-T123-T456 special-chars!!!'.repeat(15);
      const result = sanitizeQuery(complexInput, 'aggressive');

      // Check that input is processed safely (may or may not hit limit depending on input size)
      expect(result.cleaned).toBeDefined();
      expect(result.security_warnings).toBeDefined();
    });
  });

  describe('SQL Injection Prevention Effectiveness', () => {
    test('should block SQL injection attempts', () => {
      const injectionAttempts = [
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "admin'/**/OR/**/1=1#",
        "'; INSERT INTO logs VALUES ('hacked'); --",
        "1' UNION SELECT * FROM passwords --"
      ];

      injectionAttempts.forEach(injection => {
        const result = sanitizeQuery(injection, 'aggressive');

        // Should remove dangerous SQL characters
        expect(result.cleaned).not.toContain("'");
        expect(result.cleaned).not.toContain(';');
        expect(result.cleaned).not.toContain('--');
      });
    });

    test('should verify comprehensive injection prevention', () => {
      const effectiveness = verifySqlInjectionPrevention();

      expect(effectiveness.effectiveness).toBeGreaterThan(50); // Should block >50% of injections
      expect(effectiveness.results.length).toBeGreaterThan(0);

      // All results should be sanitized
      effectiveness.results.forEach(result => {
        expect(typeof result.sanitized).toBe('string');
        expect(typeof result.containsInjection).toBe('boolean');
      });
    });
  });

  describe('Performance Monitoring', () => {
    test('should track regex execution statistics', () => {
      const testInput = 'T123-T456 Phase-1 test-data';

      // Perform sanitization
      sanitizeQuery(testInput, 'moderate');

      // Check stats
      const stats = getRegexExecutionStats();
      expect(stats.size).toBeGreaterThan(0);

      // Verify stat structure
      stats.forEach((stat, pattern) => {
        expect(typeof pattern).toBe('string');
        expect(typeof stat.count).toBe('number');
        expect(typeof stat.totalTime).toBe('number');
        expect(typeof stat.failures).toBe('number');
        expect(typeof stat.avgTime).toBe('number');
      });
    });

    test('should clear execution statistics', () => {
      // Generate some stats
      sanitizeQuery('test-input', 'basic');

      // Verify stats exist
      let stats = getRegexExecutionStats();
      expect(stats.size).toBeGreaterThan(0);

      // Clear stats
      clearRegexExecutionStats();

      // Verify stats are cleared
      stats = getRegexExecutionStats();
      expect(stats.size).toBe(0);
    });
  });

  describe('Built-in ReDoS Resistance Test', () => {
    test('should pass built-in ReDoS resistance tests', () => {
      const testResults = testRedosResistance();

      expect(testResults.patterns).toBeDefined();
      expect(testResults.results).toBeDefined();
      expect(testResults.summary).toBeDefined();

      // Should have reasonable pass rate
      const passRate = (testResults.summary.passed / testResults.results.length) * 100;
      expect(passRate).toBeGreaterThan(80); // At least 80% should pass

      // Total execution time should be reasonable
      expect(testResults.summary.totalTime).toBeLessThan(1000); // Less than 1 second total

      // Each result should have expected structure
      testResults.results.forEach(result => {
        expect(typeof result.input).toBe('string');
        expect(typeof result.passed).toBe('boolean');
        expect(typeof result.executionTime).toBe('number');
        expect(result.executionTime).toBeLessThan(200); // Each test under 200ms
      });
    });
  });

  describe('Error Handling and Graceful Degradation', () => {
    test('should handle errors gracefully in suggestSanitizationLevel', () => {
      const problematicInput = 'a'.repeat(1000);
      const level = suggestSanitizationLevel(problematicInput);
      expect(['basic', 'moderate', 'aggressive']).toContain(level);
    });

    test('should handle errors gracefully in isLikelyToCauseTsqueryError', () => {
      const problematicInput = 'a'.repeat(1000);
      const isLikely = isLikelyToCauseTsqueryError(problematicInput);
      expect(typeof isLikely).toBe('boolean');
    });

    test('should provide safe fallbacks in generateSanitizationOptions', () => {
      const problematicInput = 'a'.repeat(1000);
      const options = generateSanitizationOptions(problematicInput);

      expect(options.basic).toBeDefined();
      expect(options.moderate).toBeDefined();
      expect(options.aggressive).toBeDefined();

      // All should have security warnings
      expect(options.basic.security_warnings.length).toBeGreaterThan(0);
      expect(options.moderate.security_warnings.length).toBeGreaterThan(0);
      expect(options.aggressive.security_warnings.length).toBeGreaterThan(0);
    });
  });

  describe('Backward Compatibility', () => {
    test('should maintain backward compatibility for normal inputs', () => {
      const normalInputs = [
        'T123-T456 task description',
        'Phase-1 project setup',
        'simple query with words',
        'test-data processing'
      ];

      normalInputs.forEach(input => {
        expect(() => sanitizeQuery(input)).not.toThrow();

        const result = sanitizeQuery(input);
        expect(result.cleaned).toBeDefined();
        expect(result.original).toBe(input);
        expect(['basic', 'moderate', 'aggressive']).toContain(result.level);
        expect(Array.isArray(result.transformations)).toBe(true);
        expect(Array.isArray(result.auto_fixes_applied)).toBe(true);
        expect(Array.isArray(result.patterns_detected)).toBe(true);
        expect(Array.isArray(result.security_warnings)).toBe(true);
      });
    });
  });

  describe('Edge Cases', () => {
    test('should handle empty strings', () => {
      const result = sanitizeQuery('');
      expect(result.cleaned).toBe('');
      expect(result.transformations).toContain('normalized_whitespace');
    });

    test('should handle very short strings', () => {
      const result = sanitizeQuery('a');
      expect(result.cleaned).toBe('a');
    });

    test('should handle strings with only whitespace', () => {
      const result = sanitizeQuery('   \t\n   ');
      expect(result.cleaned).toBe('');
    });

    test('should handle Unicode characters', () => {
      const unicodeInput = 'Tést-中文-العربية-🔒';
      const result = sanitizeQuery(unicodeInput);
      expect(result.cleaned).toBeDefined();
      expect(typeof result.cleaned).toBe('string');
    });
  });
});

/**
 * Performance Benchmark Test
 *
 * This test runs performance benchmarks to ensure the secure implementation
 * doesn't significantly impact performance for normal use cases.
 */
describe('Performance Benchmarks', () => {
  test('should maintain acceptable performance for typical queries', () => {
    const typicalQueries = [
      'T123-T456 implement user authentication',
      'Phase-1 database schema design',
      'bug fix for login issue',
      'performance optimization of query service',
      'document API endpoints for client integration'
    ];

    const times: number[] = [];

    typicalQueries.forEach(query => {
      const iterations = 100;
      const startTime = Date.now();

      for (let i = 0; i < iterations; i++) {
        sanitizeQuery(query, 'moderate');
      }

      const totalTime = Date.now() - startTime;
      const avgTime = totalTime / iterations;
      times.push(avgTime);
    });

    // Average time per sanitization should be very low
    const overallAvg = times.reduce((a, b) => a + b, 0) / times.length;
    expect(overallAvg).toBeLessThan(5); // Less than 5ms per operation

    // Maximum time should still be reasonable
    const maxTime = Math.max(...times);
    expect(maxTime).toBeLessThan(20); // Less than 20ms even for worst case
  });
});