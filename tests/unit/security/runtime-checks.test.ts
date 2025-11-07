/**
 * Security Runtime Checks Tests
 *
 * Tests for the security validation system including
 * input validation, XSS protection, and SQL injection detection.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  SecurityRuntimeChecker,
  securityChecker,
  validateSecurity,
  secureInput,
  SecurityViolation,
} from '../../../src/security/runtime-checks.js';

describe('Security Runtime Checker', () => {
  let checker: SecurityRuntimeChecker;

  beforeEach(() => {
    checker = new SecurityRuntimeChecker();
  });

  afterEach(() => {
    checker.clearHistory();
  });

  describe('Input Validation', () => {
    it('should pass valid input', () => {
      const violations = checker.validateInput('Hello World 123');
      expect(violations).toHaveLength(0);
    });

    it('should detect input length violations', () => {
      const longInput = 'a'.repeat(10001); // Exceeds default max
      const violations = checker.validateInput(longInput);

      expect(violations.length).toBeGreaterThan(0);
      const lengthViolation = violations.find((v) => v.type === 'LENGTH_EXCEEDED');
      expect(lengthViolation).toBeDefined();
      expect(lengthViolation?.severity).toBe('medium');
    });

    it('should detect blocked patterns', () => {
      const sqlInput = 'SELECT * FROM users WHERE id = 1';
      const violations = checker.validateInput(sqlInput);

      expect(violations.length).toBeGreaterThan(0);
      const sqlViolation = violations.find((v) => v.type === 'BLOCKED_PATTERN');
      expect(sqlViolation).toBeDefined();
      expect(sqlViolation?.severity).toBe('high');
    });

    it('should respect allowed patterns when configured', () => {
      const config = {
        allowedPatterns: [/^[a-zA-Z0-9\s]+$/],
      };
      const customChecker = new SecurityRuntimeChecker(config);

      const violations = customChecker.validateInput('Hello123'); // Should pass
      expect(violations).toHaveLength(0);

      const violations2 = customChecker.validateInput('Hello!'); // Should fail
      expect(violations2.length).toBeGreaterThan(0);
      expect(violations2[0].type).toBe('PATTERN_NOT_ALLOWED');
    });
  });

  describe('SQL Injection Detection', () => {
    it('should detect SQL injection attempts', () => {
      const sqlInputs = [
        'SELECT * FROM users',
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        'UNION SELECT password FROM users',
      ];

      for (const input of sqlInputs) {
        const violations = checker.validateInput(input);
        const sqlViolation = violations.find((v) => v.type === 'SQL_INJECTION');
        expect(sqlViolation).toBeDefined();
        expect(sqlViolation?.severity).toMatch(/high|critical/);
      }
    });

    it('should detect dangerous SQL functions', () => {
      const dangerousInputs = [
        "LOAD_FILE('/etc/passwd')",
        "INTO OUTFILE '/tmp/shell.php'",
        'SELECT * FROM INFORMATION_SCHEMA['TABLES']',
      ];

      for (const input of dangerousInputs) {
        const violations = checker.validateInput(input);
        const sqlViolation = violations.find((v) => v.type === 'SQL_INJECTION');
        expect(sqlViolation?.severity).toBe('critical');
      }
    });

    it('should not flag benign SQL-like text', () => {
      const benignInputs = [
        'I selected the best option',
        'Insert your name here',
        'Update your profile',
        'Delete this comment',
      ];

      for (const input of benignInputs) {
        const violations = checker.validateInput(input);
        const sqlViolation = violations.find((v) => v.type === 'SQL_INJECTION');
        expect(sqlViolation).toBeUndefined();
      }
    });
  });

  describe('XSS Detection', () => {
    it('should detect XSS attempts', () => {
      const xssInputs = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        '<iframe src=\'javascript:alert("XSS")\'></iframe>',
      ];

      for (const input of xssInputs) {
        const violations = checker.validateInput(input);
        const xssViolation = violations.find((v) => v.type === 'XSS');
        expect(xssViolation).toBeDefined();
        expect(xssViolation?.severity).toMatch(/medium|high|critical/);
      }
    });

    it('should detect script tags with critical severity', () => {
      const scriptInput = "<script>alert('test')</script>";
      const violations = checker.validateInput(scriptInput);

      const xssViolation = violations.find((v) => v.type === 'XSS');
      expect(xssViolation?.severity).toBe('critical');
    });

    it('should not flag benign HTML-like text', () => {
      const benignInputs = [
        'This is <strong>bold</strong> text',
        'Visit www.example.com for more info',
        'The <script> tag is used for JavaScript',
        'JavaScript is a programming language',
      ];

      for (const input of benignInputs) {
        const violations = checker.validateInput(input);
        const xssViolation = violations.find((v) => v.type === 'XSS');
        expect(xssViolation).toBeUndefined();
      }
    });
  });

  describe('Path Traversal Detection', () => {
    it('should detect path traversal attempts', () => {
      const pathInputs = [
        '../../../etc/passwd',
        '..\\..\\windows\\system32\\config\\sam',
        '/etc/passwd',
        'C:\\Windows\\System32\\config\\SAM',
        '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      ];

      for (const input of pathInputs) {
        const violations = checker.validateInput(input);
        const pathViolation = violations.find((v) => v.type === 'PATH_TRAVERSAL');
        expect(pathViolation).toBeDefined();
        expect(pathViolation?.severity).toMatch(/high|critical/);
      }
    });

    it('should validate file paths with allowed paths', () => {
      const allowedPaths = ['/var/www/uploads', '/tmp'];

      // Valid path
      const violations1 = checker.validateFilePath('/var/www/uploads/file.txt', allowedPaths);
      expect(violations1.filter((v) => v.type === 'UNAUTHORIZED_PATH')).toHaveLength(0);

      // Invalid path
      const violations2 = checker.validateFilePath('/etc/passwd', allowedPaths);
      expect(violations2.some((v) => v.type === 'UNAUTHORIZED_PATH')).toBe(true);
    });

    it('should detect dangerous file extensions', () => {
      const dangerousFiles = ['script.exe', 'malware.bat', 'hack.ps1', 'virus.scr'];

      for (const file of dangerousFiles) {
        const violations = checker.validateFilePath(file);
        const extViolation = violations.find((v) => v.type === 'DANGEROUS_EXTENSION');
        expect(extViolation).toBeDefined();
        expect(extViolation?.severity).toBe('medium');
      }
    });
  });

  describe('Command Injection Detection', () => {
    it('should detect command injection attempts', () => {
      const commandInputs = [
        'file.txt; rm -rf /',
        'data | cat /etc/passwd',
        'name && curl malicious.com',
        'input `whoami` more',
        'test $(ls -la) data',
      ];

      for (const input of commandInputs) {
        const violations = checker.validateInput(input);
        const cmdViolation = violations.find((v) => v.type === 'COMMAND_INJECTION');
        expect(cmdViolation).toBeDefined();
        expect(cmdViolation?.severity).toMatch(/medium|high/);
      }
    });

    it('should detect dangerous command names', () => {
      const dangerousCommands = [
        'rm file.txt',
        'format c:',
        'ping -t google.com',
        'curl malicious.com',
        'powershell -command "calc"',
      ];

      for (const input of dangerousCommands) {
        const violations = checker.validateInput(input);
        const cmdViolation = violations.find((v) => v.type === 'COMMAND_INJECTION');
        expect(cmdViolation?.severity).toBe('high');
      }
    });
  });

  describe('URL Validation', () => {
    it('should validate safe URLs', () => {
      const safeUrls = [
        'https://example.com',
        'http://localhost:3000',
        'https://api.service.com/v1/data',
      ];

      for (const url of safeUrls) {
        const violations = checker.validateUrl(url);
        expect(violations.filter((v) => v.severity === 'critical')).toHaveLength(0);
      }
    });

    it('should detect malicious URLs', () => {
      const maliciousUrls = [
        'javascript:alert("XSS")',
        'data:text/html,<script>alert("XSS")</script>',
        'vbscript:msgbox("XSS")',
        'file:///etc/passwd',
      ];

      for (const url of maliciousUrls) {
        const violations = checker.validateUrl(url);
        const suspiciousViolation = violations.find((v) => v.type === 'SUSPICIOUS_URL');
        expect(suspiciousViolation?.severity).toBe('critical');
      }
    });

    it('should validate URL domains against allowed list', () => {
      const allowedDomains = ['example.com', 'trusted.com'];

      // Valid domain
      const violations1 = checker.validateUrl('https://example.com/path', allowedDomains);
      expect(violations1.filter((v) => v.type === 'UNAUTHORIZED_DOMAIN')).toHaveLength(0);

      // Invalid domain
      const violations2 = checker.validateUrl('https://malicious.com/path', allowedDomains);
      expect(violations2.some((v) => v.type === 'UNAUTHORIZED_DOMAIN')).toBe(true);
    });

    it('should handle malformed URLs', () => {
      const malformedUrls = ['not-a-url', 'ht tp://broken-url', '://missing-protocol.com'];

      for (const url of malformedUrls) {
        const violations = checker.validateUrl(url);
        const invalidViolation = violations.find((v) => v.type === 'INVALID_URL');
        expect(invalidViolation).toBeDefined();
        expect(invalidViolation?.severity).toBe('medium');
      }
    });
  });

  describe('Statistics and History', () => {
    it('should track violation statistics', () => {
      // Generate various violations
      checker.validateInput("'; DROP TABLE users; --");
      checker.validateInput('<script>alert("XSS")</script>');
      checker.validateInput('../../../etc/passwd');
      checker.validateInput('<script>alert("XSS")</script>'); // Another XSS

      const stats = checker.getStatistics();

      expect(stats.total).toBe(4);
      expect(stats.byType['SQL_INJECTION']).toBe(1);
      expect(stats.byType['XSS']).toBe(2);
      expect(stats.byType['PATH_TRAVERSAL']).toBe(1);
      expect(stats.bySeverity['critical']).toBe(3);
      expect(stats.bySeverity['high']).toBe(1);
      expect(stats.recent).toHaveLength(4);
    });

    it('should clear violation history', () => {
      checker.validateInput('<script>alert("XSS")</script>');
      expect(checker.getStatistics().total).toBe(1);

      checker.clearHistory();
      expect(checker.getStatistics().total).toBe(0);
    });

    it('should limit history size', () => {
      // Create a custom checker with small history
      const smallChecker = new SecurityRuntimeChecker();
      (smallChecker as any).maxHistorySize = 3;

      // Generate more violations than limit
      for (let i = 0; i < 5; i++) {
        smallChecker.validateInput('<script>alert("XSS")</script>');
      }

      const stats = smallChecker.getStatistics();
      expect(stats.total).toBeLessThanOrEqual(3);
    });
  });

  describe('Configuration', () => {
    it('should update configuration', () => {
      const newConfig = {
        maxInputLength: 500,
        blockedPatterns: [/test/i],
      };

      checker.updateConfig(newConfig);
      const config = checker.getConfig();

      expect(config.maxInputLength).toBe(500);
      expect(config.blockedPatterns).toContain(/test/i);
    });

    it('should use custom validators', () => {
      const customValidator = (input: string): SecurityViolation | null => {
        if (input.includes('forbidden')) {
          return {
            type: 'CUSTOM_RULE',
            severity: 'high',
            message: 'Custom forbidden word detected',
            input,
            timestamp: Date.now(),
          };
        }
        return null;
      };

      const config = {
        customValidators: [customValidator],
      };

      const customChecker = new SecurityRuntimeChecker(config);
      const violations = customChecker.validateInput('This contains forbidden word');

      expect(violations.some((v) => v.type === 'CUSTOM_RULE')).toBe(true);
    });
  });

  describe('Event Emission', () => {
    it('should emit events for violations', () => {
      const mockEmit = vi.spyOn(checker, 'emit');

      checker.validateInput('<script>alert("XSS")</script>');

      expect(mockEmit).toHaveBeenCalledWith('violation', expect.any(Object));
      expect(mockEmit).toHaveBeenCalledWith('critical', expect.any(Object));
    });

    it('should emit critical events for critical violations', () => {
      const mockEmit = vi.spyOn(checker, 'emit');

      checker.validateInput('LOAD_FILE("/etc/passwd")');

      expect(mockEmit).toHaveBeenCalledWith('critical', expect.any(Object));
    });
  });
});

describe('Security Validation Functions', () => {
  describe('validateSecurity', () => {
    it('should return true for safe input', () => {
      expect(validateSecurity('Safe input 123')).toBe(true);
    });

    it('should return false for malicious input', () => {
      expect(validateSecurity('<script>alert("XSS")</script>')).toBe(false);
    });
  });

  describe('secureInput Decorator', () => {
    class TestClass {
      @secureInput({ throwOnViolation: false })
      public processInput(input: string): string {
        return `Processed: ${input}`;
      }

      @secureInput({ throwOnViolation: true })
      public strictProcess(input: string): string {
        return `Strict: ${input}`;
      }

      @secureInput({ context: { operation: 'user-data' } })
      public contextualProcess(input: string): string {
        return `Context: ${input}`;
      }
    }

    it('should monitor method inputs without throwing', () => {
      const instance = new TestClass();
      const mockEmit = vi.spyOn(securityChecker, 'emit');

      const result = instance.processInput('<script>alert("XSS")</script>');

      expect(result).toBe('Processed: <script>alert("XSS")</script>');
      expect(mockEmit).toHaveBeenCalledWith('critical', expect.any(Object));
    });

    it('should throw on violations when configured', () => {
      const instance = new TestClass();

      expect(() => instance.strictProcess('<script>alert("XSS")</script>')).toThrow(
        'Security violation'
      );
    });

    it('should include context in validation', () => {
      const instance = new TestClass();
      const mockValidate = vi.spyOn(securityChecker, 'validateInput');

      instance.contextualProcess('test input');

      expect(mockValidate).toHaveBeenCalledWith(
        'test input',
        expect.objectContaining({ operation: 'user-data' })
      );
    });

    it('should handle multiple string arguments', () => {
      const mockValidate = vi.spyOn(securityChecker, 'validateInput');

      const instance = new TestClass();
      instance.processInput('input1');

      expect(mockValidate).toHaveBeenCalledWith(
        'input1',
        expect.objectContaining({
          className: 'TestClass',
          method: 'processInput',
          argumentIndex: 0,
        })
      );
    });

    it('should handle non-string arguments gracefully', () => {
      const instance = new TestClass();
      const mockValidate = vi.spyOn(securityChecker, 'validateInput');

      expect(() => instance.processInput(123 as any)).not.toThrow();
      expect(mockValidate).not.toHaveBeenCalled();
    });
  });
});
