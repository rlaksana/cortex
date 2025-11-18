// FINAL TRIUMPHANT VICTORY EMERGENCY ROLLBACK: Complete the great migration rescue

/**
 * Security Runtime Checks
 *
 * Comprehensive runtime security validation for all user inputs
 * and system operations to prevent common security vulnerabilities.
 */

import { EventEmitter } from 'node:events';

export interface SecurityViolation {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  input: string;
  context?: Record<string, unknown>;
  timestamp: number;
}

export interface SecurityConfig {
  maxInputLength: number;
  allowedPatterns: RegExp[];
  blockedPatterns: RegExp[];
  enableSqlInjectionCheck: boolean;
  enableXssCheck: boolean;
  enablePathTraversalCheck: boolean;
  enableCommandInjectionCheck: boolean;
  customValidators: Array<
    (input: string, context?: Record<string, unknown>) => SecurityViolation | null
  >;
}

/**
 * Default security configuration
 */
const DEFAULT_CONFIG: SecurityConfig = {
  maxInputLength: 10000,
  allowedPatterns: [],
  blockedPatterns: [
    // SQL Injection patterns
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)/gi,
    /('|\\'|--|\bOR\b.*=.*\bOR\b)/gi,

    // XSS patterns
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,

    // Path traversal patterns
    /\.\.[\/\\]/g,
    /[\/\\]\.\.[\/\\]/g,

    // Command injection patterns
    /[;&|`$(){}[\]]/g,
    /\b(cat|ls|dir|rm|del|format|ping|curl|wget)\b/gi,
  ],
  enableSqlInjectionCheck: true,
  enableXssCheck: true,
  enablePathTraversalCheck: true,
  enableCommandInjectionCheck: true,
  customValidators: [],
};

/**
 * Security Runtime Checker
 */
export class SecurityRuntimeChecker extends EventEmitter {
  private config: SecurityConfig;
  private violationHistory: SecurityViolation[] = [];
  private maxHistorySize = 1000;

  constructor(config: Partial<SecurityConfig> = {}) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Validate user input against security rules
   */
  validateInput(input: string, context?: Record<string, unknown>): SecurityViolation[] {
    const violations: SecurityViolation[] = [];
    const now = Date.now();

    // Length validation
    if (input.length > this.config.maxInputLength) {
      violations.push({
        type: 'LENGTH_EXCEEDED',
        severity: 'medium',
        message: `Input exceeds maximum length of ${this.config.maxInputLength} characters`,
        input,
        context,
        timestamp: now,
      });
    }

    // Blocked patterns validation
    for (const pattern of this.config.blockedPatterns) {
      if (pattern.test(input)) {
        violations.push({
          type: 'BLOCKED_PATTERN',
          severity: 'high',
          message: `Input contains blocked pattern`,
          input,
          context,
          timestamp: now,
        });
      }
    }

    // Allowed patterns validation (if specified)
    if (this.config.allowedPatterns.length > 0) {
      const allowed = this.config.allowedPatterns.some((pattern) => pattern.test(input));
      if (!allowed) {
        violations.push({
          type: 'PATTERN_NOT_ALLOWED',
          severity: 'medium',
          message: 'Input does not match any allowed patterns',
          input,
          context,
          timestamp: now,
        });
      }
    }

    // Specific security checks
    if (this.config.enableSqlInjectionCheck) {
      violations.push(...this.checkSqlInjection(input, context));
    }

    if (this.config.enableXssCheck) {
      violations.push(...this.checkXss(input, context));
    }

    if (this.config.enablePathTraversalCheck) {
      violations.push(...this.checkPathTraversal(input, context));
    }

    if (this.config.enableCommandInjectionCheck) {
      violations.push(...this.checkCommandInjection(input, context));
    }

    // Custom validators
    for (const validator of this.config.customValidators) {
      const violation = validator(input, context);
      if (violation) {
        violations.push(violation);
      }
    }

    // Record violations and emit events
    if (violations.length > 0) {
      this.recordViolations(violations);

      for (const violation of violations) {
        this.emit('violation', violation);

        if (violation.severity === 'critical') {
          this.emit('critical', violation);
        }
      }
    }

    return violations;
  }

  /**
   * Check for SQL injection patterns
   */
  private checkSqlInjection(input: string, context?: Record<string, unknown>): SecurityViolation[] {
    const violations: SecurityViolation[] = [];
    const now = Date.now();

    const sqlPatterns = [
      {
        pattern: /\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\b/gi,
        severity: 'high' as const,
      },
      { pattern: /('|\\'|;|\bOR\b.*=.*\bOR\b)/gi, severity: 'medium' as const },
      {
        pattern: /\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b/gi,
        severity: 'critical' as const,
      },
      { pattern: /\b(INFORMATION_SCHEMA|SYS|MASTER|MSDB)\b/gi, severity: 'high' as const },
    ];

    for (const { pattern, severity } of sqlPatterns) {
      if (pattern.test(input)) {
        violations.push({
          type: 'SQL_INJECTION',
          severity,
          message: `Potential SQL injection detected`,
          input,
          context,
          timestamp: now,
        });
      }
    }

    return violations;
  }

  /**
   * Check for XSS patterns
   */
  private checkXss(input: string, context?: Record<string, unknown>): SecurityViolation[] {
    const violations: SecurityViolation[] = [];
    const now = Date.now();

    const xssPatterns = [
      {
        pattern: /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        severity: 'critical' as const,
      },
      { pattern: /javascript:/gi, severity: 'high' as const },
      { pattern: /on\w+\s*=/gi, severity: 'high' as const },
      { pattern: /<iframe\b[^>]*>/gi, severity: 'medium' as const },
      { pattern: /<object\b[^>]*>/gi, severity: 'medium' as const },
      { pattern: /<embed\b[^>]*>/gi, severity: 'medium' as const },
      { pattern: /expression\s*\(/gi, severity: 'high' as const },
      { pattern: /@import/gi, severity: 'medium' as const },
    ];

    for (const { pattern, severity } of xssPatterns) {
      if (pattern.test(input)) {
        violations.push({
          type: 'XSS',
          severity,
          message: `Potential XSS detected`,
          input,
          context,
          timestamp: now,
        });
      }
    }

    return violations;
  }

  /**
   * Check for path traversal patterns
   */
  private checkPathTraversal(
    input: string,
    context?: Record<string, unknown>
  ): SecurityViolation[] {
    const violations: SecurityViolation[] = [];
    const now = Date.now();

    const pathTraversalPatterns = [
      { pattern: /\.\.[\/\\]/g, severity: 'high' as const },
      { pattern: /[\/\\]\.\.[\/\\]/g, severity: 'high' as const },
      { pattern: /%2e%2e[\/\\]/gi, severity: 'high' as const },
      { pattern: /\.\.%2f/gi, severity: 'high' as const },
      { pattern: /\.\.%5c/gi, severity: 'high' as const },
      { pattern: /\/etc\/passwd/gi, severity: 'critical' as const },
      { pattern: /\/proc\/\//gi, severity: 'critical' as const },
      { pattern: /C:\\Windows\\System32/gi, severity: 'critical' as const },
    ];

    for (const { pattern, severity } of pathTraversalPatterns) {
      if (pattern.test(input)) {
        violations.push({
          type: 'PATH_TRAVERSAL',
          severity,
          message: `Potential path traversal detected`,
          input,
          context,
          timestamp: now,
        });
      }
    }

    return violations;
  }

  /**
   * Check for command injection patterns
   */
  private checkCommandInjection(
    input: string,
    context?: Record<string, unknown>
  ): SecurityViolation[] {
    const violations: SecurityViolation[] = [];
    const now = Date.now();

    const commandPatterns = [
      { pattern: /[;&|`$(){}[\]]/g, severity: 'medium' as const },
      {
        pattern: /\b(cat|ls|dir|rm|del|format|ping|curl|wget|nc|netcat)\b/gi,
        severity: 'high' as const,
      },
      { pattern: /\b(powershell|cmd|bash|sh|csh|tcsh|zsh)\b/gi, severity: 'high' as const },
      { pattern: />\s*\/dev\/null/gi, severity: 'medium' as const },
      { pattern: /\|\s*tee/gi, severity: 'medium' as const },
      { pattern: /&&\s*\w+/gi, severity: 'medium' as const },
      { pattern: /\|\|\s*\w+/gi, severity: 'medium' as const },
    ];

    for (const { pattern, severity } of commandPatterns) {
      if (pattern.test(input)) {
        violations.push({
          type: 'COMMAND_INJECTION',
          severity,
          message: `Potential command injection detected`,
          input,
          context,
          timestamp: now,
        });
      }
    }

    return violations;
  }

  /**
   * Validate file path for security
   */
  validateFilePath(filePath: string, allowedPaths?: string[]): SecurityViolation[] {
    const violations: SecurityViolation[] = [];
    const now = Date.now();

    // Normalize path
    const normalizedPath = filePath.replace(/\\/g, '/');

    // Check for path traversal
    if (normalizedPath.includes('../') || normalizedPath.includes('..\\')) {
      violations.push({
        type: 'PATH_TRAVERSAL',
        severity: 'critical',
        message: 'Path traversal detected in file path',
        input: filePath,
        context: { normalizedPath },
        timestamp: now,
      });
    }

    // Check against allowed paths
    if (allowedPaths && allowedPaths.length > 0) {
      const isAllowed = allowedPaths.some((allowedPath) =>
        normalizedPath.startsWith(allowedPath.replace(/\\/g, '/'))
      );

      if (!isAllowed) {
        violations.push({
          type: 'UNAUTHORIZED_PATH',
          severity: 'high',
          message: 'File path is not in allowed paths',
          input: filePath,
          context: { allowedPaths, normalizedPath },
          timestamp: now,
        });
      }
    }

    // Check for dangerous file extensions
    const dangerousExtensions = [
      '.exe',
      '.bat',
      '.cmd',
      '.sh',
      '.ps1',
      '.scr',
      '.vbs',
      '.js',
      '.jar',
    ];
    const extension = normalizedPath.toLowerCase().substring(normalizedPath.lastIndexOf('.'));

    if (dangerousExtensions.includes(extension)) {
      violations.push({
        type: 'DANGEROUS_EXTENSION',
        severity: 'medium',
        message: `File has potentially dangerous extension: ${extension}`,
        input: filePath,
        context: { extension },
        timestamp: now,
      });
    }

    // Record violations and emit events
    if (violations.length > 0) {
      this.recordViolations(violations);

      for (const violation of violations) {
        this.emit('violation', violation);
      }
    }

    return violations;
  }

  /**
   * Validate URL for security
   */
  validateUrl(url: string, allowedDomains?: string[]): SecurityViolation[] {
    const violations: SecurityViolation[] = [];
    const now = Date.now();

    try {
      const parsedUrl = new URL(url);

      // Check protocol
      const allowedProtocols = ['http:', 'https:'];
      if (!allowedProtocols.includes(parsedUrl.protocol)) {
        violations.push({
          type: 'INVALID_PROTOCOL',
          severity: 'high',
          message: `URL has invalid protocol: ${parsedUrl.protocol}`,
          input: url,
          context: { protocol: parsedUrl.protocol },
          timestamp: now,
        });
      }

      // Check against allowed domains
      if (allowedDomains && allowedDomains.length > 0) {
        if (!allowedDomains.includes(parsedUrl.hostname)) {
          violations.push({
            type: 'UNAUTHORIZED_DOMAIN',
            severity: 'high',
            message: `URL domain is not allowed: ${parsedUrl.hostname}`,
            input: url,
            context: { hostname: parsedUrl.hostname, allowedDomains },
            timestamp: now,
          });
        }
      }

      // Check for suspicious patterns in URL
      const suspiciousPatterns = [/javascript:/gi, /data:/gi, /vbscript:/gi, /file:/gi, /ftp:/gi];

      for (const pattern of suspiciousPatterns) {
        if (pattern.test(url)) {
          violations.push({
            type: 'SUSPICIOUS_URL',
            severity: 'critical',
            message: `URL contains suspicious pattern`,
            input: url,
            context: {},
            timestamp: now,
          });
        }
      }
    } catch (error) {
      violations.push({
        type: 'INVALID_URL',
        severity: 'medium',
        message: 'URL is malformed',
        input: url,
        context: { error: (error as Error).message },
        timestamp: now,
      });
    }

    // Record violations and emit events
    if (violations.length > 0) {
      this.recordViolations(violations);

      for (const violation of violations) {
        this.emit('violation', violation);
      }
    }

    return violations;
  }

  /**
   * Record security violations
   */
  private recordViolations(violations: SecurityViolation[]): void {
    this.violationHistory.push(...violations);

    // Maintain history size limit
    if (this.violationHistory.length > this.maxHistorySize) {
      this.violationHistory.splice(0, this.violationHistory.length - this.maxHistorySize);
    }
  }

  /**
   * Get violation statistics
   */
  getStatistics(): {
    total: number;
    byType: Record<string, number>;
    bySeverity: Record<string, number>;
    recent: SecurityViolation[];
  } {
    const stats = {
      total: this.violationHistory.length,
      byType: {} as Record<string, number>,
      bySeverity: {} as Record<string, number>,
      recent: this.violationHistory.slice(-10),
    };

    for (const violation of this.violationHistory) {
      stats.byType[violation.type] = (stats.byType[violation.type] || 0) + 1;
      stats.bySeverity[violation.severity] = (stats.bySeverity[violation.severity] || 0) + 1;
    }

    return stats;
  }

  /**
   * Clear violation history
   */
  clearHistory(): void {
    this.violationHistory = [];
    this.emit('history_cleared');
  }

  /**
   * Update security configuration
   */
  updateConfig(newConfig: Partial<SecurityConfig>): void {
    this.config = { ...this.config, ...newConfig };
    this.emit('config_updated', this.config);
  }

  /**
   * Get current configuration
   */
  getConfig(): SecurityConfig {
    return { ...this.config };
  }
}

// Global security checker instance
export const securityChecker = new SecurityRuntimeChecker();

/**
 * Security validation middleware
 */
export function validateSecurity(input: string, context?: Record<string, unknown>): boolean {
  const violations = securityChecker.validateInput(input, context);
  return violations.length === 0;
}

/**
 * Security validation decorator
 */
export function secureInput(
  options: {
    context?: Record<string, unknown>;
    throwOnViolation?: boolean;
  } = {}
) {
  return function (target: unknown, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = function (...args: any[]) {
      for (let i = 0; i < args.length; i++) {
        if (typeof args[i] === 'string') {
          const violations = securityChecker.validateInput(args[i], {
            ...options.context,
            className: target.constructor.name,
            method: propertyKey,
            argumentIndex: i,
          });

          if (violations.length > 0) {
            const criticalViolation = violations.find((v) => v.severity === 'critical');

            if (criticalViolation) {
              if (options.throwOnViolation) {
                throw new Error(`Security violation: ${criticalViolation.message}`);
              } else {
                securityChecker.emit('critical', criticalViolation);
              }
            }
          }
        }
      }

      return originalMethod.apply(this, args);
    };

    return descriptor;
  };
}
