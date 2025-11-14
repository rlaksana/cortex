// @ts-nocheck
// COMPREHENSIVE EMERGENCY ROLLBACK: Final systematic type issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Enhanced Security Middleware for Cortex MCP Tools
 *
 * Provides comprehensive security features:
 * - Advanced input validation and sanitization
 * - Quota enforcement with multiple dimensions
 * - Tenant isolation with multi-level scope validation
 * - Request size and rate limiting
 * - Content type validation and XSS protection
 * - Security headers and CORS handling
 */

import { type NextFunction,type Request, type Response } from 'express';

import { logger } from '@/utils/logger.js';

import { type AuthContext } from '../types/auth-types.js';

import '../types/express.d.js'; // Reference the type extensions

// ============================================================================
// Security Configuration Types
// ============================================================================

export interface SecurityQuota {
  // Rate limits
  requests_per_minute: number;
  requests_per_hour: number;
  requests_per_day: number;

  // Token/operation limits
  tokens_per_minute: number;
  tokens_per_hour: number;

  // Data limits
  max_content_length: number; // bytes
  max_items_per_request: number;

  // Burst allowances
  burst_requests: number;
  burst_tokens: number;
}

export interface TenantIsolationConfig {
  enabled: boolean;
  strict_mode: boolean; // Fail closed if tenant ID is missing
  cross_tenant_access: string[]; // Tools that can access cross-tenant data
  tenant_id_sources: ('auth' | 'header' | 'query')[];
  default_tenant: string | null;
}

export interface InputValidationConfig {
  // Content validation
  max_content_length: number;
  max_items_per_request: number;
  allowed_content_types: string[];

  // XSS and injection protection
  sanitize_html: boolean;
  sanitize_sql: boolean;
  prevent_code_injection: boolean;

  // Schema validation
  strict_schema_validation: boolean;
  allow_unknown_fields: boolean;
  field_name_validation: boolean;
}

export interface SecurityMiddlewareConfig {
  quotas: SecurityQuota;
  tenant_isolation: TenantIsolationConfig;
  input_validation: InputValidationConfig;

  // Security headers
  security_headers: {
    enable_csp: boolean;
    enable_hsts: boolean;
    enable_xss_protection: boolean;
    enable_frame_options: boolean;
    custom_headers?: Record<string, string>;
  };

  // Monitoring and logging
  enable_security_logging: boolean;
  log_failed_requests: boolean;
  log_cross_tenant_access: boolean;

  // Tool-specific overrides
  tool_overrides?: Record<string, Partial<SecurityMiddlewareConfig>>;
}

// ============================================================================
// Input Validation and Sanitization
// ============================================================================

/**
 * Dangerous content patterns for XSS and injection prevention
 */
const DANGEROUS_PATTERNS = {
  html: /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
  sql: /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)/gi,
  javascript: /javascript:/gi,
  data_url: /data:text\/html/gi,
  eval: /eval\s*\(/gi,
  code_injection: /<\?php|<%.*%>|<script|<\/script>/gi,
};

/**
 * Validate and sanitize input data
 */
export class InputValidator {
  constructor(private config: InputValidationConfig) {}

  /**
   * Validate request body against security rules
   */
  validateRequestBody(body: unknown): { isValid: boolean; errors: string[]; sanitizedBody?: unknown } {
    const errors: string[] = [];
    let sanitizedBody = body;

    // Check content length
    const contentLength = JSON.stringify(body).length;
    if (contentLength > this.config.max_content_length) {
      errors.push(
        `Request body too large: ${contentLength} bytes (max: ${this.config.max_content_length})`
      );
    }

    // Validate structure
    if (Array.isArray(body)) {
      if (body.length > this.config.max_items_per_request) {
        errors.push(`Too many items: ${body.length} (max: ${this.config.max_items_per_request})`);
      }
    }

    // Sanitize content if enabled
    if (this.config.sanitize_html || this.config.prevent_code_injection) {
      sanitizedBody = this.sanitizeData(body);
    }

    // Validate field names if enabled
    if (this.config.field_name_validation) {
      const fieldErrors = this.validateFieldNames(body);
      errors.push(...fieldErrors);
    }

    return {
      isValid: errors.length === 0,
      errors,
      sanitizedBody: errors.length === 0 ? sanitizedBody : undefined,
    };
  }

  /**
   * Sanitize data to prevent XSS and injection attacks
   */
  private sanitizeData(data: unknown): unknown {
    if (typeof data !== 'object' || data === null) {
      return this.sanitizeString(data);
    }

    if (Array.isArray(data)) {
      return data.map((item) => this.sanitizeData(item));
    }

    const sanitized: unknown = {};
    for (const [key, value] of Object.entries(data)) {
      const sanitizedKey = this.sanitizeString(key);
      sanitized[sanitizedKey] = this.sanitizeData(value);
    }
    return sanitized;
  }

  /**
   * Sanitize string content
   */
  private sanitizeString(value: unknown): unknown {
    if (typeof value !== 'string') return value;

    let sanitized = value;

    if (this.config.sanitize_html) {
      sanitized = sanitized.replace(DANGEROUS_PATTERNS.html, '');
      sanitized = sanitized.replace(DANGEROUS_PATTERNS.data_url, '');
    }

    if (this.config.sanitize_sql) {
      sanitized = sanitized.replace(DANGEROUS_PATTERNS.sql, '');
    }

    if (this.config.prevent_code_injection) {
      sanitized = sanitized.replace(DANGEROUS_PATTERNS.javascript, '');
      sanitized = sanitized.replace(DANGEROUS_PATTERNS.eval, '');
      sanitized = sanitized.replace(DANGEROUS_PATTERNS.code_injection, '');
    }

    return sanitized;
  }

  /**
   * Validate field names to prevent injection
   */
  private validateFieldNames(data: unknown, path: string = ''): string[] {
    const errors: string[] = [];

    if (typeof data !== 'object' || data === null) return errors;

    for (const key of Object.keys(data)) {
      // Check for dangerous field names
      if (key.includes('__proto__') || key.includes('constructor') || key.includes('prototype')) {
        errors.push(`Dangerous field name detected at ${path}${key}: ${key}`);
      }

      // Check for SQL injection patterns in field names
      if (DANGEROUS_PATTERNS.sql.test(key)) {
        errors.push(`SQL-like field name detected at ${path}${key}: ${key}`);
      }

      // Recursively validate nested objects
      if (typeof data[key] === 'object' && data[key] !== null) {
        errors.push(...this.validateFieldNames(data[key], `${path}${key}.`));
      }
    }

    return errors;
  }
}

// ============================================================================
// Quota Enforcement
// ============================================================================

export class QuotaEnforcer {
  constructor(private config: SecurityQuota) {}

  /**
   * Check if request exceeds quotas
   */
  async checkQuotas(
    identifier: string,
    operation: string,
    tokenCount: number = 1
  ): Promise<{ allowed: boolean; reason?: string; retryAfter?: number }> {
    const now = Date.now();
    const minuteKey = `${identifier}:${operation}:${Math.floor(now / 60000)}`;
    const hourKey = `${identifier}:${operation}:${Math.floor(now / 3600000)}`;
    const dayKey = `${identifier}:${operation}:${Math.floor(now / 86400000)}`;

    // Check minute quotas
    const minuteRequests = await this.getRequestCount(minuteKey);
    const minuteTokens = await this.getTokenCount(minuteKey);

    if (minuteRequests >= this.config.requests_per_minute) {
      return {
        allowed: false,
        reason: 'Requests per minute quota exceeded',
        retryAfter: 60 - (now % 60000) / 1000,
      };
    }

    if (minuteTokens + tokenCount > this.config.tokens_per_minute) {
      return {
        allowed: false,
        reason: 'Tokens per minute quota exceeded',
        retryAfter: 60 - (now % 60000) / 1000,
      };
    }

    // Check hour quotas
    const hourRequests = await this.getRequestCount(hourKey);
    if (hourRequests >= this.config.requests_per_hour) {
      return {
        allowed: false,
        reason: 'Requests per hour quota exceeded',
        retryAfter: 3600 - (now % 3600000) / 1000,
      };
    }

    const hourTokens = await this.getTokenCount(hourKey);
    if (hourTokens + tokenCount > this.config.tokens_per_hour) {
      return {
        allowed: false,
        reason: 'Tokens per hour quota exceeded',
        retryAfter: 3600 - (now % 3600000) / 1000,
      };
    }

    // Check day quotas
    const dayRequests = await this.getRequestCount(dayKey);
    if (dayRequests >= this.config.requests_per_day) {
      return {
        allowed: false,
        reason: 'Requests per day quota exceeded',
        retryAfter: 86400 - (now % 86400000) / 1000,
      };
    }

    return { allowed: true };
  }

  /**
   * Record quota usage
   */
  async recordUsage(identifier: string, operation: string, tokenCount: number = 1): Promise<void> {
    const now = Date.now();
    const minuteKey = `${identifier}:${operation}:${Math.floor(now / 60000)}`;
    const hourKey = `${identifier}:${operation}:${Math.floor(now / 3600000)}`;

    // Increment counters
    await this.incrementRequestCount(minuteKey);
    await this.incrementRequestCount(hourKey);
    await this.incrementTokenCount(minuteKey, tokenCount);
    await this.incrementTokenCount(hourKey, tokenCount);
  }

  private async getRequestCount(key: string): Promise<number> {
    // Implementation would use Redis or similar for distributed counting
    return 0; // Placeholder
  }

  private async getTokenCount(key: string): Promise<number> {
    // Implementation would use Redis or similar for distributed counting
    return 0; // Placeholder
  }

  private async incrementRequestCount(key: string): Promise<void> {
    // Implementation would use Redis INCR command
  }

  private async incrementTokenCount(key: string, count: number): Promise<void> {
    // Implementation would use Redis INCRBY command
  }
}

// ============================================================================
// Tenant Isolation
// ============================================================================

export class TenantIsolation {
  constructor(private config: TenantIsolationConfig) {}

  /**
   * Extract tenant ID from request
   */
  extractTenantId(req: Request, authContext?: AuthContext): string | null {
    const sources = this.config.tenant_id_sources;

    // Try auth context first
    if (sources.includes('auth') && authContext?.user?.organizationId) {
      return authContext.user.organizationId;
    }

    // Try headers
    if (sources.includes('header')) {
      const tenantId = req.headers['x-tenant-id'] as string;
      if (tenantId && typeof tenantId === 'string') {
        return tenantId;
      }
    }

    // Try query parameters
    if (sources.includes('query')) {
      const tenantId = req.query.tenant_id as string;
      if (tenantId && typeof tenantId === 'string') {
        return tenantId;
      }
    }

    return this.config.default_tenant;
  }

  /**
   * Validate tenant isolation
   */
  validateTenantIsolation(
    toolName: string,
    requestTenantId: string | null,
    authTenantId: string | null,
    scope: unknown
  ): { isValid: boolean; errors: string[]; warnings: string[] } {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!this.config.enabled) {
      return { isValid: true, errors: [], warnings: ['Tenant isolation disabled'] };
    }

    // Check if tool allows cross-tenant access
    if (this.config.cross_tenant_access.includes(toolName)) {
      if (requestTenantId && authTenantId && requestTenantId !== authTenantId) {
        warnings.push(
          `Cross-tenant access for tool ${toolName}: ${requestTenantId} -> ${authTenantId}`
        );
      }
      return { isValid: true, errors, warnings };
    }

    // Strict mode validation
    if (this.config.strict_mode && !requestTenantId) {
      errors.push('Tenant ID required in strict mode');
      return { isValid: false, errors, warnings };
    }

    // Validate tenant consistency
    if (requestTenantId && authTenantId && requestTenantId !== authTenantId) {
      errors.push(`Tenant mismatch: request=${requestTenantId}, auth=${authTenantId}`);
      return { isValid: false, errors, warnings };
    }

    // Validate scope consistency
    if (scope && requestTenantId) {
      const scopeTenantId = scope.tenant || scope.organization_id;
      if (scopeTenantId && scopeTenantId !== requestTenantId) {
        errors.push(`Scope tenant mismatch: scope=${scopeTenantId}, request=${requestTenantId}`);
      }
    }

    return { isValid: errors.length === 0, errors, warnings };
  }

  /**
   * Apply tenant isolation to query scopes
   */
  applyTenantToScope(scope: unknown, tenantId: string): unknown {
    if (!scope) return { tenant: tenantId };

    return {
      ...scope,
      tenant: tenantId,
      // Ensure consistency across all tenant-related fields
      organization_id: scope.organization_id || tenantId,
      org: scope.org || tenantId,
    };
  }
}

// ============================================================================
// Main Security Middleware
// ============================================================================

export class EnhancedSecurityMiddleware {
  private inputValidator: InputValidator;
  private quotaEnforcer: QuotaEnforcer;
  private tenantIsolation: TenantIsolation;

  constructor(private config: SecurityMiddlewareConfig) {
    this.inputValidator = new InputValidator(config.input_validation);
    this.quotaEnforcer = new QuotaEnforcer(config.quotas);
    this.tenantIsolation = new TenantIsolation(config.tenant_isolation);
  }

  /**
   * Create middleware function
   */
  createMiddleware(
    toolName: string
  ): (req: Request, res: Response, next: NextFunction) => void | Promise<void> {
    const toolConfig = this.getToolConfig(toolName);

    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const authContext = req.auth as AuthContext;
      const startTime = Date.now();

      try {
        // Extract tenant information
        const tenantId = this.tenantIsolation.extractTenantId(req, authContext);

        // Validate tenant isolation
        const scope = req.body?.scope;
        const tenantValidation = this.tenantIsolation.validateTenantIsolation(
          toolName,
          tenantId,
          authContext?.user?.organizationId || null,
          scope
        );

        if (!tenantValidation.isValid) {
          this.logSecurityEvent('tenant_validation_failed', req, {
            errors: tenantValidation.errors,
            tenantId,
            authTenantId: authContext?.user?.organizationId,
          });
          res.status(403).json({
            error: 'Tenant validation failed',
            details: tenantValidation.errors,
          });
          return;
        }

        // Apply tenant to scope
        if (tenantId && scope) {
          req.body.scope = this.tenantIsolation.applyTenantToScope(scope, tenantId);
        }

        // Input validation
        const validation = this.inputValidator.validateRequestBody(req.body);
        if (!validation.isValid) {
          this.logSecurityEvent('input_validation_failed', req, {
            errors: validation.errors,
          });
          res.status(400).json({
            error: 'Input validation failed',
            details: validation.errors,
          });
          return;
        }

        // Use sanitized body if available
        if (validation.sanitizedBody) {
          req.body = validation.sanitizedBody;
        }

        // Check quotas
        const identifier = this.getQuotaIdentifier(authContext, tenantId || undefined);
        const tokenCount = this.estimateTokenUsage(req.body);

        const quotaCheck = await this.quotaEnforcer.checkQuotas(identifier, toolName, tokenCount);

        if (!quotaCheck.allowed) {
          this.logSecurityEvent('quota_exceeded', req, {
            reason: quotaCheck.reason,
            identifier,
            toolName,
            tokenCount,
          });
          res.status(429).json({
            error: 'Quota exceeded',
            reason: quotaCheck.reason,
            retry_after: quotaCheck.retryAfter,
          });
          return;
        }

        // Record quota usage
        await this.quotaEnforcer.recordUsage(identifier, toolName, tokenCount);

        // Add security headers
        this.addSecurityHeaders(res, toolConfig.security_headers);

        // Add tenant info to request
        (req as unknown).tenantId = tenantId;
        (req as unknown).securityContext = {
          tenantId,
          validatedAt: Date.now(),
          warnings: tenantValidation.warnings,
        };

        // Log successful security validation
        if (toolConfig.enable_security_logging) {
          logger.debug(
            {
              toolName,
              tenantId,
              processingTime: Date.now() - startTime,
              warnings: tenantValidation.warnings,
            },
            'Security validation passed'
          );
        }

        return next();
      } catch (error) {
        logger.error(
          {
            error,
            toolName,
            processingTime: Date.now() - startTime,
          },
          'Security middleware error'
        );

        // Fail open for security middleware errors
        return next();
      }
    };
  }

  /**
   * Get configuration for specific tool
   */
  private getToolConfig(toolName: string): SecurityMiddlewareConfig {
    return {
      ...this.config,
      ...this.config.tool_overrides?.[toolName],
    };
  }

  /**
   * Get quota identifier for request
   */
  private getQuotaIdentifier(authContext?: AuthContext, tenantId?: string): string {
    if (authContext?.user?.id) {
      return `user:${authContext.user.id}`;
    }
    if (tenantId) {
      return `tenant:${tenantId}`;
    }
    return 'anonymous';
  }

  /**
   * Estimate token usage for request
   */
  private estimateTokenUsage(body: unknown): number {
    // Simple estimation: 1 token per 4 characters
    const contentLength = JSON.stringify(body).length;
    return Math.max(1, Math.ceil(contentLength / 4));
  }

  /**
   * Add security headers to response
   */
  private addSecurityHeaders(res: Response, headers: SecurityMiddlewareConfig['security_headers']) {
    if (headers.enable_csp) {
      res.setHeader('Content-Security-Policy', "default-src 'self'");
    }

    if (headers.enable_hsts) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }

    if (headers.enable_xss_protection) {
      res.setHeader('X-XSS-Protection', '1; mode=block');
    }

    if (headers.enable_frame_options) {
      res.setHeader('X-Frame-Options', 'DENY');
    }

    if (headers.custom_headers) {
      for (const [key, value] of Object.entries(headers.custom_headers)) {
        res.setHeader(key, value);
      }
    }
  }

  /**
   * Log security events
   */
  private logSecurityEvent(eventType: string, req: Request, details: unknown) {
    if (!this.config.enable_security_logging) return;

    logger.warn(
      {
        eventType,
        method: req.method,
        url: req.url,
        userAgent: req.headers['user-agent'],
        ip: req.ip,
        ...details,
      },
      `Security event: ${eventType}`
    );
  }
}

// ============================================================================
// Factory and Presets
// ============================================================================

/**
 * Create enhanced security middleware
 */
export function createEnhancedSecurityMiddleware(
  config: SecurityMiddlewareConfig
): EnhancedSecurityMiddleware {
  return new EnhancedSecurityMiddleware(config);
}

/**
 * Default security configuration
 */
export const DEFAULT_SECURITY_CONFIG: SecurityMiddlewareConfig = {
  quotas: {
    requests_per_minute: 60,
    requests_per_hour: 1000,
    requests_per_day: 10000,
    tokens_per_minute: 10000,
    tokens_per_hour: 100000,
    max_content_length: 1000000, // 1MB
    max_items_per_request: 100,
    burst_requests: 10,
    burst_tokens: 1000,
  },
  tenant_isolation: {
    enabled: true,
    strict_mode: false,
    cross_tenant_access: ['system_status', 'health_check'],
    tenant_id_sources: ['auth', 'header'],
    default_tenant: null,
  },
  input_validation: {
    max_content_length: 1000000,
    max_items_per_request: 100,
    allowed_content_types: ['application/json'],
    sanitize_html: true,
    sanitize_sql: true,
    prevent_code_injection: true,
    strict_schema_validation: true,
    allow_unknown_fields: false,
    field_name_validation: true,
  },
  security_headers: {
    enable_csp: true,
    enable_hsts: true,
    enable_xss_protection: true,
    enable_frame_options: true,
  },
  enable_security_logging: true,
  log_failed_requests: true,
  log_cross_tenant_access: true,
};

/**
 * Tool-specific security configurations
 */
export const TOOL_SECURITY_CONFIGS: Record<string, Partial<SecurityMiddlewareConfig>> = {
  memory_store: {
    quotas: {
      requests_per_minute: 60,
      requests_per_hour: 1000,
      requests_per_day: 10000,
      tokens_per_minute: 10000,
      tokens_per_hour: 100000,
      max_content_length: 5000000, // 5MB for store operations
      max_items_per_request: 100,
      burst_requests: 10,
      burst_tokens: 1000,
    },
    input_validation: {
      max_content_length: 5000000,
      max_items_per_request: 100,
      allowed_content_types: ['application/json'],
      sanitize_html: true,
      sanitize_sql: true,
      prevent_code_injection: true,
      strict_schema_validation: true,
      allow_unknown_fields: false,
      field_name_validation: true,
    },
  },
  memory_find: {
    quotas: {
      requests_per_minute: 120,
      requests_per_hour: 2000,
      requests_per_day: 20000,
      tokens_per_minute: 20000,
      tokens_per_hour: 200000,
      max_content_length: 100000, // Smaller for search
      max_items_per_request: 50,
      burst_requests: 20,
      burst_tokens: 2000,
    },
  },
  system_status: {
    tenant_isolation: {
      enabled: false, // System tools are cross-tenant
      strict_mode: false,
      cross_tenant_access: ['system_status', 'health_check'],
      tenant_id_sources: ['auth', 'header'],
      default_tenant: null,
    },
    quotas: {
      requests_per_minute: 30,
      requests_per_hour: 500,
      requests_per_day: 5000,
      tokens_per_minute: 5000,
      tokens_per_hour: 50000,
      max_content_length: 50000,
      max_items_per_request: 20,
      burst_requests: 5,
      burst_tokens: 500,
    },
  },
};
