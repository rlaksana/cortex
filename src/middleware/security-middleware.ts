/**
 * Security Middleware for Cortex MCP
 * Provides comprehensive security hardening including rate limiting, input validation, and security headers
 */

import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { logger } from '../utils/logger.js';
import { z, ZodSchema } from 'zod';

export interface SecurityConfig {
  enableRateLimit?: boolean;
  enableInputValidation?: boolean;
  enableSecurityHeaders?: boolean;
  enableCORS?: boolean;
  rateLimitWindowMs?: number;
  rateLimitMax?: number;
  maxRequestSize?: number;
  allowedOrigins?: string[];
  blockedIPs?: string[];
}

export interface ValidationError {
  field: string;
  message: string;
  value?: any;
}

export class SecurityMiddleware {
  private config: SecurityConfig;
  private blockedIPs: Set<string>;
  private requestCounts: Map<string, { count: number; resetTime: number }> = new Map();

  constructor(config: SecurityConfig = {}) {
    this.config = {
      enableRateLimit: true,
      enableInputValidation: true,
      enableSecurityHeaders: true,
      enableCORS: true,
      rateLimitWindowMs: 15 * 60 * 1000, // 15 minutes
      rateLimitMax: 100, // 100 requests per window
      maxRequestSize: 10 * 1024 * 1024, // 10MB
      allowedOrigins: ['http://localhost:3000', 'http://localhost:5173'],
      blockedIPs: [],
      ...config,
    };

    this.blockedIPs = new Set(this.config.blockedIPs || []);
  }

  /**
   * Comprehensive security middleware
   */
  security() {
    return (req: Request, res: Response, next: NextFunction) => {
      // Check if IP is blocked
      if (this.isIPBlocked(req.ip || '')) {
        logger.warn({ ip: req.ip, path: req.path }, 'Blocked IP attempted access');
        res.status(403).json({ error: 'Access denied' });
        return;
      }

      // Apply security headers
      if (this.config.enableSecurityHeaders) {
        this.applySecurityHeaders(req, res);
      }

      // Apply CORS headers
      if (this.config.enableCORS) {
        this.applyCORS(req, res);
      }

      // Validate request size
      if (!this.validateRequestSize(req)) {
        res.status(413).json({ error: 'Request too large' });
        return;
      }

      // Apply rate limiting
      if (this.config.enableRateLimit && !this.checkRateLimit(req, res)) {
        next();
        return;
      }

      // Continue to next middleware
      next();
    };
  }

  /**
   * Rate limiting middleware
   */
  rateLimit(options?: { windowMs?: number; max?: number; message?: string }) {
    const opts = {
      windowMs: options?.windowMs || this.config.rateLimitWindowMs!,
      max: options?.max || this.config.rateLimitMax!,
      message: options?.message || 'Too many requests from this IP',
      standardHeaders: true,
      legacyHeaders: false,
      handler: (req: Request, res: Response) => {
        logger.warn(
          {
            ip: req.ip,
            path: req.path,
            userAgent: req.headers['user-agent'],
          },
          'Rate limit exceeded'
        );

        res.status(429).json({
          error: 'Too many requests',
          message: opts.message,
          retryAfter: Math.ceil(opts.windowMs / 1000),
        });
      },
    };

    return rateLimit(opts);
  }

  /**
   * Input validation middleware using Zod schemas
   */
  validateInput(schema: ZodSchema, target: 'body' | 'query' | 'params' = 'body') {
    return (req: Request, res: Response, next: NextFunction) => {
      if (!this.config.enableInputValidation) {
        next();
        return;
      }

      try {
        const data = req[target];
        const result = schema.safeParse(data);

        if (!result.success) {
          const errors: ValidationError[] = result.error.issues.map((issue) => ({
            field: issue.path.join('.'),
            message: issue.message,
            value: (issue as any).received,
          }));

          logger.warn(
            {
              errors,
              path: req.path,
              method: req.method,
              ip: req.ip,
            },
            'Input validation failed'
          );

          res.status(400).json({
            error: 'Validation failed',
            errors,
          });
          return;
        }

        // Replace the original data with validated data
        req[target] = result.data;
        next();
      } catch (error) {
        logger.error({ error, path: req.path }, 'Validation middleware error');
        res.status(500).json({ error: 'Validation error' });
        return;
      }
    };
  }

  /**
   * SQL injection prevention
   */
  preventSQLInjection() {
    return (req: Request, res: Response, next: NextFunction) => {
      const suspiciousPatterns = [
        /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)/i,
        /(--|;|\/\*|\*\/|xp_|sp_)/i,
        /(\b(or|and)\s+\d+\s*=\s*\d+)/i,
        /(\b(or|and)\s+['"]?['"]?\s*=\s*['"]?['"]?)/i,
      ];

      const checkValue = (value: any, path: string): boolean => {
        if (typeof value === 'string') {
          for (const pattern of suspiciousPatterns) {
            if (pattern.test(value)) {
              logger.warn(
                {
                  path,
                  value: value.substring(0, 100),
                  ip: req.ip,
                  userAgent: req.headers['user-agent'],
                },
                'Potential SQL injection attempt detected'
              );
              return true;
            }
          }
        } else if (typeof value === 'object' && value !== null) {
          for (const [key, val] of Object.entries(value)) {
            if (checkValue(val, `${path}.${key}`)) {
              return true;
            }
          }
        }
        return false;
      };

      // Check request body, query, and params
      const suspicious =
        checkValue(req.body, 'body') ||
        checkValue(req.query, 'query') ||
        checkValue(req.params, 'params');

      if (suspicious) {
        return res.status(400).json({ error: 'Invalid request data' });
      }

      return next();
    };
  }

  /**
   * XSS prevention
   */
  preventXSS() {
    return (req: Request, _res: Response, next: NextFunction) => {
      const xssPatterns = [
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
        /javascript:/gi,
        /on\w+\s*=/gi,
        /<img[^>]*src[^>]*javascript:/gi,
      ];

      const sanitize = (value: any): any => {
        if (typeof value === 'string') {
          let sanitized = value;
          for (const pattern of xssPatterns) {
            if (pattern.test(sanitized)) {
              logger.warn(
                {
                  value: sanitized.substring(0, 100),
                  ip: req.ip,
                  path: req.path,
                },
                'Potential XSS attempt detected'
              );
              sanitized = sanitized.replace(pattern, '');
            }
          }
          return sanitized;
        } else if (typeof value === 'object' && value !== null) {
          const sanitized: any = {};
          for (const [key, val] of Object.entries(value)) {
            sanitized[key] = sanitize(val);
          }
          return sanitized;
        }
        return value;
      };

      req.body = sanitize(req.body);
      req.query = sanitize(req.query);
      req.params = sanitize(req.params);

      next();
    };
  }

  /**
   * File upload security
   */
  secureFileUpload() {
    // File upload security configuration available for future implementation

    return (_req: Request, _res: Response, next: NextFunction) => {
      // This would integrate with multer or similar file upload middleware
      // For now, it's a placeholder for the security checks
      logger.info('File upload security check (placeholder)');
      next();
    };
  }

  /**
   * API key authentication with enhanced security
   */
  secureAPIKey() {
    return (req: Request, res: Response, next: NextFunction) => {
      const apiKey = req.headers['x-api-key'] as string;

      if (!apiKey) {
        return res.status(401).json({ error: 'API key required' });
      }

      // Validate API key format
      if (!apiKey.startsWith('ck_') || apiKey.length !== 32) {
        logger.warn(
          {
            apiKeyPrefix: apiKey.substring(0, 10),
            ip: req.ip,
            path: req.path,
          },
          'Invalid API key format'
        );
        return res.status(401).json({ error: 'Invalid API key format' });
      }

      // Add API key to request for downstream processing
      (req as any).apiKey = apiKey;
      return next();
    };
  }

  /**
   * Block IP addresses
   */
  blockIP(ip: string): void {
    this.blockedIPs.add(ip);
    logger.warn({ ip }, 'IP address blocked');
  }

  /**
   * Unblock IP addresses
   */
  unblockIP(ip: string): void {
    this.blockedIPs.delete(ip);
    logger.info({ ip }, 'IP address unblocked');
  }

  /**
   * Get current security statistics
   */
  getSecurityStats() {
    return {
      blockedIPs: Array.from(this.blockedIPs),
      activeRateLimits: this.requestCounts.size,
      config: {
        rateLimitMax: this.config.rateLimitMax,
        rateLimitWindowMs: this.config.rateLimitWindowMs,
        maxRequestSize: this.config.maxRequestSize,
      },
    };
  }

  private isIPBlocked(ip: string): boolean {
    return this.blockedIPs.has(ip);
  }

  private applySecurityHeaders(req: Request, res: Response): void {
    // Use helmet for comprehensive security headers
    helmet()(req, res, () => {});

    // Additional custom headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    res.removeHeader('X-Powered-By');
  }

  private applyCORS(req: Request, res: Response): void {
    const origin = req.headers.origin;

    if (this.config.allowedOrigins?.includes(origin as string)) {
      res.setHeader('Access-Control-Allow-Origin', origin as string);
    }

    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours

    if (req.method === 'OPTIONS') {
      res.status(200).end();
      return;
    }
  }

  private validateRequestSize(req: Request): boolean {
    const contentLength = parseInt(req.headers['content-length'] || '0');
    return contentLength <= (this.config.maxRequestSize || 10 * 1024 * 1024);
  }

  private checkRateLimit(req: Request, res: Response): boolean {
    const key = `${req.ip}:${req.path}`;
    const now = Date.now();
    const windowMs = this.config.rateLimitWindowMs!;
    const maxRequests = this.config.rateLimitMax!;

    let requestData = this.requestCounts.get(key);

    if (!requestData || now > requestData.resetTime) {
      requestData = { count: 0, resetTime: now + windowMs };
      this.requestCounts.set(key, requestData);
    }

    requestData.count++;

    if (requestData.count > maxRequests) {
      const resetTimeSeconds = Math.ceil((requestData.resetTime - now) / 1000);
      res.setHeader('Retry-After', resetTimeSeconds);
      res.setHeader('X-RateLimit-Limit', maxRequests);
      res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - requestData.count));
      res.setHeader('X-RateLimit-Reset', requestData.resetTime);

      logger.warn(
        {
          ip: req.ip,
          path: req.path,
          count: requestData.count,
          limit: maxRequests,
        },
        'Rate limit exceeded'
      );

      res.status(429).json({
        error: 'Too many requests',
        retryAfter: resetTimeSeconds,
      });

      return false;
    }

    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - requestData.count));
    res.setHeader('X-RateLimit-Reset', requestData.resetTime);

    return true;
  }
}

// Default instance
export const securityMiddleware = new SecurityMiddleware();

// Common validation schemas
export const commonSchemas = {
  memoryStore: z.object({
    content: z.string().min(1).max(1000000),
    kind: z.enum([
      'entity',
      'relation',
      'observation',
      'section',
      'runbook',
      'change',
      'issue',
      'decision',
      'todo',
      'release_note',
      'ddl',
      'pr_context',
      'incident',
      'release',
      'risk',
      'assumption',
    ]),
    items: z.array(z.any()).optional(),
  }),

  memoryFind: z.object({
    query: z.string().min(1).max(1000),
    limit: z.number().min(1).max(1000).optional(),
    scope: z
      .object({
        project: z.string().optional(),
        branch: z.string().optional(),
        organization: z.string().optional(),
      })
      .optional(),
    types: z.array(z.string()).optional(),
  }),

  pagination: z.object({
    page: z.number().min(1).max(1000).optional(),
    limit: z.number().min(1).max(100).optional(),
    offset: z.number().min(0).max(10000).optional(),
  }),
};

// Export commonly used middleware
export const security = securityMiddleware.security();
export const rateLimitMiddleware = securityMiddleware.rateLimit();
export const preventSQLInjection = securityMiddleware.preventSQLInjection();
export const preventXSS = securityMiddleware.preventXSS();
