/**
 * Production Security Middleware
 *
 * Comprehensive security middleware for production deployments.
 * Implements security headers, rate limiting, API key validation,
 * and production-specific security measures.
 *
 * @author Cortex Team
 * @version 2.0.1
 */

import { createHash, randomBytes } from 'crypto';

import { type NextFunction,type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

import { logger } from '@/utils/logger.js';

export interface ProductionSecurityConfig {
  corsOrigin: string[];
  rateLimitEnabled: boolean;
  rateLimitWindowMs: number;
  rateLimitMaxRequests: number;
  helmetEnabled: boolean;
  requireApiKey: boolean;
  maxRequestSizeMb: number;
  enableCompression: boolean;
}

export class ProductionSecurityMiddleware {
  private config: ProductionSecurityConfig;
  private static readonly MAX_REQUEST_SIZE = 10 * 1024 * 1024; // 10MB

  constructor(config: ProductionSecurityConfig) {
    this.config = config;
  }

  /**
   * Initialize all production security middleware
   */
  initializeMiddleware(): Array<(req: Request, res: Response, next: NextFunction) => void> {
    const middleware: Array<(req: Request, res: Response, next: NextFunction) => void> = [];

    // Request size validation
    middleware.push(this.validateRequestSize());

    // API key validation
    if (this.config.requireApiKey) {
      middleware.push(this.validateApiKey());
    }

    // Rate limiting
    if (this.config.rateLimitEnabled) {
      middleware.push(this.createRateLimiter());
    }

    // Security headers
    if (this.config.helmetEnabled) {
      middleware.push(this.createHelmetMiddleware());
    }

    // Request logging
    middleware.push(this.logRequests());

    // Request sanitization
    middleware.push(this.sanitizeInput());

    return middleware;
  }

  /**
   * Validate request size to prevent payload attacks
   */
  private validateRequestSize() {
    const config = this.config;
    return (req: Request, res: Response, next: NextFunction): void => {
      const contentLength = parseInt(req.headers['content-length'] || '0');
      const maxSize = Math.min(
        config.maxRequestSizeMb * 1024 * 1024,
        ProductionSecurityMiddleware.MAX_REQUEST_SIZE
      );

      if (contentLength > maxSize) {
        logger.warn('Request size exceeded limit', {
          contentLength,
          maxSize,
          ip: req.ip,
          userAgent: req.headers['user-agent'],
        });

        res.status(413).json({
          error: 'Payload Too Large',
          message: `Request size ${contentLength} exceeds maximum allowed size of ${maxSize} bytes`,
          code: 'PAYLOAD_TOO_LARGE',
        });
        return;
      }

      next();
    };
  }

  /**
   * Validate API key for MCP operations
   */
  private validateApiKey() {
    const validApiKey = process.env.MCP_API_KEY;

    if (!validApiKey) {
      throw new Error(
        'MCP_API_KEY environment variable is required when API key validation is enabled'
      );
    }

    return (req: Request, res: Response, next: NextFunction): void => {
      const providedApiKey = req.headers['x-api-key'] as string;

      if (!providedApiKey) {
        logger.warn('Missing API key', {
          ip: req.ip,
          path: req.path,
          userAgent: req.headers['user-agent'],
        });

        res.status(401).json({
          error: 'Unauthorized',
          message: 'API key is required',
          code: 'MISSING_API_KEY',
        });
        return;
      }

      // Use constant-time comparison to prevent timing attacks
      if (!ProductionSecurityMiddleware.constantTimeCompare(providedApiKey, validApiKey)) {
        logger.warn('Invalid API key', {
          ip: req.ip,
          path: req.path,
          userAgent: req.headers['user-agent'],
        });

        res.status(401).json({
          error: 'Unauthorized',
          message: 'Invalid API key',
          code: 'INVALID_API_KEY',
        });
        return;
      }

      next();
    };
  }

  /**
   * Constant-time comparison to prevent timing attacks
   */
  private static constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return result === 0;
  }

  /**
   * Create rate limiter middleware
   */
  private createRateLimiter() {
    const config = this.config;
    const limiter = rateLimit({
      windowMs: config.rateLimitWindowMs,
      max: config.rateLimitMaxRequests,
      message: {
        error: 'Too Many Requests',
        message: `Rate limit exceeded. Maximum ${config.rateLimitMaxRequests} requests per ${config.rateLimitWindowMs / 1000} seconds.`,
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: Math.ceil(config.rateLimitWindowMs / 1000),
      },
      standardHeaders: true,
      legacyHeaders: false,
      skipSuccessfulRequests: false,
      skipFailedRequests: false,
      keyGenerator: (req: Request) => {
        // Use IP address for rate limiting
        return req.ip || 'unknown';
      },
      handler: (req: Request, res: Response) => {
        logger.warn('Rate limit exceeded', {
          ip: req.ip,
          path: req.path,
          userAgent: req.headers['user-agent'],
          rateLimit: {
            limit: config.rateLimitMaxRequests,
            windowMs: config.rateLimitWindowMs,
          },
        });

        res.status(429).json({
          error: 'Too Many Requests',
          message: `Rate limit exceeded. Maximum ${config.rateLimitMaxRequests} requests per ${config.rateLimitWindowMs / 1000} seconds.`,
          code: 'RATE_LIMIT_EXCEEDED',
          retryAfter: Math.ceil(config.rateLimitWindowMs / 1000),
        });
      },
    });

    return limiter;
  }

  /**
   * Create helmet middleware for security headers
   */
  private createHelmetMiddleware() {
    return helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"],
          childSrc: ["'none'"],
          workerSrc: ["'self'"],
          manifestSrc: ["'self'"],
          upgradeInsecureRequests: [],
        },
      },
      crossOriginEmbedderPolicy: false,
      crossOriginResourcePolicy: { policy: 'cross-origin' },
      dnsPrefetchControl: { allow: false },
      frameguard: { action: 'deny' },
      hidePoweredBy: true,
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
      },
      ieNoOpen: true,
      noSniff: true,
      originAgentCluster: true,
      permittedCrossDomainPolicies: false,
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      xssFilter: true,
    });
  }

  /**
   * Log all requests for audit purposes
   */
  private logRequests() {
    return (req: Request, res: Response, next: NextFunction) => {
      const startTime = Date.now();
      const requestId = this.generateRequestId();

      // Add request ID to headers
      res.setHeader('X-Request-ID', requestId);
      req.requestId = requestId;

      // Log request
      logger.info('Incoming request', {
        requestId,
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        contentLength: req.headers['content-length'],
        referer: req.headers['referer'],
      });

      // Log response when finished
      res.on('finish', () => {
        const duration = Date.now() - startTime;

        logger.info('Request completed', {
          requestId,
          method: req.method,
          path: req.path,
          statusCode: res.statusCode,
          duration,
          contentLength: res.getHeader('content-length'),
          ip: req.ip,
        });
      });

      next();
    };
  }

  /**
   * Sanitize input data to prevent injection attacks
   */
  private sanitizeInput() {
    return (req: Request, res: Response, next: NextFunction): void => {
      try {
        // Sanitize query parameters
        if (req.query) {
          req.query = this.sanitizeObject(req.query);
        }

        // Sanitize request body if it's JSON
        if (req.body && typeof req.body === 'object') {
          req.body = this.sanitizeObject(req.body);
        }

        // Sanitize URL parameters
        if (req.params) {
          req.params = this.sanitizeObject(req.params);
        }

        next();
      } catch (error) {
        logger.error('Input sanitization failed', {
          error: error instanceof Error ? error.message : 'Unknown error',
          path: req.path,
          method: req.method,
          ip: req.ip,
        });

        res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid input data',
          code: 'INVALID_INPUT',
        });
        return;
      }
    };
  }

  /**
   * Recursively sanitize object properties
   */
  private sanitizeObject(obj: any): any {
    if (obj === null || obj === undefined) {
      return obj;
    }

    if (typeof obj === 'string') {
      return this.sanitizeString(obj);
    }

    if (Array.isArray(obj)) {
      return obj.map((item) => this.sanitizeObject(item));
    }

    if (typeof obj === 'object') {
      const sanitized: any = {};
      for (const [key, value] of Object.entries(obj)) {
        // Sanitize key names
        const sanitizedKey = this.sanitizeString(key);
        sanitized[sanitizedKey] = this.sanitizeObject(value);
      }
      return sanitized;
    }

    return obj;
  }

  /**
   * Sanitize string to prevent injection attacks
   */
  private sanitizeString(str: string): string {
    if (typeof str !== 'string') {
      return str;
    }

    // Remove potentially dangerous characters
    return str
      .replace(/[<>]/g, '') // Remove HTML brackets
      .replace(/javascript:/gi, '') // Remove JavaScript protocol
      .replace(/on\w+=/gi, '') // Remove event handlers
      .replace(/[\x00-\x1F\x7F]/g, '') // Remove control characters
      .trim();
  }

  /**
   * Generate unique request ID for tracking
   */
  private generateRequestId(): string {
    const timestamp = Date.now().toString(36);
    const randomBytesValue = randomBytes(8).toString('hex');
    return `req_${timestamp}_${randomBytesValue}`;
  }

  /**
   * Create CORS middleware for production
   */
  createCorsMiddleware() {
    const config = this.config;
    return (req: Request, res: Response, next: NextFunction): void => {
      const origin = req.headers.origin;

      if (!origin) {
        // No origin header, allow but don't set CORS headers
        next();
        return;
      }

      // Check if origin is allowed
      const isAllowed = config.corsOrigin.some((allowedOrigin) => {
        if (allowedOrigin === '*') return true;
        if (allowedOrigin === origin) return true;

        // Support wildcard subdomains
        if (allowedOrigin.includes('*')) {
          const pattern = allowedOrigin.replace(/\*/g, '.*');
          const regex = new RegExp(`^${pattern}$`);
          return regex.test(origin);
        }

        return false;
      });

      if (isAllowed) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader(
          'Access-Control-Allow-Headers',
          'Content-Type, Authorization, X-API-Key, X-Request-ID'
        );
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours
      }

      // Handle preflight requests
      if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
      }

      next();
    };
  }

  /**
   * Validate security configuration
   */
  validateConfiguration(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (this.config.requireApiKey && !process.env.MCP_API_KEY) {
      errors.push(
        'MCP_API_KEY environment variable is required when API key validation is enabled'
      );
    }

    if (this.config.maxRequestSizeMb > 50) {
      errors.push('Maximum request size should not exceed 50MB for security reasons');
    }

    if (this.config.rateLimitMaxRequests > 10000 && this.config.rateLimitWindowMs < 60000) {
      errors.push('Rate limiting is too permissive for production');
    }

    if (this.config.corsOrigin.includes('*') && process.env.NODE_ENV === 'production') {
      errors.push('Wildcard CORS origin is not recommended for production');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}

// Extend Request interface to include requestId
declare global {
  namespace Express {
    interface Request {
      requestId?: string;
    }
  }
}

export default ProductionSecurityMiddleware;
