// EMERGENCY ROLLBACK: Final batch of type compatibility issues

/**
 * Performance Monitoring Middleware for Cortex MCP
 * Provides automatic performance tracking for HTTP requests and MCP operations
 */

import { type NextFunction, type Request, type Response } from 'express';

import { logger } from '@/utils/logger.js';

import { performanceCollector } from './performance-collector.js';
import { OperationType } from './operation-types.js';

export interface PerformanceMiddlewareOptions {
  trackRequestBody?: boolean;
  trackResponseBody?: boolean;
  slowQueryThreshold?: number; // milliseconds
  excludePaths?: string[];
  includeHeaders?: string[];
}

export class PerformanceMiddleware {
  constructor(private _options: PerformanceMiddlewareOptions = {}) {}

  /**
   * Express middleware for tracking HTTP request performance
   */
  httpPerformance() {
    return (req: Request, res: Response, next: NextFunction) => {
      // Skip excluded paths
      if (this._options.excludePaths?.some((path) => req.path.startsWith(path))) {
        next();
        return;
      }

      const startTime = Date.now();
      const operation = `${req.method} ${req.path}` as const;
      const metadata: Record<string, unknown> = {
        method: req.method,
        path: req.path,
        userAgent: req.headers['user-agent'],
        ip: req.ip || req.connection.remoteAddress,
      };

      // Store options reference for use in res.end callback
      const slowQueryThreshold = this._options.slowQueryThreshold || 1000;

      // Include selected headers
      if (this._options.includeHeaders) {
        metadata.headers = {};
        for (const header of this._options.includeHeaders) {
          if (req.headers[header]) {
            metadata.headers[header] = req.headers[header];
          }
        }
      }

      // Track request body if enabled (be careful with sensitive data)
      if (this._options.trackRequestBody && req.body) {
        metadata.requestSize = JSON.stringify(req.body).length;
      }

      // Override res.end to capture response metrics
      const originalEnd = res.end;
      res.end = function (chunk?: unknown, encoding?: unknown) {
        const endTime = Date.now();
        const duration = endTime - startTime;

        // Add response metadata
        metadata.statusCode = res.statusCode;
        metadata.responseSize = chunk && typeof chunk === 'string' ? chunk.length :
                               chunk && Buffer.isBuffer(chunk) ? chunk.length : 0;

        if (duration > slowQueryThreshold) {
          logger.warn(
            {
              operation,
              duration,
              statusCode: res.statusCode,
              path: req.path,
              method: req.method,
            },
            'Slow HTTP request detected'
          );
        }

        // Record the metric
        performanceCollector.recordMetric({
          operation,
          startTime,
          endTime,
          duration,
          success: res.statusCode < 400,
          metadata,
          tags: ['http', req.method.toLowerCase()],
        } as any); // Type assertion for HTTP operations

        // Call original end
        return originalEnd.call(this, chunk, encoding as BufferEncoding);
      };

      next();
    };
  }

  /**
   * MCP operation performance tracking decorator
   */
  static trackOperation(operationName: string, metadata?: Record<string, unknown>) {
    return function (target: unknown, propertyName: string, descriptor: PropertyDescriptor) {
      const method = descriptor.value;

      descriptor.value = async function (...args: any[]) {
        const endMetric = performanceCollector.startMetric(operationName as any, {
          className: target.constructor.name,
          methodName: propertyName,
          ...metadata,
        } as any);

        try {
          const result = await method.apply(this, args);
          endMetric();
          return result;
        } catch (error) {
          performanceCollector.recordError(operationName as any, error as Error, {
            className: target.constructor.name,
            methodName: propertyName,
            ...metadata,
          } as any);
          throw error;
        }
      };

      return descriptor;
    };
  }

  /**
   * Function wrapper for manual operation tracking
   */
  static async trackFunction<T>(
    operationName: string,
    fn: () => Promise<T>,
    metadata?: Record<string, unknown>
  ): Promise<T> {
    const endMetric = performanceCollector.startMetric(operationName as any, metadata as any);

    try {
      const result = await fn();
      endMetric();
      return result;
    } catch (error) {
      performanceCollector.recordError(operationName as any, error as Error, metadata as any);
      throw error;
    }
  }

  /**
   * Database query performance tracking
   */
  static trackDatabaseQuery(query: string, params?: unknown[]) {
    return performanceCollector.startMetric(
      OperationType.DATABASE_QUERY,
      {
        query: query.substring(0, 100), // Truncate long queries
        paramCount: params?.length || 0,
        queryType: query.trim().split(' ')[0]?.toUpperCase(),
      },
      ['database', 'sql']
    );
  }

  /**
   * Embedding generation performance tracking
   */
  static trackEmbeddingGeneration(textLength: number, model?: string) {
    return performanceCollector.startMetric(
      OperationType.EMBEDDING_GENERATION,
      {
        textLength,
        model,
        operation: 'embed',
      },
      ['embedding', 'ai']
    );
  }

  /**
   * Vector search performance tracking
   */
  static trackVectorSearch(vectorSize: number, topK: number) {
    return performanceCollector.startMetric(
      OperationType.VECTOR_SEARCH,
      {
        vectorSize,
        topK,
        operation: 'search',
      },
      ['vector', 'search']
    );
  }

  /**
   * Authentication performance tracking
   */
  static trackAuthentication(method: 'jwt' | 'api_key', userId?: string) {
    return performanceCollector.startMetric(
      OperationType.AUTH_VALIDATION,
      {
        method,
        userId: userId ? `${userId.substring(0, 8)}...` : undefined,
        operation: 'auth',
      },
      ['auth', 'security']
    );
  }

  /**
   * Cache operation performance tracking
   */
  static trackCacheOperation(operation: 'get' | 'set' | 'delete', key?: string) {
    const cacheOperation = operation === 'get' ? OperationType.CACHE_GET :
                          operation === 'set' ? OperationType.CACHE_SET :
                          OperationType.CACHE_DELETE;

    return performanceCollector.startMetric(
      cacheOperation,
      {
        key: key ? key.substring(0, 50) : undefined,
        operation,
      },
      ['cache']
    );
  }
}

// Default middleware instance
export const performanceMiddleware = new PerformanceMiddleware({
  slowQueryThreshold: 1000,
  excludePaths: ['/health', '/metrics', '/favicon.ico'],
  includeHeaders: ['user-agent', 'x-forwarded-for'],
});

// Export commonly used middleware
export const httpPerformance = performanceMiddleware.httpPerformance();
