// @ts-nocheck
/**
 * Performance Monitoring Middleware for Cortex MCP
 * Provides automatic performance tracking for HTTP requests and MCP operations
 */

import { Request, Response, NextFunction } from 'express';
import { performanceCollector } from './performance-collector.js';
import { logger } from '@/utils/logger.js';

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
      const operation = `${req.method} ${req.path}`;
      const metadata: Record<string, any> = {
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
      res.end = function (chunk?: any, encoding?: any) {
        const endTime = Date.now();
        const duration = endTime - startTime;

        // Add response metadata
        metadata.statusCode = res.statusCode;
        metadata.responseSize = chunk ? chunk.length : 0;

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
        });

        // Call original end
        return originalEnd.call(this, chunk, encoding);
      };

      next();
    };
  }

  /**
   * MCP operation performance tracking decorator
   */
  static trackOperation(operationName: string, metadata?: Record<string, any>) {
    return function (target: any, propertyName: string, descriptor: PropertyDescriptor) {
      const method = descriptor.value;

      descriptor.value = async function (...args: any[]) {
        const endMetric = performanceCollector.startMetric(operationName, {
          className: target.constructor.name,
          methodName: propertyName,
          ...metadata,
        });

        try {
          const result = await method.apply(this, args);
          endMetric();
          return result;
        } catch (error) {
          performanceCollector.recordError(operationName, error as Error, {
            className: target.constructor.name,
            methodName: propertyName,
            ...metadata,
          });
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
    metadata?: Record<string, any>
  ): Promise<T> {
    const endMetric = performanceCollector.startMetric(operationName, metadata);

    try {
      const result = await fn();
      endMetric();
      return result;
    } catch (error) {
      performanceCollector.recordError(operationName, error as Error, metadata);
      throw error;
    }
  }

  /**
   * Database query performance tracking
   */
  static trackDatabaseQuery(query: string, params?: any[]) {
    return performanceCollector.startMetric(
      'database_query',
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
      'embedding_generation',
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
      'vector_search',
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
      'auth_validation',
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
    return performanceCollector.startMetric(
      `cache_${operation}`,
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
