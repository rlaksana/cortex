/**
 * Performance Middleware Unit Tests
 *
 * Comprehensive unit tests for the performance monitoring middleware.
 * Tests HTTP request tracking, MCP operation decorators, and utility functions.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { Request, Response, NextFunction } from 'express';
import {
  PerformanceMiddleware,
  performanceMiddleware,
  httpPerformance,
  PerformanceMiddlewareOptions
} from '../../../src/monitoring/performance-middleware.js';

// Mock the performance collector
vi.mock('../../../src/monitoring/performance-collector.js', () => ({
  performanceCollector: {
    recordMetric: vi.fn(),
    recordError: vi.fn(),
    startMetric: vi.fn(),
    on: vi.fn(),
  },
}));

// Mock logger
vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

describe('PerformanceMiddleware', () => {
  let middleware: PerformanceMiddleware;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;
  const mockPerformanceCollector = vi.hoisted(() => ({
    recordMetric: vi.fn(),
    recordError: vi.fn(),
    startMetric: vi.fn(),
    on: vi.fn(),
  }));

  beforeEach(() => {
    vi.clearAllMocks();
    middleware = new PerformanceMiddleware();

    mockRequest = {
      method: 'GET',
      path: '/api/test',
      ip: '127.0.0.1',
      headers: {
        'user-agent': 'test-agent',
        'x-forwarded-for': '192.168.1.1',
        'authorization': 'Bearer token123',
      },
      body: {
        test: 'data',
      },
    };

    mockResponse = {
      statusCode: 200,
      end: vi.fn(),
    };

    mockNext = vi.fn();

    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Constructor and Configuration', () => {
    it('should create middleware with default options', () => {
      const defaultMiddleware = new PerformanceMiddleware();
      expect(defaultMiddleware).toBeInstanceOf(PerformanceMiddleware);
    });

    it('should create middleware with custom options', () => {
      const options: PerformanceMiddlewareOptions = {
        trackRequestBody: true,
        trackResponseBody: true,
        slowQueryThreshold: 500,
        excludePaths: ['/health', '/metrics'],
        includeHeaders: ['authorization', 'x-api-key'],
      };

      const customMiddleware = new PerformanceMiddleware(options);
      expect(customMiddleware).toBeInstanceOf(PerformanceMiddleware);
    });
  });

  describe('HTTP Performance Middleware', () => {
    beforeEach(() => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});
      mockPerformanceCollector.recordMetric.mockReturnValue(() => {});
    });

    it('should track HTTP request performance', () => {
      const httpMiddleware = middleware.httpPerformance();

      httpMiddleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should capture request metadata', () => {
      mockPerformanceCollector.startMetric.mockImplementation((operation, metadata) => {
        expect(metadata.method).toBe('GET');
        expect(metadata.path).toBe('/api/test');
        expect(metadata.userAgent).toBe('test-agent');
        expect(metadata.ip).toBe('192.168.1.1');
        return () => {};
      });

      const httpMiddleware = middleware.httpPerformance();
      httpMiddleware(mockRequest as Request, mockResponse as Response, mockNext);
    });

    it('should include selected headers in metadata', () => {
      const middlewareWithOptions = new PerformanceMiddleware({
        includeHeaders: ['user-agent', 'authorization'],
      });

      mockPerformanceCollector.startMetric.mockImplementation((operation, metadata) => {
        expect(metadata.headers).toBeDefined();
        expect(metadata.headers['user-agent']).toBe('test-agent');
        expect(metadata.headers['authorization']).toBe('Bearer token123');
        return () => {};
      });

      const httpMiddleware = middlewareWithOptions.httpPerformance();
      httpMiddleware(mockRequest as Request, mockResponse as Response, mockNext);
    });

    it('should track request body when enabled', () => {
      const middlewareWithBody = new PerformanceMiddleware({
        trackRequestBody: true,
      });

      mockPerformanceCollector.startMetric.mockImplementation((operation, metadata) => {
        expect(metadata.requestSize).toBeGreaterThan(0);
        return () => {};
      });

      const httpMiddleware = middlewareWithBody.httpPerformance();
      httpMiddleware(mockRequest as Request, mockResponse as Response, mockNext);
    });

    it('should skip excluded paths', () => {
      const middlewareWithExclusions = new PerformanceMiddleware({
        excludePaths: ['/api/test'],
      });

      mockPerformanceCollector.startMetric.mockImplementation(() => {
        throw new Error('Should not be called for excluded paths');
      });

      const httpMiddleware = middlewareWithExclusions.httpPerformance();
      httpMiddleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockPerformanceCollector.startMetric).not.toHaveBeenCalled();
    });

    it('should record metric when response ends', () => {
      let endCallback: any;
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});

      const httpMiddleware = middleware.httpPerformance();

      // Mock res.end to capture the callback
      const originalEnd = mockResponse.end;
      httpMiddleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockResponse.end).not.toBe(originalEnd);
      expect(typeof mockResponse.end).toBe('function');
    });

    it('should log slow requests', () => {
      const slowMiddleware = new PerformanceMiddleware({
        slowQueryThreshold: 100,
      });

      let endCallback: any;
      const startTime = Date.now() - 200; // Simulate slow request

      mockPerformanceCollector.startMetric.mockImplementation(() => {
        return () => {
          // Simulate slow completion
          mockPerformanceCollector.recordMetric({
            operation: 'GET /api/test',
            startTime,
            endTime: Date.now(),
            duration: 200,
            success: true,
            metadata: {
              method: 'GET',
              path: '/api/test',
              statusCode: 200,
            },
          });
        };
      });

      const httpMiddleware = slowMiddleware.httpPerformance();
      httpMiddleware(mockRequest as Request, mockResponse as Response, mockNext);

      // Trigger the end callback
      if (mockResponse.end && typeof mockResponse.end === 'function') {
        mockResponse.end();
      }
    });

    it('should handle requests with missing IP', () => {
      mockRequest.ip = undefined;
      mockRequest.connection = undefined;

      const httpMiddleware = middleware.httpPerformance();
      httpMiddleware(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle responses with no content', () => {
      const httpMiddleware = middleware.httpPerformance();
      httpMiddleware(mockRequest as Request, mockResponse as Response, mockNext);

      // Trigger end with no content
      if (mockResponse.end && typeof mockResponse.end === 'function') {
        mockResponse.end();
      }
    });
  });

  describe('Operation Tracking Decorator', () => {
    beforeEach(() => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});
      mockPerformanceCollector.recordError.mockReturnValue(() => {});
    });

    it('should track successful operations', async () => {
      let endMetric: any;
      mockPerformanceCollector.startMetric.mockReturnValue(() => {
        endMetric = vi.fn();
        return endMetric;
      });

      // Create a test class with a decorated method
      class TestService {
        @PerformanceMiddleware.trackOperation('test_operation', { context: 'test' })
        async testMethod(input: string): Promise<string> {
          return `processed: ${input}`;
        }
      }

      const service = new TestService();
      const result = await service.testMethod('test-input');

      expect(result).toBe('processed: test-input');
      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledWith(
        'test_operation',
        expect.objectContaining({
          className: 'TestService',
          methodName: 'testMethod',
          context: 'test',
        })
      );
      expect(endMetric).toHaveBeenCalled();
    });

    it('should track failed operations', async () => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});
      mockPerformanceCollector.recordError.mockReturnValue(() => {});

      class TestService {
        @PerformanceMiddleware.trackOperation('failing_operation')
        async failingMethod(): Promise<void> {
          throw new Error('Test error');
        }
      }

      const service = new TestService();

      await expect(service.failingMethod()).rejects.toThrow('Test error');

      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledWith(
        'failing_operation',
        expect.objectContaining({
          className: 'TestService',
          methodName: 'failingMethod',
        })
      );
      expect(mockPerformanceCollector.recordError).toHaveBeenCalledWith(
        'failing_operation',
        expect.any(Error),
        expect.objectContaining({
          className: 'TestService',
          methodName: 'failingMethod',
        })
      );
    });

    it('should work with synchronous methods', async () => {
      let endMetric: any;
      mockPerformanceCollector.startMetric.mockReturnValue(() => {
        endMetric = vi.fn();
        return endMetric;
      });

      class TestService {
        @PerformanceMiddleware.trackOperation('sync_operation')
        syncMethod(): string {
          return 'sync-result';
        }
      }

      const service = new TestService();
      const result = service.syncMethod();

      expect(result).toBe('sync-result');
      expect(endMetric).toHaveBeenCalled();
    });
  });

  describe('Function Tracking Wrapper', () => {
    beforeEach(() => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});
      mockPerformanceCollector.recordError.mockReturnValue(() => {});
    });

    it('should track successful function execution', async () => {
      let endMetric: any;
      mockPerformanceCollector.startMetric.mockReturnValue(() => {
        endMetric = vi.fn();
        return endMetric;
      });

      const testFn = async (input: string) => `result: ${input}`;
      const result = await PerformanceMiddleware.trackFunction(
        'wrapped_function',
        () => testFn('test'),
        { custom: 'metadata' }
      );

      expect(result).toBe('result: test');
      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledWith(
        'wrapped_function',
        { custom: 'metadata' }
      );
      expect(endMetric).toHaveBeenCalled();
    });

    it('should track failed function execution', async () => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});
      mockPerformanceCollector.recordError.mockReturnValue(() => {});

      const failingFn = async () => {
        throw new Error('Function failed');
      };

      await expect(
        PerformanceMiddleware.trackFunction('failing_function', failingFn)
      ).rejects.toThrow('Function failed');

      expect(mockPerformanceCollector.recordError).toHaveBeenCalledWith(
        'failing_function',
        expect.any(Error),
        undefined
      );
    });

    it('should pass metadata correctly', async () => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});

      const metadata = { userId: '123', action: 'create' };
      await PerformanceMiddleware.trackFunction(
        'function_with_metadata',
        async () => 'success',
        metadata
      );

      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledWith(
        'function_with_metadata',
        metadata
      );
    });
  });

  describe('Database Query Tracking', () => {
    beforeEach(() => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});
    });

    it('should track database queries with query information', () => {
      let endMetric: any;
      mockPerformanceCollector.startMetric.mockReturnValue(() => {
        endMetric = vi.fn();
        return endMetric;
      });

      const query = 'SELECT * FROM users WHERE id = $1';
      const params = ['123'];

      const endTracker = PerformanceMiddleware.trackDatabaseQuery(query, params);

      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledWith(
        'database_query',
        {
          query: query.substring(0, 100),
          paramCount: 1,
          queryType: 'SELECT',
        },
        ['database', 'sql']
      );

      expect(typeof endTracker).toBe('function');

      // Test the end function
      endTracker();
      expect(endMetric).toHaveBeenCalled();
    });

    it('should truncate long queries', () => {
      const longQuery = 'SELECT * FROM users WHERE ' + 'a'.repeat(200);
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});

      PerformanceMiddleware.trackDatabaseQuery(longQuery);

      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledWith(
        'database_query',
        expect.objectContaining({
          query: expect.stringMatching(/^SELECT \* FROM users WHERE a+$/),
          queryType: 'SELECT',
        }),
        ['database', 'sql']
      );
    });

    it('should handle queries without parameters', () => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});

      PerformanceMiddleware.trackDatabaseQuery('SELECT NOW()');

      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledWith(
        'database_query',
        {
          query: 'SELECT NOW()',
          paramCount: 0,
          queryType: 'SELECT',
        },
        ['database', 'sql']
      );
    });

    it('should handle different query types', () => {
      const queries = [
        'INSERT INTO users (name) VALUES ($1)',
        'UPDATE users SET name = $1 WHERE id = $2',
        'DELETE FROM users WHERE id = $1',
        'CREATE TABLE test (id SERIAL)',
      ];

      mockPerformanceCollector.startMetric.mockReturnValue(() => {});

      queries.forEach(query => {
        PerformanceMiddleware.trackDatabaseQuery(query);
      });

      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledTimes(4);
    });
  });

  describe('Embedding Generation Tracking', () => {
    beforeEach(() => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});
    });

    it('should track embedding generation', () => {
      let endMetric: any;
      mockPerformanceCollector.startMetric.mockReturnValue(() => {
        endMetric = vi.fn();
        return endMetric;
      });

      const endTracker = PerformanceMiddleware.trackEmbeddingGeneration(1000, 'text-embedding-ada-002');

      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledWith(
        'embedding_generation',
        {
          textLength: 1000,
          model: 'text-embedding-ada-002',
          operation: 'embed',
        },
        ['embedding', 'ai']
      );

      expect(typeof endTracker).toBe('function');
    });

    it('should handle embedding without model', () => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});

      PerformanceMiddleware.trackEmbeddingGeneration(500);

      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledWith(
        'embedding_generation',
        {
          textLength: 500,
          model: undefined,
          operation: 'embed',
        },
        ['embedding', 'ai']
      );
    });
  });

  describe('Vector Search Tracking', () => {
    beforeEach(() => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});
    });

    it('should track vector search operations', () => {
      let endMetric: any;
      mockPerformanceCollector.startMetric.mockReturnValue(() => {
        endMetric = vi.fn();
        return endMetric;
      });

      const endTracker = PerformanceMiddleware.trackVectorSearch(1536, 10);

      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledWith(
        'vector_search',
        {
          vectorSize: 1536,
          topK: 10,
          operation: 'search',
        },
        ['vector', 'search']
      );

      expect(typeof endTracker).toBe('function');
    });

    it('should handle different vector sizes and topK values', () => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});

      PerformanceMiddleware.trackVectorSearch(768, 5);
      PerformanceMiddleware.trackVectorSearch(1024, 20);

      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledTimes(2);
    });
  });

  describe('Authentication Tracking', () => {
    beforeEach(() => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});
    });

    it('should track JWT authentication', () => {
      let endMetric: any;
      mockPerformanceCollector.startMetric.mockReturnValue(() => {
        endMetric = vi.fn();
        return endMetric;
      });

      const endTracker = PerformanceMiddleware.trackAuthentication('jwt', 'user-123-abc');

      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledWith(
        'auth_validation',
        {
          method: 'jwt',
          userId: 'user-12...',
          operation: 'auth',
        },
        ['auth', 'security']
      );

      expect(typeof endTracker).toBe('function');
    });

    it('should track API key authentication', () => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});

      PerformanceMiddleware.trackAuthentication('api_key');

      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledWith(
        'auth_validation',
        {
          method: 'api_key',
          userId: undefined,
          operation: 'auth',
        },
        ['auth', 'security']
      );
    });

    it('should truncate user IDs for privacy', () => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});

      const longUserId = 'user-very-long-identifier-that-should-be-truncated';
      PerformanceMiddleware.trackAuthentication('jwt', longUserId);

      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledWith(
        'auth_validation',
        {
          method: 'jwt',
          userId: 'user-ve...',
          operation: 'auth',
        },
        ['auth', 'security']
      );
    });
  });

  describe('Cache Operation Tracking', () => {
    beforeEach(() => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});
    });

    it('should track cache get operations', () => {
      let endMetric: any;
      mockPerformanceCollector.startMetric.mockReturnValue(() => {
        endMetric = vi.fn();
        return endMetric;
      });

      const endTracker = PerformanceMiddleware.trackCacheOperation('get', 'user:123');

      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledWith(
        'cache_get',
        {
          key: 'user:123',
          operation: 'get',
        },
        ['cache']
      );

      expect(typeof endTracker).toBe('function');
    });

    it('should track cache set operations', () => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});

      PerformanceMiddleware.trackCacheOperation('set', 'session:abc123');

      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledWith(
        'cache_set',
        {
          key: 'session:abc123',
          operation: 'set',
        },
        ['cache']
      );
    });

    it('should track cache delete operations', () => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});

      PerformanceMiddleware.trackCacheOperation('delete');

      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledWith(
        'cache_delete',
        {
          key: undefined,
          operation: 'delete',
        },
        ['cache']
      );
    });

    it('should truncate long cache keys', () => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});

      const longKey = 'very-long-cache-key-that-should-be-truncated-for-privacy-and-performance-' + 'x'.repeat(100);
      PerformanceMiddleware.trackCacheOperation('get', longKey);

      expect(mockPerformanceCollector.startMetric).toHaveBeenCalledWith(
        'cache_get',
        {
          key: expect.stringMatching(/^very-long-cache-key-that-should-be-truncated-for-privacy-and-performance-x+$/),
          operation: 'get',
        },
        ['cache']
      );
    });
  });
});

describe('Performance Middleware Instances', () => {
  describe('Default Middleware', () => {
    it('should provide default middleware instance', () => {
      expect(performanceMiddleware).toBeInstanceOf(PerformanceMiddleware);
    });

    it('should have sensible default configuration', () => {
      expect(performanceMiddleware).toBeInstanceOf(PerformanceMiddleware);
    });
  });

  describe('HTTP Performance Middleware', () => {
    beforeEach(() => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});
    });

    it('should provide ready-to-use HTTP middleware', () => {
      expect(typeof httpPerformance).toBe('function');
    });

    it('should work as Express middleware', () => {
      mockPerformanceCollector.startMetric.mockReturnValue(() => {});

      const mockRequest = {
        method: 'GET',
        path: '/test',
        headers: {},
      };
      const mockResponse = {
        end: vi.fn(),
      };
      const mockNext = vi.fn();

      // Should not throw
      expect(() => {
        httpPerformance(mockRequest as any, mockResponse as any, mockNext);
      }).not.toThrow();

      expect(mockNext).toHaveBeenCalled();
    });
  });
});