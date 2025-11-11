/**
 * Global type definitions for Cortex Memory MCP Server
 * Provides missing global types and resolves common type issues
 */

// Performance API extensions
declare global {
  interface GlobalPerformance {
    gc?: () => void;
    retryBudgetIntegration?: unknown;
  }

  var global: GlobalPerformance & typeof globalThis;

  // Performance service global for compatibility
  var performanceService: import('./autofix-shims').PerformanceService;
}

// Global GC function for Node.js with --expose-gc
declare const gc: (() => void) | undefined;

// Vitest globals for testing
declare global {
  const describe: any;
  const it: any;
  const test: any;
  const expect: any;
  const beforeEach: any;
  const afterEach: any;
  const beforeAll: any;
  const afterAll: any;
  const vi: any;
}

// Node.js process extensions
declare namespace NodeJS {
  interface Process {
    // Environment configuration
    env: {
      [key: string]: string | undefined;
      NODE_ENV?: string;
      DEBUG?: string;
      // Database configuration
      QDRANT_URL?: string;
      QDRANT_API_KEY?: string;
      // Service configuration
      PORT?: string;
      HOST?: string;
      // Feature flags
      ENABLE_METRICS?: string;
      ENABLE_TRACING?: string;
    };

    // Memory usage for performance monitoring
    memoryUsage(): {
      rss: number;
      heapTotal: number;
      heapUsed: number;
      external: number;
      arrayBuffers: number;
    };
  }
}

// Express application extensions
declare global {
  namespace Express {
    interface Request {
      // Add common request extensions
      correlationId?: string;
      tenantId?: string;
      user?: {
        id: string;
        roles: string[];
      };
    }

    interface Response {
      // Add common response extensions
      correlationId?: string;
    }
  }
}

// Common utility types
export type LooseString = string;
export type LooseObject = Record<string, any>;
export type LooseArray = any[];

// Error handling types
export interface EnhancedError extends Error {
  code?: string | number;
  statusCode?: number;
  details?: Record<string, any>;
  timestamp?: Date;
  correlationId?: string;
}

// Configuration types
export interface BaseConfiguration {
  environment: 'development' | 'production' | 'test';
  debug: boolean;
  port: number;
  host: string;
}

export interface DatabaseConfiguration {
  url: string;
  apiKey?: string;
  timeout?: number;
  retries?: number;
}

// Service health types
export interface HealthStatus {
  status: 'healthy' | 'unhealthy' | 'degraded';
  timestamp: Date;
  services: Record<string, {
    status: 'healthy' | 'unhealthy' | 'degraded';
    message?: string;
    responseTime?: number;
  }>;
}

// Monitoring and metrics types
export interface MetricPoint {
  name: string;
  value: number;
  timestamp: Date;
  tags?: Record<string, string>;
}

export interface PerformanceMetrics {
  memory: {
    used: number;
    total: number;
    external: number;
  };
  cpu: {
    usage: number;
  };
  uptime: number;
  responseTime: number;
}

// Cache configuration
export interface CacheConfiguration {
  enabled: boolean;
  ttl: number;
  maxSize: number;
  strategy: 'lru' | 'fifo' | 'lfu';
}

// API response types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: Record<string, any>;
  };
  meta?: {
    timestamp: Date;
    correlationId: string;
    version: string;
  };
}

// Pagination types
export interface PaginationParams {
  page: number;
  limit: number;
  offset?: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}

// Search and filter types
export interface SearchParams {
  query?: string;
  filters?: Record<string, any>;
  sort?: {
    field: string;
    direction: 'asc' | 'desc';
  };
  pagination?: PaginationParams;
}

// Export for global augmentation
export {};