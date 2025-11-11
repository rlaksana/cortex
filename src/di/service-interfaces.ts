/**
 * Service Interfaces for Dependency Injection
 *
 * Abstract interfaces for all major services to enable loose coupling
 * and proper dependency injection.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import type { IDatabase } from '../db/database-interface.js';
import type {
  PerformanceBaseline,
  PerformanceReport,
  PerformanceThresholds,
} from '../monitoring/performance-monitor.js';
import type { DependencyRegistry } from '../services/deps-registry.js';
import type {
  KnowledgeItem,
  MemoryFindResponse,
  MemoryStoreResponse,
  PerformanceMetrics,
  SearchQuery,
  SearchResult,
} from '../types/core-interfaces.js';

/**
 * Configuration service interface
 */
export interface IConfigService {
  get(key: string): any;
  get<T>(key: string, defaultValue: T): T;
  has(key: string): boolean;
  reload(): Promise<void>;
}

/**
 * Logging service interface
 */
export interface ILoggerService {
  debug(message: string, ...args: any[]): void;
  info(message: string, ...args: any[]): void;
  warn(message: string, ...args: any[]): void;
  error(message: string, error?: any, ...args: any[]): void;
  child(context: Record<string, any>): ILoggerService;
}

/**
 * Performance monitoring service interface
 */
export interface IPerformanceMonitor {
  startTimer(operation: string, metadata?: Record<string, unknown>): () => void;
  startOperation(operation: string, metadata?: Record<string, unknown>): () => PerformanceMetrics;
  setThresholds(operation: string, thresholds: PerformanceThresholds): void;
  createBaseline(operation?: string): void;
  detectRegressions(): Array<{ operation: string; regressions: PerformanceMetrics[] }>;
  generateReport(): PerformanceReport;
  getMetrics(operation: string): PerformanceMetrics[];
  getBaseline(operation: string): PerformanceBaseline | undefined;
  clear(clearBaselines?: boolean): void;
}

/**
 * Memory store orchestrator interface
 */
export interface IMemoryStoreOrchestrator {
  store(items: KnowledgeItem[]): Promise<MemoryStoreResponse>;
  upsert(items: KnowledgeItem[]): Promise<MemoryStoreResponse>;
  delete(ids: string[]): Promise<{ success: boolean; deleted: number }>;
  update(items: KnowledgeItem[]): Promise<MemoryStoreResponse>;
}

/**
 * Memory find orchestrator interface
 */
export interface IMemoryFindOrchestrator {
  find(query: SearchQuery): Promise<MemoryFindResponse>;
  search(filters: Record<string, any>): Promise<SearchResult[]>;
  getById(id: string): Promise<KnowledgeItem | null>;
  getByType(type: string): Promise<KnowledgeItem[]>;
}

/**
 * Database service interface
 */
export interface IDatabaseService {
  getConnection(): Promise<IDatabase>;
  healthCheck(): Promise<boolean>;
  close(): Promise<void>;
}

/**
 * Authentication service interface
 */
export interface IAuthService {
  authenticate(token: string): Promise<boolean>;
  authorize(user: any, resource: string, action: string): Promise<boolean>;
  generateToken(user: any): Promise<string>;
  validateToken(token: string): Promise<any>;
}

/**
 * Audit service interface
 */
export interface IAuditService {
  log(action: string, data: any): Promise<void>;
  query(filters: Record<string, any>): Promise<any[]>;
  archive(before: Date): Promise<number>;
}

/**
 * Deduplication service interface
 */
export interface IDeduplicationService {
  detectDuplicates(items: KnowledgeItem[]): Promise<
    Array<{
      original: KnowledgeItem;
      duplicates: KnowledgeItem[];
      similarity: number;
    }>
  >;
  merge(items: KnowledgeItem[], strategy: string): Promise<KnowledgeItem>;
}

/**
 * Embedding service interface
 */
export interface IEmbeddingService {
  generateEmbedding(text: string): Promise<number[]>;
  generateBatch(texts: string[]): Promise<number[][]>;
  calculateSimilarity(a: number[], b: number[]): number;
}

/**
 * Circuit breaker service interface
 */
export interface ICircuitBreakerService {
  execute<T>(operation: () => Promise<T>, serviceName: string): Promise<T>;
  getState(serviceName: string): string;
  reset(serviceName: string): void;
}

/**
 * Metrics service interface
 */
export interface IMetricsService {
  increment(name: string, value?: number, tags?: Record<string, string>): void;
  gauge(name: string, value: number, tags?: Record<string, string>): void;
  histogram(name: string, value: number, tags?: Record<string, string>): void;
  timing(name: string, duration: number, tags?: Record<string, string>): void;
  collect(): Promise<Record<string, any>>;
}

/**
 * Health check service interface
 */
export interface IHealthCheckService {
  check(): Promise<{
    status: 'healthy' | 'unhealthy' | 'degraded';
    checks: Array<{
      name: string;
      status: 'healthy' | 'unhealthy' | 'degraded';
      duration: number;
      message?: string;
    }>;
  }>;
  registerCheck(name: string, check: () => Promise<boolean>): void;
}

/**
 * Cache service interface
 */
export interface ICacheService {
  get<T>(key: string): Promise<T | null>;
  set(key: string, value: any, ttl?: number): Promise<void>;
  delete(key: string): Promise<void>;
  clear(): Promise<void>;
  has(key: string): Promise<boolean>;
}

/**
 * Event service interface for loose coupling
 */
export interface IEventService {
  emit(event: string, data: any): void;
  on(event: string, handler: (data: any) => void): void;
  off(event: string, handler: (data: any) => void): void;
  once(event: string, handler: (data: any) => void): void;
  removeAllListeners(event?: string): void;
}

/**
 * Validation service interface
 */
export interface IValidationService {
  validate<T>(data: any, schema: string): Promise<T>;
  validateAsync<T>(data: any, schema: string): Promise<T>;
  addSchema(name: string, schema: any): void;
  removeSchema(name: string): void;
}

/**
 * Service tokens for dependency injection
 */
export const ServiceTokens = {
  // Core services
  CONFIG_SERVICE: Symbol('ConfigService'),
  LOGGER_SERVICE: Symbol('LoggerService'),
  PERFORMANCE_MONITOR: Symbol('PerformanceMonitor'),

  // Database and storage
  DATABASE_SERVICE: Symbol('DatabaseService'),
  MEMORY_STORE_ORCHESTRATOR: Symbol('MemoryStoreOrchestrator'),
  MEMORY_FIND_ORCHESTRATOR: Symbol('MemoryFindOrchestrator'),

  // Security
  AUTH_SERVICE: Symbol('AuthService'),
  VALIDATION_SERVICE: Symbol('ValidationService'),

  // Data processing
  DEDUPLICATION_SERVICE: Symbol('DeduplicationService'),
  EMBEDDING_SERVICE: Symbol('EmbeddingService'),

  // Monitoring and health
  METRICS_SERVICE: Symbol('MetricsService'),
  HEALTH_CHECK_SERVICE: Symbol('HealthCheckService'),
  AUDIT_SERVICE: Symbol('AuditService'),

  // Infrastructure
  CIRCUIT_BREAKER_SERVICE: Symbol('CircuitBreakerService'),
  CACHE_SERVICE: Symbol('CacheService'),
  EVENT_SERVICE: Symbol('EventService'),
  DEPENDENCY_REGISTRY: Symbol('DependencyRegistry'),
} as const;

/**
 * Service type definitions
 */
export type ServiceType = (typeof ServiceTokens)[keyof typeof ServiceTokens];

/**
 * Re-export commonly used types for convenience
 */
export type { IDatabase } from '../db/database-interface.js';
export type {
  PerformanceBaseline,
  PerformanceReport,
  PerformanceThresholds,
} from '../monitoring/performance-monitor.js';
export type { DependencyRegistry } from '../services/deps-registry.js';
export type {
  KnowledgeItem,
  MemoryFindResponse,
  MemoryStoreResponse,
  PerformanceMetrics,
  SearchQuery,
  SearchResult,
} from '../types/core-interfaces.js';
