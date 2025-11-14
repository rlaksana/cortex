// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

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
  get(key: string): unknown;
  get<T>(key: string, defaultValue: T): T;
  has(key: string): boolean;
  reload(): Promise<void>;
  getSection<T extends Record<string, unknown>>(section: string): T;
  getAll(): Record<string, unknown>;
  set(key: string, value: unknown): void;
  validate(key: string, validator: (value: unknown) => boolean): boolean;
}

/**
 * Logging service interface
 */
export interface ILoggerService {
  debug(message: string, ...args: unknown[]): void;
  info(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  error(message: string, error?: Error | unknown, ...args: unknown[]): void;
  child(context: Record<string, unknown>): ILoggerService;
  withContext(context: Record<string, unknown>): ILoggerService;
  setLevel(level: 'debug' | 'info' | 'warn' | 'error'): void;
  getLevel(): string;
  isLevelEnabled(level: string): boolean;
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
  search(filters: Record<string, unknown>): Promise<SearchResult[]>;
  getById(id: string): Promise<KnowledgeItem | null>;
  getByType(type: string): Promise<KnowledgeItem[]>;
  findByTags(tags: string[]): Promise<KnowledgeItem[]>;
  findSimilar(query: string, threshold?: number): Promise<KnowledgeItem[]>;
  validateQuery(query: SearchQuery): ValidationResult;
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
  authenticate(token: string): Promise<AuthResult>;
  authorize(user: User, resource: string, action: string): Promise<AuthzResult>;
  generateToken(user: User): Promise<string>;
  validateToken(token: string): Promise<TokenValidationResult>;
  refreshToken(refreshToken: string): Promise<TokenRefreshResult>;
  revokeToken(token: string): Promise<boolean>;
  getUserPermissions(userId: string): Promise<string[]>;
  checkRole(userId: string, role: string): Promise<boolean>;
}

// Supporting types for authentication
export interface User {
  id: string;
  username: string;
  email?: string;
  roles: string[];
  permissions: string[];
  isActive: boolean;
  lastLogin?: Date;
}

export interface AuthResult {
  success: boolean;
  user?: User;
  error?: string;
  requiresMfa?: boolean;
}

export interface AuthzResult {
  allowed: boolean;
  reason?: string;
  conditions?: string[];
}

export interface TokenValidationResult {
  valid: boolean;
  user?: User;
  error?: string;
  expiresAt?: Date;
}

export interface TokenRefreshResult {
  success: boolean;
  accessToken?: string;
  refreshToken?: string;
  error?: string;
}

/**
 * Audit service interface
 */
export interface IAuditService {
  log(action: string, data: AuditLogData): Promise<void>;
  query(filters: AuditQueryFilters): Promise<AuditLogEntry[]>;
  archive(before: Date): Promise<ArchiveResult>;
  getStats(timeRange: TimeRange): Promise<AuditStats>;
  export(filters: AuditQueryFilters, format: 'json' | 'csv'): Promise<string>;
}

// Supporting types for audit service
export interface AuditLogData {
  action: string;
  userId?: string;
  resource?: string;
  timestamp: Date;
  metadata?: Record<string, unknown>;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  category?: string;
}

export interface AuditLogEntry {
  id: string;
  action: string;
  userId?: string;
  resource?: string;
  timestamp: Date;
  metadata?: Record<string, unknown>;
  severity: string;
  category?: string;
}

export interface AuditQueryFilters {
  userId?: string;
  action?: string;
  resource?: string;
  timeRange?: TimeRange;
  severity?: string[];
  category?: string;
  limit?: number;
  offset?: number;
}

export interface TimeRange {
  start: Date;
  end: Date;
}

export interface ArchiveResult {
  success: boolean;
  archivedCount: number;
  error?: string;
}

export interface AuditStats {
  totalEntries: number;
  entriesByAction: Record<string, number>;
  entriesByUser: Record<string, number>;
  entriesBySeverity: Record<string, number>;
  timeRange: TimeRange;
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
  collect(): Promise<Record<string, unknown>>;
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
  set(key: string, value: unknown, ttl?: number): Promise<void>;
  delete(key: string): Promise<boolean>;
  clear(): Promise<void>;
  has(key: string): Promise<boolean>;
  getMultiple<T>(keys: string[]): Promise<Map<string, T | null>>;
  setMultiple(entries: Map<string, unknown>, ttl?: number): Promise<void>;
  deleteMultiple(keys: string[]): Promise<number>;
  increment(key: string, amount?: number): Promise<number>;
  getStats(): Promise<CacheStats>;
}

export interface CacheStats {
  hitCount: number;
  missCount: number;
  hitRate: number;
  itemCount: number;
  memoryUsage: number;
  evictionCount: number;
}

/**
 * Event service interface for loose coupling
 */
export interface IEventService {
  emit<T = unknown>(event: string, data: T): void;
  on<T = unknown>(event: string, handler: (data: T) => void): EventSubscription;
  off<T = unknown>(event: string, handler: (data: T) => void): void;
  once<T = unknown>(event: string, handler: (data: T) => void): EventSubscription;
  removeAllListeners(event?: string): void;
  getListenerCount(event: string): number;
  getEventNames(): string[];
  emitAsync<T = unknown>(event: string, data: T): Promise<void>;
}

export interface EventSubscription {
  unsubscribe(): void;
  isActive: boolean;
  eventId: string;
}

/**
 * Validation service interface
 */
export interface IValidationService {
  validate<T>(data: unknown, schema: string): Promise<ValidationResult<T>>;
  validateAsync<T>(data: unknown, schema: string): Promise<ValidationResult<T>>;
  addSchema(name: string, schema: unknown): void;
  removeSchema(name: string): void;
  hasSchema(name: string): boolean;
  getSchemas(): string[];
  compileSchema(schema: unknown): CompiledSchema;
}

export interface ValidationResult<T = unknown> {
  valid: boolean;
  data?: T;
  errors?: ValidationError[];
  warnings?: ValidationWarning[];
}

export interface ValidationError {
  path: string;
  message: string;
  code: string;
  value?: unknown;
}

export interface ValidationWarning {
  path: string;
  message: string;
  code: string;
  value?: unknown;
}

export interface CompiledSchema {
  validate(data: unknown): ValidationResult;
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
