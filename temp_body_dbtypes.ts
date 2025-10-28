export interface DatabaseConfig {
  type: 'qdrant';
  qdrant?: VectorConfig;
  fallback?: FallbackConfig;
}

export interface FallbackConfig {
  enabled: boolean;
  retryAttempts: number;
  retryDelay: number;
}

// Error types
export class DatabaseError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly originalError?: Error,
    public readonly context?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'DatabaseError';
  }
}

export class ConnectionError extends DatabaseError {
  constructor(message: string, originalError?: Error) {
    super(message, 'CONNECTION_ERROR', originalError);
    this.name = 'ConnectionError';
  }
}

export class ValidationError extends DatabaseError {
  constructor(
    message: string,
    public readonly field?: string
  ) {
    super(message, 'VALIDATION_ERROR', undefined, { field });
    this.name = 'ValidationError';
  }
}

export class NotFoundError extends DatabaseError {
  constructor(id: string, type: string = 'item') {
    super(`${type} with id '${id}' not found`, 'NOT_FOUND', undefined, { id, type });
    this.name = 'NotFoundError';
  }
}

export class DuplicateError extends DatabaseError {
  constructor(id: string, type: string = 'item') {
    super(`${type} with id '${id}' already exists`, 'DUPLICATE_ERROR', undefined, { id, type });
    this.name = 'DuplicateError';
  }
}

// Operation result types
export interface OperationResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: DatabaseError;
  metadata?: Record<string, unknown>;
}

export interface BatchOperationResult<T = unknown> {
  successful: T[];
  failed: Array<{
    item: T;
    error: DatabaseError;
  }>;
  total: number;
}

// Query types
export interface QueryBuilder {
  select(columns?: string[]): QueryBuilder;
  from(table: string): QueryBuilder;
  where(condition: string, params?: unknown[]): QueryBuilder;
  orderBy(column: string, direction?: 'ASC' | 'DESC'): QueryBuilder;
  limit(count: number): QueryBuilder;
  offset(count: number): QueryBuilder;
  build(): { sql: string; params: unknown[] };
}

// Transaction types
export interface TransactionOptions {
  isolation?: 'READ_UNCOMMITTED' | 'READ_COMMITTED' | 'REPEATABLE_READ' | 'SERIALIZABLE';
  readOnly?: boolean;
  timeout?: number;
}

export interface Transaction {
  query<T = unknown>(sql: string, params?: unknown[]): Promise<T[]>;
  commit(): Promise<void>;
  rollback(): Promise<void>;
}

// Connection pool types
export interface PoolStats {
  totalConnections: number;
  activeConnections: number;
  idleConnections: number;
  waitingClients: number;
}

export interface ConnectionPool {
  getConnection(): Promise<any>;
  releaseConnection(connection: any): Promise<void>;
  close(): Promise<void>;
  getStats(): PoolStats;
}

// Migration types
export interface Migration {
  id: string;
  name: string;
  up: (client: any) => Promise<void>;
  down: (client: any) => Promise<void>;
}

export interface MigrationOptions {
  direction?: 'up' | 'down';
  to?: string;
  dryRun?: boolean;
}

// Backup types
export interface BackupOptions {
  includeData?: boolean;
  includeSchema?: boolean;
  compression?: boolean;
  destination?: string;
}

export interface BackupResult {
  id: string;
  timestamp: string;
  size: number;
  location: string;
  checksum?: string;
}

// Monitoring types
export interface PerformanceMetrics {
  queryCount: number;
  averageQueryTime: number;
  slowQueries: number;
  connectionErrors: number;
  uptime: number;
}

export interface HealthCheckResult {
  healthy: boolean;
  timestamp: string;
  checks: Array<{
    name: string;
    status: 'pass' | 'fail' | 'warn';
    message?: string;
    responseTime?: number;
  }>;
}

// Generic database operation types
export interface DatabaseOperation<TParams = unknown, TResult = unknown> {
  name: string;
  execute: (params: TParams) => Promise<TResult>;
  validate?: (params: TParams) => boolean;
  timeout?: number;
}

export interface DatabaseOperations {
  [key: string]: DatabaseOperation;
}

// Type guards
export function isDatabaseError(error: unknown): error is DatabaseError {
  return error instanceof Error && 'code' in error;
}

export function isConnectionError(error: unknown): error is ConnectionError {
  return error instanceof ConnectionError;
}

export function isValidationError(error: unknown): error is ValidationError {
  return error instanceof ValidationError;
}

export function isNotFoundError(error: unknown): error is NotFoundError {
  return error instanceof NotFoundError;
}

export function isDuplicateError(error: unknown): error is DuplicateError {
  return error instanceof DuplicateError;
}

// Utility types
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export type RequiredFields<T, K extends keyof T> = T & Required<Pick<T, K>>;

export type OptionalFields<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

// Database event types
export interface DatabaseEvent {
  type: string;
  timestamp: string;
  data: Record<string, unknown>;
}

export interface QueryEvent extends DatabaseEvent {
  type: 'query';
  query: string;
  params?: unknown[];
  duration: number;
  success: boolean;
  error?: string;
}

export interface ConnectionEvent extends DatabaseEvent {
  type: 'connection';
  action: 'connect' | 'disconnect' | 'error';
  connectionId?: string;
}

export interface TransactionEvent extends DatabaseEvent {
  type: 'transaction';
  action: 'begin' | 'commit' | 'rollback';
  transactionId?: string;
}

export type DatabaseEventHandler = (event: DatabaseEvent) => void;

// Configuration validation types
export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export interface ConfigValidator<T> {
  validate: (config: T) => ValidationResult;
  sanitize?: (config: T) => T;
}

// Index types for better search performance
export interface IndexDefinition {
  name: string;
  table: string;
  columns: string[];
  unique?: boolean;
  type?: 'btree' | 'hash' | 'gist' | 'gin' | 'brin';
  where?: string;
}

// Schema types
export interface ColumnDefinition {
  name: string;
  type: string;
  nullable?: boolean;
  primary?: boolean;
  unique?: boolean;
  default?: unknown;
  check?: string;
}

export interface TableDefinition {
  name: string;
  columns: ColumnDefinition[];
  indexes?: IndexDefinition[];
  foreignKeys?: Array<{
    column: string;
    referencesTable: string;
    referencesColumn: string;
    onDelete?: 'CASCADE' | 'SET NULL' | 'RESTRICT';
  }>;
}

// Search result enhancement types
export interface EnhancedSearchResult extends SearchResult {
  excerpt?: string;
  breadcrumbs?: Array<{ title: string; id: string }>;
  related?: Array<{ id: string; score: number; kind: string }>;
  metadata?: Record<string, unknown>;
}

// Pagination types
export interface PaginationOptions {
  page?: number;
  limit?: number;
  offset?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface PaginatedResult<T> {
  items: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}
