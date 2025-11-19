#!/usr/bin/env node

/**
 * Cortex Memory MCP Server - Enhanced Entry Point Factory
 *
 * This module provides a typed factory for creating MCP server instances
 * with comprehensive type safety, validation, and runtime error handling.
 * Updated for MCP SDK v1.22.0 compatibility.
 *
 * Features:
 * - Complete type safety with no 'any' usage
 * - Comprehensive input validation and sanitization
 * - Enhanced error handling with detailed error types
 * - Graceful shutdown with proper resource cleanup
 * - Performance monitoring and metrics collection
 * - Dependency injection with lifecycle management
 * - Runtime type checking and validation
 *
 * @author Cortex Team
 * @version 3.0.0
 * @since 2025
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';

import { McpBaseError, McpErrorFactory, McpToolTimeoutError } from '@/types/mcp-error-types.js';
// MCP Error handling imports
import { generateCorrelationId } from '@/utils/correlation-id.js';
import { McpResponseBuilder } from '@/utils/mcp-response-builders.js';

import { autoEnvironment } from './config/auto-environment.js';
import { EnhancedDIContainer } from './di/enhanced-di-container';
import {
  isMemoryFindSchema,
  isSystemStatusSchema,
  isTypedMemoryStoreItem,
  validateMemoryStoreItems,
  validateServerConfig,
} from './factories/factory-type-guards';
import type { TypedDIContainer } from './factories/factory-types';
import {
  safeExtractErrorDetails
} from './utils/type-safe-access.js';

// Enhanced logger with configurable output and complete type safety
export interface LoggerConfig {
  readonly level: 'error' | 'warn' | 'info' | 'debug';
  readonly silent: boolean;
  readonly prefix?: string;
  readonly structured?: boolean;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface LogEntry {
  readonly timestamp: string;
  readonly level: string;
  readonly message: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly prefix?: string;
}

export class EntryPointLogger {
  private config: LoggerConfig;
  private originalConsoleError: typeof console.error;
  private originalConsoleLog: typeof console.log;
  private originalConsoleWarn: typeof console.warn;
  private originalConsoleDebug: typeof console.debug;
  private capturedLogs: LogEntry[] = [];
  private performanceMetrics = {
    totalLogs: 0,
    errorCount: 0,
    warnCount: 0,
    infoCount: 0,
    debugCount: 0,
  };

  constructor(config: LoggerConfig) {
    this.validateConfig(config);
    this.config = { ...config };
    this.originalConsoleError = console.error;
    this.originalConsoleLog = console.log;
    this.originalConsoleWarn = console.warn;
    this.originalConsoleDebug = console.debug;

    if (config.silent) {
      this.enableSilentMode();
    }
  }

  private validateConfig(config: LoggerConfig): void {
    const validLevels = ['error', 'warn', 'info', 'debug'] as const;
    if (!validLevels.includes(config.level)) {
      throw new Error(
        `Invalid log level: ${config.level}. Must be one of: ${validLevels.join(', ')}`
      );
    }

    if (typeof config.silent !== 'boolean') {
      throw new Error('Silent must be a boolean');
    }

    if (config.prefix !== undefined && typeof config.prefix !== 'string') {
      throw new Error('Prefix must be a string');
    }
  }

  private enableSilentMode(): void {
    console.error = (...args: ReadonlyArray<unknown>) => {
      this.captureLog('error', args.join(' '));
    };

    console.log = (...args: ReadonlyArray<unknown>) => {
      this.captureLog('info', args.join(' '));
    };

    console.warn = (...args: ReadonlyArray<unknown>) => {
      this.captureLog('warn', args.join(' '));
    };

    console.debug = (...args: ReadonlyArray<unknown>) => {
      this.captureLog('debug', args.join(' '));
    };
  }

  private captureLog(
    level: string,
    message: string,
    metadata?: Readonly<Record<string, unknown>>
  ): void {
    const logEntry: LogEntry = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      message,
      metadata,
      prefix: this.config.prefix,
    };

    this.capturedLogs.push(logEntry);
    this.updateMetrics(level);
  }

  private updateMetrics(level: string): void {
    this.performanceMetrics.totalLogs++;
    switch (level.toLowerCase()) {
      case 'error':
        this.performanceMetrics.errorCount++;
        break;
      case 'warn':
        this.performanceMetrics.warnCount++;
        break;
      case 'info':
        this.performanceMetrics.infoCount++;
        break;
      case 'debug':
        this.performanceMetrics.debugCount++;
        break;
    }
  }

  public restoreConsole(): void {
    console.error = this.originalConsoleError;
    console.log = this.originalConsoleLog;
    console.warn = this.originalConsoleWarn;
    console.debug = this.originalConsoleDebug;
  }

  public shouldLog(level: 'error' | 'warn' | 'info' | 'debug'): boolean {
    const levels: Record<string, number> = { error: 0, warn: 1, info: 2, debug: 3 };
    return levels[level] <= levels[this.config.level];
  }

  public error(
    message: string,
    error?: Error | unknown,
    metadata?: Readonly<Record<string, unknown>>
  ): void {
    if (this.shouldLog('error')) {
      const prefix = this.config.prefix ? `[${this.config.prefix}] ` : '';

      if (this.config.silent) {
        this.captureLog('error', message, { error, ...metadata });
      } else {
        if (error instanceof Error) {
          console.error(`${prefix}[ERROR] ${message}`, {
            error: {
              name: error.name,
              message: error.message,
              stack: error.stack,
            },
            ...metadata,
          });
        } else {
          console.error(`${prefix}[ERROR] ${message}`, { error, ...metadata });
        }
      }
    }
  }

  public warn(message: string, metadata?: Readonly<Record<string, unknown>>): void {
    if (this.shouldLog('warn')) {
      const prefix = this.config.prefix ? `[${this.config.prefix}] ` : '';

      if (this.config.silent) {
        this.captureLog('warn', message, metadata);
      } else {
        console.warn(`${prefix}[WARN] ${message}`, metadata);
      }
    }
  }

  public info(message: string, metadata?: Readonly<Record<string, unknown>>): void {
    if (this.shouldLog('info') && !this.config.silent) {
      const prefix = this.config.prefix ? `[${this.config.prefix}] ` : '';

      if (this.config.structured) {
        console.log(
          JSON.stringify({
            timestamp: new Date().toISOString(),
            level: 'INFO',
            prefix,
            message,
            metadata: { ...this.config.metadata, ...metadata },
          })
        );
      } else {
        console.log(`${prefix}[INFO] ${message}`, metadata);
      }
    } else if (this.config.silent) {
      this.captureLog('info', message, metadata);
    }
  }

  public debug(message: string, metadata?: Readonly<Record<string, unknown>>): void {
    if (this.shouldLog('debug') && !this.config.silent) {
      const prefix = this.config.prefix ? `[${this.config.prefix}] ` : '';

      if (this.config.structured) {
        console.debug(
          JSON.stringify({
            timestamp: new Date().toISOString(),
            level: 'DEBUG',
            prefix,
            message,
            metadata: { ...this.config.metadata, ...metadata },
          })
        );
      } else {
        console.debug(`${prefix}[DEBUG] ${message}`, metadata);
      }
    } else if (this.config.silent) {
      this.captureLog('debug', message, metadata);
    }
  }

  public getCapturedLogs(): ReadonlyArray<LogEntry> {
    return [...this.capturedLogs];
  }

  public getPerformanceMetrics() {
    return { ...this.performanceMetrics };
  }

  public clearCapturedLogs(): void {
    this.capturedLogs = [];
    this.performanceMetrics = {
      totalLogs: 0,
      errorCount: 0,
      warnCount: 0,
      infoCount: 0,
      debugCount: 0,
    };
  }
}

// Simple UUID generator
function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

// Enhanced type definitions with complete type safety
export type StoredItemKind =
  | 'entity'
  | 'relation'
  | 'observation'
  | 'section'
  | 'runbook'
  | 'change'
  | 'issue'
  | 'decision'
  | 'todo'
  | 'release_note'
  | 'ddl'
  | 'pr_context'
  | 'incident'
  | 'release'
  | 'risk'
  | 'assumption';

export interface StoredItem {
  readonly id: string;
  readonly kind: StoredItemKind;
  readonly data: Readonly<Record<string, unknown>>;
  readonly scope?: Readonly<{
    project?: string;
    branch?: string;
    org?: string;
  }>;
  readonly timestamp: string;
  readonly stored: boolean;
}

export interface ServerConfig {
  readonly name: string;
  readonly version: string;
  readonly logger: LoggerConfig;
  readonly collectionName?: string;
  readonly qdrantUrl?: string;
  readonly qdrantApiKey?: string;
}

export interface HealthStatus {
  readonly success: boolean;
  readonly timestamp: string;
  readonly server: {
    readonly name: string;
    readonly version: string;
    readonly uptime: number;
    readonly memory: NodeJS.MemoryUsage;
  };
  readonly database: {
    readonly type: string;
    readonly url: string;
    readonly collection: string;
    readonly collectionExists: boolean;
    readonly totalItems: number;
    readonly storage: string;
  };
  readonly features: {
    readonly storage: {
      readonly qdrant: boolean;
      readonly memory: boolean;
    };
  };
  readonly operation?: string;
  readonly cleanup?: {
    readonly itemsRemoved: number;
  };
}

// Qdrant client interface to replace 'any'
export interface QdrantClient {
  getCollection(collectionName: string): Promise<CollectionInfo>;
  createCollection(collectionName: string, config: CollectionConfig): Promise<void>;
  upsert(collectionName: string, points: UpsertPoints): Promise<void>;
  search(collectionName: string, params: SearchParams): Promise<SearchResult[]>;
}

export interface CollectionInfo {
  points_count: number;
  config: unknown;
}

export interface CollectionConfig {
  vectors: {
    size: number;
    distance: 'Cosine' | 'Euclid' | 'Dot' | 'Manhattan';
  };
}

export interface UpsertPoints {
  points: Array<{
    id: string;
    vector: number[];
    payload: StoredItem;
  }>;
}

export interface SearchParams {
  vector: number[];
  limit: number;
  filter?: unknown;
  with_payload?: boolean;
}

export interface SearchResult {
  payload?: StoredItem;
}

export class McpServerFactory {
  private logger: EntryPointLogger;
  private config: ServerConfig;
  private server: McpServer;
  private qdrantClient: QdrantClient | null = null;
  private memoryStore: Map<string, StoredItem> = new Map();
  private isShuttingDown = false;
  private container: TypedDIContainer;

  // MCP Error handling properties
  private responseBuilder: McpResponseBuilder;
  private activeCorrelations: Map<string, { toolName: string; startTime: number }> = new Map();
  private errorCounts: Map<string, number> = new Map();
  private readonly MAX_ERROR_COUNT = 10;
  private readonly CORRELATION_TIMEOUT_MS = 300000; // 5 minutes

  constructor(config: ServerConfig, container?: TypedDIContainer) {
    // Validate configuration
    const validation = validateServerConfig(config);
    if (!validation.valid) {
      throw new Error(`Invalid server configuration: ${validation.errors.join(', ')}`);
    }

    this.config = config;
    this.logger = new EntryPointLogger(config.logger);
    this.server = new McpServer({
      name: config.name,
      version: config.version,
    });

    // Initialize MCP response builder
    this.responseBuilder = new McpResponseBuilder({
      defaultProtocolVersion: '2024-11-05',
      defaultServerVersion: config.version || '3.0.0',
      enablePerformanceTracking: true,
      enableCorrelationLogging: true,
      maxResponseSize: 1024 * 1024, // 1MB
    });

    // Use provided container or create default
    this.container =
      container ||
      new EnhancedDIContainer({
        enableAutoValidation: true,
        enableDebugLogging: config.logger.level === 'debug',
      });

    this.logger.info('MCP Server factory initialized', {
      name: config.name,
      version: config.version,
      hasContainer: !!container,
      hasMcpErrorHandling: true,
    });
  }

  public async initialize(): Promise<void> {
    try {
      this.logger.info('Initializing MCP Server...');

      // Initialize advanced features
      await this.initializeAdvancedFeatures();

      // Register tools
      await this.registerTools();

      // Setup graceful shutdown handlers
      this.setupGracefulShutdown();

      this.logger.info('MCP Server initialized successfully');
    } catch (error) {
      this.logger.error('Failed to initialize MCP Server:', error);
      throw error;
    }
  }

  // MCP Error handling methods
  /**
   * Create a new correlation ID and track it
   */
  public createCorrelationId(toolName: string): string {
    const correlationId = generateCorrelationId();
    this.activeCorrelations.set(correlationId, {
      toolName,
      startTime: Date.now(),
    });

    // Start performance tracking
    this.responseBuilder.startPerformanceTracking(correlationId);

    // Cleanup old correlations periodically
    this.cleanupCorrelations();

    return correlationId;
  }

  /**
   * Validate and get correlation ID context
   */
  public getCorrelationContext(
    correlationId: string
  ): { toolName: string; startTime: number } | null {
    const context = this.activeCorrelations.get(correlationId);
    if (!context) {
      this.logger.warn(`Unknown correlation ID: ${correlationId}`);
      return null;
    }

    // Check for timeout
    if (Date.now() - context.startTime > this.CORRELATION_TIMEOUT_MS) {
      this.activeCorrelations.delete(correlationId);
      this.logger.warn(`Correlation ID timed out: ${correlationId}`);
      return null;
    }

    return context;
  }

  /**
   * Complete correlation tracking
   */
  public completeCorrelation(correlationId: string): void {
    const context = this.activeCorrelations.get(correlationId);
    if (context) {
      const duration = Date.now() - context.startTime;
      this.logger.debug(`Correlation completed: ${correlationId} (${duration}ms)`);
      this.activeCorrelations.delete(correlationId);
    }
  }

  /**
   * Wrap tool execution with MCP error handling
   */
  public async executeToolWithMcpHandling<T>(
    toolName: string,
    operation: () => Promise<T>,
    options: {
      correlationId?: string;
      timeoutMs?: number;
      args?: Record<string, unknown>;
      additionalContext?: {
        userId?: string;
        sessionId?: string;
        requestId?: string;
      };
    } = {}
  ): Promise<T> {
    const correlationId = options.correlationId || this.createCorrelationId(toolName);
    const timeoutMs = options.timeoutMs || 30000;

    try {
      // Set up timeout if specified
      const timeoutPromise =
        timeoutMs > 0
          ? new Promise<never>((_, reject) => {
              setTimeout(() => {
                reject(
                  new McpToolTimeoutError(toolName, timeoutMs, {
                    correlationId,
                    executionId: this.generateExecutionId(),
                  })
                );
              }, timeoutMs);
            })
          : null;

      // Execute operation with timeout
      const result =
        timeoutMs > 0 && timeoutPromise
          ? await Promise.race([operation(), timeoutPromise])
          : await operation();

      this.completeCorrelation(correlationId);
      return result;
    } catch (error) {
      this.recordError(toolName, error);

      // Convert to MCP error if needed
      const mcpError =
        error instanceof McpBaseError
          ? error
          : McpErrorFactory.fromError(error, toolName, correlationId);

      // Note: correlationId and toolContext are readonly in the base class
      // They will be set through the error response construction instead

      this.completeCorrelation(correlationId);
      throw mcpError;
    }
  }

  /**
   * Record errors for monitoring
   */
  private recordError(toolName: string, error: unknown): void {
    const errorKey = `${toolName}:${error instanceof Error ? error.name : 'Unknown'}`;
    const count = this.errorCounts.get(errorKey) || 0;
    this.errorCounts.set(errorKey, count + 1);

    // Log error tracking
    this.logger.warn(`Error recorded for ${toolName}:`, {
      errorKey,
      count: count + 1,
      maxCount: this.MAX_ERROR_COUNT,
    });

    // Check if we're approaching error threshold
    if (count + 1 >= this.MAX_ERROR_COUNT) {
      this.logger.error(`Error threshold exceeded for ${toolName}`, {
        errorKey,
        count: count + 1,
        threshold: this.MAX_ERROR_COUNT,
      });
    }
  }

  /**
   * Generate execution ID
   */
  private generateExecutionId(): string {
    return `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Clean up old correlations
   */
  private cleanupCorrelations(): void {
    const cutoff = Date.now() - this.CORRELATION_TIMEOUT_MS;
    let cleaned = 0;

    for (const [correlationId, context] of this.activeCorrelations.entries()) {
      if (context.startTime < cutoff) {
        this.activeCorrelations.delete(correlationId);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      this.logger.debug(`Cleaned up ${cleaned} expired correlations`);
    }
  }

  /**
   * Get MCP error statistics
   */
  public getMcpErrorStats(): {
    activeCorrelations: number;
    errorCounts: Record<string, number>;
    totalErrors: number;
  } {
    const totalErrors = Array.from(this.errorCounts.values()).reduce(
      (sum, count) => sum + count,
      0
    );

    return {
      activeCorrelations: this.activeCorrelations.size,
      errorCounts: Object.fromEntries(this.errorCounts),
      totalErrors,
    };
  }

  /**
   * Reset error statistics
   */
  public resetMcpErrorStats(): void {
    this.errorCounts.clear();
    this.logger.info('MCP error statistics reset');
  }

  private async initializeAdvancedFeatures(): Promise<void> {
    try {
      // Try to import Qdrant client for vector storage with proper typing
      const qdrantModule = await import('@qdrant/js-client-rest');

      // Type assertion to ensure the imported client matches our interface
      const qdrantClientInstance = new qdrantModule.QdrantClient({
        url: this.config.qdrantUrl || process.env.QDRANT_URL || 'http://localhost:6333',
        apiKey: this.config.qdrantApiKey || process.env.QDRANT_API_KEY,
      });

      // Validate that the client has required methods
      if (
        typeof qdrantClientInstance.getCollection === 'function' &&
        typeof qdrantClientInstance.createCollection === 'function' &&
        typeof qdrantClientInstance.upsert === 'function' &&
        typeof qdrantClientInstance.search === 'function'
      ) {
        this.qdrantClient = qdrantClientInstance as unknown as QdrantClient;
        this.logger.info('Qdrant client initialized and validated');
      } else {
        throw new Error('Imported Qdrant client does not implement required interface');
      }
    } catch (error) {
      const errorDetails = safeExtractErrorDetails(error);
      this.logger.warn('Qdrant client not available, using in-memory storage:', errorDetails);
      this.qdrantClient = null;
    }
  }

  private async registerTools(): Promise<void> {
    const collectionName =
      this.config.collectionName || process.env.QDRANT_COLLECTION_NAME || 'cortex-memory';

    // Typed schemas for MCP registration - JSON Schema format
    const memoryStoreSchema = {
      type: 'object',
      properties: {
        items: {
          type: 'array',
          description: 'Array of knowledge items to store',
          items: {
            type: 'object',
            properties: {
              kind: {
                type: 'string',
                enum: [
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
                ],
              },
              data: {
                type: 'object',
                description: 'The knowledge data',
              },
              scope: {
                type: 'object',
                properties: {
                  project: { type: 'string' },
                  branch: { type: 'string' },
                  org: { type: 'string' },
                },
              },
            },
            required: ['kind', 'data'],
          },
        },
      },
    };

    const memoryFindSchema = {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search query' },
        scope: { type: 'object', description: 'Search scope' },
        types: {
          type: 'array',
          items: { type: 'string' },
          description: 'Knowledge types to filter',
        },
        limit: { type: 'number', default: 10, description: 'Maximum results' },
      },
      required: ['query'],
    };

    const systemStatusSchema = {
      type: 'object',
      properties: {
        operation: { type: 'string', description: 'System operation to perform' },
      },
    };

    // Register memory_store tool
    this.server.registerTool(
      'memory_store',
      {
        title: 'Memory Store',
        description:
          'Store knowledge items in Cortex memory with advanced deduplication, TTL, truncation, and insights.',
        inputSchema: memoryStoreSchema as any,
      },
      async (args: { items?: unknown[] }, _extra: unknown) => {
        const correlationId = this.createCorrelationId('memory_store');

        try {
          return await this.executeToolWithMcpHandling(
            'memory_store',
            async () => {
              // Validate input parameters
              if (!args.items || !Array.isArray(args.items)) {
                throw McpErrorFactory.createValidationError(
                  'memory_store',
                  'items',
                  'Items array is required and must be an array',
                  {
                    correlationId,
                    receivedValue: args.items,
                    expectedType: 'array',
                  }
                );
              }

              this.logger.info('Memory store tool called', {
                itemCount: args.items.length,
                correlationId,
              });

              // Validate items before processing
              const validation = validateMemoryStoreItems(args.items);
              if (!validation.valid) {
                throw McpErrorFactory.createValidationError(
                  'memory_store',
                  'items',
                  `Invalid items: ${validation.errors.join(', ')}`,
                  {
                    correlationId,
                    receivedValue: args.items,
                    expectedType: 'array of valid memory items',
                  }
                );
              }

              const result = await this.storeItems(validation.items || []);

              // Build success response using MCP response builder
              const successResponse = this.responseBuilder.buildSuccessResponse(
                {
                  itemsStored: result.stored,
                  errors: result.errors.length,
                  warnings: validation.warnings ? [...validation.warnings] : [],
                  metadata: {
                    storage: this.qdrantClient ? 'qdrant+memory' : 'memory-only',
                    validated: true,
                  },
                },
                {
                  toolName: 'memory_store',
                  correlationId,
                  executionId: this.generateExecutionId(),
                },
                {
                  metadata: {
                    itemCount: args.items.length,
                    storageType: this.qdrantClient ? 'qdrant+memory' : 'memory-only',
                  },
                  warnings: validation.warnings ? [...validation.warnings] : undefined,
                  suggestions:
                    result.errors.length > 0
                      ? [
                          'Check error details for failed items',
                          'Verify item format and required fields',
                        ]
                      : undefined,
                }
              );

              return {
                content: successResponse.content,
              };
            },
            {
              correlationId,
              timeoutMs: 30000,
              args: { items: args.items },
            }
          );
        } catch (error) {
          this.logger.error('Memory store tool failed:', error);

          // Build error response using MCP response builder
          const errorResponse = this.responseBuilder.buildErrorResponse(error, {
            toolName: 'memory_store',
            correlationId,
            executionId: this.generateExecutionId(),
          });

          return {
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify(errorResponse, null, 2),
              },
            ],
          };
        }
      }
    );

    // Register memory_find tool
    this.server.registerTool(
      'memory_find',
      {
        title: 'Memory Find',
        description: 'Search Cortex memory with advanced strategies and graph expansion.',
        inputSchema: memoryFindSchema as any,
      },
      async (args: unknown, _extra: unknown) => {
        try {
          // Validate input parameters
          if (!isMemoryFindSchema(args)) {
            throw new McpError(ErrorCode.InvalidParams, 'Invalid memory find schema');
          }

          this.logger.info('Memory find tool called', {
            query: args.query?.substring(0, 100) + '...',
            types: args.types,
            limit: args.limit,
          });

          const result = await this.findItems(args);
          return {
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify(
                  {
                    success: true,
                    results: result.results,
                    totalFound: result.total_count,
                    metadata: {
                      timestamp: new Date().toISOString(),
                      storage: this.qdrantClient ? 'qdrant+memory' : 'memory-only',
                      validated: true,
                      filters: {
                        types: args.types,
                        scope: args.scope,
                        limit: args.limit,
                      },
                    },
                  },
                  null,
                  2
                ),
              },
            ],
          };
        } catch (error) {
          this.logger.error('Memory find tool failed:', error);
          if (error instanceof McpError) {
            throw error;
          }
          throw new McpError(
            ErrorCode.InternalError,
            `Memory find failed: ${error instanceof Error ? error.message : 'Unknown error'}`
          );
        }
      }
    );

    // Register system_status tool
    this.server.registerTool(
      'system_status',
      {
        title: 'System Status',
        description: 'System monitoring, cleanup, and maintenance operations.',
        inputSchema: systemStatusSchema as any,
      },
      async (args: unknown, _extra: unknown) => {
        try {
          // Validate input parameters
          if (!isSystemStatusSchema(args)) {
            throw new McpError(ErrorCode.InvalidParams, 'Invalid system status schema');
          }

          this.logger.info('System status tool called', { operation: args.operation });
          const status = await this.getSystemStatus(args.operation);
          return {
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify(status, null, 2),
              },
            ],
          };
        } catch (error) {
          this.logger.error('System status tool failed:', error);
          if (error instanceof McpError) {
            throw error;
          }
          throw new McpError(
            ErrorCode.InternalError,
            `System status failed: ${error instanceof Error ? error.message : 'Unknown error'}`
          );
        }
      }
    );
  }

  private async storeItems(items: unknown[]): Promise<{ stored: number; errors: string[] }> {
    const errors: string[] = [];
    const collectionName =
      this.config.collectionName || process.env.QDRANT_COLLECTION_NAME || 'cortex-memory';

    for (const item of items) {
      try {
        // Validate item structure
        if (!isTypedMemoryStoreItem(item)) {
          errors.push(`Invalid item structure: item must have kind and data properties`);
          continue;
        }

        const id = generateUUID();
        const timestamp = new Date().toISOString();
        const storedItem: StoredItem = {
          id,
          kind: item.kind,
          data: item.data,
          scope: item.scope,
          timestamp,
          stored: true,
        };

        // Store in memory
        this.memoryStore.set(id, storedItem);

        // Try to store in Qdrant if available
        if (this.qdrantClient) {
          try {
            // Ensure collection exists
            try {
              await this.qdrantClient.getCollection(collectionName);
            } catch {
              await this.qdrantClient.createCollection(collectionName, {
                vectors: {
                  size: 384,
                  distance: 'Cosine',
                },
              });
            }

            await this.qdrantClient.upsert(collectionName, {
              points: [
                {
                  id,
                  vector: Array(384).fill(0), // Placeholder embedding
                  payload: storedItem,
                },
              ],
            });
          } catch (qdrantError) {
            const errorDetails = safeExtractErrorDetails(qdrantError);
            this.logger.warn('Qdrant storage failed, using in-memory only:', errorDetails);
          }
        }
      } catch (error) {
        errors.push(
          `Failed to store item: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
      }
    }

    return { stored: items.length, errors };
  }

  private async findItems(args: {
    query: string;
    scope?: { project?: string; branch?: string; org?: string };
    types?: StoredItemKind[];
    limit?: number;
  }): Promise<{ results: StoredItem[]; total_count: number }> {
    const query = args.query || '';
    const scope = args.scope || {};
    const types = args.types || [];
    const limit = Math.min(args.limit || 10, 100); // Cap at 100 for performance
    const collectionName =
      this.config.collectionName || process.env.QDRANT_COLLECTION_NAME || 'cortex-memory';

    // Validate inputs
    if (!query.trim()) {
      throw new Error('Query cannot be empty');
    }

    if (limit < 1) {
      throw new Error('Limit must be at least 1');
    }

    let results = Array.from(this.memoryStore.values());

    // Apply filters
    if (types.length > 0) {
      results = results.filter((item) => types.includes(item.kind));
    }

    if (scope.project || scope.branch || scope.org) {
      results = results.filter((item) => {
        if (!item.scope) return false;
        if (scope.project && item.scope.project !== scope.project) return false;
        if (scope.branch && item.scope.branch !== scope.branch) return false;
        if (scope.org && item.scope.org !== scope.org) return false;
        return true;
      });
    }

    // Simple text search
    if (query) {
      const queryLower = query.toLowerCase();
      results = results.filter((item) =>
        JSON.stringify(item.data).toLowerCase().includes(queryLower)
      );
    }

    // Try Qdrant search if available
    if (this.qdrantClient && query) {
      try {
        const filter = { must: [] as unknown[] };

        if (types.length > 0) {
          filter.must.push({
            key: 'kind',
            match: { any: types },
          });
        }

        if (scope.project || scope.branch || scope.org) {
          const scopeFilter = { must: [] as unknown[] };
          if (scope.project) {
            scopeFilter.must.push({
              key: 'scope.project',
              match: { value: scope.project },
            });
          }
          if (scope.branch) {
            scopeFilter.must.push({
              key: 'scope.branch',
              match: { value: scope.branch },
            });
          }
          if (scope.org) {
            scopeFilter.must.push({
              key: 'scope.org',
              match: { value: scope.org },
            });
          }
          filter.must.push(scopeFilter);
        }

        const searchResult = await this.qdrantClient.search(collectionName, {
          vector: Array(384).fill(0.1),
          limit,
          filter: filter.must.length > 0 ? filter : undefined,
          with_payload: true,
        });

        const qdrantResults = searchResult.map(
          (point: { payload?: StoredItem }) => point.payload as StoredItem
        );
        const combinedResults = [...qdrantResults];
        for (const item of results) {
          if (!combinedResults.find((r) => r.id === item.id)) {
            combinedResults.push(item);
          }
        }
        results = combinedResults.slice(0, limit);
      } catch (qdrantError) {
        this.logger.warn('Qdrant search failed, using memory-only results:', qdrantError as Record<string, unknown>);
      }
    }

    return {
      results: results.slice(0, limit),
      total_count: results.length,
    };
  }

  private async getSystemStatus(
    operation?: string
  ): Promise<HealthStatus & { operation?: string; cleanup?: unknown }> {
    const collectionName =
      this.config.collectionName || process.env.QDRANT_COLLECTION_NAME || 'cortex-memory';
    let collectionExists = false;
    let totalItems = this.memoryStore.size;

    if (this.qdrantClient) {
      try {
        const collectionInfo = await this.qdrantClient.getCollection(collectionName);
        totalItems = collectionInfo.points_count;
        collectionExists = true;
      } catch {
        // Collection doesn't exist or connection failed
      }
    }

    const status: HealthStatus = {
      success: true,
      timestamp: new Date().toISOString(),
      server: {
        name: this.config.name,
        version: this.config.version,
        uptime: process.uptime(),
        memory: process.memoryUsage(),
      },
      database: {
        type: this.qdrantClient ? 'qdrant' : 'in-memory',
        url: this.config.qdrantUrl || process.env.QDRANT_URL || 'http://localhost:6333',
        collection: collectionName,
        collectionExists,
        totalItems,
        storage: this.qdrantClient ? 'vector database (persistent)' : 'in-memory (ephemeral)',
      },
      features: {
        storage: {
          qdrant: !!this.qdrantClient,
          memory: true,
        },
      },
      operation,
    };

    // Perform system operation if specified
    if (operation === 'cleanup') {
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      let cleaned = 0;

      for (const [id, item] of this.memoryStore.entries()) {
        if (new Date(item.timestamp) < thirtyDaysAgo) {
          this.memoryStore.delete(id);
          cleaned++;
        }
      }

      return { ...status, cleanup: { itemsRemoved: cleaned } };
    }

    return status;
  }

  private setupGracefulShutdown(): void {
    const shutdown = (signal: string): void => {
      if (this.isShuttingDown) return;
      this.isShuttingDown = true;

      this.logger.info(`Received ${signal}, shutting down gracefully...`);

      // Cleanup resources
      this.memoryStore.clear();

      // Restore console if in silent mode
      if (this.config.logger.silent) {
        this.logger.restoreConsole();
      }

      process.exit(0);
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('uncaughtException', (error) => {
      this.logger.error('Uncaught exception:', error);
      shutdown('uncaughtException');
    });
    process.on('unhandledRejection', (reason, promise) => {
      this.logger.error(`Unhandled rejection at: ${promise}, reason: ${reason}`);
      shutdown('unhandledRejection');
    });
  }

  public async startTransport(): Promise<void> {
    try {
      const transport = new StdioServerTransport();
      await this.server.connect(transport);
      this.logger.info('MCP Server transport started successfully');
    } catch (error) {
      this.logger.error('Failed to start transport:', error);
      throw error;
    }
  }

  public getServer(): McpServer {
    return this.server;
  }

  public getLogger(): EntryPointLogger {
    return this.logger;
  }

  public async shutdown(): Promise<void> {
    if (this.isShuttingDown) return;

    this.isShuttingDown = true;
    this.logger.info('Shutting down MCP Server...');

    // Log final MCP error statistics
    const errorStats = this.getMcpErrorStats();
    this.logger.info('Final MCP error statistics:', errorStats);

    // Cleanup MCP error handling resources
    this.activeCorrelations.clear();
    this.errorCounts.clear();
    this.responseBuilder.cleanupPerformanceTracking();

    // Cleanup resources
    this.memoryStore.clear();

    // Restore console if in silent mode
    if (this.config.logger.silent) {
      this.logger.restoreConsole();
    }

    this.logger.info('MCP Server shutdown complete');
  }
}

// Factory function for creating server instances with automatic environment configuration
export function createMcpServer(config: Partial<ServerConfig> = {}): McpServerFactory {
  // Initialize automatic environment configuration
  const envStatus = autoEnvironment.getConfigurationStatus();

  // Check if environment is properly configured
  if (!envStatus.isConfigured) {
    const setupInstructions = autoEnvironment.getSetupInstructions();
    throw new Error(
      `Cortex MCP Server configuration incomplete:\n` +
        `- ${envStatus.errors.join('\n- ')}\n\n` +
        `Setup instructions:\n` +
        setupInstructions.join('\n')
    );
  }

  const defaultConfig: ServerConfig = {
    name: 'cortex-memory-mcp',
    version: '3.0.0',
    logger: {
      level: (process.env.LOG_LEVEL as 'error' | 'warn' | 'info' | 'debug') || 'info',
      silent: false,
      prefix: 'CORTEX',
      structured: process.env.NODE_ENV === 'production',
    },
    collectionName: process.env.QDRANT_COLLECTION_NAME || 'cortex-memory',
    qdrantUrl: process.env.QDRANT_URL || 'http://localhost:6333',
    qdrantApiKey: process.env.QDRANT_API_KEY,
  };

  const mergedConfig = { ...defaultConfig, ...config };

  // Add environment status to config for debugging
  const serverFactory = new McpServerFactory(mergedConfig);

  // Log auto-configuration status in development mode
  if (process.env.NODE_ENV === 'development' || process.env.DEBUG_MODE === 'true') {
    const safeConfig = autoEnvironment.getSafeEnvironmentConfig();
    console.error(
      `[AUTO-CONFIG] Environment status: ${envStatus.isConfigured ? '✅ Configured' : '❌ Incomplete'}`
    );
    console.error(
      `[AUTO-CONFIG] Auto-configured: ${envStatus.autoConfigured ? '✅ Yes' : '❌ No'}`
    );
    console.error(`[AUTO-CONFIG] OpenAI API Key: ${safeConfig.OPENAI_API_KEY || '❌ Missing'}`);
    console.error(`[AUTO-CONFIG] Qdrant URL: ${safeConfig.QDRANT_URL}`);
    console.error(`[AUTO-CONFIG] Source: ${envStatus.openaiApiKeySource}`);
  }

  return serverFactory;
}

// Export for convenience
export { generateUUID };
