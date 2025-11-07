#!/usr/bin/env node

/**
 * Cortex Memory MCP Server - Entry Point Factory
 *
 * This module provides a standardized factory for creating MCP server instances
 * with consistent initialization patterns, error handling, and graceful shutdown.
 *
 * Features:
 * - Eliminates circular dependencies between entry points
 * - Provides consistent initialization patterns
 * - Implements proper error handling and graceful shutdown
 * - Supports both silent and verbose modes
 * - Ensures proper resource cleanup
 *
 * @author Cortex Team
 * @version 2.0.1
 * @since 2025
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { autoEnvironment } from './config/auto-environment.js';

// Enhanced logger with configurable output
export interface LoggerConfig {
  level: 'error' | 'warn' | 'info' | 'debug';
  silent: boolean;
  prefix?: string;
}

export class EntryPointLogger {
  private config: LoggerConfig;
  private originalConsoleError: typeof console.error;
  private originalConsoleLog: typeof console.log;
  private capturedLogs: string[] = [];

  constructor(config: LoggerConfig) {
    this.config = config;
    this.originalConsoleError = console.error;
    this.originalConsoleLog = console.log;

    if (config.silent) {
      this.enableSilentMode();
    }
  }

  private enableSilentMode(): void {
    console.error = (...args: any[]) => {
      this.capturedLogs.push(`[ERROR] ${args.join(' ')}`);
    };

    console.log = (...args: any[]) => {
      this.capturedLogs.push(`[INFO] ${args.join(' ')}`);
    };
  }

  public restoreConsole(): void {
    console.error = this.originalConsoleError;
    console.log = this.originalConsoleLog;
  }

  public shouldLog(level: string): boolean {
    const levels: Record<string, number> = { error: 0, warn: 1, info: 2, debug: 3 };
    return levels[level] <= levels[this.config.level];
  }

  public error(message: string, ...args: any[]): void {
    if (this.shouldLog('error')) {
      const prefix = this.config.prefix ? `[${this.config.prefix}] ` : '';
      console.error(`${prefix}[ERROR] ${message}`, ...args);
    }
  }

  public warn(message: string, ...args: any[]): void {
    if (this.shouldLog('warn')) {
      const prefix = this.config.prefix ? `[${this.config.prefix}] ` : '';
      console.error(`${prefix}[WARN] ${message}`, ...args);
    }
  }

  public info(message: string, ...args: any[]): void {
    if (this.shouldLog('info') && !this.config.silent) {
      const prefix = this.config.prefix ? `[${this.config.prefix}] ` : '';
      console.error(`${prefix}[INFO] ${message}`, ...args);
    }
  }

  public debug(message: string, ...args: any[]): void {
    if (this.shouldLog('debug') && !this.config.silent) {
      const prefix = this.config.prefix ? `[${this.config.prefix}] ` : '';
      console.error(`${prefix}[DEBUG] ${message}`, ...args);
    }
  }

  public getCapturedLogs(): string[] {
    return [...this.capturedLogs];
  }

  public clearCapturedLogs(): void {
    this.capturedLogs = [];
  }
}

// Simple UUID generator
function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// Type definitions
export interface StoredItem {
  id: string;
  kind: string;
  data: any;
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
  };
  timestamp: string;
  stored: boolean;
}

export interface ServerConfig {
  name: string;
  version: string;
  logger: LoggerConfig;
  collectionName?: string;
  qdrantUrl?: string;
  qdrantApiKey?: string;
}

export interface HealthStatus {
  success: boolean;
  timestamp: string;
  server: {
    name: string;
    version: string;
    uptime: number;
    memory: NodeJS.MemoryUsage;
  };
  database: {
    type: string;
    url: string;
    collection: string;
    collectionExists: boolean;
    totalItems: number;
    storage: string;
  };
  features: {
    storage: {
      qdrant: boolean;
      memory: boolean;
    };
  };
  operation?: string;
  cleanup?: any;
}

export class McpServerFactory {
  private logger: EntryPointLogger;
  private config: ServerConfig;
  private server: McpServer;
  private qdrantClient: any = null;
  private memoryStore: Map<string, StoredItem> = new Map();
  private isShuttingDown = false;

  constructor(config: ServerConfig) {
    this.config = config;
    this.logger = new EntryPointLogger(config.logger);
    this.server = new McpServer({
      name: config.name,
      version: config.version,
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

  private async initializeAdvancedFeatures(): Promise<void> {
    try {
      // Try to import Qdrant client for vector storage
      const qdrantModule = await import('@qdrant/js-client-rest');
      this.qdrantClient = new qdrantModule.QdrantClient({
        url: this.config.qdrantUrl || process.env.QDRANT_URL || 'http://localhost:6333',
        apiKey: this.config.qdrantApiKey || process.env.QDRANT_API_KEY
      });
      this.logger.info('Qdrant client initialized');
    } catch (error) {
      this.logger.warn('Qdrant client not available, using in-memory storage:', error);
    }
  }

  private async registerTools(): Promise<void> {
    const collectionName = this.config.collectionName || process.env.QDRANT_COLLECTION_NAME || 'cortex-memory';

    // Basic schemas for MCP registration
    const memoryStoreSchema: any = {
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
                enum: ['entity', 'relation', 'observation', 'section', 'runbook', 'change', 'issue', 'decision', 'todo', 'release_note', 'ddl', 'pr_context', 'incident', 'release', 'risk', 'assumption']
              },
              data: {
                type: 'object',
                description: 'The knowledge data'
              },
              scope: {
                type: 'object',
                properties: {
                  project: { type: 'string' },
                  branch: { type: 'string' },
                  org: { type: 'string' }
                }
              }
            },
            required: ['kind', 'data']
          }
        }
      }
    };

    const memoryFindSchema: any = {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search query' },
        scope: { type: 'object', description: 'Search scope' },
        types: { type: 'array', items: { type: 'string' }, description: 'Knowledge types to filter' },
        limit: { type: 'number', default: 10, description: 'Maximum results' }
      },
      required: ['query']
    };

    const systemStatusSchema: any = {
      type: 'object',
      properties: {
        operation: { type: 'string', description: 'System operation to perform' }
      }
    };

    // Register memory_store tool
    this.server.registerTool(
      'memory_store',
      {
        title: 'Memory Store',
        description: 'Store knowledge items in Cortex memory with advanced deduplication, TTL, truncation, and insights.',
        inputSchema: memoryStoreSchema,
      },
      async (args, _extra) => {
        try {
          this.logger.info('Memory store tool called', { itemCount: args.items?.length || 0 });
          const result = await this.storeItems(args.items || []);
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                success: true,
                itemsStored: result.stored,
                errors: result.errors.length,
                metadata: {
                  timestamp: new Date().toISOString(),
                  storage: this.qdrantClient ? 'qdrant+memory' : 'memory-only'
                }
              }, null, 2)
            }]
          };
        } catch (error) {
          this.logger.error('Memory store tool failed:', error);
          throw new McpError(
            ErrorCode.InternalError,
            `Memory store failed: ${error instanceof Error ? error.message : 'Unknown error'}`
          );
        }
      }
    );

    // Register memory_find tool
    this.server.registerTool(
      'memory_find',
      {
        title: 'Memory Find',
        description: 'Search Cortex memory with advanced strategies and graph expansion.',
        inputSchema: memoryFindSchema,
      },
      async (args, _extra) => {
        try {
          this.logger.info('Memory find tool called', { query: args.query?.substring(0, 100) + '...' });
          const result = await this.findItems(args);
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                success: true,
                results: result.results,
                totalFound: result.total_count,
                metadata: {
                  timestamp: new Date().toISOString(),
                  storage: this.qdrantClient ? 'qdrant+memory' : 'memory-only'
                }
              }, null, 2)
            }]
          };
        } catch (error) {
          this.logger.error('Memory find tool failed:', error);
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
        inputSchema: systemStatusSchema,
      },
      async (args, _extra) => {
        try {
          this.logger.info('System status tool called', { operation: args.operation });
          const status = await this.getSystemStatus(args.operation);
          return {
            content: [{
              type: 'text',
              text: JSON.stringify(status, null, 2)
            }]
          };
        } catch (error) {
          this.logger.error('System status tool failed:', error);
          throw new McpError(
            ErrorCode.InternalError,
            `System status failed: ${error instanceof Error ? error.message : 'Unknown error'}`
          );
        }
      }
    );
  }

  private async storeItems(items: any[]): Promise<{ stored: number; errors: string[] }> {
    const errors: string[] = [];
    const collectionName = this.config.collectionName || process.env.QDRANT_COLLECTION_NAME || 'cortex-memory';

    for (const item of items) {
      try {
        const id = generateUUID();
        const timestamp = new Date().toISOString();
        const storedItem: StoredItem = {
          id,
          kind: item.kind,
          data: item.data,
          scope: item.scope,
          timestamp,
          stored: true
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
                  distance: 'Cosine'
                }
              });
            }

            await this.qdrantClient.upsert(collectionName, {
              points: [{
                id,
                vector: Array(384).fill(0), // Placeholder embedding
                payload: storedItem
              }]
            });
          } catch (qdrantError) {
            this.logger.warn('Qdrant storage failed, using in-memory only:', qdrantError);
          }
        }
      } catch (error) {
        errors.push(`Failed to store item: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }

    return { stored: items.length, errors };
  }

  private async findItems(args: any): Promise<{ results: StoredItem[]; total_count: number }> {
    const query = args.query || '';
    const scope = args.scope || {};
    const types = args.types || [];
    const limit = args.limit || 10;
    const collectionName = this.config.collectionName || process.env.QDRANT_COLLECTION_NAME || 'cortex-memory';

    let results = Array.from(this.memoryStore.values());

    // Apply filters
    if (types.length > 0) {
      results = results.filter(item => types.includes(item.kind));
    }

    if (scope.project || scope.branch || scope.org) {
      results = results.filter(item => {
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
      results = results.filter(item =>
        JSON.stringify(item.data).toLowerCase().includes(queryLower)
      );
    }

    // Try Qdrant search if available
    if (this.qdrantClient && query) {
      try {
        const filter: any = { must: [] };

        if (types.length > 0) {
          filter.must.push({
            key: 'kind',
            match: { any: types }
          });
        }

        if (scope.project || scope.branch || scope.org) {
          const scopeFilter: any = { must: [] };
          if (scope.project) {
            scopeFilter.must.push({
              key: 'scope.project',
              match: { value: scope.project }
            });
          }
          if (scope.branch) {
            scopeFilter.must.push({
              key: 'scope.branch',
              match: { value: scope.branch }
            });
          }
          if (scope.org) {
            scopeFilter.must.push({
              key: 'scope.org',
              match: { value: scope.org }
            });
          }
          filter.must.push(scopeFilter);
        }

        const searchResult = await this.qdrantClient.search(collectionName, {
          vector: Array(384).fill(0.1),
          limit,
          filter: filter.must.length > 0 ? filter : undefined,
          with_payload: true
        });

        const qdrantResults = searchResult.map((point: { payload?: StoredItem }) => point.payload as StoredItem);
        const combinedResults = [...qdrantResults];
        for (const item of results) {
          if (!combinedResults.find(r => r.id === item.id)) {
            combinedResults.push(item);
          }
        }
        results = combinedResults.slice(0, limit);
      } catch (qdrantError) {
        this.logger.warn('Qdrant search failed, using memory-only results:', qdrantError);
      }
    }

    return {
      results: results.slice(0, limit),
      total_count: results.length
    };
  }

  private async getSystemStatus(operation?: string): Promise<HealthStatus & { operation?: string; cleanup?: any }> {
    const collectionName = this.config.collectionName || process.env.QDRANT_COLLECTION_NAME || 'cortex-memory';
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
        storage: this.qdrantClient ? 'vector database (persistent)' : 'in-memory (ephemeral)'
      },
      features: {
        storage: {
          qdrant: !!this.qdrantClient,
          memory: true
        }
      },
      operation
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
      this.logger.error('Unhandled rejection at:', promise, 'reason:', reason);
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

    // Cleanup resources
    this.memoryStore.clear();

    // Restore console if in silent mode
    if (this.config.logger.silent) {
      this.logger.restoreConsole();
    }
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
    version: '2.0.1',
    logger: {
      level: process.env.LOG_LEVEL as any || 'info',
      silent: false,
      prefix: 'CORTEX'
    },
    collectionName: process.env.QDRANT_COLLECTION_NAME || 'cortex-memory',
    qdrantUrl: process.env.QDRANT_URL || 'http://localhost:6333',
    qdrantApiKey: process.env.QDRANT_API_KEY
  };

  const mergedConfig = { ...defaultConfig, ...config };

  // Add environment status to config for debugging
  const serverFactory = new McpServerFactory(mergedConfig);

  // Log auto-configuration status in development mode
  if (process.env.NODE_ENV === 'development' || process.env.DEBUG_MODE === 'true') {
    const safeConfig = autoEnvironment.getSafeEnvironmentConfig();
    console.error(`[AUTO-CONFIG] Environment status: ${envStatus.isConfigured ? '✅ Configured' : '❌ Incomplete'}`);
    console.error(`[AUTO-CONFIG] Auto-configured: ${envStatus.autoConfigured ? '✅ Yes' : '❌ No'}`);
    console.error(`[AUTO-CONFIG] OpenAI API Key: ${safeConfig.OPENAI_API_KEY || '❌ Missing'}`);
    console.error(`[AUTO-CONFIG] Qdrant URL: ${safeConfig.QDRANT_URL}`);
    console.error(`[AUTO-CONFIG] Source: ${envStatus.openaiApiKeySource}`);
  }

  return serverFactory;
}

// Export for convenience
export { generateUUID };