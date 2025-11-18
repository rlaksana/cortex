// EMERGENCY ROLLBACK: Core entry point type compatibility issues

/**
 * Main Entry Point with Dependency Injection
 *
 * Refactored main entry point that uses the DI container instead of
 * singleton patterns. Replaces index.ts with proper dependency injection.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  InitializeRequestSchema,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

import type {
  IConfigService,
  IDatabaseService,
  IEventService,
  IHealthCheckService,
  ILoggerService,
  IMemoryFindOrchestrator,
  IMemoryStoreOrchestrator,
  IPerformanceMonitor,
  KnowledgeItem,
  SearchQuery,
} from './di/service-interfaces.js';
import { serviceLocator } from './di/service-locator.js';
// Import DI components
import { createServiceRegistry } from './di/service-registry.js';
// Import schemas and types
import { ALL_JSON_SCHEMAS } from './schemas/json-schemas.js';

// Import safe property access utilities
import {
  safeExtractEventData,
  safeExtractDataProperty,
  safeExtractItemsArray,
  safeExtractResultsArray,
  safeExtractSearchTime,
  safeExtractResultsCount,
  createItemCountResponse,
  isMemoryStoredEventData,
  isMemoryFoundEventData,
  isSystemStatusEventData
} from './utils/type-safe-access.js';

// Helper functions for safe property access
const num = (v: unknown, d = 0): number => Number((v as number | undefined) ?? d);
const str = (v: unknown, d = ''): string => ((v as string | undefined) ?? d).trim();

// Safe extraction functions for MCP arguments
function safeExtractMemoryStoreArgs(args: unknown): { items: KnowledgeItem[] } {
  if (!args || typeof args !== 'object') {
    throw new Error('Invalid memory store arguments: expected object');
  }

  const argObj = args as Record<string, unknown>;
  const items = argObj.items;

  if (!Array.isArray(items)) {
    throw new Error('Invalid memory store arguments: items must be an array');
  }

  // Basic validation - assume items are already KnowledgeItem typed after schema validation
  return { items: items as KnowledgeItem[] };
}

function safeExtractMemoryFindArgs(args: unknown): SearchQuery {
  if (!args || typeof args !== 'object') {
    throw new Error('Invalid memory find arguments: expected object');
  }

  const argObj = args as Record<string, unknown>;

  // Basic validation - assume query is already SearchQuery typed after schema validation
  const query = argObj.query;
  if (typeof query !== 'string' && typeof query !== 'object') {
    throw new Error('Invalid memory find arguments: query must be string or object');
  }

  return args as SearchQuery;
}

/**
 * Main application class with dependency injection
 */
export class CortexMemoryServer {
  private server: Server;
  private logger: ILoggerService;
  private eventService: IEventService;
  private configService: IConfigService;
  private performanceMonitor: IPerformanceMonitor;
  private memoryStoreOrchestrator: IMemoryStoreOrchestrator;
  private memoryFindOrchestrator: IMemoryFindOrchestrator;
  private databaseService: IDatabaseService;
  private healthCheckService: IHealthCheckService;
  private isShuttingDown = false;

  constructor() {
    // Services will be injected through the service locator
    this.logger = serviceLocator.logger;
    this.eventService = serviceLocator.eventService;
    this.configService = serviceLocator.config;
    this.performanceMonitor = serviceLocator.performanceMonitor;
    this.memoryStoreOrchestrator = serviceLocator.memoryStoreOrchestrator;
    this.memoryFindOrchestrator = serviceLocator.memoryFindOrchestrator;
    this.databaseService = serviceLocator.databaseService;
    this.healthCheckService = serviceLocator.healthCheckService;

    this.server = new Server(
      {
        name: 'cortex-memory-mcp',
        version: '2.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupEventHandlers();
    this.setupRequestHandlers();
    this.setupGracefulShutdown();
  }

  /**
   * Start the MCP server
   */
  async start(): Promise<void> {
    const timer = this.performanceMonitor.startTimer('server.startup');

    try {
      this.logger.info('Starting Cortex Memory MCP Server...');

      // Initialize database
      await this.databaseService.getConnection();
      this.logger.info('Database connection established');

      // Emit system start event
      this.eventService.emit('system.started', {
        version: '2.0.0',
        environment: this.configService.get('NODE_ENV'),
        timestamp: new Date().toISOString(),
      });

      // Start the transport
      const transport = new StdioServerTransport();
      await this.server.connect(transport);

      timer();
      this.logger.info('Cortex Memory MCP Server started successfully');

      // Log server metrics
      this.eventService.emit('metrics.recorded', {
        type: 'server.startup_time',
        value: Date.now(),
        unit: 'timestamp',
      });
    } catch (error) {
      timer();
      this.logger.error('Failed to start server', error);
      this.eventService.emit('system.error', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  }

  /**
   * Stop the MCP server
   */
  async stop(): Promise<void> {
    if (this.isShuttingDown) {
      return;
    }

    this.isShuttingDown = true;
    this.logger.info('Stopping Cortex Memory MCP Server...');

    try {
      // Emit shutdown event
      this.eventService.emit('system.shutdown', {
        timestamp: new Date().toISOString(),
      });

      // Close database connection
      await this.databaseService.close();

      // Dispose services
      // Note: In a full implementation, we'd dispose all services here

      this.logger.info('Cortex Memory MCP Server stopped successfully');
    } catch (error) {
      this.logger.error('Error during server shutdown', error);
    }
  }

  /**
   * Setup event handlers
   */
  private setupEventHandlers(): void {
    // Handle database events
    this.eventService.on('database.error', (event) => {
      const eventData = safeExtractEventData(event);
      this.logger.error('Database error reported', safeExtractDataProperty(eventData));
    });

    this.eventService.on('database.connected', (event) => {
      const eventData = safeExtractEventData(event);
      this.logger.info('Database connected', safeExtractDataProperty(eventData));
    });

    // Handle memory events
    this.eventService.on('memory.stored', (event) => {
      const eventData = safeExtractEventData(event);
      if (isMemoryStoredEventData(eventData)) {
        const dataObj = safeExtractDataProperty(eventData);
        const items = safeExtractItemsArray(dataObj);
        this.logger.debug('Memory stored', { count: items.length });
      }
    });

    this.eventService.on('memory.found', (event) => {
      const eventData = safeExtractEventData(event);
      if (isMemoryFoundEventData(eventData)) {
        const dataObj = safeExtractDataProperty(eventData);
        const results = safeExtractResultsArray(dataObj);
        this.logger.debug('Memory search completed', { count: results.length });
      }
    });

    // Handle processing events
    this.eventService.on('processing.failed', (event) => {
      const eventData = safeExtractEventData(event);
      this.logger.error('Processing failed', safeExtractDataProperty(eventData));
    });

    // Handle system events
    this.eventService.on('system.error', (event) => {
      const eventData = safeExtractEventData(event);
      this.logger.error('System error', safeExtractDataProperty(eventData));
    });
  }

  /**
   * Setup MCP request handlers
   */
  private setupRequestHandlers(): void {
    // List tools handler
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'memory_store',
            description: 'Store knowledge items with semantic deduplication',
            inputSchema: ALL_JSON_SCHEMAS.memory_store,
          },
          {
            name: 'memory_find',
            description: 'Find knowledge items using intelligent search',
            inputSchema: ALL_JSON_SCHEMAS.memory_find,
          },
          {
            name: 'system_status',
            description: 'Get system status and health information',
            inputSchema: ALL_JSON_SCHEMAS.system_status,
          },
        ],
      };
    });

    // Call tool handler
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        const timer = this.performanceMonitor.startTimer(`tool.${name}`);

        this.eventService.emit('processing.started', {
          tool: name,
          arguments: args,
          correlationId: this.generateCorrelationId(),
        });

        let result;

        switch (name) {
          case 'memory_store':
            result = await this.handleMemoryStore(args);
            break;

          case 'memory_find':
            result = await this.handleMemoryFind(args);
            break;

          case 'system_status':
            result = await this.handleSystemStatus(args);
            break;

          default:
            throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
        }

        timer();
        this.eventService.emit('processing.completed', {
          tool: name,
          success: true,
          duration: Date.now(),
        });

        return result;
      } catch (error) {
        this.logger.error(`Tool execution failed: ${name}`, error);
        this.eventService.emit('processing.failed', {
          tool: name,
          error: error instanceof Error ? error.message : String(error),
        });

        throw new McpError(
          ErrorCode.InternalError,
          `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    });

    // Initialize handler
    this.server.setRequestHandler(InitializeRequestSchema, async (request) => {
      this.logger.info('MCP server initialized', {
        protocolVersion: request.params.protocolVersion,
        capabilities: request.params.capabilities,
      });

      return {
        protocolVersion: '2024-11-05',
        capabilities: {
          tools: {},
        },
      };
    });
  }

  /**
   * Handle memory store requests
   */
  private async handleMemoryStore(args: unknown): Promise<unknown> {
    const timer = this.performanceMonitor.startTimer('memory.store');

    try {
      // Safely extract arguments
      const { items } = safeExtractMemoryStoreArgs(args);
      const result = await this.memoryStoreOrchestrator.store(items);

      timer();
      this.eventService.emit('memory.stored', {
        itemsCount: items.length,
        result,
      });

      // Extract data safely
      const dataObj = safeExtractDataProperty(result);
      const storedCount = typeof dataObj.stored === 'number' ? dataObj.stored : 0;
      const skippedCount = typeof dataObj.skipped === 'number' ? dataObj.skipped : 0;

      return {
        content: [
          {
            type: 'text',
            text: `Successfully stored ${storedCount} items. Skipped ${skippedCount} duplicates.`,
          },
        ],
      };
    } catch (error) {
      timer();
      throw error;
    }
  }

  /**
   * Handle memory find requests
   */
  private async handleMemoryFind(args: unknown): Promise<unknown> {
    const timer = this.performanceMonitor.startTimer('memory.find');

    try {
      const query = safeExtractMemoryFindArgs(args);
      const result = await this.memoryFindOrchestrator.find(query);

      timer();
      const resultsCount = safeExtractResultsCount(result);
      const searchTime = safeExtractSearchTime(result.metadata);

      this.eventService.emit('memory.found', {
        query: args,
        resultsCount,
        result,
      });

      return {
        content: [
          {
            type: 'text',
            text: `Found ${resultsCount} matching items. Search took ${searchTime}ms.`,
          },
        ],
      };
    } catch (error) {
      timer();
      throw error;
    }
  }

  /**
   * Handle system status requests
   */
  private async handleSystemStatus(args: unknown): Promise<unknown> {
    const healthCheck = await this.healthCheckService.check();
    const metrics = this.performanceMonitor.getMetrics('system.status');

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              status: healthCheck.status,
              timestamp: new Date().toISOString(),
              environment: this.configService.get('NODE_ENV'),
              version: '2.0.0',
              health: healthCheck.checks,
              metrics,
            },
            null,
            2
          ),
        },
      ],
    };
  }

  /**
   * Setup graceful shutdown handlers
   */
  private setupGracefulShutdown(): void {
    const shutdown = async (signal: string) => {
      this.logger.info(`Received ${signal}, starting graceful shutdown...`);
      await this.stop();
      process.exit(0);
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGUSR2', () => shutdown('SIGUSR2')); // For nodemon

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      this.logger.error('Uncaught exception', error);
      this.eventService.emit('system.error', {
        error: error.message,
        stack: error.stack,
        type: 'uncaught_exception',
      });
      shutdown('uncaughtException');
    });

    process.on('unhandledRejection', (reason, promise) => {
      this.logger.error('Unhandled rejection', { reason, promise });
      this.eventService.emit('system.error', {
        error: String(reason),
        type: 'unhandled_rejection',
      });
    });
  }

  /**
   * Generate correlation ID for request tracking
   */
  private generateCorrelationId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

/**
 * Bootstrap function to initialize and start the server
 */
async function bootstrap(): Promise<void> {
  try {
    // Initialize dependency injection container
    const container = createServiceRegistry();

    // Initialize service locator
    serviceLocator.initialize(container);

    // Create and start server
    const server = new CortexMemoryServer();
    await server.start();
  } catch (error) {
    console.error('Failed to bootstrap Cortex Memory MCP Server:', error);
    process.exit(1);
  }
}

// Start the server if this file is run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  bootstrap().catch((error) => {
    console.error('Bootstrap failed:', error);
    process.exit(1);
  });
}

export { bootstrap };
