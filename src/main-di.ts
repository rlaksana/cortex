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
} from './di/service-interfaces.js';
import { ServiceTokens } from './di/service-interfaces.js';
import { serviceLocator } from './di/service-locator.js';
// Import DI components
import { createServiceRegistry } from './di/service-registry.js';
// Import schemas and types
import { ALL_JSON_SCHEMAS } from './schemas/json-schemas.js';
import type { MemoryFindResponse,MemoryStoreResponse,SearchResult  } from './types/core-interfaces.js';


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
      this.logger.error('Database error reported', event.data);
    });

    this.eventService.on('database.connected', (event) => {
      this.logger.info('Database connected', event.data);
    });

    // Handle memory events
    this.eventService.on('memory.stored', (event) => {
      this.logger.debug('Memory stored', { count: event.data.items?.length || 0 });
    });

    this.eventService.on('memory.found', (event) => {
      this.logger.debug('Memory search completed', { count: event.data.results?.length || 0 });
    });

    // Handle processing events
    this.eventService.on('processing.failed', (event) => {
      this.logger.error('Processing failed', event.data);
    });

    // Handle system events
    this.eventService.on('system.error', (event) => {
      this.logger.error('System error', event.data);
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
  private async handleMemoryStore(args: any): Promise<any> {
    const timer = this.performanceMonitor.startTimer('memory.store');

    try {
      const result = await this.memoryStoreOrchestrator.store(args.items);

      timer();
      this.eventService.emit('memory.stored', {
        itemsCount: args.items?.length || 0,
        result,
      });

      return {
        content: [
          {
            type: 'text',
            text: `Successfully stored ${result.stored} items. Skipped ${result.skipped} duplicates.`,
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
  private async handleMemoryFind(args: any): Promise<any> {
    const timer = this.performanceMonitor.startTimer('memory.find');

    try {
      const result = await this.memoryFindOrchestrator.find(args);

      timer();
      this.eventService.emit('memory.found', {
        query: args,
        resultsCount: result.results?.length || 0,
        result,
      });

      return {
        content: [
          {
            type: 'text',
            text: `Found ${result.results?.length || 0} matching items. Search took ${result.metadata?.searchTime || 0}ms.`,
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
  private async handleSystemStatus(args: any): Promise<any> {
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
