#!/usr/bin/env node

/**
 * Cortex Memory MCP Server - Qdrant Implementation
 *
 * Enhanced MCP server with Qdrant vector database backend for semantic search
 * and enhanced similarity detection capabilities. Integrates with the unified
 * database abstraction layer for flexibility and future extensibility.
 *
 * Features:
 * - Memory storage with semantic deduplication (85% similarity threshold)
 * - Intelligent multi-strategy search (semantic, keyword, hybrid, fallback)
 * - Qdrant vector database backend with automatic fallback
 * - MCP stdio transport compatibility
 * - Enhanced duplicate detection with semantic similarity
 * - Improved search relevance and confidence scoring
 * - Integration with unified database abstraction layer
 * - Production-ready error handling and monitoring
 *
 * Knowledge Types Supported:
 * - entity: Graph nodes representing any concept or object
 * - relation: Graph edges connecting entities with typed relationships
 * - observation: Fine-grained data attached to entities
 * - section: Document containers for organizing knowledge
 * - runbook: Step-by-step operational procedures
 * - change: Code change tracking and history
 * - issue: Bug tracking and problem management
 * - decision: Architecture Decision Records (ADRs)
 * - todo: Task and action item tracking
 * - release_note: Release documentation and changelogs
 * - ddl: Database schema migration history
 * - pr_context: Pull request metadata and context
 * - incident: Incident response and management
 * - release: Release deployment tracking
 * - risk: Risk assessment and mitigation
 * - assumption: Business and technical assumptions
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { config } from 'dotenv';
import { Server } from '@modelcontextprotocol/sdk/server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types';

import { logger } from './utils/logger.js';
import { loadEnv } from './config/environment.js';
import { databaseFactory } from './db/database-factory.js';
import { MemoryStoreOrchestratorQdrant } from './services/orchestrators/memory-store-orchestrator-qdrant.js';
import { MemoryFindOrchestratorQdrant } from './services/orchestrators/memory-find-orchestrator-qdrant.js';

import type {
  MemoryStoreResponse,
  MemoryFindResponse,
  SmartFindRequest,
  SmartFindResult
} from './types/core-interfaces.js';
import type {
  IDatabase,
  DatabaseConfig
} from './db/database-interface.js';

/**
 * Load environment variables from .env file
 *
 * Uses proper logger for MCP stdio transport compatibility.
 * MCP servers must use stderr for logging to avoid interfering with
 * the JSON-RPC protocol communication on stdout.
 */
logger.debug('Loading environment variables from .env file');
config();
logger.debug('Environment variables loaded successfully');

// Load validated environment configuration
loadEnv();

/**
 * Database connection management
 */
class DatabaseManager {
  private database: IDatabase | null = null;
  private config: DatabaseConfig;

  constructor() {
    this.config = {
      type: 'qdrant',
      url: process.env.QDRANT_URL || 'http://localhost:6333',
      apiKey: process.env.QDRANT_API_KEY,
      vectorSize: parseInt(process.env.VECTOR_SIZE || '1536'),
      distance: process.env.VECTOR_DISTANCE as any || 'Cosine',
      logQueries: process.env.NODE_ENV === 'development',
      connectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '30000'),
      maxConnections: parseInt(process.env.DB_MAX_CONNECTIONS || '10')
    };
  }

  async getDatabase(): Promise<IDatabase> {
    if (!this.database) {
      this.database = await databaseFactory.create(this.config);
      logger.info('Qdrant database connection established');
    }

    return this.database;
  }

  async healthCheck(): Promise<boolean> {
    try {
      if (!this.database) {
        await this.getDatabase();
      }
      return await this.database.healthCheck();
    } catch (error) {
      logger.error({ error }, 'Database health check failed');
      return false;
    }
  }

  async close(): Promise<void> {
    if (this.database) {
      await this.database.close();
      this.database = null;
      logger.info('Database connection closed');
    }
  }
}

/**
 * Lazy initialization pattern for memory orchestrators
 *
 * Prevents blocking MCP server startup by initializing heavy
 * database connections only when first tool is called.
 * This ensures the MCP server responds quickly to initial
 * protocol handshake messages.
 */
let memoryStoreOrchestrator: MemoryStoreOrchestratorQdrant | null = null;
let memoryFindOrchestrator: MemoryFindOrchestratorQdrant | null = null;
const databaseManager = new DatabaseManager();

/**
 * Initialize memory orchestrators on-demand
 *
 * Creates instances of memory store and find orchestrators
 * only when first needed. Implements singleton pattern
 * to prevent duplicate initialization.
 *
 * @throws {Error} If orchestrator initialization fails
 */
async function initializeOrchestrators(): Promise<void> {
  if (memoryStoreOrchestrator && memoryFindOrchestrator) {
    return; // Already initialized
  }

  try {
    // Get database connection
    const database = await databaseManager.getDatabase();

    // Initialize orchestrators with database
    memoryStoreOrchestrator = new MemoryStoreOrchestratorQdrant(database);
    memoryFindOrchestrator = new MemoryFindOrchestratorQdrant(database);

    logger.info('Memory orchestrators (Qdrant) initialized successfully');
  } catch (error) {
    logger.error({ error }, 'Failed to initialize memory orchestrators (Qdrant)');
    throw error;
  }
}

/**
 * Create MCP server with Qdrant capabilities
 */
const server = new Server(
  {
    name: 'cortex-qdrant',
    version: '2.0.0'
  },
  {
    capabilities: {
      tools: {}
    }
  }
);

/**
 * Register tools with the MCP server
 */
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'memory_store',
        description: 'Store knowledge items in the memory system with enhanced semantic deduplication (85% similarity threshold)',
        inputSchema: {
          type: 'object',
          properties: {
            items: {
              type: 'array',
              items: { type: 'object' },
              description: 'Array of knowledge items to store (supports all 16 knowledge types)'
            }
          },
          required: ['items']
        }
      },
      {
        name: 'memory_find',
        description: 'Find knowledge items using intelligent multi-strategy search (semantic, keyword, hybrid, fallback)',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query string - supports natural language and keywords'
            },
            scope: {
              type: 'object',
              properties: {
                project: { type: 'string' },
                branch: { type: 'string' },
                org: { type: 'string' }
              },
              description: 'Search scope constraints (optional)'
            },
            types: {
              type: 'array',
              items: { type: 'string' },
              description: 'Filter by specific knowledge types (optional)'
            },
            mode: {
              type: 'string',
              enum: ['auto', 'fast', 'deep'],
              description: 'Search mode: auto (best results), fast (quick), deep (comprehensive)',
              default: 'auto'
            },
            limit: {
              type: 'integer',
              minimum: 1,
              maximum: 100,
              description: 'Maximum number of results to return (default: 50)',
              default: 50
            },
            top_k: {
              type: 'integer',
              minimum: 1,
              maximum: 100,
              description: 'Number of top results to consider (default: 50)',
              default: 50
            },
            enable_auto_fix: {
              type: 'boolean',
              description: 'Enable automatic query correction and optimization',
              default: true
            },
            return_corrections: {
              type: 'boolean',
              description: 'Return information about applied query corrections',
              default: true
            },
            max_attempts: {
              type: 'integer',
              minimum: 1,
              maximum: 5,
              description: 'Maximum search attempts for auto-fixing',
              default: 3
            },
            timeout_per_attempt_ms: {
              type: 'integer',
              minimum: 1000,
              maximum: 30000,
              description: 'Timeout per search attempt in milliseconds',
              default: 10000
            }
          },
          required: ['query']
        }
      },
      {
        name: 'database_health',
        description: 'Check the health and status of the Qdrant database connection',
        inputSchema: {
          type: 'object',
          properties: {},
          required: []
        }
      },
      {
        name: 'database_stats',
        description: 'Get comprehensive statistics about the Qdrant database and knowledge base',
        inputSchema: {
          type: 'object',
          properties: {
            scope: {
              type: 'object',
              properties: {
                project: { type: 'string' },
                branch: { type: 'string' },
                org: { type: 'string' }
              },
              description: 'Scope to filter statistics (optional)'
            }
          },
          required: []
        }
      }
    ]
  };
});

/**
 * Handle tool calls
 */
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request;

  try {
    switch (name) {
      case 'memory_store':
        return await handleMemoryStore(args);
      case 'memory_find':
        return await handleMemoryFind(args);
      case 'database_health':
        return await handleDatabaseHealth();
      case 'database_stats':
        return await handleDatabaseStats(args);
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    logger.error({ error, tool: name, arguments: args }, 'Tool execution failed');

    // Return error response
    return {
      content: [
        {
          type: 'text',
          text: `Error executing ${name}: ${error instanceof Error ? error.message : 'Unknown error'}`
        }
      ]
    };
  }
});

/**
 * Handle memory store operations
 */
async function handleMemoryStore(args: { items: unknown[] }): Promise<{ content: any[] }> {
  await initializeOrchestrators();

  if (!memoryStoreOrchestrator) {
    throw new Error('Memory store orchestrator not initialized');
  }

  const response: MemoryStoreResponse = await memoryStoreOrchestrator.storeItems(args.items);

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify({
          success: response.errors.length === 0,
          stored: response.stored.length,
          errors: response.errors.length,
          autonomous_context: response.autonomous_context
        }, null, 2)
      }
    ]
  };
}

/**
 * Handle memory find operations
 */
async function handleMemoryFind(args: SmartFindRequest): Promise<{ content: any[] }> {
  await initializeOrchestrators();

  if (!memoryFindOrchestrator) {
    throw new Error('Memory find orchestrator not initialized');
  }

  // Convert legacy format to smart find if needed
  const smartRequest: SmartFindRequest = {
    query: args.query,
    scope: args.scope,
    types: args.types,
    top_k: args.top_k || args.limit || 50,
    mode: args.mode || 'auto',
    enable_auto_fix: args.enable_auto_fix ?? true,
    return_corrections: args.return_corrections ?? true,
    max_attempts: args.max_attempts || 3,
    timeout_per_attempt_ms: args.timeout_per_attempt_ms || 10000
  };

  const response: SmartFindResult = await memoryFindOrchestrator.findItems(smartRequest);

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify({
          hits: response.hits.length,
          suggestions: response.suggestions,
          autonomous_metadata: response.autonomous_metadata,
          debug: response.debug
        }, null, 2)
      }
    ]
  };
}

/**
 * Handle database health check
 */
async function handleDatabaseHealth(): Promise<{ content: any[] }> {
  const healthy = await databaseManager.healthCheck();

  // Get database statistics
  const stats = await databaseManager.getDatabase().then(db => db.getMetrics()).catch(() => null);

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify({
          healthy,
          database: stats ? {
            type: stats.type,
            connection_count: stats.connectionCount,
            storage_size: stats.storageSize,
            last_health_check: stats.lastHealthCheck
          } : null,
          timestamp: new Date().toISOString()
        }, null, 2)
      }
    ]
  };
}

/**
 * Handle database statistics
 */
async function handleDatabaseStats(args: { scope?: { project?: string; branch?: string; org?: string } }): Promise<{ content: any[] }> {
  await initializeOrchestrators();

  if (!memoryStoreOrchestrator) {
    throw new Error('Memory store orchestrator not initialized');
  }

  const database = await databaseManager.getDatabase();
  const stats = await database.getStatistics(args.scope);

  // Get orchestrator stats
  const orchestratorStats = memoryStoreOrchestrator.getOrchestratorStats();

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify({
          database: stats,
          orchestrator: orchestratorStats,
          timestamp: new Date().toISOString()
        }, null, 2)
      }
    ]
  };
}

/**
 * Graceful shutdown handler
 */
process.on('SIGINT', async () => {
  logger.info('Received SIGINT, shutting down gracefully...');

  try {
    await databaseManager.close();
    process.exit(0);
  } catch (error) {
    logger.error({ error }, 'Error during shutdown');
    process.exit(1);
  }
});

process.on('SIGTERM', async () => {
  logger.info('Received SIGTERM, shutting down gracefully...');

  try {
    await databaseManager.close();
    process.exit(0);
  } catch (error) {
    logger.error({ error }, 'Error during shutdown');
    process.exit(1);
  }
});

/**
 * Start the MCP server
 */
async function startServer(): Promise<void> {
  try {
    const transport = new StdioServerTransport();

    logger.info('Starting Cortex Memory MCP Server (Qdrant Implementation)...');
    logger.info('Enhanced capabilities: semantic search, deduplication, multi-strategy search');

    await server.connect(transport);

    logger.info('Cortex Memory MCP Server (Qdrant) started successfully');
    logger.info('Available tools: memory_store, memory_find, database_health, database_stats');

  } catch (error) {
    logger.error({ error }, 'Failed to start MCP server');
    process.exit(1);
  }
}

/**
 * Start server if this file is run directly
 */
if (import.meta.url === `file://${process.argv[1]}`) {
  startServer().catch(error => {
    logger.error({ error }, 'Failed to start server');
    process.exit(1);
  });
}

export { startServer };