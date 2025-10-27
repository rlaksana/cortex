#!/usr/bin/env node

/**
 * CORTEX MEMORY MCP SERVER - CLAUDE CODE MINIMAL VERSION
 *
 * This is a simplified MCP server specifically for Claude Code.
 * - No environment configuration required
 * - Direct Qdrant connection (hardcoded)
 * - Minimal dependencies
 * - Simple memory operations only
 */

import { Server } from '@modelcontextprotocol/sdk/server/index';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types';
import { logger } from './utils/logger.js';
import {
  ApiErrorHandler,
  AsyncErrorHandler,
  ErrorRecovery
} from './middleware/error-middleware.js';
import {
  ConfigurationError,
  ExternalApiError,
  NetworkError,
  ValidationError,
  globalErrorBoundary
} from './utils/error-handler.js';

import { QdrantClient } from '@qdrant/js-client-rest';
import { OpenAI } from 'openai';
import { config } from 'dotenv';

// Load environment variables from .env file
config();

// Validate OpenAI API key on startup
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

try {
  if (!OPENAI_API_KEY) {
    throw new ConfigurationError(
      'OPENAI_API_KEY environment variable is required',
      'OpenAI API key is missing. Please set your OpenAI API key to use Cortex Memory MCP',
      { envVar: 'OPENAI_API_KEY' }
    );
  }

  if (!OPENAI_API_KEY.startsWith('sk-')) {
    throw new ConfigurationError(
      'Invalid OpenAI API key format',
      'OpenAI API keys must start with "sk-"',
      { keyPrefix: OPENAI_API_KEY.substring(0, 10) }
    );
  }
} catch (error) {
  if (error instanceof ConfigurationError) {
    logger.error(`❌ CRITICAL: ${error.userMessage}`);
    logger.error(`❌ Example: export OPENAI_API_KEY=sk-your-key-here`);
  } else {
    logger.error('❌ CRITICAL: Configuration validation failed');
  }
  process.exit(1);
}

// Configuration with mandatory OpenAI API key
const CONFIG = {
  qdrant: {
    url: 'http://localhost:6333',
    collectionName: 'knowledge_items'
  },
  openai: {
    apiKey: OPENAI_API_KEY
  }
};

class SimpleCortexServer {
  private server: Server;
  private qdrant: QdrantClient;
  private openai: OpenAI;

  constructor() {
    this.server = new Server({
      name: 'cortex-memory',
      version: '1.0.0',
    }, {
      capabilities: {
        tools: {},
      },
    });

    this.qdrant = new QdrantClient({ url: CONFIG.qdrant.url });
    this.openai = new OpenAI({ apiKey: CONFIG.openai.apiKey });

    this.setupToolHandlers();
  }

  private setupToolHandlers() {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'memory_store',
            description: 'Store information in memory',
            inputSchema: {
              type: 'object',
              properties: {
                content: {
                  type: 'string',
                  description: 'Content to store in memory (simple format)'
                },
                kind: {
                  type: 'string',
                  description: 'Type of knowledge (entity, relation, observation, decision, todo, etc.)',
                  enum: ['entity', 'relation', 'observation', 'section', 'runbook', 'change', 'issue', 'decision', 'todo', 'release_note', 'ddl', 'pr_context', 'incident', 'release', 'risk', 'assumption']
                },
                items: {
                  type: 'array',
                  description: 'Array of knowledge items (complex format)',
                  items: {
                    type: 'object',
                    properties: {
                      kind: { type: 'string' },
                      data: { type: 'object' },
                      content: { type: 'string' }
                    }
                  }
                }
              },
              anyOf: [
                { required: ['content', 'kind'] },
                { required: ['items'] }
              ]
            }
          },
          {
            name: 'memory_find',
            description: 'Search memory for information',
            inputSchema: {
              type: 'object',
              properties: {
                query: {
                  type: 'string',
                  description: 'Search query'
                },
                limit: {
                  type: 'number',
                  description: 'Maximum number of results (default: 10)',
                  default: 10
                }
              },
              required: ['query']
            }
          }
        ]
      };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      // Check circuit breaker
      if (globalErrorBoundary.shouldTrip()) {
        return ApiErrorHandler.handleToolCall(
          new Error('Service temporarily unavailable due to high error rate'),
          name,
          args
        );
      }

      try {
        const result = await ErrorRecovery.gracefulDegradation(
          // Primary operation
          async () => {
            switch (name) {
              case 'memory_store':
                return await this.handleMemoryStore(args);
              case 'memory_find':
                return await this.handleMemoryFind(args);
              default:
                throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
            }
          },
          // Fallback operations
          [
            async () => {
              // Simplified fallback response
              return {
                content: [
                  {
                    type: 'text',
                    text: `⚠️ ${name} is currently experiencing issues. Please try again later.`
                  }
                ]
              };
            }
          ],
          { tool: name, arguments: args }
        );

        // Record successful operation
        globalErrorBoundary.reset();
        return result;

      } catch (error) {
        // Record error
        const standardError = ApiErrorHandler.handleToolCall(error, name, args);
        globalErrorBoundary.recordError(standardError);
        return standardError;
      }
    });
  }

  private async handleMemoryStore(args: any) {
    try {
      // Validate args using standardized validation
      ApiErrorHandler.validateArguments(args, {
        content: { type: 'string', required: false },
        kind: { type: 'string', required: false },
        items: { type: 'object', required: false }
      });

      const { content, kind, items } = args;

      // If items array is provided, process the first item for backward compatibility
      if (items && Array.isArray(items)) {
        if (items.length > 0) {
          const item = items[0];
          let itemContent = '';
          let itemKind = 'entity';

          if (item && typeof item === 'object') {
            itemContent = item.data?.content || item.content || JSON.stringify(item.data || {});
            itemKind = item.kind || kind || 'entity';
          } else {
            itemContent = JSON.stringify(item);
          }

          return await this.storeSingleItem(itemContent, itemKind);
        } else {
          return {
            content: [
              {
                type: 'text',
                text: '❌ Items array is empty'
              }
            ]
          };
        }
      }

      // Original simple format
      if (!content) {
        return {
          content: [
            {
              type: 'text',
              text: '❌ Content is required. Provide either: {content: string, kind: string} or {items: [{kind: string, data: {...}}]}'
            }
          ]
        };
      }

      if (!kind) {
        return {
          content: [
            {
              type: 'text',
              text: '❌ Kind is required. Must be one of: entity, relation, observation, section, runbook, change, issue, decision, todo, release_note, ddl, pr_context, incident, release, risk, assumption'
            }
          ]
        };
      }

      return await this.storeSingleItem(content, kind);
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `❌ Memory store error: ${error instanceof Error ? error.message : 'Unknown error'}`
          }
        ]
      };
    }
  }

  private async storeSingleItem(content: string, kind: string): Promise<{ content: any[] }> {
    try {
      // Validate inputs
      if (!content || typeof content !== 'string') {
        return {
          content: [
            {
              type: 'text',
              text: '❌ Invalid content: must be a non-empty string'
            }
          ]
        };
      }

      if (!kind || typeof kind !== 'string') {
        return {
          content: [
            {
              type: 'text',
              text: '❌ Invalid kind: must be a non-empty string'
            }
          ]
        };
      }

      // Generate embedding
      const embedding = await this.generateEmbedding(content);

      // Validate embedding
      if (!embedding || !Array.isArray(embedding) || embedding.length === 0) {
        return {
          content: [
            {
              type: 'text',
              text: '❌ Failed to generate valid embedding'
            }
          ]
        };
      }

      // Store in Qdrant
      const point = {
        id: this.generateUUID(),
        vector: embedding,
        payload: {
          content,
          kind,
          created_at: new Date().toISOString(),
          scope: { project: 'default', branch: 'main' }
        }
      };

      // Check if collection exists, create if not
      try {
        const collections = await this.qdrant.getCollections();
        const collectionExists = collections.collections.some(c => c.name === CONFIG.qdrant.collectionName);

        if (!collectionExists) {
          await this.qdrant.createCollection(CONFIG.qdrant.collectionName, {
            vectors: {
              size: 1536,
              distance: 'Cosine'
            }
          });
        }
      } catch (dbError) {
        // Continue with upsert even if collection check fails
        logger.warn({ error: dbError }, 'Collection check failed, continuing with upsert');
      }

      await this.qdrant.upsert(CONFIG.qdrant.collectionName, {
        points: [point]
      });

      return {
        content: [
          {
            type: 'text',
            text: `✅ Successfully stored ${kind} in memory`
          }
        ]
      };
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `❌ Storage failed: ${error instanceof Error ? error.message : 'Unknown error'}`
          }
        ]
      };
    }
  }

  private async handleMemoryFind(args: any) {
    const { query, limit = 10 } = args;

    // Generate embedding for query
    const queryEmbedding = await this.generateEmbedding(query);

    // Search in Qdrant
    const searchResult = await this.qdrant.search(CONFIG.qdrant.collectionName, {
      vector: queryEmbedding,
      limit,
      with_payload: true
    });

    const results = searchResult.map(hit => ({
      content: hit.payload?.content || '',
      kind: hit.payload?.kind || '',
      score: hit.score || 0,
      created_at: hit.payload?.created_at || ''
    }));

    return {
      content: [
        {
          type: 'text',
          text: `Found ${results.length} results:\n\n${results.map((r, i) =>
            `${i + 1}. [${r.kind}] ${r.content} (score: ${r.score.toFixed(3)})`
          ).join('\n\n')}`
        }
      ]
    };
  }

  private async generateEmbedding(text: string): Promise<number[]> {
    logger.debug({ textLength: text.length }, 'Generating OpenAI embedding');

    try {
      const response = await AsyncErrorHandler.retry(
        () => this.openai.embeddings.create({
          model: 'text-embedding-ada-002',
          input: text
        }),
        {
          maxAttempts: 3,
          context: { operation: 'embedding_generation', textLength: text.length }
        }
      );

      const embedding = response.data[0].embedding;
      logger.debug({ embeddingSize: embedding.length }, 'OpenAI embedding generated successfully');
      return embedding;
    } catch (error) {
      logger.error({ error }, '❌ CRITICAL: OpenAI embedding failed');

      // Standardize the error with appropriate categorization
      const errorMessage = error instanceof Error ? error.message : String(error);

      if (errorMessage.includes('invalid api key')) {
        throw new ConfigurationError(
          'Invalid OpenAI API key',
          'OpenAI API key is invalid - please check your API key',
          { originalError: error }
        );
      } else if (errorMessage.includes('insufficient quota')) {
        throw new ExternalApiError(
          'OpenAI API quota exceeded',
          'OpenAI API quota exceeded - please check your billing',
          { originalError: error }
        );
      } else if (errorMessage.includes('rate limit')) {
        throw new ExternalApiError(
          'OpenAI API rate limit exceeded',
          'OpenAI API rate limit exceeded - please try again later',
          { originalError: error }
        );
      } else if (errorMessage.includes('network') || errorMessage.includes('timeout')) {
        throw new NetworkError(
          'Network error accessing OpenAI API',
          'Network error - please check your internet connection',
          { originalError: error }
        );
      } else {
        throw new ExternalApiError(
          `OpenAI API error: ${errorMessage}`,
          'External service error occurred',
          { originalError: error }
        );
      }
    }
  }

  private generateUUID(): string {
    // Generate a proper UUID v4
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    logger.info('Cortex Memory MCP server running on stdio');
  }
}

// Start server
const server = new SimpleCortexServer();
server.run().catch((error) => logger.error({ error }, 'Failed to start server'));