#!/usr/bin/env node
import { config } from 'dotenv';
import { Server } from '@modelcontextprotocol/sdk/server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { memoryStore } from './services/memory-store.js';
import { smartMemoryFind } from './services/smart-find.js';
import { logger } from './utils/logger.js';
import { loadEnv } from './config/env.js';
import { dbPool } from './db/pool.js';

// Load environment variables from .env file
config();

loadEnv();

const server = new Server({ name: 'cortex', version: '1.0.0' }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'memory_store',
      description: `Store, update, or delete knowledge items. Specify 'kind' (section, decision, issue, todo, runbook, change, release_note, ddl, pr_context, entity, relation, observation, incident, release, risk, assumption) and 'data' object. For updates, include 'id'. For deletes, set operation="delete". Each item needs 'scope' with project name for isolation. Returns status and autonomous_context with user_message_suggestion.`,
      inputSchema: {
        type: 'object',
        properties: {
          items: {
            type: 'array',
            items: { type: 'object' },
            description: 'Array of knowledge items to store. Each item must have: kind, scope, data fields.',
          },
        },
        required: ['items'],
      },
    },
    {
      name: 'memory_find',
      description: `Search knowledge with confidence scoring and smart auto-correction. Use query string, optional scope filter (project, branch, org), and optional types array. Returns hits with confidence scores and autonomous_context. Modes: auto (smart routing), fast (exact match), deep (fuzzy).`,
      inputSchema: {
        type: 'object',
        properties: {
          query: {
            type: 'string',
            description: 'Search query string. Supports full-text search operators in fast/auto modes.',
          },
          scope: {
            type: 'object',
            description: 'Optional scope filter: {project, branch, org}',
            properties: {
              project: { type: 'string' },
              branch: { type: 'string' },
              org: { type: 'string' },
            },
          },
          types: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional: Filter by knowledge types like ["decision", "issue"]',
          },
          mode: {
            type: 'string',
            enum: ['auto', 'fast', 'deep'],
            description: 'Search mode: auto (smart), fast (exact), deep (fuzzy). Default: auto',
          },
        },
        required: ['query'],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'memory_store': {
        const result = await memoryStore(args?.items as any[]);
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      }
      case 'memory_find': {
        const result = await smartMemoryFind({
          query: args?.query as string,
          scope: args?.scope as Record<string, unknown>,
          types: args?.types as string[],
          mode: (args?.mode as 'auto' | 'fast' | 'deep') || 'auto',
        });
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      }
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    logger.error({ error, tool: name, args }, 'Tool execution failed');
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return {
      content: [{ type: 'text', text: JSON.stringify({ error: errorMessage }, null, 2) }],
      isError: true,
    };
  }
});

async function runServer() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info('Cortex Memory MCP Server running on stdio');
}

// Graceful shutdown
process.on('SIGINT', async () => {
  logger.info('Shutting down Cortex Memory MCP Server...');
  await dbPool.shutdown();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  logger.info('Shutting down Cortex Memory MCP Server...');
  await dbPool.shutdown();
  process.exit(0);
});

runServer().catch((error) => {
  logger.error({ error }, 'Failed to start server');
  process.exit(1);
});