#!/usr/bin/env node
// Test script to check if imports are causing the hang

import { config } from 'dotenv';
import { Server } from '@modelcontextprotocol/sdk/server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

console.error('Step 1: Basic imports successful');

// Test importing logger
try {
  const { logger } = await import('./dist/utils/logger.js');
  console.error('Step 2: Logger import successful');
} catch (error) {
  console.error('Step 2: Logger import failed:', error);
  process.exit(1);
}

// Test importing env config
try {
  const { loadEnv } = await import('./dist/config/env.js');
  console.error('Step 3: Env config import successful');
} catch (error) {
  console.error('Step 3: Env config import failed:', error);
  process.exit(1);
}

// Test loadEnv function
try {
  const originalConsoleLog = console.log;
  console.log = (...args) => console.error(...args);
  config();
  console.log = originalConsoleLog;

  const { loadEnv } = await import('./dist/config/env.js');
  loadEnv();
  console.error('Step 4: loadEnv() successful');
} catch (error) {
  console.error('Step 4: loadEnv() failed:', error);
  process.exit(1);
}

// Test importing services one by one
try {
  const { AuthService } = await import('./dist/services/auth/auth-service.js');
  console.error('Step 5: AuthService import successful');
} catch (error) {
  console.error('Step 5: AuthService import failed:', error);
  process.exit(1);
}

try {
  const { AuthorizationService } = await import('./dist/services/auth/authorization-service.js');
  console.error('Step 6: AuthorizationService import successful');
} catch (error) {
  console.error('Step 6: AuthorizationService import failed:', error);
  process.exit(1);
}

try {
  const { AuditService } = await import('./dist/services/audit/audit-service.js');
  console.error('Step 7: AuditService import successful');
} catch (error) {
  console.error('Step 7: AuditService import failed:', error);
  process.exit(1);
}

// Test simple MCP server setup
const server = new Server(
  { name: 'test-cortex', version: '1.0.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: 'test',
    description: 'Test tool',
    inputSchema: {
      type: 'object',
      properties: { message: { type: 'string' } },
      required: ['message']
    }
  }]
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  if (name === 'test') {
    return {
      content: [{
        type: 'text',
        text: `Test: ${args.message}`
      }]
    };
  }
  throw new Error(`Unknown tool: ${name}`);
});

async function main() {
  console.error('Step 8: Starting MCP server...');
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Step 9: MCP server connected successfully');
}

main().catch((error) => {
  console.error('Server failed to start:', error);
  process.exit(1);
});