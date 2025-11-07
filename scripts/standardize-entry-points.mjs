#!/usr/bin/env node

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Entry point standardization script
 */

console.log('🎯 Standardizing entry points...');

// 1. Create standardized server infrastructure
try {
  console.log('\n1️⃣  Creating server infrastructure...');

  const directories = [
    'src/server',
    'src/server/tools',
    'src/server/middleware',
    'src/server/startup',
    'src/server/config'
  ];

  directories.forEach(dir => {
    const fullPath = join(__dirname, '..', dir);
    if (!existsSync(fullPath)) {
      mkdirSync(fullPath, { recursive: true });
      console.log(`📁 Created: ${dir}`);
    }
  });

  // Create core MCP server
  const mcpServerContent = `import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError
} from '@modelcontextprotocol/sdk/types.js';

import { ToolRegistry } from './tools/tool-registry.js';
import { createServerConfig } from './config/server-config.js';
import { ServiceOrchestrator } from './startup/service-orchestrator.js';
import { logger } from '../utils/logger.js';

/**
 * Core MCP Server implementation
 */
export class MCPServer {
  private server: Server;
  private transport: StdioServerTransport | null = null;
  private toolRegistry: ToolRegistry;
  private serviceOrchestrator: ServiceOrchestrator;
  private config = createServerConfig();

  constructor() {
    this.server = new Server(
      {
        name: 'cortex-memory-mcp',
        version: '2.0.1',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.toolRegistry = new ToolRegistry();
    this.serviceOrchestrator = new ServiceOrchestrator(this.config);

    this.setupHandlers();
    this.setupErrorHandling();
  }

  private setupHandlers(): void {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: this.toolRegistry.getAll().map(tool => tool.definition),
      };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      const tool = this.toolRegistry.get(name);
      if (!tool) {
        throw new McpError(
          ErrorCode.MethodNotFound,
          \`Unknown tool: \${name}\`
        );
      }

      try {
        return await tool.execute(args);
      } catch (error) {
        logger.error({ tool: name, error: error.message }, 'Tool execution failed');
        throw error;
      }
    });
  }

  private setupErrorHandling(): void {
    process.on('uncaughtException', (error) => {
      logger.error({ error: error.message, stack: error.stack }, 'Uncaught exception');
      this.shutdown();
    });

    process.on('unhandledRejection', (reason, promise) => {
      logger.error({ reason, promise }, 'Unhandled rejection');
      this.shutdown();
    });

    process.on('SIGINT', () => {
      logger.info('Received SIGINT, shutting down gracefully');
      this.shutdown();
    });

    process.on('SIGTERM', () => {
      logger.info('Received SIGTERM, shutting down gracefully');
      this.shutdown();
    });
  }

  async start(): Promise<void> {
    try {
      // Initialize services
      await this.serviceOrchestrator.initialize();

      // Register tools
      await this.toolRegistry.loadTools();

      // Create transport
      this.transport = new StdioServerTransport();

      // Connect server
      await this.server.connect(this.transport);

      logger.info('🚀 Cortex Memory MCP Server started successfully');
    } catch (error) {
      logger.error({ error: error.message }, 'Failed to start server');
      throw error;
    }
  }

  async shutdown(): Promise<void> {
    try {
      logger.info('Shutting down server...');

      await this.serviceOrchestrator.shutdown();

      if (this.transport) {
        await this.server.close();
      }

      logger.info('Server shutdown completed');
      process.exit(0);
    } catch (error) {
      logger.error({ error: error.message }, 'Error during shutdown');
      process.exit(1);
    }
  }
}
`;

  const serverPath = join(__dirname, '..', 'src', 'server', 'mcp-server.ts');
  writeFileSync(serverPath, mcpServerContent);
  console.log('✅ Core MCP server created');

} catch (error) {
  console.log('⚠️  Server infrastructure creation failed:', error.message);
}

// 2. Create tool registry
try {
  console.log('\n2️⃣  Creating tool registry...');

  const toolRegistryContent = `import { Tool } from './tool.interface.js';
import { MemoryStoreTool } from './memory-store.tool.js';
import { MemoryFindTool } from './memory-find.tool.js';
import { SystemStatusTool } from './system-status.tool.js';
import { AIStatusTool } from './ai-status.tool.js';
import { logger } from '../../utils/logger.js';

/**
 * Registry for managing MCP tools
 */
export class ToolRegistry {
  private tools = new Map<string, Tool>();

  async loadTools(): Promise<void> {
    const tools = [
      new MemoryStoreTool(),
      new MemoryFindTool(),
      new SystemStatusTool(),
      new AIStatusTool(),
    ];

    for (const tool of tools) {
      this.register(tool);
      logger.info({ tool: tool.name }, 'Tool registered');
    }

    logger.info({ count: this.tools.size }, 'All tools loaded');
  }

  register(tool: Tool): void {
    if (this.tools.has(tool.name)) {
      throw new Error(\`Tool already registered: \${tool.name}\`);
    }
    this.tools.set(tool.name, tool);
  }

  get(name: string): Tool | undefined {
    return this.tools.get(name);
  }

  getAll(): Tool[] {
    return Array.from(this.tools.values());
  }

  has(name: string): boolean {
    return this.tools.has(name);
  }

  unregister(name: string): boolean {
    return this.tools.delete(name);
  }

  clear(): void {
    this.tools.clear();
  }

  getNames(): string[] {
    return Array.from(this.tools.keys());
  }
}
`;

  const registryPath = join(__dirname, '..', 'src', 'server', 'tools', 'tool-registry.ts');
  writeFileSync(registryPath, toolRegistryContent);
  console.log('✅ Tool registry created');

} catch (error) {
  console.log('⚠️  Tool registry creation failed:', error.message);
}

// 3. Create tool interface
try {
  console.log('\n3️⃣  Creating tool interface...');

  const toolInterfaceContent = `import { Tool } from '@modelcontextprotocol/sdk/types.js';

/**
 * Base interface for MCP tools
 */
export interface Tool {
  readonly name: string;
  readonly definition: Tool;
  execute(args: any): Promise<any>;
}

/**
 * Abstract base class for tools
 */
export abstract class BaseTool implements Tool {
  abstract readonly name: string;
  abstract readonly definition: Tool;

  abstract execute(args: any): Promise<any>;

  protected validateArgs(args: any, schema: any): void {
    // Basic validation implementation
    if (!args || typeof args !== 'object') {
      throw new Error('Invalid arguments: must be an object');
    }
  }

  protected createResponse(content: any): any {
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(content, null, 2),
        },
      ],
    };
  }
}
`;

  const interfacePath = join(__dirname, '..', 'src', 'server', 'tools', 'tool.interface.ts');
  writeFileSync(interfacePath, toolInterfaceContent);
  console.log('✅ Tool interface created');

} catch (error) {
  console.log('⚠️  Tool interface creation failed:', error.message);
}

// 4. Create standardized entry points
try {
  console.log('\n4️⃣  Creating standardized entry points...');

  // Production entry point
  const productionEntry = `#!/usr/bin/env node

import { MCPServer } from './server/mcp-server.js';
import { logger } from './utils/logger.js';

/**
 * Production entry point for Cortex Memory MCP Server
 */
async function main(): Promise<void> {
  try {
    const server = new MCPServer();
    await server.start();
  } catch (error) {
    logger.error({ error: error.message }, 'Production server failed to start');
    process.exit(1);
  }
}

main();
`;

  const productionPath = join(__dirname, '..', 'src', 'index.ts');
  writeFileSync(productionPath, productionEntry);
  console.log('✅ Production entry point created');

  // Development entry point
  const devEntry = `#!/usr/bin/env node

import { MCPServer } from './server/mcp-server.js';
import { logger } from './utils/logger.js';

/**
 * Development entry point for Cortex Memory MCP Server
 */
async function main(): Promise<void> {
  try {
    // Enable debug logging in development
    process.env.DEBUG = 'cortex:*';

    logger.info('🛠️  Starting development server...');

    const server = new MCPServer();
    await server.start();

    logger.info('✅ Development server started successfully');
  } catch (error) {
    logger.error({ error: error.message }, 'Development server failed to start');
    process.exit(1);
  }
}

main();
`;

  const devPath = join(__dirname, '..', 'src', 'index.dev.ts');
  writeFileSync(devPath, devEntry);
  console.log('✅ Development entry point created');

  // Test entry point
  const testEntry = `#!/usr/bin/env node

import { MCPServer } from './server/mcp-server.js';
import { logger } from './utils/logger.js';

/**
 * Test entry point for Cortex Memory MCP Server
 */
async function main(): Promise<void> {
  try {
    // Test configuration
    process.env.NODE_ENV = 'test';
    process.env.DEBUG = 'cortex:*';

    logger.info('🧪 Starting test server...');

    const server = new MCPServer();
    await server.start();

    logger.info('✅ Test server started successfully');
  } catch (error) {
    logger.error({ error: error.message }, 'Test server failed to start');
    process.exit(1);
  }
}

main();
`;

  const testPath = join(__dirname, '..', 'src', 'index.test.ts');
  writeFileSync(testPath, testEntry);
  console.log('✅ Test entry point created');

} catch (error) {
  console.log('⚠️  Entry point creation failed:', error.message);
}

// 5. Update package.json scripts
try {
  console.log('\n5️⃣  Updating package.json scripts...');

  const packagePath = join(__dirname, '..', 'package.json');
  const packageJson = JSON.parse(readFileSync(packagePath, 'utf-8'));

  // Update main entry point
  packageJson.main = 'dist/index.js';

  // Update bin scripts
  packageJson.bin = {
    'cortex': 'dist/index.js',
    'cortex-silent': 'dist/index.js',
    'cortex-dev': 'dist/index.dev.js',
    'cortex-test': 'dist/index.test.js'
  };

  // Update scripts
  packageJson.scripts['start'] = 'NODE_OPTIONS="--max-old-space-size=4096 --expose-gc" node dist/index.js';
  packageJson.scripts['start:dev'] = 'NODE_OPTIONS="--max-old-space-size=4096 --expose-gc" node dist/index.dev.js';
  packageJson.scripts['start:test'] = 'NODE_ENV=test node dist/index.test.js';

  writeFileSync(packagePath, JSON.stringify(packageJson, null, 2));
  console.log('✅ Package.json scripts updated');

} catch (error) {
  console.log('⚠️  Package.json update failed:', error.message);
}

// 6. Create migration script
try {
  console.log('\n6️⃣  Creating migration script...');

  const migrationScript = `#!/usr/bin/env node

import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';

/**
 * Migration script for transitioning to new entry points
 */

console.log('🔄 Migrating to new entry point structure...');

// List of files to be deprecated
const deprecatedFiles = [
  'src/index-simplified.ts',
  'src/index-working.ts',
  'src/index-high-level-api.ts',
  'src/silent-mcp-entry.ts'
];

// Create deprecation warnings
deprecatedFiles.forEach(file => {
  const filePath = join(__dirname, '..', file);
  if (existsSync(filePath)) {
    const content = readFileSync(filePath, 'utf-8');
    const deprecatedContent = \`// ⚠️  DEPRECATED: This file is deprecated and will be removed in v3.0.0
// Please use the new standardized entry points:
// - src/index.ts (production)
// - src/index.dev.ts (development)
// - src/index.test.ts (testing)

\${content}\`;

    writeFileSync(filePath, deprecatedContent);
    console.log(\`📝 Added deprecation warning to \${file}\`);
  }
});

console.log('✅ Migration completed');
console.log('');
console.log('📋 New entry points:');
console.log('  src/index.ts        - Production server');
console.log('  src/index.dev.ts    - Development server');
console.log('  src/index.test.ts   - Test server');
console.log('');
console.log('🗑️  Files to remove after migration:');
deprecatedFiles.forEach(file => console.log(\`  \${file}\`));
`;

  const migrationPath = join(__dirname, '..', 'scripts', 'migrate-entry-points.mjs');
  writeFileSync(migrationPath, migrationScript);
  console.log('✅ Migration script created');

} catch (error) {
  console.log('⚠️  Migration script creation failed:', error.message);
}

console.log('\n🎉 Entry point standardization completed!');
console.log('\n📋 Next steps:');
console.log('1. Run: node scripts/migrate-entry-points.mjs');
console.log('2. Run: npm run build:optimized');
console.log('3. Test new entry points: npm start, npm run start:dev');
console.log('4. Remove deprecated files after testing');

console.log('\n✨ Benefits:');
console.log('- Clear separation of environments');
console.log('- Reduced code duplication');
console.log('- Easier maintenance');
console.log('- Better testability');