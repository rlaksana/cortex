# Entry Point Standardization Guide

This document describes the standardized and optimized dual entry point configuration for the Cortex Memory MCP Server.

## Overview

The Cortex Memory MCP Server now features a standardized dual entry point system that eliminates circular dependencies, provides consistent initialization patterns, and ensures proper error handling and graceful shutdown for both entry points.

## Architecture

### 1. Entry Point Factory (`src/entry-point-factory.ts`)

The factory module serves as the core initialization component that:

- **Eliminates Circular Dependencies**: Provides a centralized way to create server instances
- **Consistent Initialization**: Ensures both entry points use the same initialization patterns
- **Enhanced Error Handling**: Implements comprehensive error handling and recovery
- **Flexible Configuration**: Supports both silent and verbose modes
- **Graceful Shutdown**: Properly manages resources and cleanup

#### Key Features

- **McpServerFactory Class**: Main factory class for creating server instances
- **EntryPointLogger**: Configurable logger with silent mode support
- **Standardized Tool Registration**: Consistent tool schemas and handlers
- **Health Status Monitoring**: Built-in system health checking
- **Qdrant Integration**: Seamless fallback between vector database and in-memory storage

### 2. Main Entry Point (`src/index.ts`)

The main entry point provides:

- **Verbose Logging**: Detailed startup and operational logs
- **Development Mode**: Full console output for debugging
- **Standard Configuration**: Uses factory with verbose settings
- **Comprehensive Error Reporting**: Detailed error messages and stack traces

#### Usage

```bash
# Start with verbose logging
npm start
# or
node dist/index.js

# With custom log level
LOG_LEVEL=debug npm start
```

### 3. Silent Entry Point (`src/silent-mcp-entry.ts`)

The silent entry point provides:

- **Silent Operation**: Suppresses all console output for clean MCP transport
- **Debug Mode**: Optional debug mode with `--debug` flag or `CORTEX_SILENT_DEBUG=true`
- **Log Capture**: Captures logs internally for debugging purposes
- **Enhanced Error Handling**: Restores console output on critical errors
- **Production Ready**: Optimized for production MCP deployments

#### Usage

```bash
# Silent mode (default)
npm run start:silent
# or
node dist/silent-mcp-entry.js

# Debug mode
node dist/silent-mcp-entry.js --debug
# or
CORTEX_SILENT_DEBUG=true node dist/silent-mcp-entry.js
```

## Configuration

### Environment Variables

- `LOG_LEVEL`: Logging level ('error', 'warn', 'info', 'debug')
- `CORTEX_SILENT_DEBUG`: Enable debug mode for silent entry point
- `QDRANT_URL`: Qdrant database URL
- `QDRANT_API_KEY`: Qdrant database API key
- `QDRANT_COLLECTION_NAME`: Collection name for storage

### Factory Configuration Options

```typescript
interface ServerConfig {
  name: string;                    // Server name
  version: string;                 // Server version
  logger: {
    level: 'error' | 'warn' | 'info' | 'debug';
    silent: boolean;              // Silent mode flag
    prefix?: string;              // Log prefix
  };
  collectionName?: string;         // Qdrant collection name
  qdrantUrl?: string;             // Qdrant URL
  qdrantApiKey?: string;          // Qdrant API key
}
```

## Build Configuration

### TypeScript Configuration

The `tsconfig.build.json` includes all necessary files for compilation:

```json
{
  "include": [
    "src/entry-point-factory.ts",
    "src/index.ts",
    "src/silent-mcp-entry.ts"
  ]
}
```

### Package.json Scripts

```json
{
  "scripts": {
    "start": "node dist/index.js",
    "start:silent": "node dist/silent-mcp-entry.js",
    "start:raw": "node dist/index.js",
    "dev": "node dist/index.js"
  },
  "bin": {
    "cortex": "dist/silent-mcp-entry.js",
    "cortex-silent": "dist/silent-mcp-entry.js"
  },
  "main": "dist/index.js"
}
```

## Error Handling

### Main Entry Point

- **Comprehensive Error Reporting**: Full stack traces and error details
- **Graceful Shutdown**: Proper resource cleanup on errors
- **Process Signal Handling**: SIGINT, SIGTERM, uncaught exceptions
- **Console Output**: All errors and warnings are logged to console

### Silent Entry Point

- **Error Recovery**: Restores console output on errors
- **Debug Mode**: Optional debugging with captured logs
- **Critical Error Handling**: Always restores console for uncaught exceptions
- **Log Capture**: Captures logs internally for troubleshooting

## Testing

### Entry Point Verification

Run the test script to verify both entry points work correctly:

```bash
# Compile and test entry points
npx tsc src/entry-point-factory.ts src/index.ts src/silent-mcp-entry.ts --outDir dist --target es2022 --module esnext --moduleResolution node --esModuleInterop --allowSyntheticDefaultImports --skipLibCheck

# Run verification test
node test-entry-points.js
```

### Type Checking

```bash
# Check build configuration
npm run type-check:build

# Check all configurations
npm run type-check:all
```

## Migration Guide

### From Old Entry Points

1. **Update Imports**: Replace direct imports with factory usage
2. **Configuration**: Use factory configuration instead of direct settings
3. **Error Handling**: Rely on factory error handling patterns
4. **Logging**: Use factory logger instead of console directly

### Example Migration

**Before:**
```typescript
import { server } from './index.js';
await server.connect(new StdioServerTransport());
```

**After:**
```typescript
import { createMcpServer } from './entry-point-factory.js';
const server = createMcpServer({ logger: { level: 'info', silent: false } });
await server.initialize();
await server.startTransport();
```

## Benefits

### 1. Eliminated Circular Dependencies
- Factory pattern breaks circular import chains
- Clean module dependency structure
- Improved compilation performance

### 2. Consistent Initialization
- Both entry points use same initialization logic
- Consistent error handling and recovery
- Unified configuration management

### 3. Enhanced Error Handling
- Comprehensive error catching and reporting
- Graceful shutdown in all scenarios
- Debug mode for troubleshooting

### 4. Production Ready
- Silent mode for clean MCP transport
- Configurable logging levels
- Resource management and cleanup

### 5. Maintainable Code
- Centralized server creation logic
- Reduced code duplication
- Clear separation of concerns

## Troubleshooting

### Common Issues

1. **Compilation Errors**: Ensure all entry point files are included in `tsconfig.build.json`
2. **Import Errors**: Check that factory exports are properly imported
3. **Runtime Errors**: Verify configuration options are correct
4. **Silent Mode Issues**: Use debug mode to troubleshoot silent entry point

### Debug Mode

Enable debug mode for troubleshooting:

```bash
# Main entry point debug
LOG_LEVEL=debug node dist/index.js

# Silent entry point debug
node dist/silent-mcp-entry.js --debug
# or
CORTEX_SILENT_DEBUG=true node dist/silent-mcp-entry.js
```

## Future Enhancements

### Planned Improvements

1. **Configuration Validation**: Runtime configuration validation
2. **Metrics Integration**: Built-in metrics collection
3. **Health Endpoints**: HTTP health check endpoints
4. **Dynamic Reconfiguration**: Runtime configuration updates
5. **Advanced Logging**: Structured logging with correlation IDs

### Extensibility

The factory pattern makes it easy to:

- Add new entry points
- Implement custom initialization logic
- Extend server configuration options
- Add new tool registration patterns
- Implement custom error handling strategies