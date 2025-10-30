# File Handle Manager Usage Guide

## Overview

The File Handle Manager utility is designed to prevent EMFILE errors by centralizing file operations with intelligent handle pooling and automatic cleanup. It's particularly optimized for Windows environments where file handle limits are more restrictive.

## Features

- **Handle Pooling**: Manages concurrent file handles with configurable limits
- **Automatic Cleanup**: Cleans up handles when thresholds are reached
- **Windows Optimizations**: Platform-specific optimizations for Windows file systems
- **Graceful Degradation**: Falls back to direct fs operations when needed
- **Monitoring & Statistics**: Track handle usage and operation performance
- **Error Handling**: Comprehensive error handling with detailed error information

## Quick Start

### Basic Usage

```typescript
import {
  readFileManaged,
  writeFileManaged,
  getFileHandleStats,
  cleanupFileHandles,
  setMaxFileHandles
} from '../src/utils/file-handle-manager.js';

// Read a file
const content = await readFileManaged('./data/config.json', {
  encoding: 'utf-8',
  correlationId: 'config-load-001'
});

// Write a file
await writeFileManaged('./output/result.json', content, {
  encoding: 'utf-8',
  correlationId: 'result-save-001'
});

// Get statistics
const stats = getFileHandleStats();
console.log(`Active handles: ${stats.currentHandles}/${stats.maxHandles}`);

// Cleanup handles if needed
await cleanupFileHandles();

// Configure maximum handles
setMaxFileHandles(150);
```

### Advanced Usage with Custom Configuration

```typescript
import { FileHandleManager } from '../src/utils/file-handle-manager.js';

// Create custom manager instance
const fileManager = new FileHandleManager({
  maxHandles: 200,
  cleanupThreshold: 0.75,
  enableWindowsOptimizations: true,
  operationTimeout: 60000,
  enableGracefulDegradation: true,
  logLevel: 'info'
});

// Use the manager
try {
  const data = await fileManager.managedReadFile('./large-file.txt', {
    timeout: 120000,
    correlationId: 'large-read-001'
  });

  await fileManager.managedWriteFile('./processed.txt', processedData, {
    encoding: 'utf-8',
    flag: 'w',
    correlationId: 'large-write-001'
  });
} catch (error) {
  if (error instanceof FileHandleManagerError) {
    console.error(`File operation failed: ${error.message}`);
    console.error(`Operation: ${error.operation}`);
    console.error(`Path: ${error.path}`);
    console.error(`Code: ${error.code}`);
  }
}

// Get detailed statistics
const stats = fileManager.getStats();
console.log('File Handle Manager Statistics:', {
  currentHandles: stats.currentHandles,
  maxHandles: stats.maxHandles,
  totalOperations: stats.totalOperations,
  successfulOperations: stats.successfulOperations,
  failedOperations: stats.failedOperations,
  cleanupCount: stats.cleanupCount,
  degradationCount: stats.degradationCount,
  averageOperationDuration: stats.averageOperationDuration,
  peakHandleCount: stats.peakHandleCount
});

// Cleanup when done
await fileManager.shutdown();
```

## Integration Examples

### Replacing Direct fs Operations

#### Before (Direct fs usage)

```typescript
import { promises as fs } from 'node:fs';

// Problematic code that can cause EMFILE errors
async function processMultipleFiles(filePaths: string[]) {
  const results = [];

  for (const filePath of filePaths) {
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const processed = processContent(content);
      await fs.writeFile(`${filePath}.processed`, processed, 'utf-8');
      results.push(filePath);
    } catch (error) {
      console.error(`Failed to process ${filePath}:`, error);
    }
  }

  return results;
}
```

#### After (With File Handle Manager)

```typescript
import {
  readFileManaged,
  writeFileManaged,
  setMaxFileHandles,
  getFileHandleStats
} from '../src/utils/file-handle-manager.js';

// Safe code with handle management
async function processMultipleFiles(filePaths: string[]) {
  // Configure for batch processing
  setMaxFileHandles(50);

  const results = [];

  for (const filePath of filePaths) {
    try {
      // Read with managed handles
      const content = await readFileManaged(filePath, {
        encoding: 'utf-8',
        correlationId: `process-${filePaths.indexOf(filePath)}`
      });

      // Process content
      const processed = processContent(content);

      // Write with managed handles
      await writeFileManaged(`${filePath}.processed`, processed, {
        encoding: 'utf-8',
        correlationId: `process-${filePaths.indexOf(filePath)}`
      });

      results.push(filePath);

      // Monitor handle usage
      const stats = getFileHandleStats();
      if (stats.currentHandles > stats.maxHandles * 0.8) {
        console.log('Handle usage high, triggering cleanup');
        await cleanupFileHandles();
      }
    } catch (error) {
      console.error(`Failed to process ${filePath}:`, error);
    }
  }

  return results;
}
```

### Test Suite Integration

```typescript
// test/utils/file-test-helper.ts
import { readFileManaged, writeFileManaged } from '../../src/utils/file-handle-manager.js';

export class FileTestHelper {
  private testDataDir: string;

  constructor(testDataDir: string) {
    this.testDataDir = testDataDir;
  }

  async createTestFile(name: string, content: string): Promise<string> {
    const filePath = `${this.testDataDir}/${name}`;
    await writeFileManaged(filePath, content, {
      correlationId: `test-create-${name}`
    });
    return filePath;
  }

  async readTestFile(name: string): Promise<string> {
    const filePath = `${this.testDataDir}/${name}`;
    const content = await readFileManaged(filePath, {
      encoding: 'utf-8',
      correlationId: `test-read-${name}`
    });
    return content as string;
  }

  async cleanup(): Promise<void> {
    // File handle manager handles automatic cleanup
  }
}

// Usage in tests
import { FileTestHelper } from '../utils/file-test-helper.js';

describe('File Processing Tests', () => {
  let helper: FileTestHelper;

  beforeEach(() => {
    helper = new FileTestHelper('./test-data');
  });

  afterEach(async () => {
    await helper.cleanup();
  });

  it('should process files without EMFILE errors', async () => {
    // Create many test files
    const files = [];
    for (let i = 0; i < 100; i++) {
      const filePath = await helper.createTestFile(`test-${i}.txt`, `Content ${i}`);
      files.push(filePath);
    }

    // Process all files
    const results = await processMultipleFiles(files);

    expect(results).toHaveLength(files.length);
  });
});
```

### Configuration Service Integration

```typescript
// src/services/configuration.service.ts
import { readFileManaged, writeFileManaged } from '../utils/file-handle-manager.js';

export class ConfigurationService {
  private configPath: string;

  constructor(configPath: string) {
    this.configPath = configPath;
  }

  async loadConfiguration(): Promise<Configuration> {
    try {
      const content = await readFileManaged(this.configPath, {
        encoding: 'utf-8',
        correlationId: 'config-load',
        timeout: 10000
      });

      return JSON.parse(content as string);
    } catch (error) {
      if (error instanceof FileHandleManagerError) {
        throw new ConfigurationError(
          `Failed to load configuration: ${error.message}`,
          { cause: error }
        );
      }
      throw error;
    }
  }

  async saveConfiguration(config: Configuration): Promise<void> {
    try {
      const content = JSON.stringify(config, null, 2);
      await writeFileManaged(this.configPath, content, {
        encoding: 'utf-8',
        correlationId: 'config-save',
        timeout: 10000
      });
    } catch (error) {
      if (error instanceof FileHandleManagerError) {
        throw new ConfigurationError(
          `Failed to save configuration: ${error.message}`,
          { cause: error }
        );
      }
      throw error;
    }
  }
}
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxHandles` | `number` | `100` (Windows), `1000` (other) | Maximum concurrent file handles |
| `cleanupThreshold` | `number` | `0.8` | Percentage threshold to trigger cleanup |
| `enableWindowsOptimizations` | `boolean` | `true` on Windows | Enable Windows-specific optimizations |
| `operationTimeout` | `number` | `30000` | Default timeout for operations (ms) |
| `enableGracefulDegradation` | `boolean` | `true` | Fall back to direct fs operations on errors |
| `logLevel` | `'debug' \| 'info' \| 'warn' \| 'error'` | `'debug'` | Logging level for operations |

## Error Handling

The File Handle Manager provides comprehensive error handling:

```typescript
import { FileHandleManagerError } from '../src/utils/file-handle-manager.js';

try {
  await readFileManaged('./non-existent-file.txt');
} catch (error) {
  if (error instanceof FileHandleManagerError) {
    console.error('File Handle Manager Error:');
    console.error(`Message: ${error.message}`);
    console.error(`Code: ${error.code}`);
    console.error(`Path: ${error.path}`);
    console.error(`Operation: ${error.operation}`);

    // Access original error
    if (error.cause) {
      console.error(`Original error: ${error.cause.message}`);
    }
  }
}
```

### Common Error Codes

- `EMFILE`: Too many open files (handle limit exceeded)
- `ENOENT`: File or directory not found
- `EACCES`: Permission denied
- `TIMEOUT`: Operation timed out
- `INVALID_CONFIG`: Invalid configuration parameter

## Performance Monitoring

Monitor handle usage and performance:

```typescript
import { getFileHandleStats } from '../src/utils/file-handle-manager.js';

// Monitor statistics
function logHandleStats() {
  const stats = getFileHandleStats();

  console.log('File Handle Manager Statistics:');
  console.log(`  Current handles: ${stats.currentHandles}/${stats.maxHandles}`);
  console.log(`  Total operations: ${stats.totalOperations}`);
  console.log(`  Success rate: ${((stats.successfulOperations / stats.totalOperations) * 100).toFixed(2)}%`);
  console.log(`  Average duration: ${stats.averageOperationDuration.toFixed(2)}ms`);
  console.log(`  Peak handles: ${stats.peakHandleCount}`);
  console.log(`  Cleanup count: ${stats.cleanupCount}`);
  console.log(`  Degradation count: ${stats.degradationCount}`);
}

// Monitor periodically
setInterval(logHandleStats, 30000); // Every 30 seconds
```

## Best Practices

### 1. Configure Appropriate Limits

```typescript
// For high-throughput applications
setMaxFileHandles(200);

// For memory-constrained environments
setMaxFileHandles(25);

// For batch processing
const batchManager = new FileHandleManager({
  maxHandles: 10,
  cleanupThreshold: 0.6
});
```

### 2. Use Correlation IDs

```typescript
import { generateCorrelationId } from '../src/utils/correlation-id.js';

const correlationId = generateCorrelationId();

await readFileManaged('./data.json', {
  correlationId,
  timeout: 15000
});
```

### 3. Monitor Handle Usage

```typescript
// Add to your monitoring system
function checkHandleHealth() {
  const stats = getFileHandleStats();
  const usageRatio = stats.currentHandles / stats.maxHandles;

  if (usageRatio > 0.9) {
    console.warn('High handle usage detected:', usageRatio);
  }

  if (stats.failedOperations > stats.totalOperations * 0.1) {
    console.error('High failure rate detected');
  }
}
```

### 4. Graceful Shutdown

```typescript
import { fileHandleManager } from '../src/utils/file-handle-manager.js';

process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  await fileHandleManager.shutdown();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('Shutting down gracefully...');
  await fileHandleManager.shutdown();
  process.exit(0);
});
```

## Migration Guide

### Step 1: Identify File Operations

Search for direct `fs` usage:

```bash
grep -r "fs\." src/
grep -r "readFile\|writeFile" src/
grep -r "readFileSync\|writeFileSync" src/
```

### Step 2: Replace with Managed Operations

```typescript
// Before
import { promises as fs } from 'node:fs';
const content = await fs.readFile('./data.json', 'utf-8');

// After
import { readFileManaged } from '../utils/file-handle-manager.js';
const content = await readFileManaged('./data.json', { encoding: 'utf-8' });
```

### Step 3: Add Error Handling

```typescript
// Before
try {
  const data = await fs.readFile('./config.json');
} catch (error) {
  console.error('Failed to read config:', error);
}

// After
try {
  const data = await readFileManaged('./config.json');
} catch (error) {
  if (error instanceof FileHandleManagerError) {
    console.error(`File operation failed: ${error.code} - ${error.message}`);
  } else {
    console.error('Unexpected error:', error);
  }
}
```

### Step 4: Configure for Your Environment

```typescript
// In your application initialization
import { setMaxFileHandles } from '../utils/file-handle-manager.js';

// Configure based on your needs
if (process.env.NODE_ENV === 'production') {
  setMaxFileHandles(150);
} else {
  setMaxFileHandles(50);
}
```

## Troubleshooting

### EMFILE Errors Still Occur

1. **Increase handle limit**:
   ```typescript
   setMaxFileHandles(200);
   ```

2. **Lower cleanup threshold**:
   ```typescript
   const manager = new FileHandleManager({
     cleanupThreshold: 0.6
   });
   ```

3. **Check for handle leaks**:
   ```typescript
   const stats = getFileHandleStats();
   console.log('Active handles:', stats.currentHandles);
   ```

### Performance Issues

1. **Monitor operation duration**:
   ```typescript
   const stats = getFileHandleStats();
   if (stats.averageOperationDuration > 5000) {
     console.warn('Slow file operations detected');
   }
   ```

2. **Check degradation count**:
   ```typescript
   if (stats.degradationCount > 0) {
     console.warn(`Graceful degradation used ${stats.degradationCount} times`);
   }
   ```

### Memory Issues

1. **Enable regular cleanup**:
   ```typescript
   setInterval(cleanupFileHandles, 60000); // Every minute
   ```

2. **Monitor handle growth**:
   ```typescript
   setInterval(() => {
     const stats = getFileHandleStats();
     if (stats.currentHandles > stats.maxHandles * 0.8) {
       console.warn('Handle usage approaching limit');
     }
   }, 30000);
   ```