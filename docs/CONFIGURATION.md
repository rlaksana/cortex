# Configuration Guide

## Overview

Cortex Memory MCP Server uses a comprehensive configuration system that supports multiple environments, validation, and runtime configuration changes. This guide covers all available configuration options and best practices.

## Configuration Files

### 1. Environment Variables (.env)

The primary configuration method is through environment variables. Copy `.env.example` to `.env` and customize:

```bash
# Required Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/cortex_memory
QDRANT_URL=http://localhost:6333
OPENAI_API_KEY=your-openai-api-key

# Application Settings
NODE_ENV=development                    # development, staging, production
LOG_LEVEL=info                        # error, warn, info, debug
PORT=3000                             # Server port

# PostgreSQL Configuration
DATABASE_URL=postgresql://user:pass@host:5432/dbname
DB_POOL_SIZE=10                       # Connection pool size
DB_TIMEOUT=30000                      # Connection timeout (ms)
DB_IDLE_TIMEOUT=30000                 # Idle timeout (ms)
DB_MAX_CLIENTS=20                     # Maximum concurrent clients

# Qdrant Configuration
QDRANT_URL=http://localhost:6333
QDRANT_API_KEY=                       # Optional API key
QDRANT_COLLECTION_NAME=cortex-memory
QDRANT_MAX_CONNECTIONS=10             # Max concurrent connections
QDRANT_TIMEOUT=30000                  # Connection timeout (ms)
QDRANT_RETRY_ATTEMPTS=3               # Max retry attempts

# Vector Configuration
VECTOR_SIZE=1536                      # Embedding dimensions
VECTOR_DISTANCE=Cosine                # Distance metric: Cosine, Euclidean, Dot
SIMILARITY_THRESHOLD=0.7              # Default similarity threshold
DUPLICATE_THRESHOLD=0.85              # Duplicate detection threshold

# OpenAI Configuration
OPENAI_API_KEY=sk-...                 # Your OpenAI API key
EMBEDDING_MODEL=text-embedding-ada-002 # Embedding model
OPENAI_MAX_RETRIES=3                  # Max API retries
OPENAI_TIMEOUT=30000                  # API timeout (ms)
OPENAI_BATCH_SIZE=10                  # Embedding batch size

# Search Configuration
SEARCH_LIMIT=50                       # Default search results limit
SEARCH_MAX_LIMIT=100                  # Maximum allowed results
SEARCH_MODE=auto                      # auto, fast, deep
SEARCH_TIMEOUT=10000                  # Search timeout (ms)
ENABLE_CACHE=true                     # Enable search caching
CACHE_TTL=3600                        # Cache TTL (seconds)
CACHE_MAX_SIZE=1000                   # Max cached items

# Similarity Service Configuration
SIMILARITY_ENABLED=true               # Enable similarity detection
SIMILARITY_MAX_RESULTS=10             # Max similar items to return
SIMILARITY_WEIGHT_CONTENT=0.5         # Content similarity weight
SIMILARITY_WEIGHT_TITLE=0.2           # Title similarity weight
SIMILARITY_WEIGHT_KIND=0.1            # Kind matching weight
SIMILARITY_WEIGHT_SCOPE=0.2           # Scope similarity weight

# Authentication & Security
API_KEY_ENABLED=false                 # Enable API key authentication
API_KEY_HEADER=X-API-Key              # API key header name
JWT_SECRET=                           # JWT secret (if JWT enabled)
RATE_LIMIT_ENABLED=true               # Enable rate limiting
RATE_LIMIT_REQUESTS=100               # Requests per minute
RATE_LIMIT_BURST=200                  # Burst limit

# Monitoring & Logging
ENABLE_METRICS=true                   # Enable metrics collection
METRICS_PORT=9090                     # Metrics endpoint port
HEALTH_CHECK_ENABLED=true             # Enable health checks
HEALTH_CHECK_INTERVAL=30000           # Health check interval (ms)
LOG_FORMAT=json                       # Log format: json, pretty
LOG_CORRELATION_ID=true               # Enable correlation IDs

# Development Settings
DEBUG=*                               # Debug categories (development)
HOT_RELOAD=true                       # Enable hot reloading
ENABLE_DEV_TOOLS=true                 # Enable development tools
```

### 2. Configuration Profiles

Create specific configuration files for different environments:

#### development.env
```bash
NODE_ENV=development
LOG_LEVEL=debug
DEBUG=cortex:*
HOT_RELOAD=true
ENABLE_DEV_TOOLS=true
ENABLE_CACHE=false                    # Disable cache for development
SIMILARITY_THRESHOLD=0.5              # Lower threshold for testing
```

#### staging.env
```bash
NODE_ENV=staging
LOG_LEVEL=info
ENABLE_CACHE=true
ENABLE_METRICS=true
RATE_LIMIT_ENABLED=true
SEARCH_LIMIT=25                       # Smaller limit for staging
```

#### production.env
```bash
NODE_ENV=production
LOG_LEVEL=warn
ENABLE_CACHE=true
ENABLE_METRICS=true
RATE_LIMIT_ENABLED=true
API_KEY_ENABLED=true                  # Enable security in production
HEALTH_CHECK_ENABLED=true
LOG_FORMAT=json
```

## Configuration Loading

### 1. Environment-Based Loading

```typescript
// src/config/environment.ts
import { config } from 'dotenv';

export class Environment {
  private static instance: Environment;
  private env: NodeJS.ProcessEnv;

  constructor(envFile?: string) {
    if (envFile) {
      config({ path: envFile });
    }
    this.env = process.env;
    this.validate();
  }

  static getInstance(): Environment {
    if (!Environment.instance) {
      const envFile = `.env.${process.env.NODE_ENV || 'development'}`;
      Environment.instance = new Environment(envFile);
    }
    return Environment.instance;
  }

  private validate(): void {
    const required = ['DATABASE_URL', 'QDRANT_URL', 'OPENAI_API_KEY'];
    const missing = required.filter(key => !this.env[key]);

    if (missing.length > 0) {
      throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
    }
  }
}
```

### 2. Configuration Schemas

```typescript
// src/config/schemas.ts
import { z } from 'zod';

export const DatabaseConfigSchema = z.object({
  DATABASE_URL: z.string().url(),
  DB_POOL_SIZE: z.coerce.number().min(1).max(100).default(10),
  DB_TIMEOUT: z.coerce.number().min(1000).default(30000),
  DB_IDLE_TIMEOUT: z.coerce.number().min(5000).default(30000),
});

export const QdrantConfigSchema = z.object({
  QDRANT_URL: z.string().url().default('http://localhost:6333'),
  QDRANT_API_KEY: z.string().optional(),
  QDRANT_COLLECTION_NAME: z.string().default('cortex-memory'),
  QDRANT_MAX_CONNECTIONS: z.coerce.number().min(1).max(50).default(10),
  QDRANT_TIMEOUT: z.coerce.number().min(1000).default(30000),
});

export const SearchConfigSchema = z.object({
  SEARCH_LIMIT: z.coerce.number().min(1).max(1000).default(50),
  SEARCH_MAX_LIMIT: z.coerce.number().min(1).max(10000).default(100),
  SEARCH_MODE: z.enum(['auto', 'fast', 'deep']).default('auto'),
  ENABLE_CACHE: z.coerce.boolean().default(true),
  CACHE_TTL: z.coerce.number().min(60).default(3600),
});
```

## Service-Specific Configuration

### 1. Database Configuration

```typescript
// src/config/database.ts
import { Environment } from './environment.js';
import { DatabaseConfigSchema } from './schemas.js';

const env = Environment.getInstance();
const dbConfig = DatabaseConfigSchema.parse(process.env);

export const DatabaseConfig = {
  postgres: {
    connectionString: dbConfig.DATABASE_URL,
    pool: {
      min: 2,
      max: dbConfig.DB_POOL_SIZE,
      idleTimeoutMillis: dbConfig.DB_IDLE_TIMEOUT,
      connectionTimeoutMillis: dbConfig.DB_TIMEOUT,
      acquireTimeoutMillis: dbConfig.DB_TIMEOUT,
      createTimeoutMillis: 30000,
      destroyTimeoutMillis: 5000,
      reapIntervalMillis: 1000,
      createRetryIntervalMillis: 200
    },
    ssl: env.isProduction() ? { rejectUnauthorized: false } : false
  },

  migrations: {
    tableName: 'migrations',
    directory: './src/db/migrations',
    autoMigrate: env.isProduction()
  }
};
```

### 2. Search Configuration

```typescript
// src/config/search.ts
export const SearchConfig = {
  limits: {
    default: dbConfig.SEARCH_LIMIT,
    maximum: dbConfig.SEARCH_MAX_LIMIT
  },

  strategies: {
    auto: {
      enableSemantic: true,
      enableFullText: true,
      enableHybrid: true,
      fallbackEnabled: true
    },
    fast: {
      enableSemantic: false,
      enableFullText: true,
      enableHybrid: false,
      fallbackEnabled: true
    },
    deep: {
      enableSemantic: true,
      enableFullText: true,
      enableHybrid: true,
      fallbackEnabled: true,
      expandedContext: true,
      maxIterations: 3
    }
  },

  cache: {
    enabled: dbConfig.ENABLE_CACHE,
    ttl: dbConfig.CACHE_TTL * 1000, // Convert to milliseconds
    maxSize: 1000,
    strategy: 'lru' // Least Recently Used
  },

  timeout: dbConfig.SEARCH_TIMEOUT
};
```

### 3. Similarity Configuration

```typescript
// src/config/similarity.ts
export const SimilarityConfig = {
  enabled: dbConfig.SIMILARITY_ENABLED,

  thresholds: {
    duplicate: dbConfig.DUPLICATE_THRESHOLD,
    similarity: dbConfig.SIMILARITY_THRESHOLD,
    high: 0.8,
    medium: 0.6,
    low: 0.4
  },

  weighting: {
    content: dbConfig.SIMILARITY_WEIGHT_CONTENT,
    title: dbConfig.SIMILARITY_WEIGHT_TITLE,
    kind: dbConfig.SIMILARITY_WEIGHT_KIND,
    scope: dbConfig.SIMILARITY_WEIGHT_SCOPE
  },

  limits: {
    maxResults: dbConfig.SIMILARITY_MAX_RESULTS,
    maxCandidates: 100,
    recentDays: 30 // Only consider recent items
  },

  analysis: {
    includeContentAnalysis: true,
    includeMetadataAnalysis: true,
    enableStopWordFiltering: true,
    minWordLength: 3,
    maxTitleLength: 200
  }
};
```

## Runtime Configuration

### 1. Dynamic Configuration Updates

```typescript
// src/config/runtime-config.ts
export class RuntimeConfig {
  private config: Map<string, any> = new Map();
  private watchers: Map<string, Set<(value: any) => void>> = new Map();

  set(key: string, value: any): void {
    const oldValue = this.config.get(key);
    this.config.set(key, value);

    // Notify watchers
    const watchers = this.watchers.get(key);
    if (watchers) {
      watchers.forEach(watcher => watcher(value));
    }
  }

  get(key: string): any {
    return this.config.get(key);
  }

  watch(key: string, callback: (value: any) => void): () => void {
    if (!this.watchers.has(key)) {
      this.watchers.set(key, new Set());
    }

    this.watchers.get(key)!.add(callback);

    // Return unwatch function
    return () => {
      this.watchers.get(key)?.delete(callback);
    };
  }
}
```

### 2. Configuration Validation

```typescript
// src/config/validation.ts
import { logger } from '../utils/logger.js';

export class ConfigValidator {
  static validateDatabaseUrl(url: string): boolean {
    try {
      new URL(url);
      return url.startsWith('postgresql://');
    } catch {
      return false;
    }
  }

  static validateQdrantUrl(url: string): boolean {
    try {
      const parsed = new URL(url);
      return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  }

  static validateOpenAIApiKey(key: string): boolean {
    return key.startsWith('sk-') && key.length > 40;
  }

  static validateAll(): void {
    const errors: string[] = [];

    if (!this.validateDatabaseUrl(process.env.DATABASE_URL)) {
      errors.push('Invalid DATABASE_URL');
    }

    if (!this.validateQdrantUrl(process.env.QDRANT_URL)) {
      errors.push('Invalid QDRANT_URL');
    }

    if (!this.validateOpenAIApiKey(process.env.OPENAI_API_KEY)) {
      errors.push('Invalid OPENAI_API_KEY');
    }

    if (errors.length > 0) {
      throw new Error(`Configuration validation failed: ${errors.join(', ')}`);
    }

    logger.info('Configuration validation passed');
  }
}
```

## Environment-Specific Settings

### Development Environment

```typescript
// src/config/development.ts
export const DevelopmentConfig = {
  logging: {
    level: 'debug',
    format: 'pretty',
    enableColors: true,
    enableStackTrace: true
  },

  features: {
    hotReload: true,
    devTools: true,
    mockData: false,
    debugEndpoints: true
  },

  performance: {
    enableCache: false,
    enableMetrics: false,
    enableProfiling: true,
    slowQueryThreshold: 1000
  }
};
```

### Production Environment

```typescript
// src/config/production.ts
export const ProductionConfig = {
  logging: {
    level: 'warn',
    format: 'json',
    enableColors: false,
    enableStackTrace: false
  },

  security: {
    enableApiKeyAuth: true,
    enableRateLimit: true,
    enableCORS: true,
    enableHelmet: true
  },

  performance: {
    enableCache: true,
    enableMetrics: true,
    enableProfiling: false,
    slowQueryThreshold: 500
  },

  monitoring: {
    enableHealthChecks: true,
    enablePrometheus: true,
    healthCheckInterval: 30000
  }
};
```

## Configuration Best Practices

### 1. Security

```typescript
// src/config/security.ts
export class SecurityConfig {
  static sanitizeConfig(): void {
    // Remove sensitive data from logs
    const sensitiveKeys = ['OPENAI_API_KEY', 'DATABASE_URL', 'QDRANT_API_KEY'];

    sensitiveKeys.forEach(key => {
      if (process.env[key]) {
        process.env[key] = '***REDACTED***';
      }
    });
  }

  static validateSecureSettings(): void {
    // Ensure secure defaults
    if (process.env.NODE_ENV === 'production') {
      if (!process.env.API_KEY_ENABLED || process.env.API_KEY_ENABLED !== 'true') {
        logger.warn('API key authentication should be enabled in production');
      }

      if (!process.env.RATE_LIMIT_ENABLED || process.env.RATE_LIMIT_ENABLED !== 'true') {
        logger.warn('Rate limiting should be enabled in production');
      }
    }
  }
}
```

### 2. Performance Optimization

```typescript
// src/config/performance.ts
export const PerformanceConfig = {
  connectionPooling: {
    postgres: {
      min: Math.max(2, Math.floor(cpus.length / 2)),
      max: Math.min(20, cpus.length * 2)
    },
    qdrant: {
      min: 2,
      max: 10
    }
  },

  caching: {
    search: {
      ttl: process.env.NODE_ENV === 'production' ? 3600 : 300,
      maxSize: process.env.NODE_ENV === 'production' ? 10000 : 1000
    },
    embeddings: {
      ttl: 86400, // 24 hours
      maxSize: 50000
    }
  },

  timeouts: {
    database: 30000,
    search: 10000,
    embedding: 60000,
    api: 120000
  }
};
```

### 3. Environment Detection

```typescript
// src/config/environment-detection.ts
export class EnvironmentDetector {
  static isDevelopment(): boolean {
    return process.env.NODE_ENV === 'development' ||
           process.env.NODE_ENV === 'dev' ||
           !process.env.NODE_ENV;
  }

  static isStaging(): boolean {
    return process.env.NODE_ENV === 'staging' ||
           process.env.NODE_ENV === 'stage';
  }

  static isProduction(): boolean {
    return process.env.NODE_ENV === 'production' ||
           process.env.NODE_ENV === 'prod';
  }

  static isTest(): boolean {
    return process.env.NODE_ENV === 'test' ||
           process.env.NODE_ENV === 'testing';
  }

  static getCpuCount(): number {
    return require('os').cpus().length;
  }

  static getMemoryLimit(): number {
    return parseInt(process.env.MEMORY_LIMIT || '2048'); // MB
  }
}
```

## Configuration Validation

### 1. Startup Validation

```typescript
// src/config/startup-validation.ts
export async function validateConfiguration(): Promise<void> {
  const validator = new ConfigValidator();

  try {
    // Validate required fields
    validator.validateRequired();

    // Validate URLs and API keys
    ConfigValidator.validateAll();

    // Validate database connections
    await validateDatabaseConnections();

    // Validate external services
    await validateExternalServices();

    logger.info('✅ Configuration validation passed');
  } catch (error) {
    logger.error('❌ Configuration validation failed:', error);
    process.exit(1);
  }
}

async function validateDatabaseConnections(): Promise<void> {
  const db = new UnifiedDatabaseLayer();
  const isHealthy = await db.healthCheck();

  if (!isHealthy) {
    throw new Error('Database health check failed');
  }
}

async function validateExternalServices(): Promise<void> {
  // Validate OpenAI API
  const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  await openai.models.list();

  // Validate Qdrant connection
  const qdrant = new QdrantClient({ url: process.env.QDRANT_URL });
  await qdrant.getCollections();
}
```

### 2. Runtime Validation

```typescript
// src/config/runtime-validation.ts
export class RuntimeValidator {
  private static validationInterval: NodeJS.Timeout;

  static startValidation(): void {
    this.validationInterval = setInterval(async () => {
      try {
        await this.validateConnections();
        await this.validatePerformance();
      } catch (error) {
        logger.error('Runtime validation failed:', error);
      }
    }, 60000); // Every minute
  }

  static stopValidation(): void {
    if (this.validationInterval) {
      clearInterval(this.validationInterval);
    }
  }

  private static async validateConnections(): Promise<void> {
    // Check database connection health
    const db = new UnifiedDatabaseLayer();
    const healthy = await db.healthCheck();

    if (!healthy) {
      logger.warn('Database connection health check failed');
    }
  }

  private static async validatePerformance(): Promise<void> {
    // Check memory usage
    const memUsage = process.memoryUsage();
    const memLimitMB = EnvironmentDetector.getMemoryLimit();
    const memUsageMB = memUsage.heapUsed / 1024 / 1024;

    if (memUsageMB > memLimitMB * 0.9) {
      logger.warn(`High memory usage: ${memUsageMB.toFixed(2)}MB / ${memLimitMB}MB`);
    }
  }
}
```

## Configuration Examples

### Docker Environment Configuration

```yaml
# docker-compose.yml
version: '3.8'
services:
  cortex-mcp:
    build: .
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://cortex:${DB_PASSWORD}@postgres:5432/cortex_memory
      - QDRANT_URL=http://qdrant:6333
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - DB_POOL_SIZE=20
      - ENABLE_CACHE=true
      - ENABLE_METRICS=true
      - API_KEY_ENABLED=true
    depends_on:
      - postgres
      - qdrant
    restart: unless-stopped

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=cortex_memory
      - POSTGRES_USER=cortex
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data

  qdrant:
    image: qdrant/qdrant:v1.7.0
    volumes:
      - qdrant_data:/qdrant/storage
```

### Kubernetes Configuration

```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cortex-config
data:
  NODE_ENV: "production"
  DB_POOL_SIZE: "20"
  ENABLE_CACHE: "true"
  ENABLE_METRICS: "true"
  LOG_LEVEL: "info"
  SEARCH_LIMIT: "50"
  SIMILARITY_THRESHOLD: "0.7"

---
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: cortex-secrets
type: Opaque
data:
  DATABASE_URL: <base64-encoded-url>
  OPENAI_API_KEY: <base64-encoded-key>
  QDRANT_API_KEY: <base64-encoded-key>
```

This comprehensive configuration system ensures that the Cortex Memory MCP Server can be easily deployed and managed across different environments while maintaining security, performance, and reliability.