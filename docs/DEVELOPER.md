# Developer Guide

## Overview

This guide provides comprehensive information for developers working with the Cortex Memory MCP Server, including setup, development workflow, testing, and contribution guidelines.

## Prerequisites

### System Requirements

- **Node.js**: 20.0.0 or higher
- **Qdrant**: 1.7.0 or higher
- **Docker**: 20.10+ and Docker Compose 2.0+
- **Git**: 2.40+
- **TypeScript**: 5.0+ (included with dev dependencies)

⚠️ **IMPORTANT**: This system uses **QDRANT ONLY**. Do NOT install PostgreSQL - it is not needed and will cause confusion.

### Development Tools

- **IDE**: VS Code (recommended) with extensions:
  - TypeScript and JavaScript Language Features
  - ESLint
  - Prettier
  - GitLens
  - Thunder Client (for API testing)

- **Database Tools**:
  - Qdrant Web UI (http://localhost:6333/dashboard)
  - NO PostgreSQL tools needed

## Quick Start

### 1. Clone and Setup

```bash
# Clone the repository
git clone https://github.com/your-org/cortex-memory-mcp.git
cd cortex-memory-mcp

# Install dependencies
npm install

# Copy environment configuration
cp .env.example .env
```

### 2. Database Setup

#### Option A: Docker (Recommended)

```bash
# Start Qdrant only
docker-compose -f docker-compose.dev.yml up -d

# Wait for Qdrant to be ready
npm run qdrant:wait
```

#### Option B: Local Installation

```bash
# Qdrant setup only - NO PostgreSQL needed
curl -L https://github.com/qdrant/qdrant/releases/latest/download/qdrant-linux-x86_64.tar.gz | tar xz
./qdrant/x86_64-unknown-linux-gnu/qdrant &

# Verify Qdrant is running
curl http://localhost:6333/health
```

### 3. Environment Configuration

Edit `.env` file with your configuration:

```bash
# Database Configuration - QDRANT ONLY
QDRANT_URL=http://localhost:6333
QDRANT_API_KEY=your-api-key-if-required
# NO DATABASE_URL NEEDED - QDRANT ONLY!

# OpenAI Configuration (for embeddings)
OPENAI_API_KEY=your-openai-api-key
EMBEDDING_MODEL=text-embedding-ada-002

# Development Configuration
NODE_ENV=development
LOG_LEVEL=debug
ENABLE_CACHE=true
SEARCH_LIMIT=50
```

### 4. Database Initialization

```bash
# No database migrations needed for Qdrant
echo "✅ Qdrant is ready - no migrations required"

# Initialize Qdrant collection (handled automatically on first run)
npm run qdrant:init
```

### 5. Start Development Server

```bash
# Start the MCP server
npm run dev

# Qdrant-only mode is the default and only supported mode
npm run dev
```

## Development Workflow

### 1. Branch Strategy

We use Git Flow branching model:

```bash
# Main branches
main          # Production-ready code
develop       # Integration branch

# Feature branches
feature/feature-name
bugfix/bug-description
hotfix/critical-fix
release/version-number
```

### 2. Code Organization

```
src/
├── config/           # Configuration management
│   ├── environment.ts
│   ├── database.ts
│   └── auth.ts
├── db/              # Database layer
│   ├── unified-database-layer.ts
│   ├── pool.ts
│   └── migrations/
├── services/        # Business logic
│   ├── knowledge/   # Knowledge type handlers
│   ├── orchestrators/ # Service orchestration
│   ├── similarity/  # Similarity detection
│   └── validation/  # Input validation
├── middleware/      # Express middleware
├── utils/           # Utility functions
├── types/           # TypeScript definitions
└── schemas/         # Validation schemas
```

### 3. Development Commands

```bash
# Development
npm run dev              # Start development server
npm run dev:debug        # Start with debug logging
npm run dev:watch        # Start with file watching

# Building
npm run build            # Build for production
npm run build:watch      # Build with file watching
npm run type-check       # TypeScript type checking

# Testing
npm test                 # Run all tests
npm run test:unit        # Unit tests only
npm run test:integration # Integration tests only
npm run test:watch       # Run tests in watch mode
npm run test:coverage    # Run with coverage report

# Database (Qdrant only)
npm run qdrant:init      # Initialize Qdrant collection
npm run qdrant:reset     # Reset Qdrant collection
# NO DATABASE MIGRATIONS - QDRANT ONLY

# Code Quality
npm run lint             # Run ESLint
npm run lint:fix         # Fix linting issues
npm run format           # Format code with Prettier
npm run quality-check    # Run all quality checks
```

## Testing Strategy

### 1. Test Structure

```
tests/
├── unit/               # Unit tests
│   ├── services/
│   ├── utils/
│   └── types/
├── integration/        # Integration tests
│   ├── database/
│   ├── api/
│   └── services/
├── e2e/               # End-to-end tests
│   ├── workflows/
│   └── scenarios/
└── fixtures/          # Test data and mocks
```

### 2. Writing Tests

#### Unit Tests

```typescript
// tests/unit/services/similarity.test.ts
import { SimilarityService } from '../../../src/services/similarity/similarity-service.js';
import { describe, it, expect, beforeEach } from '@jest/globals';

describe('SimilarityService', () => {
  let service: SimilarityService;

  beforeEach(() => {
    service = new SimilarityService();
  });

  describe('findSimilar', () => {
    it('should find similar items above threshold', async () => {
      const item = {
        kind: 'entity',
        data: { title: 'User Authentication' },
        scope: { project: 'test' }
      };

      const results = await service.findSimilar(item, 0.5);

      expect(results).toBeDefined();
      expect(Array.isArray(results)).toBe(true);
    });
  });
});
```

#### Integration Tests

```typescript
// tests/integration/api/memory-store.test.ts
import { request } from 'supertest';
import { app } from '../../src/app.js';
import { setupTestDatabase, cleanupTestDatabase } from '../helpers/database.js';

describe('Memory Store API', () => {
  beforeAll(async () => {
    await setupTestDatabase();
  });

  afterAll(async () => {
    await cleanupTestDatabase();
  });

  it('should store knowledge items successfully', async () => {
    const response = await request(app)
      .post('/api/memory/store')
      .send({
        items: [{
          kind: 'entity',
          data: { title: 'Test Entity' }
        }]
      });

    expect(response.status).toBe(200);
    expect(response.body.stored).toHaveLength(1);
  });
});
```

### 3. Test Configuration

Jest configuration in `jest.config.js`:

```javascript
export default {
  preset: 'ts-jest/presets/default-esm',
  extensionsToTreatAsEsm: ['.ts'],
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      useESM: true,
      tsconfig: {
        module: 'ESNext',
        target: 'ES2022'
      }
    }]
  },
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/index.ts'
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  }
};
```

### 4. Running Tests

```bash
# Run all tests
npm test

# Run specific test file
npm test -- similarity.test.ts

# Run tests matching pattern
npm test -- --testNamePattern="findSimilar"

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

## Database Development

### 1. Qdrant Collection Management

Qdrant automatically manages collections. No manual schema migrations needed:

```bash
# Initialize the main collection (handled automatically)
npm run qdrant:init

# Reset collection if needed
npm run qdrant:reset
```

### 2. Qdrant Schema

The system uses a single collection with metadata-based organization:

```typescript
// Collection: "cortex-memory"
interface VectorPayload {
  // Knowledge item data
  title: string;
  content: string;
  kind: string; // entity, relation, observation, etc.
  scope: {
    project?: string;
    branch?: string;
    org?: string;
  };

  // Metadata for filtering
  created_at: string;
  updated_at: string;
  tags?: string[];

  // Content for retrieval
  data: Record<string, any>;
}
```

### 3. Query Development

Use the Qdrant adapter:

```typescript
import { QdrantAdapter } from '../src/db/adapters/qdrant-adapter.js';

const qdrant = new QdrantAdapter();

// Semantic search
const results = await qdrant.search({
  query: 'authentication security',
  limit: 50,
  filter: {
    must: [
      { key: "kind", match: { value: "entity" }}
    ]
  }
});

// Metadata filtering
const entities = await qdrant.search({
  vector: embedding,
  filter: {
    must: [
      { key: "scope.project", match: { value: "my-project" }},
      { key: "data.status", match: { value: "active" }}
    ]
  }
});

// Similarity search
const similar = await qdrant.findSimilar({
  id: "existing-vector-id",
  limit: 10
});
```

⚠️ **IMPORTANT**: All database operations go through Qdrant. No SQL queries or PostgreSQL operations are supported.

## API Development

### 1. Creating New Endpoints

```typescript
// src/routes/custom-endpoint.ts
import { Router } from 'express';
import { body, validationResult } from 'express-validator';
import { handleErrors } from '../middleware/error-handler.js';

const router = Router();

// Validation middleware
const validateCustomRequest = [
  body('name').notEmpty().withMessage('Name is required'),
  body('type').isIn(['type1', 'type2']).withMessage('Invalid type')
];

// Route handler
router.post('/custom', validateCustomRequest, handleErrors(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const result = await customService.process(req.body);
  res.json(result);
}));

export default router;
```

### 2. Error Handling

```typescript
// src/middleware/error-handler.ts
export class AppError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public errorCode: string
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export const handleErrors = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

export const errorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (error instanceof AppError) {
    return res.status(error.statusCode).json({
      error: error.errorCode,
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }

  // Unknown error
  console.error('Unexpected error:', error);
  res.status(500).json({
    error: 'INTERNAL_ERROR',
    message: 'An unexpected error occurred',
    timestamp: new Date().toISOString()
  });
};
```

### 3. Validation Schemas

```typescript
// src/schemas/knowledge-schemas.ts
import { z } from 'zod';

export const KnowledgeItemSchema = z.object({
  kind: z.enum([
    'entity', 'relation', 'observation', 'section', 'runbook',
    'change', 'issue', 'decision', 'todo', 'release_note',
    'ddl', 'pr_context', 'incident', 'release', 'risk', 'assumption'
  ]),
  data: z.record(z.any()),
  scope: z.object({
    project: z.string().optional(),
    branch: z.string().optional(),
    org: z.string().optional()
  }).optional()
});

export const MemoryStoreRequestSchema = z.object({
  items: z.array(KnowledgeItemSchema).min(1)
});

export const MemoryFindRequestSchema = z.object({
  query: z.string().min(1),
  scope: z.object({
    project: z.string().optional(),
    branch: z.string().optional(),
    org: z.string().optional()
  }).optional(),
  types: z.array(z.string()).optional(),
  mode: z.enum(['auto', 'fast', 'deep']).optional(),
  limit: z.number().int().positive().max(100).optional()
});
```

## Configuration Management

### 1. Environment Configuration

```typescript
// src/config/environment.ts
export class Environment {
  private static instance: Environment;
  private config: NodeJS.ProcessEnv;

  private constructor() {
    this.config = process.env;
    this.validateRequired();
  }

  static getInstance(): Environment {
    if (!Environment.instance) {
      Environment.instance = new Environment();
    }
    return Environment.instance;
  }

  private validateRequired(): void {
    const required = ['QDRANT_URL'];
    const missing = required.filter(key => !this.config[key]);

    if (missing.length > 0) {
      throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
    }
  }

  // NO DATABASE_URL - QDRANT ONLY
  getQdrantUrl(): string {
    return this.config.QDRANT_URL!;
  }

  getQdrantConfig() {
    return {
      url: this.config.QDRANT_URL!,
      apiKey: this.config.QDRANT_API_KEY,
      timeout: parseInt(this.config.QDRANT_TIMEOUT || '30000'),
      maxConnections: parseInt(this.config.QDRANT_MAX_CONNECTIONS || '10')
    };
  }

  isDevelopmentMode(): boolean {
    return this.config.NODE_ENV === 'development';
  }

  isProductionMode(): boolean {
    return this.config.NODE_ENV === 'production';
  }
}
```

### 2. Service Configuration

```typescript
// src/config/services.ts
import { Environment } from './environment.js';

const env = Environment.getInstance();

export const DatabaseConfig = {
  // NO POSTGRESQL CONFIG - QDRANT ONLY
  qdrant: env.getQdrantConfig()
};

export const SearchConfig = {
  defaultLimit: parseInt(process.env.SEARCH_DEFAULT_LIMIT || '50'),
  maxLimit: parseInt(process.env.SEARCH_MAX_LIMIT || '100'),
  similarityThreshold: parseFloat(process.env.SIMILARITY_THRESHOLD || '0.7'),
  enableCache: process.env.ENABLE_CACHE === 'true',
  cacheTTL: parseInt(process.env.CACHE_TTL || '3600')
};
```

## Debugging and Troubleshooting

### 1. Debug Mode

```bash
# Enable debug logging
DEBUG=* npm run dev

# Specific debug categories
DEBUG=cortex:database,cortex:search npm run dev

# Debug with Node.js inspector
node --inspect-brk dist/index.js
```

### 2. Common Issues

#### Database Connection Issues

```bash
# Check Qdrant connection
curl http://localhost:6333/health

# Check Docker containers
docker-compose -f docker-compose.dev.yml ps
docker-compose -f docker-compose.dev.yml logs

# NO POSTGRESQL CONNECTION CHECKS NEEDED
```

#### TypeScript Issues

```bash
# Type checking
npm run type-check

# Clear TypeScript cache
rm -rf .tsbuildinfo
npm run build

# Check for type errors
npx tsc --noEmit
```

#### Test Issues

```bash
# Run tests with verbose output
npm test -- --verbose

# Run specific test with debug
npm test -- --testNamePattern="specific test" --verbose

# Check test coverage
npm run test:coverage
```

### 3. Performance Debugging

```typescript
// Add performance monitoring
import { performance } from 'perf_hooks';

const startTime = performance.now();
await someOperation();
const duration = performance.now() - startTime;

logger.debug({ operation: 'someOperation', duration }, 'Performance metrics');
```

## Contributing Guidelines

### 1. Code Style

We use ESLint and Prettier for code formatting:

```bash
# Check code style
npm run lint

# Fix automatically
npm run lint:fix

# Format code
npm run format
```

### 2. Commit Messages

Follow conventional commits:

```
type(scope): description

feat(api): add new memory search endpoint
fix(database): resolve connection pool timeout
docs(readme): update installation instructions
test(similarity): add unit tests for similarity service
```

### 3. Pull Request Process

1. Create feature branch from `develop`
2. Make changes with tests
3. Ensure all tests pass
4. Update documentation if needed
5. Submit pull request to `develop`

```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Make changes and commit
git add .
git commit -m "feat(service): implement new feature"

# Push and create PR
git push origin feature/your-feature-name
```

### 4. Code Review Checklist

- [ ] Tests are included and passing
- [ ] Code follows style guidelines
- [ ] Documentation is updated
- [ ] No security vulnerabilities
- [ ] Performance impact considered
- [ ] Error handling is appropriate
- [ ] Logging is added where needed

## Release Process

### 1. Version Management

We use semantic versioning:

```bash
# Patch version (bug fixes)
npm version patch

# Minor version (new features)
npm version minor

# Major version (breaking changes)
npm version major
```

### 2. Release Checklist

- [ ] All tests are passing
- [ ] Documentation is updated
- [ ] CHANGELOG is updated
- [ ] Version is bumped
- [ ] Git tag is created
- [ ] Docker image is built
- [ ] Deployment is tested

### 3. Deployment

```bash
# Build for production
npm run build

# Create Docker image
docker build -t cortex-memory-mcp:latest .

# Tag and push
docker tag cortex-memory-mcp:latest your-registry/cortex-memory-mcp:v1.0.0
docker push your-registry/cortex-memory-mcp:v1.0.0
```

## Additional Resources

### Documentation

- [API Documentation](./API.md)
- [Architecture Overview](./ARCHITECTURE.md)
- [Configuration Guide](./CONFIGURATION.md)
- [Deployment Guide](./DEPLOYMENT.md)

### Tools and Libraries

- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [Jest Testing Framework](https://jestjs.io/docs/getting-started)
- [Qdrant Documentation](https://qdrant.tech/documentation/)
- [Express.js Guide](https://expressjs.com/en/guide/)

### Community

- [GitHub Repository](https://github.com/your-org/cortex-memory-mcp)
- [Discord Community](https://discord.gg/your-server)
- [Stack Overflow](https://stackoverflow.com/questions/tagged/cortex-memory)

For any questions or support, please create an issue in the GitHub repository or contact the development team.