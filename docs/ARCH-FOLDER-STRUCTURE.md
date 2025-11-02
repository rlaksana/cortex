# Cortex Memory MCP - Project Folder Structure

## Overview

This document provides a comprehensive overview of the Cortex Memory MCP Server project structure, designed to help developers, users, and contributors navigate the codebase efficiently. The project follows a well-organized architecture that supports scalability, maintainability, and clear separation of concerns.

**Last Updated:** 2025-10-30
**Project Type:** Node.js TypeScript MCP Server
**Architecture:** Modular Service-Oriented Design
**Database:** Qdrant Vector Database

## 📁 Complete Project Structure

```
mcp-cortex/
├── 📄 Configuration & Setup Files
│   ├── package.json                    # Project metadata, scripts, dependencies
│   ├── package-lock.json              # Locked dependency versions
│   ├── tsconfig.json                  # TypeScript compiler configuration
│   ├── vitest.config.ts               # Unit testing configuration
│   ├── vitest.coverage.config.ts      # Coverage testing configuration
│   ├── vitest.integration.config.ts   # Integration testing configuration
│   ├── vitest.e2e.config.ts          # End-to-end testing configuration
│   ├── eslint.config.cjs              # ESLint linting configuration
│   ├── .prettierrc.cjs                # Prettier code formatting configuration
│   ├── .coveragerc.json               # Coverage reporting configuration
│   └── .gitignore                     # Git ignore patterns
│
├── 📁 Core Source Code (`src/`)
│   ├── 📁 Configuration (`src/config/`)
│   │   ├── auth-config.ts             # Authentication service configuration
│   │   ├── database-config.ts         # Database connection settings
│   │   ├── environment.ts             # Environment variable management
│   │   ├── migration-config.ts        # Database migration settings
│   │   └── validation.ts              # Configuration validation rules
│   │
│   ├── 📁 Database Layer (`src/db/`)
│   │   ├── 📁 Adapters (`src/db/adapters/`)
│   │   │   └── qdrant-adapter.ts      # Qdrant vector database adapter
│   │   ├── 📁 Factory (`src/db/factory/`)
│   │   │   └── database-factory.ts    # Database connection factory
│   │   ├── 📁 Interfaces (`src/db/interfaces/`)
│   │   │   ├── database-factory.interface.ts  # Factory interface
│   │   │   └── vector-adapter.interface.ts    # Adapter interface
│   │   ├── 📁 Types (`src/db/types/`)
│   │   │   └── database-types.ts      # Database-specific type definitions
│   │   ├── audit.ts                   # Database audit logging
│   │   ├── database-factory.ts        # Main database factory
│   │   ├── database-interface.ts      # Database interface definitions
│   │   ├── migrate.ts                 # Database migration utilities
│   │   ├── pool.ts                    # Connection pool management
│   │   ├── qdrant-client.ts           # Qdrant client implementation
│   │   ├── qdrant.ts                  # Qdrant-specific operations
│   │   ├── schema.ts                  # Database schema definitions
│   │   └── unified-database-layer-v2.ts # Unified database abstraction
│   │
│   ├── 📁 Middleware (`src/middleware/`)
│   │   ├── auth-middleware.ts         # Authentication middleware
│   │   ├── error-middleware.ts        # Error handling middleware
│   │   └── security-middleware.ts     # Security enforcement middleware
│   │
│   ├── 📁 Monitoring (`src/monitoring/`)
│   │   ├── performance-collector.ts   # Performance metrics collection
│   │   ├── performance-dashboard.ts   # Performance monitoring dashboard
│   │   └── performance-middleware.ts  # Performance monitoring middleware
│   │
│   ├── 📁 Schemas (`src/schemas/`)
│   │   ├── enhanced-validation.ts     # Enhanced validation schemas
│   │   ├── knowledge-types.ts         # Knowledge entity type schemas
│   │   └── mcp-inputs.ts              # MCP protocol input schemas
│   │
│   ├── 📁 Services (`src/services/`)
│   │   ├── 📁 Analytics (`src/services/analytics/`)
│   │   │   └── analytics.service.ts   # Analytics and metrics service
│   │   ├── 📁 Audit (`src/services/audit/`)
│   │   │   ├── audit-service.ts       # Audit logging service
│   │   │   └── query.ts               # Audit query utilities
│   │   ├── 📁 Auth (`src/services/auth/`)
│   │   │   ├── api-key-service.ts     # API key management
│   │   │   ├── auth-middleware-helper.ts  # Auth middleware helpers
│   │   │   ├── auth-service.ts        # Authentication service
│   │   │   └── authorization-service.ts   # Authorization service
│   │   ├── 📁 Deduplication (`src/services/deduplication/`)
│   │   │   └── deduplication-service.ts   # Content deduplication
│   │   ├── 📁 Embeddings (`src/services/embeddings/`)
│   │   │   └── embedding-service.ts   # Text embedding generation
│   │   ├── 📁 Filters (`src/services/filters/`)
│   │   │   └── scope-filter.ts        # Scope-based filtering
│   │   ├── 📁 Knowledge (`src/services/knowledge/`)
│   │   │   ├── assumption.ts          # Assumption knowledge type
│   │   │   ├── change.ts              # Change knowledge type
│   │   │   ├── decision.ts            # Decision knowledge type
│   │   │   ├── ddl.ts                 # DDL knowledge type
│   │   │   ├── entity.ts              # Entity knowledge type
│   │   │   ├── incident.ts            # Incident knowledge type
│   │   │   ├── issue.ts               # Issue knowledge type
│   │   │   ├── observation.ts         # Observation knowledge type
│   │   │   ├── pr_context.ts          # PR Context knowledge type
│   │   │   ├── reason.ts              # Reason knowledge type
│   │   │   ├── release_note.ts        # Release Note knowledge type
│   │   │   ├── relation.ts            # Relation knowledge type
│   │   │   ├── risk.ts                # Risk knowledge type
│   │   │   ├── runbook.ts             # Runbook knowledge type
│   │   │   ├── section.ts             # Section knowledge type
│   │   │   └── todo.ts                # TODO knowledge type
│   │   ├── 📁 Logging (`src/services/logging/`)
│   │   │   ├── logging-service.ts     # Core logging service
│   │   │   ├── pino-logger.ts         # Pino logger implementation
│   │   │   └── structured-logger.ts   # Structured logging utilities
│   │   ├── 📁 Orchestrators (`src/services/orchestrators/`)
│   │   │   ├── memory-store-orchestrator.ts  # Memory storage orchestration
│   │   │   └── search-orchestrator.ts       # Search operation orchestration
│   │   ├── 📁 Ranking (`src/services/ranking/`)
│   │   │   └── ranking-service.ts     # Search result ranking
│   │   ├── 📁 Search (`src/services/search/`)
│   │   │   ├── 📁 Tests (`src/services/search/__tests__/`)
│   │   │   │   └── deep-search.test.ts  # Search service tests
│   │   │   ├── deep-search.ts         # Deep search implementation
│   │   │   ├── query-builder.ts       # Search query construction
│   │   │   ├── search-orchestrator.ts # Search operation orchestration
│   │   │   └── semantic-search.ts     # Semantic search capabilities
│   │   ├── 📁 Similarity (`src/services/similarity/`)
│   │   │   └── similarity-service.ts  # Content similarity analysis
│   │   ├── 📁 Validation (`src/services/validation/`)
│   │   │   └── validation-service.ts  # Input validation service
│   │   ├── 📁 Workflow (`src/services/workflow/`)
│   │   │   └── workflow-service.ts    # Workflow management
│   │   ├── api.service.ts             # API service coordination
│   │   ├── auto-purge.ts              # Automatic data purging
│   │   ├── core-memory-find.ts        # Core memory search functionality
│   │   ├── delete-operations.ts       # Data deletion operations
│   │   ├── graph-traversal.ts         # Knowledge graph traversal
│   │   └── query-orchestrator.ts      # Query orchestration
│   │
│   ├── 📁 Types (`src/types/`)
│   │   ├── api-interfaces.ts          # API interface definitions
│   │   ├── api-types.ts               # API type definitions
│   │   ├── auth-types.ts              # Authentication types
│   │   ├── core-interfaces.ts         # Core system interfaces
│   │   ├── database-results.ts        # Database result types
│   │   ├── db-rows.ts                 # Database row types
│   │   ├── error-handling-interfaces.ts  # Error handling types
│   │   ├── knowledge-data.ts          # Knowledge data types
│   │   ├── logging-interfaces.ts      # Logging interface types
│   │   ├── mcp-sdk.d.ts               # MCP SDK type definitions
│   │   ├── query-results.ts           # Query result types
│   │   └── workflow-interfaces.ts     # Workflow interface types
│   │
│   ├── 📁 Utils (`src/utils/`)
│   │   ├── crypto.ts                  # Cryptographic utilities
│   │   ├── encryption.ts              # Encryption utilities
│   │   ├── error-handling.ts          # Error handling utilities
│   │   ├── file-operations.ts         # File operation utilities
│   │   ├── formatting.ts              # Data formatting utilities
│   │   ├── immutability.ts            # Immutable data utilities
│   │   ├── json.ts                    # JSON manipulation utilities
│   │   ├── string.ts                  # String manipulation utilities
│   │   ├── time.ts                    # Time and date utilities
│   │   └── validation.ts              # General validation utilities
│   │
│   ├── 📁 Test (`src/test/`)
│   │   └── test-database.ts           # Test database utilities
│   │
│   ├── index.ts                       # Main application entry point
│   ├── minimal-mcp-server.ts          # Minimal MCP server implementation
│   └── silent-mcp-entry.ts            # Silent MCP server entry
│
├── 📁 Test Suite (`tests/`)
│   ├── 📁 Concurrency (`tests/concurrency/`)
│   │   └── concurrent-operations.test.ts  # Concurrency testing
│   ├── 📁 Framework (`tests/framework/`)
│   │   ├── 📁 Helpers (`tests/framework/helpers/`)
│   │   │   ├── mock-qdrant.ts         # Qdrant mocking utilities
│   │   │   ├── test-database.ts       # Test database setup
│   │   │   └── test-server.ts         # Test server utilities
│   │   └── test-base.ts               # Base test framework
│   ├── 📁 Helpers (`tests/helpers/`)
│   │   ├── test-utils.ts              # General test utilities
│   │   └── test-fixtures.ts           # Test data fixtures
│   ├── 📁 Scenarios (`tests/scenarios/`)
│   │   ├── api-usage.test.ts          # API usage scenarios
│   │   ├── complex-search.test.ts     # Complex search scenarios
│   │   └── knowledge-workflows.test.ts # Knowledge workflow scenarios
│   ├── 📁 Systematic (`tests/systematic/`)
│   │   ├── integration-tests.test.ts  # Systematic integration tests
│   │   └── performance-tests.test.ts  # Systematic performance tests
│   ├── 📁 Unit (`tests/unit/`)
│   │   ├── 📁 Database (`tests/unit/database/`)
│   │   │   ├── connection-pool.test.ts   # Connection pool tests
│   │   │   ├── database-migration.test.ts # Database migration tests
│   │   │   └── qdrant-client.test.ts     # Qdrant client tests
│   │   ├── 📁 Knowledge Types (`tests/unit/knowledge-types/`)
│   │   │   ├── ddl.test.ts                 # DDL type tests
│   │   │   ├── issue.test.ts               # Issue type tests
│   │   │   └── decision.test.ts            # Decision type tests
│   │   ├── 📁 MCP Server (`tests/unit/mcp-server/`)
│   │   │   └── mcp-protocol-compliance.test.ts  # MCP protocol tests
│   │   ├── 📁 Performance (`tests/unit/performance/`)
│   │   │   ├── optimization-analytics.test.ts   # Performance optimization tests
│   │   │   └── performance-benchmarking.test.ts # Performance benchmarking tests
│   │   ├── 📁 Search (`tests/unit/search/`)
│   │   │   └── search-services.test.ts     # Search service tests
│   │   ├── 📁 Search Services (`tests/unit/search-services/`)
│   │   │   └── deep-search.test.ts        # Deep search tests
│   │   ├── 📁 Security (`tests/unit/security/`)
│   │   │   └── security.test.ts           # Security tests
│   │   ├── 📁 Services (`tests/unit/services/`)
│   │   │   ├── configuration.service.test.ts   # Configuration service tests
│   │   │   ├── import.service.test.ts        # Import service tests
│   │   │   ├── metrics.service.test.ts       # Metrics service tests
│   │   │   └── security.service.test.ts      # Security service tests
│   │   ├── 📁 Types (`tests/unit/types/`)
│   │   │   └── type-validation.test.ts     # Type validation tests
│   │   ├── 📁 Utilities (`tests/unit/utilities/`)
│   │   │   ├── encryption-utilities.test.ts  # Encryption utility tests
│   │   │   └── testing-utilities.test.ts     # Testing utility tests
│   │   └── 📁 Utils (`tests/unit/utils/`)
│   │       └── test-database.ts           # Test database utilities
│   ├── 📁 Utils (`tests/utils/`)
│   │   └── test-helpers.ts              # Test helper utilities
│   ├── 📁 Temp (`tests/temp/`)           # Temporary test files
│   └── 📁 Test Results (`tests/test-results/`)  # Test result artifacts
│
├── 📁 Documentation (`docs/`)
│   ├── API-REFERENCE.md                # Complete API reference
│   ├── ARCH-DATABASE.md                # Database architecture documentation
│   ├── ARCH-SYSTEM.md                  # System architecture documentation
│   ├── CONFIG-DEPLOYMENT.md            # Deployment configuration guide
│   ├── CONFIG-MONITORING.md            # Monitoring configuration guide
│   ├── DEV-FILE-HANDLES.md             # File handle management guide
│   ├── DEV-PACKAGE-MANAGEMENT.md       # Package management guide
│   ├── DEV-TEST-COMBINATIONS.md        # Test combinations documentation
│   ├── SETUP-CONFIGURATION.md          # Configuration setup guide
│   ├── SETUP-DEVELOPER.md              # Developer setup guide
│   ├── TROUBLESHOOT-EMFILE.md          # EMFILE troubleshooting guide
│   └── TROUBLESHOOT-ERRORS.md          # Error troubleshooting guide
│
├── 📁 Scripts (`scripts/`)
│   ├── 📁 CI (`scripts/ci/`)           # CI/CD pipeline scripts
│   ├── audit-dependencies.js           # Dependency audit script
│   ├── backup-qdrant.sh               # Qdrant backup script
│   ├── generate-coverage-badge.js      # Coverage badge generation
│   ├── generate-coverage-report.js     # Coverage report generation
│   ├── improve-code-organization.js    # Code organization improvements
│   ├── merge-coverage-reports.js       # Coverage report merging
│   ├── upload-coverage-reports.js      # Coverage report uploading
│   ├── validate-config.js              # Configuration validation
│   └── validate-tests.js               # Test validation script
│
├── 📁 Configuration (`config/`)
│   ├── CONFIG-MCP-SERVER.md            # MCP server configuration guide
│   ├── env-template.env                # Environment variable template
│   ├── install-config.json             # Installation configuration
│   ├── simple-mcp-config.json          # Simple MCP configuration
│   └── system-requirements.json        # System requirements specification
│
├── 📁 Examples (`examples/`)
│   └── file-handle-manager-integration.ts  # File handle integration example
│
├── 📁 Infrastructure
│   ├── 📁 Docker (`docker/`)          # Docker containerization files
│   ├── 📁 Kubernetes (`k8s/`)         # Kubernetes deployment files
│   └── 📁 Terraform (`terraform/`)    # Infrastructure as Code
│
├── 📁 Build Output (`dist/`)
│   ├── 📁 Config (`dist/config/`)     # Compiled configuration
│   ├── 📁 Database (`dist/db/`)       # Compiled database layer
│   ├── 📁 Middleware (`dist/middleware/`)  # Compiled middleware
│   ├── 📁 Monitoring (`dist/monitoring/`)  # Compiled monitoring
│   ├── 📁 Schemas (`dist/schemas/`)   # Compiled schemas
│   ├── 📁 Services (`dist/services/`) # Compiled services
│   ├── index.d.ts                     # Type definitions for main entry
│   ├── index.js                       # Compiled main application
│   ├── minimal-mcp-server.js          # Compiled minimal server
│   └── silent-mcp-entry.js            # Compiled silent entry
│
├── 📁 Environment Files
│   ├── .env                           # Local environment variables
│   ├── .env.ci                        # CI environment variables
│   ├── .env.example                   # Environment variable examples
│   ├── .env.simple                    # Simple environment configuration
│   ├── .env.test                      # Test environment variables
│   ├── .env.test.backup               # Backup test environment
│   ├── .env.test.local                # Local test environment
│   ├── .env.test-simple               # Simple test environment
│   ├── .env.windows                   # Windows-specific environment
│   └── .env.wsl                       # WSL-specific environment
│
├── 📁 Development Tools
│   ├── 📁 Git Hooks (`.husky/`)       # Git hooks configuration
│   ├── 📁 Claude Config (`.claude/`)  # Claude AI configuration
│   ├── 📁 Serena (`.serena/`)         # Serena MCP configuration
│   └── 📁 GitHub (`.github/`)         # GitHub Actions configuration
│
├── 📁 Logs & Runtime
│   ├── 📁 Logs (`logs/`)              # Application logs
│   ├── 📁 Test Logs (`test-logs/`)    # Test execution logs
│   ├── 📁 Test Results (`test-results/`)  # Test result files
│   ├── 📁 Coverage (`coverage/`)      # Code coverage reports
│   └── 📁 Test Temp (`test-temp/`)    # Temporary test files
│
├── 📄 Root Documentation
│   ├── README.md                      # Main project documentation
│   ├── SETUP-QUICK-START.md          # Quick start guide
│   ├── SETUP-CLONE.md                # Clone setup guide
│   ├── SETUP-ESM.md                  # ESM configuration guide
│   ├── SETUP-OPENAI.md               # OpenAI setup guide
│   ├── SETUP-PORTABLE.md             # Portable setup guide
│   ├── DEV-POLICY.md                 # Development policy guide
│   ├── CONFIG-SECURITY.md            # Security configuration guide
│   ├── CONFIG-VITEST-ESM.md          # Vitest ESM configuration
│   └── Various analysis and setup files
│
└── 📄 Development & Deployment Scripts
    ├── start-cortex.js                # Application startup script
    ├── start-cortex-windows.bat       # Windows startup script
    ├── debug-mcp.js                   # MCP debugging script
    ├── deferred-init-server.js        # Deferred initialization server
    └── Various test and utility scripts
```

## 🎯 Directory Purpose Categories

### 🔧 Core Application Code

- **`src/`** - All TypeScript source code (main application)
- **`dist/`** - Compiled JavaScript output (production code)
- **`types/`** - TypeScript type definitions and interfaces

### 🧪 Testing & Quality Assurance

- **`tests/`** - Comprehensive test suite (unit, integration, e2e)
- **`coverage/`** - Code coverage reports and analysis
- **`test-results/`** - Test execution artifacts and results

### 📚 Documentation & Guides

- **`docs/`** - Comprehensive technical documentation
- **Root `*.md` files** - Setup guides, policies, and quick references

### ⚙️ Configuration & Infrastructure

- **`config/`** - Configuration templates and specifications
- **`scripts/`** - Build, deployment, and utility scripts
- **Infrastructure files** - Docker, Kubernetes, Terraform configurations

### 🛠️ Development Tools & Environment

- **Environment files** - Multiple environment configurations
- **Development tools** - Git hooks, CI/CD, AI assistant configs
- **Build artifacts** - Logs, temporary files, caches

## 🧭 User-Specific Navigation Guide

### 🆕 For New Developers

**Starting Point:** `README.md` → `SETUP-QUICK-START.md` → `docs/SETUP-DEVELOPER.md`

**Key Directories to Explore:**

1. **`src/`** - Main application code
2. **`src/services/`** - Core business logic
3. **`src/types/`** - Type definitions
4. **`tests/`** - Understanding test patterns
5. **`docs/`** - Comprehensive documentation

**Recommended Workflow:**

1. Read `README.md` for project overview
2. Follow `SETUP-QUICK-START.md` for environment setup
3. Study `docs/SETUP-DEVELOPER.md` for development guidelines
4. Explore `src/` directory structure
5. Run tests to understand functionality

### 🔧 For API Users

**Starting Point:** `docs/API-REFERENCE.md` → `docs/ARCH-SYSTEM.md`

**Key Directories:**

1. **`src/services/`** - Available MCP services
2. **`src/schemas/`** - Input/output schemas
3. **`src/types/`** - API type definitions
4. **`examples/`** - Usage examples

**API Service Categories:**

- **Memory Operations:** `src/services/orchestrators/memory-store-orchestrator.ts`
- **Search Operations:** `src/services/search/`
- **Knowledge Types:** `src/services/knowledge/`
- **Authentication:** `src/services/auth/`

### 🐛 For Troubleshooters

**Starting Point:** `docs/TROUBLESHOOT-EMFILE.md` → `docs/TROUBLESHOOT-ERRORS.md`

**Key Locations:**

1. **`logs/`** - Application logs
2. **`test-logs/`** - Test execution logs
3. **Environment files** - Configuration debugging
4. **`scripts/validate-*.js`** - Validation scripts

**Troubleshooting Workflow:**

1. Check `logs/` for runtime errors
2. Review `test-logs/` for test failures
3. Validate configuration with `scripts/validate-config.js`
4. Run health checks: `npm run db:health`

### 🤝 For Contributors

**Starting Point:** `DEV-POLICY.md` → `docs/SETUP-DEVELOPER.md`

**Key Areas for Contribution:**

1. **`src/services/`** - New service implementations
2. **`tests/unit/`** - Unit test coverage
3. **`docs/`** - Documentation improvements
4. **`scripts/`** - Development tooling

**Contribution Guidelines:**

1. Follow patterns in existing service modules
2. Add comprehensive tests in corresponding test directories
3. Update documentation for new features
4. Ensure all quality checks pass: `npm run quality-check`

## 📝 File Naming Conventions

### TypeScript Files

- **PascalCase** for classes and interfaces: `AuthMiddleware.ts`, `DatabaseFactory.ts`
- **kebab-case** for utilities and helpers: `crypto.ts`, `validation.ts`
- **Suffix conventions:**
  - `.service.ts` - Service classes
  - `.middleware.ts` - Express middleware
  - `.interface.ts` - TypeScript interfaces
  - `.types.ts` - Type definitions
  - `.config.ts` - Configuration modules
  - `.util.ts` or `.utils.ts` - Utility functions

### Test Files

- **`.test.ts`** - Unit and integration tests
- **`.spec.ts`** - Specification tests (alternative naming)
- **Test structure mirrors source structure**
- **Descriptive naming:** `authentication-service.test.ts`, `user-validation.test.ts`

### Configuration Files

- **Environment files:** `.env`, `.env.example`, `.env.production`
- **Configuration templates:** `*-template.json`, `*-config.json`
- **Documentation:** `CONFIG-*.md`, `SETUP-*.md`

### Documentation Files

- **`ARCH-*.md`** - Architecture documentation
- **`API-*.md`** - API documentation
- **`SETUP-*.md`** - Setup and installation guides
- **`TROUBLESHOOT-*.md`** - Troubleshooting guides
- **`DEV-*.md`** - Development-specific documentation

## 🔄 Import/Export Patterns

### Service Module Pattern

```typescript
// src/services/example/example.service.ts
export class ExampleService {
  // Service implementation
}

export type ExampleServiceConfig = {
  // Configuration type
};
```

### Index File Pattern

```typescript
// src/services/example/index.ts
export { ExampleService } from './example.service';
export { ExampleServiceConfig } from './example.types';
```

### Type Definition Pattern

```typescript
// src/types/example-types.ts
export interface ExampleEntity {
  id: string;
  name: string;
}

export type ExampleOperation = {
  type: 'create' | 'update' | 'delete';
  data: Partial<ExampleEntity>;
};
```

## 🏗️ Adding New Files

### 📍 Where to Add New Components

#### New Services

1. Create directory: `src/services/new-service/`
2. Add service file: `src/services/new-service/new-service.service.ts`
3. Add types: `src/services/new-service/new-service.types.ts`
4. Add tests: `tests/unit/services/new-service.test.ts`
5. Add documentation: `docs/NEW-SERVICE.md`

#### New Knowledge Types

1. Add type file: `src/services/knowledge/new-type.ts`
2. Add tests: `tests/unit/knowledge-types/new-type.test.ts`
3. Update schemas: `src/schemas/knowledge-types.ts`
4. Update documentation

#### New API Endpoints

1. Update service: `src/services/api.service.ts`
2. Add types: `src/types/api-types.ts`
3. Add validation: `src/schemas/mcp-inputs.ts`
4. Add tests: `tests/unit/api/`

#### New Utilities

1. Add utility: `src/utils/new-utility.ts`
2. Add tests: `tests/unit/utilities/new-utility.test.ts`
3. Export from appropriate index files

### 📋 Maintenance Guidelines

#### When Adding New Files

1. **Follow naming conventions** consistently
2. **Add comprehensive tests** with proper coverage
3. **Update documentation** for new functionality
4. **Include type definitions** for all public APIs
5. **Add error handling** and logging as appropriate
6. **Update import paths** in affected files

#### When Modifying Existing Files

1. **Maintain backward compatibility** when possible
2. **Update corresponding tests** for changed functionality
3. **Document breaking changes** in appropriate documentation
4. **Run full test suite** to ensure no regressions
5. **Update type definitions** if interfaces change

#### Documentation Requirements

1. **All public APIs** must have JSDoc comments
2. **Complex algorithms** need inline documentation
3. **Configuration options** require comprehensive documentation
4. **Setup procedures** must be documented in setup guides
5. **Architecture decisions** should be documented in ARCH files

## 🔍 Search Patterns

### Finding Specific Types of Files

#### Services

```bash
# Find all service files
find src/services -name "*.service.ts"

# Find specific service
find src/services -name "*auth*.ts"
```

#### Tests

```bash
# Find all test files
find tests -name "*.test.ts"

# Find tests for specific module
find tests -name "*auth*.test.ts"
```

#### Configuration

```bash
# Find configuration files
find . -name "*.config.ts" -o -name "*.env*"

# Find environment templates
find . -name "*.env.example"
```

#### Documentation

```bash
# Find architecture documentation
find docs -name "ARCH-*.md"

# Find setup guides
find . -name "SETUP-*.md"
```

## 📊 File Type Distribution

### By Purpose

- **Source Code:** ~65% (src/ directory)
- **Tests:** ~20% (tests/ directory)
- **Documentation:** ~10% (docs/ + \*.md files)
- **Configuration:** ~5% (config/ + environment files)

### By Language

- **TypeScript:** ~80% (main implementation)
- **JavaScript:** ~15% (scripts, build tools)
- **Markdown:** ~4% (documentation)
- **JSON:** ~1% (configuration)

### By Category

- **Services:** ~30% of source code
- **Database Layer:** ~20% of source code
- **Types & Interfaces:** ~15% of source code
- **Middleware & Utils:** ~20% of source code
- **Configuration & Setup:** ~15% of source code

This comprehensive structure supports scalable development, clear separation of concerns, and maintainable code organization. The modular design allows for easy extension and modification while maintaining consistency across the codebase.
