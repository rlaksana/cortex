# Cortex Memory MCP Server - Unified Database Architecture

## Overview

Cortex Memory MCP Server is an advanced knowledge management system that leverages a **unified PostgreSQL + Qdrant architecture** for comprehensive data management and intelligent semantic search. The system provides sophisticated memory management with autonomous decision support capabilities.

**Key Features:**
- 🧠 **Unified Database Architecture** - PostgreSQL for structured data + Qdrant for vector search
- 🔍 **Multi-Strategy Search** - Semantic, full-text, hybrid, and fallback search strategies
- 🗄️ **16 Knowledge Types** - Complete knowledge management (entities, relations, observations, etc.)
- 🛡️ **Advanced Deduplication** - Intelligent content similarity detection with configurable thresholds
- 🚀 **Production Ready** - Comprehensive error handling, graceful degradation, and performance optimization
- ⚡ **Smart Orchestration** - Autonomous service coordination with context generation

## Architecture

### Unified Database Layer
The system uses a sophisticated dual-database architecture that combines the strengths of both databases:

**PostgreSQL Responsibilities:**
- Structured relational data storage
- Full-text search with advanced `tsvector` capabilities
- Complex queries and aggregations
- ACID transactions and data integrity
- JSON/JSONB operations with indexing
- Array operations and pattern matching

**Qdrant Responsibilities:**
- Vector similarity search and semantic understanding
- Embedding storage and retrieval
- Approximate nearest neighbor search
- Collection management and sharding
- Semantic ranking and relevance scoring

**Unified Interface:**
- Single `UnifiedDatabaseLayer` class coordinating both databases
- Automatic query routing based on operation type
- Connection pooling and performance optimization
- Comprehensive error handling with graceful degradation
- Type-safe TypeScript operations

### Service Layer
- **Memory Store Orchestrator** - Coordinates validation, deduplication, similarity detection, and storage
- **Memory Find Orchestrator** - Multi-strategy search with automatic strategy selection
- **Similarity Service** - Advanced content analysis with configurable weighting
- **Deduplication Service** - Intelligent duplicate detection using semantic similarity
- **Validation Service** - Input validation and business rule enforcement
- **Audit Service** - Comprehensive operation logging and change tracking

### Integration Layer
- **MCP Protocol** - Model Context Protocol for seamless Claude Code integration
- **REST API** - HTTP endpoints for external system integration
- **Unified Interface** - Single entry point for all database operations

## Knowledge Types

The system supports 16 comprehensive knowledge types:

1. **entity** - Graph nodes representing any concept or object
2. **relation** - Graph edges connecting entities with typed relationships
3. **observation** - Fine-grained data attached to entities
4. **section** - Document containers for organizing knowledge
5. **runbook** - Step-by-step operational procedures
6. **change** - Code change tracking and history
7. **issue** - Bug tracking and problem management
8. **decision** - Architecture Decision Records (ADRs)
9. **todo** - Task and action item tracking
10. **release_note** - Release documentation and changelogs
11. **ddl** - Database schema migration history
12. **pr_context** - Pull request metadata and context
13. **incident** - Incident response and management
14. **release** - Release deployment tracking
15.**risk** - Risk assessment and mitigation
16. **assumption** - Business and technical assumptions

## Quick Start

### Prerequisites

- Node.js 20.0.0 or higher
- PostgreSQL 15.0 or higher
- Qdrant 1.7.0 or higher
- OpenAI API key for vector embeddings
- Docker (for containerized deployment)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/cortex-memory-mcp.git
cd cortex-memory-mcp

# Install dependencies
npm install

# Configure environment variables
cp .env.example .env
# Edit .env with your configuration
```

### Environment Configuration

```bash
# PostgreSQL Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/cortex_memory
DB_POOL_SIZE=10
DB_TIMEOUT=30000

# Qdrant Configuration
QDRANT_URL=http://localhost:6333
QDRANT_API_KEY=your-api-key-if-required
QDRANT_COLLECTION_NAME=cortex-memory
QDRANT_MAX_CONNECTIONS=10

# OpenAI Configuration (Required for embeddings)
OPENAI_API_KEY=your-openai-api-key
EMBEDDING_MODEL=text-embedding-ada-002

# Vector Configuration
VECTOR_SIZE=1536
VECTOR_DISTANCE=Cosine
SIMILARITY_THRESHOLD=0.7

# Search Configuration
SEARCH_LIMIT=50
SEARCH_MODE=auto
ENABLE_CACHE=true
CACHE_TTL=3600

# Application Configuration
NODE_ENV=development
LOG_LEVEL=info
```

### Development Setup with Docker

```bash
# Start databases with Docker Compose
docker-compose -f docker-compose.dev.yml up -d

# Wait for services to be ready
npm run db:wait

# Run database migrations
npm run db:migrate

# Start development server
npm run dev
```

### Running the Server

```bash
# Start the unified MCP server
npm start

# Development mode with hot reload
npm run dev

# Or run specific modes
npm run start:unified    # Unified PostgreSQL + Qdrant mode (default)
npm run start:postgres   # PostgreSQL-only mode
npm run start:qdrant     # Qdrant-only mode
```

### Docker Deployment

```bash
# Build and start with Docker Compose
docker-compose -f docker-compose.yml up -d

# Development environment
docker-compose -f docker-compose.dev.yml up -d

# Production environment
docker-compose -f docker-compose.prod.yml up -d

# Check health status
docker-compose -f docker-compose.yml logs -f

# Scale services
docker-compose -f docker-compose.yml up -d --scale cortex-mcp=3
```

## Usage Examples

### Storing Knowledge Items

```javascript
// Store multiple knowledge items
const items = [
  {
    kind: "entity",
    data: {
      title: "User Authentication System",
      description: "Comprehensive authentication module with OAuth 2.0 support",
      content: "Detailed implementation notes..."
    },
    scope: {
      project: "my-app",
      branch: "main",
      org: "my-org"
    }
  },
  {
    kind: "decision",
    data: {
      title: "Use OAuth 2.0 for Authentication",
      rationale: "Industry standard with robust security features",
      alternatives: ["Basic Auth", "JWT", "Session-based"]
    }
  }
];

// Store items via MCP
const result = await client.callTool("memory_store", { items });
```

### Semantic Search

```javascript
// Search for relevant knowledge
const searchQuery = "How should I implement user authentication?";
const searchOptions = {
  limit: 10,
  mode: "auto",
  types: ["decision", "entity"],
  scope: {
    project: "my-app"
  }
};

// Search via MCP
const results = await client.callTool("memory_find", {
  query: searchQuery,
  ...searchOptions
});
```

### Health Monitoring

```javascript
// Check database health
const health = await client.callTool("database_health", {});

// Get comprehensive statistics
const stats = await client.callTool("database_stats", {
  scope: {
    project: "my-app"
  }
});
```

## API Reference

### memory_store

Store knowledge items in the vector database with automatic deduplication.

**Parameters:**
- `items` (array): Array of knowledge items to store

**Returns:**
- `success` (boolean): Whether storage was successful
- `stored` (number): Number of items stored
- `errors` (number): Number of storage errors
- `duplicates` (array): Detected duplicates with similarity scores

### memory_find

Find knowledge items using intelligent multi-strategy search.

**Parameters:**
- `query` (string): Search query - supports natural language and keywords
- `scope` (object): Search scope constraints (project, branch, org)
- `types` (array): Filter by specific knowledge types
- `mode` (string): Search mode - 'auto', 'fast', or 'deep'
- `limit` (number): Maximum number of results (default: 50)

**Returns:**
- `hits` (array): Search results with relevance scores
- `suggestions` (array): Alternative search suggestions
- `metadata` (object): Search metadata and debug information

### database_health

Check the health and status of the Qdrant database connection.

**Returns:**
- `healthy` (boolean): Database health status
- `connection` (object): Connection details and metrics
- `timestamp` (string): Health check timestamp

### database_stats

Get comprehensive statistics about the Qdrant database and knowledge base.

**Parameters:**
- `scope` (object): Optional scope to filter statistics

**Returns:**
- `database` (object): Database metrics and collection info
- `total_items` (number): Total knowledge items stored
- `items_by_type` (object): Items count by knowledge type
- `storage_size` (number): Total storage used
- `last_updated` (string): Last update timestamp

## Advanced Features

### Semantic Deduplication

The system automatically detects duplicates using vector similarity with an 85% threshold:

```javascript
const duplicateItem = {
  kind: "entity",
  data: { title: "User Authentication" }
};

// System will detect and prevent duplicate storage
const result = await memory_store({ items: [duplicateItem] });
// Returns: { success: true, stored: 0, duplicates: 1, errors: 0 }
```

### Multi-Strategy Search

The search orchestrator automatically selects the best search strategy:

1. **Hybrid Search** - Combines semantic and keyword search
2. **Semantic Search** - Pure vector similarity search
3. **Keyword Search** - Traditional text-based search
4. **Fallback Search** - Broad search when others fail

### Autonomous Context Generation

The system automatically generates context for search results:

```javascript
const results = await memory_find({
  query: "authentication best practices",
  return_corrections: true
});

// Results include autonomous context and search insights
```

## Configuration Options

### Qdrant Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `QDRANT_URL` | `http://localhost:6333` | Qdrant server URL |
| `QDRANT_API_KEY` | - | Optional API key for authentication |
| `QDRANT_COLLECTION_NAME` | `cortex-memory` | Primary collection name |
| `VECTOR_SIZE` | `1536` | Embedding dimension (OpenAI ada-002) |
| `VECTOR_DISTANCE` | `Cosine` | Distance metric for similarity |

### Search Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `SEARCH_LIMIT` | `50` | Maximum results per search |
| `SEARCH_THRESHOLD` | `0.7` | Minimum similarity threshold |
| `ENABLE_CACHING` | `true` | Enable result caching |
| `CACHE_TTL` | `3600` | Cache time-to-live (seconds) |

### Performance Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `DB_MAX_CONNECTIONS` | `10` | Maximum concurrent connections |
| `EMBEDDING_BATCH_SIZE` | `10` | Batch size for embedding generation |
| `API_TIMEOUT` | `30000` | API request timeout (ms) |
| `RETRY_ATTEMPTS` | `3` | Maximum retry attempts |

## Deployment

### Docker Compose

```yaml
version: '3.8'
services:
  qdrant:
    image: qdrant/qdrant:v1.13.2
    ports:
      - "6333:6333"
    volumes:
      - qdrant_data:/qdrant/storage
    environment:
      - QDRANT__SERVICE__HTTP_PORT=6333

  cortex-mcp:
    build: .
    ports:
      - "3000:3000"
    depends_on:
      - qdrant
    environment:
      - QDRANT_URL=http://qdrant:6333
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - NODE_ENV=production
    restart: unless-stopped

volumes:
  qdrant_data:
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cortex-mcp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cortex-mcp
  template:
    metadata:
      labels:
        app: cortex-mcp
    spec:
      containers:
      - name: cortex-mcp
        image: your-registry/cortex-mcp:latest
        ports:
        - containerPort: 3000
        env:
        - name: QDRANT_URL
          value: "http://qdrant-service:6333"
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: cortex-secrets
              key: openai-api-key
```

## Monitoring

### Health Checks

The system provides comprehensive health monitoring:

```bash
# Check server health
curl http://localhost:3000/health

# Check database health
npm run db:health

# Get detailed statistics
npm run database_stats
```

### Metrics and Logging

- **Structured Logging** - JSON-formatted logs with correlation IDs
- **Performance Metrics** - Query latency, throughput, and error rates
- **Connection Monitoring** - Database connection pool statistics
- **Search Analytics** - Search patterns and result relevance

## Security

### Authentication

- **API Key Management** - Secure API key storage and rotation
- **Scope Isolation** - Project and branch-based access control
- **Content Validation** - Input sanitization and type checking
- **Rate Limiting** - Configurable request rate limits

### Data Protection

- **Encryption in Transit** - HTTPS/TLS for all API communications
- **Vector Security** - Secure embedding generation and storage
- **Backup Encryption** - Encrypted database backups
- **Access Logging** - Comprehensive audit logging

## Troubleshooting

### Common Issues

**Qdrant Connection Errors:**
```bash
# Check Qdrant server status
curl http://localhost:6333/health

# Verify collection exists
curl http://localhost:6333/collections/cortex-memory
```

**OpenAI API Issues:**
```bash
# Test API key
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
     https://api.openai.com/v1/models

# Check embedding generation
npm run test:embeddings
```

**Performance Issues:**
```bash
# Monitor connection pools
npm run db:stats

# Check cache performance
npm run test:cache

# Run performance benchmarks
npm run test:performance
```

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
# Enable debug mode
DEBUG=* npm start

# Or set in environment
export DEBUG=*
npm start
```

## Development

### Running Tests

```bash
# Run all tests
npm test

# Run specific test suites
npm run test:unit
npm run test:integration
npm run test:e2e

# Run with coverage
npm run test:coverage
```

### Building

```bash
# Build for production
npm run build

# Build Qdrant-specific version
npm run build:qdrant

# Type checking
npm run type-check
npm run type-check:qdrant
```

### Code Quality

```bash
# Lint code
npm run lint

# Fix linting issues
npm run lint:fix

# Quality checks
npm run quality-check
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📖 [Documentation](./docs/)
- 🐛 [Issue Tracker](https://github.com/your-org/cortex-memory-mcp/issues)
- 💬 [Discussions](https://github.com/your-org/cortex-memory-mcp/discussions)
- 📧 [Email Support](mailto:support@your-org.com)

## Documentation

- 📖 [API Documentation](./docs/API.md) - Complete API reference with examples
- 🏗️ [Architecture Overview](./docs/ARCHITECTURE.md) - Detailed system architecture
- 👨‍💻 [Developer Guide](./docs/DEVELOPER.md) - Development setup and contribution guidelines
- ⚙️ [Configuration Guide](./docs/CONFIGURATION.md) - Comprehensive configuration options
- 🚀 [Deployment Guide](./docs/DEPLOYMENT.md) - Production deployment instructions

## Recent Improvements

### Unified Database Architecture (v2.0.0)

**Major Architecture Enhancement:**
- ✅ **PostgreSQL + Qdrant Integration** - Unified database layer combining structured and vector search
- ✅ **Advanced Service Orchestration** - Modular services with clear separation of concerns
- ✅ **Enhanced Error Handling** - Graceful degradation with multiple fallback strategies
- ✅ **Improved Performance** - Connection pooling, caching, and query optimization

**New Services:**
- **Similarity Service** - Advanced content analysis with configurable weighting
- **Deduplication Service** - Intelligent duplicate detection using semantic similarity
- **Validation Service** - Input validation and business rule enforcement
- **Audit Service** - Comprehensive operation logging and change tracking

**Search Enhancements:**
- **Multi-Strategy Search** - Automatic strategy selection (semantic, full-text, hybrid, fallback)
- **Advanced Full-Text Search** - PostgreSQL tsvector with configurable weighting
- **Semantic Understanding** - Vector embeddings with similarity ranking
- **Context Generation** - Autonomous context and user suggestions

**Developer Experience:**
- **Type Safety** - Comprehensive TypeScript interfaces and validation
- **Error Recovery** - Multi-level fallbacks with graceful degradation
- **Monitoring** - Health checks, metrics, and performance tracking
- **Configuration Management** - Environment-based configuration with validation

---

**Made with ❤️ by the Cortex Team**

For the latest updates and documentation, visit [our website](https://your-org.com/cortex).