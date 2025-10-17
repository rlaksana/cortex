# MCP-Cortex

A comprehensive Memory Cortex MCP server that provides advanced knowledge management capabilities with PostgreSQL backend.

## Features

- **Memory Management**: Persistent storage of entities, relations, observations, and decisions
- **Cross-Platform Support**: Compatible with Windows, Linux, and WSL2 environments
- **Advanced Search**: Deep search capabilities with confidence scoring
- **Knowledge Graph**: Relationship tracking between entities and concepts
- **Type Safety**: Full TypeScript support with comprehensive validation
- **Audit Logging**: Complete audit trail for all operations

## Prerequisites

- Node.js 18+
- PostgreSQL database
- Git

## Installation

### 1. Clone Repository
```bash
git clone <repository-url>
cd mcp-cortex
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Database Setup

Create a PostgreSQL database and configure environment variables:

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your database configuration
DATABASE_URL="postgresql://username:password@localhost:5432/your_database"
```

### 4. Database Migration
```bash
# Apply database schema
npx prisma migrate dev
```

### 5. Build and Start
```bash
# Build the project
npm run build

# Start the server
npm start
```

## Cross-Platform Compatibility

This project includes cross-platform binary targets for Prisma, ensuring compatibility across:

- Windows (native)
- Linux/WSL2 (debian-openssl-3.0.x)

The Prisma Client is automatically generated with support for both environments.

## Docker Installation (Alternative)

For easier deployment, use Docker Compose:

```bash
docker-compose up -d
```

## Development

### Running Tests
```bash
npm test
```

### Type Checking
```bash
npm run type-check
```

### Linting
```bash
npm run lint
```

### Database Operations
```bash
# Generate Prisma client
npx prisma generate

# View database
npx prisma studio

# Create new migration
npx prisma migrate dev --name <migration-name>
```

## Configuration

The server uses environment variables for configuration:

- `DATABASE_URL`: PostgreSQL connection string
- `LOG_LEVEL`: Logging level (default: 'info')
- `PORT`: Server port (default: 3000)

## Usage

Once installed, the MCP-Cortex server provides:

1. **Memory Storage**: Store and retrieve knowledge entities
2. **Relationship Tracking**: Link related concepts and decisions
3. **Search Capabilities**: Advanced search with confidence scoring
4. **Audit Trail**: Complete history of all changes

## API Reference

The server exposes MCP protocol endpoints for:

- Entity management
- Relationship operations
- Search and query
- Audit logging

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

[License information]

## Troubleshooting

### Prisma Binary Compatibility Issues

If you encounter binary compatibility errors when running on different operating systems:

1. Ensure you have the latest version: `npm install`
2. Regenerate Prisma Client: `npx prisma generate`
3. Verify binary targets in `prisma/schema.prisma` include both environments

### Database Connection Issues

- Verify PostgreSQL is running
- Check connection string in `.env`
- Ensure database exists and is accessible

## Changelog

### Recent Updates

- **Cross-platform support**: Added binary targets for Windows and Linux/WSL2 compatibility
- **Dependency optimization**: Moved Prisma to devDependencies for cleaner production builds
- **Enhanced validation**: Improved type safety and validation across all endpoints