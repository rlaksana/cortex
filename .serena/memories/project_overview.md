# Cortex Memory MCP Project Overview

## Project Identity
- **Name**: Cortex Memory MCP
- **Type**: Model Context Protocol (MCP) Server
- **Purpose**: Knowledge management with autonomous decision support
- **Architecture**: 2-layer (Local Node.js → Docker Qdrant)

## Core Capabilities
- **Memory Store**: Store/update/delete knowledge with 16 types (section, decision, issue, todo, release, risk, etc.)
- **Memory Find**: Search with confidence scoring and autonomous retry logic
- **Knowledge Graph**: Entities, relations, observations with Qdrant backend
- **Autonomous Protocol**: AI-driven decision making for memory operations

## Technical Stack
- **Runtime**: Node.js with ES Modules
- **Database**: Qdrant 18 with Prisma ORM
- **Language**: TypeScript (compiled to JavaScript)
- **MCP SDK**: Model Context Protocol for AI integration
- **Features**: Content deduplication, branch isolation, immutability enforcement

## Current Issues
- **Module Compatibility**: ES Module vs CommonJS conflict in Prisma client
- **Multi-Instance**: Cannot run in multiple Claude Code instances due to import errors
- **Error**: `The requested module '../generated/prisma/index.js' does not provide an export named 'PrismaClient'`

## Development Commands
```bash
npm run lint          # ESLint check
npm run lint:fix      # Auto-fix ESLint issues
npm run type-check    # TypeScript type checking
npm run quality-check # Run lint + type-check
```

## Project Structure
- `src/index.ts` - Main MCP server entry point
- `src/services/` - Memory store/find services
- `src/db/` - Database layer with Prisma
- `prisma/schema.prisma` - Database schema
- `dist/` - Compiled JavaScript output

## Memory Types Supported
section, runbook, change, issue, decision, todo, release_note, ddl, pr_context, incident, release, risk, assumption, entity, relation, observation