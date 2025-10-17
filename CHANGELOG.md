# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive README documentation with installation instructions
- Cross-platform installation guide
- Docker deployment instructions
- Troubleshooting section for common issues

### Fixed
- **Cross-platform binary compatibility**: Added binaryTargets to Prisma schema for Windows and Linux/WSL2 support
- Resolves Prisma Client binary mismatch errors when running across different operating systems

### Changed
- **Dependency optimization**: Moved Prisma from dependencies to devDependencies
- Production builds now only include @prisma/client, reducing bundle size
- Prisma CLI is now only available during development

### Security
- Improved dependency management by moving build tools to devDependencies

## [1.0.0] - 2025-10-17

### Added
- Initial release of MCP-Cortex server
- Memory management capabilities
- PostgreSQL backend with Prisma ORM
- Entity, relation, and observation storage
- Advanced search functionality
- Confidence scoring system
- Audit logging for all operations
- Complete TypeScript support
- Comprehensive validation system
- MCP protocol implementation
- Quality gates and ESLint configuration
- Test suite with Vitest
- Development tools and scripts

### Features
- **Memory System**: Store and retrieve knowledge entities with full metadata
- **Relationship Tracking**: Link entities with typed relationships
- **Search Capabilities**: Advanced search with confidence scoring and filtering
- **Audit Trail**: Complete history of all changes with user attribution
- **Cross-Platform**: Support for Windows, Linux, and WSL2 environments
- **Type Safety**: Full TypeScript integration with strict typing
- **Validation**: Comprehensive input validation and error handling
- **Performance**: Optimized queries and efficient data structures

### Database Schema
- Sections table for documentation chunks
- ADR decisions table with status tracking
- Issue logs with external integration support
- Todo tracking with priority and due dates
- Change logs with commit tracking
- Full audit capabilities

### Development Tools
- ESLint configuration with security rules
- TypeScript strict mode
- Automated testing setup
- Pre-commit quality gates
- Database migration tools
- Development scripts and utilities

## Installation Notes

For cross-platform deployment, ensure you regenerate the Prisma Client after installation:

```bash
npm install
npx prisma generate
```

This will generate the appropriate binary targets for your operating system.