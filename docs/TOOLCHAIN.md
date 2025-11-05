# Toolchain Configuration & Pinning

## Overview

This document specifies the exact versions and configurations for all development tools used in the MCP-Cortex project to ensure reproducible builds and consistent development environments.

## Core Toolchain

### Node.js
- **Version**: `25.1.0` (Current)
- **Minimum Required**: `>=18.0.0` (as specified in package.json engines)
- **Recommendation**: Use Node.js 25.x LTS for development and production
- **Memory Configuration**:
  - Development: `--max-old-space-size=4096 --expose-gc`
  - Production: `--max-old-space-size=8192 --max-heap-size=8192 --expose-gc`

### PNPM Package Manager
- **Version**: `10.20.0` (Current)
- **Advantages**:
  - Faster installation times
  - Reduced disk space usage through efficient package sharing
  - Strict dependency management
  - Better security isolation

### TypeScript Compiler
- **Version**: `5.9.3` (Current)
- **Configuration**: See `tsconfig.json` and `tsconfig.build.json`
- **Key Compiler Options**:
  - Target: ES2022
  - Module: ESNext
  - Module Resolution: Node
  - Strict mode enabled
  - Source maps enabled for debugging

## Development Tools

### ESLint (Code Quality)
- **Version**: `9.38.0`
- **TypeScript Parser**: `@typescript-eslint/parser@8.46.1`
- **Plugins**:
  - `@typescript-eslint/eslint-plugin@8.46.1`
  - `eslint-plugin-import@2.32.0`
  - `eslint-plugin-security@3.0.1`
- **Configuration Files**:
  - `eslint.config.cjs` (main configuration)
  - `eslint.security.config.cjs` (security-specific rules)

### Prettier (Code Formatting)
- **Version**: `3.6.2`
- **Configuration**: `.prettierrc.json`
- **Integration**: Automatic formatting on save recommended

### Vitest (Testing Framework)
- **Version**: `4.0.3`
- **Coverage**: `@vitest/coverage-v8@4.0.4`
- **UI**: `@vitest/ui@4.0.4`
- **Configuration Files**:
  - `vitest.config.ts` (unit tests)
  - `vitest.integration.config.ts` (integration tests)
  - `vitest.e2e.config.ts` (end-to-end tests)
  - `vitest.coverage.config.ts` (coverage reporting)
  - `vitest.ci.config.ts` (CI/CD pipeline)

### Husky (Git Hooks)
- **Version**: `9.1.7`
- **Purpose**: Pre-commit hooks for code quality
- **Integration**: Automatic quality checks before commits

## Build Tools

### TypeScript Compiler (tsc)
- **Primary Build Tool**: `tsc`
- **Post-build Fix**: `tsc-esm-fix@3.1.2` for ESM compatibility
- **Build Script**: `npm run build`
- **Watch Mode**: Available for development

### TSX (TypeScript Executor)
- **Version**: `4.20.6`
- **Purpose**: Direct TypeScript execution for development scripts
- **Usage**: Development and debugging scenarios

## Runtime Dependencies

### Core Framework
- **MCP SDK**: `@modelcontextprotocol/sdk@1.0.3`
- **Vector Database**: `@qdrant/js-client-rest@1.13.0`
- **Validation**: `zod@3.25.76`, `ajv@8.12.0`, `ajv-formats@2.1.1`

### Web Framework (Optional)
- **Express**: `express@4.19.2`
- **Security**: `helmet@8.1.0`
- **Authentication**: `jsonwebtoken@9.0.2`, `bcryptjs@3.0.2`

### Utilities
- **Environment**: `dotenv@17.2.3`
- **UUID**: `uuid@13.0.0`
- **CLI**: `commander@12.0.0`
- **Logging**: `pino@10.1.0`

## Environment Setup

### Prerequisites Installation

```bash
# Install Node.js (using version manager recommended)
# Using nvm:
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash
nvm install 25.1.0
nvm use 25.1.0

# Install PNPM
npm install -g pnpm@10.20.0

# Verify installations
node --version  # Should show v25.1.0
pnpm --version  # Should show 10.20.0
```

### Project Setup

```bash
# Clone repository
git clone <repository-url>
cd mcp-cortex

# Install dependencies with exact versions
pnpm install

# Build the project
pnpm run build

# Run tests to verify setup
pnpm run test:ci
```

## Version Locking Strategy

### Package Versions
- All dependencies are pinned to exact versions in `package.json`
- Use `pnpm lockfile` for reproducible installs
- Regular dependency updates should use `pnpm update` with care

### Toolchain Updates
1. **Node.js**: Update quarterly or when security patches are released
2. **TypeScript**: Update monthly for new features and fixes
3. **ESLint/Prettier**: Update when major versions are released
4. **Vitest**: Update quarterly or when testing features are needed

### CI/CD Considerations
- Use exact version matching in all CI environments
- Cache dependencies based on lockfile hash
- Validate toolchain versions in pipeline setup

## IDE Configuration

### Recommended VS Code Extensions
- TypeScript and JavaScript Language Features (built-in)
- ESLint extension
- Prettier extension
- Vitest extension
- GitLens (for enhanced Git functionality)

### VS Code Settings (.vscode/settings.json)
```json
{
  "typescript.preferences.includePackageJsonAutoImports": "on",
  "editor.formatOnSave": true,
  "editor.defaultFormatter": "esbenp.prettier-vscode",
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": "explicit"
  },
  "typescript.suggest.autoImports": true,
  "typescript.updateImportsOnFileMove.enabled": "always"
}
```

## Troubleshooting

### Common Issues

1. **Memory Issues During Build**
   ```bash
   export NODE_OPTIONS="--max-old-space-size=4096 --expose-gc"
   pnpm run build
   ```

2. **TypeScript Compilation Errors**
   ```bash
   pnpm run type-check
   pnpm run lint:fix
   ```

3. **Test Timeouts**
   ```bash
   pnpm run test:ci
   # Or increase timeout in vitest config
   ```

### Version Conflicts
- Always use `pnpm` instead of `npm` to avoid dependency mismatches
- Clear node_modules and reinstall if encountering issues:
  ```bash
  rm -rf node_modules pnpm-lock.yaml
  pnpm install
  ```

## Security Considerations

### Dependency Scanning
- Run `pnpm audit` regularly
- Use `npm audit fix` with caution (review changes)
- CI/CD pipeline includes security audit automation

### Toolchain Security
- Keep all development tools updated
- Review new version releases for security patches
- Use npm scripts for consistent command execution

## Performance Optimization

### Build Performance
- Use TypeScript's incremental compilation
- Enable skipLibCheck for faster builds
- Consider using `tsx` for development script execution

### Test Performance
- Use Vitest's watch mode for development
- Parallel test execution enabled by default
- Coverage reporting optimized for CI environments

---

**Last Updated**: 2025-11-04
**Next Review**: 2025-12-04 (Monthly review recommended)
**Maintainer**: Cortex Development Team