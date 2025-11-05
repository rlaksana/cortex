# Development Setup Guide

## Quick Start

### Prerequisites
- **Node.js**: `25.1.0` (minimum `18.0.0`)
- **PNPM**: `10.20.0` (minimum `8.0.0`)
- **Git**: Latest version

### One-Command Setup
```bash
# Clone and setup
git clone <repository-url>
cd mcp-cortex
pnpm install

# Verify toolchain
npm run toolchain:verify

# Build and test
npm run build
npm run test:ci
```

## Detailed Setup

### 1. Install Node.js
```bash
# Using nvm (recommended)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash
nvm install 25.1.0
nvm use 25.1.0

# Verify installation
node --version  # Should show v25.1.0
```

### 2. Install PNPM
```bash
npm install -g pnpm@10.20.0
pnpm --version  # Should show 10.20.0
```

### 3. Clone Repository
```bash
git clone <repository-url>
cd mcp-cortex
```

### 4. Install Dependencies
```bash
pnpm install
```

### 5. Verify Setup
```bash
# Check toolchain versions
npm run toolchain:verify

# Run comprehensive checks
npm run toolchain:check

# Verify build
npm run build

# Run tests
npm run test:ci
```

## Development Workflow

### Making Changes
```bash
# Start development mode
npm run dev:watch

# Or build and run manually
npm run build && npm run dev
```

### Code Quality
```bash
# Format code
npm run format

# Lint code
npm run lint:fix

# Type checking
npm run type-check
```

### Testing
```bash
# Run all tests
npm run test:all

# Run specific test suites
npm run test:unit
npm run test:integration
npm run test:e2e

# Run tests with coverage
npm run test:coverage
```

## Toolchain Management

### Verify Current Toolchain
```bash
npm run toolchain:verify
```

### Update Toolchain
See [TOOLCHAIN.md](./TOOLCHAIN.md) for detailed update procedures.

### Troubleshooting
```bash
# Clean build
rm -rf node_modules dist
pnpm install
npm run build

# Reset toolchain
npm run toolchain:verify
npm run type-check
npm run lint:fix
```

## IDE Configuration

### VS Code
Install recommended extensions:
- TypeScript and JavaScript Language Features
- ESLint extension
- Prettier extension
- Vitest extension

Configure settings (see `.vscode/settings.json`).

## Environment Variables

Create `.env` file for development:
```env
# Database
QDRANT_URL=http://localhost:6333
QDRANT_API_KEY=your-api-key

# OpenAI (optional)
OPENAI_API_KEY=your-openai-key

# Development
NODE_ENV=development
LOG_LEVEL=debug
```

## Next Steps

1. Read [TOOLCHAIN.md](./TOOLCHAIN.md) for detailed toolchain information
2. Check [NEW-ENGINEER-GUIDE.md](./NEW-ENGINEER-GUIDE.md) for project overview
3. Review [API-REFERENCE.md](./API-REFERENCE.md) for API documentation
4. Explore [ARCH-SYSTEM.md](./ARCH-SYSTEM.md) for architecture details

## Support

- **Documentation**: See docs/ directory
- **Issues**: Create GitHub issue
- **Discussions**: Use GitHub Discussions
- **Chat**: Available in Discord/Slack workspace

---

**Related Documentation**:
- [TOOLCHAIN.md](./TOOLCHAIN.md) - Detailed toolchain configuration
- [SETUP-QUICK-START.md](./SETUP-QUICK-START.md) - Quick start guide
- [NEW-ENGINEER-GUIDE.md](./NEW-ENGINEER-GUIDE.md) - Onboarding guide