# Contributing to Cortex Memory MCP

Thank you for contributing! This guide covers the essential rules and practices for working with this codebase.

## Import Rules (Critical)

This project uses ESM with strict import extension enforcement. **Follow these rules without exception:**

### ✅ Allowed Imports

```typescript
// 1. Relative imports MUST end with .js (even in TypeScript source)
import { ConfigService } from './services/config-service.js';
import { handleError } from '../utils/error-handler.js';

// 2. External packages (no extensions)
import { z } from 'zod';
import { FastifyInstance } from 'fastify';

// 3. Dynamic imports MUST also end with .js
const module = await import('./utils/heavy-computation.js');
```

### ❌ Forbidden Imports

```typescript
// NEVER import relatives without .js extension
import { ConfigService } from './services/config-service'; // ❌ Missing .js
import { handleError } from '../utils/error-handler'; // ❌ Missing .js

// NEVER use deep imports (violates architectural boundaries)
import { InternalClass } from './services/subdir/internal.js'; // ❌ Deep import
```

### Layer Enforcement

- **Public APIs**: Import only through `index.js` barrel exports
- **No package imports**: Relative imports should never use package syntax
- **Architectural boundaries**: Use index files to access other modules

## Before Committing

Always run: `pnpm run check`

This command validates:

1. Import extension compliance (static + dynamic)
2. TypeScript compilation (no type errors)
3. ESLint rules (zero warnings)

## Quick Fix Workflow (30 seconds)

If you get import extension errors:

```bash
# 1. Run the codemod to fix extensionless imports
pnpm run codemod:add-js-extensions

# 2. Let pre-commit handle the rest (auto-fix + formatting)
git add .
git commit -m "your message"
# lint-staged will auto-fix remaining issues
```

**Note**: `chaos-testing/` and other legacy folders are intentionally excluded from linting until scheduled cleanup.

## Getting Started

1. **Install dependencies**: `pnpm install`
2. **Run development**: `pnpm run dev`
3. **Run tests**: `pnpm run test`
4. **Build project**: `pnpm run build`

## Code Style

- ESLint auto-fixes on save in VS Code
- Import sorting follows predefined groups:
  1. Node.js builtins (`node:fs`, `node:path`)
  2. External packages (`zod`, `fastify`)
  3. Internal aliases (`@/*`, `@services/*`)
  4. Relative imports (`./`, `../`)

## Quality Gates

The CI pipeline enforces:

- Zero ESLint warnings (`--max-warnings=0`)
- No TypeScript compilation errors
- No import extension violations
- Runtime smoke test (verifies built modules load correctly)

**Any violation blocks the PR from merging.**

## Need Help?

- Check existing code patterns for guidance
- Ask in discussions or issues for clarification
- When in doubt, run `pnpm run lint:fix` to auto-format

---

_These rules ensure ESM compatibility and maintain clean architecture. Respect them!_
