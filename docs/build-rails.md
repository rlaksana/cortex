# TypeScript Build Rails & Type Safety Guide

**Comprehensive guide for maintaining type safety, configuration hierarchy, and development workflow.**

## Table of Contents

1. [Configuration Hierarchy](#configuration-hierarchy)
2. [Strict Type Checking](#strict-type-checking)
3. [ESLint Rules & Gates](#eslint-rules--gates)
4. [Type Guard Patterns](#type-guard-patterns)
5. [Discriminated Unions](#discriminated-unions)
6. [Zod Validation](#zod-validation)
7. [Adding New Types](#adding-new-types)
8. [Development Workflow](#development-workflow)

---

## Configuration Hierarchy

### TypeScript Configuration Structure

The project uses a hierarchical TypeScript configuration system:

```
tsconfig.base.json          # Base configuration for all environments
├── tsconfig.json          # Development configuration
├── tsconfig.build.json    # Build configuration (permissive)
├── tsconfig.production.json # Production configuration (strictest)
└── tsconfig.test.json     # Test configuration
```

### Base Configuration (`tsconfig.base.json`)

```json
{
  "compilerOptions": {
    // Target and Module Settings
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],

    // Base Strict Type Checking
    "strict": true,
    "strictNullChecks": true,
    "noImplicitAny": true,
    "strictFunctionTypes": true,
    "strictBindCallApply": true,
    "noImplicitThis": true,
    "alwaysStrict": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,

    // Disabled for compatibility (enabled in production)
    "strictPropertyInitialization": false,
    "noUncheckedIndexedAccess": false,
    "noPropertyAccessFromIndexSignature": false,
    "useUnknownInCatchVariables": false,
    "noImplicitOverride": false,
    "exactOptionalPropertyTypes": false,

    // Path Mappings (authoritative source)
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"],
      "@/types/*": ["src/types/*"],
      "@/services/*": ["src/services/*"],
      "@/config/*": ["src/config/*"],
      "@/utils/*": ["src/utils/*"],
      "@/schemas/*": ["src/schemas/*"],
      "@/middleware/*": ["src/middleware/*"],
      "@/db/*": ["src/db/*"],
      "@/monitoring/*": ["src/monitoring/*"]
    }
  }
}
```

### Development Configuration (`tsconfig.json`)

```json
{
  "extends": "./tsconfig.base.json",
  "compilerOptions": {
    // Development-specific features
    "downlevelIteration": true,
    "noUnusedLocals": false,  // Allow for debugging
    "noUnusedParameters": false,  // Allow for debugging
    "noEmit": false,
    "sourceMap": true,
    "noEmitOnError": true
  }
}
```

### Production Configuration (`tsconfig.production.json`)

```json
{
  "extends": "./tsconfig.base.json",
  "compilerOptions": {
    // Enhanced strict type checking for production
    "strictPropertyInitialization": true,
    "noUncheckedIndexedAccess": true,
    "noPropertyAccessFromIndexSignature": true,
    "useUnknownInCatchVariables": true,
    "noImplicitOverride": true,
    "exactOptionalPropertyTypes": true,

    // Production optimizations
    "declaration": true,
    "sourceMap": false,
    "incremental": false,
    "removeComments": true,
    "stripInternal": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "lib": ["ES2022"]  // Remove DOM for server-side
  }
}
```

### Build Configuration (`tsconfig.build.json`)

```json
{
  "compilerOptions": {
    // Very permissive settings for script optimization
    "strict": false,
    "noImplicitAny": false,
    "strictNullChecks": false,
    "noEmitOnError": false,
    "allowUnreachableCode": true,
    "allowUnusedLabels": true
  }
}
```

---

## Strict Type Checking

### Levels of Strictness

1. **Development**: Base strictness with relaxed rules for debugging
2. **Production**: Maximum strictness for safety
3. **Build**: Permissive for script optimization

### Key Strict Settings Explained

| Setting | Purpose | Environment |
|---------|---------|-------------|
| `strictPropertyInitialization` | Ensures class properties are initialized | Production |
| `noUncheckedIndexedAccess` | Prevents unsafe array/object access | Production |
| `noPropertyAccessFromIndexSignature` | Forces explicit property access | Production |
| `useUnknownInCatchVariables` | Uses `unknown` instead of `any` in catch | Production |
| `exactOptionalPropertyTypes` | Strict optional property checking | Production |
| `noImplicitOverride` | Requires `override` keyword for method overrides | Production |

### Migration Path

Use the `scripts/ts-fix-*.mjs` utilities to gradually enable stricter settings:

```bash
# Enable property initialization checks
npm run codemod:properties

# Fix type issues
npm run codemod:types

# Comprehensive fix
npm run ts-fix-all
```

---

## ESLint Rules & Gates

### Configuration Files

```
eslint.config.cjs              # Development configuration
├── eslint.production.config.cjs  # Production (strictest)
└── eslint.security.config.cjs    # Security-focused rules
```

### Key Type Safety Rules

#### Core TypeScript Rules

```javascript
// Prevent `any` usage
'@typescript-eslint/no-explicit-any': ['error', {
  'fixToUnknown': true,
  'ignoreRestArgs': false
}],

// Prevent unsafe operations on `any` values
'@typescript-eslint/no-unsafe-assignment': 'error',
'@typescript-eslint/no-unsafe-member-access': 'error',
'@typescript-eslint/no-unsafe-call': 'error',
'@typescript-eslint/no-unsafe-return': 'error',

// Consistent type imports
'@typescript-eslint/consistent-type-imports': 'error',

// Prevent unnecessary type assertions
'@typescript-eslint/no-unnecessary-type-assertion': 'error',

// Modern TypeScript features
'@typescript-eslint/prefer-nullish-coalescing': 'error',
'@typescript-eslint/prefer-optional-chain': 'error',
```

#### Quality Gates

```javascript
// Unused imports and variables
'unused-imports/no-unused-imports': 'error',
'@typescript-eslint/no-unused-vars': ['error', {
  'argsIgnorePattern': '^_',
  'varsIgnorePattern': '^_',
  'caughtErrorsIgnorePattern': '^_'
}],

// Enforce best practices
'prefer-const': 'error',
'no-var': 'error',
'prefer-arrow-callback': 'error',
'prefer-template': 'error',

// Prevent errors
'no-debugger': 'error',
'no-console': 'warn',  // 'error' in production
'no-eval': 'error',
'no-implied-eval': 'error',
```

### Gate Scripts

#### Quality Gates (`package.json`)

```json
{
  "scripts": {
    "gate:tsc": "tsc --noEmit",
    "gate:eslint": "eslint . --max-warnings 0",
    "gate:fmt": "prettier --check .",
    "check": "tsc -p tsconfig.test.json --noEmit && eslint . --max-warnings=0",
    "check:strict": "npm run check && npm run test:coverage && npm run security",
    "check:ci": "CI=true npm run check:strict"
  }
}
```

#### Pre-commit Hook

```json
{
  "scripts": {
    "precommit": "npm run gate:fmt && npm run gate:eslint && npm run gate:tsc"
  }
}
```

### Automated Fixes

```bash
# Fix import issues
npm run fix:imports

# Fix common TypeScript issues
npm run codemod:types

# Fix ESLint issues
npm run lint:fix
```

---

## Type Guard Patterns

### Comprehensive Type Guard Framework

The project includes a comprehensive type guard system at `src/utils/type-guards.ts`:

#### Primitive Type Guards

```typescript
import { PrimitiveTypeGuards } from '@/utils/type-guards';

// String validation
if (PrimitiveTypeGuards.isString(value)) {
  // value is typed as string
}

// Number validation with NaN protection
if (PrimitiveTypeGuards.isNumber(value)) {
  // value is typed as number (not NaN, finite)
}

// Non-nullish check
if (PrimitiveTypeGuards.isNotNullish(value)) {
  // value is typed as T (not null or undefined)
}
```

#### Object Type Guards

```typescript
import { ObjectTypeGuards } from '@/utils/type-guards';

// Plain object validation
if (ObjectTypeGuards.isPlainObject<{ name: string }>(value)) {
  // value is typed as Record<string, unknown> initially
}

// Array with element validation
if (ObjectTypeGuards.isArray(value, PrimitiveTypeGuards.isString)) {
  // value is typed as string[]
}

// Property existence checking
if (ObjectTypeGuards.hasProperties<{ id: string; name: string }>(
  obj,
  ['id', 'name']
)) {
  // obj is typed as { id: string; name: string }
}
```

#### Safe Property Access

```typescript
import { SafePropertyAccess } from '@/utils/type-guards';

// Nested property access with defaults
const title = SafePropertyAccess.getString(data, 'metadata.title', 'Default Title');

// Array property access
const tags = SafePropertyAccess.getArray<string>(data, 'tags', []);

// Property existence check
if (SafePropertyAccess.has(data, 'user.profile.email')) {
  // Safe to access nested property
}
```

#### API Response Type Guards

```typescript
import { ApiTypeGuards } from '@/utils/type-guards';

// API response validation
if (ApiTypeGuards.isApiResponse(response, PrimitiveTypeGuards.isString)) {
  // response.data is typed as string
  console.log(response.success, response.data);
}

// Paginated response validation
if (ApiTypeGuards.isPaginatedResponse(response, itemGuard)) {
  // response.items is typed as T[]
  // response.pagination has proper typing
}
```

### Custom Type Guards

#### Creating Type Guards

```typescript
// Simple type guard
function isValidUser(value: unknown): value is User {
  return (
    ObjectTypeGuards.isPlainObject(value) &&
    PrimitiveTypeGuards.isString(value.id) &&
    PrimitiveTypeGuards.isString(value.email) &&
    ObjectTypeGuards.isDate(value.createdAt)
  );
}

// Complex type guard with validation
function isValidSearchResult(value: unknown): value is SearchResult {
  return (
    ObjectTypeGuards.isPlainObject(value) &&
    PrimitiveTypeGuards.isString(value.id) &&
    PrimitiveTypeGuards.isNumber(value.score) &&
    ObjectTypeGuards.isArray(value.documents, isValidDocument)
  );
}
```

#### Type Guard Utilities

```typescript
import { TypeUtils } from '@/utils/type-guards';

// Chaining type guards
const isStringArray = TypeUtils.chain(
  ObjectTypeGuards.isArray,
  (arr: unknown[]): arr is string[] => arr.every(PrimitiveTypeGuards.isString)
);

// Optional type guard
const optionalString = TypeUtils.optional(PrimitiveTypeGuards.isString);
// Returns true for string or undefined

// Negated type guard
const notString = TypeUtils.not(PrimitiveTypeGuards.isString);
// Returns true for anything except string
```

---

## Discriminated Unions

### Pattern Overview

Discriminated unions provide type-safe handling of different object shapes:

```typescript
// Base knowledge item with discriminated kind
type KnowledgeItem =
  | { kind: 'section'; data: SectionData; scope: Scope }
  | { kind: 'runbook'; data: RunbookData; scope: Scope }
  | { kind: 'decision'; data: DecisionData; scope: Scope }
  | { kind: 'incident'; data: IncidentData; scope: Scope };
```

### Implementation with Zod

```typescript
// Discriminated union schema
export const KnowledgeItemSchema = z.discriminatedUnion('kind', [
  SectionSchema,
  RunbookSchema,
  DecisionSchema,
  IncidentSchema,
  // ... other schemas
]);

// Type inference from schema
export type KnowledgeItem = z.infer<typeof KnowledgeItemSchema>;
```

### Type-Safe Handling

```typescript
function processKnowledgeItem(item: KnowledgeItem): void {
  switch (item.kind) {
    case 'section':
      // item.data is typed as SectionData
      console.log('Processing section:', item.data.title);
      break;

    case 'runbook':
      // item.data is typed as RunbookData
      console.log('Processing runbook:', item.data.service);
      break;

    case 'decision':
      // item.data is typed as DecisionData
      console.log('Processing decision:', item.data.outcome);
      break;

    default:
      // TypeScript ensures exhaustive checking
      const _exhaustiveCheck: never = item;
      throw new Error(`Unhandled kind: ${_exhaustiveCheck.kind}`);
  }
}
```

### Adding New Types

1. **Define the schema**:
```typescript
export const NewTypeDataSchema = z.object({
  // Define required fields
  id: z.string().uuid(),
  title: z.string().min(1),
  // ... other fields
}).strict();

export const NewTypeSchema = z.object({
  kind: z.literal('new-type'),
  scope: ScopeSchema,
  data: NewTypeDataSchema,
  tags: z.record(z.unknown()).optional(),
  source: SourceSchema.optional(),
}).strict();
```

2. **Add to discriminated union**:
```typescript
export const KnowledgeItemSchema = z.discriminatedUnion('kind', [
  // ... existing schemas
  NewTypeSchema,  // Add new schema
]);
```

3. **Update processing functions**:
```typescript
function processKnowledgeItem(item: KnowledgeItem): void {
  switch (item.kind) {
    // ... existing cases
    case 'new-type':
      // item.data is typed as NewTypeData
      console.log('Processing new type:', item.data.title);
      break;
  }
}
```

---

## Zod Validation

### Schema Definition Patterns

#### Base Schemas

```typescript
import { z } from 'zod';

// Reusable base schemas
export const ScopeSchema = z.object({
  org: z.string().optional(),
  project: z.string().min(1, 'project is required'),
  branch: z.string().min(1, 'branch is required'),
}).strict();

export const SourceSchema = z.object({
  actor: z.string().optional(),
  tool: z.string().optional(),
  timestamp: z.string().datetime().optional(),
}).strict();
```

#### Complex Object Schema

```typescript
export const SectionDataSchema = z
  .object({
    id: z.string().uuid().optional(),
    title: z.string()
      .min(1, 'title is required')
      .max(500, 'title must be 500 characters or less'),
    body_md: z.string().optional(),
    body_text: z.string().optional(),
    heading: z.string()
      .min(1, 'heading is required')
      .max(300, 'heading must be 300 characters or less'),
  })
  .strict()
  .refine(
    (data) => data.body_md ?? data.body_text,
    {
      message: 'Either body_md or body_text must be provided',
      path: ['body_md'],  // Error path
    }
  );
```

#### Array Schema with Validation

```typescript
export const RunbookDataSchema = z.object({
  service: z.string().min(1).max(200),
  steps: z.array(
    z.object({
      step_number: z.number().int().positive(),
      description: z.string().min(1),
      command: z.string().optional(),
      expected_outcome: z.string().optional(),
    }).strict()
  ).min(1, 'At least one step is required'),
}).strict();
```

### Validation Patterns

#### Safe Parsing

```typescript
import { KnowledgeItemSchema } from '@/schemas/knowledge-types';

// Safe parsing with detailed errors
const result = KnowledgeItemSchema.safeParse(input);
if (!result.success) {
  console.error('Validation errors:', result.error.errors);
  // Handle errors...
} else {
  // result.data is properly typed
  processKnowledgeItem(result.data);
}
```

#### Custom Validation

```typescript
export const CustomSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  confirmPassword: z.string(),
}).refine(
  (data) => data.password === data.confirmPassword,
  {
    message: "Passwords don't match",
    path: ['confirmPassword'],
  }
);
```

#### Transformations

```typescript
export const DateSchema = z.string().datetime().transform(
  (dateString) => new Date(dateString)
);

export const NumberFromStringSchema = z.string().transform(
  (str, ctx) => {
    const num = Number(str);
    if (isNaN(num)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Not a number",
      });
      return z.NEVER;
    }
    return num;
  }
);
```

### Integration with Type Guards

```typescript
import { ZodTypeGuards } from '@/utils/type-guards';

// Create type guard from Zod schema
const isKnowledgeItem = ZodTypeGuards.fromSchema(KnowledgeItemSchema);

// Use with type guards
if (isKnowledgeItem(value)) {
  // value is typed as KnowledgeItem
  processKnowledgeItem(value);
}

// Validate array items
const { valid, invalid } = ZodTypeGuards.validateArray(
  KnowledgeItemSchema,
  unknownItems
);
```

---

## Adding New Types

### Step-by-Step Process

#### 1. Define the Type Interface

```typescript
// src/types/new-type.types.ts
export interface NewTypeData {
  id: string;
  title: string;
  description?: string;
  metadata: Record<string, unknown>;
  createdAt: Date;
}

export interface NewType {
  kind: 'new-type';
  scope: Scope;
  data: NewTypeData;
  tags?: Record<string, unknown>;
  source?: Source;
}
```

#### 2. Create Zod Schema

```typescript
// src/schemas/new-type.schema.ts
export const NewTypeDataSchema = z.object({
  id: z.string().uuid(),
  title: z.string().min(1).max(200),
  description: z.string().optional(),
  metadata: z.record(z.unknown()),
  createdAt: z.date(),
}).strict();

export const NewTypeSchema = z.object({
  kind: z.literal('new-type'),
  scope: ScopeSchema,
  data: NewTypeDataSchema,
  tags: z.record(z.unknown()).optional(),
  source: SourceSchema.optional(),
}).strict();
```

#### 3. Add to Discriminated Union

```typescript
// src/schemas/knowledge-types.ts
export const KnowledgeItemSchema = z.discriminatedUnion('kind', [
  // ... existing schemas
  NewTypeSchema,  // Add the new schema
]);

// Export updated type
export type KnowledgeItem = z.infer<typeof KnowledgeItemSchema>;
```

#### 4. Add Type Guard

```typescript
// src/utils/type-guards.ts
export const KnowledgeTypeGuards = {
  // ... existing guards

  isNewType(_value: unknown): value is NewType {
    return (
      ObjectTypeGuards.isPlainObject(value) &&
      PrimitiveTypeGuards.isString(value.kind) &&
      value.kind === 'new-type' &&
      ObjectTypeGuards.isPlainObject(value.data) &&
      ObjectTypeGuards.hasProperties(value.data, ['id', 'title'])
    );
  },
};
```

#### 5. Update Processing Logic

```typescript
// src/services/knowledge-processor.ts
function processKnowledgeItem(item: KnowledgeItem): void {
  switch (item.kind) {
    // ... existing cases
    case 'new-type':
      processNewType(item);
      break;
  }
}

function processNewType(item: Extract<KnowledgeItem, { kind: 'new-type' }>): void {
  // item.data is typed as NewTypeData
  console.log('Processing new type:', item.data.title);
}
```

#### 6. Add Tests

```typescript
// src/schemas/__tests__/new-type.test.ts
import { NewTypeSchema } from '../new-type.schema';

describe('NewTypeSchema', () => {
  it('should validate valid new type', () => {
    const validData = {
      kind: 'new-type',
      scope: {
        project: 'test-project',
        branch: 'main',
      },
      data: {
        id: '123e4567-e89b-12d3-a456-426614174000',
        title: 'Test New Type',
        metadata: {},
        createdAt: new Date(),
      },
    };

    expect(NewTypeSchema.parse(validData)).toEqual(validData);
  });

  it('should reject invalid data', () => {
    const invalidData = {
      kind: 'new-type',
      scope: {},
      data: {
        // Missing required fields
      },
    };

    expect(() => NewTypeSchema.parse(invalidData)).toThrow();
  });
});
```

### Validation Checklist

- [ ] Type interface defined
- [ ] Zod schema created with validation
- [ ] Added to discriminated union
- [ ] Type guard implemented
- [ ] Processing logic updated
- [ ] Tests written and passing
- [ ] Documentation updated
- [ ] ESLint rules passing

---

## Development Workflow

### Daily Development

#### 1. Start Development

```bash
# Install dependencies
npm install

# Start development with watch mode
npm run dev:watch

# Or build and start
npm run build && npm run dev
```

#### 2. Type Safety Checks

```bash
# Quick type check
npm run gate:tsc

# Full lint check
npm run check

# Format code
npm run format

# Run tests
npm run test
```

#### 3. Before Commit

```bash
# Run all gates (automatically runs in pre-commit hook)
npm run precommit

# Full quality check
npm run check:strict

# Security audit
npm run security
```

### CI/CD Pipeline

#### Quality Gates in CI

```bash
# CI quality check
npm run check:ci

# Equivalent to:
npm run gate:tsc &&          # TypeScript compilation
npm run gate:eslint &&       # ESLint rules
npm run gate:fmt &&          # Code formatting
npm run test:coverage &&     # Test coverage
npm run security             # Security audit
```

#### Coverage Requirements

- **Global**: 80% coverage minimum
- **Services**: 85% coverage minimum
- **Utilities**: 90% coverage minimum

### Type Error Resolution Workflow

#### 1. Identify Error Type

```bash
# Get detailed TypeScript errors
npx tsc --noEmit --pretty

# Get ESLint errors
npx eslint . --max-warnings 0
```

#### 2. Choose Fix Strategy

| Error Type | Fix Strategy | Tool |
|------------|--------------|------|
| Missing imports | `npm run fix:imports` | Automated script |
| `any` types | `npm run codemod:types` | Automated script |
| Property access | Add type guards | Manual |
| Missing properties | Update interfaces | Manual |
| Unsafe operations | Add validation | Manual |

#### 3. Apply Fixes

```bash
# Fix import issues
npm run fix:imports

# Fix type issues automatically
npm run codemod:types

# Fix property access patterns
npm run codemod:properties

# Comprehensive fix (may need manual review)
npm run ts-fix-all
```

#### 4. Validate Fixes

```bash
# Check TypeScript compilation
npm run gate:tsc

# Check ESLint rules
npm run gate:eslint

# Run tests to ensure no regressions
npm run test
```

### Migration Path for Legacy Code

#### Phase 1: Enable Base Strictness

```bash
# Enable base strict mode (already done)
npm run ts-fix-basic

# Fix immediate type issues
npm run codemod:types
```

#### Phase 2: Add Type Guards

```bash
# Identify untyped external data
npm run audit:external-types

# Add type guards for external data
# Manual process using src/utils/type-guards.ts
```

#### Phase 3: Enable Production Strictness

```bash
# Enable production strict mode
npm run ts-enable-production-strict

# Fix remaining issues
npm run ts-fix-high-severity
```

### Performance Considerations

#### Build Performance

- **Development**: Use `tsconfig.json` for faster builds
- **Production**: Use `tsconfig.production.json` for maximum safety
- **CI**: Use `tsconfig.test.json` with mocked dependencies

#### Runtime Validation

```typescript
// Use Zod for external data validation
const parsedData = ExternalDataSchema.parse(rawData);

// Use type guards for performance-critical paths
if (FastTypeGuard.isType(value)) {
  // Fast path for common cases
} else {
  // Full validation for edge cases
  const parsed = FullSchema.parse(value);
}
```

### Best Practices

#### Do's

- ✅ Use discriminated unions for different object types
- ✅ Add type guards for all external data
- ✅ Use Zod schemas for runtime validation
- ✅ Enable strict mode in production
- ✅ Write tests for all new types
- ✅ Use the automated fix scripts
- ✅ Run quality gates before commits

#### Don'ts

- ❌ Use `any` type without justification
- ❌ Suppress TypeScript errors without fixing root cause
- ❌ Skip type guards for external APIs
- ❌ Ignore ESLint type safety rules
- ❌ Commit code that fails quality gates
- ❌ Use type assertions instead of proper type guards

---

## Emergency Procedures

### Breaking Type Changes

1. **Identify affected files**:
```bash
npx tsc --noEmit | grep "error TS"
```

2. **Use automated fixes**:
```bash
npm run ts-fix-all
```

3. **Manual fixes for remaining issues**:
   - Add missing properties to interfaces
   - Update type guards
   - Fix external data validation

4. **Validate fixes**:
```bash
npm run check:strict
```

### Rollback Procedures

If type changes break the build:

```bash
# Revert TypeScript changes
git checkout HEAD~1 -- tsconfig*.json src/types/ src/schemas/

# Revert ESLint changes
git checkout HEAD~1 -- eslint.config.cjs

# Rebuild with working configuration
npm run clean && npm run build
```

### Emergency Mode

For urgent fixes that need to bypass type safety:

```bash
# Use build configuration (permissive)
npm run build

# Document the bypass with @ts-ignore comments
// @ts-ignore: Emergency bypass for production fix
const bypassedCode = anyValue as SomeType;

// Create follow-up ticket to fix properly
```

---

## Resources

### Documentation

- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [Zod Documentation](https://zod.dev/)
- [ESLint TypeScript Rules](https://typescript-eslint.io/rules/)

### Tools

- **TypeScript Compiler**: `tsc`
- **ESLint**: `eslint .`
- **Prettier**: `prettier .`
- **Vitest**: `npm run test`

### Scripts

- `npm run check`: Full quality check
- `npm run gate:tsc`: TypeScript compilation check
- `npm run gate:eslint`: ESLint rules check
- `npm run fix:imports`: Fix import issues
- `npm run codemod:types`: Fix type issues
- `npm run ts-fix-all`: Comprehensive TypeScript fixes

Remember: Type safety is not just about preventing errors—it's about making the codebase more maintainable, self-documenting, and resilient to change. Use these patterns and tools to build robust, type-safe applications.