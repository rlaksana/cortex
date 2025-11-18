# Multi-Level Quality Gates Setup

This document describes the 3-level quality gates implementation for mcp-cortex project.

## LEVEL 1: Pre-commit (Lightweight)

- **Target**: Staged files only
- **Actions**: ESLint + Prettier via lint-staged
- **Duration**: < 10 seconds
- **Focus**: Code formatting and basic linting

### Configuration:

- `.husky/pre-commit`: Runs lint-staged on staged files
- `package.json` lint-staged: ESLint with 5 warnings max, Prettier formatting
- **Excludes**: Test files, chaos-testing, problematic files

## LEVEL 2: Commit Message Validation

- **Target**: Commit message format
- **Actions**: Conventional Commits validation
- **Duration**: < 1 second
- **Focus**: Consistent commit history

### Configuration:

- `.husky/commit-msg`: Validates Conventional Commits format
- **Supported types**: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert
- **Rules**: Max 80 chars, lowercase description, optional scope

## LEVEL 3: Pre-push (Comprehensive)

- **Target**: Changed TypeScript files
- **Actions**: Incremental type-check + unit tests
- **Duration**: 1-3 minutes
- **Focus**: Type safety and basic functionality

### Configuration:

- `.husky/pre-push`: Incremental TypeScript check + unit tests
- **Type-check**: Excludes test files, uses incremental compilation
- **Tests**: Unit tests only (timeout 180s)
- **Security**: Basic audit for high/critical vulnerabilities

## Benefits:

1. **Fast feedback**: Level 1 provides instant feedback
2. **Progressive checking**: Heavier checks only when needed
3. **Developer-friendly**: No blocking on simple formatting issues
4. **Quality assurance**: Type safety before reaching remote

## Usage:

```bash
# Stage changes and commit (LEVEL 1 + 2)
git add .
git commit -m "feat: add new feature"

# Push to remote (LEVEL 3)
git push origin main
```

## Migration Strategy:

- Existing 2238 TypeScript errors are handled gradually
- Level 1 allows commits while fixing errors incrementally
- Level 3 catches type errors before they reach team members
