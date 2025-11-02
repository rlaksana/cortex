# Pre-commit Gate Sequence Implementation

This document describes the implementation of the required pre-commit gate sequence: **type → lint → format/imports → dead-code → complexity**, with proper failure handling and Fix Plan guidance.

## Overview

The MCP Cortex project implements a systematic 5+1 gate sequence that ensures code quality and consistency:

### Required Gates (Blocking)

1. **Type checking** - TypeScript compilation validation
2. **Linting** - ESLint code quality checks
3. **Format/Imports** - Prettier formatting and import ordering

### Advisory Gates (Non-blocking)

4. **Dead code detection** - ts-prune unused export analysis
5. **Complexity analysis** - Code complexity reporting

### Final Gate (Blocking)

6. **Test coverage verification** - Comprehensive test coverage validation

## Implementation Details

### Pre-commit Hook (`.husky/pre-commit`)

The pre-commit hook follows the exact required sequence:

```bash
# Gate 1: Type checking (BLOCKING)
echo "📝 Gate 1: Type checking..."
npm run type-check
if [ $? -ne 0 ]; then
    echo "❌ Type checking failed - Fix Plan:"
    echo "   1. Check TypeScript errors in output above"
    echo "   2. Fix type annotations, missing imports, or interface mismatches"
    echo "   3. Run 'npm run type-check' to verify fixes"
    echo "   ❌ STOPPED: Type checking must pass before proceeding"
    exit 1
fi

# Gate 2: Linting (BLOCKING)
echo "🧹 Gate 2: Linting..."
npm run lint
if [ $? -ne 0 ]; then
    echo "❌ Linting failed - Fix Plan:"
    echo "   1. Check ESLint errors in output above"
    echo "   2. Fix unused variables, missing semicolons, quote styles"
    echo "   3. Run 'npm run lint:fix' for auto-fixable issues"
    echo "   4. Run 'npm run lint' to verify fixes"
    echo "   ❌ STOPPED: Linting must pass before proceeding"
    exit 1
fi

# Gate 3: Format/Imports checking (BLOCKING)
echo "✨ Gate 3: Format and Imports checking..."
npm run format:check
if [ $? -ne 0 ]; then
    echo "❌ Format checking failed - Fix Plan:"
    echo "   1. Run 'npm run format' to auto-fix formatting issues"
    echo "   2. Check import ordering and consistency"
    echo "   3. Run 'npm run lint:imports' to check import order"
    echo "   4. Run 'npm run format:check' to verify fixes"
    echo "   ❌ STOPPED: Formatting must pass before proceeding"
    exit 1
fi

npm run lint:imports
if [ $? -ne 0 ]; then
    echo "❌ Import checking failed - Fix Plan:"
    echo "   1. Check import order violations in output above"
    echo "   2. Reorder imports according to ESLint rules"
    echo "   3. Run 'npm run lint:imports' to verify fixes"
    echo "   ❌ STOPPED: Import order must pass before proceeding"
    exit 1
fi

# Gate 4: Dead code detection (ADVISORY)
echo "🧼 Gate 4: Dead code detection..."
npm run dead-code
if [ $? -ne 0 ]; then
    echo "⚠️  Dead code detected - Fix Plan:"
    echo "   1. Review unused exports in output above"
    echo "   2. Remove unused exports or add '_' prefix to unused parameters"
    echo "   3. Consider if code is needed for external API"
    echo "   4. Re-run 'npm run dead-code' to verify cleanup"
    echo "   ⚠️  WARNING: Dead code should be cleaned up but not blocking"
fi

# Gate 5: Complexity analysis (ADVISORY)
echo "📊 Gate 5: Complexity analysis..."
npm run complexity
if [ $? -ne 0 ]; then
    echo "⚠️  Complexity issues detected - Fix Plan:"
    echo "   1. Review complexity-report.json for high-complexity functions"
    echo "   2. Consider refactoring complex functions (>10 complexity)"
    echo "   3. Break down large functions into smaller, focused ones"
    echo "   4. Re-run 'npm run complexity' to verify improvements"
    echo "   ⚠️  WARNING: High complexity should be refactored but not blocking"
fi

# Final Gate: Test coverage verification (BLOCKING)
echo "🧪 Final Gate: Test coverage verification..."
npm run verify-test-coverage
if [ $? -ne 0 ]; then
    echo "❌ Test coverage verification failed - Fix Plan:"
    echo "   1. Check test coverage errors in output above"
    echo "   2. Add missing test files for protected source code"
    echo "   3. Improve test coverage to meet thresholds (80%+ statements)"
    echo "   4. Run 'npm run verify-test-coverage' to verify fixes"
    echo "   ❌ STOPPED: Test coverage must pass before committing"
    exit 1
fi
```

### CI/CD Pipeline Alignment (`.github/workflows/comprehensive-ci.yml`)

The GitHub Actions `code-quality` job mirrors the pre-commit hook exactly:

```yaml
- name: Gate 1: Type checking
  run: |
    echo "📝 Gate 1: Type checking..."
    if ! npm run type-check; then
      echo "❌ Type checking failed - Fix Plan:"
      echo "   1. Check TypeScript errors in output above"
      echo "   2. Fix type annotations, missing imports, or interface mismatches"
      echo "   3. Run 'npm run type-check' to verify fixes"
      echo "   ❌ STOPPED: Type checking must pass before proceeding"
      exit 1
    fi
    echo "✅ Type checking passed"

# ... [other gates follow same pattern]
```

## Gate Behaviors

### Blocking Gates (Stop on First Failure)

**Gates 1, 2, 3, and Final:**

- **Exit immediately** on failure
- **Provide Fix Plan** with actionable steps
- **Stop execution** of subsequent gates
- **Return clear error messages** with guidance

### Advisory Gates (Continue with Warnings)

**Gates 4 and 5:**

- **Report issues** without stopping
- **Provide Fix Plan** for improvements
- **Continue execution** to subsequent gates
- **Mark as warnings** rather than errors

## Available NPM Scripts

Each gate corresponds to specific NPM scripts:

```json
{
  "type-check": "tsc --noEmit",
  "lint": "eslint src",
  "lint:fix": "eslint src --fix",
  "format:check": "prettier --check \"src/**/*.{ts,js,json,md}\"",
  "format": "prettier --write \"src/**/*.{ts,js,json,md}\"",
  "lint:imports": "eslint src --ext .ts --rule 'import/order: error'",
  "dead-code": "ts-prune -p tsconfig.json",
  "complexity": "complexity-report -o complexity-report.json src/",
  "verify-test-coverage": "node scripts/verify-test-coverage.js"
}
```

## Failure Handling

### Type Checking Failures

- **Common Issues**: Type mismatches, missing imports, interface errors
- **Fix Commands**: `npm run type-check` for detailed errors
- **Auto-fixes**: Limited - usually manual fixes required

### Linting Failures

- **Common Issues**: Unused variables, formatting, quote styles
- **Fix Commands**: `npm run lint:fix` for auto-fixable issues
- **Auto-fixes**: High - many issues auto-fixable

### Format/Import Failures

- **Common Issues**: Inconsistent formatting, import ordering
- **Fix Commands**: `npm run format` and `npm run lint:imports`
- **Auto-fixes**: Very high - mostly automated

### Dead Code Warnings

- **Common Issues**: Unused exports, dead code paths
- **Fix Commands**: `npm run dead-code` for identification
- **Auto-fixes**: Manual - requires developer decision

### Complexity Warnings

- **Common Issues**: High cyclomatic complexity, large functions
- **Fix Commands**: Review `complexity-report.json`
- **Auto-fixes**: Manual - requires refactoring

### Test Coverage Failures

- **Common Issues**: Missing test files, low coverage percentages
- **Fix Commands**: `npm run verify-test-coverage` for detailed analysis
- **Auto-fixes**: Manual - requires writing tests

## Usage Examples

### Running Gates Individually

```bash
# Run specific gate
npm run type-check
npm run lint
npm run format:check
npm run dead-code
npm run complexity
npm run verify-test-coverage
```

### Running Full Gate Sequence

```bash
# Pre-commit hook (automatically runs on git commit)
git add . && git commit -m "feat: new feature"

# Manual gate sequence
npm run quality-check && npm run verify-test-coverage
```

### Fixing Gate Failures

```bash
# Type errors
npm run type-check  # Review errors
# Manual fixes...

# Linting issues
npm run lint:fix    # Auto-fix many issues
npm run lint        # Verify fixes

# Formatting issues
npm run format      # Auto-fix formatting
npm run format:check # Verify fixes

# Import ordering
npm run lint:imports # Check order
# Manual reordering...

# Dead code (review warnings)
npm run dead-code   # Identify unused code
# Manual cleanup...

# Complexity (review warnings)
npm run complexity  # Generate report
# Manual refactoring...

# Test coverage
npm run verify-test-coverage # Detailed analysis
# Add tests...
```

## Gate Success Flow

When all gates pass successfully:

```
🔍 Running pre-commit gate sequence...
📝 Gate 1: Type checking...
✅ Type checking passed
🧹 Gate 2: Linting...
✅ Linting passed
✨ Gate 3: Format and Imports checking...
✅ Format and Imports checking passed
🧼 Gate 4: Dead code detection...
✅ Dead code detection completed
📊 Gate 5: Complexity analysis...
✅ Complexity analysis completed
🧪 Final Gate: Test coverage verification...
✅ Test coverage verification passed

🎉 All pre-commit gates passed successfully!
✅ Ready to commit with confidence!
```

## Gate Failure Flow

When a blocking gate fails:

```
🔍 Running pre-commit gate sequence...
📝 Gate 1: Type checking...
❌ Type checking failed - Fix Plan:
   1. Check TypeScript errors in output above
   2. Fix type annotations, missing imports, or interface mismatches
   3. Run 'npm run type-check' to verify fixes
   ❌ STOPPED: Type checking must pass before proceeding
husky - pre-commit script failed (code 1)
```

## Benefits

### For Developers

- **Consistent Feedback**: Same gate sequence locally and in CI/CD
- **Actionable Fix Plans**: Clear steps to resolve each issue
- **Fast Feedback**: Early detection prevents CI/CD failures
- **Progressive Enhancement**: Advisory gates encourage improvement without blocking

### For Code Quality

- **Type Safety**: Ensures TypeScript compilation
- **Code Consistency**: Standardized formatting and linting
- **Maintainability**: Dead code removal and complexity management
- **Test Coverage**: Comprehensive test verification

### For Team Collaboration

- **Unified Standards**: Same quality gates for all team members
- **Reduced Review Friction**: Automated quality checks
- **Clear Expectations**: Documented requirements and processes
- **Continuous Improvement**: Advisory gates encourage best practices

## Compliance

This implementation satisfies the requirement:

> **"run gates: type → lint → format/imports → dead-code → complexity; stop on first failure and return Fix Plan"**

✅ **Exact Sequence**: type → lint → format/imports → dead-code → complexity
✅ **Stop on First Failure**: Blocking gates exit immediately
✅ **Fix Plan Return**: Each failure includes actionable guidance
✅ **Consistent Implementation**: Same behavior in pre-commit and CI/CD

The implementation ensures code quality while maintaining developer productivity with clear, actionable feedback for every gate failure.
