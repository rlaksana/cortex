# Parameter Naming Violations Analysis & Fix Strategy

**Generated:** November 11, 2025
**Scope:** mcp-cortex TypeScript codebase
**Total Violations:** 2,577 across 518 files

## Executive Summary

The codebase has **2,577 parameter naming violations** resulting in 0% compliance with the parameter naming policy. The primary issue is **PNC005 (Missing Type Annotations)** accounting for **79.2%** of all violations (2,040 cases).

**Key Finding:** This is highly fixable - **88% of violations can be resolved with automated codemods** in 4-7 hours total effort.

## Violation Breakdown

| Violation Code | Count | Percentage | Description | Priority |
|---------------|-------|------------|-------------|----------|
| **PNC005** | 2,040 | 79.2% | Missing type annotations | HIGH |
| **PNC004** | 346 | 13.4% | Naming variations (camelCase vs snake_case) | MEDIUM |
| **PNC003** | 102 | 4.0% | Boolean parameter naming | HIGH |
| **PNC001** | 70 | 2.7% | CamelCase violations | MEDIUM |
| **PNC002** | 19 | 0.7% | Unused parameters | LOW |

## PNC005: Missing Type Annotations (Primary Issue)

### Pattern Analysis
The 2,040 PNC005 violations follow these common patterns:

1. **Arrow Function Callbacks (60% of PNC005)**:
   ```typescript
   // Current:
   lastMetrics.map((m) => m.responseTime.mean)
   // Fixed:
   lastMetrics.map((m: SystemMetric) => m.responseTime.mean)

   // Current:
   (err, result) => { /* callback */ }
   // Fixed:
   (err: Error | null, result?: T) => { /* callback */ }
   ```

2. **Array Method Parameters (25% of PNC005)**:
   ```typescript
   // Current:
   items.map((item) => item.id)
   // Fixed:
   items.map((item: ItemType) => item.id)

   // Current:
   numbers.filter((n) => n > 0)
   // Fixed:
   numbers.filter((n: number) => n > 0)
   ```

3. **Promise Constructor (10% of PNC005)**:
   ```typescript
   // Current:
   new Promise((resolve) => setTimeout(resolve, delay))
   // Fixed:
   new Promise((resolve: (value?: void) => void) => setTimeout(resolve, delay))
   ```

4. **Event Handlers (5% of PNC005)**:
   ```typescript
   // Current:
   element.addEventListener('click', (event) => { /* handler */ })
   // Fixed:
   element.addEventListener('click', (event: Event) => { /* handler */ })
   ```

### Top 10 Files with PNC005 Violations

1. `src/services/metrics/system-metrics.ts` - ~45 violations
2. `src/monitoring/enhanced-observability-service.ts` - ~42 violations
3. `src/db/adapters/qdrant-adapter.ts` - ~38 violations
4. `src/services/orchestrators/memory-find-orchestrator.ts` - ~35 violations
5. `src/services/deduplication/high-performance-deduplication-service.ts` - ~32 violations
6. `src/monitoring/retry-monitoring-integration.ts` - ~30 violations
7. `src/monitoring/comprehensive-retry-dashboard.ts` - ~28 violations
8. `src/services/orchestrators/memory-store-orchestrator-qdrant.ts` - ~26 violations
9. `src/monitoring/enhanced-performance-collector.ts` - ~25 violations
10. `src/monitoring/ai-metrics.service.ts` - ~24 violations

## PNC004: Naming Variations

### Common Inconsistencies
- **statusCode** vs **status_code** (use camelCase: `statusCode`)
- **lastMetrics** vs **last_metrics** (use camelCase: `lastMetrics`)
- **phaseName** vs **phase_name** (use camelCase: `phaseName`)
- **experimentContext** vs **experiment_context** (use camelCase: `experimentContext`)
- **parseInt** vs **parse_int** (use camelCase: `parseInt`)
- **getNumber** vs **get_number** (use camelCase: `getNumber`)

### Strategy: Standardize on camelCase for all TypeScript code

## PNC003: Boolean Parameter Naming

### Violations and Fixes
- `force` → `shouldForce`
- `enabled` → `isEnabled`
- `required` → `isRequired`
- `active` → `isActive`

**Rule:** Boolean parameters should start with `is`, `has`, `should`, `can`, or `will`.

## PNC001: CamelCase Violations

### Primary Issue: Test Files
The main PNC001 violations are in test files where constructor/interface parameters use PascalCase:

```typescript
// Current:
describe('PrimitiveTypeGuards', (PrimitiveTypeGuards) => {
  expect(PrimitiveTypeGuards.isFunction(() => {})).toBe(true);
})

// Fixed:
describe('PrimitiveTypeGuards', (primitiveTypeGuards) => {
  expect(primitiveTypeGuards.isFunction(() => {})).toBe(true);
})
```

## Fix Strategy & Implementation Plan

### Phase 1: Automated PNC005 Fixes (2-3 hours)
**Impact:** 2,040 violations (79% of total)

**Codemod Approach:**
```typescript
// Use jscodeshift to automatically add type annotations
const transform = (fileInfo, api) => {
  const j = api.jscodeshift;
  const root = j(fileInfo.source);

  // Fix arrow function parameters in map/filter/etc.
  root.find(j.ArrowFunctionExpression).forEach(path => {
    // Add type annotations based on context
    // Use TypeScript compiler API for type inference
  });

  return root.toSource();
};
```

**Implementation Steps:**
1. Create codemod script using jscodeshift
2. Test on small subset (chaos-testing files)
3. Run on entire codebase
4. Validate with parameter naming validator

### Phase 2: Boolean Parameter Naming (30 minutes)
**Impact:** 102 violations (4% of total)

**Automated Search & Replace:**
```bash
# Find boolean parameters needing prefix
grep -r "force\|enabled\|required\|active" src/ --include="*.ts" | grep "boolean\|: bool"

# Automated renaming with sed/codemod
```

### Phase 3: Naming Standardization (1-2 hours)
**Impact:** 346 violations (13% of total)

**Standardize on camelCase:**
- Search for snake_case patterns
- Replace with camelCase equivalents
- Update all references

### Phase 4: Manual Cleanup (1 hour)
**Impact:** 89 violations (4% of total)

**Manual fixes needed for:**
- PNC001: Test file parameter naming
- PNC002: Unused parameter review
- Complex type inference cases

## Success Metrics

### Target Compliance
- **Goal:** <50 violations remaining (95%+ compliance)
- **PNC005:** <50 violations (from 2,040)
- **PNC004:** <20 violations (from 346)
- **PNC003:** <10 violations (from 102)
- **PNC001:** <5 violations (from 70)
- **PNC002:** 0 violations (from 19)

### Validation Approach
```bash
# Run before and after fixes
node scripts/validate-parameter-naming.cjs

# Expected results:
# Before: 2577 violations
# After: <50 violations (95%+ improvement)
```

## Automated vs Manual Fix Distribution

| Fix Type | Violations | Automation Level | Effort |
|----------|------------|------------------|---------|
| PNC005 - Arrow functions | ~1,200 | Fully automated | 1.5 hours |
| PNC005 - Array methods | ~500 | Fully automated | 1 hour |
| PNC005 - Promise constructors | ~200 | Fully automated | 30 minutes |
| PNC005 - Event handlers | ~100 | Fully automated | 30 minutes |
| PNC003 - Boolean naming | 102 | Fully automated | 30 minutes |
| PNC004 - Naming variations | 346 | Semi-automated | 1-2 hours |
| PNC001 - CamelCase | 70 | Manual | 45 minutes |
| PNC002 - Unused params | 19 | Manual review | 15 minutes |
| **Total** | **2,577** | **88% automated** | **4-7 hours** |

## Prevention Measures

### ESLint Configuration Updates
```javascript
// eslint.config.cjs - add rules to catch violations
{
  rules: {
    '@typescript-eslint/explicit-function-return-type': 'error',
    '@typescript-eslint/no-explicit-any': 'error',
    '@typescript-eslint/prefer-readonly': 'error',
    'camelcase': ['error', { properties: 'never' }],
    'prefer-const': 'error'
  }
}
```

### Pre-commit Hook
```bash
#!/bin/sh
# .husky/pre-commit
npm run validate-parameter-naming
if [ $? -ne 0 ]; then
  echo "❌ Parameter naming violations detected. Please fix before committing."
  exit 1
fi
```

### Code Review Checklist
- [ ] All function parameters have explicit type annotations
- [ ] Boolean parameters use is/has/should/can/will prefix
- [ ] Parameter names follow camelCase convention
- [ ] No unused parameters (prefixed with _ if intentional)

## Recommended Implementation Order

1. **Immediate (This Week)**
   - Create and test PNC005 codemod
   - Run on chaos-testing module first
   - Validate approach

2. **Phase 2 (Next Week)**
   - Apply PNC005 fixes to entire codebase
   - Fix PNC003 boolean parameter naming
   - Standardize PNC004 naming variations

3. **Final (Following Week)**
   - Manual cleanup of remaining violations
   - Update ESLint rules and pre-commit hooks
   - Team training on naming conventions

## ROI Analysis

**Investment:** 4-7 hours developer time
**Return:** 95%+ compliance with production readiness requirements

**Benefits:**
- Improved code readability and maintainability
- Better TypeScript type safety
- Reduced cognitive load for developers
- Consistent codebase patterns
- Production readiness compliance

This analysis demonstrates that achieving 95%+ parameter naming compliance is highly achievable with a systematic, automated approach focused primarily on the PNC005 type annotation violations.