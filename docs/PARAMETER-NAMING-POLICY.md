# Parameter Naming Policy Enforcement Guide

This document outlines the comprehensive parameter naming policy enforcement strategy for the mcp-cortex project, designed to eliminate the 19,159 TypeScript errors and maintain high code quality standards.

## 🎯 Overview

The parameter naming policy enforcement strategy includes:

1. **ESLint Rules** - Automated code quality checks
2. **Git Hooks** - Pre-commit and pre-push validations
3. **CI/CD Gates** - Build pipeline enforcement
4. **Development Workflow** - Local development tools
5. **Team Training** - Guidelines and best practices

## 📋 Current Error Analysis

Based on the latest analysis:

- **Total TypeScript Errors:** 19,159
- **Major Error Codes:**
  - TS2304 (Cannot find name): 11,274 errors
  - TS18046 (Object possibly undefined): 1,209 errors
  - TS7006 (Implicit any): 1,007 errors
  - TS2551 (Property does not exist): 746 errors

## 🔧 ESLint Configuration

### Core Naming Convention Rules

```javascript
'@typescript-eslint/naming-convention': ['error', {
  // Variable and function naming
  'variable': ['camelCase', 'UPPER_CASE'],
  'function': ['camelCase'],

  // Parameter naming - strict enforcement
  'parameter': [
    'camelCase',
    {
      'filter': {
        'regex': '^(id|_|ev|cb|next)$',
        'match': false
      }
    }
  ],

  // Property and method naming
  'property': ['camelCase'],
  'method': ['camelCase'],

  // Type-related naming
  'typeLike': ['PascalCase'],
  'interface': ['PascalCase', { 'prefix': ['I'] }],
  'typeAlias': ['PascalCase'],
  'enum': ['PascalCase'],
  'enumMember': ['UPPER_CASE'],
  'class': ['PascalCase']
}]
```

### Additional Parameter-Specific Rules

```javascript
// Type safety enforcement
'@typescript-eslint/no-inferrable-types': 'error',
'@typescript-eslint/prefer-readonly': 'error',
'@typescript-eslint/prefer-as-const': 'error',

// Strict boolean and null handling
'@typescript-eslint/strict-boolean-expressions': 'error',
'@typescript-eslint/no-non-null-assertion': 'error',
'@typescript-eslint/prefer-nullish-coalescing': 'error',
'@typescript-eslint/prefer-optional-chain': 'error',

// Parameter reassignment prevention
'no-param-reassign': ['error', {
  'props': false,
  'ignorePropertyModificationsFor': ['config', 'options', 'params']
}]
```

## 🪝 Git Hooks

### Pre-commit Hook

The pre-commit hook enforces parameter naming policy before any commit:

```bash
# Parameter naming validation
echo "🔍 Running parameter naming policy validation..."
node scripts/validate-parameter-naming.js src/

# Check for anti-patterns in staged files
STAGED_TS_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.ts$')
if [ -n "$STAGED_TS_FILES" ]; then
  # Check for non-descriptive parameter names
  # Check for missing type annotations
fi
```

### Pre-push Hook

The pre-push hook performs comprehensive validation:

```bash
# TypeScript error analysis
TS2304_COUNT=$(echo "$TS_ERRORS" | grep -c "TS2304" || echo 0)
TS18046_COUNT=$(echo "$TS_ERRORS" | grep -c "TS18046" || echo 0)
TS7006_COUNT=$(echo "$TS_ERRORS" | grep -c "TS7006" || echo 0)
TS2551_COUNT=$(echo "$TS_ERRORS" | grep -c "TS2551" || echo 0)

# Error thresholds
TS2304_THRESHOLD=100
TS18046_THRESHOLD=50
TS7006_THRESHOLD=100
TS2551_THRESHOLD=200
TOTAL_THRESHOLD=500
```

## 🚀 CI/CD Pipeline Enforcement

### GitHub Actions Workflow

The CI pipeline includes parameter naming validation:

```yaml
- name: Run TypeScript compiler with strict parameter checking
  run: |
    npx tsc --noEmit --strict --noImplicitReturns --noUnusedLocals --noUnusedParameters

    # Count specific error types
    TS2304=$(grep -c "TS2304" ts-errors.log)
    TS18046=$(grep -c "TS18046" ts-errors.log)
    TS7006=$(grep -c "TS7006" ts-errors.log)
    TS2551=$(grep -c "TS2551" ts-errors.log)

    # Fail if thresholds exceeded
    if [ $TOTAL_ERRORS -gt 500 ]; then
      exit 1
    fi
```

### Build Gate Requirements

- **TS2304 errors:** Must be ≤ 100
- **TS18046 errors:** Must be ≤ 50
- **TS7006 errors:** Must be ≤ 100
- **TS2551 errors:** Must be ≤ 200
- **Total errors:** Must be ≤ 500

## 🛠️ Development Workflow

### Local Development Commands

```bash
# Run parameter naming validation
npm run validate:naming

# Check naming convention violations
npm run lint:naming

# Generate compliance report
npm run report:naming

# Fix common issues automatically
npm run codemod:types
```

### VS Code Integration

The project includes VS Code settings for parameter naming:

- **Inlay hints:** Show parameter names and types
- **Auto-fix:** Automatic ESLint fixes on save
- **Semantic highlighting:** Visual distinction for parameters
- **Code lens:** Enhanced navigation and references

### Validation Scripts

#### Parameter Naming Validator

```bash
node scripts/validate-parameter-naming.js src/
```

Features:
- Scans all TypeScript files
- Validates camelCase naming
- Checks for descriptive names
- Identifies inconsistent patterns
- Generates detailed violation reports

#### Compliance Report Generator

```bash
node scripts/generate-naming-report.js
```

Features:
- Analyzes current error trends
- Compares with previous reports
- Provides actionable recommendations
- Tracks compliance metrics

## 📚 Parameter Naming Guidelines

### 1. Use camelCase

```typescript
// ✅ Good
function getUserData(userId: string, includeProfile: boolean) {}

// ❌ Bad
function get_user_data(user_id: string, include_profile: boolean) {}
```

### 2. Be Descriptive

```typescript
// ✅ Good
function processUserAuthentication(authToken: string, rememberDevice: boolean) {}

// ❌ Bad
function processUserAuth(token: string, flag: boolean) {}
```

### 3. Add Type Annotations

```typescript
// ✅ Good
function createUser(userData: CreateUserRequest): Promise<User> {}

// ❌ Bad
function createUser(userData) {}
```

### 4. Use Consistent Patterns

```typescript
// ✅ Good - Consistent across similar functions
function findUserById(userId: string): Promise<User | null>
function findDocumentById(documentId: string): Promise<Document | null>
function findSessionById(sessionId: string): Promise<Session | null>

// ❌ Bad - Inconsistent naming
function findUserById(userId: string): Promise<User | null>
function getDocument(docId: string): Promise<Document | null>
function retrieveSession(session_identifier: string): Promise<Session | null>
```

### 5. Handle Optional Parameters

```typescript
// ✅ Good
function updateUser(
  userId: string,
  updates: Partial<UserUpdates>,
  options?: UpdateOptions
): Promise<User> {}

// ❌ Bad
function updateUser(id, updates, opts) {}
```

## 🎓 Error Types and Solutions

### TS2304: Cannot find name

**Causes:**
- Missing imports
- Incorrect module references
- Typos in variable names

**Solutions:**
```typescript
// Add missing imports
import { User, UserService } from './user-service';

// Fix typos
const userService = new UserService(); // Not 'userSerivce'
```

### TS18046: Object is possibly undefined

**Causes:**
- Missing null checks
- Optional chaining not used
- Type assertions missing

**Solutions:**
```typescript
// Add null checks
if (user && user.profile) {
  return user.profile.name;
}

// Use optional chaining
return user?.profile?.name;

// Add type guards
function isUser(input: unknown): input is User {
  return typeof input === 'object' && input !== null && 'id' in input;
}
```

### TS7006: Implicit any type

**Causes:**
- Missing type annotations
- Parameters without types
- Function return types not specified

**Solutions:**
```typescript
// Add explicit types
function processUserData(userData: UserData): ProcessedResult {
  return process(userData);
}

// Use interface definitions
interface UserData {
  id: string;
  name: string;
  email?: string;
}
```

### TS2551: Property does not exist

**Causes:**
- Incorrect property names
- Interface mismatches
- Type definition issues

**Solutions:**
```typescript
// Fix property names
user.userName // Not 'username' if interface defines 'userName'

// Update interfaces
interface User {
  firstName: string;  // Not 'first_name'
  lastName: string;   // Not 'last_name'
}
```

## 📈 Compliance Metrics

### Tracking Progress

The system tracks:

- **Error counts by type** (TS2304, TS18046, TS7006, TS2551)
- **Parameter naming violations** (PNC001-PNC005)
- **Compliance percentage** (target: >95%)
- **Trend analysis** (improvement/regression)

### Success Criteria

- **Phase 1:** Reduce total errors from 19,159 to <5,000
- **Phase 2:** Reduce total errors to <1,000
- **Phase 3:** Maintain <500 errors with 95%+ compliance
- **Phase 4:** Achieve and maintain <100 errors with 99%+ compliance

## 🚀 Implementation Plan

### Week 1: Foundation
1. Deploy ESLint configuration updates
2. Implement git hooks
3. Set up CI/CD validation
4. Team training session

### Week 2: Automated Fixes
1. Run codemod scripts for common issues
2. Fix high-impact error categories
3. Update VS Code settings
4. Establish baseline metrics

### Week 3: Manual Cleanup
1. Address complex parameter naming issues
2. Review and fix interface definitions
3. Update documentation
4. Optimize validation scripts

### Week 4: Stabilization
1. Monitor error trends
2. Fine-tune validation thresholds
3. Update team guidelines
4. Celebrate success metrics

## 🔍 Monitoring and Reporting

### Daily Reports
- Error count trends
- Violation patterns
- Compliance percentage
- Team contributor metrics

### Weekly Reviews
- Progress toward goals
- Blocking issues identification
- Process optimization
- Team recognition

### Monthly Audits
- Comprehensive compliance assessment
- Policy effectiveness evaluation
- Threshold adjustments
- Training updates

## 🤝 Team Responsibilities

### Developers
- Follow parameter naming guidelines
- Fix violations immediately
- Participate in code reviews
- Update documentation

### Tech Leads
- Review compliance reports
- Mentor team members
- Escalate blocking issues
- Approve threshold changes

### DevOps
- Maintain CI/CD pipelines
- Monitor build failures
- Update validation scripts
- Generate compliance metrics

## 📞 Support and Resources

### Getting Help
- **Documentation:** `docs/PARAMETER-NAMING-POLICY.md`
- **Validation Scripts:** `scripts/validate-parameter-naming.js`
- **Report Generator:** `scripts/generate-naming-report.js`
- **ESLint Config:** `eslint.config.cjs`

### Training Materials
- Parameter naming best practices
- TypeScript error resolution
- ESLint rule configuration
- Git hook troubleshooting

### Communication Channels
- **Slack:** `#parameter-naming-policy`
- **GitHub Issues:** Label with `parameter-naming`
- **Code Reviews:** Required for all parameter changes
- **Stand-ups:** Weekly compliance updates

---

*This policy is enforced automatically through tooling and should be treated as mandatory for all code contributions.*