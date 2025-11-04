#!/bin/bash

# Security Scan Script
# Performs comprehensive security scanning of the codebase

set -e

echo "🔒 Starting Comprehensive Security Scan..."
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Track overall status
OVERALL_STATUS=0

# Function to print status
print_status() {
    local status=$1
    local message=$2

    case $status in
        "PASS")
            echo -e "${GREEN}✅ PASS${NC}: $message"
            ;;
        "WARN")
            echo -e "${YELLOW}⚠️  WARN${NC}: $message"
            ;;
        "FAIL")
            echo -e "${RED}❌ FAIL${NC}: $message"
            OVERALL_STATUS=1
            ;;
        "INFO")
            echo -e "${BLUE}ℹ️  INFO${NC}: $message"
            ;;
    esac
}

echo ""
echo "1. 📦 Dependency Security Audit"
echo "--------------------------------"

# Run npm audit with JSON output for parsing
if npm audit --json > /tmp/audit.json 2>/tmp/audit-errors.txt; then
    VULNS=$(cat /tmp/audit.json | jq -r '.metadata.vulnerabilities.total // 0')
    if [ "$VULNS" -eq 0 ]; then
        print_status "PASS" "No vulnerabilities found"
    else
        CRITICAL=$(cat /tmp/audit.json | jq -r '.metadata.vulnerabilities.critical // 0')
        HIGH=$(cat /tmp/audit.json | jq -r '.metadata.vulnerabilities.high // 0')
        if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
            print_status "FAIL" "$CRITICAL critical, $HIGH high severity vulnerabilities found"
        else
            print_status "WARN" "$VULNS total vulnerabilities found (moderate or lower)"
        fi
    fi
else
    print_status "FAIL" "npm audit failed to run"
fi

echo ""
echo "2. 🔍 ESLint Security Analysis"
echo "--------------------------------"

# Run ESLint with security configuration
if npm run lint:security 2>/tmp/eslint-errors.txt; then
    print_status "PASS" "ESLint security checks passed"
else
    ESLINT_ERRORS=$(cat /tmp/eslint-errors.txt | grep -c "error" || echo "0")
    if [ "$ESLINT_ERRORS" -gt 0 ]; then
        print_status "FAIL" "$ESLINT_ERRORS ESLint security issues found"
        cat /tmp/eslint-errors.txt | head -20
    else
        print_status "WARN" "ESLint warnings found"
    fi
fi

echo ""
echo "3. 🧪 Security Test Suite"
echo "-------------------------"

# Run security tests
if npm run test:security 2>/tmp/test-errors.txt; then
    print_status "PASS" "Security tests passed"
else
    print_status "FAIL" "Security tests failed"
    cat /tmp/test-errors.txt | head -10
fi

echo ""
echo "4. 🔐 Secret Detection Scan"
echo "----------------------------"

# Scan for potential secrets in the codebase
echo "Scanning for potential secrets..."
SECRETS_FOUND=0

# Common secret patterns
PATTERNS=(
    "password\s*=\s*['\"][^'\"]+['\"]"
    "api_key\s*=\s*['\"][^'\"]+['\"]"
    "secret_key\s*=\s*['\"][^'\"]+['\"]"
    "private_key\s*=\s*['\"][^'\"]+['\"]"
    "token\s*=\s*['\"][^'\"]+['\"]"
    "AKIA[0-9A-Z]{16}"  # AWS Access Key
    "sk-[a-zA-Z0-9]{20,}"  # OpenAI API Key
    "ghp_[a-zA-Z0-9]{36}"  # GitHub Personal Access Token
)

for pattern in "${PATTERNS[@]}"; do
    if grep -r -E --include="*.ts" --include="*.js" --include="*.json" --exclude-dir=node_modules --exclude-dir=dist "$pattern" src/ > /tmp/secrets.txt 2>/dev/null; then
        if [ -s /tmp/secrets.txt ]; then
            print_status "WARN" "Potential secrets found with pattern: $pattern"
            cat /tmp/secrets.txt | head -5
            SECRETS_FOUND=$((SECRETS_FOUND + 1))
        fi
    fi
done

if [ "$SECRETS_FOUND" -eq 0 ]; then
    print_status "PASS" "No obvious secrets detected"
fi

echo ""
echo "5. 🏗️  Build Configuration Security"
echo "------------------------------------"

# Check for security-related build configurations
echo "Checking build security..."

# Check if production build excludes development dependencies
if grep -q "NODE_ENV=production" package.json; then
    print_status "PASS" "Production environment configuration found"
else
    print_status "WARN" "Production environment configuration not explicitly defined"
fi

# Check for security headers in dependencies
if npm list helmet 2>/dev/null >/dev/null; then
    print_status "PASS" "Security headers library (helmet) found"
else
    print_status "WARN" "Security headers library not found"
fi

# Check for authentication dependencies
if npm list jsonwebtoken bcryptjs 2>/dev/null >/dev/null; then
    print_status "PASS" "Authentication libraries found"
else
    print_status "INFO" "Authentication libraries not found (may not be required)"
fi

echo ""
echo "6. 📁 File Permission Analysis"
echo "------------------------------"

# Check file permissions
echo "Analyzing file permissions..."
PERMISSIONS_ISSUES=0

# Check for executable files that shouldn't be
find src/ -type f -executable 2>/dev/null | while read file; do
    if [[ "$file" != *.sh ]] && [[ "$file" != *.js ]] && [[ "$file" != *.ts ]]; then
        print_status "WARN" "Unexpected executable file: $file"
        PERMISSIONS_ISSUES=$((PERMISSIONS_ISSUES + 1))
    fi
done

# Check for sensitive files with world-readable permissions
SENSITIVE_FILES=(
    ".env*"
    "*.key"
    "*.pem"
    "*.p12"
    "*.pfx"
    "id_rsa"
)

for file_pattern in "${SENSITIVE_FILES[@]}"; do
    if find . -name "$file_pattern" -type f -perm /o+r 2>/dev/null | grep -q .; then
        print_status "WARN" "Sensitive files may be world-readable: $file_pattern"
        PERMISSIONS_ISSUES=$((PERMISSIONS_ISSUES + 1))
    fi
done

if [ "$PERMISSIONS_ISSUES" -eq 0 ]; then
    print_status "PASS" "No permission issues detected"
fi

echo ""
echo "7. 🔗 Dependency License Check"
echo "-------------------------------"

# Check for problematic licenses
echo "Analyzing dependency licenses..."
if command -v npx &> /dev/null; then
    if npx license-checker --summary --excludePrivatePackages 2>/tmp/license-errors.txt > /tmp/licenses.txt; then
        # Check for GPL licenses (may have compliance requirements)
        if grep -i "gpl" /tmp/licenses.txt > /dev/null; then
            print_status "WARN" "GPL licenses found - review compliance requirements"
        else
            print_status "PASS" "No GPL licenses detected"
        fi
    else
        print_status "INFO" "License check not available (install license-checker for this feature)"
    fi
else
    print_status "INFO" "License check skipped (npx not available)"
fi

echo ""
echo "8. 🚀 CI/CD Security Configuration"
echo "------------------------------------"

# Check CI configuration for security
if [ -f ".github/workflows/ci.yml" ]; then
    echo "Analyzing CI configuration..."

    # Check if security steps are included
    if grep -q "security:audit" .github/workflows/ci.yml; then
        print_status "PASS" "Security audit found in CI pipeline"
    else
        print_status "WARN" "Security audit not found in CI pipeline"
    fi

    # Check for dependency caching
    if grep -q "node_modules" .github/workflows/ci.yml; then
        print_status "PASS" "Dependency caching configured in CI"
    else
        print_status "INFO" "Dependency caching not configured in CI"
    fi
else
    print_status "INFO" "No CI configuration found"
fi

echo ""
echo "=========================================="
echo "🔒 Security Scan Summary"
echo "=========================================="

if [ "$OVERALL_STATUS" -eq 0 ]; then
    echo -e "${GREEN}✅ Overall Status: PASSED${NC}"
    echo "All critical security checks passed."
else
    echo -e "${RED}❌ Overall Status: FAILED${NC}"
    echo "Some security issues were found. Please review the output above."
fi

echo ""
echo "📊 Security Recommendations:"
echo "  1. Address any HIGH or CRITICAL vulnerabilities immediately"
echo "  2. Review and fix ESLint security issues"
echo "  3. Ensure all security tests pass"
echo "  4. Investigate any potential secrets found"
echo "  5. Review permission settings for sensitive files"
echo "  6. Update dependencies regularly"

# Cleanup
rm -f /tmp/audit.json /tmp/audit-errors.txt /tmp/eslint-errors.txt /tmp/test-errors.txt /tmp/secrets.txt /tmp/licenses.txt /tmp/license-errors.txt

exit $OVERALL_STATUS