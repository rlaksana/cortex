# Deployment Runbook

## Overview

This runbook provides step-by-step procedures for deploying the Cortex Memory MCP Server to production environments. It includes pre-deployment checks, deployment stages, validation, and rollback procedures.

## Prerequisites

### Environment Requirements
- **Node.js**: >= 20.x
- **Docker**: >= 20.x (for containerized deployments)
- **Kubernetes**: >= 1.25 (for K8s deployments)
- **Qdrant**: >= 1.7.0
- **Memory**: Minimum 4GB RAM
- **Storage**: Minimum 20GB available disk space
- **Network**: Outbound HTTPS access (port 443)

### Required Access
- SSH access to deployment servers
- Docker registry push permissions
- Kubernetes cluster admin permissions (if using K8s)
- AWS/GCP credentials (if using cloud services)

## Pre-Deployment Checklist

### 1. Environment Validation (5 minutes)

```bash
#!/bin/bash
# scripts/pre-deploy-check.sh

set -euo pipefail

echo "🔍 PRE-DEPLOYMENT VALIDATION"
echo "============================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

VALIDATION_PASSED=true

# Function to run validation check
validate() {
    local check_name=$1
    local check_command=$2

    echo -n "🧪 $check_name... "

    if eval "$check_command"; then
        echo -e "${GREEN}PASSED${NC}"
        return 0
    else
        echo -e "${RED}FAILED${NC}"
        VALIDATION_PASSED=false
        return 1
    fi
}

# System requirements
validate "Node.js Version" "node --version | grep -E 'v2[0-9]+\.[0-9]+'"
validate "Docker Available" "docker --version"
validate "Memory Available" "[ \$(free -m | awk 'NR==2{print \$2}') -ge 4096 ]"
validate "Disk Space Available" "[ \$(df -BG . | awk 'NR==2{print \$4}' | sed 's/G//') -ge 20 ]"

# Service dependencies
validate "Qdrant Running" "curl -f -s http://localhost:6333/health"
validate "Qdrant Collection Exists" "curl -f -s http://localhost:6333/collections/cortex-memory"

# Network connectivity
validate "Internet Access" "curl -f -s https://api.openai.com/v1/models > /dev/null"
validate "DNS Resolution" "nslookup google.com > /dev/null"

# Configuration files
validate "Environment File Exists" "[ -f .env ]"
validate "Package.json Exists" "[ -f package.json ]"
validate "Dockerfile Exists" "[ -f Dockerfile ]"

# Git status
validate "Git Clean Working Directory" "[ -z \"\$(git status --porcelain)\" ]"

echo ""
if [ "$VALIDATION_PASSED" = true ]; then
    echo -e "${GREEN}✅ All pre-deployment checks passed${NC}"
    exit 0
else
    echo -e "${RED}❌ Some pre-deployment checks failed${NC}"
    echo "Fix failed checks before proceeding with deployment"
    exit 1
fi
```

### 2. Backup Current System (2 minutes)

```bash
#!/bin/bash
# scripts/pre-deploy-backup.sh

set -euo pipefail

echo "📦 PRE-DEPLOYMENT BACKUP"
echo "======================="

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/tmp/pre_deploy_backup_${BACKUP_DATE}"

mkdir -p "$BACKUP_DIR"

# Backup current configuration
echo "Backing up configuration files..."
[ -f ".env" ] && cp ".env" "$BACKUP_DIR/"
[ -f "package.json" ] && cp "package.json" "$BACKUP_DIR/"
[ -f "docker-compose.yml" ] && cp "docker-compose.yml" "$BACKUP_DIR/"

# Backup current Git state
echo "Backing up Git state..."
git rev-parse HEAD > "$BACKUP_DIR/git_commit.txt"
git log --oneline -5 > "$BACKUP_DIR/git_recent.log"

# Backup Docker images (if using containerized deployment)
if command -v docker &> /dev/null; then
    echo "Backing up Docker images..."
    docker images | grep cortex-mcp > "$BACKUP_DIR/docker_images.txt" || true
fi

# Backup Qdrant collection info
echo "Backing up Qdrant state..."
curl -s http://localhost:6333/collections/cortex-memory > "$BACKUP_DIR/qdrant_collection.json" || true

echo "✅ Pre-deployment backup completed: $BACKUP_DIR"
echo "Save this directory for rollback if needed"
```

## Deployment Procedures

### Stage 1: Code Deployment (5 minutes)

#### Option A: Docker Deployment

```bash
#!/bin/bash
# scripts/deploy-docker.sh

set -euo pipefail

ENVIRONMENT=${1:-production}
VERSION=${2:-latest}
REGISTRY=${REGISTRY:-"your-registry.com"}

echo "🐳 DOCKER DEPLOYMENT - Stage 1"
echo "=============================="
echo "Environment: $ENVIRONMENT"
echo "Version: $VERSION"
echo "Registry: $REGISTRY"
echo ""

# Build the application
echo "📦 Building application..."
npm ci --only=production
npm run build

# Build Docker image
echo "🏗️ Building Docker image..."
docker build -t $REGISTRY/cortex-mcp:$VERSION .
docker tag $REGISTRY/cortex-mcp:$VERSION $REGISTRY/cortex-mcp:latest

# Push to registry
echo "📤 Pushing to registry..."
docker push $REGISTRY/cortex-mcp:$VERSION
docker push $REGISTRY/cortex-mcp:latest

# Update docker-compose file
echo "📝 Updating docker-compose configuration..."
sed -i.bak "s|image: .*cortex-mcp:.*|image: $REGISTRY/cortex-mcp:$VERSION|g" docker-compose.yml

# Expected output:
# ✅ Building application completed in 45s
# ✅ Building Docker image completed in 2m 15s
# ✅ Pushing to registry completed in 1m 30s
# ✅ Configuration updated successfully

echo "✅ Stage 1: Code deployment completed"
```

#### Option B: Kubernetes Deployment

```bash
#!/bin/bash
# scripts/deploy-k8s.sh

set -euo pipefail

ENVIRONMENT=${1:-production}
VERSION=${2:-latest}
REGISTRY=${REGISTRY:-"your-registry.com"}
NAMESPACE=${NAMESPACE:-"cortex-mcp"}

echo "☸️ KUBERNETES DEPLOYMENT - Stage 1"
echo "=================================="
echo "Environment: $ENVIRONMENT"
echo "Version: $VERSION"
echo "Namespace: $NAMESPACE"
echo ""

# Build and push image (same as Docker deployment)
echo "📦 Building and pushing image..."
npm ci --only=production
npm run build
docker build -t $REGISTRY/cortex-mcp:$VERSION .
docker push $REGISTRY/cortex-mcp:$VERSION

# Update Kubernetes deployment
echo "📝 Updating Kubernetes deployment..."
kubectl set image deployment/cortex-mcp cortex-mcp=$REGISTRY/cortex-mcp:$VERSION -n $NAMESPACE

# Expected output:
# deployment.apps/cortex-mcp image updated

echo "✅ Stage 1: Code deployment completed"
```

### Stage 2: Database Migration (3 minutes)

```bash
#!/bin/bash
# scripts/deploy-migrate.sh

set -euo pipefail

echo "🗄️ DATABASE MIGRATION - Stage 2"
echo "=============================="

# Check if Qdrant collection exists, create if not
echo "Checking Qdrant collection status..."
COLLECTION_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:6333/collections/cortex-memory)

if [ "$COLLECTION_STATUS" = "404" ]; then
    echo "Creating Qdrant collection..."
    curl -X PUT http://localhost:6333/collections/cortex-memory \
        -H "Content-Type: application/json" \
        -d '{
            "vectors": {
                "size": 1536,
                "distance": "Cosine"
            },
            "optimizers_config": {
                "default_segment_number": 2,
                "max_segment_size": 200000,
                "memmap_threshold": 50000
            },
            "quantization_config": {
                "scalar": {
                    "type": "int8",
                    "quantile": 0.99
                }
            }
        }'

    echo "✅ Qdrant collection created"
else
    echo "✅ Qdrant collection already exists"
fi

# Verify collection is accessible
echo "Verifying collection access..."
VECTOR_COUNT=$(curl -s http://localhost:6333/collections/cortex-memory | jq -r '.result.points_count // 0')
echo "Current vector count: $VECTOR_COUNT"

# Expected output:
# ✅ Qdrant collection created
# Current vector count: 0
# OR
# ✅ Qdrant collection already exists
# Current vector count: 1,234

echo "✅ Stage 2: Database migration completed"
```

### Stage 3: Service Restart (5 minutes)

```bash
#!/bin/bash
# scripts/deploy-restart.sh

set -euo pipefail

DEPLOYMENT_TYPE=${1:-docker}

echo "🔄 SERVICE RESTART - Stage 3"
echo "============================"

if [ "$DEPLOYMENT_TYPE" = "docker" ]; then
    echo "Restarting Docker services..."

    # Stop existing services
    echo "Stopping existing services..."
    docker-compose down

    # Start new services
    echo "Starting new services..."
    docker-compose up -d

    # Wait for services to be ready
    echo "Waiting for services to be ready..."
    sleep 30

    # Check service health
    echo "Checking service health..."
    for i in {1..10}; do
        if curl -f -s http://localhost:3000/health > /dev/null; then
            echo "✅ Services are healthy"
            break
        fi

        if [ $i -eq 10 ]; then
            echo "❌ Services failed to start within 5 minutes"
            exit 1
        fi

        echo "Waiting for services... ($i/10)"
        sleep 30
    done

elif [ "$DEPLOYMENT_TYPE" = "kubernetes" ]; then
    echo "Restarting Kubernetes deployment..."

    # Watch rollout status
    echo "Watching rollout status..."
    kubectl rollout status deployment/cortex-mcp -n cortex-mcp --timeout=300s

    # Expected output:
    # deployment "cortex-mcp" successfully rolled out

    # Check pod status
    echo "Checking pod status..."
    kubectl get pods -n cortex-mcp -l app=cortex-mcp

    # Wait for pods to be ready
    echo "Waiting for pods to be ready..."
    kubectl wait --for=condition=ready pod -l app=cortex-mcp -n cortex-mcp --timeout=300s
fi

echo "✅ Stage 3: Service restart completed"
```

### Stage 4: Post-Deployment Validation (5 minutes)

```bash
#!/bin/bash
# scripts/deploy-validate.sh

set -euo pipefail

echo "✅ POST-DEPLOYMENT VALIDATION - Stage 4"
echo "======================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

VALIDATION_PASSED=true

# Function to run validation check
validate() {
    local check_name=$1
    local check_command=$2

    echo -n "🧪 $check_name... "

    if eval "$check_command"; then
        echo -e "${GREEN}PASSED${NC}"
        return 0
    else
        echo -e "${RED}FAILED${NC}"
        VALIDATION_PASSED=false
        return 1
    fi
}

# Health checks
validate "API Health Check" "curl -f -s http://localhost:3000/health"
validate "API Readiness Check" "curl -f -s http://localhost:3000/ready"

# Basic functionality tests
validate "Memory Store Test" "curl -s -X POST http://localhost:3000/api/memory/store -H 'Content-Type: application/json' -d '{\"items\":[{\"kind\":\"observation\",\"content\":\"deployment test\"}]}' | jq -e '.success'"

validate "Memory Find Test" "curl -s -X POST http://localhost:3000/api/memory/find -H 'Content-Type: application/json' -d '{\"query\":\"deployment test\",\"limit\":1}' | jq -e '.items | length > 0'"

# Performance checks
echo -n "🧪 API Response Time... "
RESPONSE_TIME=$(curl -o /dev/null -s -w '%{time_total}' http://localhost:3000/health)
if (( $(echo "$RESPONSE_TIME < 2.0" | bc -l) )); then
    echo -e "${GREEN}PASSED${NC} (${RESPONSE_TIME}s)"
else
    echo -e "${RED}FAILED${NC} (${RESPONSE_TIME}s)"
    VALIDATION_PASSED=false
fi

# Database connectivity
validate "Qdrant Connectivity" "curl -f -s http://localhost:6333/health"
validate "Qdrant Collection Access" "curl -f -s http://localhost:6333/collections/cortex-memory"

# Resource usage
echo -n "🧪 Memory Usage... "
MEMORY_USAGE=$(ps aux | grep 'node.*index.js' | grep -v grep | awk '{sum+=$6} END {print sum/1024}')
if (( $(echo "$MEMORY_USAGE < 1024" | bc -l) )); then
    echo -e "${GREEN}PASSED${NC} (${MEMORY_USAGE}MB)"
else
    echo -e "${YELLOW}WARNING${NC} (${MEMORY_USAGE}MB - high memory usage)"
fi

echo ""
if [ "$VALIDATION_PASSED" = true ]; then
    echo -e "${GREEN}✅ All post-deployment validations passed${NC}"
    echo "🎉 Deployment completed successfully!"

    # Generate deployment summary
    cat << EOF

=== DEPLOYMENT SUMMARY ===
Deployment Time: $(date '+%Y-%m-%d %H:%M:%S')
Environment: $ENVIRONMENT
Version: $VERSION
API Response Time: ${RESPONSE_TIME}s
Memory Usage: ${MEMORY_USAGE}MB

NEXT STEPS:
1. Monitor system performance for next 30 minutes
2. Check application logs for any errors
3. Verify all integrations are working
4. Update monitoring dashboards

EOF

    exit 0
else
    echo -e "${RED}❌ Some post-deployment validations failed${NC}"
    echo "Review failed checks and consider rollback"
    exit 1
fi
```

## Rollback Procedures

### Immediate Rollback (5 minutes)

```bash
#!/bin/bash
# scripts/rollback.sh

set -euo pipefail

PREVIOUS_VERSION=${1:-}
BACKUP_DIR=${2:-}

echo "🔙 ROLLBACK PROCEDURE"
echo "===================="

if [ -z "$PREVIOUS_VERSION" ] && [ -z "$BACKUP_DIR" ]; then
    echo "Usage: $0 <previous_version> [backup_directory]"
    echo "Example: $0 v1.2.3"
    echo "Example: $0 v1.2.3 /tmp/pre_deploy_backup_20241103_120000"
    exit 1
fi

# Confirmation
echo "⚠️ WARNING: This will rollback to version $PREVIOUS_VERSION"
echo "   All changes made during the last deployment will be lost"
echo ""
read -p "Continue with rollback? (type 'rollback' to confirm): " confirm

if [ "$confirm" != "rollback" ]; then
    echo "Rollback cancelled"
    exit 0
fi

echo "🔄 Starting rollback process..."

# Stage 1: Stop current services
echo "🛑 Stopping current services..."
if [ -f "docker-compose.yml" ]; then
    docker-compose down
else
    kubectl scale deployment cortex-mcp --replicas=0 -n cortex-mcp
fi

# Stage 2: Restore previous version
if [ -n "$PREVIOUS_VERSION" ]; then
    echo "📦 Restoring previous version: $PREVIOUS_VERSION"

    if [ -f "docker-compose.yml" ]; then
        # Docker rollback
        sed -i.bak "s|image: .*cortex-mcp:.*|image: $REGISTRY/cortex-mcp:$PREVIOUS_VERSION|g" docker-compose.yml
        docker-compose up -d
    else
        # Kubernetes rollback
        kubectl set image deployment/cortex-mcp cortex-mcp=$REGISTRY/cortex-mcp:$PREVIOUS_VERSION -n cortex-mcp
        kubectl rollout status deployment/cortex-mcp -n cortex-mcp --timeout=300s
    fi
fi

# Stage 3: Restore configuration if backup provided
if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
    echo "📋 Restoring configuration from backup..."

    [ -f "$BACKUP_DIR/.env" ] && cp "$BACKUP_DIR/.env" .env
    [ -f "$BACKUP_DIR/package.json" ] && cp "$BACKUP_DIR/package.json" package.json
    [ -f "$BACKUP_DIR/docker-compose.yml" ] && cp "$BACKUP_DIR/docker-compose.yml" docker-compose.yml

    echo "Configuration restored from: $BACKUP_DIR"
fi

# Stage 4: Restart services
echo "🔄 Starting rolled back services..."
sleep 30

# Stage 5: Verify rollback
echo "✅ Verifying rollback..."
for i in {1..10}; do
    if curl -f -s http://localhost:3000/health > /dev/null; then
        echo "✅ Rollback completed successfully"
        echo "System is now running version: $PREVIOUS_VERSION"

        # Test basic functionality
        STORE_RESPONSE=$(curl -s -X POST http://localhost:3000/api/memory/store \
            -H "Content-Type: application/json" \
            -d '{"items":[{"kind":"observation","content":"rollback test"}]}')

        if echo "$STORE_RESPONSE" | jq -e '.success' > /dev/null; then
            echo "✅ Basic functionality verified"
        else
            echo "⚠️ Basic functionality test failed - manual investigation required"
        fi

        break
    fi

    if [ $i -eq 10 ]; then
        echo "❌ Rollback failed - services not healthy after 5 minutes"
        echo "Manual intervention required"
        exit 1
    fi

    echo "Waiting for services... ($i/10)"
    sleep 30
done

echo ""
echo "🔙 ROLLBACK SUMMARY"
echo "=================="
echo "Previous Version: $PREVIOUS_VERSION"
echo "Rollback Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Configuration Restored: ${BACKUP_DIR:-"N/A"}"
echo ""

echo "NEXT STEPS:"
echo "1. Monitor system performance closely"
echo "2. Investigate why original deployment failed"
echo "3. Check application logs for errors"
echo "4. Test all integrations thoroughly"
echo "5. Document the incident for future reference"

exit 0
```

## Environment-Specific Considerations

### Development Environment
- Use hot reload during development: `npm run dev`
- Enable debug logging: `DEBUG=cortex:*`
- Use development ports: MCP (3001), Qdrant (6334)
- Skip backup procedures for rapid iteration

### Staging Environment
- Mirror production configuration as closely as possible
- Use production-sized data samples for testing
- Run full validation suite including performance tests
- Test rollback procedures before production deployment

### Production Environment
- Always run pre-deployment backups
- Use blue-green deployment for zero-downtime updates
- Monitor system metrics during and after deployment
- Have on-call engineer available during deployment window
- Deploy during low-traffic periods when possible

## Troubleshooting Common Issues

### Service Won't Start
```bash
# Check logs
docker logs cortex-mcp
kubectl logs -f deployment/cortex-mcp -n cortex-mcp

# Check configuration
cat .env
cat docker-compose.yml

# Check port conflicts
netstat -tlnp | grep :3000
```

### Database Connection Issues
```bash
# Test Qdrant connectivity
curl -v http://localhost:6333/health

# Check collection status
curl -s http://localhost:6333/collections/cortex-memory | jq

# Test from container
docker exec cortex-mcp curl -f http://qdrant:6333/health
```

### Performance Degradation
```bash
# Check resource usage
docker stats
kubectl top pods -n cortex-mcp

# Check response times
curl -o /dev/null -s -w '%{time_total}' http://localhost:3000/health

# Monitor logs for errors
tail -f /app/logs/cortex-mcp.log | grep ERROR
```

## Communication During Deployment

### Pre-Deployment Notification
```
Subject: [DEPLOYMENT] Cortex MCP - Starting Deployment to Production

Time: [Deployment Window Start]
Duration: Estimated 20 minutes
Impact: Brief service interruptions (rolling restart)
Contact: [On-call Engineer]

Plan:
1. Pre-deployment validation and backup
2. Code deployment (Docker/Kubernetes)
3. Database migration (Qdrant collection setup)
4. Service restart and validation
5. Post-deployment monitoring

Rollback plan available if issues arise.
```

### Post-Deployment Notification
```
Subject: [DEPLOYMENT] Cortex MCP - Deployment Completed Successfully

Time: [Deployment Completion Time]
Duration: [Actual Duration]
Version: [Deployed Version]
Status: ✅ SUCCESS

Validation Results:
- API Health: ✅ PASSED
- Basic Functionality: ✅ PASSED
- Performance: ✅ PASSED (Response Time: <2s)

System is operating normally. Monitor for next 30 minutes for any issues.
```

### Deployment Failure Notification
```
Subject: [INCIDENT] Cortex MCP - Deployment Failed

Time: [Failure Time]
Version: [Attempted Version]
Status: ❌ FAILED

Issue: [Brief description of failure]
Impact: [Current impact on users]
Action Taken: [Immediate action (rollback/rollback initiated)]
ETA for Resolution: [Estimated time]

Next Steps:
1. Investigate root cause
2. Prepare fix
3. Schedule retry deployment

On-call team is actively working on resolution.
```

This comprehensive deployment runbook ensures consistent, reliable deployments with proper validation, rollback capabilities, and clear communication protocols.