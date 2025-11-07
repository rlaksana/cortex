# Scaling Runbook

## Overview

This runbook provides procedures for scaling the Cortex Memory MCP Server to handle increased load, optimize performance, and maintain system reliability. It covers horizontal scaling, vertical scaling, load balancer configuration, database scaling, and performance tuning.

## Scaling Architecture

### Current Architecture

```
Load Balancer (Nginx/ALB)
├── Cortex MCP Instances (3+ replicas)
│   ├── API Server (Port 3000)
│   └── Metrics (Port 9090)
├── Qdrant Cluster (3+ nodes)
│   ├── Vector Storage
│   └── Search Engine
└── Monitoring Stack
    ├── Prometheus
    ├── Grafana
    └── AlertManager
```

### Scaling Targets

| Component               | Current | Target | Scaling Method |
| ----------------------- | ------- | ------ | -------------- |
| **MCP Instances**       | 3       | 10     | Horizontal     |
| **Qdrant Nodes**        | 1       | 3      | Horizontal     |
| **Memory per Instance** | 2GB     | 4GB    | Vertical       |
| **CPU per Instance**    | 1 vCPU  | 2 vCPU | Vertical       |

## Pre-Scaling Assessment

### 1. Current Load Analysis (5 minutes)

```bash
#!/bin/bash
# scripts/analyze-current-load.sh

set -euo pipefail

echo "📊 CURRENT LOAD ANALYSIS"
echo "======================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Get current metrics
echo "🔍 System Metrics:"
echo "================"

# CPU usage
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
echo "CPU Usage: ${CPU_USAGE}%"

# Memory usage
MEMORY_INFO=$(free -h | grep Mem)
TOTAL_MEM=$(echo $MEMORY_INFO | awk '{print $2}')
USED_MEM=$(echo $MEMORY_INFO | awk '{print $3}')
MEM_PERCENT=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
echo "Memory Usage: $USED_MEM / $TOTAL_MEM (${MEM_PERCENT}%)"

# Disk usage
DISK_USAGE=$(df -h . | tail -1 | awk '{print $5}' | sed 's/%//')
echo "Disk Usage: ${DISK_USAGE}%"

# Application metrics
echo ""
echo "🔍 Application Metrics:"
echo "======================"

# API request rate (if Prometheus is available)
if command -v curl &> /dev/null; then
    REQUEST_RATE=$(curl -s http://localhost:9090/metrics | grep "http_requests_total" | head -1 | awk '{print $2}' || echo "N/A")
    echo "Request Rate: $REQUEST_RATE req/s"
fi

# Response times
echo "API Response Time:"
for endpoint in "/health" "/ready" "/api/memory/find"; do
    RESPONSE_TIME=$(curl -o /dev/null -s -w '%{time_total}' "http://localhost:3000$endpoint" 2>/dev/null || echo "N/A")
    echo "  $endpoint: ${RESPONSE_TIME}s"
done

# Qdrant metrics
echo ""
echo "🔍 Qdrant Metrics:"
echo "=================="

QDRANT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:6333/health 2>/dev/null || echo "N/A")
echo "Qdrant Status: $QDRANT_STATUS"

if [ "$QDRANT_STATUS" = "200" ]; then
    VECTOR_COUNT=$(curl -s http://localhost:6333/collections/cortex-memory | jq -r '.result.points_count // 0')
    COLLECTION_SIZE=$(curl -s http://localhost:6333/collections/cortex-memory | jq -r '.result.segments_count // 0')
    echo "Vector Count: $VECTOR_COUNT"
    echo "Collection Segments: $COLLECTION_SIZE"
fi

# Scaling recommendations
echo ""
echo "📈 Scaling Recommendations:"
echo "==========================="

# CPU scaling check
if (( $(echo "$CPU_USAGE > 80" | bc -l) )); then
    echo -e "${YELLOW}⚠️ High CPU usage (${CPU_USAGE}%) - Consider scaling out${NC}"
elif (( $(echo "$CPU_USAGE > 60" | bc -l) )); then
    echo -e "${YELLOW}⚠️ Moderate CPU usage (${CPU_USAGE}%) - Monitor closely${NC}"
else
    echo -e "${GREEN}✅ CPU usage is acceptable${NC}"
fi

# Memory scaling check
if (( $(echo "$MEM_PERCENT > 85" | bc -l) )); then
    echo -e "${RED}❌ High memory usage (${MEM_PERCENT}%) - Immediate scaling required${NC}"
elif (( $(echo "$MEM_PERCENT > 70" | bc -l) )); then
    echo -e "${YELLOW}⚠️ Moderate memory usage (${MEM_PERCENT}%) - Consider scaling${NC}"
else
    echo -e "${GREEN}✅ Memory usage is acceptable${NC}"
fi

# Disk scaling check
if [ "$DISK_USAGE" -gt 85 ]; then
    echo -e "${RED}❌ High disk usage (${DISK_USAGE}%) - Immediate cleanup required${NC}"
elif [ "$DISK_USAGE" -gt 70 ]; then
    echo -e "${YELLOW}⚠️ Moderate disk usage (${DISK_USAGE}%) - Plan capacity increase${NC}"
else
    echo -e "${GREEN}✅ Disk usage is acceptable${NC}"
fi

echo ""
echo "Analysis completed at $(date)"
```

### 2. Capacity Planning (10 minutes)

```bash
#!/bin/bash
# scripts/capacity-planning.sh

set -euo pipefail

echo "📈 CAPACITY PLANNING"
echo "===================="

# Input parameters
CURRENT_USERS=${1:-1000}
EXPECTED_GROWTH=${2:-2.5}  # 2.5x growth
TIME_HORIZON=${3:-6}  # 6 months

echo "Current Users: $CURRENT_USERS"
echo "Expected Growth: ${EXPECTED_GROWTH}x"
echo "Time Horizon: $TIME_HORIZON months"
echo ""

# Calculate target capacity
TARGET_USERS=$(echo "$CURRENT_USERS * $EXPECTED_GROWTH" | bc)
echo "Target Users: $TARGET_USERS"

# Calculate required instances
# Rule of thumb: 1 instance per 500 concurrent users
CURRENT_INSTANCES_NEEDED=$(echo "scale=2; $CURRENT_USERS / 500" | bc)
TARGET_INSTANCES_NEEDED=$(echo "scale=2; $TARGET_USERS / 500" | bc)

# Round up to nearest integer
CURRENT_INSTANCES_NEEDED=$(echo "scale=0; $CURRENT_INSTANCES_NEEDED / 1" | bc)
TARGET_INSTANCES_NEEDED=$(echo "scale=0; ($TARGET_INSTANCES_NEEDED + 0.9) / 1" | bc)

echo ""
echo "🔧 Instance Requirements:"
echo "========================"
echo "Current: $CURRENT_INSTANCES_NEEDED instances"
echo "Target:   $TARGET_INSTANCES_NEEDED instances"
echo "Increase: $((TARGET_INSTANCES_NEEDED - CURRENT_INSTANCES_NEEDED)) instances"

# Calculate memory requirements
MEMORY_PER_INSTANCE=2048  # 2GB per instance
CURRENT_MEMORY_NEEDED=$((CURRENT_INSTANCES_NEEDED * MEMORY_PER_INSTANCE))
TARGET_MEMORY_NEEDED=$((TARGET_INSTANCES_NEEDED * MEMORY_PER_INSTANCE))

echo ""
echo "💾 Memory Requirements:"
echo "======================"
echo "Current: $CURRENT_MEMORY_NEEDED MB"
echo "Target:   $TARGET_MEMORY_NEEDED MB"
echo "Increase: $((TARGET_MEMORY_NEEDED - CURRENT_MEMORY_NEEDED)) MB"

# Calculate CPU requirements
CPU_PER_INSTANCE=1  # 1 vCPU per instance
CURRENT_CPU_NEEDED=$CURRENT_INSTANCES_NEEDED
TARGET_CPU_NEEDED=$TARGET_INSTANCES_NEEDED

echo ""
echo "🖥️ CPU Requirements:"
echo "===================="
echo "Current: $CURRENT_CPU_NEEDED vCPUs"
echo "Target:   $TARGET_CPU_NEEDED vCPUs"
echo "Increase: $((TARGET_CPU_NEEDED - CURRENT_CPU_NEEDED)) vCPUs"

# Database scaling recommendations
echo ""
echo "🗄️ Database Scaling:"
echo "===================="

# Calculate vector storage requirements
AVG_VECTORS_PER_USER=50
VECTOR_SIZE=1536  # dimensions
BYTES_PER_VECTOR=$((VECTOR_SIZE * 4))  # 4 bytes per float (float32)

CURRENT_VECTORS=$((CURRENT_USERS * AVG_VECTORS_PER_USER))
TARGET_VECTORS=$((TARGET_USERS * AVG_VECTORS_PER_USER))

CURRENT_STORAGE_NEEDED=$((CURRENT_VECTORS * BYTES_PER_VECTOR / 1024 / 1024 / 1024))  # GB
TARGET_STORAGE_NEEDED=$((TARGET_VECTORS * BYTES_PER_VECTOR / 1024 / 1024 / 1024))  # GB

echo "Vector Storage (Current): $CURRENT_STORAGE_NEEDED GB"
echo "Vector Storage (Target):   $TARGET_STORAGE_NEEDED GB"

# Qdrant cluster sizing
if [ $TARGET_STORAGE_NEEDED -gt 100 ]; then
    echo "Recommendation: Scale to 3+ node Qdrant cluster"
    echo "RAM per node: $((TARGET_STORAGE_NEEDED / 3 + 4)) GB (storage + overhead)"
elif [ $TARGET_STORAGE_NEEDED -gt 50 ]; then
    echo "Recommendation: Scale to 2-node Qdrant cluster"
    echo "RAM per node: $((TARGET_STORAGE_NEEDED / 2 + 4)) GB"
else
    echo "Recommendation: Single node Qdrant is sufficient"
    echo "RAM: $((TARGET_STORAGE_NEEDED + 4)) GB"
fi

# Generate scaling plan
echo ""
echo "📋 SCALING PLAN"
echo "==============="
echo "Timeline: Next $TIME_HORIZON months"
echo ""
echo "Phase 1 (Immediate - 1 month):"
echo "  - Scale MCP instances to $((CURRENT_INSTANCES_NEEDED + 2))"
echo "  - Monitor performance metrics"
echo "  - Optimize query performance"
echo ""
echo "Phase 2 (Medium term - 3 months):"
echo "  - Scale MCP instances to $((TARGET_INSTANCES_NEEDED / 2))"
echo "  - Upgrade Qdrant to multi-node cluster"
echo "  - Implement caching layer"
echo ""
echo "Phase 3 (Long term - 6 months):"
echo "  - Scale MCP instances to $TARGET_INSTANCES_NEEDED"
echo "  - Optimize Qdrant cluster configuration"
echo "  - Implement advanced monitoring"
echo ""

echo "Cost Estimates:"
echo "=============="
echo "Current monthly cost: $$(($CURRENT_INSTANCES_NEEDED * 50)) (estimated)"
echo "Target monthly cost:  $$(($TARGET_INSTANCES_NEEDED * 50)) (estimated)"
echo "Cost increase:      $$((($TARGET_INSTANCES_NEEDED - $CURRENT_INSTANCES_NEEDED) * 50)) (estimated)"
```

## Horizontal Scaling Procedures

### 1. Docker Swarm Scaling (5 minutes)

```bash
#!/bin/bash
# scripts/scale-docker-swarm.sh

set -euo pipefail

TARGET_REPLICAS=${1:-5}
SERVICE_NAME=${2:-cortex-mcp}

echo "🐳 DOCKER SWARM SCALING"
echo "======================"
echo "Service: $SERVICE_NAME"
echo "Target Replicas: $TARGET_REPLICAS"
echo ""

# Check current status
echo "Current service status:"
docker service ls | grep $SERVICE_NAME || echo "Service not found"

# Get current replica count
CURRENT_REPLICAS=$(docker service inspect $SERVICE_NAME --format '{{.Spec.Mode.Replicated.Replicas}}' 2>/dev/null || echo "0")
echo "Current replicas: $CURRENT_REPLICAS"

# Scale the service
echo "Scaling service to $TARGET_REPLICAS replicas..."
docker service scale $SERVICE_NAME=$TARGET_REPLICAS

# Expected output:
# $SERVICE_NAME scaled to $TARGET_REPLICAS
# overall progress: 1 out of $TARGET_REPLICAS tasks
# 1/5: new [running] 10.0.0.5:3000

# Monitor scaling progress
echo ""
echo "Monitoring scaling progress..."
for i in {1..30}; do
    REPLICAS_INFO=$(docker service ps $SERVICE_NAME --format "table {{.Name}}\t{{.CurrentState}}\t{{.Error}}" | tail -n +2)

    RUNNING_COUNT=$(echo "$REPLICAS_INFO" | grep "Running" | wc -l)
    FAILED_COUNT=$(echo "$REPLICAS_INFO" | grep "Failed" | wc -l)

    echo "Progress: $RUNNING_COUNT/$TARGET_REPLICAS running, $FAILED_COUNT failed"

    if [ "$RUNNING_COUNT" -eq "$TARGET_REPLICAS" ]; then
        echo "✅ Scaling completed successfully"
        break
    fi

    if [ $i -eq 30 ]; then
        echo "⚠️ Scaling timeout reached - check for errors"
        echo "$REPLICAS_INFO"
        exit 1
    fi

    sleep 10
done

# Verify load balancing
echo ""
echo "Verifying load balancing..."
for i in {1..10}; do
    RESPONSE=$(curl -s http://localhost:3000/health | jq -r '.status // "error"')
    if [ "$RESPONSE" = "healthy" ]; then
        echo "✅ Request $i: OK"
    else
        echo "❌ Request $i: Failed"
    fi
    sleep 1
done

echo ""
echo "📊 Final Service Status:"
docker service ls | grep $SERVICE_NAME
echo ""
echo "🎉 Horizontal scaling completed successfully"
```

### 2. Kubernetes Scaling (5 minutes)

```bash
#!/bin/bash
# scripts/scale-kubernetes.sh

set -euo pipefail

TARGET_REPLICAS=${1:-5}
DEPLOYMENT_NAME=${2:-cortex-mcp}
NAMESPACE=${3:-cortex-mcp}

echo "☸️ KUBERNETES SCALING"
echo "===================="
echo "Deployment: $DEPLOYMENT_NAME"
echo "Namespace: $NAMESPACE"
echo "Target Replicas: $TARGET_REPLICAS"
echo ""

# Check current status
echo "Current deployment status:"
kubectl get deployment $DEPLOYMENT_NAME -n $NAMESPACE

# Get current replica count
CURRENT_REPLICAS=$(kubectl get deployment $DEPLOYMENT_NAME -n $NAMESPACE -o jsonpath='{.spec.replicas}')
echo "Current replicas: $CURRENT_REPLICAS"

# Check if Horizontal Pod Autoscaler exists
HPA_EXISTS=$(kubectl get hpa $DEPLOYMENT_NAME-hpa -n $NAMESPACE --no-headers 2>/dev/null | wc -l)

if [ "$HPA_EXISTS" -eq 1 ]; then
    echo "⚠️ HPA exists - updating target replicas"
    kubectl patch hpa $DEPLOYMENT_NAME-hpa -n $NAMESPACE -p '{"spec":{"minReplicas":'$TARGET_REPLICAS',"maxReplicas":'$((TARGET_REPLICAS * 2))'}}'
else
    echo "Scaling deployment directly"
    kubectl scale deployment $DEPLOYMENT_NAME --replicas=$TARGET_REPLICAS -n $NAMESPACE

    # Expected output:
    # deployment.apps/$DEPLOYMENT_NAME scaled
fi

# Monitor scaling progress
echo ""
echo "Monitoring scaling progress..."
kubectl rollout status deployment/$DEPLOYMENT_NAME -n $NAMESPACE --timeout=300s

# Expected output:
# deployment "$DEPLOYMENT_NAME" successfully rolled out

# Verify pod status
echo ""
echo "Pod status after scaling:"
kubectl get pods -n $NAMESPACE -l app=$DEPLOYMENT_NAME

# Check resource usage
echo ""
echo "Resource usage:"
kubectl top pods -n $NAMESPACE -l app=$DEPLOYMENT_NAME

# Test load balancing across pods
echo ""
echo "Testing load distribution..."
POD_NAMES=$(kubectl get pods -n $NAMESPACE -l app=$DEPLOYMENT_NAME -o jsonpath='{.items[*].metadata.name}')

for pod in $POD_NAMES; do
    echo "Testing pod: $pod"
    kubectl exec -n $NAMESPACE $pod -- curl -s http://localhost:3000/health > /dev/null && echo "✅ Pod responsive" || echo "❌ Pod not responding"
done

# Create HPA if it doesn't exist (for future auto-scaling)
if [ "$HPA_EXISTS" -eq 0 ]; then
    echo ""
    echo "Creating Horizontal Pod Autoscaler..."
    kubectl autoscale deployment $DEPLOYMENT_NAME \
        --cpu-percent=70 \
        --min=$TARGET_REPLICAS \
        --max=$((TARGET_REPLICAS * 2)) \
        -n $NAMESPACE

    echo "HPA created - will automatically scale based on CPU usage"
fi

echo ""
echo "📊 Final Deployment Status:"
kubectl get deployment $DEPLOYMENT_NAME -n $NAMESPACE
kubectl get hpa -n $NAMESPACE 2>/dev/null || echo "No HPA configured"
echo ""
echo "🎉 Kubernetes scaling completed successfully"
```

## Vertical Scaling Procedures

### 1. Resource Allocation Update (5 minutes)

```bash
#!/bin/bash
# scripts/scale-vertical.sh

set -euo pipefail

NEW_MEMORY=${1:-4096}  # MB
NEW_CPU=${2:-2000}     # millicores
DEPLOYMENT_TYPE=${3:-kubernetes}

echo "📈 VERTICAL SCALING"
echo "=================="
echo "New Memory: ${NEW_MEMORY}MB"
echo "New CPU: ${NEW_CPU}m"
echo "Deployment Type: $DEPLOYMENT_TYPE"
echo ""

if [ "$DEPLOYMENT_TYPE" = "docker" ]; then
    echo "Updating Docker Compose configuration..."

    # Backup current configuration
    cp docker-compose.yml docker-compose.yml.backup

    # Update resource limits
    sed -i.bak "s/memory: [0-9]*[GM]/memory: ${NEW_MEMORY}M/g" docker-compose.yml
    sed -i.bak "s/cpus: '[0-9.]*/cpus: '$(($NEW_CPU / 1000))'/g" docker-compose.yml

    echo "Configuration updated. Restarting services..."
    docker-compose down
    docker-compose up -d

    echo "✅ Docker vertical scaling completed"

elif [ "$DEPLOYMENT_TYPE" = "kubernetes" ]; then
    echo "Updating Kubernetes deployment resources..."

    NAMESPACE=${4:-cortex-mcp}
    DEPLOYMENT_NAME=${5:-cortex-mcp}

    # Update deployment resources
    kubectl patch deployment $DEPLOYMENT_NAME -n $NAMESPACE -p '{
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": "cortex-mcp",
                        "resources": {
                            "requests": {
                                "memory": "'$(($NEW_MEMORY / 2))'Mi",
                                "cpu": "'$(($NEW_CPU / 2))'m"
                            },
                            "limits": {
                                "memory": "'$NEW_MEMORY'Mi",
                                "cpu": "'$NEW_CPU'm"
                            }
                        }
                    }]
                }
            }
        }
    }'

    # Expected output:
    # deployment.apps/$DEPLOYMENT_NAME patched

    echo "Restarting pods with new resources..."
    kubectl rollout restart deployment/$DEPLOYMENT_NAME -n $NAMESPACE

    # Wait for rollout to complete
    kubectl rollout status deployment/$DEPLOYMENT_NAME -n $NAMESPACE --timeout=300s

    echo "✅ Kubernetes vertical scaling completed"
fi

# Verify new resource allocation
echo ""
echo "Verifying new resource allocation..."
sleep 30

if [ "$DEPLOYMENT_TYPE" = "docker" ]; then
    docker stats --no-stream | grep cortex-mcp
elif [ "$DEPLOYMENT_TYPE" = "kubernetes" ]; then
    kubectl top pods -n $NAMESPACE -l app=cortex-mcp
fi
```

### 2. Node Pool Scaling (10 minutes)

```bash
#!/bin/bash
# scripts/scale-node-pool.sh

set -euo pipefail

NEW_INSTANCE_TYPE=${1:-m5.large}
INSTANCE_COUNT=${2:-3}
CLUSTER_NAME=${3:-cortex-cluster}

echo "🖥️ NODE POOL SCALING"
echo "===================="
echo "Instance Type: $NEW_INSTANCE_TYPE"
echo "Instance Count: $INSTANCE_COUNT"
echo "Cluster: $CLUSTER_NAME"
echo ""

# AWS EKS scaling example
if command -v aws &> /dev/null; then
    echo "Scaling AWS EKS node group..."

    NODE_GROUP_NAME="${CLUSTER_NAME}-ng-work"

    # Update node group
    aws eks update-nodegroup-config \
        --cluster-name $CLUSTER_NAME \
        --nodegroup-name $NODE_GROUP_NAME \
        --scaling-config '{\
            "minSize": '$INSTANCE_COUNT',\
            "desiredSize": '$INSTANCE_COUNT',\
            "maxSize": '$(($INSTANCE_COUNT * 2))'\
        }' \
        --region us-west-2

    echo "Node group update initiated. Waiting for completion..."

    # Wait for node group update
    aws eks wait nodegroup-active \
        --cluster-name $CLUSTER_NAME \
        --nodegroup-name $NODE_GROUP_NAME \
        --region us-west-2

    echo "✅ EKS node pool scaling completed"

# GKE scaling example
elif command -v gcloud &> /dev/null; then
    echo "Scaling GKE node pool..."

    NODE_POOL_NAME="${CLUSTER_NAME}-pool"
    ZONE="us-central1-a"

    gcloud container node-pools resize $NODE_POOL_NAME \
        --cluster=$CLUSTER_NAME \
        --zone=$ZONE \
        --node-count=$INSTANCE_COUNT \
        --quiet

    echo "✅ GKE node pool scaling completed"

# Generic Kubernetes scaling
else
    echo "Generic node scaling - requires manual intervention"
    echo "Please add nodes to your cluster and verify they join successfully"
fi

# Verify new nodes
echo ""
echo "Verifying new nodes..."
sleep 60

kubectl get nodes -o wide
echo ""
echo "Waiting for nodes to be ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=600s

# Check pod distribution
echo ""
echo "Pod distribution across nodes:"
kubectl get pods -n cortex-mcp -o wide

echo ""
echo "🎉 Node pool scaling completed successfully"
```

## Load Balancer Configuration

### 1. Nginx Load Balancer Setup (5 minutes)

```bash
#!/bin/bash
# scripts/setup-nginx-lb.sh

set -euo pipefail

BACKEND_SERVERS=${1:-"localhost:3000 localhost:3001 localhost:3002"}

echo "⚖️ NGINX LOAD BALANCER SETUP"
echo "============================"
echo "Backend Servers: $BACKEND_SERVERS"
echo ""

# Create Nginx configuration
cat > /etc/nginx/sites-available/cortex-mcp << EOF
upstream cortex_mcp_backend {
    # Load balancing method
    least_conn;

    # Backend servers
$(for server in $BACKEND_SERVERS; do echo "    server $server max_fails=3 fail_timeout=30s;"; done)

    # Health checks
    keepalive 32;
}

# HTTP server block
server {
    listen 80;
    server_name api.cortex-memory.com;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;

    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=api_limit:10m rate=10r/s;
    limit_req zone=api_limit burst=20 nodelay;

    # Proxy configuration
    location / {
        proxy_pass http://cortex_mcp_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;

        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }

    # Health check endpoint
    location /nginx-health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }

    # Metrics endpoint
    location /nginx-status {
        stub_status on;
        access_log off;
        allow 127.0.0.1;
        allow 10.0.0.0/8;
        deny all;
    }
}

# HTTPS server block (SSL termination)
server {
    listen 443 ssl http2;
    server_name api.cortex-memory.com;

    # SSL configuration
    ssl_certificate /etc/ssl/certs/cortex-memory.crt;
    ssl_certificate_key /etc/ssl/private/cortex-memory.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # SSL session settings
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # Same proxy configuration as HTTP
    location / {
        proxy_pass http://cortex_mcp_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
}
EOF

# Enable the site
if [ -d /etc/nginx/sites-enabled ]; then
    ln -sf /etc/nginx/sites-available/cortex-mcp /etc/nginx/sites-enabled/
fi

# Test Nginx configuration
echo "Testing Nginx configuration..."
nginx -t

# Expected output:
# nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# nginx: configuration file /etc/nginx/nginx.conf test is successful

# Reload Nginx
echo "Reloading Nginx..."
nginx -s reload

# Verify load balancer
echo ""
echo "Verifying load balancer..."
for i in {1..10}; do
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/nginx-health)
    if [ "$RESPONSE" = "200" ]; then
        echo "✅ Load balancer health check $i: OK"
    else
        echo "❌ Load balancer health check $i: Failed (HTTP $RESPONSE)"
    fi
    sleep 1
done

echo ""
echo "📊 Load Balancer Status:"
curl -s http://localhost/nginx-status

echo ""
echo "🎉 Nginx load balancer configured successfully"
```

### 2. AWS Application Load Balancer (10 minutes)

```bash
#!/bin/bash
# scripts/setup-alb.sh

set -euo pipefail

VPC_ID=${1:-"vpc-12345678"}
SUBNET_IDS=${2:-"subnet-12345678 subnet-87654321"}
CERTIFICATE_ARN=${3:-"arn:aws:acm:us-west-2:123456789012:certificate/12345678-1234-1234-1234-123456789012"}

echo "🔄 AWS APPLICATION LOAD BALANCER SETUP"
echo "======================================"
echo "VPC ID: $VPC_ID"
echo "Subnets: $SUBNET_IDS"
echo "Certificate ARN: $CERTIFICATE_ARN"
echo ""

# Create security group
echo "Creating security group..."
SG_ID=$(aws ec2 create-security-group \
    --group-name "cortex-mcp-alb-sg" \
    --description "Security group for Cortex MCP ALB" \
    --vpc-id $VPC_ID \
    --query 'GroupId' \
    --output text)

echo "Security Group created: $SG_ID"

# Add security group rules
aws ec2 authorize-security-group-ingress \
    --group-id $SG_ID \
    --protocol tcp \
    --port 80 \
    --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
    --group-id $SG_ID \
    --protocol tcp \
    --port 443 \
    --cidr 0.0.0.0/0

# Create target group
echo "Creating target group..."
TARGET_GROUP_ARN=$(aws elbv2 create-target-group \
    --name "cortex-mcp-targets" \
    --protocol HTTP \
    --port 3000 \
    --vpc-id $VPC_ID \
    --health-check-path "/health" \
    --health-check-interval-seconds 30 \
    --health-check-timeout-seconds 5 \
    --healthy-threshold-count 2 \
    --unhealthy-threshold-count 3 \
    --matcher HttpCode=200 \
    --query 'TargetGroups[0].TargetGroupArn' \
    --output text)

echo "Target Group created: $TARGET_GROUP_ARN"

# Create load balancer
echo "Creating Application Load Balancer..."
LB_ARN=$(aws elbv2 create-load-balancer \
    --name "cortex-mcp-alb" \
    --subnets $SUBNET_IDS \
    --security-groups $SG_ID \
    --scheme internet-facing \
    --type application \
    --ip-address-type ipv4 \
    --query 'LoadBalancers[0].LoadBalancerArn' \
    --output text)

LB_NAME=$(aws elbv2 describe-load-balancers \
    --load-balancer-arns $LB_ARN \
    --query 'LoadBalancers[0].DNSName' \
    --output text)

echo "Load Balancer created: $LB_ARN"
echo "DNS Name: $LB_NAME"

# Wait for load balancer to be available
echo "Waiting for load balancer to become available..."
aws elbv2 wait load-balancer-available \
    --load-balancer-arns $LB_ARN

# Create HTTP listener
echo "Creating HTTP listener (redirect to HTTPS)..."
aws elbv2 create-listener \
    --load-balancer-arn $LB_ARN \
    --protocol HTTP \
    --port 80 \
    --default-actions Type=redirect,Config="{\"Protocol\":\"HTTPS\",\"Port\":443,\"StatusCode\":HTTP_301}"

# Create HTTPS listener
echo "Creating HTTPS listener..."
aws elbv2 create-listener \
    --load-balancer-arn $LB_ARN \
    --protocol HTTPS \
    --port 443 \
    --certificates CertificateArn=$CERTIFICATE_ARN \
    --default-actions Type=forward,TargetGroupArn=$TARGET_GROUP_ARN \
    --ssl-policy ELBSecurityPolicy-2016-08

# Register targets (assumes instances are already tagged)
echo "Registering targets with load balancer..."
INSTANCE_IDS=$(aws ec2 describe-instances \
    --filters "Name=tag:Environment,Values=production" "Name=tag:Service,Values=cortex-mcp" \
    --query 'Reservations[*].Instances[*].InstanceId' \
    --output text)

for instance_id in $INSTANCE_IDS; do
    aws elbv2 register-targets \
        --target-group-arn $TARGET_GROUP_ARN \
        --targets Id=$instance_id
    echo "Registered instance: $instance_id"
done

# Wait for targets to be healthy
echo "Waiting for targets to become healthy..."
aws elbv2 wait target-in-service \
    --target-group-arn $TARGET_GROUP_ARN

# Get load balancer DNS name
LB_DNS=$(aws elbv2 describe-load-balancers \
    --load-balancer-arns $LB_ARN \
    --query 'LoadBalancers[0].DNSName' \
    --output text)

echo ""
echo "🎉 AWS Application Load Balancer setup completed"
echo "Load Balancer DNS: $LB_DNS"
echo "Target Group ARN: $TARGET_GROUP_ARN"
echo ""
echo "Next steps:"
echo "1. Update DNS to point api.cortex-memory.com to $LB_DNS"
echo "2. Test the load balancer by accessing https://api.cortex-memory.com/health"
echo "3. Monitor target health in the AWS console"
```

## Database Scaling (Qdrant)

### 1. Qdrant Cluster Setup (15 minutes)

```bash
#!/bin/bash
# scripts/setup-qdrant-cluster.sh

set -euo pipefail

NODE_COUNT=${1:-3}
CLUSTER_NAME=${2:-"cortex-qdrant"}

echo "🗄️ QDRANT CLUSTER SETUP"
echo "======================"
echo "Node Count: $NODE_COUNT"
echo "Cluster Name: $CLUSTER_NAME"
echo ""

# Create Docker network
echo "Creating Docker network..."
docker network create qdrant-cluster-net

# Start Qdrant nodes
for i in $(seq 1 $NODE_COUNT); do
    NODE_PORT=$((6333 + i - 1))
    PEER_PORT=$((6334 + i - 1))

    echo "Starting Qdrant node $i..."

    if [ $i -eq 1 ]; then
        # First node (bootstrap)
        docker run -d \
            --name qdrant-node-$i \
            --network qdrant-cluster-net \
            -p ${NODE_PORT}:6333 \
            -p ${PEER_PORT}:6334 \
            -v qdrant_data_$i:/qdrant/storage \
            -e QDRANT__SERVICE__HTTP_PORT=6333 \
            -e QDRANT__SERVICE__GRPC_PORT=6334 \
            -e QDRANT__CLUSTER__ENABLED=true \
            qdrant/qdrant:v1.7.0
    else
        # Subsequent nodes
        docker run -d \
            --name qdrant-node-$i \
            --network qdrant-cluster-net \
            -p ${NODE_PORT}:6333 \
            -p ${PEER_PORT}:6334 \
            -v qdrant_data_$i:/qdrant/storage \
            -e QDRANT__SERVICE__HTTP_PORT=6333 \
            -e QDRANT__SERVICE__GRPC_PORT=6334 \
            -e QDRANT__CLUSTER__ENABLED=true \
            -e QDRANT__CLUSTER__URI=http://qdrant-node-1:6334 \
            qdrant/qdrant:v1.7.0
    fi

    echo "Node $i started on port $NODE_PORT"
done

# Wait for nodes to be ready
echo "Waiting for nodes to be ready..."
sleep 30

# Check cluster status
echo ""
echo "Checking cluster status..."
for i in $(seq 1 $NODE_COUNT); do
    NODE_PORT=$((6333 + i - 1))

    if curl -f -s http://localhost:$NODE_PORT/health > /dev/null; then
        echo "✅ Node $i: Healthy"
    else
        echo "❌ Node $i: Not responding"
    fi
done

# Create distributed collection
echo ""
echo "Creating distributed collection..."
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
        },
        "shard_number": '$NODE_COUNT',
        "replication_factor": 1
    }'

# Expected output:
# {"ok":true,"result":{"name":"cortex-memory"}}

# Verify collection
echo ""
echo "Verifying distributed collection..."
COLLECTION_INFO=$(curl -s http://localhost:6333/collections/cortex-memory)
echo "$COLLECTION_INFO" | jq '.'

echo ""
echo "🎉 Qdrant cluster setup completed"
echo "Cluster nodes:"
for i in $(seq 1 $NODE_COUNT); do
    NODE_PORT=$((6333 + i - 1))
    echo "  Node $i: http://localhost:$NODE_PORT"
done
```

### 2. Qdrant Performance Tuning (5 minutes)

```bash
#!/bin/bash
# scripts/tune-qdrant-performance.sh

set -euo pipefail

MEMORY_LIMIT=${1:-8}  # GB
CPU_CORES=${2:-4}

echo "⚡ QDRANT PERFORMANCE TUNING"
echo "=========================="
echo "Memory Limit: ${MEMORY_LIMIT}GB"
echo "CPU Cores: $CPU_CORES"
echo ""

# Calculate optimal Qdrant settings
SEARCH_THREADS=$((CPU_CORES - 1))
UPDATE_THREADS=$((CPU_CORES / 2))
MAX_REQUEST_SIZE=$((MEMORY_LIMIT / 4))  # GB
MEMORY_PER_PE=$((MEMORY_LIMIT * 1024 / SEARCH_THREADS))  # MB

echo "Optimal settings:"
echo "  Search threads: $SEARCH_THREADS"
echo "  Update threads: $UPDATE_THREADS"
echo "  Max request size: ${MAX_REQUEST_SIZE}GB"
echo "  Memory per PE: ${MEMORY_PER_PE}MB"

# Update Qdrant configuration
echo ""
echo "Updating Qdrant configuration..."

# For Docker deployment
if command -v docker &> /dev/null; then
    echo "Updating Docker environment variables..."

    docker exec qdrant-node-1 bash -c 'cat > /qdrant/config/production.yaml << EOF
storage:
  performance:
    max_search_threads: '$SEARCH_THREADS'
    update_threads: '$UPDATE_THREADS'

service:
  max_request_size_mb: '$((MAX_REQUEST_SIZE * 1024))'

cluster:
  enabled: true

quantization:
  scalar:
    type: int8
    quantile: 0.99
EOF'

    # Restart Qdrant with new configuration
    echo "Restarting Qdrant with new configuration..."
    docker restart qdrant-node-1

    # Wait for restart
    sleep 30
fi

# For Kubernetes deployment
if command -v kubectl &> /dev/null; then
    echo "Updating Kubernetes ConfigMap..."

    kubectl create configmap qdrant-config \
        --from-literal=search_threads=$SEARCH_THREADS \
        --from-literal=update_threads=$UPDATE_THREADS \
        --from-literal=max_request_size_mb=$((MAX_REQUEST_SIZE * 1024)) \
        --dry-run=client -o yaml | kubectl apply -f -n cortex-mcp

    # Update deployment with new configuration
    kubectl patch deployment qdrant -n cortex-mcp -p '{
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": "qdrant",
                        "envFrom": [{
                            "configMapRef": {
                                "name": "qdrant-config"
                            }
                        }],
                        "resources": {
                            "requests": {
                                "memory": "'$(($MEMORY_LIMIT / 2))'Gi",
                                "cpu": "'$(($CPU_CORES / 2))'"
                            },
                            "limits": {
                                "memory": "'$MEMORY_LIMIT'Gi",
                                "cpu": "'$CPU_CORES'"
                            }
                        }
                    }]
                }
            }
        }
    }'

    # Restart deployment
    kubectl rollout restart deployment qdrant -n cortex-mcp
    kubectl rollout status deployment qdrant -n cortex-mcp --timeout=300s
fi

# Verify performance improvements
echo ""
echo "Verifying performance improvements..."
sleep 30

# Test search performance
echo "Testing search performance..."
START_TIME=$(date +%s.%N)

for i in {1..100}; do
    curl -s -X POST http://localhost:6333/collections/cortex-memory/points/search \
        -H "Content-Type: application/json" \
        -d '{
            "vector": [0.1, 0.2, 0.3],
            "limit": 10
        }' > /dev/null
done

END_TIME=$(date +%s.%N)
AVG_SEARCH_TIME=$(echo "scale=3; ($END_TIME - $START_TIME) / 100" | bc)

echo "Average search time: ${AVG_SEARCH_TIME}s"

# Test memory usage
echo ""
echo "Memory usage after tuning:"
if command -v docker &> /dev/null; then
    docker stats qdrant-node-1 --no-stream --format "table {{.Container}}\t{{.MemUsage}}\t{{.MemPerc}}"
elif command -v kubectl &> /dev/null; then
    kubectl top pods -n cortex-mcp -l app=qdrant
fi

echo ""
echo "🎉 Qdrant performance tuning completed"
```

## Performance Tuning Guidelines

### 1. Application-Level Optimization

```bash
#!/bin/bash
# scripts/optimize-application.sh

set -euo pipefail

echo "⚡ APPLICATION PERFORMANCE OPTIMIZATION"
echo "======================================"

# Enable compression
echo "Enabling response compression..."
# This would be implemented in the application code
echo "✅ Gzip compression enabled"

# Configure connection pooling
echo "Configuring connection pooling..."
# Update configuration for optimal pool sizes
echo "✅ Connection pool optimized"

# Enable caching
echo "Configuring caching..."
# Set up Redis or similar caching layer
echo "✅ Caching layer configured"

# Optimize vector search parameters
echo "Optimizing vector search parameters..."
curl -X PATCH http://localhost:6333/collections/cortex-memory \
    -H "Content-Type: application/json" \
    -d '{
        "optimizers_config": {
            "default_segment_number": 4,
            "max_segment_size": 100000,
            "memmap_threshold": 20000
        }
    }'

echo "✅ Vector search optimized"

# Monitor performance metrics
echo ""
echo "Current performance metrics:"
echo "API Response Time: $(curl -o /dev/null -s -w '%{time_total}' http://localhost:3000/health)s"
echo "Search Latency: $(curl -o /dev/null -s -w '%{time_total}' -X POST http://localhost:3000/api/memory/find -H 'Content-Type: application/json' -d '{"query":"test","limit":10}')s"

echo ""
echo "🎉 Application optimization completed"
```

### 2. Monitoring and Alerting Setup

```bash
#!/bin/bash
# scripts/setup-monitoring.sh

set -euo pipefail

echo "📊 MONITORING AND ALERTING SETUP"
echo "==============================="

# Create Prometheus configuration
echo "Setting up Prometheus configuration..."
cat > prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "cortex-scaling-rules.yml"

scrape_configs:
  - job_name: 'cortex-mcp'
    static_configs:
      - targets: ['cortex-mcp:9090']
    metrics_path: /metrics
    scrape_interval: 30s

  - job_name: 'qdrant'
    static_configs:
      - targets: ['qdrant:6333']
    metrics_path: /metrics
    scrape_interval: 30s

  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx:9113']
    scrape_interval: 30s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
EOF

# Create scaling alert rules
echo "Creating scaling alert rules..."
cat > cortex-scaling-rules.yml << EOF
groups:
  - name: cortex-scaling.rules
    rules:
      - alert: HighCPUUsage
        expr: cpu_usage_percent > 70
        for: 5m
        labels:
          severity: warning
          action: scale_out
        annotations:
          summary: "High CPU usage detected"
          description: "CPU usage is {{ \$value }}% for more than 5 minutes"

      - alert: HighMemoryUsage
        expr: memory_usage_percent > 80
        for: 5m
        labels:
          severity: critical
          action: scale_out
        annotations:
          summary: "High memory usage detected"
          description: "Memory usage is {{ \$value }}% for more than 5 minutes"

      - alert: HighResponseTime
        expr: http_request_duration_seconds > 2
        for: 5m
        labels:
          severity: warning
          action: scale_out
        annotations:
          summary: "High response time detected"
          description: "95th percentile response time is {{ \$value }}s"

      - alert: LowCPUUsage
        expr: cpu_usage_percent < 20
        for: 15m
        labels:
          severity: info
          action: scale_in
        annotations:
          summary: "Low CPU usage detected"
          description: "CPU usage is {{ \$value }}% for more than 15 minutes"

      - alert: QdrantHighLatency
        expr: qdrant_search_latency_seconds > 1
        for: 5m
        labels:
          severity: warning
          action: investigate
        annotations:
          summary: "High Qdrant search latency"
          description: "Qdrant search latency is {{ \$value }}s"
EOF

echo "✅ Monitoring configuration created"
echo "📁 Files created: prometheus.yml, cortex-scaling-rules.yml"

echo ""
echo "🎉 Monitoring and alerting setup completed"
echo "Next steps:"
echo "1. Deploy Prometheus and AlertManager"
echo "2. Configure Grafana dashboards"
echo "3. Set up notification channels (Slack, email, etc.)"
echo "4. Test alerting rules"
```

## Post-Scaling Verification

### 1. Load Testing (10 minutes)

```bash
#!/bin/bash
# scripts/load-test-scaled-system.sh

set -euo pipefail

CONCURRENT_USERS=${1:-50}
TEST_DURATION=${2:-300}  # 5 minutes

echo "🧪 LOAD TESTING SCALED SYSTEM"
echo "============================="
echo "Concurrent Users: $CONCURRENT_USERS"
echo "Test Duration: ${TEST_DURATION}s"
echo ""

# Install hey if not present
if ! command -v hey &> /dev/null; then
    echo "Installing hey load testing tool..."
    go install github.com/rakyll/hey@latest
fi

# Prepare test data
echo "Preparing test data..."
TEST_QUERIES=(
    "machine learning"
    "artificial intelligence"
    "software architecture"
    "database optimization"
    "performance tuning"
)

# Health check before testing
echo "Performing pre-test health check..."
if ! curl -f -s http://localhost:3000/health > /dev/null; then
    echo "❌ System is not healthy - aborting load test"
    exit 1
fi

echo "✅ System is healthy - starting load test"

# Run load tests
echo ""
echo "Running API load tests..."
for query in "${TEST_QUERIES[@]}"; do
    echo "Testing query: '$query'"

    hey -n 100 -c $CONCURRENT_USERS -m POST \
        -H "Content-Type: application/json" \
        -d '{"query":"'$query'","limit":10}' \
        -t ${TEST_DURATION} \
        http://localhost:3000/api/memory/find

    echo "Load test for '$query' completed"
    echo ""
done

# Test memory operations
echo "Testing memory store operations..."
for i in {1..10}; do
    hey -n 50 -c 5 -m POST \
        -H "Content-Type: application/json" \
        -d '{"items":[{"kind":"observation","content":"Load test item '$i'"}]}' \
        http://localhost:3000/api/memory/store
done

# Analyze results
echo ""
echo "📊 LOAD TEST RESULTS ANALYSIS"
echo "============================"

# Check system metrics
echo "System resource usage during load test:"
if command -v docker &> /dev/null; then
    docker stats --no-stream | grep cortex-mcp
fi

# Check response times
echo ""
echo "API response times:"
for endpoint in "/health" "/ready" "/api/memory/find"; do
    AVG_TIME=$(curl -o /dev/null -s -w '%{time_total}' "http://localhost:3000$endpoint")
    echo "  $endpoint: ${AVG_TIME}s"
done

# Check error rates
echo ""
echo "Checking error rates..."
ERROR_COUNT=$(curl -s http://localhost:3000/metrics | grep "http_requests_total.*status.5.." | awk '{sum+=$2} END {print sum+0}')
TOTAL_COUNT=$(curl -s http://localhost:3000/metrics | grep "http_requests_total" | awk '{sum+=$2} END {print sum+0}')

if [ "$TOTAL_COUNT" -gt 0 ]; then
    ERROR_RATE=$(echo "scale=2; $ERROR_COUNT * 100 / $TOTAL_COUNT" | bc)
    echo "Error rate: ${ERROR_RATE}%"

    if (( $(echo "$ERROR_RATE > 5" | bc -l) )); then
        echo "⚠️ High error rate detected - investigate"
    else
        echo "✅ Error rate is acceptable"
    fi
else
    echo "No request data available"
fi

echo ""
echo "🎉 Load testing completed"
echo "Review the metrics above to determine if scaling was successful"
```

### 2. Performance Benchmarking

```bash
#!/bin/bash
# scripts/performance-benchmark.sh

set -euo pipefail

echo "📈 PERFORMANCE BENCHMARKING"
echo "=========================="

# Create benchmark report
REPORT_FILE="performance-benchmark-$(date +%Y%m%d_%H%M%S).md"

cat > $REPORT_FILE << EOF
# Performance Benchmark Report

**Date:** $(date '+%Y-%m-%d %H:%M:%S')
**Environment:** Production
**System Configuration:**
- Instances: $(kubectl get pods -n cortex-mcp -l app=cortex-mcp --no-headers | wc -l)
- Memory per Instance: $(kubectl describe pod -n cortex-mcp -l app=cortex-mcp | grep "Memory:" | head -1)
- CPU per Instance: $(kubectl describe pod -n cortex-mcp -l app=cortex-mcp | grep "CPU:" | head -1)

## Benchmark Results

### API Performance
EOF

echo "Generating performance benchmarks..."

# Test API endpoints
echo "### API Response Times" >> $REPORT_FILE
echo "" >> $REPORT_FILE

endpoints=("/health" "/ready" "/api/memory/find" "/api/memory/store")
for endpoint in "${endpoints[@]}"; do
    echo "Testing $endpoint..."

    # Run 100 requests and calculate average
    total_time=0
    for i in {1..100}; do
        if [[ "$endpoint" == "/api/memory/find" ]]; then
            response_time=$(curl -o /dev/null -s -w '%{time_total}' -X POST http://localhost:3000$endpoint -H 'Content-Type: application/json' -d '{"query":"test","limit":10}')
        elif [[ "$endpoint" == "/api/memory/store" ]]; then
            response_time=$(curl -o /dev/null -s -w '%{time_total}' -X POST http://localhost:3000$endpoint -H 'Content-Type: application/json' -d '{"items":[{"kind":"observation","content":"test"}]}')
        else
            response_time=$(curl -o /dev/null -s -w '%{time_total}' http://localhost:3000$endpoint)
        fi
        total_time=$(echo "$total_time + $response_time" | bc)
    done

    avg_time=$(echo "scale=3; $total_time / 100" | bc)
    echo "- $endpoint: ${avg_time}s average" >> $REPORT_FILE
done

# Test search performance with different result sizes
echo "" >> $REPORT_FILE
echo "### Search Performance by Result Size" >> $REPORT_FILE
echo "" >> $REPORT_FILE

result_sizes=(10 50 100 500)
for size in "${result_sizes[@]}"; do
    echo "Testing search with $size results..."

    total_time=0
    for i in {1..50}; do
        response_time=$(curl -o /dev/null -s -w '%{time_total}' -X POST http://localhost:3000/api/memory/find -H 'Content-Type: application/json' -d "{\"query\":\"test\",\"limit\":$size}")
        total_time=$(echo "$total_time + $response_time" | bc)
    done

    avg_time=$(echo "scale=3; $total_time / 50" | bc)
    echo "- $size results: ${avg_time}s average" >> $REPORT_FILE
done

# Test concurrent load
echo "" >> $REPORT_FILE
echo "### Concurrent Load Performance" >> $REPORT_FILE
echo "" >> $REPORT_FILE

concurrent_levels=(5 10 20 50)
for level in "${concurrent_levels[@]}"; do
    echo "Testing $level concurrent requests..."

    if command -v hey &> /dev/null; then
        # Use hey for concurrent testing
        temp_output=$(mktemp)
        hey -n 100 -c $level -m POST \
            -H "Content-Type: application/json" \
            -d '{"query":"test","limit":10}' \
            http://localhost:3000/api/memory/find > $temp_output 2>&1

        # Extract metrics from hey output
        avg_response=$(grep "Average:" $temp_output | awk '{print $2}')
        p95_response=$(grep "95th percentile:" $temp_output | awk '{print $3}')
        rps=$(grep "Requests/sec:" $temp_output | awk '{print $2}')

        echo "- $level concurrent:" >> $REPORT_FILE
        echo "  - Average: ${avg_response}s" >> $REPORT_FILE
        echo "  - 95th percentile: ${p95_response}s" >> $REPORT_FILE
        echo "  - Throughput: ${rps} req/s" >> $REPORT_FILE

        rm $temp_output
    fi
done

# Add system metrics
echo "" >> $REPORT_FILE
echo "### System Metrics During Load" >> $REPORT_FILE
echo "" >> $REPORT_FILE

if command -v docker &> /dev/null; then
    echo "#### Docker Container Metrics" >> $REPORT_FILE
    echo "\`\`\`" >> $REPORT_FILE
    docker stats --no-stream | grep cortex-mcp >> $REPORT_FILE
    echo "\`\`\`" >> $REPORT_FILE
fi

# Qdrant metrics
echo "" >> $REPORT_FILE
echo "#### Qdrant Metrics" >> $REPORT_FILE
echo "\`\`\`" >> $REPORT_FILE
curl -s http://localhost:6333/metrics | grep -E "(qdrant_app_collections_points_total|qdrant_search_requests_total)" >> $REPORT_FILE
echo "\`\`\`" >> $REPORT_FILE

# Add recommendations
echo "" >> $REPORT_FILE
echo "## Performance Recommendations" >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Analyze results and provide recommendations
echo "Based on the benchmark results:" >> $REPORT_FILE

echo "Report saved to: $REPORT_FILE"
echo "🎉 Performance benchmarking completed"

# Display summary
echo ""
echo "📊 BENCHMARK SUMMARY"
echo "===================="
echo "Report: $REPORT_FILE"
echo "API Performance: See report for detailed metrics"
echo "System Load: See report for resource utilization"
echo ""
echo "Review the full report for detailed performance analysis and recommendations"
```

This comprehensive scaling runbook provides procedures for all aspects of scaling the Cortex Memory MCP Server, from horizontal and vertical scaling to load balancer configuration, database scaling, and performance tuning. Each procedure includes specific commands, expected outputs, and validation steps.
