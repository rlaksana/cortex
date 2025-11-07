# Cortex Memory MCP Production Deployment Guide

## Overview

This comprehensive guide covers the complete production deployment of Cortex Memory MCP, including Docker, Kubernetes, monitoring, security hardening, and CI/CD integration.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Docker Deployment](#docker-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [Monitoring and Alerting](#monitoring-and-alerting)
6. [Security Hardening](#security-hardening)
7. [CI/CD Pipeline](#cicd-pipeline)
8. [Backup and Recovery](#backup-and-recovery)
9. [Validation and Testing](#validation-and-testing)
10. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

#### Minimum Hardware Requirements

- **CPU**: 4 cores (8 recommended for production)
- **Memory**: 8GB RAM (16GB recommended for production)
- **Storage**: 100GB SSD (500GB recommended for production)
- **Network**: 1Gbps connection

#### Software Requirements

- Docker Engine 20.10+
- Docker Compose 2.0+
- Kubernetes 1.25+ (for Kubernetes deployment)
- kubectl 1.25+
- Helm 3.8+ (optional)
- Node.js 18+ (for local development)
- Git 2.30+

#### External Dependencies

- Qdrant Vector Database 1.7+
- OpenAI API account and key
- SMTP server for email notifications
- S3-compatible storage for backups
- SSL certificates (Let's Encrypt recommended)

## Environment Setup

### 1. Clone Repository

```bash
git clone https://github.com/your-org/cortex-memory-mcp.git
cd cortex-memory-mcp
```

### 2. Configure Environment Variables

Create environment-specific configuration files:

```bash
# Development
cp .env.example .env.dev

# Staging
cp .env.example .env.staging

# Production
cp .env.example .env.production
```

### 3. Set Production Secrets

```bash
# Generate secure secrets
export JWT_SECRET=$(openssl rand -base64 32)
export API_KEY=$(openssl rand -base64 24)
export SESSION_SECRET=$(openssl rand -base64 32)
export ENCRYPTION_KEY=$(openssl rand -hex 32)

# Add to .env.production
echo "JWT_SECRET=$JWT_SECRET" >> .env.production
echo "API_KEY=$API_KEY" >> .env.production
echo "SESSION_SECRET=$SESSION_SECRET" >> .env.production
echo "ENCRYPTION_KEY=$ENCRYPTION_KEY" >> .env.production
```

### 4. Configure External Services

#### OpenAI API

```bash
echo "OPENAI_API_KEY=your-openai-api-key" >> .env.production
echo "EMBEDDING_MODEL=text-embedding-3-large" >> .env.production
```

#### Backup Storage (S3)

```bash
echo "S3_BACKUP_BUCKET=your-backup-bucket" >> .env.production
echo "AWS_ACCESS_KEY_ID=your-access-key" >> .env.production
echo "AWS_SECRET_ACCESS_KEY=your-secret-key" >> .env.production
echo "AWS_REGION=us-west-2" >> .env.production
```

#### Email Notifications

```bash
echo "SMTP_HOST=smtp.gmail.com" >> .env.production
echo "SMTP_USER=your-email@gmail.com" >> .env.production
echo "SMTP_PASSWORD=your-app-password" >> .env.production
echo "SMTP_FROM=noreply@cortex-mcp.example.com" >> .env.production
```

## Docker Deployment

### Development Environment

```bash
# Start development environment
docker-compose -f environments/dev/docker-compose.yml up -d

# View logs
docker-compose -f environments/dev/docker-compose.yml logs -f

# Stop development environment
docker-compose -f environments/dev/docker-compose.yml down
```

### Staging Environment

```bash
# Deploy to staging
./scripts/deploy/deploy.sh staging

# Or manually
docker-compose -f environments/staging/docker-compose.yml up -d
```

### Production Environment

```bash
# Validate production configuration
./scripts/validate-production.sh --environment prod

# Deploy to production (with confirmation)
./scripts/deploy/deploy.sh prod

# Or force deployment
./scripts/deploy/deploy.sh prod --force
```

### Production Docker Compose Features

- **High Availability**: Multiple instances with load balancing
- **Security Hardening**: Non-root users, read-only filesystems, security headers
- **Resource Management**: CPU and memory limits, health checks
- **Monitoring**: Prometheus, Grafana, and alerting
- **Backup**: Automated backup service with S3 integration
- **SSL/TLS**: HTTPS with Let's Encrypt certificates

## Kubernetes Deployment

### Prerequisites

```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Verify cluster access
kubectl cluster-info
```

### Deploy to Kubernetes

```bash
# Apply namespace and configuration
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml

# Deploy database
kubectl apply -f k8s/qdrant-statefulset.yaml

# Deploy application
kubectl apply -f k8s/cortex-mcp-deployment.yaml

# Deploy monitoring
kubectl apply -f k8s/monitoring.yaml

# Configure ingress
kubectl apply -f k8s/ingress.yaml
```

### Verify Deployment

```bash
# Check pod status
kubectl get pods -n cortex-mcp

# Check services
kubectl get services -n cortex-mcp

# Check ingress
kubectl get ingress -n cortex-mcp

# View logs
kubectl logs -f deployment/cortex-mcp -n cortex-mcp
```

### Kubernetes Features

- **Namespace Isolation**: Separate namespaces for application and monitoring
- **Resource Management**: Resource quotas, limits, and HPA
- **Security**: Network policies, RBAC, pod security policies
- **High Availability**: Multiple replicas with anti-affinity rules
- **Monitoring**: Prometheus Operator, Grafana, and ServiceMonitors
- **Ingress**: TLS termination, rate limiting, and security headers

## Monitoring and Alerting

### Prometheus Configuration

Prometheus is configured to collect metrics from:

- Cortex MCP application
- Qdrant vector database
- System metrics (Node Exporter)
- Container metrics (cAdvisor)

### Grafana Dashboards

Pre-configured dashboards include:

- **Application Performance**: Response times, error rates, throughput
- **Resource Usage**: CPU, memory, disk, and network utilization
- **Database Performance**: Qdrant query performance and storage metrics
- **System Health**: Node status and container health

### Alerting Rules

Critical alerts:

- Application downtime
- High error rates
- Resource exhaustion
- Database connectivity issues

Warning alerts:

- High response times
- Resource usage thresholds
- Backup failures

### Access Monitoring

```bash
# Grafana Dashboard
https://grafana.cortex-mcp.example.com
# Default credentials: admin/change-me-in-production

# Prometheus
https://prometheus.cortex-mcp.example.com

# Alertmanager
https://alerts.cortex-mcp.example.com
```

## Security Hardening

### Container Security

- **Non-root Users**: All containers run as non-root users
- **Minimal Images**: Multi-stage builds with minimal base images
- **Read-only Filesystems**: Where possible
- **Resource Limits**: CPU, memory, and disk quotas
- **Security Scanning**: Automated vulnerability scanning in CI/CD

### Network Security

- **TLS 1.3**: All external communication encrypted
- **Network Policies**: Restrict inter-pod communication
- **Ingress Security**: Rate limiting, security headers, WAF rules
- **VPC Isolation**: Network segmentation for different environments

### Application Security

- **Authentication**: JWT-based authentication
- **Authorization**: Role-based access control
- **Input Validation**: Comprehensive input sanitization
- **Secrets Management**: Encrypted secrets with rotation
- **Audit Logging**: Comprehensive audit trails

### Data Security

- **Encryption-at-Rest**: All data encrypted
- **Encryption-in-Transit**: TLS for all data transfers
- **Key Management**: Secure key generation and rotation
- **Access Control**: Principle of least privilege

## CI/CD Pipeline

### GitHub Actions Workflow

The CI/CD pipeline includes:

1. **Security Scanning**
   - npm audit
   - Snyk vulnerability scanning
   - Trivy container scanning

2. **Code Quality**
   - ESLint and Prettier
   - TypeScript type checking
   - Code complexity analysis

3. **Testing**
   - Unit tests with coverage
   - Integration tests
   - Contract tests
   - Performance tests

4. **Build and Deploy**
   - Docker image building
   - Multi-environment deployment
   - Kubernetes deployment
   - Rollback capabilities

### Deployment Environments

- **Development**: Auto-deploy from develop branch
- **Staging**: Auto-deploy from main branch
- **Production**: Manual approval required

### Pipeline Features

- **Automated Testing**: Comprehensive test suite
- **Security Gates**: Automated security scanning
- **Quality Gates**: Code quality thresholds
- **Rollback**: Automatic rollback on failure
- **Notification**: Slack/email notifications

## Backup and Recovery

### Automated Backups

- **Database Backups**: Qdrant snapshots
- **Configuration Backups**: Docker Compose and Kubernetes configs
- **Log Backups**: Application and system logs
- **Cloud Storage**: S3-compatible backup storage

### Backup Schedule

- **Full Backups**: Daily at 2 AM
- **Incremental Backups**: Every 4 hours
- **Log Backups**: Hourly
- **Retention**: 30 days (configurable)

### Recovery Procedures

#### Database Recovery

```bash
# Restore from latest backup
docker-compose -f environments/prod/docker-compose.yml exec qdrant \
  qdrant --snapshot-path /qdrant/snapshots/latest.snapshot
```

#### Application Recovery

```bash
# Rollback to previous version
./scripts/deploy/deploy.sh prod --rollback
```

#### Disaster Recovery

1. Restore infrastructure
2. Restore configurations
3. Restore database
4. Verify application health
5. Update DNS if needed

## Validation and Testing

### Pre-deployment Validation

```bash
# Run comprehensive validation
./scripts/validate-production.sh --environment prod

# Skip specific validations
./scripts/validate-production.sh --skip-security --skip-backup
```

### Validation Categories

1. **Prerequisites**: Tools and dependencies
2. **Security**: Security configurations
3. **Performance**: Resource and performance settings
4. **Backup**: Backup and recovery configurations
5. **Kubernetes**: Manifests and configurations
6. **Monitoring**: Alerting and metrics setup
7. **Networking**: Ingress and network policies

### Smoke Tests

```bash
# Run smoke tests
npm run test:smoke

# Environment-specific smoke tests
npm run test:smoke:prod
npm run test:smoke:staging
```

### Performance Testing

```bash
# Load testing
npm run test:load

# Stress testing
npm run test:stress

# Performance profiling
npm run test:profile
```

## Troubleshooting

### Common Issues

#### Application Won't Start

```bash
# Check logs
docker-compose logs cortex-mcp-primary

# Check health status
curl http://localhost:3000/health

# Check configuration
docker-compose config
```

#### Database Connection Issues

```bash
# Check Qdrant status
docker-compose exec qdrant curl http://localhost:6333/health

# Check network connectivity
docker-compose exec cortex-mcp-primary ping qdrant
```

#### Performance Issues

```bash
# Check resource usage
docker stats

# Check application metrics
curl http://localhost:9090/metrics

# Check system metrics
docker exec node-exporter cat /proc/meminfo
```

#### Monitoring Issues

```bash
# Check Prometheus targets
curl http://localhost:9091/api/v1/targets

# Check Grafana datasource
curl http://localhost:3001/api/health

# Check Alertmanager
curl http://localhost:9093/api/v1/status
```

### Debug Commands

```bash
# Debug application
docker-compose -f environments/prod/docker-compose.yml exec cortex-mcp-primary \
  node --inspect=0.0.0.0:9229 dist/index.js

# Network debugging
docker network ls
docker network inspect cortex-prod-network

# Volume inspection
docker volume ls
docker volume inspect cortex-prod-data
```

### Log Analysis

```bash
# Real-time logs
docker-compose logs -f cortex-mcp-primary

# Error logs only
docker-compose logs cortex-mcp-primary | grep ERROR

# Performance logs
docker-compose logs cortex-mcp-primary | grep "response_time"
```

## Maintenance

### Regular Tasks

#### Daily

- Monitor application health
- Check backup completion
- Review error logs
- Verify security alerts

#### Weekly

- Review performance metrics
- Update security patches
- Clean up old logs and backups
- Test restore procedures

#### Monthly

- Security audit
- Performance optimization review
- Capacity planning
- Documentation updates

### Scaling Procedures

#### Horizontal Scaling

```bash
# Scale application
kubectl scale deployment cortex-mcp --replicas=5 -n cortex-mcp

# Or via Docker Compose
docker-compose up -d --scale cortex-mcp-primary=3
```

#### Vertical Scaling

```bash
# Update resource limits
kubectl patch deployment cortex-mcp -n cortex-mcp -p '{"spec":{"template":{"spec":{"containers":[{"name":"cortex-mcp","resources":{"limits":{"memory":"8Gi"}}}]}}}}'
```

### Updates and Upgrades

#### Application Updates

```bash
# Update application version
docker-compose pull cortex-mcp:2.0.2
docker-compose up -d

# Or via deployment script
./scripts/deploy/deploy.sh prod
```

#### Database Upgrades

```bash
# Backup before upgrade
./scripts/backup/create-backup.sh

# Upgrade Qdrant
docker-compose pull qdrant:v1.8.0
docker-compose up -d qdrant

# Verify upgrade
curl http://localhost:6333/collections
```

## Support

### Documentation

- [API Reference](docs/API-REFERENCE.md)
- [Architecture Guide](docs/ARCH-SYSTEM.md)
- [Operations Guide](docs/OPS-DISASTER-RECOVERY.md)
- [Troubleshooting Guide](docs/TROUBLESHOOT-ERRORS.md)

### Community

- GitHub Issues: https://github.com/your-org/cortex-memory-mcp/issues
- Discussions: https://github.com/your-org/cortex-memory-mcp/discussions
- Slack: #cortex-mcp on your workspace

### Emergency Contacts

- DevOps Team: devops@yourcompany.com
- Security Team: security@yourcompany.com
- On-call Engineer: +1-555-0123

## Changelog

### Version 2.0.1 (Current)

- Production-ready deployment configurations
- Comprehensive security hardening
- Full monitoring and alerting setup
- Automated CI/CD pipeline
- Kubernetes manifests and configurations
- Environment-specific configurations
- Backup and disaster recovery procedures

### Version 2.0.0

- Initial production release
- Basic Docker deployment
- Core functionality

---

**Last Updated**: $(date)
**Version**: 2.0.1
**Maintainer**: Cortex MCP Team
