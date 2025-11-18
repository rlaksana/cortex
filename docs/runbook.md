# Cortex Memory MCP Server - Deployment Runbook

**Version**: 2.0.1
**Last Updated**: 2025-11-14
**Author**: Cortex Team

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Environment Configuration](#environment-configuration)
4. [Deployment Procedures](#deployment-procedures)
5. [Health Monitoring](#health-monitoring)
6. [Troubleshooting](#troubleshooting)
7. [Rollback Procedures](#rollback-procedures)
8. [Security Considerations](#security-considerations)
9. [Performance Tuning](#performance-tuning)
10. [Backup and Recovery](#backup-and-recovery)
11. [Common Failures and Recovery](#common-failures-and-recovery)

---

## 🎯 Overview

This runbook provides comprehensive procedures for deploying, monitoring, and maintaining the Cortex Memory MCP Server across development, staging, and production environments.

### Architecture Components

- **Cortex Memory MCP Server**: Core application with vector search capabilities
- **Qdrant Vector Database**: High-performance vector storage and search
- **Monitoring Stack**: Prometheus, Grafana, AlertManager
- **Load Balancer**: Nginx reverse proxy
- **Container Runtime**: Docker with security hardening

---

## ✅ Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| Memory | 4GB | 16GB+ |
| Storage | 20GB SSD | 100GB+ SSD |
| Network | 100Mbps | 1Gbps+ |
| Docker | 20.10+ | 24.0+ |
| Node.js | 18.x | 20.x |

### Required Secrets

Before deployment, ensure the following secrets are configured:

```bash
# OpenAI API (MANDATORY)
OPENAI_API_KEY=sk-...

# Security Keys
JWT_SECRET=minimum_32_characters_secure_random_string
MCP_API_KEY=minimum_48_characters_secure_random_string
ENCRYPTION_KEY=64_character_hex_string_for_data_encryption

# Database (if using managed Qdrant)
QDRANT_API_KEY=your_qdrant_api_key
```

### SSL/TLS Certificates

Production deployments require:
- Valid SSL certificates for all domains
- Certificate monitoring and renewal process
- Support for HTTPS-only communication

---

## 🌍 Environment Configuration

### Development Environment

```bash
# Environment setup
cp .env.example .env
# Edit .env with development configuration

# Quick start
npm run quickstart
```

### Staging Environment

```bash
# Staging configuration
cp .env.staging .env
# Update with staging-specific values

# Deploy to staging
docker-compose -f docker/docker-compose.staging.yml up -d

# Verify deployment
curl -f https://staging.your-domain.com/health
```

### Production Environment

```bash
# Production configuration
cp .env.production .env
# Update with production values (SECURE ENVIRONMENT)

# Deploy with monitoring stack
docker-compose -f docker/docker-compose.production.yml up -d

# Health check sequence
curl -f https://api.your-domain.com/health
curl -f https://api.your-domain.com/metrics
```

---

## 🚀 Deployment Procedures

### Automated Deployment (CI/CD)

#### Development → Staging

```bash
# Push to develop branch
git checkout develop
git add .
git commit -m "feat: deploy to staging"
git push origin develop

# Monitor deployment
# GitHub Actions will automatically:
# 1. Run tests and security scans
# 2. Build Docker image
# 3. Deploy to staging
# 4. Run smoke tests
```

#### Staging → Production

```bash
# Create release tag
git tag -a v2.0.1 -m "Production release v2.0.1"
git push origin v2.0.1

# Create GitHub Release
gh release create v2.0.1 --generate-notes

# Monitor production deployment
# GitHub Actions will automatically:
# 1. Deploy to production
# 2. Run production health checks
# 3. Update monitoring dashboards
```

### Manual Deployment

#### Step 1: Pre-deployment Checks

```bash
# Validate configuration
npm run prod:validate

# Health check of dependencies
npm run test:connection

# Backup current deployment
docker exec cortex-mcp-prod tar -czf /backup/pre-deploy-$(date +%Y%m%d-%H%M%S).tar.gz /app/data
```

#### Step 2: Build and Deploy

```bash
# Build latest version
npm run build

# Build Docker image
docker build -f docker/Dockerfile -t cortex-mcp:v2.0.1 .

# Deploy with zero downtime
docker-compose -f docker/docker-compose.production.yml up -d --no-deps cortex-mcp-primary
```

#### Step 3: Post-deployment Verification

```bash
# Health check sequence
sleep 60  # Wait for startup
curl -f https://api.your-domain.com/health
curl -f https://api.your-domain.com/metrics

# Run smoke tests
npm run test:e2e:production

# Verify monitoring
curl -f http://localhost:9091/api/v1/query?query=up
```

---

## 📊 Health Monitoring

### Health Check Endpoints

| Endpoint | Purpose | Frequency |
|----------|---------|-----------|
| `/health` | Application health | Every 30s |
| `/health/detailed` | Detailed system status | Every 2m |
| `/metrics` | Prometheus metrics | Every 30s |
| `/metrics/health` | Health metrics | Every 1m |

### Critical Metrics to Monitor

```bash
# Application health
up{job="cortex-mcp"}

# Response times
http_request_duration_seconds{quantile="0.95"}

# Error rates
http_requests_total{status=~"5.."}

# Memory usage
process_resident_memory_bytes

# Database connections
qdrant_connections_active

# Vector search performance
vector_search_duration_seconds{quantile="0.99"}
```

### Alerting Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Response Time (p95) | >500ms | >2000ms |
| Error Rate | >1% | >5% |
| Memory Usage | >80% | >95% |
| Database Connections | >15 | >18 |
| CPU Usage | >70% | >90% |

---

## 🔧 Troubleshooting

### Common Issues and Solutions

#### 1. Application Won't Start

**Symptoms**: Container exits immediately, health checks fail

**Diagnosis**:
```bash
# Check container logs
docker logs cortex-mcp-prod

# Validate environment
docker exec cortex-mcp-prod printenv | grep -E "(OPENAI_API_KEY|JWT_SECRET)"

# Check resource limits
docker stats cortex-mcp-prod
```

**Solutions**:
- Verify all required environment variables
- Check resource limits (memory/CPU)
- Validate OpenAI API key
- Ensure Qdrant is accessible

#### 2. High Memory Usage

**Symptoms**: Memory >80%, OOM errors

**Diagnosis**:
```bash
# Check memory breakdown
docker exec cortex-mcp-prod node -e "console.log(process.memoryUsage())"

# Monitor trends
docker stats --no-stream cortex-mcp-prod
```

**Solutions**:
- Adjust NODE_OPTIONS: `--max-old-space-size=4096`
- Optimize embedding batch size
- Enable garbage collection tuning
- Scale horizontally

#### 3. Slow Search Performance

**Symptoms**: Search requests >2s, timeouts

**Diagnosis**:
```bash
# Check Qdrant health
curl -f http://localhost:6333/health

# Monitor database metrics
curl -s http://localhost:6333/metrics | grep qdrant

# Check collection statistics
curl -s "http://localhost:6333/collections/cortex-memory-production"
```

**Solutions**:
- Optimize similarity threshold
- Increase Qdrant resources
- Check network latency
- Consider collection sharding

#### 4. Authentication Failures

**Symptoms**: 401 errors, JWT validation failures

**Diagnosis**:
```bash
# Check JWT secret
echo $JWT_SECRET | wc -c  # Should be 32+ characters

# Verify token format
curl -H "Authorization: Bearer $TOKEN" https://api.your-domain.com/health
```

**Solutions**:
- Regenerate JWT secret (32+ chars)
- Check token expiration
- Verify clock synchronization
- Update API key configuration

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=debug
export DEBUG_MODE=true

# Restart with debug
docker-compose -f docker/docker-compose.production.yml restart cortex-mcp-primary

# Monitor debug logs
docker logs -f cortex-mcp-prod | grep DEBUG
```

---

## 🔄 Rollback Procedures

### Emergency Rollback

```bash
# 1. Identify last stable version
git log --oneline -10

# 2. Tag last known good commit
git tag -a rollback-v2.0.0 -m "Emergency rollback to v2.0.0"

# 3. Deploy rollback version
docker pull ghcr.io/your-org/cortex-mcp:rollback-v2.0.0
docker-compose -f docker/docker-compose.production.yml up -d --force-recreate

# 4. Verify rollback
curl -f https://api.your-domain.com/health
npm run test:e2e:production
```

### Database Rollback

```bash
# 1. Stop application
docker stop cortex-mcp-prod

# 2. Restore Qdrant snapshot
docker exec cortex-qdrant-prod \
  curl -X POST 'http://localhost:6333/snapshots/restore' \
  -H 'Content-Type: application/json' \
  -d '{"snapshot_name": "backup-20251114-120000"}'

# 3. Restart application
docker start cortex-mcp-prod

# 4. Verify data integrity
npm run test:integration:database
```

---

## 🔒 Security Considerations

### Security Checklist

#### Pre-deployment:
- [ ] All secrets are properly stored in vault
- [ ] SSL certificates are valid and renewed
- [ ] Security headers are configured
- [ ] Rate limiting is enabled
- [ ] Input validation is active
- [ ] Audit logging is enabled

#### Runtime:
- [ ] Container runs as non-root user
- [ ] Read-only filesystem where possible
- [ ] Network segmentation is configured
- [ ] Security patches are applied
- [ ] Regular vulnerability scans run

### Security Monitoring

```bash
# Check for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image ghcr.io/your-org/cortex-mcp:latest

# Monitor security events
docker logs cortex-mcp-prod | grep -i "security\|auth\|unauthorized"

# Check SSL certificate expiry
openssl s_client -connect api.your-domain.com:443 2>/dev/null | \
  openssl x509 -noout -dates
```

---

## ⚡ Performance Tuning

### Container Resources

```yaml
# Recommended production limits
deploy:
  resources:
    limits:
      cpus: '2.0'
      memory: 8G
    reservations:
      cpus: '1.0'
      memory: 4G
```

### Application Tuning

```bash
# Node.js optimization
export NODE_OPTIONS="--max-old-space-size=8192 --optimize-for-size"
export UV_THREADPOOL_SIZE=16

# Embedding optimization
export EMBEDDING_BATCH_SIZE=25
export EMBEDDING_TIMEOUT=30000

# Database optimization
export QDRANT_MAX_CONNECTIONS=20
export QDRANT_TIMEOUT=60000
```

### Monitoring Performance

```bash
# Performance profiling
npm run performance:profile

# Load testing
npm run bench:stress

# Memory profiling
npm run test:performance:memory
```

---

## 💾 Backup and Recovery

### Automated Backups

```bash
# Configure daily backups
export BACKUP_SCHEDULE="0 2 * * *"
export BACKUP_RETENTION_DAYS=30

# Manual backup trigger
npm run ops:backup:daily

# Verify backup integrity
npm run ops:backup:verify
```

### Recovery Procedures

```bash
# 1. Stop services
docker-compose -f docker/docker-compose.production.yml down

# 2. Restore from backup
./scripts/disaster-recovery.sh --backup-file /backup/backup-20251114.tar.gz

# 3. Start services
docker-compose -f docker/docker-compose.production.yml up -d

# 4. Verify recovery
npm run test:integration:recovery
```

---

## 🚨 Common Failures and Recovery

### 1. Complete System Outage

**Symptoms**: All services down, no network connectivity

**Recovery Steps**:
1. **Assess Scope**: `ping api.your-domain.com`
2. **Check Infrastructure**: `docker ps -a`
3. **Restart Services**: `docker-compose -f docker/docker-compose.production.yml restart`
4. **Verify Recovery**: `curl -f https://api.your-domain.com/health`
5. **Communicate**: Alert stakeholders via notification channels

### 2. Database Connection Failure

**Symptoms**: 503 errors, database timeout messages

**Recovery Steps**:
1. **Check Qdrant**: `curl -f http://localhost:6333/health`
2. **Restart Database**: `docker restart cortex-qdrant-prod`
3. **Verify Network**: `telnet qdrant-host 6333`
4. **Check Configuration**: Review `QDRANT_URL` and `QDRANT_API_KEY`
5. **Failover**: If using cluster, promote replica

### 3. High Error Rate

**Symptoms**: >5% 5xx errors, latency spikes

**Recovery Steps**:
1. **Scale Out**: `docker-compose up -d --scale cortex-mcp-primary=3`
2. **Check Dependencies**: Verify external services (OpenAI, Qdrant)
3. **Load Balance**: Restart load balancer
4. **Debug**: Enable debug logging
5. **Rollback**: If recent deployment, rollback to previous version

### 4. Memory Exhaustion

**Symptoms**: OOM errors, container restarts

**Recovery Steps**:
1. **Free Memory**: `docker system prune -f`
2. **Increase Limits**: Adjust memory limits in docker-compose
3. **Optimize**: Reduce batch sizes, enable garbage collection
4. **Scale Horizontally**: Add more instances
5. **Monitor**: Set up memory usage alerts

---

## 📞 Emergency Contacts

| Role | Contact | Availability |
|------|---------|---------------|
| DevOps Lead | devops@your-domain.com | 24/7 |
| Security Team | security@your-domain.com | 24/7 |
| Database Team | database@your-domain.com | Business hours |
| Product Team | product@your-domain.com | Business hours |

---

## 🔄 Runbook Maintenance

- **Monthly**: Review and update procedures
- **Quarterly**: Test disaster recovery scenarios
- **Semi-annually**: Security audit and penetration testing
- **Annually**: Complete runbook review and updates

---

**Document Version**: 2.0.1
**Next Review**: 2025-12-14
**Approved By**: Cortex Team

---

*This runbook should be updated whenever:
- New deployment procedures are implemented
- Infrastructure changes occur
- Security requirements evolve
- Performance baselines are updated*