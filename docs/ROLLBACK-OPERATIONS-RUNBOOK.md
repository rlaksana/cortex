# Cortex Memory MCP - Rollback Operations Runbook

**Version:** 2.0.1
**Last Updated:** 2025-11-05
**Author:** Cortex Operations Team

## Table of Contents

1. [Overview](#overview)
2. [Rollback Scope & Impact Assessment](#rollback-scope--impact-assessment)
3. [Emergency Rollback Procedures](#emergency-rollback-procedures)
4. [Rollback Scenarios](#rollback-scenarios)
   - [Full Application Rollback](#full-application-rollback)
   - [Database-Only Rollback](#database-only-rollback)
   - [Configuration Rollback](#configuration-rollback)
   - [Partial/Feature Rollback](#partialfeature-rollback)
5. [Verification Procedures](#verification-procedures)
6. [Recovery Time Objectives (RTO/RPO)](#recovery-time-objectives-rtorpo)
7. [Pre-Deployment Rollback Testing](#pre-deployment-rollback-testing)
8. [Communication Procedures](#communication-procedures)
9. [Troubleshooting](#troubleshooting)
10. [Post-Rollback Activities](#post-rollback-activities)

---

## Overview

This runbook provides comprehensive procedures for rolling back Cortex Memory MCP Server deployments in various failure scenarios. The system uses Qdrant vector database with Node.js MCP server architecture.

### Architecture Summary

- **Application:** Node.js MCP Server (v2.0.1)
- **Database:** Qdrant Vector Database
- **Deployment:** Docker Compose + Native Node.js
- **Monitoring:** Built-in health checks and metrics
- **Backup:** Automated Qdrant snapshots and configuration backups

### Rollback Triggers

1. **Critical Issues:** Service outage, data corruption, security vulnerabilities
2. **Performance Degradation:** Response times > 5s, error rate > 5%
3. **Data Integrity Issues:** Vector search failures, indexing problems
4. **Configuration Errors:** Invalid environment settings, authentication failures
5. **Dependency Failures:** Qdrant connection issues, external API failures

---

## Rollback Scope & Impact Assessment

### Blast Radius Analysis

| Rollback Type        | User Impact           | Data Impact         | Downtime     | Dependencies      |
| -------------------- | --------------------- | ------------------- | ------------ | ----------------- |
| **Full Application** | Complete outage       | No data loss        | 2-5 minutes  | All services      |
| **Database Only**    | Read-only mode        | Potential data loss | 1-3 minutes  | Qdrant only       |
| **Configuration**    | Partial functionality | No data loss        | < 1 minute   | No dependencies   |
| **Partial Feature**  | Limited features      | No data loss        | < 30 seconds | Targeted services |

### Impact Assessment Matrix

#### Critical Impact (Immediate Rollback Required)

- Service completely unavailable
- Data corruption or loss
- Security breach vulnerability
- Error rate > 10%

#### High Impact (Rollback within 5 minutes)

- Response times > 10 seconds
- Error rate 5-10%
- Critical features non-functional
- Database connection failures

#### Medium Impact (Rollback within 15 minutes)

- Response times 5-10 seconds
- Error rate 2-5%
- Non-critical features affected
- Performance degradation

#### Low Impact (Rollback within 30 minutes)

- Minor performance issues
- Non-essential features affected
- Cosmetic issues

---

## Emergency Rollback Procedures

### Immediate Response (First 60 Seconds)

1. **Alert Team:** Send emergency notification to on-call engineers
2. **Assess Impact:** Determine scope and severity using health checks
3. **Initiate Rollback:** Execute appropriate rollback procedure
4. **Monitor Progress:** Track rollback status and system health

### Emergency Contacts

- **Primary On-Call:** [Contact Information]
- **Secondary On-Call:** [Contact Information]
- **Engineering Manager:** [Contact Information]
- **Product Manager:** [Contact Information]

### Escalation Triggers

- Rollback fails to complete within RTO
- Data corruption detected during rollback
- Multiple service failures
- Security incident identified

---

## Rollback Scenarios

### Full Application Rollback

**Use Case:** Complete service failure, critical bugs, or widespread performance issues

#### Prerequisites

- Previous stable version available
- Full system backup created within last 24 hours
- Rollback window approved (2-5 minutes downtime)

#### Step-by-Step Procedure

**Step 1: Assess Current State (30 seconds)**

```bash
# Check current service status
systemctl status cortex-mcp
docker ps | grep qdrant
curl -s http://localhost:3000/health | jq .

# Check recent changes
git log --oneline -5
docker images | grep cortex
```

**Step 2: Stop Current Services (30 seconds)**

```bash
# Stop MCP server
sudo systemctl stop cortex-mcp

# Stop Qdrant if needed
docker-compose -f docker/docker-compose.yml down qdrant

# Verify services stopped
systemctl status cortex-mcp
docker ps | grep qdrant
```

**Step 3: Restore Previous Version (1-2 minutes)**

```bash
# Switch to previous stable tag
git checkout v2.0.0  # Replace with target version

# Build previous version
npm run clean:build
npm run build

# Restore configuration if needed
cp /backups/config/.env.production .env
cp /backups/config/production-config.json src/config/
```

**Step 4: Restore Database (1-2 minutes)**

```bash
# Restore Qdrant from backup
cd docker
docker-compose down qdrant

# Remove corrupted data
docker volume rm cortex-mcp_qdrant_data

# Restore from backup
tar -xzf /backups/qdrant/qdrant-backup-$(date +%Y%m%d-%H%M).tar.gz

# Start Qdrant
docker-compose up -d qdrant

# Wait for Qdrant to be ready
sleep 30
curl -s http://localhost:6333/health
```

**Step 5: Restart Services (30 seconds)**

```bash
# Start MCP server
sudo systemctl start cortex-mcp

# Verify services
systemctl status cortex-mcp
curl -s http://localhost:3000/health | jq .
```

#### Rollback Verification Checklist

- [ ] MCP server responding on port 3000
- [ ] Health endpoint returns healthy status
- [ ] Qdrant responding on port 6333
- [ ] Vector search operations working
- [ ] Memory store/retrieve operations functional
- [ ] No error logs in system logs
- [ ] Performance metrics within normal range

### Database-Only Rollback

**Use Case:** Data corruption, indexing issues, or Qdrant-specific problems

#### Prerequisites

- Recent Qdrant snapshot available
- Database backup verified
- Application code is stable

#### Step-by-Step Procedure

**Step 1: Isolate Database Issues (30 seconds)**

```bash
# Test Qdrant connectivity
curl -s http://localhost:6333/collections
curl -s http://localhost:6333/health

# Check application logs
tail -100 /app/logs/cortex-mcp.log | grep -i error
```

**Step 2: Create Emergency Backup (30 seconds)**

```bash
# Create snapshot of current state
curl -X POST "http://localhost:6333/collections/cortex-memory/snapshots" \
     -H "Content-Type: application/json"

# Copy snapshot to backup location
docker cp cortex-qdrant:/qdrant/snapshots /backups/qdrant/emergency-$(date +%Y%m%d-%H%M%S)/
```

**Step 3: Stop Database Operations (30 seconds)**

```bash
# Stop MCP server to prevent writes
sudo systemctl stop cortex-mcp

# Stop Qdrant
docker-compose -f docker/docker-compose.yml down qdrant
```

**Step 4: Restore Database (1-2 minutes)**

```bash
# Identify target backup
LATEST_BACKUP=$(ls -t /backups/qdrant/qdrant-backup-*.tar.gz | head -1)

# Remove corrupted data
docker volume rm cortex-mcp_qdrant_data

# Restore from backup
tar -xzf $LATEST_BACKUP -C /var/lib/docker/volumes/

# Restart Qdrant
docker-compose -f docker/docker-compose.yml up -d qdrant

# Wait for readiness
sleep 30
```

**Step 5: Verify Database Health (30 seconds)**

```bash
# Test collection access
curl -s http://localhost:6333/collections/cortex-memory

# Test vector search
curl -X POST "http://localhost:6333/collections/cortex-memory/points/search" \
     -H "Content-Type: application/json" \
     -d '{"vector": [0.1, 0.2, 0.3], "limit": 1}'
```

**Step 6: Restart Application (30 seconds)**

```bash
# Start MCP server
sudo systemctl start cortex-mcp

# Verify full system health
curl -s http://localhost:3000/health | jq .
```

#### Database Rollback Verification

- [ ] Qdrant collection accessible
- [ ] Vector search operations successful
- [ ] Point count matches expected
- [ ] No database connection errors
- [ ] Application can read/write vectors
- [ ] Search performance within acceptable range

### Configuration Rollback

**Use Case:** Invalid environment settings, authentication issues, configuration errors

#### Prerequisites

- Configuration backup available
- Change history documented
- Configuration validation tools ready

#### Step-by-Step Procedure

**Step 1: Identify Configuration Issue (30 seconds)**

```bash
# Check current configuration
cat .env | grep -v '^#' | sort
cat src/config/production-config.json | jq .

# Validate configuration
npm run prod:validate
npm run config:check
```

**Step 2: Backup Current Configuration (15 seconds)**

```bash
# Create timestamped backup
cp .env /backups/config/.env.failed-$(date +%Y%m%d-%H%M%S)
cp src/config/production-config.json /backups/config/production-config.failed-$(date +%Y%m%d-%H%M%S).json
```

**Step 3: Restore Previous Configuration (30 seconds)**

```bash
# Identify last known good configuration
LATEST_ENV_BACKUP=$(ls -t /backups/config/.env.production.* | head -1)
LATEST_CONFIG_BACKUP=$(ls -t /backups/config/production-config.json.* | head -1)

# Restore configuration
cp $LATEST_ENV_BACKUP .env
cp $LATEST_CONFIG_BACKUP src/config/production-config.json
```

**Step 4: Validate Restored Configuration (30 seconds)**

```bash
# Run configuration validation
npm run prod:validate
npm run config:check

# Check for syntax errors
node -c src/config/production-config.json
```

**Step 5: Restart Service (30 seconds)**

```bash
# Restart with new configuration
sudo systemctl restart cortex-mcp

# Verify health
curl -s http://localhost:3000/health | jq .
```

#### Configuration Rollback Verification

- [ ] Configuration files syntactically correct
- [ ] Environment variables properly set
- [ ] Service starts without errors
- [ ] Health endpoints responding
- [ ] Authentication working (if enabled)
- [ ] All features functional

### Partial/Feature Rollback

**Use Case:** Specific feature failure, experimental feature issues, targeted component problems

#### Prerequisites

- Feature flags implemented
- Component isolation possible
- Granular rollback mechanism available

#### Step-by-Step Procedure

**Step 1: Identify Affected Feature (30 seconds)**

```bash
# Check feature flags
grep -r "ENABLE_" .env
grep -r "feature" src/config/

# Check component-specific logs
tail -100 /app/logs/cortex-mcp.log | grep -E "(embedding|search|auth)"
```

**Step 2: Disable Problematic Feature (15 seconds)**

```bash
# Disable feature via environment variable
sed -i 's/INSIGHT_GENERATION_ENABLED=true/INSIGHT_GENERATION_ENABLED=false/' .env
sed -i 's/SEMANTIC_CHUNKING_OPTIONAL=true/SEMANTIC_CHUNKING_OPTIONAL=false/' .env

# Or disable via configuration
npm run feature:disable --feature=insight-generation
npm run feature:disable --feature=semantic-chunking
```

**Step 3: Restart Affected Components (30 seconds)**

```bash
# Graceful restart to apply changes
sudo systemctl reload cortex-mcp

# Or full restart if needed
sudo systemctl restart cortex-mcp
```

**Step 4: Verify Feature Rollback (30 seconds)**

```bash
# Test that feature is disabled
curl -s http://localhost:3000/features | jq '.insight_generation.enabled'

# Test core functionality still works
curl -s http://localhost:3000/health | jq .
```

#### Partial Rollback Verification

- [ ] Targeted feature disabled
- [ ] Core functionality intact
- [ ] No error propagation to other components
- [ ] Service stability maintained
- [ ] Performance impact minimal

---

## Verification Procedures

### Automated Health Checks

#### Primary Health Check

```bash
# Comprehensive health verification
curl -s http://localhost:3000/health | jq .
```

Expected response:

```json
{
  "status": "healthy",
  "timestamp": "2025-11-05T10:30:00.000Z",
  "uptime": 3600,
  "version": "2.0.0",
  "checks": {
    "database": "healthy",
    "embeddings": "healthy",
    "search": "healthy",
    "memory": "healthy"
  }
}
```

#### Component-Specific Checks

**Database Health:**

```bash
# Qdrant health check
curl -s http://localhost:6333/health

# Collection status
curl -s http://localhost:6333/collections/cortex-memory

# Point count verification
curl -s http://localhost:6333/collections/cortex-memory | jq '.result.points_count'
```

**Search Functionality:**

```bash
# Test vector search
curl -X POST "http://localhost:3000/api/search" \
     -H "Content-Type: application/json" \
     -d '{"query": "test query", "limit": 5}'
```

**Memory Operations:**

```bash
# Test memory storage
curl -X POST "http://localhost:3000/api/memory/store" \
     -H "Content-Type: application/json" \
     -d '{"content": "test memory", "type": "observation"}'

# Test memory retrieval
curl -X GET "http://localhost:3000/api/memory/recent?limit=5"
```

### Manual Verification Checklist

#### Service Availability

- [ ] HTTP server responding on port 3000
- [ ] Health endpoint returns 200 OK
- [ ] All API endpoints accessible
- [ ] No 500 errors in logs
- [ ] Response times < 2 seconds

#### Data Integrity

- [ ] Qdrant collection accessible
- [ ] Vector search operations working
- [ ] Memory storage/retrieval functional
- [ ] No data corruption indicators
- [ ] Point counts stable

#### Performance Metrics

- [ ] CPU usage < 80%
- [ ] Memory usage < 2GB
- [ ] Disk space available > 1GB
- [ ] Network latency < 100ms
- [ ] Error rate < 1%

#### Security Validation

- [ ] Authentication working (if enabled)
- [ ] Rate limiting functional
- [ ] HTTPS/TLS working (if configured)
- [ ] No security headers missing
- [ ] API key validation working

### Smoke Test Script

```bash
#!/bin/bash
# rollback-smoke-test.sh

set -e

echo "🔍 Starting rollback smoke test..."

# Test basic health
echo "1. Testing health endpoint..."
HEALTH_RESPONSE=$(curl -s http://localhost:3000/health)
if echo "$HEALTH_RESPONSE" | jq -e '.status == "healthy"' > /dev/null; then
    echo "✅ Health check passed"
else
    echo "❌ Health check failed"
    exit 1
fi

# Test database connection
echo "2. Testing database connection..."
DB_HEALTH=$(curl -s http://localhost:6333/health)
if echo "$DB_HEALTH" | jq -e '.result.status == "ok"' > /dev/null; then
    echo "✅ Database health check passed"
else
    echo "❌ Database health check failed"
    exit 1
fi

# Test search functionality
echo "3. Testing search functionality..."
SEARCH_RESPONSE=$(curl -s -X POST "http://localhost:3000/api/search" \
    -H "Content-Type: application/json" \
    -d '{"query": "test", "limit": 1}')
if echo "$SEARCH_RESPONSE" | jq -e '.results' > /dev/null; then
    echo "✅ Search functionality test passed"
else
    echo "❌ Search functionality test failed"
    exit 1
fi

# Test memory operations
echo "4. Testing memory operations..."
MEMORY_ID=$(curl -s -X POST "http://localhost:3000/api/memory/store" \
    -H "Content-Type: application/json" \
    -d '{"content": "smoke test", "type": "observation"}' | jq -r '.id')

if [ "$MEMORY_ID" != "null" ]; then
    echo "✅ Memory storage test passed"

    # Test retrieval
    RETRIEVE_RESPONSE=$(curl -s "http://localhost:3000/api/memory/$MEMORY_ID")
    if echo "$RETRIEVE_RESPONSE" | jq -e '.content' > /dev/null; then
        echo "✅ Memory retrieval test passed"
    else
        echo "❌ Memory retrieval test failed"
        exit 1
    fi
else
    echo "❌ Memory storage test failed"
    exit 1
fi

echo "🎉 All smoke tests passed! Rollback verification successful."
```

---

## Recovery Time Objectives (RTO/RPO)

### Recovery Time Objectives (RTO)

| Scenario                      | Target RTO | Typical Actual | Maximum Acceptable |
| ----------------------------- | ---------- | -------------- | ------------------ |
| **Full Application Rollback** | 5 minutes  | 2-5 minutes    | 10 minutes         |
| **Database-Only Rollback**    | 3 minutes  | 1-3 minutes    | 5 minutes          |
| **Configuration Rollback**    | 1 minute   | < 1 minute     | 2 minutes          |
| **Partial Feature Rollback**  | 30 seconds | < 30 seconds   | 1 minute           |

### Recovery Point Objectives (RPO)

| Scenario          | Target RPO | Backup Frequency | Maximum Data Loss |
| ----------------- | ---------- | ---------------- | ----------------- |
| **Vector Data**   | 15 minutes | Every 10 minutes | 15 minutes        |
| **Configuration** | 1 hour     | On change        | Minimal           |
| **System State**  | 1 hour     | Every 30 minutes | 1 hour            |
| **User Data**     | 5 minutes  | Real-time        | < 5 minutes       |

### Performance Targets During Rollback

| Metric            | Target        | Critical Threshold |
| ----------------- | ------------- | ------------------ |
| **Response Time** | < 2 seconds   | > 5 seconds        |
| **Error Rate**    | < 1%          | > 5%               |
| **Availability**  | > 99.9%       | < 99%              |
| **Throughput**    | > 100 req/min | < 50 req/min       |

---

## Pre-Deployment Rollback Testing

### Automated Rollback Testing

#### Test Environment Setup

```bash
# Create rollback test environment
npm run test:rollback:setup

# Deploy test version
npm run deploy:test

# Simulate failure
npm run test:failure:simulate
```

#### Rollback Test Execution

```bash
#!/bin/bash
# test-rollback-procedure.sh

echo "🧪 Testing rollback procedures..."

# Test 1: Configuration rollback
echo "1. Testing configuration rollback..."
npm run test:rollback:config

# Test 2: Database rollback
echo "2. Testing database rollback..."
npm run test:rollback:database

# Test 3: Full application rollback
echo "3. Testing full application rollback..."
npm run test:rollback:application

# Test 4: Partial feature rollback
echo "4. Testing partial feature rollback..."
npm run test:rollback:feature

echo "✅ All rollback tests completed"
```

### Manual Rollback Testing Checklist

#### Pre-Deployment Validation

- [ ] Rollback procedures documented and reviewed
- [ ] Backup procedures tested and verified
- [ ] Rollback test environment prepared
- [ ] Team trained on rollback procedures
- [ ] Communication channels tested

#### Rollback Dry Run

- [ ] Configuration backup restored successfully
- [ ] Database backup restored successfully
- [ ] Application version downgrade successful
- [ ] Service restart completed within RTO
- [ ] Health checks pass after rollback
- [ ] No data loss detected

#### Failure Scenario Testing

- [ ] Service unavailable scenario tested
- [ ] Database corruption scenario tested
- [ ] Configuration error scenario tested
- [ ] Partial failure scenario tested
- [ ] Network partition scenario tested

### Rollback Validation Test Suite

```typescript
// rollback-validation.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { RollbackValidator } from '../src/rollback-validator';

describe('Rollback Validation', () => {
  let validator: RollbackValidator;

  beforeEach(() => {
    validator = new RollbackValidator();
  });

  describe('Configuration Rollback', () => {
    it('should restore previous configuration', async () => {
      const result = await validator.testConfigurationRollback();
      expect(result.success).toBe(true);
      expect(result.duration).toBeLessThan(60000); // 1 minute
    });
  });

  describe('Database Rollback', () => {
    it('should restore database from backup', async () => {
      const result = await validator.testDatabaseRollback();
      expect(result.success).toBe(true);
      expect(result.dataLoss).toBeLessThan(100); // max 100 records
    });
  });

  describe('Application Rollback', () => {
    it('should rollback to previous version', async () => {
      const result = await validator.testApplicationRollback();
      expect(result.success).toBe(true);
      expect(result.downtime).toBeLessThan(300000); // 5 minutes
    });
  });
});
```

---

## Communication Procedures

### Rollback Communication Matrix

| Audience          | Communication Method | Timing            | Content                             |
| ----------------- | -------------------- | ----------------- | ----------------------------------- |
| **Internal Team** | Slack/Teams          | Immediate         | Technical details, rollback status  |
| **Management**    | Email/Phone          | Within 5 minutes  | Impact assessment, ETA              |
| **Users**         | Status Page          | Within 10 minutes | Service status, expected resolution |
| **Stakeholders**  | Email/Meeting        | Within 30 minutes | Root cause, prevention measures     |

### Communication Templates

#### Internal Team Notification

```
🚨 EMERGENCY ROLLBACK INITIATED

Service: Cortex Memory MCP
Time: [Timestamp]
Issue: [Brief description]
Impact: [Severity level]
Rollback Type: [Full/Database/Configuration/Partial]
ETA: [Estimated completion time]

Status Updates:
- [ ] Rollback initiated
- [ ] Services stopped
- [ ] Backup restoration in progress
- [ ] Services restarting
- [ ] Verification in progress

Next Update: [Time]
```

#### User-Facing Status Update

```
⚠️ SERVICE INTERRUPTION - ROLLBACK IN PROGRESS

We're currently experiencing issues with Cortex Memory MCP and are performing an emergency rollback to restore service.

Status: Rollback in progress
Impact: Service temporarily unavailable
Expected Resolution: [Time]

We apologize for the inconvenience and appreciate your patience.

Real-time updates: [Status Page URL]
```

#### Management Update

```
EMERGENCY ROLLBACK - SITUATION REPORT

Executive Summary:
- Service: Cortex Memory MCP
- Incident Time: [Timestamp]
- Impact Level: [Critical/High/Medium/Low]
- Users Affected: [Number/Percentage]
- ETA for Resolution: [Time]

Technical Details:
- Root Cause: [Brief description]
- Rollback Procedure: [Type]
- Progress: [Percentage complete]
- Data Impact: [None/Minimal/Significant]

Business Impact:
- Revenue Impact: [Yes/No/Estimated]
- Customer Impact: [Description]
- SLA Impact: [Yes/No]

Next Steps:
- [ ] Complete rollback
- [ ] Verify service restoration
- [ ] Post-incident review
- [ ] Prevention measures

Contact: [On-call contact]
```

### Escalation Procedures

#### Level 1 Escalation (5 minutes)

- **Trigger:** Rollback not progressing as expected
- **Action:** Notify senior engineer
- **Contact:** [Senior Engineer Contact]

#### Level 2 Escalation (10 minutes)

- **Trigger:** Rollback failed or exceeding RTO
- **Action:** Notify engineering manager
- **Contact:** [Engineering Manager Contact]

#### Level 3 Escalation (15 minutes)

- **Trigger:** Critical service failure, data loss
- **Action:** Notify director/VPOE
- **Contact:** [Director Contact]

---

## Troubleshooting

### Common Rollback Issues

#### Issue 1: Service Won't Stop

**Symptoms:** `systemctl stop` hangs, service still running
**Causes:** Hanging connections, graceful shutdown timeout
**Solutions:**

```bash
# Force stop service
sudo systemctl kill cortex-mcp
sudo pkill -f "node.*cortex"

# Check for hanging processes
ps aux | grep cortex
netstat -tulpn | grep :3000

# Clean up resources
sudo systemctl reset-failed cortex-mcp
```

#### Issue 2: Database Won't Start

**Symptoms:** Qdrant container fails to start, connection refused
**Causes:** Corrupted data, port conflicts, permission issues
**Solutions:**

```bash
# Check container status
docker ps -a | grep qdrant
docker logs cortex-qdrant

# Check port availability
netstat -tulpn | grep :6333

# Reset database volume
docker-compose down qdrant
docker volume rm cortex-mcp_qdrant_data
docker-compose up -d qdrant

# Check permissions
ls -la /var/lib/docker/volumes/
```

#### Issue 3: Configuration Validation Fails

**Symptoms:** Service starts but health checks fail
**Causes:** Invalid environment variables, missing required config
**Solutions:**

```bash
# Validate configuration
npm run prod:validate
node -e "console.log(JSON.stringify(require('./src/config/production-config.json'), null, 2))"

# Check environment variables
env | grep -E "(QDRANT|OPENAI|NODE_ENV)" | sort

# Reset to known good config
cp /backups/config/.env.production .env
cp /backups/config/production-config.json src/config/
```

#### Issue 4: Performance Issues After Rollback

**Symptoms:** Slow response times, high CPU/memory usage
**Causes:** Incomplete rollback, cache issues, resource contention
**Solutions:**

```bash
# Check system resources
top -p $(pgrep -f "node.*cortex")
free -h
df -h

# Clear caches
npm run cache:clear
curl -X POST http://localhost:3000/admin/cache/clear

# Restart with fresh resources
sudo systemctl restart cortex-mcp
```

### Debugging Commands

#### Service Status

```bash
# Detailed service status
systemctl status cortex-mcp --no-pager -l

# Recent service logs
journalctl -u cortex-mcp --since "10 minutes ago" -f

# Application logs
tail -100 /app/logs/cortex-mcp.log | grep -E "(ERROR|WARN)"
```

#### Database Diagnostics

```bash
# Qdrant container status
docker ps | grep qdrant
docker stats cortex-qdrant

# Qdrant logs
docker logs cortex-qdrant --tail 100

# Collection information
curl -s http://localhost:6333/collections/cortex-memory | jq .

# Vector count and size
curl -s http://localhost:6333/collections/cortex-memory/points/count | jq .
```

#### Network Diagnostics

```bash
# Port availability
netstat -tulpn | grep -E ":(3000|6333)"

# Connection testing
telnet localhost 3000
telnet localhost 6333

# Service connectivity
curl -v http://localhost:3000/health
curl -v http://localhost:6333/health
```

### Emergency Commands

#### Force System Reset

```bash
# Complete system reset (use with caution)
sudo systemctl stop cortex-mcp
docker-compose -f docker/docker-compose.yml down
docker system prune -f
docker-compose -f docker/docker-compose.yml up -d
sudo systemctl start cortex-mcp
```

#### Emergency Data Recovery

```bash
# Restore from latest backup
LATEST_BACKUP=$(ls -t /backups/qdrant/qdrant-backup-*.tar.gz | head -1)
docker-compose down qdrant
docker volume rm cortex-mcp_qdrant_data
tar -xzf $LATEST_BACKUP -C /var/lib/docker/volumes/
docker-compose up -d qdrant
```

---

## Post-Rollback Activities

### Immediate Post-Rollback Tasks (First Hour)

1. **Verification Completion**
   - [ ] All health checks passing
   - [ ] Full functionality restored
   - [ ] Performance metrics normal
   - [ ] No error logs generated

2. **Documentation Update**
   - [ ] Incident logged in tracking system
   - [ ] Rollback procedure documented
   - [ ] Root cause analysis initiated
   - [ ] Timeline updated

3. **Stakeholder Communication**
   - [ ] "All clear" notification sent
   - [ ] Post-incident review scheduled
   - [ ] User confirmation received
   - [ ] Management debrief completed

### Follow-up Activities (24 Hours)

1. **System Monitoring**
   - [ ] Continuous monitoring active
   - [ ] Alert thresholds adjusted if needed
   - [ ] Performance baseline updated
   - [ ] Automated monitoring enhanced

2. **Process Improvement**
   - [ ] Rollback procedures reviewed
   - [ ] Root cause analysis completed
   - [ ] Prevention measures identified
   - [ ] Team training conducted

3. **System Hardening**
   - [ ] Configuration validated
   - [ ] Security patches applied
   - [ ] Backup procedures verified
   - [ ] Monitoring enhanced

### Post-Incident Review Template

```
POST-INCIDENT REVIEW - ROLLBACK ANALYSIS

Incident Details:
- Date/Time: [Timestamp]
- Service: Cortex Memory MCP
- Rollback Type: [Type]
- Duration: [Total time]
- Impact: [Description]

Timeline:
[ ] Issue detected (Time)
[ ] Rollback initiated (Time)
[ ] Services stopped (Time)
[ ] Backup restored (Time)
[ ] Services restarted (Time)
[ ] Verification completed (Time)
[ ] Service restored (Time)

Root Cause Analysis:
- Primary Cause: [Description]
- Contributing Factors: [List]
- Detection Method: [How identified]
- Prevention Opportunities: [List]

Rollback Performance:
- RTO Met: [Yes/No] (Actual: [Time])
- RPO Met: [Yes/No] (Data loss: [Amount])
- Rollback Success: [Yes/No]
- Issues Encountered: [List]

Lessons Learned:
- What Went Well: [List]
- What Could Be Improved: [List]
- Action Items: [List with owners]
- Follow-up Required: [Yes/No]

Prevention Measures:
- [ ] Enhanced monitoring
- [ ] Improved testing
- [ ] Better rollback procedures
- [ ] Additional safeguards

Review Participants:
- [ ] Name/Role
- [ ] Name/Role
- [ ] Name/Role

Next Review Date: [Date]
```

---

## Appendix

### Quick Reference Commands

#### Health Checks

```bash
# Application health
curl -s http://localhost:3000/health | jq .

# Database health
curl -s http://localhost:6333/health

# Service status
systemctl status cortex-mcp
docker ps | grep qdrant
```

#### Rollback Commands

```bash
# Full rollback
git checkout v2.0.0
npm run clean:build
npm run build
sudo systemctl restart cortex-mcp

# Database rollback
docker-compose down qdrant
tar -xzf /backups/qdrant/latest-backup.tar.gz
docker-compose up -d qdrant

# Configuration rollback
cp /backups/config/.env.production .env
sudo systemctl restart cortex-mcp
```

#### Verification Commands

```bash
# Smoke test
./scripts/rollback-smoke-test.sh

# Full verification
npm run test:comprehensive
npm run verify:readiness

# Performance test
npm run test:performance:quick
```

### Contact Information

| Role                    | Contact            | Hours                    |
| ----------------------- | ------------------ | ------------------------ |
| **Primary On-Call**     | [Phone/Email]      | 24/7                     |
| **Secondary On-Call**   | [Phone/Email]      | 24/7                     |
| **Engineering Manager** | [Phone/Email]      | Business Hours           |
| **Product Manager**     | [Phone/Email]      | Business Hours           |
| **DevOps Team**         | [Slack Channel]    | Business Hours           |
| **Security Team**       | [Security Hotline] | 24/7 for security issues |

### Document History

| Version | Date       | Changes                                | Author                 |
| ------- | ---------- | -------------------------------------- | ---------------------- |
| 2.0.1   | 2025-11-05 | Initial comprehensive rollback runbook | Cortex Operations Team |
|         |            |                                        |                        |
|         |            |                                        |                        |

---

**This runbook should be reviewed quarterly and updated after any significant changes to the system architecture or deployment procedures.**
