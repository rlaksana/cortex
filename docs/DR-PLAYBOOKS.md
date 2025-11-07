# Disaster Recovery Playbooks

## Overview

This document provides step-by-step playbooks for responding to various disaster scenarios. Each playbook includes detailed procedures, checklists, and decision points to guide the response team through critical incidents.

## Table of Contents

1. [Service Outage Playbook](#service-outage-playbook)
2. [Database Failure Playbook](#database-failure-playbook)
3. [Network Partition Playbook](#network-partition-playbook)
4. [Security Incident Playbook](#security-incident-playbook)
5. [Data Center Outage Playbook](#data-center-outage-playbook)
6. [Performance Degradation Playbook](#performance-degradation-playbook)

---

## Service Outage Playbook

### Scenario

Cortex MCP services become unavailable or are experiencing severe degradation.

### Severity Levels

- **Level 1**: Single service outage (MCP or Qdrant)
- **Level 2**: Multiple services affected
- **Level 3**: Complete system outage

### Response Timeline

| Time | Action                           | Owner               |
| ---- | -------------------------------- | ------------------- |
| T+0  | Detection and initial assessment | Monitoring System   |
| T+5  | Incident activation              | On-call Engineer    |
| T+15 | Service recovery attempt         | Technical Lead      |
| T+30 | Escalation if needed             | Incident Commander  |
| T+60 | Stakeholder communication        | Communications Lead |

### Step-by-Step Procedures

#### Phase 1: Immediate Response (T+0 to T+5 minutes)

**1.1 Detection and Assessment**

- [ ] Verify alert accuracy
- [ ] Check service status dashboards
- [ ] Confirm user impact
- [ ] Document initial findings

**Commands:**

```bash
# Check service status
systemctl status cortex-mcp
systemctl status qdrant

# Check API endpoints
curl -f http://localhost:3000/health
curl -f http://localhost:6333/health

# Check logs
tail -50 /app/logs/cortex-mcp.log
tail -50 /var/log/qdrant/qdrant.log
```

**1.2 Incident Activation**

- [ ] Activate incident response team
- [ ] Create incident channel
- [ ] Document incident ID
- [ ] Set up war room

**Slack Command:**

```
/incident activate service=cortex-mcp severity=high description="Service health check failing"
```

#### Phase 2: Investigation (T+5 to T+15 minutes)

**2.1 System Diagnostics**

- [ ] Check system resources
- [ ] Review recent changes
- [ ] Analyze error patterns
- [ ] Identify root cause

**Commands:**

```bash
# System resources
free -h
df -h
top -p $(pgrep -f "node.*index.js")

# Recent changes
git log --oneline -10
systemctl list-units --failed

# Error patterns
grep -i error /app/logs/cortex-mcp.log | tail -20
journalctl -u cortex-mcp --no-pager -n 50
```

**2.2 Impact Assessment**

- [ ] Determine affected users
- [ ] Assess business impact
- [ ] Identify dependent services
- [ ] Estimate recovery time

#### Phase 3: Recovery (T+15 to T+30 minutes)

**3.1 Service Recovery**

- [ ] Attempt service restart
- [ ] Verify configuration
- [ ] Check dependencies
- [ ] Validate functionality

**Service Restart Commands:**

```bash
# MCP Server restart
systemctl restart cortex-mcp
sleep 10
curl -f http://localhost:3000/health

# Qdrant restart
systemctl restart qdrant
sleep 30
curl -f http://localhost:6333/health
```

**3.2 Recovery Validation**

- [ ] Test API functionality
- [ ] Verify data integrity
- [ ] Check performance metrics
- [ ] Confirm user access

**Validation Commands:**

```bash
# API functionality test
curl -f -X POST http://localhost:3000/api/memory/find \
  -H "Content-Type: application/json" \
  -d '{"query":"test","limit":1}'

# Data integrity check
curl -s http://localhost:6333/collections/cortex-memory | jq '.result.points_count'
```

#### Phase 4: Resolution (T+30+ minutes)

**4.1 Full System Validation**

- [ ] Complete health check
- [ ] Performance validation
- [ ] User access confirmation
- [ ] Documentation update

**4.2 Communication**

- [ ] Update status page
- [ ] Notify stakeholders
- [ ] Send resolution notice
- [ ] Document lessons learned

### Decision Points

| Situation                                 | Decision                           | Rationale                            |
| ----------------------------------------- | ---------------------------------- | ------------------------------------ |
| Service fails to restart after 3 attempts | Escalate to Level 2                | Possible deeper infrastructure issue |
| Multiple services affected                | Activate major incident procedure  | Coordination required across teams   |
| Data corruption suspected                 | Do not restart - investigate first | Risk of further damage               |
| Recovery time exceeds 30 minutes          | Management notification            | Business impact significant          |

### Rollback Procedures

If recovery attempts fail:

1. **Stop all services** to prevent further damage
2. **Preserve forensic evidence** (logs, metrics, configurations)
3. **Activate disaster recovery plan**
4. **Consider data center failover** if applicable

### Success Criteria

- [ ] All services responding to health checks
- [ ] API functionality fully operational
- [ ] Performance metrics within normal range
- [ ] No data loss or corruption
- [ ] Users can access all features

---

## Database Failure Playbook

### Scenario

Qdrant database becomes unavailable, corrupted, or experiences performance issues.

### Response Procedures

#### Phase 1: Detection (T+0 to T+5 minutes)

**1.1 Identify Database Issues**

- [ ] Database health check failures
- [ ] Search query timeouts
- [ ] Connection errors
- [ ] Performance degradation

**Commands:**

```bash
# Database health
curl -f http://localhost:6333/health

# Collection status
curl -f http://localhost:6333/collections/cortex-memory

# Performance check
curl -X POST http://localhost:6333/collections/cortex-memory/search \
  -H "Content-Type: application/json" \
  -d '{"vector":[0.1,0.2],"limit":1}' -w "Time: %{time_total}s\n"
```

#### Phase 2: Assessment (T+5 to T+15 minutes)

**2.1 Determine Failure Type**

- [ ] Service unavailable vs. performance issue
- [ ] Data corruption assessment
- [ ] Storage space check
- [ ] Memory usage analysis

**Commands:**

```bash
# Check storage
df -h /qdrant/storage
ls -la /qdrant/storage/

# Check memory
cat /proc/meminfo | grep -E "(MemTotal|MemAvailable)"
ps aux | grep qdrant

# Check logs
tail -50 /var/log/qdrant/qdrant.log | grep -i error
```

#### Phase 3: Recovery (T+15 to T+45 minutes)

**3.1 Database Recovery Steps**

**Option A: Service Restart**

```bash
# Attempt graceful restart
systemctl restart qdrant
sleep 30
curl -f http://localhost:6333/health
```

**Option B: Collection Recovery**

```bash
# Recreate collection if corrupted
curl -X PUT http://localhost:6333/collections/cortex-memory \
  -H "Content-Type: application/json" \
  -d '{
    "vectors": {"size": 1536, "distance": "Cosine"},
    "optimizers_config": {
      "default_segment_number": 2,
      "max_segment_size": 200000
    }
  }'
```

**Option C: Backup Restore**

```bash
# Find latest backup
latest_backup=$(find /backups/qdrant -name "*.snapshot.gz" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)

# Restore from backup
gunzip -c "$latest_backup" > /tmp/restore.snapshot
curl -X POST "http://localhost:6333/collections/cortex-memory/snapshots/restore" \
  -H "Content-Type: application/json" \
  -d '{"snapshot_name": "restore.snapshot"}'
```

#### Phase 4: Validation (T+45 to T+60 minutes)

**4.1 Database Validation**

- [ ] Health check passing
- [ ] Collection accessible
- [ ] Vector count verification
- [ ] Search functionality test
- [ ] Performance validation

### Escalation Criteria

- **Immediate Escalation**: Data corruption confirmed
- **15-minute Escalation**: Service restart fails
- **30-minute Escalation**: Backup restore needed

---

## Network Partition Playbook

### Scenario

Network connectivity issues between components or with external services.

### Detection Indicators

- Connection timeouts
- Intermittent service availability
- High latency
- Partial service failures

### Response Procedures

#### Phase 1: Isolation (T+0 to T+10 minutes)

**1.1 Identify Scope**

- [ ] Internal vs. external connectivity
- [ ] Affected components identification
- [ ] Network path analysis
- [ ] Impact assessment

**Commands:**

```bash
# Check local connectivity
ping -c 3 127.0.0.1
netstat -tlnp | grep -E ":(3000|6333)"

# Check external connectivity
ping -c 3 8.8.8.8
nslookup google.com

# Check service-to-service connectivity
curl -s http://localhost:3000/health
curl -s http://localhost:6333/health
```

#### Phase 2: Recovery (T+10 to T+30 minutes)

**2.1 Network Recovery**

- [ ] Restart network services
- [ ] Check firewall rules
- [ ] Verify DNS resolution
- [ ] Test load balancer health

**Commands:**

```bash
# Network service restart
systemctl restart networking  # or appropriate service
systemctl restart docker     # if using Docker

# Check firewall
iptables -L -n
ufw status

# DNS check
systemctl restart systemd-resolved
nslookup cortex.ai
```

#### Phase 3: Validation (T+30 to T+45 minutes)

**3.1 Connectivity Validation**

- [ ] End-to-end connectivity test
- [ ] Service integration verification
- [ ] Performance measurement
- [ ] User access confirmation

---

## Security Incident Playbook

### Scenario

Security breach, unauthorized access, or suspicious activity detected.

### Immediate Actions (T+0 to T+5 minutes)

**1.1 Incident Activation**

- [ ] Activate security incident response team
- [ ] Isolate affected systems
- [ ] Preserve forensic evidence
- [ ] Initiate incident documentation

**Commands:**

```bash
# Preserve evidence
cp -r /app/logs /tmp/evidence-$(date +%s)
cp -r /var/log /tmp/evidence-logs-$(date +%s)

# System isolation
iptables -A INPUT -j DROP  # Block incoming traffic
systemctl stop cortex-mcp   # Stop affected services
```

### Investigation Phase (T+5 to T+30 minutes)

**2.1 Security Assessment**

- [ ] Access log analysis
- [ ] Intrusion detection review
- [ ] Malware scan
- [ ] Data compromise assessment

**Commands:**

```bash
# Access log analysis
grep -i "failed\|error\|unauthorized" /app/logs/cortex-mcp.log | tail -100

# Check for unusual processes
ps aux | grep -vE "^USER|^root|^daemon"

# File integrity check
find /app -type f -exec md5sum {} \; > /tmp/filesums-$(date +%s)
```

### Recovery Phase (T+30 to T+120 minutes)

**3.1 System Recovery**

- [ ] Remove malicious software
- [ ] Patch vulnerabilities
- [ ] Rebuild from clean backups
- [ ] Strengthen security measures

**3.2 Security Validation**

- [ ] Penetration testing
- [ ] Security scan
- [ ] Access control verification
- [ ] Monitoring enhancement

### Communication Requirements

- **Immediate**: Security team notification
- **T+15**: Management notification
- **T+30**: Stakeholder communication (if customer impact)
- **T+60**: Regulatory notification (if required)

---

## Data Center Outage Playbook

### Scenario

Complete data center failure or extended unavailability.

### Activation Criteria

- Power failure
- Network infrastructure failure
- Environmental disaster
- Extended provider outage

### Response Phases

#### Phase 1: Immediate Response (T+0 to T+15 minutes)

**1.1 Disaster Declaration**

- [ ] Activate disaster recovery team
- [ ] Declare disaster status
- [ ] Initiate failover procedures
- [ ] Notify all stakeholders

**1.2 Site Activation**

- [ ] Activate secondary site
- [ ] Start failover services
- [ ] Update DNS records
- [ ] Initialize communication

#### Phase 2: Failover Execution (T+15 to T+90 minutes)

**2.1 Service Failover**

- [ ] Database failover
- [ ] Application startup
- [ ] Configuration validation
- [ ] Integration testing

**2.2 Data Recovery**

- [ ] Restore from offsite backups
- [ ] Validate data integrity
- [ ] Synchronize recent changes
- [ ] Rebuild indexes

#### Phase 3: Validation (T+90 to T+120 minutes)

**3.1 System Validation**

- [ ] End-to-end testing
- [ ] Performance validation
- [ ] Security verification
- [ ] User access testing

### Success Criteria

- [ ] All critical services operational
- [ ] Data integrity verified
- [ ] Performance within acceptable range
- [ ] Security posture maintained
- [ ] Users can access system

---

## Performance Degradation Playbook

### Scenario

System performance issues, slow response times, or resource exhaustion.

### Detection Thresholds

- API response time > 2 seconds
- Memory usage > 85%
- CPU usage > 90%
- Disk usage > 80%
- Error rate > 5%

### Response Procedures

#### Phase 1: Detection (T+0 to T+5 minutes)

**1.1 Performance Assessment**

- [ ] Identify affected metrics
- [ ] Determine scope of impact
- [ ] Check resource utilization
- [ ] Analyze performance trends

**Commands:**

```bash
# Performance metrics
curl -o /dev/null -s -w '%{time_total}' http://localhost:3000/health
top -p $(pgrep -f "node.*index.js")
iostat -x 1 5

# Resource usage
free -h
df -h
uptime
```

#### Phase 2: Investigation (T+5 to T+20 minutes)

**2.1 Root Cause Analysis**

- [ ] Application profiling
- [ ] Database query analysis
- [ ] Network performance check
- [ ] Resource bottleneck identification

**Commands:**

```bash
# Application profiling
node --inspect dist/index.js
# Connect Chrome DevTools for analysis

# Database performance
curl -s http://localhost:6333/metrics | grep qdrant
```

#### Phase 3: Remediation (T+20 to T+45 minutes)

**3.1 Performance Optimization**

- [ ] Resource allocation adjustment
- [ ] Query optimization
- [ ] Caching strategy enhancement
- [ ] Load balancing adjustment

**3.2 Scaling Actions**

- [ ] Horizontal scaling if needed
- [ ] Vertical resource allocation
- [ ] Service optimization
- [ ] Configuration tuning

#### Phase 4: Validation (T+45 to T+60 minutes)

**4.1 Performance Validation**

- [ ] Response time measurement
- [ ] Resource utilization check
- [ ] Load testing validation
- [ ] User experience verification

### Escalation Criteria

- **15-minute Escalation**: Performance metrics continue to degrade
- **30-minute Escalation**: Service impact increases
- **45-minute Escalation**: User experience significantly affected

---

## Post-Incident Procedures

### Incident Review Checklist

**Technical Review:**

- [ ] Root cause identification
- [ ] Timeline reconstruction
- [ ] Impact assessment
- [ ] Resolution effectiveness

**Process Review:**

- [ ] Response timeline evaluation
- [ ] Communication effectiveness
- [ ] Escalation appropriateness
- [ ] Tool utilization assessment

**Lessons Learned:**

- [ ] What went well
- [ ] What could be improved
- [ ] Preventive measures needed
- [ ] Documentation updates required

### Documentation Requirements

1. **Incident Report**: Detailed timeline, actions, and outcomes
2. **Root Cause Analysis**: Technical investigation results
3. **Corrective Actions**: Short and long-term improvements
4. **Knowledge Base Updates**: Playbook revisions and new procedures

### Follow-up Actions

**Immediate (24 hours):**

- [ ] Complete incident documentation
- [ ] Update monitoring and alerting
- [ ] Communicate lessons learned
- [ ] Schedule follow-up meeting

**Short-term (1 week):**

- [ ] Implement preventive measures
- [ ] Update playbooks and procedures
- [ ] Conduct team training
- [ ] Review tooling needs

**Long-term (1 month):**

- [ ] Evaluate DR plan effectiveness
- [ ] Update infrastructure resilience
- [ ] Schedule regular testing
- [ ] Review and update RTO/RPO targets

---

## Contact Information

### Emergency Contacts

| Role                   | Contact                      | Method                     |
| ---------------------- | ---------------------------- | -------------------------- |
| **On-call Engineer**   | oncall@cortex.ai             | Phone: +1-555-CORTEX1      |
| **Incident Commander** | incident-commander@cortex.ai | Slack: @incident-commander |
| **Technical Lead**     | tech-lead@cortex.ai          | Phone: +1-555-TECHLEAD     |
| **Security Team**      | security@cortex.ai           | Pager: security-alerts     |
| **Management**         | exec@cortex.ai               | Phone: +1-555-EXEC         |

### External Contacts

| Service              | Contact                       | Method                 |
| -------------------- | ----------------------------- | ---------------------- |
| **Cloud Provider**   | AWS Support                   | 1-800-AWS-HELP         |
| **DNS Provider**     | Cloudflare Support            | support@cloudflare.com |
| **Security Advisor** | security-consultant@cortex.ai | Phone: +1-555-SECURE   |

### Communication Channels

- **War Room**: https://cortex.zoom.us/j/incident-{INCIDENT_ID}
- **Slack**: #incidents, #cortex-alerts
- **Status Page**: https://status.cortex.ai
- **Email Distribution**: all-staff@cortex.ai

---

## Tool Reference

### Monitoring Tools

- **Grafana**: https://grafana.cortex.ai
- **Prometheus**: https://prometheus.cortex.ai
- **AlertManager**: https://alertmanager.cortex.ai

### Diagnostic Commands

```bash
# System health
./ops/dr-validation.sh --type quick

# Service restart
./ops/dr-recovery.sh --type complete

# Performance analysis
./ops/dr-testing-framework.sh --scenario load_testing
```

### Documentation Links

- **Architecture**: /docs/ARCH-SYSTEM.md
- **API Reference**: /docs/API-REFERENCE.md
- **Configuration**: /docs/CONFIG-DEPLOYMENT.md
- **Monitoring**: /docs/CONFIG-MONITORING.md

---

**Last Updated**: 2025-11-04
**Next Review**: 2026-02-04
**Approved By**: Cortex Operations Team
