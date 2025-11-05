# MCP Cortex Incident Response Runbook

**Version**: v2.0.0
**Last Updated**: 2025-11-05
**Owner**: Platform Operations Team

## 🚨 Executive Summary

This runbook provides comprehensive incident response procedures for the MCP Cortex Memory Server. It covers all critical components including Qdrant database, MCP server services, monitoring systems, and client connectivity.

**Target Response Time**: < 15 minutes for critical incidents
**Target Resolution Time**: < 2 hours for critical incidents
**Escalation Path**: L1 → L2 → L3 → Management → Executive

---

## 📋 Incident Classification

### Severity Levels

| Severity | Definition | Response Time | Resolution Time | SLA Impact |
|----------|------------|---------------|----------------|------------|
| **SEV-0** | Complete system outage, all users affected | 5 minutes | 30 minutes | Critical |
| **SEV-1** | Major functionality degraded, most users affected | 15 minutes | 2 hours | High |
| **SEV-2** | Partial functionality loss, some users affected | 30 minutes | 4 hours | Medium |
| **SEV-3** | Minor issues, limited impact | 2 hours | 1 business day | Low |
| **SEV-4** | Documentation or minor UI issues | 24 hours | 1 week | Minimal |

### Service Impact Matrix

| Component | SEV-0 Impact | SEV-1 Impact | SEV-2 Impact | SEV-3 Impact |
|-----------|--------------|--------------|--------------|--------------|
| **Qdrant Database** | 100% data loss | Search unavailable | Slow queries | Occasional timeouts |
| **MCP Server** | No API responses | API failures 50%+ | API failures 10-50% | API failures <10% |
| **Authentication** | Complete auth failure | Intermittent auth | Slow auth | Minor auth delays |
| **Monitoring** | No metrics | Incomplete metrics | Delayed metrics | Minor metric gaps |
| **Backups** | No backups | Failed backups | Late backups | Backup warnings |

---

## 🚀 Immediate Response Procedures

### Step 1: Incident Acknowledgment (T+0 to T+5min)

**Actions Required:**
1. **Acknowledge** incident in primary channels (Slack, PagerDuty)
2. **Create** incident channel: `#incidents-cortex-YYYY-MM-DD-HHMM`
3. **Assign** incident commander and technical lead
4. **Enable** emergency response procedures
5. **Initial assessment**: What's broken? Who's impacted?

**Commands:**
```bash
# Enable emergency logging
export LOG_LEVEL=debug
export INCIDENT_MODE=true

# Start incident logging
npm run ops:emergency --mode=incident --severity=SEV-0

# Create war room
/slack create-channel #incidents-cortex-$(date +%Y-%m-%d-%H%M)
```

**Response Template:**
```
🚨 **INCIDENT DECLARED** 🚨
- Service: MCP Cortex Memory Server
- Severity: SEV-X
- Impact: [Brief description]
- Timeline: Started at [timestamp]
- Commander: [@name]
- Next Update: [timestamp + 15min]
- War Room: #incidents-cortex-[timestamp]
```

### Step 2: Initial Triage (T+5 to T+15min)

**Triage Checklist:**

#### 2.1 System Health Assessment
```bash
# Core system checks
npm run ops:health
npm run prod:health
curl -s http://localhost:3000/health | jq .
curl -s http://localhost:6333/health | jq .

# Service status
systemctl status cortex-mcp qdrant --no-pager
docker ps | grep -E "(cortex|qdrant)"

# Resource utilization
top -b -n1 | head -20
df -h
free -h
```

#### 2.2 Database Connectivity
```bash
# Qdrant health checks
curl -s http://localhost:6333/collections/cortex-memory | jq .
curl -s http://localhost:6333/collections | jq .

# Test database operations
npm run test:connection
npm run db:health
```

#### 2.3 Network & External Dependencies
```bash
# Network connectivity
ping -c 3 qdrant-server
nslookup api.openai.com
curl -I https://api.openai.com/v1/models

# Check external services
npm run security:check
npm run ops:status
```

#### 2.4 Recent Changes Analysis
```bash
# Recent deployments
git log --oneline --since="24 hours ago"
docker ps -a --format "table {{.Image}}\t{{.Status}}\t{{.CreatedAt}}"

# Recent configuration changes
git diff HEAD~1..HEAD --name-only
find /app/config -type f -mtime -1 -exec ls -la {} \;
```

**Triage Decision Tree:**

```
Is Qdrant healthy? → No → Database Recovery Procedures
Is API responding? → No → Service Recovery Procedures
Are resources adequate? → No → Resource Scaling Procedures
Are external dependencies available? → No → External Service Workarounds
```

---

## 🛠️ Component-Specific Recovery Procedures

### Qdrant Database Recovery

#### Scenario 1: Qdrant Service Down
```bash
# Restart Qdrant service
sudo systemctl restart qdrant
docker restart qdrant-container

# Verify startup
curl -s http://localhost:6333/health
docker logs qdrant-container --tail 50

# Check data integrity
curl -s http://localhost:6333/collections/cortex-memory | jq '.status'
```

#### Scenario 2: Collection Corruption
```bash
# Export current data (if possible)
curl -X POST http://localhost:6333/collections/cortex-memory/points/export \
  -H "Content-Type: application/json" \
  -d '{"limit": 1000000}' > /tmp/backup-$(date +%Y%m%d-%H%M%S).json

# Recreate collection
curl -X DELETE http://localhost:6333/collections/cortex-memory
curl -X PUT http://localhost:6333/collections/cortex-memory \
  -H "Content-Type: application/json" \
  -d '{"vectors": {"size": 1536, "distance": "Cosine"}}'

# Restore from latest backup
npm run ops:restore --backup=latest
```

#### Scenario 3: Performance Degradation
```bash
# Check Qdrant metrics
curl -s http://localhost:6333/telemetry | jq .

# Optimize collection settings
curl -X PATCH http://localhost:6333/collections/cortex-memory \
  -H "Content-Type: application/json" \
  -d '{"optimizers_config": {"default_segment_number": 2}}'

# Restart with optimized configuration
sudo systemctl restart qdrant
```

### MCP Server Recovery

#### Scenario 1: Service Crash
```bash
# Check service status
systemctl status cortex-mcp --no-pager -l
journalctl -u cortex-mcp --since "1 hour ago" --no-pager

# Restart service
sudo systemctl restart cortex-mcp

# Monitor startup
sudo journalctl -u cortex-mcp -f --no-pager
```

#### Scenario 2: Memory Issues
```bash
# Check memory usage
ps aux | grep -E "(node|cortex)" | sort -rk4 | head -10
free -h

# Restart with increased memory
sudo systemctl set-environment NODE_OPTIONS="--max-old-space-size=8192"
sudo systemctl restart cortex-mcp

# Monitor memory usage
npm run ops:metrics | grep -E "(memory|heap)"
```

#### Scenario 3: Configuration Issues
```bash
# Validate configuration
npm run prod:validate
npm run mcp:validate

# Check environment variables
env | grep -E "(QDRANT|OPENAI|NODE)" | sort

# Reset to known-good configuration
cp /app/config/production.env.backup /app/.env
sudo systemctl restart cortex-mcp
```

### Monitoring & Alerting Recovery

#### Scenario 1: Monitoring Stack Down
```bash
# Restart monitoring services
docker-compose -f docker/monitoring-stack.yml restart

# Verify monitoring stack
npm run monitor:status
npm run monitor:verify

# Check data pipelines
curl -s http://localhost:3000/metrics | jq .
```

#### Scenario 2: Alerting System Failure
```bash
# Reconfigure alerting
npm run monitor:alerts

# Test alert delivery
node scripts/test-alert-delivery.js

# Verify alert rules
curl -s http://localhost:9090/api/v1/rules | jq '.data.groups[].rules[]'
```

---

## 📊 Communication Protocols

### Internal Communication

#### Incident Channel Updates
**Frequency**: Every 15 minutes for SEV-0/1, every 30 minutes for SEV-2/3

**Update Format:**
```
📊 **Incident Update** 📊
- Time: [current timestamp]
- Duration: [total duration]
- Impact: [current status, affected users]
- Actions Taken: [specific actions]
- Next Steps: [immediate next actions]
- ETA: [estimated resolution time]
```

#### Stakeholder Notifications
**Immediate**: SEV-0 incidents - notify within 5 minutes
**Standard**: SEV-1 incidents - notify within 15 minutes
**Delayed**: SEV-2/3 incidents - notify within 30 minutes

**Notification Template:**
```
🚨 **Service Incident Notification** 🚨
Service: MCP Cortex Memory Server
Severity: [SEV-X]
Started: [timestamp]
Impact: [description of user impact]
Current Status: [investigation/mitigation/monitoring]
Follow: #incidents-cortex-[timestamp]
```

### External Communication

#### Customer Communication
**SEV-0**: Immediately, then every 30 minutes
**SEV-1**: Within 30 minutes, then every hour
**SEV-2/3**: Within 2 hours, then every 4 hours

**External Status Page Template:**
```
🔧 **Service Status Update** 🔧
Service: MCP Cortex Memory Server
Status: [Operational/Degraded Performance/Partial Outage/Major Outage]
Impact: [description of what customers are experiencing]
Started: [timestamp]
Update: [summary of current situation]
Next Update: [time of next update]
```

---

## 🔍 Post-Incident Procedures

### Step 1: Service Restoration Verification

**Verification Checklist:**
- [ ] All health checks passing
- [ ] API response times < 100ms
- [ ] Database queries completing successfully
- [ ] Monitoring systems operational
- [ ] No active alerts
- [ ] Customer-reported issues resolved

**Verification Commands:**
```bash
# Comprehensive health check
npm run gates:validate

# Performance verification
npm run perf:gate:ci

# End-to-end testing
npm run test:integration

# Monitor for 30 minutes post-recovery
timeout 1800 npm run ops:health | tee recovery-monitor.log
```

### Step 2: Incident Documentation

**Required Documentation:**

1. **Incident Timeline**
   - Detection time
   - Response actions (with timestamps)
   - Resolution steps
   - Service restoration time

2. **Root Cause Analysis**
   - Primary cause
   - Contributing factors
   - Technical details

3. **Impact Assessment**
   - Users affected
   - Data impact (if any)
   - Business impact

4. **Lessons Learned**
   - What went well
   - What could be improved
   - Action items

**Documentation Template:**
```markdown
# Incident Report: [Incident Name]

## Executive Summary
- **Incident ID**: INC-[YYYYMMDD]-[sequence]
- **Severity**: SEV-X
- **Duration**: [start] to [end] ([total duration])
- **Business Impact**: [description]

## Timeline
| Time | Action | Owner |
|------|--------|-------|
| [time] | Incident detected | [system/person] |
| [time] | Initial response | [person] |
| [time] | [specific action] | [person] |
| [time] | Service restored | [person] |

## Root Cause Analysis
**Primary Cause**: [technical explanation]

**Contributing Factors**:
- [factor 1]
- [factor 2]

**Technical Details**:
[Logs, metrics, configuration details]

## Resolution
**Immediate Actions**:
- [action 1]
- [action 2]

**Permanent Fixes**:
- [fix 1]
- [fix 2]

## Impact Assessment
**Affected Services**: [list]
**Affected Users**: [count/percentage]
**Data Impact**: [description]
**Business Impact**: [description]

## Lessons Learned
**What Went Well**:
- [item 1]
- [item 2]

**Areas for Improvement**:
- [item 1]
- [item 2]

**Action Items**:
- [ ] [action item] - Owner: [name] - Due: [date]
- [ ] [action item] - Owner: [name] - Due: [date]
```

### Step 3: Follow-up Actions

**Immediate (24 hours)**:
- Schedule post-mortem meeting
- Create action items in Jira
- Update monitoring thresholds
- Update runbooks based on lessons learned

**Short-term (1 week)**:
- Implement permanent fixes
- Improve monitoring and alerting
- Update documentation
- Conduct blameless post-mortem

**Long-term (1 month)**:
- Review incident trends
- Update disaster recovery procedures
- Implement architectural improvements
- Schedule follow-up training

---

## 🚨 Escalation Procedures

### Escalation Matrix

| Level | Contact | When to Escalate | Escalation Time |
|-------|---------|------------------|-----------------|
| **L1** | On-call Engineer | Standard incidents | 0 minutes |
| **L2** | Senior Engineer | Complex technical issues | 15 minutes |
| **L3** | Staff Engineer | Architecture/system issues | 30 minutes |
| **Manager** | Engineering Manager | Business impact > 1 hour | 1 hour |
| **Director** | Director of Engineering | Multi-service impact | 2 hours |
| **VP** | VP of Engineering | Major customer impact | 4 hours |

### Escalation Triggers

**Immediate Escalation (SEV-0)**:
- Complete system outage
- Data corruption or loss
- Security breach
- Customer revenue impact > $10K/hour

**Standard Escalation (SEV-1)**:
- Major functionality degradation
- >50% of users affected
- Critical customer impact
- Estimated resolution > 4 hours

**Deferred Escalation (SEV-2/3)**:
- Partial functionality loss
- Minor customer impact
- Estimated resolution > 24 hours

### Escalation Commands

```bash
# Trigger escalation
npm run ops:emergency --escalate-to=L2 --reason="database corruption"

# Notify management
/slack notify --channel="#leadership" --message="SEV-0 incident escalation required"

# Create executive status update
npm run ops:status --format=executive --severity=SEV-0
```

---

## 📈 Monitoring and Metrics

### Key Performance Indicators

**Availability Metrics**:
- API Uptime: Target 99.9%
- Database Uptime: Target 99.9%
- Response Time: Target < 100ms (p95)
- Error Rate: Target < 0.1%

**Incident Response Metrics**:
- Mean Time to Detection (MTTD): Target < 5 minutes
- Mean Time to Acknowledgment (MTTA): Target < 15 minutes
- Mean Time to Resolution (MTTR): Target < 2 hours for SEV-0/1
- Mean Time Between Failures (MTBF): Target > 30 days

**Health Check Commands**:
```bash
# Real-time monitoring
npm run ops:metrics
npm run perf:dashboard

# Historical analysis
npm run ops:baseline
npm run ops:status --history=24h

# Alert validation
npm run monitor:alerts --test-all
```

---

## 🔄 Testing and Validation

### Incident Response Drills

**Monthly Drill Schedule**:
- **Week 1**: Tabletop exercise (SEV-1 scenario)
- **Week 2**: Technical simulation (Qdrant outage)
- **Week 3**: Communication drill (customer notification)
- **Week 4**: Escalation procedure review

**Drill Commands**:
```bash
# Start incident response drill
npm run ops:emergency --mode=drill --scenario=database-outage

# Validate response procedures
npm run test:emergency-response

# Generate drill report
npm run ops:report --type=drill --date=$(date +%Y-%m-%d)
```

### Runbook Validation

**Quarterly Validation**:
- All recovery procedures tested
- Contact information verified
- Monitoring thresholds validated
- Documentation accuracy checked

**Validation Commands**:
```bash
# Test all recovery procedures
npm run test:runbook-validation

# Verify contact information
npm run ops:validate-contacts

# Check monitoring configuration
npm run monitor:verify
```

---

## 📞 Emergency Contacts

### Primary Contacts

| Role | Name | Phone | Slack | Email |
|------|------|-------|-------|-------|
| **Incident Commander** | [Name] | +1-XXX-XXX-XXXX | @incident-commander | [email] |
| **Tech Lead - Database** | [Name] | +1-XXX-XXX-XXXX | @db-lead | [email] |
| **Tech Lead - Backend** | [Name] | +1-XXX-XXX-XXXX | @backend-lead | [email] |
| **DevOps Engineer** | [Name] | +1-XXX-XXX-XXXX | @devops-lead | [email] |
| **Product Manager** | [Name] | +1-XXX-XXX-XXXX | @product-manager | [email] |

### Escalation Contacts

| Role | Name | Phone | Slack | Email |
|------|------|-------|-------|-------|
| **Engineering Manager** | [Name] | +1-XXX-XXX-XXXX | @eng-manager | [email] |
| **Director of Engineering** | [Name] | +1-XXX-XXX-XXXX | @director-eng | [email] |
| **VP of Engineering** | [Name] | +1-XXX-XXX-XXXX | @vp-eng | [email] |
| **CTO** | [Name] | +1-XXX-XXX-XXXX | @cto | [email] |

### External Contacts

| Service | Contact | Phone | Email |
|---------|---------|-------|-------|
| **Qdrant Support** | [Contact] | +1-XXX-XXX-XXXX | [email] |
| **Cloud Provider** | [Provider] | [hotline] | [email] |
| **Security Team** | [Contact] | +1-XXX-XXX-XXXX | [email] |

---

## 📚 Appendices

### A. Command Reference

**Emergency Commands**:
```bash
# System emergency stop
npm run ops:emergency --stop-all

# Force restart all services
npm run ops:emergency --restart-all

# Activate disaster recovery
npm run ops:emergency --disaster-recovery

# Enable debug logging
npm run ops:emergency --debug-mode

# Take system snapshot
npm run ops:backup --snapshot=emergency-$(date +%Y%m%d-%H%M%S)
```

**Diagnostic Commands**:
```bash
# Generate system report
npm run system:diagnose

# Collect logs for analysis
npm run ops:logs --export=/tmp/incident-logs-$(date +%Y%m%d-%H%M%S).tar.gz

# Performance analysis
npm run performance:analyze --output=/tmp/perf-analysis-$(date +%Y%m%d).json
```

### B. Monitoring Dashboard References

**Primary Dashboards**:
- Main System Dashboard: [Link]
- Database Performance: [Link]
- API Metrics: [Link]
- Infrastructure Health: [Link]

**Alert Manager**: [Link]
**Grafana**: [Link]
**Kibana**: [Link]

### C. Runbook Maintenance

**Monthly Reviews**:
- Contact list updates
- Procedure validation
- Metrics threshold review
- Documentation updates

**Quarterly Reviews**:
- Full runbook audit
- Scenario updates
- Tool integration updates
- Training material updates

**Change Management**:
- All changes must be approved
- Version control required
- Rollback procedures mandatory
- Documentation updates enforced

---

**Document Owner**: Platform Operations Team
**Last Reviewed**: 2025-11-05
**Next Review**: 2025-12-05
**Version**: v2.0.0

**For updates or corrections, create a pull request or contact the Platform Operations Team.**