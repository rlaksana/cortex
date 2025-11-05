# Cortex Memory MCP - Rollback Quick Reference

**Version:** 2.0.1
**Last Updated:** 2025-11-05

## Emergency Commands (First 60 Seconds)

### Full Emergency Rollback
```bash
# Complete system rollback to last stable version
./scripts/rollback-emergency.sh full v2.0.0

# Database-only rollback
./scripts/rollback-emergency.sh database

# Configuration-only rollback
./scripts/rollback-emergency.sh config

# Create emergency backup only
./scripts/rollback-emergency.sh backup
```

### Quick System Checks
```bash
# Application health
curl -s http://localhost:3000/health | jq .

# Database health
curl -s http://localhost:6333/health

# Service status
systemctl status cortex-mcp
docker ps | grep qdrant
```

### Immediate Verification
```bash
# Run comprehensive smoke test
./scripts/rollback-smoke-test.sh
```

## Rollback Scenarios Matrix

| Scenario | Command | RTO | Impact | Verification |
|----------|---------|-----|--------|--------------|
| **Full System** | `./scripts/rollback-emergency.sh full` | 5 min | Complete outage | Smoke test |
| **Database Only** | `./scripts/rollback-emergency.sh database` | 3 min | Read-only mode | DB health check |
| **Config Only** | `./scripts/rollback-emergency.sh config` | 1 min | Partial features | Config validation |
| **Feature Disable** | Edit `.env` and restart | 30 sec | Specific feature | Feature test |

## Critical Contact Information

- **Primary On-Call:** [Phone/Slack]
- **Secondary On-Call:** [Phone/Slack]
- **Engineering Manager:** [Phone/Email]
- **DevOps Emergency:** [Slack #devops-emergency]

## Decision Tree

### Service Completely Down?
1. **YES:** Run full emergency rollback
   ```bash
   ./scripts/rollback-emergency.sh full
   ```
2. **NO:** Check individual components

### Database Issues?
1. **YES:** Run database rollback
   ```bash
   ./scripts/rollback-emergency.sh database
   ```
2. **NO:** Check configuration

### Configuration Issues?
1. **YES:** Run config rollback
   ```bash
   ./scripts/rollback-emergency.sh config
   ```
2. **NO:** Check specific features

### Specific Feature Issues?
1. **YES:** Disable feature in `.env`
2. **NO:** Investigate further

## Verification Checklist

### After Any Rollback
- [ ] Health endpoint returns healthy
- [ ] All API endpoints responding
- [ ] Database connectivity working
- [ ] Vector search operational
- [ ] Memory store/retrieve working
- [ ] Performance metrics normal
- [ ] No error logs

### Full Rollback Additional Checks
- [ ] Correct version deployed
- [ ] All features functional
- [ ] User data intact
- [ ] Security measures working

## Testing Before Production

### Run Test Suite
```bash
# Comprehensive rollback testing
./scripts/rollback-test-runner.sh

# Test specific scenarios
./scripts/rollback-test-runner.sh --test-config
./scripts/rollback-test-runner.sh --test-database
./scripts/rollback-test-runner.sh --test-scripts
```

### Validate Backups
```bash
# Check backup integrity
./scripts/rollback-emergency.sh backup
ls -la /backups/qdrant/
ls -la /backups/config/
```

## Common Issues & Solutions

### Service Won't Stop
```bash
sudo systemctl kill cortex-mcp
sudo pkill -f "node.*cortex"
```

### Database Won't Start
```bash
docker-compose down qdrant
docker volume rm cortex-mcp_qdrant_data
docker-compose up -d qdrant
```

### Configuration Errors
```bash
# Reset to known good config
cp /backups/config/.env.production .env
cp /backups/config/production-config.json src/config/

# Validate configuration
npm run prod:validate
```

## Performance Targets

| Metric | Target | Critical |
|--------|--------|----------|
| **Response Time** | < 2s | > 5s |
| **Error Rate** | < 1% | > 5% |
| **Availability** | > 99.9% | < 99% |
| **Uptime** | > 99.9% | < 99% |

## Documentation Links

- [Full Runbook](./ROLLBACK-OPERATIONS-RUNBOOK.md)
- [API Reference](./API-REFERENCE.md)
- [Troubleshooting Guide](./TROUBLESHOOT-ERRORS.md)
- [Health Monitoring Guide](./HEALTH-MONITORING-GUIDE.md)

## Quick Script Summary

| Script | Purpose | Usage |
|--------|---------|-------|
| `rollback-emergency.sh` | Emergency rollback procedures | `./scripts/rollback-emergency.sh [command]` |
| `rollback-smoke-test.sh` | Post-rollback verification | `./scripts/rollback-smoke-test.sh` |
| `rollback-test-runner.sh` | Pre-deployment testing | `./scripts/rollback-test-runner.sh` |

---

**Remember:** Always create a backup before making changes, and verify rollback success before declaring the incident resolved.

**Last Review:** 2025-11-05
**Next Review:** 2026-02-05 (Quarterly)