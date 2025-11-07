# Production Deployment Automation Guide

## Overview

The Cortex Memory MCP Server includes comprehensive production deployment automation that handles environment validation, health checks, monitoring setup, artifact management, and deployment verification.

## Features

### 1. Comprehensive Startup Script (`scripts/start-production.js`)

The production startup script provides:
- Environment validation and configuration loading
- Health checks and monitoring integration
- Production-specific logging and error handling
- Deployment artifact packaging and verification
- Automated deployment reporting
- Graceful shutdown handling

### 2. Production Monitoring Service

Integrated monitoring that includes:
- Real-time metrics collection (system, application, database)
- Health check automation
- Alert management with configurable thresholds
- Performance monitoring and baselines
- Security event tracking

### 3. Production Error Handler

Advanced error handling with:
- Automatic recovery strategies for common issues
- Structured error reporting and analysis
- Error pattern detection and alerting
- Recovery attempt tracking and success metrics

### 4. Environment Validator

Comprehensive validation that checks:
- Security configuration and headers
- Performance baselines and thresholds
- Infrastructure readiness and compatibility
- External dependencies and connectivity
- Compliance requirements (GDPR, data protection)

### 5. Deployment Artifact Manager

Complete artifact management with:
- Versioned packaging with integrity verification
- Compression and optional encryption
- Automated deployment and rollback capabilities
- Artifact signing and verification
- Retention and cleanup policies

## Quick Start

### 1. Basic Production Startup

```bash
# Start production server with default settings
npm run start:prod
```

### 2. Production Startup with Custom Port

```bash
# Start on custom port
npm run start:prod -- --port 8080 --host 127.0.0.1
```

### 3. Dry Run Validation

```bash
# Validate environment without starting server
npm run start:prod -- --dry-run --generate-report
```

### 4. Full Deployment Verification

```bash
# Complete deployment with verification and artifact packaging
npm run start:prod -- --verify-deployment --package-artifacts --generate-report
```

## Configuration

### Environment Variables

Key production environment variables:

#### Required Security Configuration
```bash
OPENAI_API_KEY=your-production-openai-api-key
JWT_SECRET=your_64_character_jwt_secret_here
ENCRYPTION_KEY=your_64_character_hex_encryption_key
MCP_API_KEY=your_48_character_mcp_api_key
```

#### Database Configuration
```bash
QDRANT_URL=https://your-production-qdrant-cluster.com
QDRANT_API_KEY=your-production-qdrant-api-key
QDRANT_TIMEOUT=60000
QDRANT_MAX_CONNECTIONS=20
```

#### Security Settings
```bash
CORS_ORIGIN=https://your-domain.com,https://api.your-domain.com
RATE_LIMIT_ENABLED=true
HELMET_ENABLED=true
ENABLE_ENCRYPTION=true
ENABLE_AUDIT_LOGGING=true
```

#### Monitoring Configuration
```bash
LOG_LEVEL=info
ENABLE_METRICS_COLLECTION=true
ENABLE_HEALTH_CHECKS=true
MONITORING_INTERVAL_MS=30000
HEALTH_CHECK_INTERVAL_MS=60000
```

### Monitoring Thresholds

Configure alert thresholds:
```bash
ALERT_ERROR_RATE_THRESHOLD=0.05
ALERT_RESPONSE_TIME_THRESHOLD=5000
ALERT_MEMORY_USAGE_THRESHOLD=0.85
ALERT_CPU_USAGE_THRESHOLD=0.80
ALERT_DISK_USAGE_THRESHOLD=0.90
```

## Advanced Usage

### Custom Startup Options

The production startup script supports numerous options:

```bash
node scripts/start-production.js [options]

Options:
  --port, -p <number>     Port to listen on (default: 3000)
  --host, -h <string>     Host to bind to (default: 0.0.0.0)
  --skip-validation       Skip environment validation
  --skip-health-checks    Skip health checks
  --enable-debug          Enable debug logging
  --config <path>         Custom config file path
  --dry-run               Validate but don't start server
  --generate-report       Generate startup report
  --verify-deployment     Run deployment verification
  --package-artifacts     Package deployment artifacts
  --help, -?              Show help message
```

### Environment Validation

Run comprehensive validation separately:

```javascript
import { ProductionEnvironmentValidator } from './src/monitoring/production-environment-validator.js';

const validator = new ProductionEnvironmentValidator({
  strictMode: true,
  enableDeepChecks: true,
  thresholds: {
    maxResponseTimeMs: 5000,
    maxErrorRate: 0.01,
    minMemoryMB: 2048,
  }
});

const report = await validator.performComprehensiveValidation();
console.log('Validation Score:', report.score);
console.log('Critical Issues:', report.summary.critical);
```

### Artifact Management

Create and manage deployment artifacts:

```javascript
import { DeploymentArtifactManager } from './src/monitoring/deployment-artifact-manager.js';

const artifactManager = new DeploymentArtifactManager({
  signingEnabled: true,
  encryptionEnabled: true,
  compressionEnabled: true,
});

// Create artifact
const artifactId = await artifactManager.createArtifact('2.0.1', 'production');

// Verify artifact
const verification = await artifactManager.verifyArtifact(artifactId);

// Deploy artifact
const deployment = await artifactManager.deployArtifact(artifactId, 'production');
```

### Custom Monitoring

Set up custom monitoring:

```javascript
import { ProductionMonitoringService } from './src/monitoring/production-monitoring-service.js';

const monitoring = new ProductionMonitoringService({
  intervalMs: 30000,
  alertThresholds: {
    errorRate: 0.05,
    responseTime: 5000,
    memoryUsage: 0.85,
  },
  enableAlerting: true,
});

// Start monitoring
await monitoring.start();

// Listen for alerts
monitoring.on('alert', (alert) => {
  console.log('Alert:', alert.message);
});

// Record custom metrics
monitoring.recordRequest(150, false); // 150ms response, no error
```

## Deployment Workflow

### 1. Pre-deployment Checks

```bash
# Run comprehensive validation
npm run prod:validate

# Check production health
npm run prod:health

# Run security audit
npm run security:audit
```

### 2. Build and Package

```bash
# Build production assets
npm run build:prod

# Package deployment artifacts
npm run start:prod -- --dry-run --package-artifacts
```

### 3. Deployment

```bash
# Deploy with full verification
npm run start:prod -- --verify-deployment --generate-report
```

### 4. Post-deployment Verification

```bash
# Check server status
npm run prod:status

# View metrics
npm run prod:metrics

# Check logs
npm run prod:logs
```

## Health Checks

The system provides multiple health check endpoints:

- `/health` - Basic health status
- `/health/live` - Liveness probe (container orchestration)
- `/health/ready` - Readiness probe (container orchestration)
- `/health/detailed` - Comprehensive health report
- `/metrics` - Prometheus-compatible metrics

## Monitoring Dashboards

### Built-in Metrics

The monitoring service tracks:

- **System Metrics**: CPU, memory, disk usage, load average
- **Application Metrics**: Request count, error rate, response times, throughput
- **Database Metrics**: Connection pool, query performance, slow queries
- **Health Check Metrics**: Service availability, dependency health

### Alert Types

- **Critical**: Security issues, system failures, service unavailability
- **Warning**: High resource usage, degraded performance, dependency issues
- **Info**: Configuration changes, deployments, system events

## Error Handling

### Automatic Recovery

The system includes automatic recovery for:

- Network timeouts (with exponential backoff)
- Database connection issues (with reconnection)
- Memory pressure (with garbage collection)
- Rate limiting (with backoff strategies)

### Error Classification

Errors are classified by type and severity:

- **System**: Infrastructure, platform, resource issues
- **Application**: Logic, validation, processing errors
- **Security**: Authentication, authorization, access issues
- **Infrastructure**: Database, network, service dependencies
- **Network**: Connectivity, timeout, protocol errors

## Rollback Procedures

### Automated Rollback

```bash
# The system supports automatic rollback when:
# - Health checks fail consistently
# - Critical errors exceed thresholds
# - Performance degrades significantly
```

### Manual Rollback

```javascript
import { DeploymentArtifactManager } from './src/monitoring/deployment-artifact-manager.js';

const artifactManager = new DeploymentArtifactManager();

// List available artifacts
const artifacts = artifactManager.listArtifacts('production');

// Rollback to previous version
const previousArtifact = artifacts.find(a => a.version === '2.0.0');
if (previousArtifact) {
  await artifactManager.deployArtifact(previousArtifact.id, 'production');
}
```

## Troubleshooting

### Common Issues

1. **Environment Validation Failures**
   - Check required environment variables
   - Verify security configuration
   - Ensure external services are accessible

2. **Health Check Failures**
   - Review system resource usage
   - Check database connectivity
   - Verify network configuration

3. **Performance Issues**
   - Monitor memory and CPU usage
   - Check database query performance
   - Review application metrics

### Debug Mode

Enable debug logging for troubleshooting:

```bash
npm run start:prod -- --enable-debug
```

### Log Analysis

Production logs are structured JSON format:

```bash
# View recent errors
npm run prod:logs

# Filter for specific events
grep "ERROR" /app/logs/cortex-mcp.log

# Analyze performance metrics
grep "Performance:" /app/logs/cortex-mcp.log
```

## Best Practices

### 1. Environment Configuration
- Use strong, unique secrets for production
- Configure specific CORS origins
- Enable all security features
- Set appropriate resource limits

### 2. Monitoring
- Configure alert thresholds appropriately
- Set up multiple notification channels
- Monitor system and application metrics
- Regular review of health check results

### 3. Deployment
- Use dry-run mode for validation
- Generate deployment reports
- Verify artifact integrity
- Test rollback procedures

### 4. Security
- Regular security audits
- Monitor for security events
- Keep dependencies updated
- Follow least privilege principle

### 5. Performance
- Monitor response times and throughput
- Set up performance baselines
- Optimize database queries
- Implement caching strategies

## Support

For issues with production deployment:

1. Check the deployment logs and reports
2. Review health check status
3. Verify environment configuration
4. Consult the troubleshooting guide
5. Contact the operations team with detailed error information

---

*This guide covers the production deployment automation features of Cortex Memory MCP Server v2.0.1.*