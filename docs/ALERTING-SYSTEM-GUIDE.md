# MCP Cortex Alerting System Guide

## Overview

The MCP Cortex Alerting System is a comprehensive, production-ready alerting and incident management solution designed to provide end-to-end monitoring, alerting, and response capabilities for the MCP Cortex platform.

## Features

### 🔔 Alert Management
- **Multi-channel alerting**: Email, Slack, PagerDuty, Microsoft Teams, SMS, Webhooks
- **Advanced alert rules**: Flexible conditions with time-based evaluation
- **Alert lifecycle**: Creation, acknowledgment, escalation, resolution
- **Intelligent routing**: Automatic assignment based on skills and availability
- **Cooldown periods**: Prevent alert spam and notification fatigue

### 👥 On-Call Management
- **Scheduling and rotations**: Daily, weekly, monthly rotations
- **Escalation policies**: Multi-level escalation with configurable delays
- **Handoff workflows**: Smooth transition between on-call engineers
- **Skill-based routing**: Match alerts to appropriate on-call personnel
- **Vacation and override management**: Temporary coverage and scheduling changes

### 📖 Runbook Integration
- **Automated runbooks**: Step-by-step incident response procedures
- **Template system**: Reusable runbook templates for common scenarios
- **Execution tracking**: Monitor runbook progress and results
- **Rollback capabilities**: Automatic and manual rollback procedures
- **Verification steps**: Ensure incident resolution before closing

### 🧪 Testing and Validation
- **Fault injection**: Simulate real-world failure scenarios
- **Comprehensive test suites**: Unit, integration, and end-to-end testing
- **Load testing**: Validate system performance under stress
- **Test automation**: Scheduled and on-demand test execution
- **Validation reporting**: Detailed test results and recommendations

### 📊 Metrics and Dashboards
- **Real-time metrics**: Alert volumes, response times, system health
- **Historical analysis**: Trends, patterns, and performance data
- **Predictive analytics**: Forecast alert volumes and system load
- **Custom dashboards**: Configurable Grafana-style dashboards
- **Performance monitoring**: System resource utilization and bottlenecks

## Architecture

The alerting system consists of several integrated components:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Alert System Integration                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐  │
│  │   Alert         │ │   Notification   │ │   On-Call        │  │
│  │   Management    │ │   Channels      │ │   Management    │  │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘  │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐  │
│  │   Runbook       │ │   Alert          │ │   Metrics &      │  │
│  │   Integration   │ │   Testing        │ │   Dashboards     │  │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                      Health Monitoring                           │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐  │
│  │   Health Check   │ │   Performance    │ │   System         │  │
│  │   Service        │ │   Monitoring     │ │   Metrics        │  │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Basic Setup

```typescript
import { quickStartAlerting } from './src/monitoring/index.js';

// Start the complete alerting system
const alertingSystem = await quickStartAlerting();

// Get system status
const status = alertingSystem.system.getSystemStatus();
console.log('System health:', status.health.status);
```

### Advanced Configuration

```typescript
import { createAlertingSystem } from './src/monitoring/index.js';

// Create a customized alerting system
const alertingSystem = createAlertingSystem({
  enabled: true,
  environment: 'production',
  healthCheckInterval: 30000,
  alertEvaluationInterval: 10000,
  metricsCollectionInterval: 60000,
  testingEnabled: true,
  dashboardEnabled: true,
  integrations: {
    email: {
      enabled: true,
      provider: 'smtp',
      config: {
        host: 'smtp.example.com',
        port: 587,
        secure: true,
        auth: {
          user: 'alerts@example.com',
          pass: 'password',
        },
      },
    },
    slack: {
      enabled: true,
      webhookUrl: 'https://hooks.slack.com/services/...',
      channel: '#alerts',
    },
    pagerduty: {
      enabled: true,
      integrationKey: 'your-integration-key',
    },
  },
});

await alertingSystem.system.start();
```

## Alert Rules

### Creating Alert Rules

```typescript
import { alertManagementService } from './src/monitoring/index.js';

// Database connectivity alert
const databaseDownRule = {
  id: 'database-down',
  name: 'Database Connectivity Loss',
  description: 'Alert when database becomes unreachable',
  enabled: true,
  severity: 'critical',
  condition: {
    metric: 'status',
    operator: 'eq',
    threshold: 'unhealthy',
    duration: 30000, // 30 seconds
    evaluationWindow: 60000,
  },
  actions: [
    {
      type: 'email',
      config: {
        to: ['oncall@example.com'],
        subject: 'CRITICAL: Database Connectivity Loss',
        template: 'database-down',
      },
      enabled: true,
    },
    {
      type: 'slack',
      config: {
        channel: '#alerts-critical',
        message: 'Database connectivity loss detected!',
      },
      enabled: true,
    },
  ],
  cooldownPeriod: 300000, // 5 minutes
  tags: ['database', 'connectivity', 'critical'],
};

await alertManagementService.upsertAlertRule(databaseDownRule);
```

### Alert Rule Conditions

Alert rules support various condition types:

- **Status checks**: Component health status monitoring
- **Metric thresholds**: Numeric value comparisons
- **Error rates**: Percentage-based alerts
- **Time-based conditions**: Duration-based evaluation
- **Complex expressions**: Multiple condition combinations

## Notification Channels

### Email Notifications

```typescript
// Configure email notifications
const emailConfig = {
  provider: 'smtp', // or 'sendgrid', 'ses'
  to: ['alerts@example.com'],
  from: 'noreply@example.com',
  subject: 'Alert: {{alert.title}}',
  template: 'default', // or custom template
  attachments: [],
  headers: {},
};
```

### Slack Notifications

```typescript
// Configure Slack notifications
const slackConfig = {
  webhookUrl: 'https://hooks.slack.com/services/...',
  channel: '#alerts',
  username: 'AlertBot',
  iconEmoji: ':warning:',
  enableAcknowledge: true,
  enableResolve: true,
  runbookUrl: 'https://docs.example.com/runbooks',
  dashboardUrl: 'https://grafana.example.com',
};
```

### PagerDuty Integration

```typescript
// Configure PagerDuty notifications
const pagerDutyConfig = {
  integrationKey: 'your-integration-key',
  escalationPolicy: 'escalation-policy-id',
  assignee: {
    id: 'user-id',
    type: 'user_reference',
  },
};
```

## On-Call Management

### Creating On-Call Users

```typescript
import { onCallManagementService } from './src/monitoring/index.js';

// Register on-call users
const user = {
  id: 'user-1',
  name: 'John Doe',
  email: 'john.doe@example.com',
  phone: '+1234567890',
  slackUserId: 'U123456',
  timezone: 'America/New_York',
  skills: ['database', 'infrastructure', 'networking'],
  maxConcurrentAlerts: 5,
  notificationPreferences: {
    email: true,
    sms: true,
    phone: true,
    slack: true,
    push: false,
    escalationDelay: 15,
  },
  workingHours: {
    days: [1, 2, 3, 4, 5], // Monday-Friday
    start: '09:00',
    end: '17:00',
    timezone: 'America/New_York',
  },
};

await onCallManagementService.registerUser(user);
```

### Setting Up Schedules

```typescript
// Create on-call schedule
const schedule = {
  id: 'primary-schedule',
  name: 'Primary On-Call Schedule',
  timezone: 'America/New_York',
  rotations: [
    {
      id: 'rotation-1',
      name: 'Weekly Rotation',
      users: ['user-1', 'user-2', 'user-3'],
      type: 'weekly',
      startTime: new Date('2025-01-01T09:00:00Z'),
      handoffTime: '09:00',
    },
  ],
  overrides: [],
};

await onCallManagementService.upsertSchedule(schedule);
```

## Runbook Integration

### Creating Runbooks

```typescript
import { runbookIntegrationService } from './src/monitoring/index.js';

// Database recovery runbook
const runbook = {
  id: 'database-recovery',
  name: 'Database Recovery Procedures',
  description: 'Step-by-step procedures for database incident recovery',
  version: '1.0.0',
  category: 'database',
  severity: 'critical',
  tags: ['database', 'recovery', 'incident'],
  author: 'DBA Team',
  estimatedDuration: 15,
  prerequisites: ['Database admin access', 'Network connectivity'],
  riskLevel: 'medium',
  rollbackPlan: {
    enabled: true,
    automatic: false,
    triggers: [],
    steps: [],
  },
  steps: [
    {
      id: 'check-status',
      title: 'Check Database Status',
      description: 'Verify current database status and identify the issue',
      type: 'investigation',
      order: 1,
      estimatedDuration: 2,
      required: true,
      parallel: false,
      commands: [
        {
          id: 'ping-db',
          type: 'shell',
          executor: 'bash',
          script: 'pg_isready -h $DB_HOST -p $DB_PORT',
          timeout: 30,
          expectedExitCode: 0,
        },
      ],
      verificationCriteria: [
        {
          id: 'db-accessible',
          name: 'Database is accessible',
          type: 'exit_code',
          expected: 0,
          operator: 'eq',
          critical: true,
          timeout: 60,
        },
      ],
      timeout: 300,
      retryPolicy: {
        maxAttempts: 3,
        delay: 10,
        backoffType: 'exponential',
        maxDelay: 60,
      },
      outputs: [
        {
          name: 'database_status',
          type: 'string',
          description: 'Current database connection status',
          required: true,
        },
      ],
    },
  ],
  variables: [
    {
      name: 'DB_HOST',
      type: 'string',
      description: 'Database host address',
      required: true,
      defaultValue: 'localhost',
    },
    {
      name: 'DB_PORT',
      type: 'number',
      description: 'Database port',
      required: true,
      defaultValue: 5432,
    },
  ],
  dependencies: [
    {
      name: 'postgresql',
      type: 'service',
      required: true,
      checkCommand: 'systemctl is-active postgresql',
    },
  ],
  metadata: {},
  createdAt: new Date(),
  updatedAt: new Date(),
};

await runbookIntegrationService.upsertRunbook(runbook);
```

### Executing Runbooks

```typescript
// Execute runbook for alert
const runbookOptions = {
  triggeredBy: 'system',
  triggerType: 'alert',
  alertId: 'alert-123',
  environment: 'production',
  variables: {
    DB_HOST: 'prod-db.example.com',
    DB_PORT: 5432,
  },
};

const execution = await runbookIntegrationService.executeRunbook(
  'database-recovery',
  runbookOptions
);

console.log('Runbook execution:', execution.id);
```

## Testing and Validation

### Running System Tests

```typescript
import { alertSystemIntegrationService } from './src/monitoring/index.js';

// Run comprehensive system tests
const testResults = await alertSystemIntegrationService.runSystemTests();

console.log('Test Results:');
console.log(`- Total suites: ${testResults.overall.total}`);
console.log(`- Passed: ${testResults.overall.passed}`);
console.log(`- Failed: ${testResults.overall.failed}`);
console.log(`- Success rate: ${testResults.overall.successRate}%`);
```

### Fault Scenario Testing

```typescript
// Test specific fault scenario
const faultTestResult = await alertSystemIntegrationService.runFaultScenarioTest(
  'database-down'
);

console.log('Fault Test Results:');
console.log(`- Duration: ${faultTestResult.duration}ms`);
console.log(`- Alerts triggered: ${faultTestResult.triggeredAlerts}`);
console.log(`- Success: ${faultTestResult.success}`);
```

## Metrics and Dashboards

### System Metrics

```typescript
import { alertMetricsService } from './src/monitoring/index.js';

// Get current dashboard metrics
const dashboardMetrics = alertMetricsService.getDashboardMetrics({
  from: 'now-1h',
  to: 'now',
});

console.log('Dashboard Metrics:');
console.log(`- Active alerts: ${dashboardMetrics.overview.activeAlerts}`);
console.log(`- Critical alerts: ${dashboardMetrics.overview.criticalAlerts}`);
console.log(`- Health score: ${dashboardMetrics.overview.healthScore}`);
```

### Custom Metrics

```typescript
// Define custom metrics
alertMetricsService.defineCustomMetric({
  name: 'alert_processing_time',
  type: 'histogram',
  description: 'Time taken to process alerts',
  unit: 'milliseconds',
  labels: ['severity', 'rule', 'component'],
});

// Record custom metric values
alertMetricsService.recordCustomMetric(
  'alert_processing_time',
  150,
  {
    severity: 'critical',
    rule: 'database-down',
    component: 'database',
  }
);
```

## Configuration

### Environment Variables

```bash
# General Configuration
ALERT_SYSTEM_ENABLED=true
ALERT_ENVIRONMENT=production
ALERT_HEALTH_CHECK_INTERVAL=30000
ALERT_EVALUATION_INTERVAL=10000
ALERT_METRICS_INTERVAL=60000

# Email Configuration
EMAIL_PROVIDER=smtp
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USER=alerts@example.com
EMAIL_PASS=password

# Slack Configuration
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SLACK_CHANNEL=#alerts

# PagerDuty Configuration
PAGERDUTY_INTEGRATION_KEY=your-integration-key
PAGERDUTY_API_KEY=your-api-key

# Database Configuration
QDRANT_URL=http://localhost:6333
QDRANT_API_KEY=your-api-key

# Auto-start
AUTO_START_HEALTH_MONITORING=true
```

### Configuration File

```typescript
// alerting.config.ts
export const alertingConfig = {
  enabled: true,
  environment: process.env.NODE_ENV || 'development',
  healthCheckInterval: parseInt(process.env.ALERT_HEALTH_CHECK_INTERVAL || '30000'),
  alertEvaluationInterval: parseInt(process.env.ALERT_EVALUATION_INTERVAL || '10000'),
  metricsCollectionInterval: parseInt(process.env.ALERT_METRICS_INTERVAL || '60000'),
  notificationRetryAttempts: 3,
  escalationTimeout: 1800000, // 30 minutes
  runbookTimeout: 1800000, // 30 minutes
  testingEnabled: true,
  dashboardEnabled: true,
  integrations: {
    email: {
      enabled: process.env.EMAIL_PROVIDER !== undefined,
      provider: process.env.EMAIL_PROVIDER || 'smtp',
      config: {
        host: process.env.EMAIL_HOST,
        port: parseInt(process.env.EMAIL_PORT || '587'),
        secure: process.env.EMAIL_PORT === '465',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS,
        },
      },
    },
    slack: {
      enabled: process.env.SLACK_WEBHOOK_URL !== undefined,
      webhookUrl: process.env.SLACK_WEBHOOK_URL,
      channel: process.env.SLACK_CHANNEL || '#alerts',
    },
    pagerduty: {
      enabled: process.env.PAGERDUTY_INTEGRATION_KEY !== undefined,
      integrationKey: process.env.PAGERDUTY_INTEGRATION_KEY,
      apiKey: process.env.PAGERDUTY_API_KEY,
    },
  },
};
```

## API Reference

### Alert Management

```typescript
// Get active alerts
const activeAlerts = alertManagementService.getActiveAlerts();

// Get alert history
const alertHistory = alertManagementService.getAlertHistory(100);

// Acknowledge alert
await alertManagementService.acknowledgeAlert('alert-id', 'user-id');

// Resolve alert
await alertManagementService.resolveAlert('alert-id', 'Issue resolved');
```

### On-Call Management

```typescript
// Get current assignments
const assignments = onCallManagementService.getCurrentAssignments();

// Get on-call metrics
const metrics = onCallManagementService.getOnCallMetrics();

// Assign alert to user
await onCallManagementService.assignAlert('alert-id', {
  userId: 'user-id',
  assignedBy: 'system',
  requiredSkills: ['database'],
});
```

### Runbook Execution

```typescript
// Get runbook recommendations
const recommendations = await runbookIntegrationService.getRunbookRecommendations(alert);

// Execute runbook
const execution = await runbookIntegrationService.executeRunbook('runbook-id', {
  triggeredBy: 'user-id',
  variables: { param1: 'value1' },
});
```

### System Status

```typescript
// Get system status
const status = alertSystemIntegrationService.getSystemStatus();

// Perform health check
const health = await alertSystemIntegrationService.performHealthCheck();

// Get dashboard data
const dashboardData = await alertSystemIntegrationService.getDashboardData();
```

## Troubleshooting

### Common Issues

1. **Alerts not firing**
   - Check alert rule configuration
   - Verify health check is running
   - Review notification channel settings

2. **Notifications not sending**
   - Validate integration credentials
   - Check network connectivity
   - Review error logs

3. **Escalation not working**
   - Verify on-call schedule configuration
   - Check escalation policy settings
   - Review user availability

4. **Runbook execution failing**
   - Check system permissions
   - Validate command syntax
   - Review error messages

### Debug Logging

Enable debug logging to troubleshoot issues:

```typescript
import { logger } from './src/utils/logger.js';

logger.level = 'debug';

// Enable detailed logging for specific components
logger.debug('Alert management configuration', {
  rules: alertManagementService.getAlertRules(),
  activeAlerts: alertManagementService.getActiveAlerts(),
});
```

### Health Check Endpoints

```bash
# Health check
GET /health

# Detailed health status
GET /health/detailed

# Metrics
GET /metrics

# System status
GET /status
```

## Best Practices

### Alert Rule Design

1. **Use meaningful names and descriptions**
2. **Set appropriate severity levels**
3. **Configure cooldown periods**
4. **Add relevant tags**
5. **Test rules thoroughly**

### On-Call Management

1. **Regular schedule reviews**
2. **Maintain up-to-date contact information**
3. **Provide proper training**
4. **Document escalation procedures**
5. **Monitor on-call workload**

### Runbook Maintenance

1. **Regular review and updates**
2. **Test procedures regularly**
3. **Include rollback steps**
4. **Document dependencies**
5. **Train team members**

### Monitoring and Metrics

1. **Monitor system performance**
2. **Track alert trends**
3. **Analyze response times**
4. **Review success rates**
5. **Optimize based on data**

## Contributing

When contributing to the alerting system:

1. **Write comprehensive tests**
2. **Update documentation**
3. **Follow code style guidelines**
4. **Add type definitions**
5. **Test in development environment**

## Support

For support and questions:

- 📧 Email: alerts-support@example.com
- 📚 Documentation: [Link to docs]
- 💬 Slack: #alerting-support
- 🐛 Issues: [Link to issue tracker]

## License

This alerting system is licensed under the MIT License. See LICENSE file for details.