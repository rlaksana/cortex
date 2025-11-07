# Qdrant Graceful Degradation System

## Overview

The Qdrant Graceful Degradation System provides comprehensive resilience for Qdrant vector database outages, ensuring continued operation with automatic failover to in-memory storage and seamless recovery when service is restored.

## Architecture

### Core Components

1. **In-Memory Fallback Storage** (`src/db/adapters/in-memory-fallback-storage.ts`)
   - LRU eviction and TTL support
   - Configurable memory limits and item limits
   - Deduplication and content hashing
   - Performance metrics tracking

2. **Degradation Detector** (`src/monitoring/degradation-detector.ts`)
   - Real-time health monitoring
   - Configurable degradation triggers
   - Auto-failover decision logic
   - Recovery detection and signaling

3. **Degradation Notifier** (`src/monitoring/degradation-notifier.ts`)
   - Multi-channel notifications (log, console, webhook, Slack, email)
   - Rate limiting and message templating
   - User-facing degradation messages
   - Recipient management and preferences

4. **Error Budget Tracker** (`src/monitoring/error-budget-tracker.ts`)
   - SLO compliance monitoring
   - Error budget consumption tracking
   - Burn rate calculations and projections
   - Automated alerting on budget depletion

5. **Graceful Degradation Manager** (`src/monitoring/graceful-degradation-manager.ts`)
   - Orchestrates all degradation components
   - Operation interception and routing
   - Failover/failback coordination
   - Statistics and reporting

## Configuration

### Environment Variables

```bash
# Enable/disable graceful degradation
QDRANT_GRACEFUL_DEGRADATION=true

# Qdrant connection settings
QDRANT_URL=http://localhost:6333
QDRANT_API_KEY=your-api-key
OPENAI_API_KEY=your-openai-key
```

### Degradation Manager Configuration

```typescript
const config = {
  failover: {
    enabled: true,
    triggerLevel: DegradationLevel.CRITICAL,
    minDurationBeforeFailover: 30000,
    maxFailoverAttempts: 3,
    failoverCooldownMs: 300000,
    automaticFailback: true,
    consecutiveHealthChecksRequired: 3,
    healthCheckIntervalMs: 15000,
  },
  fallback: {
    maxItems: 10000,
    maxMemoryUsageMB: 100,
    defaultTTL: 30,
    enablePersistence: false,
    syncOnRecovery: true,
  },
  notifications: {
    enabled: true,
    userFacingMessages: true,
    operatorAlerts: true,
    detailedLogging: true,
  },
  errorBudget: {
    enabled: true,
    availabilityTarget: 99.9,
    latencyTarget: 1000,
    errorRateTarget: 0.1,
  },
};
```

## Usage

### Basic Integration

The graceful degradation system is automatically integrated with the Qdrant adapter when enabled:

```typescript
import { QdrantAdapter } from './src/db/adapters/qdrant-adapter.js';

const adapter = new QdrantAdapter({
  type: 'qdrant',
  url: process.env.QDRANT_URL,
  // ... other config
});

await adapter.initialize();

// Store and search operations work seamlessly
const result = await adapter.store(items);
const searchResults = await adapter.search(query);
```

### Manual Degradation Control

```typescript
import { QdrantGracefulDegradationManager } from './src/monitoring/graceful-degradation-manager.js';

const manager = new QdrantGracefulDegradationManager(adapter);
await manager.start();

// Force manual failover
await manager.forceFailover('Emergency maintenance');

// Force manual failback
await manager.forceFailback();

// Check current state
const state = manager.getCurrentState();
const stats = manager.getStatistics();
```

### Standalone Fallback Storage

```typescript
import { InMemoryFallbackStorage } from './src/db/adapters/in-memory-fallback-storage.js';

const fallback = new InMemoryFallbackStorage({
  maxItems: 5000,
  maxMemoryUsageMB: 50,
  defaultTTL: 60,
});

await fallback.initialize();

// Store items during degradation
const result = await fallback.store(items);

// Search items during degradation
const searchResults = await fallback.search(query);
```

## Degradation Levels

1. **HEALTHY** - Normal operation
2. **WARNING** - Performance degradation detected
3. **DEGRADED** - Service impaired but functional
4. **CRITICAL** - Major issues, limited functionality
5. **UNAVAILABLE** - Service completely unavailable

## Failover Process

### Automatic Failover Triggers

- Response time exceeds critical threshold
- Error rate exceeds critical threshold
- Circuit breaker opens
- Consecutive health check failures
- Manual trigger via API

### Failover Sequence

1. **Detection**: Degradation detector identifies service issues
2. **Evaluation**: System evaluates triggers and thresholds
3. **Decision**: Auto-failover decision made based on configuration
4. **Activation**: In-memory fallback storage activated
5. **Notification**: Users and operators notified of degradation
6. **Operation**: Continue operations using fallback storage

### Recovery Process

1. **Health Monitoring**: Continuous health checks during failover
2. **Recovery Detection**: Service health restoration detected
3. **Validation**: Consecutive successful health checks required
4. **Failback**: Automatic failback to primary storage
5. **Data Sync**: Synchronize fallback data if enabled
6. **Notification**: Recovery notifications sent

## Monitoring and Observability

### Key Metrics

- **Availability**: Service uptime percentage
- **Response Time**: Average and percentile response times
- **Error Rate**: Percentage of failed operations
- **Error Budget**: SLO compliance and budget consumption
- **Failover Events**: Number and duration of failovers
- **Fallback Operations**: Operations handled by fallback storage

### Health Endpoints

```typescript
// Get degradation status
const state = manager.getCurrentState();

// Get failover statistics
const stats = manager.getStatistics();

// Get error budget status
const budgetStatus = errorBudgetTracker.getCurrentStatus();

// Get user-facing messages
const userMessage = notifier.getUserFacingMessage();
```

### Error Budget Tracking

```typescript
// Track operation
errorBudgetTracker.recordOperation({
  timestamp: Date.now(),
  operationType: 'store',
  success: true,
  responseTime: 150,
  degraded: false,
  fallbackUsed: false,
});

// Get error budget report
const report = errorBudgetTracker.generateReport();
console.log('Error budget consumed:', report.errorBudget.consumed);
console.log('Burn rate:', report.errorBudget.burnRate);
```

## Notification System

### Notification Channels

- **Log**: Structured logging with severity levels
- **Console**: Console output for development
- **Webhook**: HTTP webhook notifications
- **Slack**: Slack integration via webhooks
- **Email**: SMTP email notifications
- **Dashboard**: UI dashboard updates
- **API**: API callbacks for custom handling

### Message Templates

The system includes configurable message templates for different degradation levels:

```typescript
// Critical degradation example
{
  level: DegradationLevel.CRITICAL,
  title: 'Critical Service Issues',
  message: 'Qdrant database is experiencing critical issues...',
  severity: 'critical',
  estimatedDuration: '30-60 minutes',
  recommendations: [
    'Avoid making important changes',
    'Wait for service restoration',
    'Contact support if needed'
  ]
}
```

### Rate Limiting

Notifications are rate-limited to prevent spam:

- Maximum notifications per minute: 10
- Maximum notifications per hour: 50
- Cooldown period between notifications: 30 seconds

## Performance Considerations

### Memory Usage

- Fallback storage uses configurable memory limits
- LRU eviction prevents memory exhaustion
- Compression can be enabled for large datasets
- Memory usage is actively monitored and reported

### Performance Impact

- Degradation detection adds minimal overhead (~5ms per check)
- Fallback storage operations are typically faster than Qdrant
- Circuit breaker prevents cascading failures
- Background processes are optimized for low resource usage

### Scalability

- Handles thousands of operations per second in fallback mode
- Configurable batch sizes for optimal performance
- Concurrent operation support with proper synchronization
- Horizontal scaling possible with distributed fallback storage

## Testing

### Unit Tests

```bash
# Run graceful degradation tests
npm test -- tests/integration/qdrant-graceful-degradation.test.ts
```

### Integration Tests

The test suite covers:

- Fallback storage operations and limits
- Degradation detection and triggering
- Failover/failback sequences
- Error budget tracking and alerts
- Notification delivery and formatting
- Performance under load
- Recovery scenarios
- Circuit breaker integration

### Manual Testing

```bash
# Enable graceful degradation
export QDRANT_GRACEFUL_DEGRADATION=true

# Start the application
npm start

# Simulate Qdrant outage (stop Qdrant service)
docker stop qdrant

# Verify operations continue with fallback storage
# Check logs for degradation notifications
# Restart Qdrant service
# Verify automatic recovery
docker start qdrant
```

## Troubleshooting

### Common Issues

**Degradation not triggering:**

- Check configuration thresholds
- Verify Qdrant health monitor is running
- Review circuit breaker status
- Check error budget settings

**Failover not working:**

- Ensure graceful degradation is enabled
- Check fallback storage initialization
- Verify operation interception
- Review error logs for issues

**Recovery not happening:**

- Check health check configuration
- Verify consecutive success requirements
- Review failback logic
- Check for manual intervention blocks

**Memory issues in fallback:**

- Adjust maxMemoryUsageMB configuration
- Enable compression if needed
- Review TTL policies
- Check for memory leaks

### Debug Logging

Enable detailed logging for troubleshooting:

```typescript
const manager = new QdrantGracefulDegradationManager(adapter, {
  notifications: {
    enabled: true,
    detailedLogging: true,
  },
});
```

### Health Monitoring

Monitor these health indicators:

- Degradation level changes
- Failover/failback events
- Error budget consumption
- Fallback storage utilization
- Notification delivery status

## Best Practices

### Configuration

1. **Set appropriate thresholds** based on your service requirements
2. **Configure realistic TTL policies** for fallback storage
3. **Enable multiple notification channels** for critical alerts
4. **Monitor error budget consumption** regularly
5. **Test failover scenarios** in staging environment

### Operations

1. **Monitor degradation metrics** proactively
2. **Respond to critical alerts** promptly
3. **Review failover incidents** for improvement
4. **Update configurations** based on operational experience
5. **Document recovery procedures** for team reference

### Development

1. **Test with graceful degradation** enabled
2. **Handle degraded responses** in application code
3. **Monitor fallback storage usage** during development
4. **Implement proper error handling** for all operations
5. **Add observability** for degradation states

## Migration Guide

### Enabling Graceful Degradation

1. Set `QDRANT_GRACEFUL_DEGRADATION=true`
2. Configure appropriate thresholds for your environment
3. Test failover scenarios in non-production
4. Monitor error budget consumption
5. Gradually roll out to production

### Configuration Migration

```typescript
// Before (basic Qdrant adapter)
const adapter = new QdrantAdapter({
  type: 'qdrant',
  url: process.env.QDRANT_URL,
});

// After (with graceful degradation)
const adapter = new QdrantAdapter({
  type: 'qdrant',
  url: process.env.QDRANT_URL,
});

// Graceful degradation is automatically enabled
// Configure via environment variables or custom config
```

## API Reference

### QdrantGracefulDegradationManager

```typescript
class QdrantGracefulDegradationManager {
  constructor(adapter: QdrantAdapter, config?: Partial<GracefulDegradationManagerConfig>)

  // Lifecycle
  async start(): Promise<void>
  async stop(): Promise<void>

  // Operations
  async store(items: KnowledgeItem[]): Promise<DegradedOperationResponse<...>>
  async search(query: SearchQuery): Promise<DegradedOperationResponse<...>>

  // Control
  async forceFailover(reason: string): Promise<boolean>
  async forceFailback(): Promise<boolean>

  // Monitoring
  getCurrentState(): DegradationState
  getStatistics(): FailoverStatistics
}
```

### InMemoryFallbackStorage

```typescript
class InMemoryFallbackStorage {
  constructor(config?: Partial<InMemoryFallbackConfig>)

  // Lifecycle
  async initialize(): Promise<void>
  async shutdown(): Promise<void>

  // Operations
  async store(items: KnowledgeItem[]): Promise<...>
  async search(query: SearchQuery): Promise<...>
  async findById(ids: string[]): Promise<KnowledgeItem[]>
  async delete(ids: string[]): Promise<{ deleted: number; errors: StoreError[] }>

  // Monitoring
  getMetrics(): DegradationMetrics
  isHealthy(): boolean
  clear(): void
}
```

## Support and Contributing

For issues, questions, or contributions related to the graceful degradation system:

1. Check existing issues in the project repository
2. Review test cases for usage examples
3. Follow the contribution guidelines
4. Include logs and configuration details in bug reports
5. Provide reproduction steps for issues

---

**Version**: 2.0.1
**Last Updated**: 2025-11-05
**Author**: Cortex Team
