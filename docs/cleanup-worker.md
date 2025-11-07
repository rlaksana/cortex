# Cleanup Worker Service - P3-2 Implementation

## Overview

The Cleanup Worker Service is a comprehensive data management system designed to safely and efficiently clean up expired data, orphaned relationships, duplicates, and system maintenance data. It provides MCP-callable operations with robust safety mechanisms and comprehensive metrics tracking.

## Features

### 🔧 Core Functionality

- **Multi-Operation Cleanup**: Expired items, orphaned relationships, duplicates, metrics, and logs
- **Dry-Run Mode**: Count-only preview mode without actual deletions
- **Safety Mechanisms**: Confirmation tokens, backups, rollback capabilities
- **Batch Processing**: Configurable batch sizes and limits for performance
- **Scope Filtering**: Project, organization, and branch-level filtering

### 📊 Metrics & Monitoring

- **cleanup_deleted_total**: Total items deleted across all operations
- **cleanup_dryrun_total**: Items identified for deletion in dry-run
- **cleanup_by_type**: Breakdown by knowledge type (entity, relation, todo, etc.)
- **cleanup_duration**: Operation timing metrics per operation type
- **cleanup_errors**: Error tracking with detailed context
- **Performance Metrics**: Items per second, average batch duration, memory usage

### 🛡️ Safety Features

- **Confirmation Tokens**: Required for destructive operations
- **Automatic Backups**: Configurable backup creation before cleanup
- **Safety Thresholds**: Automatic warnings for large operations
- **Audit Logging**: Comprehensive operation tracking
- **Rollback Support**: Backup restoration capabilities

## MCP Tool Interface

### 1. run_cleanup

Main cleanup operation with comprehensive configuration options.

```json
{
  "operation": "run_cleanup",
  "dry_run": true,
  "cleanup_operations": ["expired", "orphaned", "duplicate", "metrics", "logs"],
  "cleanup_scope_filters": {
    "project": "my-project",
    "org": "my-org",
    "branch": "main"
  },
  "require_confirmation": true,
  "confirmation_token": "optional_token_for_confirmed_operations",
  "enable_backup": true,
  "batch_size": 100,
  "max_batches": 50
}
```

**Response Format:**

```json
{
  "content": [
    {
      "type": "cleanup_report",
      "report": {
        "operation_id": "cleanup_123456789",
        "timestamp": "2025-01-01T10:00:00.000Z",
        "mode": "dry_run",
        "summary": {
          "operations_completed": 2,
          "total_items_deleted": 0,
          "total_items_dryrun": 1250,
          "duration_ms": 450,
          "errors_count": 0,
          "warnings_count": 1,
          "backup_created": false
        },
        "metrics": {
          "cleanup_deleted_total": 0,
          "cleanup_dryrun_total": 1250,
          "cleanup_by_type": {
            "entity": 500,
            "relation": 375,
            "todo": 250,
            "decision": 125
          },
          "cleanup_duration": {
            "expired": 200,
            "orphaned": 150
          },
          "performance": {
            "items_per_second": 2777.78,
            "average_batch_duration_ms": 175,
            "total_batches_processed": 2
          }
        },
        "safety_confirmations": {
          "required": false,
          "confirmed": true,
          "confirmation_token": null
        },
        "errors": [],
        "warnings": ["Large deletion operation: 1250 items estimated"]
      }
    },
    {
      "type": "text",
      "text": "Cleanup dry_run completed: 0 items deleted, 1250 items identified for deletion. Duration: 450ms. Errors: 0, Warnings: 1."
    }
  ]
}
```

### 2. confirm_cleanup

Confirm a cleanup operation that requires confirmation.

```json
{
  "operation": "confirm_cleanup",
  "cleanup_token": "cleanup_confirm_1234567890_abcdef"
}
```

### 3. get_cleanup_statistics

Get statistics for cleanup operations over a time period.

```json
{
  "operation": "get_cleanup_statistics",
  "cleanup_stats_days": 30
}
```

**Response:**

```json
{
  "content": [
    {
      "type": "cleanup_statistics",
      "statistics": {
        "total_operations": 15,
        "total_items_deleted": 8750,
        "total_items_dryrun": 12500,
        "average_duration_ms": 320,
        "success_rate": 93.3,
        "operations_by_type": {
          "expired": 8,
          "orphaned": 3,
          "duplicate": 2,
          "metrics": 1,
          "logs": 1
        },
        "errors_by_type": {
          "expired": 1
        },
        "period_days": 30,
        "calculated_at": "2025-01-01T10:00:00.000Z"
      }
    }
  ]
}
```

### 4. get_cleanup_history

Get historical cleanup operation records.

```json
{
  "operation": "get_cleanup_history",
  "cleanup_history_limit": 10
}
```

## Configuration

### Default Configuration

```typescript
const DEFAULT_CONFIG = {
  enabled: true,
  batch_size: 100,
  max_batches: 50,
  dry_run: true, // Default to safe mode
  require_confirmation: true,
  enable_backup: true,
  backup_retention_days: 30,
  enable_orphan_cleanup: true,
  enable_duplicate_cleanup: 1, // Days threshold
  duplicate_similarity_threshold: 0.9,
  scope_filters: {},
  performance: {
    max_items_per_second: 1000,
    enable_parallel_processing: false,
    max_parallel_workers: 2,
  },
};
```

### Configuration Updates

```typescript
const cleanupWorker = getCleanupWorker();
cleanupWorker.updateConfig({
  dry_run: false,
  batch_size: 200,
  require_confirmation: false,
});
```

## Operations

### 1. Expired Items Cleanup

- **Purpose**: Remove items past their TTL expiry time
- **Method**: Uses existing expiry worker functionality
- **Safety**: Respects TTL settings and retention policies
- **Metrics**: Tracks expired_items_deleted

### 2. Orphaned Relationships Cleanup

- **Purpose**: Remove relationships without valid target entities
- **Method**: Searches for dangling references and broken links
- **Safety**: Validates orphan status before deletion
- **Metrics**: Tracks orphaned_items_deleted

### 3. Duplicate Items Cleanup

- **Purpose**: Remove or merge duplicate knowledge items
- **Method**: Semantic similarity detection with configurable thresholds
- **Safety**: Keeps newest/highest quality items
- **Metrics**: Tracks duplicate_items_deleted

### 4. Metrics Cleanup

- **Purpose**: Clean up old performance metrics and telemetry data
- **Retention**: Configurable retention period (default: 30 days)
- **Safety**: Preserves recent performance data
- **Metrics**: Tracks metrics_items_deleted

### 5. Log Cleanup

- **Purpose**: Rotate and archive old log entries
- **Retention**: Configurable log retention (default: 7 days)
- **Method**: Archive old logs, clean up temporary files
- **Metrics**: Tracks logs_items_deleted

## Safety Mechanisms

### Confirmation Workflow

1. **Dry-Run**: First run with `dry_run: true` to preview impact
2. **Safety Check**: System evaluates operation impact and generates warnings
3. **Token Generation**: Confirmation token created for large operations
4. **User Confirmation**: Use `confirm_cleanup` with the generated token
5. **Execution**: Proceed with actual cleanup operation

### Backup System

- **Automatic**: Backup created when `enable_backup: true`
- **Scope**: Only includes items affected by cleanup operation
- **Retention**: Configurable backup retention period
- **Rollback**: Backup items can be restored if needed

### Safety Thresholds

- **Large Operations**: Warnings for >100 items
- **Extremely Large**: Confirmation required for >1000 items
- **Safety Limits**: Maximum 100,000 items per operation
- **Time Limits**: Maximum 30 minutes per operation

## Performance Considerations

### Batch Processing

- Configurable batch sizes (1-1000 items)
- Maximum batch limits (1-100 batches)
- Automatic retry for failed batches
- Progress reporting for long operations

### Resource Management

- Memory usage monitoring
- Items per second throttling
- Database connection pooling
- Background processing capabilities

### Optimization Strategies

- Index-aware queries for efficient filtering
- Parallel processing options (configurable)
- Smart caching for repeated operations
- Resource cleanup between operations

## Error Handling

### Error Categories

1. **Configuration Errors**: Invalid parameters, missing required fields
2. **Permission Errors**: Insufficient rights for destructive operations
3. **Database Errors**: Connection issues, transaction failures
4. **System Errors**: Memory limits, timeout errors

### Error Recovery

- Automatic retry for transient errors
- Partial operation rollback
- Detailed error logging with context
- Graceful degradation for non-critical failures

### Error Metrics

- cleanup_errors array with detailed error information
- Error categorization by operation type
- Success rate tracking in statistics
- Error trend analysis over time

## Testing

### Test Suites

1. **Unit Tests**: Core service functionality and business logic
2. **Integration Tests**: MCP tool interface and end-to-end workflows
3. **Performance Tests**: Metrics accuracy and load testing

### Running Tests

```bash
# Run all cleanup tests
npm run test:cleanup

# Run specific test suite
npm run test:cleanup:service
npm run test:cleanup:integration
npm run test:cleanup:performance

# Run with coverage
npm run test:cleanup:coverage

# Run in watch mode
npm run test:cleanup:watch
```

### Test Coverage

- Configuration management
- Safety mechanisms and confirmation flows
- Metrics tracking accuracy
- Error handling and recovery
- Performance under load
- Integration with MCP tools

## Monitoring and Observability

### Key Metrics

- `cleanup_deleted_total`: Total items deleted (primary success metric)
- `cleanup_dryrun_total`: Items identified in dry-run mode
- `cleanup_duration_ms`: Operation duration metrics
- `cleanup_errors_total`: Error count tracking
- `cleanup_success_rate`: Operation success percentage

### Logging

- Structured logging with operation IDs
- Performance metrics in every operation
- Detailed error contexts and stack traces
- Audit trail for all destructive operations

### Health Checks

- Database connectivity validation
- Configuration sanity checks
- Resource availability verification
- Performance baseline monitoring

## Best Practices

### Before Running Cleanup

1. **Always dry-run first**: Preview impact before actual deletion
2. **Check scope filters**: Ensure you're targeting correct data
3. **Verify backups**: Confirm backup system is working
4. **Monitor resources**: Ensure sufficient system resources

### During Operations

1. **Monitor progress**: Watch operation logs and metrics
2. **Check errors**: Review any errors that occur
3. **Validate results**: Confirm expected number of deletions
4. **System health**: Monitor overall system performance

### After Operations

1. **Review reports**: Analyze operation reports and metrics
2. **Verify integrity**: Check that system is functioning correctly
3. **Update statistics**: Review cleanup statistics for trends
4. **Backup verification**: Confirm backups are valid if created

## Troubleshooting

### Common Issues

1. **Confirmation Required**: Operation requires confirmation token
2. **Scope Filters**: No items found with specified filters
3. **Database Errors**: Connection or transaction issues
4. **Performance Issues**: Operations taking too long

### Debugging Steps

1. Check operation logs for detailed error information
2. Verify configuration parameters are correct
3. Test with smaller batch sizes
4. Run in dry-run mode first
5. Review system metrics and health status

### Getting Help

- Check operation history for similar successful operations
- Review error logs for specific error messages
- Use get_cleanup_statistics to understand system state
- Contact support with operation IDs and error details

## Future Enhancements

### Planned Features

- **Machine Learning**: Intelligent duplicate detection
- **Advanced Scheduling**: Cron-based cleanup scheduling
- **Multi-Region Support**: Cross-region cleanup coordination
- **Advanced Analytics**: Cleanup optimization recommendations

### Performance Improvements

- **Distributed Processing**: Multi-node cleanup operations
- **Smart Batching**: Adaptive batch size optimization
- **Caching Layer**: Intelligent result caching
- **Database Optimizations**: Query performance improvements

## API Reference

### CleanupWorkerService Class

```typescript
class CleanupWorkerService {
  constructor(config?: Partial<CleanupWorkerConfig>);

  async runCleanup(options: CleanupOptions): Promise<CleanupReport>;
  confirmCleanup(token: string): boolean;
  getOperationHistory(limit?: number): CleanupReport[];
  getCleanupStatistics(days?: number): Promise<CleanupStatistics>;
  updateConfig(config: Partial<CleanupWorkerConfig>): void;
  getConfig(): CleanupWorkerConfig;
}
```

### Key Interfaces

```typescript
interface CleanupReport {
  operation_id: string;
  timestamp: string;
  mode: 'dry_run' | 'cleanup';
  config: CleanupWorkerConfig;
  operations: CleanupOperation[];
  metrics: CleanupMetrics;
  backup_created?: BackupInfo;
  safety_confirmations: SafetyConfirmation;
  errors: CleanupError[];
  warnings: string[];
  performance: PerformanceMetrics;
}

interface CleanupMetrics {
  cleanup_deleted_total: number;
  cleanup_dryrun_total: number;
  cleanup_by_type: Record<string, number>;
  cleanup_duration: Record<string, number>;
  cleanup_errors: CleanupError[];
  expired_items_deleted: number;
  orphaned_items_deleted: number;
  duplicate_items_deleted: number;
  metrics_items_deleted: number;
  logs_items_deleted: number;
  items_per_second: number;
  average_batch_duration_ms: number;
  total_batches_processed: number;
}
```

## Version History

### v1.0.0 (Current)

- Initial implementation with comprehensive cleanup operations
- MCP tool interface with safety mechanisms
- Full metrics tracking and monitoring
- Comprehensive test coverage
- Performance optimization and batch processing

### Roadmap

- v1.1.0: Advanced scheduling and automation
- v1.2.0: Machine learning enhanced duplicate detection
- v2.0.0: Distributed cleanup processing
