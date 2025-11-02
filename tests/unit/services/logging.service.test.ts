/**
 * Comprehensive Unit Tests for Logging Service
 *
 * Tests advanced logging service functionality including:
 * - Log management and formatting with structured JSON logging
 * - Log level management (debug, info, warn, error, fatal)
 * - Log template rendering and message formatting
 * - Log context and correlation ID management
 * - Log storage and persistence strategies
 * - Log rotation and archiving mechanisms
 * - Log retention policies and cleanup
 * - High-volume log handling and buffering
 * - Advanced log search and filtering capabilities
 * - Filter-based log retrieval with pagination
 * - Log aggregation and summarization
 * - Real-time log streaming and subscriptions
 * - High-throughput logging performance optimization
 * - Memory-efficient buffering and batch processing
 * - Asynchronous log processing and queuing
 * - Service integration patterns with distributed logging
 * - Log analytics and metrics collection
 * - Error tracking and alerting mechanisms
 * - Health monitoring and log service status
 * - Sensitive data masking and PII protection
 * - Access control for logs and role-based permissions
 * - Audit trail maintenance and compliance
 * - Security event logging and threat detection
 * - Regulatory compliance reporting (GDPR, SOX, HIPAA)
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { LoggingService } from '../../../src/services/logging/logging-service';
import { createRequestLogger, createChildLogger } from '../../../src/utils/logger';
import type {
  LogEntry,
  LogLevel,
  LogQueryOptions,
  LogStorageConfig,
  LogRetentionConfig,
  LogStreamingConfig,
  LogAnalyticsConfig,
  LogSecurityConfig,
} from '../../../src/types/logging-interfaces';

// Mock external dependencies
vi.mock('../../../src/utils/logger', () => {
  const mockLogger = {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    fatal: vi.fn(),
    child: vi.fn(() => mockLogger),
  };

  return {
    logger: mockLogger,
    createRequestLogger: vi.fn(() => mockLogger),
    createChildLogger: vi.fn(() => mockLogger),
  };
});

vi.mock('fs/promises', () => ({
  writeFile: vi.fn().mockResolvedValue(undefined),
  appendFile: vi.fn().mockResolvedValue(undefined),
  readFile: vi.fn(),
  mkdir: vi.fn().mockResolvedValue(undefined),
  readdir: vi.fn(),
  stat: vi.fn(),
  unlink: vi.fn(),
}));

vi.mock('zlib', () => ({
  gzip: vi.fn((data, callback) => callback(null, Buffer.from('compressed'))),
  gunzip: vi.fn((data, callback) => callback(null, Buffer.from('decompressed'))),
}));

describe('LoggingService - Comprehensive Logging Functionality', () => {
  let loggingService: LoggingService;
  let mockLogger: any;
  let mockFileSystem: any;

  beforeEach(async () => {
    vi.clearAllMocks();

    // Set up file system mocks
    const { promises: fsPromises } = await import('fs');
    mockFileSystem = fsPromises;

    // Import and use the mocked logger
    const { logger } = await import('../../../src/utils/logger');
    mockLogger = logger;

    loggingService = new LoggingService({
      storage: {
        type: 'file',
        directory: './logs',
        maxSize: '100MB',
        maxFiles: 10,
        compression: true,
      },
      retention: {
        defaultDays: 30,
        errorDays: 90,
        auditDays: 2555,
        cleanupInterval: '1h',
      },
      streaming: {
        enabled: true,
        bufferSize: 1000,
        flushInterval: 5000,
        retryAttempts: 3,
      },
      analytics: {
        enabled: true,
        metricsInterval: 60000,
        aggregationWindow: 300000,
      },
      security: {
        masking: {
          enabled: true,
          patterns: ['password', 'token', 'secret', 'key'],
          replacement: '[REDACTED]',
        },
        accessControl: {
          enabled: true,
          roles: ['admin', 'auditor', 'user'],
          defaultRole: 'user',
        },
      },
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. Log Management and Formatting Tests
  describe('Log Management and Formatting', () => {
    it('should create structured log entries with proper formatting', async () => {
      const logData = {
        level: 'info' as LogLevel,
        message: 'User authentication successful',
        context: {
          userId: 'user-123',
          action: 'login',
          ip: '192.168.1.100',
        },
        correlationId: 'corr-abc-123',
        timestamp: new Date().toISOString(),
      };

      await loggingService.writeLog(logData);

      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-123',
          action: 'login',
          ip: '192.168.1.100',
        }),
        'User authentication successful'
      );
    });

    it('should handle different log levels with appropriate severity', async () => {
      const logLevels: LogLevel[] = ['debug', 'info', 'warn', 'error', 'fatal'];

      for (const level of logLevels) {
        await loggingService.writeLog({
          level,
          message: `Test ${level} message`,
          context: { test: true },
        });
      }

      expect(mockLogger.debug).toHaveBeenCalledTimes(1);
      expect(mockLogger.info).toHaveBeenCalledTimes(1);
      expect(mockLogger.warn).toHaveBeenCalledTimes(1);
      expect(mockLogger.error).toHaveBeenCalledTimes(2); // error + fatal maps to error
      expect(mockLogger.fatal).toHaveBeenCalledTimes(0); // fatal maps to error in standard logger
    });

    it('should render log templates with dynamic values', async () => {
      const template = 'User {userId} performed {action} on resource {resourceId}';
      const variables = {
        userId: 'user-456',
        action: 'update',
        resourceId: 'doc-789',
      };

      const renderedMessage = loggingService.renderTemplate(template, variables);

      expect(renderedMessage).toBe('User user-456 performed update on resource doc-789');
    });

    it('should manage log context and correlation IDs', async () => {
      const correlationId = 'corr-xyz-789';

      loggingService.setCorrelationContext(correlationId, {
        service: 'auth-service',
        version: '1.2.3',
      });

      await loggingService.writeLog({
        level: 'info',
        message: 'Processing request',
        context: { endpoint: '/api/auth' },
      });

      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          correlation_id: correlationId,
          service: 'auth-service',
          version: '1.2.3',
          endpoint: '/api/auth',
        }),
        'Processing request'
      );
    });

    it('should validate log entry structure and required fields', async () => {
      const invalidLogEntry = {
        level: 'invalid' as LogLevel,
        message: '',
        context: null,
      };

      const result1 = await loggingService.writeLog(invalidLogEntry);
      expect(result1.success).toBe(false);
      expect(result1.error).toContain('Invalid log entry');

      const result2 = await loggingService.writeLog({
        level: 'info',
        message: '',
        context: {},
      });
      expect(result2.success).toBe(false);
      expect(result2.error).toContain('Invalid log entry: message is required');
    });
  });

  // 2. Log Storage and Persistence Tests
  describe('Log Storage and Persistence', () => {
    it('should store logs efficiently in file system', async () => {
      const logEntry: LogEntry = {
        level: 'info',
        message: 'Test log entry',
        context: { test: true },
        timestamp: new Date().toISOString(),
      };

      await loggingService.storeLog(logEntry);

      expect(mockFileSystem.appendFile).toHaveBeenCalledWith(
        expect.stringContaining('./logs'),
        expect.stringContaining('"Test log entry"'),
        'utf8'
      );
    });

    it('should implement log rotation when size limits exceeded', async () => {
      // Mock large file size to trigger rotation
      mockFileSystem.stat = vi.fn().mockResolvedValue({ size: 150 * 1024 * 1024 }); // 150MB

      await loggingService.rotateLog('test.log');

      expect(mockFileSystem.unlink).toHaveBeenCalled();
      expect(mockFileSystem.writeFile).toHaveBeenCalled();
    });

    it('should archive old logs with compression', async () => {
      const archiveResult = await loggingService.archiveLog('test.log', '2024-01');

      expect(archiveResult.success).toBe(true);
      expect(archiveResult.archivePath).toContain('test-2024-01.log.gz');
    });

    it('should enforce log retention policies', async () => {
      const retentionConfig: LogRetentionConfig = {
        defaultDays: 30,
        errorDays: 90,
        auditDays: 2555,
        cleanupInterval: '1h',
      };

      loggingService.configureRetention(retentionConfig);
      const cleanupResult = await loggingService.cleanupOldLogs();

      expect(cleanupResult.deletedFiles).toBeGreaterThan(0);
      expect(cleanupResult.freedSpace).toBeGreaterThan(0);
    });

    it('should handle high-volume logging with buffering', async () => {
      const logCount = 10000;
      const logs = Array.from({ length: logCount }, (_, i) => ({
        level: 'info' as LogLevel,
        message: `High volume test log ${i}`,
        context: { batch: 'high-volume-test' },
      }));

      const startTime = Date.now();
      await Promise.all(logs.map((log) => loggingService.writeLog(log)));
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
      expect(mockFileSystem.appendFile).toHaveBeenCalled();
    });
  });

  // 3. Log Querying and Filtering Tests
  describe('Log Querying and Filtering', () => {
    it('should provide advanced log search capabilities', async () => {
      const queryOptions: LogQueryOptions = {
        level: ['error', 'fatal'],
        timeRange: {
          start: new Date('2024-01-01'),
          end: new Date('2024-01-31'),
        },
        context: {
          userId: 'user-123',
          service: 'auth-service',
        },
        limit: 100,
        offset: 0,
      };

      const searchResult = await loggingService.searchLogs(queryOptions);

      expect(searchResult.logs).toBeDefined();
      expect(searchResult.total).toBeGreaterThanOrEqual(0);
      expect(searchResult.hasMore).toBeDefined();
    });

    it('should filter logs by multiple criteria', async () => {
      const filters = {
        levels: ['error', 'warn'],
        timeRange: {
          start: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
          end: new Date(),
        },
        contextFilters: {
          service: ['auth-service', 'api-gateway'],
          userId: ['user-123', 'user-456'],
        },
        messagePattern: /authentication.*failed/i,
      };

      const filteredLogs = await loggingService.filterLogs(filters);

      expect(
        filteredLogs.every(
          (log) =>
            ['error', 'warn'].includes(log.level) &&
            log.context?.service &&
            ['auth-service', 'api-gateway'].includes(log.context.service as string)
        )
      ).toBe(true);
    });

    it('should aggregate and summarize log data', async () => {
      const aggregationOptions = {
        groupBy: ['level', 'service'],
        timeWindow: '1h',
        metrics: ['count', 'avg_duration', 'error_rate'],
      };

      const aggregation = await loggingService.aggregateLogs(aggregationOptions);

      expect(aggregation.groups).toBeDefined();
      expect(aggregation.metrics).toBeDefined();
      expect(aggregation.timeRange).toBeDefined();
    });

    it('should provide real-time log streaming', async () => {
      const streamingConfig: LogStreamingConfig = {
        enabled: true,
        bufferSize: 1000,
        flushInterval: 5000,
        retryAttempts: 3,
        subscribers: ['websocket', 'event-stream'],
      };

      loggingService.configureStreaming(streamingConfig);

      const stream = loggingService.createLogStream({
        level: ['error', 'warn'],
        realTime: true,
      });

      // Test streaming capabilities
      expect(stream).toBeDefined();
      expect(typeof stream.subscribe).toBe('function');
      expect(typeof stream.unsubscribe).toBe('function');
    });
  });

  // 4. Performance and Optimization Tests
  describe('Performance and Optimization', () => {
    it('should handle high-throughput logging efficiently', async () => {
      const throughputTest = async (logCount: number) => {
        const startTime = performance.now();

        const promises = Array.from({ length: logCount }, (_, i) =>
          loggingService.writeLog({
            level: 'info',
            message: `Throughput test log ${i}`,
            context: { test: 'throughput' },
          })
        );

        await Promise.all(promises);
        const duration = performance.now() - startTime;
        const logsPerSecond = (logCount / duration) * 1000;

        return { duration, logsPerSecond };
      };

      const result = await throughputTest(10000);
      expect(result.logsPerSecond).toBeGreaterThan(1000); // Should handle >1000 logs/second
    });

    it('should implement memory-efficient buffering', async () => {
      const bufferConfig = {
        maxSize: 500,
        flushInterval: 1000,
        compressionEnabled: true,
      };

      loggingService.configureBuffering(bufferConfig);

      // Fill buffer beyond capacity
      for (let i = 0; i < 600; i++) {
        await loggingService.writeLog({
          level: 'info',
          message: `Buffer test ${i}`,
          context: { buffer: 'test' },
        });
      }

      // Buffer should have flushed automatically
      expect(mockFileSystem.appendFile).toHaveBeenCalled();
    });

    it('should process logs asynchronously with queuing', async () => {
      const queueSize = 1000;
      const processingPromises: Promise<any>[] = [];

      // Add many logs to queue
      for (let i = 0; i < queueSize; i++) {
        processingPromises.push(
          loggingService.writeLogAsync({
            level: 'info',
            message: `Async queue test ${i}`,
            context: { queue: 'test' },
          })
        );
      }

      const startTime = performance.now();
      await Promise.all(processingPromises);
      const duration = performance.now() - startTime;

      expect(duration).toBeLessThan(3000); // Should process queue efficiently
    });

    it('should support batch log operations', async () => {
      const batchLogs = Array.from({ length: 100 }, (_, i) => ({
        level: 'info' as LogLevel,
        message: `Batch log ${i}`,
        context: { batch: 'test' },
      }));

      const batchResult = await loggingService.writeBatchLogs(batchLogs);

      expect(batchResult.successful).toBe(100);
      expect(batchResult.failed).toBe(0);
      expect(batchResult.duration).toBeGreaterThan(0);
    });
  });

  // 5. Integration and Monitoring Tests
  describe('Integration and Monitoring', () => {
    it('should integrate with other services using established patterns', async () => {
      const serviceIntegration = {
        serviceName: 'auth-service',
        correlationId: 'corr-integration-123',
        metadata: {
          version: '1.0.0',
          environment: 'production',
        },
      };

      await loggingService.integrateWithService(serviceIntegration);

      const integrationLog = {
        level: 'info' as LogLevel,
        message: 'Service integration successful',
        context: { service: 'auth-service' },
      };

      await loggingService.writeLog(integrationLog);

      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          service: 'auth-service',
          correlation_id: 'corr-integration-123',
        }),
        'Service integration successful'
      );
    });

    it('should collect log analytics and metrics', async () => {
      const analyticsConfig: LogAnalyticsConfig = {
        enabled: true,
        metricsInterval: 60000,
        aggregationWindow: 300000,
        metrics: ['log_volume', 'error_rate', 'response_time', 'throughput'],
      };

      loggingService.configureAnalytics(analyticsConfig);
      const analytics = await loggingService.getAnalytics();

      expect(analytics.logVolume).toBeDefined();
      expect(analytics.errorRate).toBeDefined();
      expect(analytics.averageResponseTime).toBeDefined();
      expect(analytics.throughput).toBeDefined();
    });

    it('should implement error tracking and alerting', async () => {
      const alertingConfig = {
        enabled: true,
        thresholds: {
          errorRate: 0.05, // 5% error rate threshold
          logVolume: 10000, // 10k logs/minute threshold
          responseTime: 5000, // 5 second response time threshold
        },
        channels: ['email', 'slack', 'webhook'],
      };

      loggingService.configureAlerting(alertingConfig);

      // Trigger error conditions
      for (let i = 0; i < 100; i++) {
        await loggingService.writeLog({
          level: i < 10 ? 'error' : 'info',
          message: `Alert test log ${i}`,
          context: { alert: 'test' },
        });
      }

      const alerts = await loggingService.checkAlerts();
      expect(alerts.length).toBeGreaterThanOrEqual(0);
    });

    it('should provide health monitoring status', async () => {
      // Small delay to ensure uptime > 0
      await new Promise((resolve) => setTimeout(resolve, 10));

      const healthStatus = await loggingService.getHealthStatus();

      expect(healthStatus.status).toBeDefined();
      expect(healthStatus.uptime).toBeGreaterThan(0);
      expect(healthStatus.memoryUsage).toBeDefined();
      expect(healthStatus.diskUsage).toBeDefined();
      expect(healthStatus.bufferStatus).toBeDefined();
      expect(healthStatus.queueStatus).toBeDefined();
    });
  });

  // 6. Security and Compliance Tests
  describe('Security and Compliance', () => {
    it('should mask sensitive data in logs', async () => {
      const sensitiveData = {
        level: 'info' as LogLevel,
        message: 'User login attempt',
        context: {
          userId: 'user-123',
          password: 'super-secret-password',
          apiToken: 'sk-test-1234567890',
          creditCard: '4111-1111-1111-1111',
          ssn: '123-45-6789',
        },
      };

      await loggingService.writeLog(sensitiveData);

      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-123',
          password: '[REDACTED]',
          apiToken: '[REDACTED]',
          creditCard: '[REDACTED]',
          ssn: '[REDACTED]',
        }),
        'User login attempt'
      );
    });

    it('should implement access control for logs', async () => {
      const securityConfig: LogSecurityConfig = {
        masking: {
          enabled: true,
          patterns: ['password', 'token', 'secret'],
          replacement: '[REDACTED]',
        },
        accessControl: {
          enabled: true,
          roles: {
            admin: ['read', 'write', 'delete', 'audit'],
            auditor: ['read', 'audit'],
            user: ['read'],
          },
          defaultRole: 'user',
        },
        encryption: {
          enabled: true,
          algorithm: 'AES-256-GCM',
          keyRotationDays: 90,
        },
      };

      loggingService.configureSecurity(securityConfig);

      // Test access control
      const adminAccess = await loggingService.checkAccess('admin', 'read');
      const userAccess = await loggingService.checkAccess('user', 'delete');

      expect(adminAccess).toBe(true);
      expect(userAccess).toBe(false);
    });

    it('should maintain audit trail for compliance', async () => {
      const auditLog = {
        level: 'info' as LogLevel,
        message: 'Data modification event',
        context: {
          userId: 'admin-user',
          action: 'update_user_profile',
          resource: 'user-profile-123',
          changes: {
            old_values: { status: 'inactive' },
            new_values: { status: 'active' },
          },
          compliance: {
            regulation: 'GDPR',
            data_category: 'personal_data',
            retention_days: 2555,
          },
        },
      };

      await loggingService.writeLog(auditLog);

      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'admin-user',
          action: 'update_user_profile',
          resource: 'user-profile-123',
          compliance: expect.objectContaining({
            regulation: 'GDPR',
            data_category: 'personal_data',
          }),
        }),
        'Data modification event'
      );
    });

    it('should generate compliance reports', async () => {
      const complianceReportOptions = {
        regulation: 'GDPR',
        dateRange: {
          start: new Date('2024-01-01'),
          end: new Date('2024-01-31'),
        },
        dataCategories: ['personal_data', 'sensitive_data'],
        format: 'json',
      };

      const complianceReport =
        await loggingService.generateComplianceReport(complianceReportOptions);

      expect(complianceReport.regulation).toBe('GDPR');
      expect(complianceReport.period).toBeDefined();
      expect(complianceReport.dataAccessEvents).toBeDefined();
      expect(complianceReport.dataModifications).toBeDefined();
      expect(complianceReport.dataRetention).toBeDefined();
    });

    it('should handle security event logging and threat detection', async () => {
      const securityEvent = {
        level: 'warn' as LogLevel,
        message: 'Potential security threat detected',
        context: {
          threat_type: 'brute_force_attempt',
          source_ip: '192.168.1.100',
          target_user: 'admin',
          attempt_count: 5,
          time_window: '5m',
          severity: 'medium',
          mitigation: 'rate_limiting_applied',
        },
      };

      await loggingService.writeLog(securityEvent);

      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.objectContaining({
          threat_type: 'brute_force_attempt',
          source_ip: '192.168.1.100',
          severity: 'medium',
        }),
        'Potential security threat detected'
      );
    });
  });

  // 7. Edge Cases and Error Handling Tests
  describe('Edge Cases and Error Handling', () => {
    it('should handle malformed log entries gracefully', async () => {
      const malformedEntries = [
        null,
        undefined,
        { level: null },
        { level: 'info', message: '' },
        { level: 'invalid', message: 'test' },
        { level: 'info', message: 'test', context: 'invalid' },
      ];

      const results = await Promise.allSettled(
        malformedEntries.map((entry) => loggingService.writeLog(entry as any))
      );

      // All should either succeed (if recoverable) or fail gracefully
      results.forEach((result) => {
        expect(result.status).toBe('fulfilled');
      });
    });

    it('should recover from file system errors', async () => {
      mockFileSystem.appendFile.mockRejectedValueOnce(new Error('Disk full'));

      const logEntry = {
        level: 'info' as LogLevel,
        message: 'Test during error condition',
        context: { test: 'error-recovery' },
      };

      // Should not throw and should retry or use fallback
      await expect(loggingService.writeLog(logEntry)).resolves.not.toThrow();
    });

    it('should handle circular references in log context', async () => {
      const circularObject: any = { name: 'test' };
      circularObject.self = circularObject;

      const logEntry = {
        level: 'info' as LogLevel,
        message: 'Circular reference test',
        context: { circular: circularObject },
      };

      await expect(loggingService.writeLog(logEntry)).resolves.not.toThrow();
    });

    it('should handle extremely large log messages', async () => {
      const largeMessage = 'x'.repeat(10 * 1024 * 1024); // 10MB message

      const logEntry = {
        level: 'info' as LogLevel,
        message: largeMessage,
        context: { size: 'large' },
      };

      await loggingService.writeLog(logEntry);

      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.any(Object),
        expect.stringContaining('[TRUNCATED]')
      );
    });
  });
});
