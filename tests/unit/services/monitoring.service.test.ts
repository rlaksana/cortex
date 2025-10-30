import {
  MonitoringService,
  HealthStatus,
  LogLevel,
  AlertSeverity,
  type HealthCheckResult,
  type PerformanceMetrics,
  type AlertConfiguration,
  type LogEntry,
  type MonitoringDashboard
} from '../../../src/services/monitoring.service';
import { TestDatabase } from '../../utils/test-database';
import { sleep } from '../../utils/test-helpers';

describe('MonitoringService', () => {
  let monitoringService: MonitoringService;
  let testDatabase: TestDatabase;

  beforeAll(async () => {
    testDatabase = new TestDatabase();
    await testDatabase.initialize();
    monitoringService = new MonitoringService({
      database: testDatabase.getDatabase(),
      metricsRetentionDays: 30,
      alertCheckInterval: 30000, // 30 seconds
      enableRealTimeMonitoring: true
    });
    await monitoringService.initialize();
  });

  afterAll(async () => {
    await monitoringService.shutdown();
    await testDatabase.cleanup();
  });

  beforeEach(async () => {
    await testDatabase.clearTables();
  });

  describe('Health Monitoring', () => {
    it('should perform comprehensive health check', async () => {
      const healthCheck = await monitoringService.performHealthCheck();

      expect(healthCheck).toMatchObject({
        status: expect.stringMatching(/^(healthy|degraded|unhealthy)$/),
        timestamp: expect.any(Date),
        checks: expect.objectContaining({
          database: expect.objectContaining({
            status: expect.stringMatching(/^(pass|fail|warn)$/),
            responseTime: expect.any(Number)
          }),
          memory: expect.objectContaining({
            status: expect.stringMatching(/^(pass|fail|warn)$/),
            usage: expect.any(Number)
          }),
          disk: expect.objectContaining({
            status: expect.stringMatching(/^(pass|fail|warn)$/),
            usage: expect.any(Number)
          })
        })
      });
    });

    it('should register custom health checks', async () => {
      const customCheck = jest.fn().mockResolvedValue({
        status: 'pass' as const,
        responseTime: 50,
        message: 'Custom service is healthy'
      });

      monitoringService.registerHealthCheck('custom-service', customCheck);

      const healthCheck = await monitoringService.performHealthCheck();
      expect(healthCheck.checks.customService).toBeDefined();
      expect(customCheck).toHaveBeenCalled();
    });

    it('should detect degraded service state', async () => {
      // Simulate high memory usage
      const mockMemoryCheck = jest.fn().mockResolvedValue({
        status: 'warn' as const,
        responseTime: 100,
        usage: 85,
        message: 'High memory usage'
      });

      monitoringService.registerHealthCheck('memory', mockMemoryCheck);

      const healthCheck = await monitoringService.performHealthCheck();
      expect(healthCheck.status).toBe('degraded');
    });

    it('should detect unhealthy service state', async () => {
      const mockDatabaseCheck = jest.fn().mockResolvedValue({
        status: 'fail' as const,
        responseTime: 5000,
        message: 'Database connection failed'
      });

      monitoringService.registerHealthCheck('database', mockDatabaseCheck);

      const healthCheck = await monitoringService.performHealthCheck();
      expect(healthCheck.status).toBe('unhealthy');
    });

    it('should monitor service dependencies', async () => {
      const dependencies = ['database', 'cache', 'external-api'];
      const dependencyHealth = await monitoringService.checkDependencies(dependencies);

      expect(dependencyHealth).toHaveProperty('database');
      expect(dependencyHealth).toHaveProperty('cache');
      expect(dependencyHealth).toHaveProperty('external-api');

      Object.values(dependencyHealth).forEach((dep: any) => {
        expect(dep).toMatchObject({
          status: expect.stringMatching(/^(healthy|degraded|unhealthy)$/),
          responseTime: expect.any(Number),
          lastChecked: expect.any(Date)
        });
      });
    });
  });

  describe('Performance Metrics', () => {
    it('should track response time metrics', async () => {
      const operationId = 'user-login';
      const responseTime = 250;

      await monitoringService.recordResponseTime(operationId, responseTime);

      const metrics = await monitoringService.getPerformanceMetrics(operationId);
      expect(metrics).toMatchObject({
        operationId,
        averageResponseTime: expect.any(Number),
        maxResponseTime: expect.any(Number),
        minResponseTime: expect.any(Number),
        requestCount: expect.any(Number),
        errorRate: expect.any(Number),
        p50: expect.any(Number),
        p95: expect.any(Number),
        p99: expect.any(Number)
      });

      expect(metrics.averageResponseTime).toBe(responseTime);
      expect(metrics.requestCount).toBe(1);
    });

    it('should calculate percentiles correctly', async () => {
      const operationId = 'api-request';
      const responseTimes = [100, 150, 200, 250, 300, 350, 400, 450, 500, 1000];

      for (const time of responseTimes) {
        await monitoringService.recordResponseTime(operationId, time);
      }

      const metrics = await monitoringService.getPerformanceMetrics(operationId);

      expect(metrics.p50).toBeLessThanOrEqual(300);
      expect(metrics.p95).toBeLessThanOrEqual(800);
      expect(metrics.p99).toBeLessThanOrEqual(1000);
      expect(metrics.minResponseTime).toBe(100);
      expect(metrics.maxResponseTime).toBe(1000);
    });

    it('should track throughput metrics', async () => {
      const operationId = 'data-processing';
      const timeWindow = 60000; // 1 minute

      // Record multiple requests
      for (let i = 0; i < 10; i++) {
        await monitoringService.recordResponseTime(operationId, 100);
        await sleep(10);
      }

      const throughput = await monitoringService.getThroughputMetrics(operationId, timeWindow);
      expect(throughput).toMatchObject({
        operationId,
        requestsPerMinute: expect.any(Number),
        requestsPerSecond: expect.any(Number),
        timeWindowMs: timeWindow,
        totalRequests: expect.any(Number)
      });

      expect(throughput.totalRequests).toBe(10);
      expect(throughput.requestsPerMinute).toBeGreaterThan(0);
    });

    it('should track error rates', async () => {
      const operationId = 'payment-processing';

      // Record successful requests
      for (let i = 0; i < 8; i++) {
        await monitoringService.recordResponseTime(operationId, 100);
      }

      // Record failed requests
      for (let i = 0; i < 2; i++) {
        await monitoringService.recordError(operationId, 'validation_error');
      }

      const metrics = await monitoringService.getPerformanceMetrics(operationId);
      expect(metrics.errorRate).toBe(0.2); // 2 errors out of 10 total requests
    });

    it('should monitor resource utilization', async () => {
      const resourceMetrics = await monitoringService.getResourceMetrics();

      expect(resourceMetrics).toMatchObject({
        timestamp: expect.any(Date),
        cpu: expect.objectContaining({
          usage: expect.any(Number),
          cores: expect.any(Number),
          loadAverage: expect.arrayOf([expect.any(Number)])
        }),
        memory: expect.objectContaining({
          used: expect.any(Number),
          total: expect.any(Number),
          usagePercentage: expect.any(Number),
          heapUsed: expect.any(Number),
          heapTotal: expect.any(Number)
        }),
        disk: expect.objectContaining({
          used: expect.any(Number),
          total: expect.any(Number),
          usagePercentage: expect.any(Number)
        }),
        network: expect.objectContaining({
          bytesReceived: expect.any(Number),
          bytesSent: expect.any(Number),
          packetsReceived: expect.any(Number),
          packetsSent: expect.any(Number)
        })
      });
    });
  });

  describe('Alerting and Notifications', () => {
    it('should configure alert thresholds', async () => {
      const alertConfig: AlertConfiguration = {
        id: 'high-error-rate',
        name: 'High Error Rate Alert',
        metric: 'error_rate',
        threshold: 0.1,
        operator: '>',
        severity: 'critical',
        enabled: true,
        notificationChannels: ['email', 'slack'],
        cooldownPeriod: 300000, // 5 minutes
        description: 'Alert when error rate exceeds 10%'
      };

      const created = await monitoringService.createAlert(alertConfig);
      expect(created).toMatchObject(alertConfig);
      expect(created.id).toBeDefined();
    });

    it('should trigger alerts when thresholds are exceeded', async () => {
      const alertConfig = await monitoringService.createAlert({
        id: 'test-alert',
        name: 'Test Alert',
        metric: 'response_time',
        threshold: 1000,
        operator: '>',
        severity: 'warning',
        enabled: true,
        notificationChannels: ['email']
      });

      // Record response time that exceeds threshold
      await monitoringService.recordResponseTime('test-operation', 1500);

      // Check for triggered alerts
      const triggeredAlerts = await monitoringService.getTriggeredAlerts();
      const testAlert = triggeredAlerts.find(alert => alert.configId === alertConfig.id);

      expect(testAlert).toBeDefined();
      expect(testAlert?.severity).toBe('warning');
      expect(testAlert?.status).toBe('active');
    });

    it('should respect alert cooldown periods', async () => {
      const alertConfig = await monitoringService.createAlert({
        id: 'cooldown-test',
        name: 'Cooldown Test',
        metric: 'cpu_usage',
        threshold: 80,
        operator: '>',
        severity: 'warning',
        enabled: true,
        notificationChannels: ['email'],
        cooldownPeriod: 60000 // 1 minute
      });

      // Trigger alert first time
      await monitoringService.evaluateAlert(alertConfig.id, { cpu_usage: 85 });
      const firstAlert = await monitoringService.getTriggeredAlerts();

      // Try to trigger again within cooldown
      await monitoringService.evaluateAlert(alertConfig.id, { cpu_usage: 90 });
      const secondAlert = await monitoringService.getTriggeredAlerts();

      expect(firstAlert.length).toBeGreaterThan(0);
      expect(secondAlert.length).toBe(firstAlert.length); // No new alert due to cooldown
    });

    it('should support alert escalation rules', async () => {
      const escalationConfig = {
        alertId: 'escalation-test',
        rules: [
          {
            condition: 'duration > 300', // 5 minutes
            action: 'escalate_to_manager',
            severity: 'critical'
          },
          {
            condition: 'duration > 900', // 15 minutes
            action: 'escalate_to_director',
            severity: 'critical'
          }
        ]
      };

      await monitoringService.configureAlertEscalation(escalationConfig);

      const config = await monitoringService.getAlertEscalationConfig(escalationConfig.alertId);
      expect(config).toMatchObject(escalationConfig);
    });

    it('should deduplicate similar alerts', async () => {
      const alertConfig = await monitoringService.createAlert({
        id: 'deduplication-test',
        name: 'Deduplication Test',
        metric: 'disk_usage',
        threshold: 90,
        operator: '>',
        severity: 'warning',
        enabled: true,
        notificationChannels: ['email']
      });

      // Trigger multiple similar alerts
      await monitoringService.evaluateAlert(alertConfig.id, { disk_usage: 95 });
      await monitoringService.evaluateAlert(alertConfig.id, { disk_usage: 96 });
      await monitoringService.evaluateAlert(alertConfig.id, { disk_usage: 97 });

      const triggeredAlerts = await monitoringService.getTriggeredAlerts();
      const deduplicatedAlerts = triggeredAlerts.filter(alert => alert.configId === alertConfig.id);

      expect(deduplicatedAlerts.length).toBe(1); // Should deduplicate to single alert
    });
  });

  describe('Logging and Auditing', () => {
    it('should create structured log entries', async () => {
      const logEntry: LogEntry = {
        level: 'info',
        message: 'User authentication successful',
        timestamp: new Date(),
        context: {
          userId: 'user123',
          ipAddress: '192.168.1.1',
          userAgent: 'Mozilla/5.0...'
        },
        service: 'auth-service',
        traceId: 'trace-123'
      };

      const created = await monitoringService.createLogEntry(logEntry);
      expect(created).toMatchObject(logEntry);
      expect(created.id).toBeDefined();
    });

    it('should manage log levels', async () => {
      const logLevels = ['debug', 'info', 'warn', 'error', 'fatal'];

      for (const level of logLevels) {
        await monitoringService.createLogEntry({
          level: level as LogLevel,
          message: `Test ${level} message`,
          timestamp: new Date(),
          service: 'test-service'
        });
      }

      // Test filtering by log level
      const errorLogs = await monitoringService.getLogs({ minLevel: 'error' });
      expect(errorLogs.length).toBe(2); // error and fatal

      const infoLogs = await monitoringService.getLogs({ minLevel: 'info' });
      expect(infoLogs.length).toBe(4); // info, warn, error, fatal
    });

    it('should maintain audit trail', async () => {
      const auditEntry = {
        action: 'user_deleted',
        userId: 'admin123',
        targetUserId: 'user456',
        timestamp: new Date(),
        ip: '192.168.1.100',
        userAgent: 'Mozilla/5.0...',
        result: 'success',
        metadata: {
          reason: 'Account closure request',
          approvalId: 'approval-789'
        }
      };

      await monitoringService.createAuditEntry(auditEntry);

      const auditTrail = await monitoringService.getAuditTrail({
        userId: 'admin123',
        action: 'user_deleted'
      });

      expect(auditTrail).toHaveLength(1);
      expect(auditTrail[0]).toMatchObject(auditEntry);
    });

    it('should aggregate logs by time periods', async () => {
      const now = new Date();
      const timeWindow = 3600000; // 1 hour

      // Create logs at different times
      for (let i = 0; i < 10; i++) {
        await monitoringService.createLogEntry({
          level: 'info',
          message: `Test message ${i}`,
          timestamp: new Date(now.getTime() + i * 60000), // 1 minute apart
          service: 'test-service'
        });
      }

      const aggregatedLogs = await monitoringService.getAggregatedLogs({
        startTime: new Date(now.getTime() - timeWindow),
        endTime: new Date(now.getTime() + timeWindow),
        groupBy: 'service',
        interval: '1h'
      });

      expect(aggregatedLogs).toHaveProperty('test-service');
      expect(aggregatedLogs['test-service'].total).toBe(10);
    });

    it('should support log search and filtering', async () => {
      // Create test logs
      await monitoringService.createLogEntry({
        level: 'error',
        message: 'Database connection failed',
        timestamp: new Date(),
        service: 'database-service',
        context: { error: 'Connection timeout' }
      });

      await monitoringService.createLogEntry({
        level: 'info',
        message: 'User logged in successfully',
        timestamp: new Date(),
        service: 'auth-service',
        context: { userId: 'user123' }
      });

      // Search logs
      const searchResults = await monitoringService.searchLogs({
        query: 'database',
        level: 'error',
        service: 'database-service',
        limit: 10
      });

      expect(searchResults).toHaveLength(1);
      expect(searchResults[0].message).toContain('database');
      expect(searchResults[0].level).toBe('error');
    });
  });

  describe('Dashboard and Reporting', () => {
    it('should collect metrics for dashboard', async () => {
      // Generate some test data
      await monitoringService.recordResponseTime('api-users', 150);
      await monitoringService.recordResponseTime('api-users', 200);
      await monitoringService.recordError('api-orders', 'validation_error');

      const dashboardData: MonitoringDashboard = await monitoringService.getDashboardData();

      expect(dashboardData).toMatchObject({
        overview: expect.objectContaining({
          totalRequests: expect.any(Number),
          errorRate: expect.any(Number),
          averageResponseTime: expect.any(Number),
          uptime: expect.any(Number),
          activeAlerts: expect.any(Number)
        }),
        performance: expect.objectContaining({
          topOperations: expect.arrayContaining([
            expect.objectContaining({
              operationId: expect.any(String),
              requestCount: expect.any(Number),
              averageResponseTime: expect.any(Number),
              errorRate: expect.any(Number)
            })
          ])
        }),
        health: expect.objectContaining({
          status: expect.stringMatching(/^(healthy|degraded|unhealthy)$/),
          lastCheck: expect.any(Date),
          services: expect.arrayContaining([
            expect.objectContaining({
              name: expect.any(String),
              status: expect.stringMatching(/^(healthy|degraded|unhealthy)$/),
              responseTime: expect.any(Number)
            })
          ])
        }),
        alerts: expect.objectContaining({
          active: expect.arrayContaining([
            expect.objectContaining({
              id: expect.any(String),
              severity: expect.stringMatching(/^(info|warning|critical)$/),
              message: expect.any(String),
              triggeredAt: expect.any(Date)
            })
          ]),
          totalToday: expect.any(Number)
        })
      });
    });

    it('should generate performance reports', async () => {
      const reportPeriod = {
        startTime: new Date(Date.now() - 86400000), // 24 hours ago
        endTime: new Date()
      };

      // Generate test data
      const operations = ['users', 'orders', 'products'];
      for (const op of operations) {
        for (let i = 0; i < 10; i++) {
          await monitoringService.recordResponseTime(`api-${op}`, Math.random() * 500 + 100);
        }
      }

      const report = await monitoringService.generatePerformanceReport(reportPeriod);

      expect(report).toMatchObject({
        period: reportPeriod,
        summary: expect.objectContaining({
          totalRequests: expect.any(Number),
          totalErrors: expect.any(Number),
          overallErrorRate: expect.any(Number),
          averageResponseTime: expect.any(Number),
          uptime: expect.any(Number)
        }),
        operations: expect.arrayContaining([
          expect.objectContaining({
            operationId: expect.any(String),
            requestCount: expect.any(Number),
            errorCount: expect.any(Number),
            errorRate: expect.any(Number),
            averageResponseTime: expect.any(Number),
            p50: expect.any(Number),
            p95: expect.any(Number),
            p99: expect.any(Number)
          })
        ]),
        trends: expect.objectContaining({
          responseTimeTrend: expect.arrayContaining([expect.any(Number)]),
          errorRateTrend: expect.arrayContaining([expect.any(Number)]),
          requestVolumeTrend: expect.arrayContaining([expect.any(Number)])
        })
      });
    });

    it('should provide real-time monitoring data', async () => {
      const realTimeData = await monitoringService.getRealTimeMetrics();

      expect(realTimeData).toMatchObject({
        timestamp: expect.any(Date),
        requests: expect.objectContaining({
          currentRate: expect.any(Number),
          lastMinute: expect.any(Number),
          lastHour: expect.any(Number)
        }),
        errors: expect.objectContaining({
          currentRate: expect.any(Number),
          lastMinute: expect.any(Number),
          lastHour: expect.any(Number)
        }),
        responseTime: expect.objectContaining({
          current: expect.any(Number),
          lastMinuteAverage: expect.any(Number),
          lastHourAverage: expect.any(Number)
        }),
        system: expect.objectContaining({
          cpu: expect.any(Number),
          memory: expect.any(Number),
          disk: expect.any(Number)
        })
      });
    });

    it('should analyze historical trends', async () => {
      const analysisPeriod = {
        startTime: new Date(Date.now() - 7 * 86400000), // 7 days ago
        endTime: new Date()
      };

      const trendAnalysis = await monitoringService.analyzeTrends(analysisPeriod);

      expect(trendAnalysis).toMatchObject({
        period: analysisPeriod,
        responseTime: expect.objectContaining({
          trend: expect.stringMatching(/^(improving|degrading|stable)$/),
          slope: expect.any(Number),
          correlation: expect.any(Number)
        }),
        errorRate: expect.objectContaining({
          trend: expect.stringMatching(/^(improving|degrading|stable)$/),
          slope: expect.any(Number),
          correlation: expect.any(Number)
        }),
        throughput: expect.objectContaining({
          trend: expect.stringMatching(/^(increasing|decreasing|stable)$/),
          slope: expect.any(Number),
          correlation: expect.any(Number)
        }),
        recommendations: expect.arrayContaining([expect.any(String)])
      });
    });
  });

  describe('Integration with Services', () => {
    it('should collect metrics from multiple services', async () => {
      const services = ['auth-service', 'user-service', 'order-service'];

      for (const service of services) {
        await monitoringService.recordServiceMetrics(service, {
          requestCount: 10,
          errorCount: 1,
          averageResponseTime: 200,
          memoryUsage: 50000000,
          cpuUsage: 0.3
        });
      }

      const serviceMetrics = await monitoringService.getServiceMetrics();

      expect(Object.keys(serviceMetrics)).toEqual(expect.arrayContaining(services));

      for (const service of services) {
        expect(serviceMetrics[service]).toMatchObject({
          requestCount: expect.any(Number),
          errorCount: expect.any(Number),
          errorRate: expect.any(Number),
          averageResponseTime: expect.any(Number),
          memoryUsage: expect.any(Number),
          cpuUsage: expect.any(Number),
          lastUpdated: expect.any(Date)
        });
      }
    });

    it('should support cross-service monitoring', async () => {
      const serviceDependencies = {
        'order-service': ['user-service', 'payment-service', 'inventory-service'],
        'user-service': ['auth-service', 'database'],
        'payment-service': ['payment-gateway', 'database']
      };

      const crossServiceHealth = await monitoringService.checkCrossServiceHealth(serviceDependencies);

      expect(crossServiceHealth).toMatchObject({
        overallStatus: expect.stringMatching(/^(healthy|degraded|unhealthy)$/),
        services: expect.objectContaining(
          Object.keys(serviceDependencies).reduce((acc, service) => {
            acc[service] = expect.objectContaining({
              status: expect.stringMatching(/^(healthy|degraded|unhealthy)$/),
              dependencies: expect.arrayContaining([
                expect.objectContaining({
                  name: expect.any(String),
                  status: expect.stringMatching(/^(healthy|degraded|unhealthy)$/),
                  responseTime: expect.any(Number)
                })
              ])
            });
            return acc;
          }, {} as any)
        )
      });
    });

    it('should support distributed tracing', async () => {
      const traceId = 'trace-123-456';
      const spans = [
        {
          spanId: 'span-1',
          parentSpanId: null,
          operationName: 'http.request',
          startTime: Date.now(),
          duration: 150,
          service: 'api-gateway',
          tags: { 'http.method': 'GET', 'http.status_code': '200' }
        },
        {
          spanId: 'span-2',
          parentSpanId: 'span-1',
          operationName: 'user.authenticate',
          startTime: Date.now() + 10,
          duration: 50,
          service: 'auth-service',
          tags: { 'user.id': 'user123' }
        }
      ];

      for (const span of spans) {
        await monitoringService.recordSpan(traceId, span);
      }

      const trace = await monitoringService.getTrace(traceId);
      expect(trace).toMatchObject({
        traceId,
        spans: expect.arrayContaining([
          expect.objectContaining({
            spanId: expect.any(String),
            parentSpanId: expect.any(String),
            operationName: expect.any(String),
            startTime: expect.any(Number),
            duration: expect.any(Number),
            service: expect.any(String),
            tags: expect.any(Object)
          })
        ]),
        duration: expect.any(Number),
        serviceMap: expect.any(Object)
      });

      expect(trace.spans).toHaveLength(2);
    });

    it('should map service dependencies', async () => {
      // Record some service calls to build dependency map
      await monitoringService.recordServiceCall('api-gateway', 'user-service', 100);
      await monitoringService.recordServiceCall('user-service', 'database', 50);
      await monitoringService.recordServiceCall('api-gateway', 'order-service', 150);
      await monitoringService.recordServiceCall('order-service', 'database', 75);

      const dependencyMap = await monitoringService.getDependencyMap();

      expect(dependencyMap).toMatchObject({
        nodes: expect.arrayContaining([
          expect.objectContaining({
            id: expect.any(String),
            name: expect.any(String),
            type: expect.stringMatching(/^(service|database|external)$/),
            metrics: expect.objectContaining({
              requestCount: expect.any(Number),
              errorCount: expect.any(Number),
              averageResponseTime: expect.any(Number)
            })
          })
        ]),
        edges: expect.arrayContaining([
          expect.objectContaining({
            from: expect.any(String),
            to: expect.any(String),
            metrics: expect.objectContaining({
              callCount: expect.any(Number),
              averageResponseTime: expect.any(Number),
              errorRate: expect.any(Number)
            })
          })
        ])
      });
    });
  });

  describe('Configuration and Management', () => {
    it('should update monitoring configuration', async () => {
      const newConfig = {
        metricsRetentionDays: 60,
        alertCheckInterval: 15000,
        enableRealTimeMonitoring: false,
        logLevel: 'warn' as LogLevel,
        maxLogEntriesPerSecond: 1000
      };

      await monitoringService.updateConfiguration(newConfig);

      const currentConfig = await monitoringService.getConfiguration();
      expect(currentConfig).toMatchObject(newConfig);
    });

    it('should export monitoring data', async () => {
      // Generate test data
      await monitoringService.recordResponseTime('test-operation', 100);
      await monitoringService.createLogEntry({
        level: 'info',
        message: 'Test message',
        timestamp: new Date(),
        service: 'test-service'
      });

      const exportOptions = {
        format: 'json',
        includeMetrics: true,
        includeLogs: true,
        includeAlerts: true,
        dateRange: {
          startTime: new Date(Date.now() - 86400000),
          endTime: new Date()
        }
      };

      const exportedData = await monitoringService.exportData(exportOptions);

      expect(exportedData).toHaveProperty('metadata');
      expect(exportedData).toHaveProperty('metrics');
      expect(exportedData).toHaveProperty('logs');
      expect(exportedData).toHaveProperty('alerts');
      expect(exportedData.metadata.format).toBe('json');
    });

    it('should cleanup old monitoring data', async () => {
      // Create old data
      const oldTimestamp = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000); // 40 days ago

      await monitoringService.recordResponseTime('old-operation', 100, oldTimestamp);
      await monitoringService.createLogEntry({
        level: 'info',
        message: 'Old log entry',
        timestamp: oldTimestamp,
        service: 'old-service'
      });

      const cleanupResult = await monitoringService.cleanupOldData(30); // Keep 30 days

      expect(cleanupResult).toMatchObject({
        deletedMetrics: expect.any(Number),
        deletedLogs: expect.any(Number),
        deletedAlerts: expect.any(Number),
        freedSpace: expect.any(Number)
      });

      expect(cleanupResult.deletedMetrics).toBeGreaterThan(0);
      expect(cleanupResult.deletedLogs).toBeGreaterThan(0);
    });
  });
});