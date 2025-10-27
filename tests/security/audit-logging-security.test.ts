/**
 * Audit Logging Security Tests
 *
 * Comprehensive testing for audit logging security including:
 * - Security event logging and monitoring
 * - Log integrity and tamper protection
 * - Log retention and archival policies
 * - Sensitive data redaction in logs
 * - Log access control and permissions
 * - Log backup and recovery
 * - Log aggregation and analysis
 * - Compliance and regulatory logging
 * - Security incident logging
 * - Authentication event logging
 * - Authorization event logging
 * - Data access logging
 * - System event logging
 * - Error and exception logging
 * - Performance monitoring logging
 * - Security metric collection
 * - Log forensics and investigation
 * - Log alerting and notification
 * - Log privacy and confidentiality
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { memoryStore } from '../services/memory-store.ts';
import { smartMemoryFind } from '../services/smart-find.ts';
import { validateMemoryStoreInput, validateMemoryFindInput } from '../schemas/mcp-inputs.ts';
import { logger } from '../utils/logger.ts';
import { createAuditLog, validateLogIntegrity, redactSensitiveData } from '../utils/audit-logger.ts';

describe('Audit Logging Security Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('Security Event Logging', () => {
    it('should log authentication events appropriately', async () => {
      const authEvents = [
        {
          event: 'login_success',
          userId: 'user-123',
          ip: '192.168.1.100',
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          timestamp: new Date(),
          success: true
        },
        {
          event: 'login_failure',
          userId: 'user-456',
          ip: '192.168.1.101',
          reason: 'invalid_password',
          timestamp: new Date(),
          success: false
        },
        {
          event: 'account_locked',
          userId: 'user-789',
          ip: '192.168.1.102',
          reason: 'too_many_attempts',
          timestamp: new Date(),
          success: false
        },
        {
          event: 'logout',
          userId: 'user-123',
          ip: '192.168.1.100',
          timestamp: new Date(),
          success: true
        }
      ];

      const logSpy = vi.spyOn(logger, 'info');
      const securitySpy = vi.spyOn(logger, 'warn');

      try {
        for (const event of authEvents) {
          await createAuditLog('authentication', event);
        }

        // Should log authentication events
        expect(logSpy).toHaveBeenCalledTimes(2); // Success events
        expect(securitySpy).toHaveBeenCalledTimes(2); // Failure events

        // Verify logged events contain required fields
        const loggedEvents = [...logSpy.mock.calls, ...securitySpy.mock.calls];
        for (const [logMessage, logData] of loggedEvents) {
          expect(typeof logMessage).toBe('string');
          expect(logData).toHaveProperty('event');
          expect(logData).toHaveProperty('userId');
          expect(logData).toHaveProperty('ip');
          expect(logData).toHaveProperty('timestamp');
        }

        // Should not log sensitive data like passwords
        for (const [, logData] of loggedEvents) {
          expect(logData).not.toHaveProperty('password');
          expect(logData).not.toHaveProperty('token');
          expect(logData).not.toHaveProperty('session');
        }
      } finally {
        logSpy.mockRestore();
        securitySpy.mockRestore();
      }
    });

    it('should log authorization events with proper detail', async () => {
      const authzEvents = [
        {
          event: 'access_granted',
          userId: 'user-123',
          resource: '/api/data',
          action: 'read',
          permissions: ['read'],
          timestamp: new Date()
        },
        {
          event: 'access_denied',
          userId: 'user-456',
          resource: '/api/admin',
          action: 'delete',
          requiredPermissions: ['admin'],
          userPermissions: ['read'],
          timestamp: new Date()
        },
        {
          event: 'privilege_escalation_attempt',
          userId: 'user-789',
          attemptedRole: 'admin',
          currentRole: 'user',
          timestamp: new Date()
        }
      ];

      const logSpy = vi.spyOn(logger, 'info');
      const securitySpy = vi.spyOn(logger, 'warn');

      try {
        for (const event of authzEvents) {
          await createAuditLog('authorization', event);
        }

        // Should log authorization events
        expect(logSpy).toHaveBeenCalledWith(
          expect.stringContaining('access_granted'),
          expect.objectContaining({
            event: 'access_granted',
            userId: expect.any(String),
            resource: expect.any(String),
            action: expect.any(String)
          })
        );

        expect(securitySpy).toHaveBeenCalledWith(
          expect.stringContaining('access_denied'),
          expect.objectContaining({
            event: 'access_denied',
            userId: expect.any(String),
            resource: expect.any(String),
            requiredPermissions: expect.any(Array)
          })
        );

        expect(securitySpy).toHaveBeenCalledWith(
          expect.stringContaining('privilege_escalation_attempt'),
          expect.objectContaining({
            event: 'privilege_escalation_attempt',
            userId: expect.any(String),
            attemptedRole: expect.any(String),
            currentRole: expect.any(String)
          })
        );
      } finally {
        logSpy.mockRestore();
        securitySpy.mockRestore();
      }
    });

    it('should log data access events comprehensively', async () => {
      const dataAccessEvents = [
        {
          event: 'data_read',
          userId: 'user-123',
          resource: 'memory_entity_456',
          resourceType: 'entity',
          query: 'test query',
          resultCount: 10,
          timestamp: new Date()
        },
        {
          event: 'data_write',
          userId: 'user-456',
          resource: 'memory_decision_789',
          resourceType: 'decision',
          operation: 'create',
          changes: { field: 'value' },
          timestamp: new Date()
        },
        {
          event: 'data_delete',
          userId: 'user-789',
          resource: 'memory_entity_123',
          resourceType: 'entity',
          operation: 'delete',
          reason: 'user_request',
          timestamp: new Date()
        },
        {
          event: 'bulk_operation',
          userId: 'user-123',
          resourceType: 'entity',
          operation: 'bulk_update',
          affectedRecords: 100,
          timestamp: new Date()
        }
      ];

      const logSpy = vi.spyOn(logger, 'info');

      try {
        for (const event of dataAccessEvents) {
          await createAuditLog('data_access', event);
        }

        // Verify all data access events are logged
        expect(logSpy).toHaveBeenCalledTimes(4);

        // Verify logged events contain required fields
        for (const [logMessage, logData] of logSpy.mock.calls) {
          expect(typeof logMessage).toBe('string');
          expect(logData).toHaveProperty('event');
          expect(logData).toHaveProperty('userId');
          expect(logData).toHaveProperty('resourceType');
          expect(logData).toHaveProperty('timestamp');
        }

        // Verify bulk operations are properly logged
        const bulkOperationLog = logSpy.mock.calls.find(([msg]) => msg.includes('bulk_operation'));
        expect(bulkOperationLog).toBeDefined();
        expect(bulkOperationLog![1]).toHaveProperty('affectedRecords', 100);
      } finally {
        logSpy.mockRestore();
      }
    });
  });

  describe('Log Integrity and Tamper Protection', () => {
    it('should protect logs against tampering', async () => {
      const logEntries = [
        { id: '1', event: 'login', data: { userId: 'user1' }, timestamp: new Date() },
        { id: '2', event: 'access', data: { resource: '/api/data' }, timestamp: new Date() },
        { id: '3', event: 'logout', data: { userId: 'user1' }, timestamp: new Date() }
      ];

      // Create logs with integrity protection
      const protectedLogs = [];
      for (const entry of logEntries) {
        const protectedLog = await createAuditLog('system', entry, { protectIntegrity: true });
        protectedLogs.push(protectedLog);
      }

      // Verify each log has integrity protection
      for (const log of protectedLogs) {
        expect(log).toHaveProperty('integrityHash');
        expect(log).toHaveProperty('sequenceNumber');
        expect(log.integrityHash).toMatch(/^[a-f0-9]+$/);
      }

      // Verify log chain integrity
      const isChainValid = validateLogIntegrity(protectedLogs);
      expect(isChainValid).toBe(true);

      // Simulate tampering
      const tamperedLogs = [...protectedLogs];
      tamperedLogs[1].event = 'malicious_event';

      // Should detect tampering
      const isTamperedChainValid = validateLogIntegrity(tamperedLogs);
      expect(isTamperedChainValid).toBe(false);
    });

    it('should detect log modification attempts', async () => {
      const originalLog = await createAuditLog('security', {
        event: 'login_success',
        userId: 'user-123',
        ip: '192.168.1.100',
        timestamp: new Date()
      });

      // Verify original log integrity
      expect(originalLog).toHaveProperty('integrityHash');
      const originalHash = originalLog.integrityHash;

      // Simulate log modification
      const modifiedLog = { ...originalLog, event: 'admin_access' };

      // Recalculate hash for modified log
      const modifiedHash = calculateLogHash(modifiedLog);

      // Hashes should be different
      expect(modifiedHash).not.toBe(originalHash);

      // Should detect modification
      const isOriginalValid = validateLogIntegrity([originalLog]);
      const isModifiedValid = validateLogIntegrity([modifiedLog]);

      expect(isOriginalValid).toBe(true);
      expect(isModifiedValid).toBe(false);
    });

    it('should maintain log sequence integrity', async () => {
      const logs = [];

      // Create sequential logs
      for (let i = 1; i <= 10; i++) {
        const log = await createAuditLog('system', {
          event: `event_${i}`,
          sequenceNumber: i,
          timestamp: new Date()
        });
        logs.push(log);
      }

      // Verify sequence integrity
      for (let i = 0; i < logs.length; i++) {
        expect(logs[i].sequenceNumber).toBe(i + 1);

        if (i > 0) {
          expect(logs[i].previousHash).toBe(logs[i - 1].integrityHash);
        }
      }

      // Detect missing logs (gap in sequence)
      const incompleteLogs = logs.slice(0, 5).concat(logs.slice(7)); // Remove logs 6 and 7
      const isIncompleteValid = validateLogIntegrity(incompleteLogs);
      expect(isIncompleteValid).toBe(false);

      // Detect out-of-order logs
      const reorderedLogs = [logs[0], logs[2], logs[1], ...logs.slice(3)];
      const isReorderedValid = validateLogIntegrity(reorderedLogs);
      expect(isReorderedValid).toBe(false);
    });
  });

  describe('Sensitive Data Redaction', () => {
    it('should redact sensitive information from logs', () => {
      const sensitiveData = {
        username: 'john.doe',
        email: 'john.doe@example.com',
        password: 'SuperSecret123!',
        apiKey: 'sk_live_1234567890abcdef',
        creditCard: '4111111111111111',
        ssn: '123-45-6789',
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        session: 'sess_1234567890abcdef',
        privateKey: '-----BEGIN RSA PRIVATE KEY-----\n...'
      };

      const redactedData = redactSensitiveData(sensitiveData);

      // Should redact sensitive fields
      expect(redactedData.password).toBe('[REDACTED]');
      expect(redactedData.apiKey).toBe('[REDACTED]');
      expect(redactedData.creditCard).toBe('[REDACTED]');
      expect(redactedData.ssn).toBe('[REDACTED]');
      expect(redactedData.token).toBe('[REDACTED]');
      expect(redactedData.session).toBe('[REDACTED]');
      expect(redactedData.privateKey).toBe('[REDACTED]');

      // Should preserve non-sensitive fields
      expect(redactedData.username).toBe('john.doe');
      expect(redactedData.email).toBe('john.doe@example.com');
    });

    it('should handle nested object redaction', () => {
      const nestedData = {
        user: {
          id: 'user-123',
          name: 'John Doe',
          credentials: {
            password: 'secret123',
            apiKey: 'key_abcdef123456'
          }
        },
        request: {
          headers: {
            authorization: 'Bearer token123',
            cookie: 'session=abc123'
          },
          body: {
            creditCard: '4111111111111111',
            normalField: 'normal value'
          }
        }
      };

      const redactedData = redactSensitiveData(nestedData);

      // Should redact nested sensitive fields
      expect(redactedData.user.credentials.password).toBe('[REDACTED]');
      expect(redactedData.user.credentials.apiKey).toBe('[REDACTED]');
      expect(redactedData.request.headers.authorization).toBe('[REDACTED]');
      expect(redactedData.request.headers.cookie).toBe('[REDACTED]');
      expect(redactedData.request.body.creditCard).toBe('[REDACTED]');

      // Should preserve non-sensitive nested fields
      expect(redactedData.user.id).toBe('user-123');
      expect(redactedData.user.name).toBe('John Doe');
      expect(redactedData.request.body.normalField).toBe('normal value');
    });

    it('should handle array redaction', () => {
      const arrayData = {
        users: [
          { id: 1, name: 'Alice', password: 'alice123' },
          { id: 2, name: 'Bob', password: 'bob456' }
        ],
        apiKeys: [
          { name: 'Production Key', key: 'sk_live_123456' },
          { name: 'Test Key', key: 'sk_test_789012' }
        ]
      };

      const redactedData = redactSensitiveData(arrayData);

      // Should redact sensitive fields in arrays
      expect(redactedData.users[0].password).toBe('[REDACTED]');
      expect(redactedData.users[1].password).toBe('[REDACTED]');
      expect(redactedData.apiKeys[0].key).toBe('[REDACTED]');
      expect(redactedData.apiKeys[1].key).toBe('[REDACTED]');

      // Should preserve non-sensitive fields
      expect(redactedData.users[0].name).toBe('Alice');
      expect(redactedData.apiKeys[0].name).toBe('Production Key');
    });
  });

  describe('Log Access Control', () => {
    it('should enforce log access permissions', async () => {
      const accessScenarios = [
        {
          userRole: 'admin',
          requestedAccess: 'read',
          logLevel: 'security',
          expected: true
        },
        {
          userRole: 'auditor',
          requestedAccess: 'read',
          logLevel: 'security',
          expected: true
        },
        {
          userRole: 'user',
          requestedAccess: 'read',
          logLevel: 'security',
          expected: false
        },
        {
          userRole: 'admin',
          requestedAccess: 'delete',
          logLevel: 'security',
          expected: false
        },
        {
          userRole: 'user',
          requestedAccess: 'read',
          logLevel: 'application',
          expected: true
        }
      ];

      for (const scenario of accessScenarios) {
        const hasPermission = checkLogAccessPermission(
          scenario.userRole,
          scenario.requestedAccess,
          scenario.logLevel
        );

        expect(hasPermission).toBe(scenario.expected);
      }
    });

    it('should log log access attempts', async () => {
      const logAccessSpy = vi.spyOn(logger, 'info');
      const securitySpy = vi.spyOn(logger, 'warn');

      const accessAttempts = [
        {
          userId: 'admin-123',
          action: 'access_logs',
          resource: 'security_logs',
          success: true,
          timestamp: new Date()
        },
        {
          userId: 'user-456',
          action: 'access_logs',
          resource: 'security_logs',
          success: false,
          reason: 'insufficient_permissions',
          timestamp: new Date()
        },
        {
          userId: 'auditor-789',
          action: 'export_logs',
          resource: 'audit_trail',
          success: true,
          timestamp: new Date()
        }
      ];

      try {
        for (const attempt of accessAttempts) {
          await createAuditLog('log_access', attempt);
        }

        // Should log access attempts
        expect(logAccessSpy).toHaveBeenCalledWith(
          expect.stringContaining('access_logs'),
          expect.objectContaining({
            userId: expect.any(String),
            action: expect.any(String),
            resource: expect.any(String)
          })
        );

        // Should log failed access attempts as security events
        expect(securitySpy).toHaveBeenCalledWith(
          expect.stringContaining('access_logs'),
          expect.objectContaining({
            success: false,
            reason: expect.any(String)
          })
        );
      } finally {
        logAccessSpy.mockRestore();
        securitySpy.mockRestore();
      }
    });
  });

  describe('Log Retention and Archival', () => {
    it('should implement proper log retention policies', () => {
      const retentionPolicies = {
        security_logs: 2555, // 7 years in days
        audit_logs: 2555, // 7 years in days
        access_logs: 1095, // 3 years in days
        error_logs: 365, // 1 year in days
        debug_logs: 30, // 30 days
        performance_logs: 90 // 90 days
      };

      const logTypes = Object.keys(retentionPolicies);

      for (const logType of logTypes) {
        const retentionDays = retentionPolicies[logType as keyof typeof retentionPolicies];
        const createdDate = new Date();
        createdDate.setDate(createdDate.getDate() - retentionDays - 1); // Older than retention

        const shouldArchive = shouldArchiveLog(logType, createdDate);
        expect(shouldArchive).toBe(true);

        // Recent logs should not be archived
        const recentDate = new Date();
        recentDate.setDate(recentDate.getDate() - retentionDays + 1); // Within retention
        const shouldNotArchive = shouldArchiveLog(logType, recentDate);
        expect(shouldNotArchive).toBe(false);
      }
    });

    it('should handle log archival process', async () => {
      const logsToArchive = [
        { type: 'security', created: new Date('2020-01-01'), size: 1024 },
        { type: 'audit', created: new Date('2020-01-01'), size: 2048 },
        { type: 'access', created: new Date('2022-01-01'), size: 512 }
      ];

      const archiveSpy = vi.spyOn(logger, 'info');

      try {
        // Archive logs
        for (const log of logsToArchive) {
          await archiveLog(log);
        }

        // Should log archival operations
        expect(archiveSpy).toHaveBeenCalledTimes(3);

        // Verify archival metadata
        for (const [logMessage, logData] of archiveSpy.mock.calls) {
          expect(logMessage).toContain('archived');
          expect(logData).toHaveProperty('logType');
          expect(logData).toHaveProperty('archiveDate');
          expect(logData).toHaveProperty('originalSize');
          expect(logData).toHaveProperty('archiveLocation');
        }
      } finally {
        archiveSpy.mockRestore();
      }
    });
  });

  describe('Security Incident Logging', () => {
    it('should log security incidents with proper severity', async () => {
      const securityIncidents = [
        {
          type: 'brute_force_attack',
          severity: 'high',
          sourceIp: '192.168.1.100',
          targetUser: 'admin',
          attemptCount: 100,
          duration: 300000, // 5 minutes
          timestamp: new Date()
        },
        {
          type: 'sql_injection_attempt',
          severity: 'critical',
          sourceIp: '10.0.0.1',
          payload: "'; DROP TABLE users; --",
          blocked: true,
          timestamp: new Date()
        },
        {
          type: 'privilege_escalation',
          severity: 'high',
          userId: 'user-123',
          attemptedRole: 'admin',
          currentRole: 'user',
          blocked: true,
          timestamp: new Date()
        },
        {
          type: 'data_exfiltration',
          severity: 'critical',
          userId: 'user-456',
          dataVolume: 1073741824, // 1GB
          destination: 'external-ip',
          detected: true,
          timestamp: new Date()
        }
      ];

      const criticalSpy = vi.spyOn(logger, 'error');
      const highSpy = vi.spyOn(logger, 'warn');

      try {
        for (const incident of securityIncidents) {
          await createAuditLog('security_incident', incident);
        }

        // Should log critical incidents as errors
        expect(criticalSpy).toHaveBeenCalledWith(
          expect.stringContaining('sql_injection_attempt'),
          expect.objectContaining({
            type: 'sql_injection_attempt',
            severity: 'critical',
            blocked: true
          })
        );

        expect(criticalSpy).toHaveBeenCalledWith(
          expect.stringContaining('data_exfiltration'),
          expect.objectContaining({
            type: 'data_exfiltration',
            severity: 'critical',
            detected: true
          })
        );

        // Should log high severity incidents as warnings
        expect(highSpy).toHaveBeenCalledWith(
          expect.stringContaining('brute_force_attack'),
          expect.objectContaining({
            type: 'brute_force_attack',
            severity: 'high',
            attemptCount: 100
          })
        );

        expect(highSpy).toHaveBeenCalledWith(
          expect.stringContaining('privilege_escalation'),
          expect.objectContaining({
            type: 'privilege_escalation',
            severity: 'high',
            blocked: true
          })
        );
      } finally {
        criticalSpy.mockRestore();
        highSpy.mockRestore();
      }
    });

    it('should create incident response timeline', async () => {
      const incidentTimeline = [
        {
          event: 'incident_detected',
          incidentId: 'INC-2024-001',
          type: 'unauthorized_access',
          timestamp: new Date('2024-01-01T10:00:00Z'),
          details: { sourceIp: '192.168.1.100', userId: 'attacker' }
        },
        {
          event: 'incident_triage',
          incidentId: 'INC-2024-001',
          assignedTo: 'security-team',
          severity: 'high',
          timestamp: new Date('2024-01-01T10:05:00Z')
        },
        {
          event: 'incident_contained',
          incidentId: 'INC-2024-001',
          action: 'account_suspended',
          timestamp: new Date('2024-01-01T10:15:00Z')
        },
        {
          event: 'incident_resolved',
          incidentId: 'INC-2024-001',
          resolution: 'threat_eliminated',
          timestamp: new Date('2024-01-01T11:00:00Z')
        }
      ];

      const incidentSpy = vi.spyOn(logger, 'info');

      try {
        for (const event of incidentTimeline) {
          await createAuditLog('incident_response', event);
        }

        // Should create complete incident timeline
        expect(incidentSpy).toHaveBeenCalledTimes(4);

        // Verify timeline continuity
        const loggedEvents = incidentSpy.mock calls.map(([_, data]) => data);
        const incidentIds = loggedEvents.map(event => event.incidentId);
        expect(incidentIds.every(id => id === 'INC-2024-001')).toBe(true);

        // Verify chronological order
        const timestamps = loggedEvents.map(event => new Date(event.timestamp));
        for (let i = 1; i < timestamps.length; i++) {
          expect(timestamps[i]).toBeGreaterThanOrEqual(timestamps[i - 1]);
        }
      } finally {
        incidentSpy.mockRestore();
      }
    });
  });

  describe('Compliance and Regulatory Logging', () => {
    it('should log events for regulatory compliance', async () => {
      const complianceEvents = [
        {
          regulation: 'GDPR',
          eventType: 'data_access_request',
          userId: 'user-123',
          requestData: { type: 'personal_data', scope: 'all' },
          processed: true,
          timestamp: new Date()
        },
        {
          regulation: 'SOX',
          eventType: 'financial_data_modification',
          userId: 'user-456',
          recordId: 'FIN-2024-001',
          changeType: 'adjustment',
          approved: true,
          timestamp: new Date()
        },
        {
          regulation: 'HIPAA',
          eventType: 'phi_access',
          userId: 'user-789',
          patientId: 'PAT-123456',
          accessReason: 'treatment',
          timestamp: new Date()
        },
        {
          regulation: 'PCI-DSS',
          eventType: 'card_data_processing',
          transactionId: 'TXN-123456',
          masked: true,
          compliant: true,
          timestamp: new Date()
        }
      ];

      const complianceSpy = vi.spyOn(logger, 'info');

      try {
        for (const event of complianceEvents) {
          await createAuditLog('compliance', event);
        }

        // Should log all compliance events
        expect(complianceSpy).toHaveBeenCalledTimes(4);

        // Verify required compliance fields
        for (const [logMessage, logData] of complianceSpy.mock.calls) {
          expect(logData).toHaveProperty('regulation');
          expect(logData).toHaveProperty('eventType');
          expect(logData).toHaveProperty('timestamp');
          expect(['GDPR', 'SOX', 'HIPAA', 'PCI-DSS']).toContain(logData.regulation);
        }

        // Verify GDPR specific logging
        const gdprLog = complianceSpy.mock.calls.find(([msg]) => msg.includes('data_access_request'));
        expect(gdprLog![1]).toHaveProperty('requestData');
        expect(gdprLog![1]).toHaveProperty('processed');

        // Verify PCI-DSS specific logging
        const pciLog = complianceSpy.mock.calls.find(([msg]) => msg.includes('card_data_processing'));
        expect(pciLog![1]).toHaveProperty('masked', true);
        expect(pciLog![1]).toHaveProperty('compliant', true);
      } finally {
        complianceSpy.mockRestore();
      }
    });

    it('should maintain audit trail for compliance', async () => {
      const auditTrailEvents = [
        {
          eventType: 'record_created',
          recordId: 'REC-001',
          recordType: 'financial_record',
          userId: 'user-123',
          timestamp: new Date(),
          systemGenerated: false
        },
        {
          eventType: 'record_modified',
          recordId: 'REC-001',
          changes: { amount: 1000, status: 'approved' },
          userId: 'user-456',
          previousValue: { amount: 500, status: 'pending' },
          timestamp: new Date(),
          approvalRequired: true,
          approvedBy: 'manager-789'
        },
        {
          eventType: 'record_accessed',
          recordId: 'REC-001',
          userId: 'auditor-999',
          accessReason: 'audit',
          timestamp: new Date()
        }
      ];

      const auditSpy = vi.spyOn(logger, 'info');

      try {
        for (const event of auditTrailEvents) {
          await createAuditLog('audit_trail', event);
        }

        // Should maintain complete audit trail
        expect(auditSpy).toHaveBeenCalledTimes(3);

        // Verify audit trail completeness
        const auditLogs = auditSpy.mock.calls.map(([_, data]) => data);
        const recordIds = auditLogs.map(log => log.recordId);
        expect(recordIds.every(id => id === 'REC-001')).toBe(true);

        // Verify change tracking
        const modificationLog = auditLogs.find(log => log.eventType === 'record_modified');
        expect(modificationLog).toHaveProperty('changes');
        expect(modificationLog).toHaveProperty('previousValue');
        expect(modificationLog).toHaveProperty('approvedBy');

        // Verify access logging
        const accessLog = auditLogs.find(log => log.eventType === 'record_accessed');
        expect(accessLog).toHaveProperty('accessReason', 'audit');
      } finally {
        auditSpy.mockRestore();
      }
    });
  });

  describe('Log Analysis and Monitoring', () =\> {
    it('should detect anomalous log patterns', async () => {
      const normalLogs = Array.from({ length: 100 }, (_, i) => ({
        event: 'normal_operation',
        userId: `user-${i % 10}`,
        ip: `192.168.1.${(i % 254) + 1}`,
        timestamp: new Date(Date.now() - i * 60000) // 1 minute intervals
      }));

      const anomalousLogs = [
        {
          event: 'login_failure',
          userId: 'user-123',
          ip: '192.168.1.100',
          timestamp: new Date()
        },
        {
          event: 'login_failure',
          userId: 'user-123',
          ip: '192.168.1.100',
          timestamp: new Date()
        },
        {
          event: 'login_failure',
          userId: 'user-123',
          ip: '192.168.1.100',
          timestamp: new Date()
        },
        {
          event: 'login_failure',
          userId: 'user-123',
          ip: '192.168.1.100',
          timestamp: new Date()
        },
        {
          event: 'login_failure',
          userId: 'user-123',
          ip: '192.168.1.100',
          timestamp: new Date()
        }
      ];

      const allLogs = [...normalLogs, ...anomalousLogs];
      const anomalies = detectLogAnomalies(allLogs);

      // Should detect high frequency login failures
      expect(anomalies).toContain(
        expect.objectContaining({
          type: 'high_frequency_failure',
          userId: 'user-123',
          ip: '192.168.1.100',
          count: 5
        })
      );
    });

    it('should generate security metrics from logs', async () => {
      const securityEvents = [
        { event: 'login_success', severity: 'info', timestamp: new Date() },
        { event: 'login_failure', severity: 'warning', timestamp: new Date() },
        { event: 'access_denied', severity: 'warning', timestamp: new Date() },
        { event: 'sql_injection_attempt', severity: 'critical', timestamp: new Date() },
        { event: 'privilege_escalation', severity: 'high', timestamp: new Date() },
        { event: 'data_exfiltration', severity: 'critical', timestamp: new Date() },
        { event: 'brute_force_attack', severity: 'high', timestamp: new Date() },
      ];

      const metrics = generateSecurityMetrics(securityEvents);

      // Should calculate severity distribution
      expect(metrics.severityDistribution).toEqual({
        info: 1,
        warning: 2,
        high: 2,
        critical: 2
      });

      // Should calculate risk score
      expect(metrics.riskScore).toBeGreaterThan(0);
      expect(metrics.riskScore).toBeLessThanOrEqual(100);

      // Should identify top threats
      expect(metrics.topThreats).toContain('sql_injection_attempt');
      expect(metrics.topThreats).toContain('data_exfiltration');

      // Should provide recommendations
      expect(metrics.recommendations).toBeInstanceOf(Array);
      expect(metrics.recommendations.length).toBeGreaterThan(0);
    });
  });

  describe('Log Backup and Recovery', () => {
    it('should handle log backup procedures', async () => {
      const logBackup = {
        backupId: 'BACKUP-2024-001',
        logType: 'security',
        dateRange: {
          start: new Date('2024-01-01'),
          end: new Date('2024-01-31')
        },
        recordCount: 100000,
        size: 1073741824, // 1GB
        location: 's3://secure-backups/logs/security/2024/01/',
        encrypted: true,
        checksum: 'a1b2c3d4e5f6...',
        timestamp: new Date()
      };

      const backupSpy = vi.spyOn(logger, 'info');

      try {
        await createAuditLog('log_backup', logBackup);

        // Should log backup operation
        expect(backupSpy).toHaveBeenCalledWith(
          expect.stringContaining('log_backup'),
          expect.objectContaining({
            backupId: expect.any(String),
            logType: 'security',
            encrypted: true
          })
        );

        // Should verify backup integrity
        const backupData = backupSpy.mock.calls[0][1];
        expect(backupData).toHaveProperty('checksum');
        expect(backupData).toHaveProperty('size');
        expect(backupData).toHaveProperty('recordCount');
      } finally {
        backupSpy.mockRestore();
      }
    });

    it('should handle log recovery procedures', async () => {
      const recoveryEvents = [
        {
          eventType: 'backup_restored',
          backupId: 'BACKUP-2024-001',
          reason: 'incident_investigation',
          restoredBy: 'security-admin',
          timestamp: new Date(),
          success: true
        },
        {
          eventType: 'log_verification',
          backupId: 'BACKUP-2024-001',
          checksumVerified: true,
          integrityVerified: true,
          timestamp: new Date(),
          success: true
        },
        {
          eventType: 'recovery_failed',
          backupId: 'BACKUP-2024-002',
          reason: 'corrupted_backup',
          timestamp: new Date(),
          success: false
        }
      ];

      const recoverySpy = vi.spyOn(logger, 'info');
      const errorSpy = vi.spyOn(logger, 'error');

      try {
        for (const event of recoveryEvents) {
          await createAuditLog('log_recovery', event);
        }

        // Should log successful recoveries
        expect(recoverySpy).toHaveBeenCalledWith(
          expect.stringContaining('backup_restored'),
          expect.objectContaining({
            success: true,
            restoredBy: expect.any(String)
          })
        );

        expect(recoverySpy).toHaveBeenCalledWith(
          expect.stringContaining('log_verification'),
          expect.objectContaining({
            checksumVerified: true,
            integrityVerified: true
          })
        );

        // Should log failed recoveries as errors
        expect(errorSpy).toHaveBeenCalledWith(
          expect.stringContaining('recovery_failed'),
          expect.objectContaining({
            success: false,
            reason: expect.any(String)
          })
        );
      } finally {
        recoverySpy.mockRestore();
        errorSpy.mockRestore();
      }
    });
  });

  describe('Log Privacy and Confidentiality', () => {
    it('should protect log privacy', async () => {
      const privacySensitiveLogs = [
        {
          eventType: 'personal_data_access',
          userId: 'user-123',
          personalData: {
            name: 'John Doe',
            email: 'john.doe@example.com',
            phone: '+1-555-123-4567',
            address: '123 Main St, City, State'
          },
          purpose: 'service_delivery',
          legalBasis: 'consent',
          timestamp: new Date()
        },
        {
          eventType: 'health_data_access',
          userId: 'user-456',
          healthData: {
            conditions: ['hypertension', 'diabetes'],
            medications: ['metformin', 'lisinopril'],
            visits: ['2024-01-15', '2024-02-20']
          },
          purpose: 'treatment',
          legalBasis: 'healthcare',
          timestamp: new Date()
        }
      ];

      const privacySpy = vi.spyOn(logger, 'info');

      try {
        for (const log of privacySensitiveLogs) {
          const redactedLog = redactSensitiveData(log);
          await createAuditLog('privacy_protected', redactedLog);
        }

        // Should log privacy-protected events
        expect(privacySpy).toHaveBeenCalledTimes(2);

        // Verify privacy protection in logs
        for (const [logMessage, logData] of privacySpy.mock.calls) {
          expect(logData).toHaveProperty('eventType');
          expect(logData).toHaveProperty('purpose');
          expect(logData).toHaveProperty('legalBasis');

          // Should not contain raw personal data
          expect(JSON.stringify(logData)).not.toContain('john.doe@example.com');
          expect(JSON.stringify(logData)).not.toContain('+1-555-123-4567');
          expect(JSON.stringify(logData)).not.toContain('123 Main St');
          expect(JSON.stringify(logData)).not.toContain('hypertension');
          expect(JSON.stringify(logData)).not.toContain('metformin');
        }
      } finally {
        privacySpy.mockRestore();
      }
    });

    it('should implement data minimization in logs', async () => {
      const verboseData = {
        userId: 'user-123',
        session: 'sess_abcdef1234567890abcdef1234567890',
        request: {
          headers: {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'accept': 'application/json',
            'authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
            'cookie': 'session_id=sess_abcdef; csrf_token=token123'
          },
          body: {
            username: 'john.doe',
            password: 'SuperSecret123!',
            email: 'john.doe@example.com',
            preferences: { theme: 'dark', notifications: true }
          },
          query: { search: 'test results', page: 1, limit: 10 }
        },
        response: {
          status: 200,
          data: Array.from({ length: 100 }, (_, i) => ({ id: i, value: `item-${i}` }))
        }
      };

      const minimizedLog = minimizeLogData(verboseData);

      // Should minimize data while preserving audit trail
      expect(minimizedLog).toHaveProperty('userId', 'user-123');
      expect(minimizedLog).toHaveProperty('session', '[REDACTED]');
      expect(minimizedLog).toHaveProperty('request');

      // Should redact sensitive request data
      expect(minimizedLog.request.headers.authorization).toBe('[REDACTED]');
      expect(minimizedLog.request.headers.cookie).toBe('[REDACTED]');
      expect(minimizedLog.request.body.password).toBe('[REDACTED]');

      // Should preserve non-sensitive request data
      expect(minimizedLog.request.headers['user-agent']).toContain('Mozilla');
      expect(minimizedLog.request.body.username).toBe('john.doe');

      // Should minimize response data
      expect(minimizedLog.response).toHaveProperty('status', 200);
      expect(minimizedLog.response.data).toBe('[TRUNCATED: 100 items]');
    });
  });
});

// Helper functions

function calculateLogHash(log: any): string {
  const crypto = require('crypto');
  const logString = JSON.stringify(log);
  return crypto.createHash('sha256').update(logString).digest('hex');
}

function checkLogAccessPermission(userRole: string, access: string, logLevel: string): boolean {
  const permissions = {
    admin: { read: ['all'], write: ['application'], delete: [] },
    auditor: { read: ['all'], write: [], delete: [] },
    user: { read: ['application'], write: [], delete: [] }
  };

  const userPermissions = permissions[userRole as keyof typeof permissions];
  if (!userPermissions) return false;

  return userPermissions[access as keyof typeof userPermissions].includes('all') ||
         userPermissions[access as keyof typeof userPermissions].includes(logLevel);
}

function shouldArchiveLog(logType: string, createdDate: Date): boolean {
  const now = new Date();
  const daysDiff = Math.floor((now.getTime() - createdDate.getTime()) / (1000 * 60 * 60 * 24));

  const retentionPeriods = {
    security_logs: 2555, // 7 years
    audit_logs: 2555, // 7 years
    access_logs: 1095, // 3 years
    error_logs: 365, // 1 year
    debug_logs: 30, // 30 days
    performance_logs: 90 // 90 days
  };

  const retention = retentionPeriods[logType as keyof typeof retentionPeriods] || 365;
  return daysDiff > retention;
}

async function archiveLog(log: any): Promise<void> {
  // Simulate archiving process
  const archiveLocation = `s3://secure-backups/logs/${log.type}/${log.created.toISOString().slice(0, 7)}/`;
  const checksum = calculateLogHash(log);

  await createAuditLog('log_archived', {
    originalLogId: log.id,
    archiveLocation,
    checksum,
    archivedAt: new Date(),
    originalSize: log.size
  });
}

function detectLogAnomalies(logs: any[]): any[] {
  const anomalies = [];
  const eventCounts = new Map<string, number>();

  // Count events by user and IP
  for (const log of logs) {
    const key = `${log.event}-${log.userId}-${log.ip}`;
    eventCounts.set(key, (eventCounts.get(key) || 0) + 1);
  }

  // Detect high-frequency events
  for (const [key, count] of eventCounts.entries()) {
    if (count > 3) {
      const [event, userId, ip] = key.split('-');
      anomalies.push({
        type: 'high_frequency_failure',
        event,
        userId,
        ip,
        count
      });
    }
  }

  return anomalies;
}

function generateSecurityMetrics(events: any[]): any {
  const severityDistribution = events.reduce((acc, event) => {
    acc[event.severity] = (acc[event.severity] || 0) + 1;
    return acc;
  }, {});

  const riskScore = Object.entries(severityDistribution).reduce((score, [severity, count]) => {
    const weights = { info: 1, warning: 5, high: 15, critical: 50 };
    return score + (weights[severity as keyof typeof weights] || 0) * count;
  }, 0);

  const topThreats = events
    .filter(e => e.severity === 'critical' || e.severity === 'high')
    .map(e => e.event)
    .slice(0, 5);

  const recommendations = [];
  if (severityDistribution.critical > 0) {
    recommendations.push('Immediate investigation required for critical events');
  }
  if (severityDistribution.high > 2) {
    recommendations.push('Review high-severity events for patterns');
  }

  return {
    severityDistribution,
    riskScore: Math.min(riskScore, 100),
    topThreats,
    recommendations
  };
}

function minimizeLogData(data: any): any {
  const minimized = JSON.parse(JSON.stringify(data));

  // Redact sensitive fields
  const sensitiveFields = ['password', 'token', 'session', 'authorization', 'cookie'];
  const redactSensitive = (obj: any) => {
    if (typeof obj !== 'object' || obj === null) return obj;

    for (const key in obj) {
      if (sensitiveFields.includes(key.toLowerCase())) {
        obj[key] = '[REDACTED]';
      } else if (typeof obj[key] === 'object') {
        redactSensitive(obj[key]);
      }
    }
    return obj;
  };

  redactSensitive(minimized);

  // Truncate large arrays
  if (minimized.response?.data && Array.isArray(minimized.response.data)) {
    minimized.response.data = `[TRUNCATED: ${minimized.response.data.length} items]`;
  }

  return minimized;
}