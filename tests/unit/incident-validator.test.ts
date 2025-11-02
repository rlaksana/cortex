import { describe, it, expect, beforeEach, vi } from 'vitest';
import { IncidentValidator } from '../../src/services/validation/business-validators';
import type { KnowledgeItem } from '../../src/types/core-interfaces';

describe('IncidentValidator - P5-T5.1 Business Rules', () => {
  let validator: IncidentValidator;

  beforeEach(() => {
    validator = new IncidentValidator();
  });

  describe('Critical Incident Commander Rule', () => {
    it('should REJECT critical incident without incident commander assigned', async () => {
      // Arrange: Create a critical incident without commander
      const criticalIncident: KnowledgeItem = {
        id: 'incident-123',
        kind: 'incident',
        content: 'Production database is down',
        data: {
          title: 'Production Database Outage',
          severity: 'critical',
          impact: 'All services unavailable',
          timeline: {
            detected: '2024-01-20T10:00:00Z',
            last_update: '2024-01-20T10:15:00Z',
          },
          status: 'active',
          // Missing incident_commander - this should cause validation failure
        },
        metadata: { created_at: '2024-01-20T10:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T10:00:00Z'),
        updated_at: new Date('2024-01-20T10:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(criticalIncident);

      // Assert: Should fail validation
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Critical incidents require assignment of incident commander'
      );
    });

    it('should ACCEPT critical incident with incident commander assigned', async () => {
      // Arrange: Create a critical incident with proper commander assignment
      const criticalIncidentWithCommander: KnowledgeItem = {
        id: 'incident-123',
        kind: 'incident',
        content: 'Production database is down',
        data: {
          title: 'Production Database Outage',
          severity: 'critical',
          impact: 'All services unavailable',
          timeline: {
            detected: '2024-01-20T10:00:00Z',
            last_update: '2024-01-20T10:15:00Z',
          },
          status: 'active',
          incident_commander: {
            name: 'Jane Smith',
            role: 'Senior DevOps Engineer',
            contact: 'jane.smith@company.com',
            assigned_at: '2024-01-20T10:05:00Z',
          },
        },
        metadata: { created_at: '2024-01-20T10:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T10:00:00Z'),
        updated_at: new Date('2024-01-20T10:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(criticalIncidentWithCommander);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should ACCEPT high severity incident without incident commander (not critical)', async () => {
      // Arrange: Create a high severity incident (not critical) without commander
      const highSeverityIncident: KnowledgeItem = {
        id: 'incident-456',
        kind: 'incident',
        content: 'API response times elevated',
        data: {
          title: 'API Performance Degradation',
          severity: 'high', // High but not critical
          impact: 'Slower response times for users',
          timeline: {
            detected: '2024-01-20T11:00:00Z',
            last_update: '2024-01-20T11:15:00Z',
          },
          status: 'active',
          // No incident commander required for high (only critical)
        },
        metadata: { created_at: '2024-01-20T11:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T11:00:00Z'),
        updated_at: new Date('2024-01-20T11:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(highSeverityIncident);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should ACCEPT medium severity incident without incident commander', async () => {
      // Arrange: Create a medium severity incident without commander
      const mediumSeverityIncident: KnowledgeItem = {
        id: 'incident-789',
        kind: 'incident',
        content: 'Non-critical feature not working',
        data: {
          title: 'User Profile Photo Upload Failing',
          severity: 'medium',
          impact: 'Users cannot upload profile photos',
          timeline: {
            detected: '2024-01-20T12:00:00Z',
            last_update: '2024-01-20T12:10:00Z',
          },
          status: 'active',
        },
        metadata: { created_at: '2024-01-20T12:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T12:00:00Z'),
        updated_at: new Date('2024-01-20T12:10:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(mediumSeverityIncident);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should REJECT critical incident with incomplete incident commander information', async () => {
      // Arrange: Create a critical incident with incomplete commander info
      const criticalIncidentIncompleteCommander: KnowledgeItem = {
        id: 'incident-999',
        kind: 'incident',
        content: 'Security breach detected',
        data: {
          title: 'Security Breach - Unauthorized Access',
          severity: 'critical',
          impact: 'Potential data exposure',
          timeline: {
            detected: '2024-01-20T13:00:00Z',
            last_update: '2024-01-20T13:05:00Z',
          },
          status: 'active',
          incident_commander: {
            name: 'John Doe',
            // Missing role and contact information
          },
        },
        metadata: { created_at: '2024-01-20T13:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T13:00:00Z'),
        updated_at: new Date('2024-01-20T13:05:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(criticalIncidentIncompleteCommander);

      // Assert: Should fail validation
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Critical incident commander must have complete contact information (name, role, contact)'
      );
    });
  });

  describe('Basic Incident Validation', () => {
    it('should REJECT incident without title', async () => {
      const incidentWithoutTitle: KnowledgeItem = {
        id: 'incident-123',
        kind: 'incident',
        content: 'Incident content',
        data: {
          severity: 'high',
          impact: 'Some impact',
        },
        metadata: {},
        scope: {},
        created_at: new Date(),
        updated_at: new Date(),
      };

      const result = await validator.validate(incidentWithoutTitle);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Incident requires a title');
    });

    it('should REJECT incident without severity', async () => {
      const incidentWithoutSeverity: KnowledgeItem = {
        id: 'incident-123',
        kind: 'incident',
        content: 'Incident content',
        data: {
          title: 'Some incident',
          impact: 'Some impact',
        },
        metadata: {},
        scope: {},
        created_at: new Date(),
        updated_at: new Date(),
      };

      const result = await validator.validate(incidentWithoutSeverity);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Incident requires a severity level');
    });
  });
});
