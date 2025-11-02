import { describe, it, expect, beforeEach, vi } from 'vitest';
import { RiskValidator } from '../../src/services/validation/business-validators';
import type { KnowledgeItem } from '../../src/types/core-interfaces';

describe('RiskValidator - P5-T5.1 Business Rules', () => {
  let validator: RiskValidator;

  beforeEach(() => {
    validator = new RiskValidator();
  });

  describe('Critical Risk Mitigation Rule', () => {
    it('should REJECT critical risk without mitigation strategies', async () => {
      // Arrange: Create a critical risk without mitigation strategies
      const criticalRisk: KnowledgeItem = {
        id: 'risk-123',
        kind: 'risk',
        content: 'Database security vulnerability',
        data: {
          title: 'Database Security Vulnerability',
          risk_level: 'critical',
          impact: 'Potential data breach affecting all customer data',
          probability: 'high',
          category: 'security',
          status: 'active',
          // Missing mitigation_strategies - this should cause validation failure
        },
        metadata: { created_at: '2024-01-20T10:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T10:00:00Z'),
        updated_at: new Date('2024-01-20T10:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(criticalRisk);

      // Assert: Should fail validation
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Critical risks must have documented mitigation strategies');
    });

    it('should ACCEPT critical risk with comprehensive mitigation strategies', async () => {
      // Arrange: Create a critical risk with proper mitigation strategies
      const criticalRiskWithMitigation: KnowledgeItem = {
        id: 'risk-456',
        kind: 'risk',
        content: 'Database security vulnerability',
        data: {
          title: 'Database Security Vulnerability',
          risk_level: 'critical',
          impact: 'Potential data breach affecting all customer data',
          probability: 'high',
          category: 'security',
          status: 'active',
          mitigation_strategies: [
            {
              strategy: 'Implement database encryption at rest',
              owner: 'Security Team',
              due_date: '2024-02-15T00:00:00Z',
              status: 'in_progress',
              effectiveness: 'high',
            },
            {
              strategy: 'Conduct security audit and penetration testing',
              owner: 'External Security Firm',
              due_date: '2024-02-01T00:00:00Z',
              status: 'planned',
              effectiveness: 'high',
            },
          ],
        },
        metadata: { created_at: '2024-01-20T10:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T10:00:00Z'),
        updated_at: new Date('2024-01-20T10:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(criticalRiskWithMitigation);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should REJECT critical risk with empty mitigation strategies array', async () => {
      // Arrange: Create a critical risk with empty mitigation strategies
      const criticalRiskEmptyMitigation: KnowledgeItem = {
        id: 'risk-789',
        kind: 'risk',
        content: 'Server infrastructure aging',
        data: {
          title: 'Aging Server Infrastructure',
          risk_level: 'critical',
          impact: 'Complete system failure due to hardware degradation',
          probability: 'medium',
          category: 'infrastructure',
          status: 'active',
          mitigation_strategies: [], // Empty array should cause validation failure
        },
        metadata: { created_at: '2024-01-20T11:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T11:00:00Z'),
        updated_at: new Date('2024-01-20T11:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(criticalRiskEmptyMitigation);

      // Assert: Should fail validation
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Critical risks must have documented mitigation strategies');
    });

    it('should ACCEPT high risk without mitigation strategies (not critical)', async () => {
      // Arrange: Create a high risk (not critical) without mitigation strategies
      const highRisk: KnowledgeItem = {
        id: 'risk-999',
        kind: 'risk',
        content: 'Performance degradation under load',
        data: {
          title: 'Performance Degradation Under High Load',
          risk_level: 'high', // High but not critical
          impact: 'Slow response times during peak usage',
          probability: 'medium',
          category: 'performance',
          status: 'active',
          // No mitigation strategies required for high (only critical)
        },
        metadata: { created_at: '2024-01-20T12:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T12:00:00Z'),
        updated_at: new Date('2024-01-20T12:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(highRisk);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should REJECT critical risk with incomplete mitigation strategy information', async () => {
      // Arrange: Create a critical risk with incomplete mitigation strategy
      const criticalRiskIncompleteMitigation: KnowledgeItem = {
        id: 'risk-111',
        kind: 'risk',
        content: 'Data backup failure risk',
        data: {
          title: 'Data Backup System Failure',
          risk_level: 'critical',
          impact: 'Complete data loss in disaster scenario',
          probability: 'low',
          category: 'disaster_recovery',
          status: 'active',
          mitigation_strategies: [
            {
              strategy: 'Implement automated backup verification',
              // Missing owner, due_date, status, effectiveness
            },
          ],
        },
        metadata: { created_at: '2024-01-20T13:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-20T13:00:00Z'),
        updated_at: new Date('2024-01-20T13:15:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(criticalRiskIncompleteMitigation);

      // Assert: Should fail validation
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Critical risk mitigation strategies must have complete information (strategy, owner, due_date, status, effectiveness)'
      );
    });
  });

  describe('Risk Status Transition Rules', () => {
    it('should REJECT closing critical risk without verification of implemented mitigations', async () => {
      // Arrange: Create a critical risk being closed without verified mitigations
      const closingCriticalRisk: KnowledgeItem = {
        id: 'risk-222',
        kind: 'risk',
        content: 'Previously critical risk being closed',
        data: {
          title: 'Network Security Vulnerability',
          risk_level: 'critical',
          impact: 'Unauthorized network access',
          probability: 'medium',
          category: 'security',
          status: 'closed', // Trying to close
          mitigation_strategies: [
            {
              strategy: 'Install firewall updates',
              owner: 'IT Team',
              due_date: '2024-01-15T00:00:00Z',
              status: 'in_progress', // Not completed
              effectiveness: 'high',
            },
          ],
          // Missing verification of implementation
        },
        metadata: { created_at: '2024-01-10T10:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-10T10:00:00Z'),
        updated_at: new Date('2024-01-20T14:00:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(closingCriticalRisk);

      // Assert: Should fail validation
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Cannot close critical risk until all mitigation strategies are implemented and verified'
      );
    });

    it('should ACCEPT closing critical risk with verified implemented mitigations', async () => {
      // Arrange: Create a critical risk being closed with verified mitigations
      const closingCriticalRiskVerified: KnowledgeItem = {
        id: 'risk-333',
        kind: 'risk',
        content: 'Previously critical risk with verified mitigations',
        data: {
          title: 'Network Security Vulnerability',
          risk_level: 'critical',
          impact: 'Unauthorized network access',
          probability: 'low',
          category: 'security',
          status: 'closed',
          mitigation_strategies: [
            {
              strategy: 'Install firewall updates',
              owner: 'IT Team',
              due_date: '2024-01-15T00:00:00Z',
              status: 'completed', // Completed
              effectiveness: 'high',
              completed_date: '2024-01-14T16:30:00Z',
              verification: 'Security audit passed on 2024-01-15',
            },
          ],
          closure_reason: 'All mitigations implemented and verified',
          closure_verified_by: 'Security Lead',
          closure_date: '2024-01-16T09:00:00Z',
        },
        metadata: { created_at: '2024-01-10T10:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-10T10:00:00Z'),
        updated_at: new Date('2024-01-16T09:00:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(closingCriticalRiskVerified);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });

  describe('Basic Risk Validation', () => {
    it('should REJECT risk without title', async () => {
      const riskWithoutTitle: KnowledgeItem = {
        id: 'risk-123',
        kind: 'risk',
        content: 'Risk content',
        data: {
          impact: 'Some impact',
          risk_level: 'medium',
        },
        metadata: {},
        scope: {},
        created_at: new Date(),
        updated_at: new Date(),
      };

      const result = await validator.validate(riskWithoutTitle);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Risk requires a title');
    });

    it('should REJECT risk without impact description', async () => {
      const riskWithoutImpact: KnowledgeItem = {
        id: 'risk-123',
        kind: 'risk',
        content: 'Risk content',
        data: {
          title: 'Some risk',
          risk_level: 'medium',
        },
        metadata: {},
        scope: {},
        created_at: new Date(),
        updated_at: new Date(),
      };

      const result = await validator.validate(riskWithoutImpact);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Risk requires an impact description');
    });
  });
});
