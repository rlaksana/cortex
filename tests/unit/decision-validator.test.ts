import { describe, it, expect, beforeEach, vi } from 'vitest';
import { DecisionValidator } from '../../src/services/validation/business-validators';
import type { KnowledgeItem } from '../../src/types/core-interfaces';

describe('DecisionValidator - P5-T5.1 Business Rules', () => {
  let validator: DecisionValidator;

  beforeEach(() => {
    validator = new DecisionValidator();
  });

  describe('Decision Immutability Rule', () => {
    it('should REJECT when trying to modify an accepted decision without supersede', async () => {
      // Arrange: Create an accepted decision being modified
      const acceptedDecision: KnowledgeItem = {
        id: 'decision-123',
        kind: 'decision',
        content: 'Original decision content',
        data: {
          title: 'Use OAuth 2.0 for Authentication',
          rationale: 'Industry standard with broad support',
          status: 'accepted',
          // Missing superseded_by - this should cause validation failure
          acceptance_date: '2024-01-15T10:00:00Z',
        },
        metadata: { created_at: '2024-01-15T10:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-15T10:00:00Z'),
        updated_at: new Date('2024-01-20T14:30:00Z'), // Modified after acceptance
      };

      // Act: Run validation
      const result = await validator.validate(acceptedDecision);

      // Assert: Should fail validation
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Cannot modify accepted decision - must create a new decision that supersedes this one'
      );
    });

    it('should ACCEPT when modifying an accepted decision with proper supersede relationship', async () => {
      // Arrange: Create an accepted decision being superseded
      const supersededDecision: KnowledgeItem = {
        id: 'decision-123',
        kind: 'decision',
        content: 'Updated decision content',
        data: {
          title: 'Use OAuth 2.0 for Authentication - Updated',
          rationale: 'Updated rationale with security considerations',
          status: 'superseded',
          superseded_by: 'decision-456', // Proper supersede relationship
          acceptance_date: '2024-01-15T10:00:00Z',
        },
        metadata: { created_at: '2024-01-15T10:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-15T10:00:00Z'),
        updated_at: new Date('2024-01-20T14:30:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(supersededDecision);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should ACCEPT when modifying a draft decision (not accepted yet)', async () => {
      // Arrange: Create a draft decision being modified
      const draftDecision: KnowledgeItem = {
        id: 'decision-123',
        kind: 'decision',
        content: 'Draft decision content',
        data: {
          title: 'Use OAuth 2.0 for Authentication',
          rationale: 'Industry standard with broad support',
          status: 'draft', // Not accepted yet
        },
        metadata: { created_at: '2024-01-15T10:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-15T10:00:00Z'),
        updated_at: new Date('2024-01-20T14:30:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(draftDecision);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should ACCEPT when modifying a proposed decision (not accepted yet)', async () => {
      // Arrange: Create a proposed decision being modified
      const proposedDecision: KnowledgeItem = {
        id: 'decision-123',
        kind: 'decision',
        content: 'Proposed decision content',
        data: {
          title: 'Use OAuth 2.0 for Authentication',
          rationale: 'Industry standard with broad support',
          status: 'proposed', // Not accepted yet
        },
        metadata: { created_at: '2024-01-15T10:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-15T10:00:00Z'),
        updated_at: new Date('2024-01-20T14:30:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(proposedDecision);

      // Assert: Should pass validation
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should REJECT when trying to change status back from accepted to draft', async () => {
      // Arrange: Create an accepted decision trying to revert to draft
      const revertingDecision: KnowledgeItem = {
        id: 'decision-123',
        kind: 'decision',
        content: 'Reverting decision content',
        data: {
          title: 'Use OAuth 2.0 for Authentication',
          rationale: 'Trying to revert status',
          status: 'draft', // Trying to revert from accepted
          original_status: 'accepted', // Track original status
          acceptance_date: '2024-01-15T10:00:00Z',
        },
        metadata: { created_at: '2024-01-15T10:00:00Z' },
        scope: { project: 'test-project' },
        created_at: new Date('2024-01-15T10:00:00Z'),
        updated_at: new Date('2024-01-20T14:30:00Z'),
      };

      // Act: Run validation
      const result = await validator.validate(revertingDecision);

      // Assert: Should fail validation
      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Cannot revert accepted decision back to draft status - must create new decision'
      );
    });
  });

  describe('Basic Decision Validation', () => {
    it('should REJECT decision without title', async () => {
      const decisionWithoutTitle: KnowledgeItem = {
        id: 'decision-123',
        kind: 'decision',
        content: 'Decision content',
        data: {
          rationale: 'Some rationale',
          status: 'draft',
        },
        metadata: {},
        scope: {},
        created_at: new Date(),
        updated_at: new Date(),
      };

      const result = await validator.validate(decisionWithoutTitle);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Decision requires a title');
    });

    it('should REJECT decision without rationale', async () => {
      const decisionWithoutRationale: KnowledgeItem = {
        id: 'decision-123',
        kind: 'decision',
        content: 'Decision content',
        data: {
          title: 'Some decision',
          status: 'draft',
        },
        metadata: {},
        scope: {},
        created_at: new Date(),
        updated_at: new Date(),
      };

      const result = await validator.validate(decisionWithoutRationale);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Decision requires a rationale');
    });
  });
});
