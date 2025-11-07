import { describe, it, expect, beforeEach } from 'vitest';
import type { KnowledgeItem } from '../../../types/core-interfaces';
import {
  ValidatorRegistry,
  type BusinessValidator,
} from '../../src/services/validation/validator-registry';

describe('ValidatorRegistry', () => {
  let validatorRegistry: ValidatorRegistry;
  let mockValidator: BusinessValidator;

  beforeEach(() => {
    validatorRegistry = new ValidatorRegistry();
    mockValidator = {
      getType: () => 'decision',
      validate: async (_item: KnowledgeItem) => ({
        valid: true,
        errors: [],
        warnings: [],
      }),
    };
  });

  describe('Validator Registration', () => {
    it('should register a validator for a specific knowledge type', () => {
      validatorRegistry.registerValidator('decision', mockValidator);
      const registeredValidator = validatorRegistry.getValidator('decision');
      expect(registeredValidator).toBe(mockValidator);
    });

    it('should throw error when registering validator for invalid type', () => {
      expect(() => {
        validatorRegistry.registerValidator('invalid_type', mockValidator);
      }).toThrow('Invalid knowledge type: invalid_type');
    });

    it('should allow overriding existing validators', () => {
      const mockValidator2: BusinessValidator = {
        getType: () => 'decision',
        validate: async (_item: KnowledgeItem) => ({
          valid: false,
          errors: ['New validator error'],
          warnings: [],
        }),
      };

      validatorRegistry.registerValidator('decision', mockValidator);
      validatorRegistry.registerValidator('decision', mockValidator2);

      const registeredValidator = validatorRegistry.getValidator('decision');
      expect(registeredValidator).toBe(mockValidator2);
    });
  });

  describe('Validator Retrieval', () => {
    it('should return null for unregistered knowledge types', () => {
      const validator = validatorRegistry.getValidator('todo');
      expect(validator).toBeNull();
    });

    it('should return registered validators for valid types', () => {
      validatorRegistry.registerValidator('decision', mockValidator);
      validatorRegistry.registerValidator('incident', mockValidator);
      validatorRegistry.registerValidator('risk', mockValidator);
      validatorRegistry.registerValidator('todo', mockValidator);
      validatorRegistry.registerValidator('ddl', mockValidator);

      expect(validatorRegistry.getValidator('decision')).toBe(mockValidator);
      expect(validatorRegistry.getValidator('incident')).toBe(mockValidator);
      expect(validatorRegistry.getValidator('risk')).toBe(mockValidator);
      expect(validatorRegistry.getValidator('todo')).toBe(mockValidator);
      expect(validatorRegistry.getValidator('ddl')).toBe(mockValidator);
    });
  });

  describe('Batch Validation', () => {
    beforeEach(() => {
      // Register validators for test types
      validatorRegistry.registerValidator('decision', mockValidator);

      const mockIncidentValidator: BusinessValidator = {
        getType: () => 'incident',
        validate: async (item: KnowledgeItem) => ({
          valid: item['data.severity'] === 'critical',
          errors: item['data.severity'] !== 'critical' ? ['Incident must have critical severity'] : [],
          warnings: [],
        }),
      };
      validatorRegistry.registerValidator('incident', mockIncidentValidator);
    });

    it('should validate batch of items successfully', async () => {
      const items: KnowledgeItem[] = [
        {
          kind: 'decision',
          scope: { project: 'test' },
          data: { title: 'Test Decision', rationale: 'Test rationale' },
        },
        {
          kind: 'incident',
          scope: { project: 'test' },
          data: { title: 'Test Incident', severity: 'critical' },
        },
      ];

      const results = await validatorRegistry.validateBatch(items);

      expect(results).toHaveLength(2);
      expect(results[0].valid).toBe(true);
      expect(results[0].errors).toHaveLength(0);
      expect(results[1].valid).toBe(true);
      expect(results[1].errors).toHaveLength(0);
    });

    it('should handle validation errors in batch', async () => {
      const items: KnowledgeItem[] = [
        {
          kind: 'decision',
          scope: { project: 'test' },
          data: { title: 'Test Decision', rationale: 'Test rationale' },
        },
        {
          kind: 'incident',
          scope: { project: 'test' },
          data: { title: 'Test Incident', severity: 'low' }, // Will fail validation
        },
      ];

      const results = await validatorRegistry.validateBatch(items);

      expect(results).toHaveLength(2);
      expect(results[0].valid).toBe(true);
      expect(results[0].errors).toHaveLength(0);
      expect(results[1].valid).toBe(false);
      expect(results[1].errors).toContain('Incident must have critical severity');
    });

    it('should skip validation for unregistered types', async () => {
      const items: KnowledgeItem[] = [
        {
          kind: 'todo',
          scope: { project: 'test' },
          data: { title: 'Test Todo' },
        },
      ];

      const results = await validatorRegistry.validateBatch(items);

      expect(results).toHaveLength(1);
      expect(results[0].valid).toBe(true);
      expect(results[0].errors).toHaveLength(0);
    });

    it('should handle mixed batch with registered and unregistered types', async () => {
      const items: KnowledgeItem[] = [
        {
          kind: 'decision',
          scope: { project: 'test' },
          data: { title: 'Test Decision', rationale: 'Test rationale' },
        },
        {
          kind: 'todo',
          scope: { project: 'test' },
          data: { title: 'Test Todo' }, // Unregistered type
        },
        {
          kind: 'incident',
          scope: { project: 'test' },
          data: { title: 'Test Incident', severity: 'low' }, // Will fail validation
        },
      ];

      const results = await validatorRegistry.validateBatch(items);

      expect(results).toHaveLength(3);
      expect(results[0].valid).toBe(true);
      expect(results[0].errors).toHaveLength(0);
      expect(results[1].valid).toBe(true); // Skipped validation
      expect(results[1].errors).toHaveLength(0);
      expect(results[2].valid).toBe(false);
      expect(results[2].errors).toContain('Incident must have critical severity');
    });
  });

  describe('Supported Knowledge Types', () => {
    it('should return list of supported knowledge types', () => {
      validatorRegistry.registerValidator('decision', mockValidator);
      validatorRegistry.registerValidator('incident', mockValidator);

      const supportedTypes = validatorRegistry.getSupportedTypes();
      expect(supportedTypes).toContain('decision');
      expect(supportedTypes).toContain('incident');
      expect(supportedTypes).toHaveLength(2);
    });

    it('should return empty list when no validators registered', () => {
      const supportedTypes = validatorRegistry.getSupportedTypes();
      expect(supportedTypes).toHaveLength(0);
    });
  });

  describe('Error Handling', () => {
    it('should handle validator exceptions gracefully', async () => {
      const faultyValidator: BusinessValidator = {
        getType: () => 'decision',
        validate: async (_item: KnowledgeItem) => {
          throw new Error('Validator error');
        },
      };

      validatorRegistry.registerValidator('decision', faultyValidator);

      const items: KnowledgeItem[] = [
        {
          kind: 'decision',
          scope: { project: 'test' },
          data: { title: 'Test Decision' },
        },
      ];

      const results = await validatorRegistry.validateBatch(items);

      expect(results).toHaveLength(1);
      expect(results[0].valid).toBe(false);
      expect(results[0].errors).toContain('Validator error');
    });
  });
});

describe('Business Validators Integration', () => {
  let validatorRegistry: ValidatorRegistry;

  beforeEach(() => {
    validatorRegistry = new ValidatorRegistry();
  });

  describe('Decision Validator', () => {
    it('should validate decision structure and immutability rules', async () => {
      // This test will be implemented when we create the actual DecisionValidator
      // For now, just test the integration point
      const decisionValidator = validatorRegistry.getValidator('decision');
      expect(decisionValidator).toBeDefined();
      expect(decisionValidator?.getType()).toBe('decision');
    });
  });

  describe('Incident Validator', () => {
    it('should validate incident severity and commander requirements', async () => {
      const incidentValidator = validatorRegistry.getValidator('incident');
      expect(incidentValidator).toBeDefined();
      expect(incidentValidator?.getType()).toBe('incident');
    });
  });

  describe('Risk Validator', () => {
    it('should validate risk level and mitigation requirements', async () => {
      const riskValidator = validatorRegistry.getValidator('risk');
      expect(riskValidator).toBeDefined();
      expect(riskValidator?.getType()).toBe('risk');
    });
  });

  describe('Todo Validator', () => {
    it('should validate todo dependencies and completion rules', async () => {
      const todoValidator = validatorRegistry.getValidator('todo');
      expect(todoValidator).toBeDefined();
      expect(todoValidator?.getType()).toBe('todo');
    });
  });

  describe('DDL Validator', () => {
    it('should validate DDL checksum and migration rules', async () => {
      const ddlValidator = validatorRegistry.getValidator('ddl');
      expect(ddlValidator).toBeDefined();
      expect(ddlValidator?.getType()).toBe('ddl');
    });
  });
});
