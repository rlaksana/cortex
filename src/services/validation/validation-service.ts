import { logger } from '../../utils/logger.js';
import type {
  ValidationService as IValidationService,
  KnowledgeItem,
  StoreError,
} from '../../types/core-interfaces.js';
import {
  MemoryStoreRequestSchema,
  MemoryFindRequestSchema,
  validateKnowledgeItems,
} from '../../schemas/enhanced-validation.js';

/**
 * Validation service for input validation and business rule enforcement
 */
export class ValidationService implements IValidationService {
  /**
   * Validate store input using Zod schema
   */
  async validateStoreInput(items: unknown[]): Promise<{ valid: boolean; errors: StoreError[] }> {
    try {
      const requestValidation = MemoryStoreRequestSchema.safeParse({ items });

      if (!requestValidation.success) {
        const errors: StoreError[] = requestValidation.error.errors.map((error, index) => ({
          index,
          error_code: 'INVALID_REQUEST',
          message: error.message,
          field: error.path.join('.'),
        }));

        logger.warn({ errors }, 'Store input validation failed');
        return { valid: false, errors };
      }

      // Additional validation for knowledge items
      const itemValidation = validateKnowledgeItems(requestValidation.data.items);
      if (itemValidation.valid.length === 0 && itemValidation.errors.length > 0) {
        const errors: StoreError[] = itemValidation.errors.map((error, index) => ({
          index,
          error_code: 'INVALID_ITEM',
          message: error.message,
          field: error.field,
        }));

        logger.warn({ errors }, 'Knowledge item validation failed');
        return { valid: false, errors };
      }

      return { valid: true, errors: [] };
    } catch (error) {
      logger.error({ error }, 'Validation service error');
      return {
        valid: false,
        errors: [
          {
            index: 0,
            error_code: 'VALIDATION_ERROR',
            message: error instanceof Error ? error.message : 'Unknown validation error',
          },
        ],
      };
    }
  }

  /**
   * Validate find input using Zod schema
   */
  async validateFindInput(input: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const requestValidation = MemoryFindRequestSchema.safeParse(input);

      if (!requestValidation.success) {
        const errors = requestValidation.error.errors.map((error) => error.message);
        logger.warn({ errors }, 'Find input validation failed');
        return { valid: false, errors };
      }

      return { valid: true, errors: [] };
    } catch (error) {
      logger.error({ error }, 'Find validation service error');
      return {
        valid: false,
        errors: [error instanceof Error ? error.message : 'Unknown validation error'],
      };
    }
  }

  /**
   * Validate individual knowledge item
   */
  async validateKnowledgeItem(item: KnowledgeItem): Promise<{ valid: boolean; errors: string[] }> {
    const errors: string[] = [];

    // Validate required fields
    if (!item.kind) {
      errors.push('Kind is required');
    }

    if (!item.scope) {
      errors.push('Scope is required');
    } else {
      if (!item.scope.project && !item.scope.org) {
        errors.push('Scope must have either project or org');
      }
    }

    if (!item.data || typeof item.data !== 'object') {
      errors.push('Data is required and must be an object');
    }

    // Validate kind is one of allowed values
    const allowedKinds = [
      'section',
      'decision',
      'issue',
      'todo',
      'runbook',
      'change',
      'release_note',
      'ddl',
      'pr_context',
      'entity',
      'relation',
      'observation',
      'incident',
      'release',
      'risk',
      'assumption',
    ];

    if (item.kind && !allowedKinds.includes(item.kind)) {
      errors.push(`Invalid kind: ${item.kind}. Must be one of: ${allowedKinds.join(', ')}`);
    }

    // Validate data structure based on kind
    if (item.kind && item.data) {
      const kindValidation = await this.validateKindSpecificData(item.kind, item.data);
      if (!kindValidation.valid) {
        errors.push(...kindValidation.errors);
      }
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Validate kind-specific data requirements
   */
  private async validateKindSpecificData(
    kind: string,
    data: Record<string, any>
  ): Promise<{ valid: boolean; errors: string[] }> {
    const errors: string[] = [];

    switch (kind) {
      case 'decision':
        if (!data.title) errors.push('Decision requires title');
        if (!data.rationale) errors.push('Decision requires rationale');
        break;

      case 'issue':
        if (!data.title) errors.push('Issue requires title');
        if (!data.description) errors.push('Issue requires description');
        break;

      case 'todo':
        if (!data.title) errors.push('Todo requires title');
        break;

      case 'runbook':
        if (!data.title) errors.push('Runbook requires title');
        if (!data.steps || !Array.isArray(data.steps)) errors.push('Runbook requires steps array');
        break;

      case 'entity':
        if (!data.name) errors.push('Entity requires name');
        if (!data.type) errors.push('Entity requires type');
        break;

      case 'relation':
        if (!data.source) errors.push('Relation requires source');
        if (!data.target) errors.push('Relation requires target');
        if (!data.type) errors.push('Relation requires type');
        break;

      case 'observation':
        if (!data.content) errors.push('Observation requires content');
        break;

      case 'incident':
        if (!data.title) errors.push('Incident requires title');
        if (!data.severity) errors.push('Incident requires severity');
        break;

      case 'release':
        if (!data.version) errors.push('Release requires version');
        if (!data.scope) errors.push('Release requires scope');
        break;

      case 'risk':
        if (!data.title) errors.push('Risk requires title');
        if (!data.impact) errors.push('Risk requires impact');
        break;

      case 'assumption':
        if (!data.title) errors.push('Assumption requires title');
        if (!data.description) errors.push('Assumption requires description');
        break;
    }

    return { valid: errors.length === 0, errors };
  }
}

// Export singleton instance
export const validationService = new ValidationService();
