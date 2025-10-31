import { logger } from '../../utils/logger.js';
import type {
  BusinessValidator,
  ValidatorRegistry as IValidatorRegistry,
  ValidationResult,
  KnowledgeItem,
} from '../../types/core-interfaces.js';

/**
 * Registry for managing business rule validators
 * Provides centralized validation for different knowledge types
 */
export class ValidatorRegistry implements IValidatorRegistry {
  private validators: Map<string, BusinessValidator> = new Map();

  // Supported knowledge types for Phase 5 business rules
  private readonly supportedTypes = [
    'decision',
    'incident',
    'risk',
    'todo',
    'ddl',
  ];

  /**
   * Register a validator for a specific knowledge type
   * @param type - The knowledge type to validate
   * @param validator - The validator implementation
   * @throws Error if type is not supported
   */
  registerValidator(type: string, validator: BusinessValidator): void {
    if (!this.supportedTypes.includes(type)) {
      throw new Error(`Invalid knowledge type: ${type}. Supported types: ${this.supportedTypes.join(', ')}`);
    }

    logger.info({ type, validatorType: validator.getType() }, 'Registering business validator');
    this.validators.set(type, validator);
  }

  /**
   * Get the validator for a specific knowledge type
   * @param type - The knowledge type
   * @returns The validator or null if not registered
   */
  getValidator(type: string): BusinessValidator | null {
    return this.validators.get(type) || null;
  }

  /**
   * Get list of supported knowledge types that have registered validators
   * @returns Array of supported types
   */
  getSupportedTypes(): string[] {
    return Array.from(this.validators.keys());
  }

  /**
   * Validate a batch of knowledge items using their respective validators
   * @param items - Array of knowledge items to validate
   * @returns Array of validation results
   */
  async validateBatch(items: KnowledgeItem[]): Promise<ValidationResult[]> {
    const results: ValidationResult[] = [];

    for (const item of items) {
      const result = await this.validateItem(item);
      results.push(result);
    }

    return results;
  }

  /**
   * Validate a single knowledge item
   * @param item - The knowledge item to validate
   * @returns Validation result
   */
  private async validateItem(item: KnowledgeItem): Promise<ValidationResult> {
    const validator = this.getValidator(item.kind);

    // If no validator is registered for this type, skip validation
    if (!validator) {
      logger.debug({ kind: item.kind }, 'No validator registered, skipping business rule validation');
      return {
        valid: true,
        errors: [],
        warnings: [],
      };
    }

    try {
      logger.debug({ kind: item.kind, id: item.id }, 'Running business rule validation');
      const result = await validator.validate(item);

      if (!result.valid) {
        logger.warn({
          kind: item.kind,
          id: item.id,
          errors: result.errors,
          warnings: result.warnings
        }, 'Business rule validation failed');
      } else if (result.warnings.length > 0) {
        logger.info({
          kind: item.kind,
          id: item.id,
          warnings: result.warnings
        }, 'Business rule validation passed with warnings');
      } else {
        logger.debug({ kind: item.kind, id: item.id }, 'Business rule validation passed');
      }

      return result;
    } catch (error) {
      logger.error({
        error,
        kind: item.kind,
        id: item.id
      }, 'Business rule validation error');

      return {
        valid: false,
        errors: [error instanceof Error ? error.message : 'Unknown validation error'],
        warnings: [],
      };
    }
  }

  /**
   * Check if a knowledge type is supported for business rule validation
   * @param type - The knowledge type to check
   * @returns True if supported, false otherwise
   */
  isSupportedType(type: string): boolean {
    return this.supportedTypes.includes(type);
  }

  /**
   * Get all supported knowledge types (including those without registered validators)
   * @returns Array of all supported types
   */
  getAllSupportedTypes(): string[] {
    return [...this.supportedTypes];
  }

  /**
   * Remove a validator for a specific knowledge type
   * @param type - The knowledge type to remove validator for
   * @returns True if validator was removed, false if not found
   */
  removeValidator(type: string): boolean {
    const removed = this.validators.delete(type);
    if (removed) {
      logger.info({ type }, 'Removed business validator');
    }
    return removed;
  }

  /**
   * Clear all registered validators
   * Useful for testing or resetting the registry
   */
  clearValidators(): void {
    const count = this.validators.size;
    this.validators.clear();
    logger.info({ count }, 'Cleared all business validators');
  }

  /**
   * Get statistics about the registry
   * @returns Registry statistics
   */
  getStats(): {
    registeredValidators: number;
    supportedTypes: number;
    registeredTypes: string[];
  } {
    return {
      registeredValidators: this.validators.size,
      supportedTypes: this.supportedTypes.length,
      registeredTypes: this.getSupportedTypes(),
    };
  }
}

// Export singleton instance for application-wide use
export const validatorRegistry = new ValidatorRegistry();