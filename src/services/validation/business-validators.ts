import { logger } from '../../utils/logger.js';
import type { BusinessValidator, ValidationResult, KnowledgeItem } from '../../types/core-interfaces.js';

/**
 * Base class for business validators with common functionality
 */
export abstract class BaseBusinessValidator implements BusinessValidator {
  protected readonly type: string;

  constructor(type: string) {
    this.type = type;
  }

  getType(): string {
    return this.type;
  }

  abstract validate(item: KnowledgeItem): Promise<ValidationResult>;

  /**
   * Create a successful validation result
   */
  protected createSuccessResult(warnings: string[] = []): ValidationResult {
    return {
      valid: true,
      errors: [],
      warnings,
    };
  }

  /**
   * Create a failed validation result
   */
  protected createFailureResult(errors: string[], warnings: string[] = []): ValidationResult {
    return {
      valid: false,
      errors,
      warnings,
    };
  }
}

/**
 * Decision validator for P5-T5.1 immutability rules
 * Implements business rules for decision immutability and status transitions
 */
export class DecisionValidator extends BaseBusinessValidator {
  constructor() {
    super('decision');
  }

  async validate(item: KnowledgeItem): Promise<ValidationResult> {
    logger.debug({ id: item.id }, 'Validating decision');

    const errors: string[] = [];
    const warnings: string[] = [];

    // Basic structural validation
    if (!item.data.title) {
      errors.push('Decision requires a title');
    }

    if (!item.data.rationale) {
      errors.push('Decision requires a rationale');
    }

    // P5-T5.1 Business Rule: Decision Immutability
    // Accepted decisions are immutable and must be superseded to modify
    const isAccepted = this.isAcceptedDecision(item);
    const isModified = this.isBeingModified(item);
    logger.debug({
      isAccepted,
      isModified,
      status: item.data.status,
      acceptanceDate: item.data.acceptance_date,
      createdAt: item.created_at || item.data.created_at,
      updatedAt: item.updated_at || item.data.updated_at
    }, 'Decision immutability check');

    if (isAccepted && isModified) {
      if (!this.hasProperSupersedeRelationship(item)) {
        errors.push('Cannot modify accepted decision - must create a new decision that supersedes this one');
      }
    }

    // P5-T5.1 Business Rule: Prevent status reversion
    // Cannot revert an accepted decision back to draft/proposed
    if (this.isRevertingAcceptedDecision(item)) {
      errors.push('Cannot revert accepted decision back to draft status - must create new decision');
    }

    if (errors.length > 0) {
      return this.createFailureResult(errors, warnings);
    }

    return this.createSuccessResult(warnings);
  }

  /**
   * Check if the decision is in accepted status
   */
  private isAcceptedDecision(item: KnowledgeItem): boolean {
    return item.data.status === 'accepted' && item.data.acceptance_date;
  }

  /**
   * Check if the decision is being modified (has updated_at later than created_at)
   */
  private isBeingModified(item: KnowledgeItem): boolean {
    // For business rule validation, prioritize data-level timestamps over top-level
    // because top-level timestamps are added by the transform layer
    const createdAt = item.data.created_at || item.created_at;
    const updatedAt = item.data.updated_at || item.updated_at;

    if (!createdAt || !updatedAt) return false;

    try {
      const createdDate = new Date(createdAt);
      const updatedDate = new Date(updatedAt);

      // Validate that both dates are valid
      if (isNaN(createdDate.getTime()) || isNaN(updatedDate.getTime())) {
        return false;
      }

      return updatedDate > createdDate;
    } catch (error) {
      return false;
    }
  }

  /**
   * Check if the decision has proper supersede relationship when being modified
   */
  private hasProperSupersedeRelationship(item: KnowledgeItem): boolean {
    // A decision being modified after acceptance should either:
    // 1. Have status 'superseded' with superseded_by pointing to new decision
    // 2. Be the new decision that supersedes an old one
    return item.data.status === 'superseded' && item.data.superseded_by;
  }

  /**
   * Check if attempting to revert an accepted decision back to draft/proposed
   */
  private isRevertingAcceptedDecision(item: KnowledgeItem): boolean {
    return (
      item.data.status === 'draft' &&
      item.data.original_status === 'accepted'
    );
  }
}

/**
 * Incident validator for P5-T5.1 severity/commander rules
 * Implements business rules for critical incident commander requirements
 */
export class IncidentValidator extends BaseBusinessValidator {
  constructor() {
    super('incident');
  }

  async validate(item: KnowledgeItem): Promise<ValidationResult> {
    logger.debug({ id: item.id }, 'Validating incident');

    const errors: string[] = [];
    const warnings: string[] = [];

    // Basic structural validation
    if (!item.data.title) {
      errors.push('Incident requires a title');
    }

    if (!item.data.severity) {
      errors.push('Incident requires a severity level');
    }

    // P5-T5.1 Business Rule: Critical incidents require commander assignment
    if (item.data.severity === 'critical') {
      if (!item.data.incident_commander) {
        errors.push('Critical incidents require assignment of incident commander');
      } else if (!this.hasCompleteCommanderInfo(item.data.incident_commander)) {
        errors.push('Critical incident commander must have complete contact information (name, role, contact)');
      }
    }

    // Additional business rule: Authorization warnings for closed incidents
    if (item.data.resolution_status === 'closed' && !item.data.reopen_authorized) {
      warnings.push('Reopening closed incidents may require authorization');
    }

    if (errors.length > 0) {
      return this.createFailureResult(errors, warnings);
    }

    return this.createSuccessResult(warnings);
  }

  /**
   * Check if incident commander has complete required information
   */
  private hasCompleteCommanderInfo(commander: any): boolean {
    return (
      commander &&
      commander.name &&
      commander.role &&
      commander.contact
    );
  }
}

/**
 * Risk validator for P5-T5.1 risk level/mitigation rules
 * Implements business rules for critical risk mitigation requirements
 */
export class RiskValidator extends BaseBusinessValidator {
  constructor() {
    super('risk');
  }

  async validate(item: KnowledgeItem): Promise<ValidationResult> {
    logger.debug({ id: item.id }, 'Validating risk');

    const errors: string[] = [];
    const warnings: string[] = [];

    // Basic structural validation
    if (!item.data.title) {
      errors.push('Risk requires a title');
    }

    if (!item.data.impact) {
      errors.push('Risk requires an impact description');
    }

    // P5-T5.1 Business Rule: Critical risks require mitigation strategies
    if (item.data.risk_level === 'critical') {
      if (!item.data.mitigation_strategies || item.data.mitigation_strategies.length === 0) {
        errors.push('Critical risks must have documented mitigation strategies');
      } else {
        // Validate that mitigation strategies have complete information
        const incompleteStrategies = item.data.mitigation_strategies.filter(
          (strategy: any) => !this.hasCompleteMitigationInfo(strategy)
        );

        if (incompleteStrategies.length > 0) {
          errors.push('Critical risk mitigation strategies must have complete information (strategy, owner, due_date, status, effectiveness)');
        }
      }
    }

    // P5-T5.1 Business Rule: Critical risk closure validation
    if (item.data.risk_level === 'critical' && item.data.status === 'closed') {
      if (!this.canCloseCriticalRisk(item)) {
        errors.push('Cannot close critical risk until all mitigation strategies are implemented and verified');
      }
    }

    // Additional business rule: Accepted risks must have owners
    if (item.data.status === 'accepted' && !item.data.owner) {
      errors.push('Accepted risks must have an assigned owner');
    }

    if (errors.length > 0) {
      return this.createFailureResult(errors, warnings);
    }

    return this.createSuccessResult(warnings);
  }

  /**
   * Check if mitigation strategy has complete required information
   */
  private hasCompleteMitigationInfo(strategy: any): boolean {
    return (
      strategy &&
      strategy.strategy &&
      strategy.owner &&
      strategy.due_date &&
      strategy.status &&
      strategy.effectiveness
    );
  }

  /**
   * Check if a critical risk can be closed
   * Requires all mitigation strategies to be completed and verified
   */
  private canCloseCriticalRisk(item: KnowledgeItem): boolean {
    if (!item.data.mitigation_strategies || item.data.mitigation_strategies.length === 0) {
      return false;
    }

    // All mitigation strategies must be completed
    const allCompleted = item.data.mitigation_strategies.every(
      (strategy: any) => strategy.status === 'completed'
    );

    // Must have closure reason and verification
    const hasClosureInfo = item.data.closure_reason &&
                          item.data.closure_verified_by &&
                          item.data.closure_date;

    return allCompleted && hasClosureInfo;
  }
}

/**
 * Todo validator for P5-T5.1 circular dependency and completion rules
 * Implements business rules for todo circular dependency detection and completion tracking
 */
export class TodoValidator extends BaseBusinessValidator {
  constructor() {
    super('todo');
  }

  async validate(item: KnowledgeItem): Promise<ValidationResult> {
    logger.debug({ id: item.id }, 'Validating todo');

    const errors: string[] = [];
    const warnings: string[] = [];

    // Basic structural validation
    if (!item.data.title) {
      errors.push('Todo requires a title');
    }

    // P5-T5.1 Business Rule: Validate todo status
    const validStatuses = ['pending', 'in_progress', 'done', 'blocked', 'cancelled'];
    if (item.data.status && !validStatuses.includes(item.data.status)) {
      errors.push(`Invalid todo status: ${item.data.status}`);
    }

    // P5-T5.1 Business Rule: Todo completion tracking
    if (item.data.status === 'done') {
      if (!item.data.completed_at) {
        // Auto-set completed_at timestamp
        item.data.completed_at = new Date().toISOString();
        warnings.push('Todo marked as done without completed_at timestamp - auto-setting current time');
      } else if (!this.isValidTimestamp(item.data.completed_at)) {
        errors.push('Completed timestamp must be a valid ISO 8601 date string');
      }
    }

    // P5-T5.1 Business Rule: Circular dependency detection
    if (item.data.dependencies && Array.isArray(item.data.dependencies)) {
      // Check for self-dependency using data.id (the todo's actual ID)
      const todoId = item.data.id || item.id;
      if (item.data.dependencies.includes(todoId)) {
        errors.push(`Self-dependency detected: ${todoId} cannot depend on itself`);
      }

      // Check for circular dependencies flagged in the data
      if (item.data.circular_dependency_detected) {
        const circularPath = item.data.circular_dependency_path || [todoId, '...', todoId];
        errors.push(`Circular dependency detected: ${circularPath.join(' -> ')}`);
      }
    }

    if (errors.length > 0) {
      return this.createFailureResult(errors, warnings);
    }

    return this.createSuccessResult(warnings);
  }

  /**
   * Check if timestamp is valid ISO 8601 format
   */
  private isValidTimestamp(timestamp: string): boolean {
    const iso8601Regex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;
    return iso8601Regex.test(timestamp) && !isNaN(Date.parse(timestamp));
  }
}

/**
 * DDL validator for P5-T5.1 checksum and migration rules
 * Implements business rules for DDL checksum requirements and migration ID uniqueness
 */
export class DDLValidator extends BaseBusinessValidator {
  constructor() {
    super('ddl');
  }

  async validate(item: KnowledgeItem): Promise<ValidationResult> {
    logger.debug({ id: item.id }, 'Validating DDL');

    const errors: string[] = [];
    const warnings: string[] = [];

    // Basic structural validation
    if (!item.data.sql) {
      errors.push('DDL requires SQL content');
    }

    if (!item.data.database) {
      errors.push('DDL requires database name');
    }

    // P5-T5.1 Business Rule: Checksum validation
    if (item.data.checksum_required) {
      if (!item.data.checksum) {
        errors.push('DDL requires checksum verification');
      } else if (!this.isValidChecksumFormat(item.data.checksum)) {
        errors.push('Invalid checksum format: must be in format "algorithm:hash"');
      }
    }

    // P5-T5.1 Business Rule: Migration ID uniqueness
    if (item.data.migration_id) {
      if (item.data.duplicate_migration_id_detected) {
        const scope = this.getScopeKey(item);
        errors.push(
          `Duplicate migration_id "${item.data.migration_id}" detected in scope "${scope}". Existing DDL ID: ${item.data.existing_ddl_id}`
        );
      }
    }

    // P5-T5.1 Business Rule: Rollback requirements
    if (item.data.rollback_required && !item.data.rollback_sql) {
      errors.push('DDL requires rollback SQL when rollback is required');
    }

    // Additional business rule: Destructive migration warnings
    if (item.data.migration_type === 'destructive' && !item.data.backup_required) {
      warnings.push('Destructive migrations should require backup');
    }

    if (errors.length > 0) {
      return this.createFailureResult(errors, warnings);
    }

    return this.createSuccessResult(warnings);
  }

  /**
   * Check if checksum has valid format (algorithm:hash)
   */
  private isValidChecksumFormat(checksum: string): boolean {
    const checksumRegex = /^[a-zA-Z0-9_-]+:[a-fA-F0-9]+$/;
    return checksumRegex.test(checksum);
  }

  /**
   * Generate scope key for migration ID uniqueness checking
   */
  private getScopeKey(item: KnowledgeItem): string {
    const project = item.scope?.project || 'default';
    const database = item.data.database || 'default';
    return `${project}:${database}`;
  }
}

/**
 * Factory function to create all business validators
 * Used to register validators with the validator registry
 */
export function createBusinessValidators(): Map<string, BusinessValidator> {
  const validators = new Map<string, BusinessValidator>();

  validators.set('decision', new DecisionValidator());
  validators.set('incident', new IncidentValidator());
  validators.set('risk', new RiskValidator());
  validators.set('todo', new TodoValidator());
  validators.set('ddl', new DDLValidator());

  return validators;
}

// Individual validator classes are already exported inline above