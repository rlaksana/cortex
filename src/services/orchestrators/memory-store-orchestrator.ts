import { logger, withRequestLogging } from '../../utils/logger.js';
import {
  logRequestStart,
  logRequestSuccess,
  logRequestError,
  logDatabaseOperation,
  logBusinessOperation,
} from '../../utils/logging-patterns.js';
import { softDelete, type DeleteRequest } from '../delete-operations.js';
import {
  storeRunbook,
  storeChange,
  storeIssue,
  storeTodo,
  storeReleaseNote,
  storeDDL,
  storePRContext,
  storeEntity,
  storeRelation,
  addObservation,
  storeIncident,
  updateIncident,
  storeRelease,
  updateRelease,
  storeRisk,
  updateRisk,
  storeAssumption,
  updateAssumption,
} from '../knowledge/index.js';
import { storeDecision, updateDecision } from '../knowledge/decision.js';
import { storeSection } from '../knowledge/section.js';
import { violatesADRImmutability, violatesSpecWriteLock } from '../../schemas/knowledge-types.js';
import { ImmutabilityViolationError } from '../../utils/immutability.js';
import type {
  KnowledgeItem,
  StoreResult,
  StoreError,
  AutonomousContext,
  MemoryStoreResponse,
} from '../../types/core-interfaces.js';
import { validationService } from '../validation/validation-service.js';
import { auditService } from '../audit/audit-service.js';

/**
 * Orchestrator for memory store operations
 * Coordinates validation, deduplication, similarity detection, and storage
 */
export class MemoryStoreOrchestrator {
  /**
   * Main entry point for storing knowledge items
   */
  async storeItems(items: unknown[]): Promise<MemoryStoreResponse> {
    return withRequestLogging('memory.store', async () => {
      const requestLogger = logRequestStart('memory.store', { itemCount: items.length });
      const startTime = Date.now();
      const stored: StoreResult[] = [];
      const errors: StoreError[] = [];

      try {
        // Step 1: Validate input
        const validation = await validationService.validateStoreInput(items);
        if (!validation.valid) {
          return this.createErrorResponse(validation.errors);
        }

        const validItems = items as KnowledgeItem[];

        // Step 2: Process each item
        for (let index = 0; index < validItems.length; index++) {
          const item = validItems[index];

          try {
            const result = await this.processItem(item, index);
            stored.push(result);

            // Log successful operation
            await auditService.logStoreOperation(
              result.status === 'deleted'
                ? 'delete'
                : result.status === 'updated'
                  ? 'update'
                  : 'create',
              item.kind,
              result.id,
              item.scope,
              undefined,
              true
            );
          } catch (error) {
            const storeError: StoreError = {
              index,
              error_code: 'PROCESSING_ERROR',
              message: error instanceof Error ? error.message : 'Unknown processing error',
            };
            errors.push(storeError);

            // Log error
            await auditService.logError(
              error instanceof Error ? error : new Error('Unknown error'),
              {
                operation: 'store_item',
                itemIndex: index,
                itemKind: item.kind,
              }
            );
          }
        }

        // Step 3: Generate autonomous context
        const autonomousContext = await this.generateAutonomousContext(stored, errors);

        // Step 4: Log batch operation
        await auditService.logBatchOperation(
          'store',
          validItems.length,
          stored.length,
          errors.length,
          undefined,
          undefined,
          Date.now() - startTime
        );

        const response = { stored, errors, autonomous_context: autonomousContext };
        logRequestSuccess(requestLogger, 'memory.store', response);
        return response;
      } catch (error) {
        logRequestError(requestLogger, 'memory.store', error, { itemCount: items.length });

        // Log critical error
        await auditService.logError(error instanceof Error ? error : new Error('Critical error'), {
          operation: 'memory_store_batch',
          itemCount: items.length,
        });

        return this.createErrorResponse([
          {
            index: 0,
            error_code: 'BATCH_ERROR',
            message: error instanceof Error ? error.message : 'Unknown batch error',
          },
        ]);
      }
    });
  }

  /**
   * Process a single knowledge item
   */
  private async processItem(item: KnowledgeItem, index: number): Promise<StoreResult> {
    const operation = this.extractOperation(item);

    // Handle delete operations
    if (operation === 'delete') {
      return await this.handleDeleteOperation(item, index);
    }

    // Check for business rule violations
    await this.validateBusinessRules(item);

    // Store the item using appropriate service
    const result = await this.storeItemByKind(item);

    // Check for similar items and log findings
    await this.checkForSimilarItems(item);

    return result;
  }

  /**
   * Extract operation type from item
   */
  private extractOperation(item: KnowledgeItem): 'create' | 'update' | 'delete' | null {
    const data = item.data || {};

    if (data.operation === 'delete' || data.action === 'delete') {
      return 'delete';
    }

    if (item.id || data.id) {
      return 'update';
    }

    return 'create';
  }

  /**
   * Handle delete operations
   */
  private async handleDeleteOperation(item: KnowledgeItem, _index: number): Promise<StoreResult> {
    const deleteRequest: DeleteRequest = {
      entity_type: item.kind,
      entity_id: item.id || item.data?.id || '',
      cascade_relations: item.data?.cascade_relations || false,
    };

    if (!deleteRequest.entity_id) {
      throw new Error('Delete operation requires an ID');
    }

    const deleted = await softDelete(deleteRequest);

    if (!deleted) {
      throw new Error(`Failed to delete item: ${deleteRequest.entity_id}`);
    }

    return {
      id: deleteRequest.entity_id,
      status: 'deleted',
      kind: item.kind,
      created_at: new Date().toISOString(),
    };
  }

  /**
   * Validate business rules for all 16 knowledge types
   */
  private async validateBusinessRules(item: KnowledgeItem): Promise<void> {
    const operation = this.extractOperation(item);

    // Skip validation for delete operations (handled elsewhere)
    if (operation === 'delete') {
      return;
    }

    // Skip validation for create operations (no existing entity to check)
    if (operation === 'create') {
      return;
    }

    // Only perform business rule validation for update operations
    if (operation === 'update' && item.id) {
      switch (item.kind) {
        case 'decision':
          await this.validateDecisionImmutability(item.id, item);
          break;

        case 'section':
          await this.validateSectionWriteLock(item.id, item);
          break;

        case 'incident':
          await this.validateIncidentUpdateRules(item.id, item);
          break;

        case 'release':
          await this.validateReleaseUpdateRules(item.id, item);
          break;

        case 'risk':
          await this.validateRiskUpdateRules(item.id, item);
          break;

        case 'assumption':
          await this.validateAssumptionUpdateRules(item.id, item);
          break;

        case 'todo':
          await this.validateTodoUpdateRules(item.id, item);
          break;

        case 'issue':
          await this.validateIssueUpdateRules(item.id, item);
          break;

        case 'runbook':
          await this.validateRunbookUpdateRules(item.id, item);
          break;

        case 'entity':
        case 'relation':
        case 'observation':
        case 'change':
        case 'release_note':
        case 'ddl':
        case 'pr_context':
          // These types typically don't have strict business rule constraints
          logger.debug(
            { kind: item.kind, id: item.id },
            'No specific business rules for this knowledge type'
          );
          break;

        default:
          logger.warn(
            { kind: item.kind, id: item.id },
            'Unknown knowledge type for business rule validation'
          );
      }
    }
  }

  /**
   * Validate decision ADR immutability rules
   */
  private async validateDecisionImmutability(id: string, item: KnowledgeItem): Promise<void> {
    try {
      // Import and use the validation function from knowledge types
      const { violatesADRImmutability } = await import('../../schemas/knowledge-types.js');

      // Get existing decision from database
      const { getQdrantClient } = await import('../../db/qdrant.js');
      const qdrant = getQdrantClient();

      const existing = await qdrant.adrDecision.findUnique({
        where: { id },
        select: {
          id: true,
          status: true,
          component: true,
          title: true,
          rationale: true,
          alternativesConsidered: true,
          created_at: true,
        },
      });

      if (!existing) {
        return; // Decision doesn't exist, skip validation
      }

      // Create existing decision item format for validation
      const existingDecision: any = {
        kind: 'decision',
        data: {
          component: existing.component,
          status: existing.status,
          title: existing.title,
          rationale: existing.rationale,
          alternatives_considered: existing.alternativesConsidered || [],
        },
      };

      // Check immutability violation
      if (violatesADRImmutability(existingDecision, item as any)) {
        throw new ImmutabilityViolationError(
          `Cannot modify accepted ADR "${existing.title}". Create a new ADR with supersedes reference instead.`,
          'IMMUTABILITY_VIOLATION',
          'decision_content'
        );
      }
    } catch (error) {
      if (error instanceof ImmutabilityViolationError) {
        throw error;
      }
      logger.warn({ error, id, kind: 'decision' }, 'Failed to validate decision immutability');
    }
  }

  /**
   * Validate section write-lock rules for approved specifications
   */
  private async validateSectionWriteLock(id: string, item: KnowledgeItem): Promise<void> {
    try {
      const { violatesSpecWriteLock } = await import('../../schemas/knowledge-types.js');

      // Get existing section from database
      const { getQdrantClient } = await import('../../db/qdrant.js');
      const qdrant = getQdrantClient();

      const existing = await qdrant.section.findUnique({
        where: { id },
        select: {
          id: true,
          title: true,
          body_md: true,
          body_text: true,
          heading: true,
          tags: true,
          created_at: true,
        },
      });

      if (!existing) {
        return; // Section doesn't exist, skip validation
      }

      // Create existing section item format for validation
      const existingSection: any = {
        kind: 'section',
        data: {
          title: existing.title,
          body_md: existing.body_md,
          body_text: existing.body_text,
          heading: existing.heading,
        },
        tags: (existing.tags as any) || {},
      };

      // Check write-lock violation
      if (violatesSpecWriteLock(existingSection, item as any)) {
        throw new ImmutabilityViolationError(
          `Cannot modify approved specification section "${existing.title}". Content is write-locked.`,
          'SPEC_WRITE_LOCK_VIOLATION',
          'section_content'
        );
      }
    } catch (error) {
      if (error instanceof ImmutabilityViolationError) {
        throw error;
      }
      logger.warn({ error, id, kind: 'section' }, 'Failed to validate section write-lock');
    }
  }

  /**
   * Validate incident update rules (business logic for incident state transitions)
   */
  private async validateIncidentUpdateRules(id: string, item: KnowledgeItem): Promise<void> {
    try {
      const { getQdrantClient } = await import('../../db/qdrant.js');
      const qdrant = getQdrantClient();

      const existing = await qdrant.incidentLog.findUnique({
        where: { id },
        select: {
          id: true,
          resolution_status: true,
          severity: true,
          created_at: true,
        },
      });

      if (!existing) {
        return; // Incident doesn't exist, skip validation
      }

      const newStatus = item.data.resolution_status;
      const currentStatus = existing.resolution_status;

      // Business rule: Cannot reopen closed incidents without special authorization
      if (currentStatus === 'closed' && newStatus !== 'closed' && !item.data.reopen_authorized) {
        throw new ImmutabilityViolationError(
          `Cannot reopen closed incident without explicit authorization. Create new incident instead.`,
          'INCIDENT_REOPEN_VIOLATION',
          'resolution_status'
        );
      }

      // Business rule: Critical incidents require commander assignment
      if (
        existing.severity === 'critical' &&
        newStatus === 'investigating' &&
        !item.data.incident_commander
      ) {
        throw new ImmutabilityViolationError(
          `Critical incidents require assignment of incident commander before investigation.`,
          'INCIDENT_COMMANDER_REQUIRED',
          'incident_commander'
        );
      }
    } catch (error) {
      if (error instanceof ImmutabilityViolationError) {
        throw error;
      }
      logger.warn({ error, id, kind: 'incident' }, 'Failed to validate incident update rules');
    }
  }

  /**
   * Validate release update rules (business logic for release state transitions)
   */
  private async validateReleaseUpdateRules(id: string, item: KnowledgeItem): Promise<void> {
    try {
      const { getQdrantClient } = await import('../../db/qdrant.js');
      const qdrant = getQdrantClient();

      const existing = await qdrant.releaseLog.findUnique({
        where: { id },
        select: {
          id: true,
          status: true,
          version: true,
          created_at: true,
          tags: true,
        },
      });

      if (!existing) {
        return; // Release doesn't exist, skip validation
      }

      const newStatus = item.data.status;
      const currentStatus = existing.status;

      // Business rule: Cannot modify completed releases
      if (currentStatus === 'completed' && newStatus !== 'completed') {
        throw new ImmutabilityViolationError(
          `Cannot modify completed release "${existing.version}". Create new release instead.`,
          'RELEASE_MODIFICATION_VIOLATION',
          'status'
        );
      }

      // Business rule: Cannot rollback without rollback plan
      if (newStatus === 'rolled_back' && !item.data.rollback_plan) {
        throw new ImmutabilityViolationError(
          `Rollback requires explicit rollback plan to be specified.`,
          'ROLLBACK_PLAN_REQUIRED',
          'rollback_plan'
        );
      }
    } catch (error) {
      if (error instanceof ImmutabilityViolationError) {
        throw error;
      }
      logger.warn({ error, id, kind: 'release' }, 'Failed to validate release update rules');
    }
  }

  /**
   * Validate risk update rules (business logic for risk management)
   */
  private async validateRiskUpdateRules(id: string, item: KnowledgeItem): Promise<void> {
    try {
      const { getQdrantClient } = await import('../../db/qdrant.js');
      const qdrant = getQdrantClient();

      const existing = await qdrant.riskLog.findUnique({
        where: { id },
        select: {
          id: true,
          status: true,
          risk_level: true,
          created_at: true,
        },
      });

      if (!existing) {
        return; // Risk doesn't exist, skip validation
      }

      const newStatus = item.data.status;
      const currentStatus = existing.status;

      // Business rule: Cannot close critical risks without mitigation
      if (
        existing.risk_level === 'critical' &&
        newStatus === 'closed' &&
        (!item.data.mitigation_strategies || item.data.mitigation_strategies.length === 0)
      ) {
        throw new ImmutabilityViolationError(
          `Cannot close critical risks without documented mitigation strategies.`,
          'RISK_CLOSURE_VIOLATION',
          'mitigation_strategies'
        );
      }

      // Business rule: Accepted risks require owner assignment
      if (newStatus === 'accepted' && !item.data.owner) {
        throw new ImmutabilityViolationError(
          `Accepted risks must have an assigned owner.`,
          'RISK_OWNER_REQUIRED',
          'owner'
        );
      }
    } catch (error) {
      if (error instanceof ImmutabilityViolationError) {
        throw error;
      }
      logger.warn({ error, id, kind: 'risk' }, 'Failed to validate risk update rules');
    }
  }

  /**
   * Validate assumption update rules (business logic for assumption management)
   */
  private async validateAssumptionUpdateRules(id: string, item: KnowledgeItem): Promise<void> {
    try {
      const { getQdrantClient } = await import('../../db/qdrant.js');
      const qdrant = getQdrantClient();

      const existing = await qdrant.assumptionLog.findUnique({
        where: { id },
        select: {
          id: true,
          validation_status: true,
          created_at: true,
        },
      });

      if (!existing) {
        return; // Assumption doesn't exist, skip validation
      }

      const newStatus = item.data.validation_status;
      const currentStatus = existing.validation_status;

      // Business rule: Cannot validate assumptions without validation criteria
      if (
        newStatus === 'validated' &&
        (!item.data.validation_criteria || item.data.validation_criteria.length === 0)
      ) {
        throw new ImmutabilityViolationError(
          `Cannot validate assumptions without explicit validation criteria.`,
          'ASSUMPTION_VALIDATION_VIOLATION',
          'validation_criteria'
        );
      }

      // Business rule: Invalidated assumptions require impact analysis
      if (newStatus === 'invalidated' && !item.data.impact_if_invalid) {
        throw new ImmutabilityViolationError(
          `Invalidated assumptions must include impact analysis.`,
          'ASSUMPTION_IMPACT_REQUIRED',
          'impact_if_invalid'
        );
      }
    } catch (error) {
      if (error instanceof ImmutabilityViolationError) {
        throw error;
      }
      logger.warn({ error, id, kind: 'assumption' }, 'Failed to validate assumption update rules');
    }
  }

  /**
   * Validate todo update rules (business logic for task management)
   */
  private async validateTodoUpdateRules(id: string, item: KnowledgeItem): Promise<void> {
    try {
      const { getQdrantClient } = await import('../../db/qdrant.js');
      const qdrant = getQdrantClient();

      const existing = await qdrant.todoLog.findUnique({
        where: { id },
        select: {
          id: true,
          status: true,
          created_at: true,
        },
      });

      if (!existing) {
        return; // Todo doesn't exist, skip validation
      }

      const newStatus = item.data.status;
      const currentStatus = existing.status;

      // Business rule: Cannot reopen archived todos
      if (currentStatus === 'archived' && newStatus !== 'archived') {
        throw new ImmutabilityViolationError(
          `Cannot reopen archived todos. Create new todo instead.`,
          'TODO_REOPEN_VIOLATION',
          'status'
        );
      }

      // Business rule: Completed todos require closure timestamp
      if (newStatus === 'done' && !item.data.closed_at) {
        logger.warn({ id, kind: 'todo' }, 'Todo marked as done without closure timestamp');
        // Not throwing error, just warning - auto-set closed_at if not provided
        item.data.closed_at = new Date().toISOString();
      }
    } catch (error) {
      if (error instanceof ImmutabilityViolationError) {
        throw error;
      }
      logger.warn({ error, id, kind: 'todo' }, 'Failed to validate todo update rules');
    }
  }

  /**
   * Validate issue update rules (business logic for issue management)
   */
  private async validateIssueUpdateRules(id: string, item: KnowledgeItem): Promise<void> {
    try {
      const { getQdrantClient } = await import('../../db/qdrant.js');
      const qdrant = getQdrantClient();

      const existing = await qdrant.issueLog.findUnique({
        where: { id },
        select: {
          id: true,
          status: true,
          created_at: true,
        },
      });

      if (!existing) {
        return; // Issue doesn't exist, skip validation
      }

      const newStatus = item.data.status;
      const currentStatus = existing.status;

      // Business rule: Cannot reopen wont_fix issues
      if (currentStatus === 'wont_fix' && newStatus !== 'wont_fix') {
        throw new ImmutabilityViolationError(
          `Cannot reopen issues marked as wont_fix. Create new issue instead.`,
          'ISSUE_REOPEN_VIOLATION',
          'status'
        );
      }
    } catch (error) {
      if (error instanceof ImmutabilityViolationError) {
        throw error;
      }
      logger.warn({ error, id, kind: 'issue' }, 'Failed to validate issue update rules');
    }
  }

  /**
   * Validate runbook update rules (business logic for runbook management)
   */
  private async validateRunbookUpdateRules(id: string, item: KnowledgeItem): Promise<void> {
    try {
      // Runbooks are generally flexible with minimal business rules
      // Just ensure basic data integrity
      if (!item.data.steps || !Array.isArray(item.data.steps) || item.data.steps.length === 0) {
        throw new ImmutabilityViolationError(
          `Runbooks must have at least one step defined.`,
          'RUNBOOK_STEPS_REQUIRED',
          'steps'
        );
      }

      // Validate step structure
      for (const step of item.data.steps) {
        if (!step.step_number || !step.description) {
          throw new ImmutabilityViolationError(
            `Each runbook step must have step_number and description.`,
            'RUNBOOK_STEP_INVALID',
            'steps'
          );
        }
      }
    } catch (error) {
      if (error instanceof ImmutabilityViolationError) {
        throw error;
      }
      logger.warn({ error, id, kind: 'runbook' }, 'Failed to validate runbook update rules');
    }
  }

  /**
   * Store item using appropriate kind-specific service
   */
  private async storeItemByKind(item: KnowledgeItem): Promise<StoreResult> {
    const operation = this.extractOperation(item);
    const scope = item.scope || {};

    // Delete operations are handled elsewhere
    if (operation === 'delete') {
      throw new Error('Delete operations should be handled by handleDeleteOperation');
    }

    const createOrUpdateOperation: 'create' | 'update' = operation as 'create' | 'update';

    try {
      let storedId: string;
      let status: StoreResult['status'] = 'inserted';

      switch (item.kind) {
        case 'section':
          storedId = await this.storeSectionItem(item, createOrUpdateOperation);
          if (createOrUpdateOperation === 'update') status = 'updated';
          break;

        case 'decision':
          storedId = await this.storeDecisionItem(item, createOrUpdateOperation);
          if (createOrUpdateOperation === 'update') status = 'updated';
          break;

        case 'todo':
          storedId = await this.storeTodoItem(item, createOrUpdateOperation);
          if (createOrUpdateOperation === 'update') status = 'updated';
          break;

        case 'issue':
          storedId = await this.storeIssueItem(item, createOrUpdateOperation);
          if (createOrUpdateOperation === 'update') status = 'updated';
          break;

        case 'runbook':
          storedId = await this.storeRunbookItem(item, createOrUpdateOperation);
          if (createOrUpdateOperation === 'update') status = 'updated';
          break;

        case 'change':
          storedId = await this.storeChangeItem(item, createOrUpdateOperation);
          if (createOrUpdateOperation === 'update') status = 'updated';
          break;

        case 'release_note':
          storedId = await this.storeReleaseNoteItem(item, createOrUpdateOperation);
          if (createOrUpdateOperation === 'update') status = 'updated';
          break;

        case 'ddl':
          storedId = await this.storeDDLItem(item, createOrUpdateOperation);
          if (createOrUpdateOperation === 'update') status = 'updated';
          break;

        case 'pr_context':
          storedId = await this.storePRContextItem(item, createOrUpdateOperation);
          if (createOrUpdateOperation === 'update') status = 'updated';
          break;

        case 'entity':
          storedId = await this.storeEntityItem(item, createOrUpdateOperation);
          if (createOrUpdateOperation === 'update') status = 'updated';
          break;

        case 'relation':
          storedId = await this.storeRelationItem(item, createOrUpdateOperation);
          if (createOrUpdateOperation === 'update') status = 'updated';
          break;

        case 'observation':
          storedId = await this.storeObservationItem(item, createOrUpdateOperation);
          if (createOrUpdateOperation === 'update') status = 'updated';
          break;

        case 'incident':
          storedId = await this.storeIncidentItem(item, createOrUpdateOperation);
          if (createOrUpdateOperation === 'update') status = 'updated';
          break;

        case 'release':
          storedId = await this.storeReleaseItem(item, createOrUpdateOperation);
          if (createOrUpdateOperation === 'update') status = 'updated';
          break;

        case 'risk':
          storedId = await this.storeRiskItem(item, createOrUpdateOperation);
          if (createOrUpdateOperation === 'update') status = 'updated';
          break;

        case 'assumption':
          storedId = await this.storeAssumptionItem(item, createOrUpdateOperation);
          if (createOrUpdateOperation === 'update') status = 'updated';
          break;

        default:
          throw new Error(`Unknown knowledge kind: ${item.kind}`);
      }

      return {
        id: storedId,
        status,
        kind: item.kind,
        created_at: new Date().toISOString(),
      };
    } catch (error) {
      logger.error({ error, kind: item.kind, id: item.id }, 'Failed to store item by kind');
      throw error;
    }
  }

  // Individual kind-specific storage methods

  private async storeSectionItem(
    item: KnowledgeItem,
    operation: 'create' | 'update'
  ): Promise<string> {
    if (operation === 'update' && item.id) {
      // For updates, we'd need to implement updateSection function
      // For now, just create new section
      logger.warn({ id: item.id }, 'Section update not fully implemented, creating new section');
    }

    return await storeSection(item.data, item.scope);
  }

  private async storeDecisionItem(
    item: KnowledgeItem,
    operation: 'create' | 'update'
  ): Promise<string> {
    if (operation === 'update' && item.id) {
      await updateDecision(item.id, item.data as any);
      return item.id;
    }

    return await storeDecision(item.data as any, item.scope);
  }

  private async storeTodoItem(
    item: KnowledgeItem,
    operation: 'create' | 'update'
  ): Promise<string> {
    if (operation === 'update' && item.id) {
      const { updateTodo } = await import('../knowledge/todo.js');
      return await updateTodo(item.id, item.data as any, item.scope);
    }

    return await storeTodo(item.data as any, item.scope);
  }

  private async storeIssueItem(
    item: KnowledgeItem,
    operation: 'create' | 'update'
  ): Promise<string> {
    if (operation === 'update' && item.id) {
      // For updates, we'd need to implement updateIssue function
      logger.warn({ id: item.id }, 'Issue update not fully implemented, creating new issue');
    }

    return await storeIssue(item.data as any, item.scope);
  }

  private async storeRunbookItem(
    item: KnowledgeItem,
    operation: 'create' | 'update'
  ): Promise<string> {
    if (operation === 'update' && item.id) {
      // For updates, we'd need to implement updateRunbook function
      logger.warn({ id: item.id }, 'Runbook update not fully implemented, creating new runbook');
    }

    return await storeRunbook(item.data as any, item.scope);
  }

  private async storeChangeItem(
    item: KnowledgeItem,
    operation: 'create' | 'update'
  ): Promise<string> {
    if (operation === 'update' && item.id) {
      // For updates, we'd need to implement updateChange function
      logger.warn({ id: item.id }, 'Change update not fully implemented, creating new change');
    }

    return await storeChange(item.data as any, item.scope);
  }

  private async storeReleaseNoteItem(
    item: KnowledgeItem,
    operation: 'create' | 'update'
  ): Promise<string> {
    if (operation === 'update' && item.id) {
      // For updates, we'd need to implement updateReleaseNote function
      logger.warn(
        { id: item.id },
        'ReleaseNote update not fully implemented, creating new release note'
      );
    }

    return await storeReleaseNote(item.data as any, item.scope);
  }

  private async storeDDLItem(item: KnowledgeItem, operation: 'create' | 'update'): Promise<string> {
    if (operation === 'update' && item.id) {
      // For updates, we'd need to implement updateDDL function
      logger.warn({ id: item.id }, 'DDL update not fully implemented, creating new DDL');
    }

    return await storeDDL(item.data as any);
  }

  private async storePRContextItem(
    item: KnowledgeItem,
    operation: 'create' | 'update'
  ): Promise<string> {
    if (operation === 'update' && item.id) {
      // For updates, we'd need to implement updatePRContext function
      logger.warn(
        { id: item.id },
        'PRContext update not fully implemented, creating new PR context'
      );
    }

    return await storePRContext(item.data as any, item.scope);
  }

  private async storeEntityItem(
    item: KnowledgeItem,
    operation: 'create' | 'update'
  ): Promise<string> {
    // Entity service handles both create and update logic internally
    return await storeEntity(item.data as any, item.scope);
  }

  private async storeRelationItem(
    item: KnowledgeItem,
    operation: 'create' | 'update'
  ): Promise<string> {
    if (operation === 'update' && item.id) {
      // For updates, we'd need to implement updateRelation function
      logger.warn({ id: item.id }, 'Relation update not fully implemented, creating new relation');
    }

    return await storeRelation(item.data as any, item.scope);
  }

  private async storeObservationItem(
    item: KnowledgeItem,
    operation: 'create' | 'update'
  ): Promise<string> {
    if (operation === 'update' && item.id) {
      // For updates, we'd need to implement updateObservation function
      logger.warn(
        { id: item.id },
        'Observation update not fully implemented, creating new observation'
      );
    }

    return await addObservation(item.data as any, item.scope);
  }

  private async storeIncidentItem(
    item: KnowledgeItem,
    operation: 'create' | 'update'
  ): Promise<string> {
    if (operation === 'update' && item.id) {
      await updateIncident(item.id, item.data as any);
      return item.id;
    }

    return await storeIncident(item.data as any, item.scope);
  }

  private async storeReleaseItem(
    item: KnowledgeItem,
    operation: 'create' | 'update'
  ): Promise<string> {
    if (operation === 'update' && item.id) {
      await updateRelease(item.id, item.data as any);
      return item.id;
    }

    return await storeRelease(item.data as any, item.scope);
  }

  private async storeRiskItem(
    item: KnowledgeItem,
    operation: 'create' | 'update'
  ): Promise<string> {
    if (operation === 'update' && item.id) {
      await updateRisk(item.id, item.data as any);
      return item.id;
    }

    return await storeRisk(item.data as any, item.scope);
  }

  private async storeAssumptionItem(
    item: KnowledgeItem,
    operation: 'create' | 'update'
  ): Promise<string> {
    if (operation === 'update' && item.id) {
      await updateAssumption(item.id, item.data as any);
      return item.id;
    }

    return await storeAssumption(item.data as any, item.scope);
  }

  /**
   * Check for similar items and log findings
   */
  private async checkForSimilarItems(item: KnowledgeItem): Promise<void> {
    // For now, skip similarity checking since the service was removed
    // TODO: Re-implement similarity checking with proper service integration
    logger.info({ kind: item.kind }, 'Skipping similarity check (service not implemented)');
  }

  /**
   * Generate autonomous context with insights and recommendations
   */
  private async generateAutonomousContext(
    stored: StoreResult[],
    errors: StoreError[]
  ): Promise<AutonomousContext> {
    const duplicatesCount = stored.filter((s) => s.status === 'skipped_dedupe').length;
    const updatesCount = stored.filter((s) => s.status === 'updated').length;
    const createsCount = stored.filter((s) => s.status === 'inserted').length;
    const deletesCount = stored.filter((s) => s.status === 'deleted').length;

    // Determine action performed
    let actionPerformed: AutonomousContext['action_performed'] = 'batch';
    if (stored.length === 1) {
      if (createsCount === 1) actionPerformed = 'created';
      else if (updatesCount === 1) actionPerformed = 'updated';
      else if (deletesCount === 1) actionPerformed = 'deleted';
      else if (duplicatesCount === 1) actionPerformed = 'skipped';
    }

    // Generate reasoning and recommendations
    const reasoning = this.generateReasoning(stored, errors);
    const recommendation = this.generateRecommendation(stored, errors);
    const userMessage = this.generateUserMessage(actionPerformed, stored, errors);

    // Check for contradictions (simplified logic)
    const contradictionsDetected = await this.detectContradictions(stored);

    return {
      action_performed: actionPerformed,
      similar_items_checked: stored.length, // This would be enhanced with actual similarity checking
      duplicates_found: duplicatesCount,
      contradictions_detected: contradictionsDetected,
      recommendation,
      reasoning,
      user_message_suggestion: userMessage,
    };
  }

  /**
   * Generate reasoning for the operations performed
   */
  private generateReasoning(stored: StoreResult[], errors: StoreError[]): string {
    const parts: string[] = [];

    if (stored.length > 0) {
      const successful = stored.filter((s) => s.status !== 'skipped_dedupe').length;
      parts.push(`${successful} items successfully processed`);
    }

    if (errors.length > 0) {
      parts.push(`${errors.length} items failed to process`);
    }

    const duplicates = stored.filter((s) => s.status === 'skipped_dedupe').length;
    if (duplicates > 0) {
      parts.push(`${duplicates} duplicates detected and skipped`);
    }

    return parts.join('; ');
  }

  /**
   * Generate recommendations based on results
   */
  private generateRecommendation(stored: StoreResult[], errors: StoreError[]): string {
    if (errors.length > 0) {
      return 'Review and fix validation errors before retrying';
    }

    const duplicates = stored.filter((s) => s.status === 'skipped_dedupe').length;
    if (duplicates > 0) {
      return 'Consider updating existing items instead of creating duplicates';
    }

    if (stored.length === 0) {
      return 'No items were processed';
    }

    return 'Operation completed successfully';
  }

  /**
   * Generate user-friendly message
   */
  private generateUserMessage(
    action: AutonomousContext['action_performed'],
    stored: StoreResult[],
    errors: StoreError[]
  ): string {
    if (errors.length > 0) {
      return `❌ ${errors.length} error${errors.length > 1 ? 's' : ''} occurred`;
    }

    const successful = stored.filter((s) => s.status !== 'skipped_dedupe').length;
    const duplicates = stored.filter((s) => s.status === 'skipped_dedupe').length;

    switch (action) {
      case 'created':
        return successful > 0
          ? `✅ Created ${successful} item${successful > 1 ? 's' : ''}`
          : '✅ Item created';
      case 'updated':
        return successful > 0
          ? `✅ Updated ${successful} item${successful > 1 ? 's' : ''}`
          : '✅ Item updated';
      case 'deleted':
        return successful > 0
          ? `✅ Deleted ${successful} item${successful > 1 ? 's' : ''}`
          : '✅ Item deleted';
      case 'batch': {
        let message = `✅ Processed ${successful} item${successful > 1 ? 's' : ''}`;
        if (duplicates > 0) {
          message += ` (skipped ${duplicates} duplicate${duplicates > 1 ? 's' : ''})`;
        }
        return message;
      }
      default:
        return '✅ Operation completed';
    }
  }

  /**
   * Detect contradictions in stored items (simplified)
   */
  private async detectContradictions(stored: StoreResult[]): Promise<boolean> {
    // This is a simplified implementation
    // In a full system, you would check for:
    // - Contradictory decisions
    // - Conflicting observations
    // - Inconsistent data

    try {
      // Check for multiple decisions on same topic
      const decisions = stored.filter((s) => s.kind === 'decision');
      if (decisions.length > 1) {
        // Would implement actual contradiction detection logic here
        return false; // Placeholder
      }

      return false;
    } catch (error) {
      logger.warn({ error }, 'Error detecting contradictions');
      return false;
    }
  }

  /**
   * Create error response
   */
  private createErrorResponse(errors: StoreError[]): MemoryStoreResponse {
    return {
      stored: [],
      errors,
      autonomous_context: {
        action_performed: 'skipped',
        similar_items_checked: 0,
        duplicates_found: 0,
        contradictions_detected: false,
        recommendation: 'Fix validation errors before retrying',
        reasoning: 'Request failed validation',
        user_message_suggestion: '❌ Request validation failed',
      },
    };
  }
}

// Export singleton instance
export const memoryStoreOrchestrator = new MemoryStoreOrchestrator();
