import { getPool } from '../db/pool.js';
import { auditLog } from '../db/audit.js';
import { computeContentHash } from '../utils/hash.js';
import {
  violatesADRImmutability,
  violatesSpecWriteLock,
  type DecisionItem,
  type SectionItem,
} from '../schemas/knowledge-types.js';
import {
  validateKnowledgeItems,
  MemoryStoreRequestSchema,
} from '../schemas/enhanced-validation.js';
import { logger } from '../utils/logger.js';
import { sectionService, decisionService } from '../db/prisma.js';
import { ImmutabilityViolationError } from '../utils/immutability.js';
import { storeRunbook } from './knowledge/runbook.js';
import { storeChange } from './knowledge/change.js';
import { storeIssue } from './knowledge/issue.js';
import { storeDecision, updateDecision } from './knowledge/decision.js';
import { storeTodo } from './knowledge/todo.js';
import { storeReleaseNote } from './knowledge/release_note.js';
import { storeDDL } from './knowledge/ddl.js';
import { storePRContext } from './knowledge/pr_context.js';
import { storeEntity } from './knowledge/entity.js';
import { storeRelation } from './knowledge/relation.js';
import { addObservation } from './knowledge/observation.js';
import { storeIncident, storeRelease, storeRisk, storeAssumption } from './knowledge/session-logs.js';
import { softDelete, type DeleteRequest } from './delete-operations.js';
import { checkAndPurge } from './auto-purge.js';
import { findSimilar } from './similarity.js';

interface StoreResult {
  id: string;
  status: 'inserted' | 'updated' | 'skipped_dedupe' | 'deleted';
  kind: string;
  created_at: string;
}

interface StoreError {
  index: number;
  error_code: string;
  message: string;
  field?: string;
}

interface AutonomousContext {
  action_performed: 'created' | 'updated' | 'deleted' | 'skipped' | 'batch';
  similar_items_checked: number;
  duplicates_found: number;
  contradictions_detected: boolean;
  recommendation: string;
  reasoning: string;
  user_message_suggestion: string;
}

export async function memoryStore(items: unknown[]): Promise<{
  stored: StoreResult[];
  errors: StoreError[];
  autonomous_context: AutonomousContext;
}> {
  // Enhanced validation using new Zod schemas
  const requestValidation = MemoryStoreRequestSchema.safeParse({ items });
  if (!requestValidation.success) {
    const errors: StoreError[] = requestValidation.error.errors.map((error, index) => ({
      index,
      error_code: 'INVALID_REQUEST',
      message: error.message,
      field: error.path.join('.'),
    }));
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
      }
    };
  }

  // Validate individual items with comprehensive checks
  const validation = validateKnowledgeItems(items);
  if (validation.errors.length > 0) {
    const errors: StoreError[] = validation.errors.map(err => ({
      index: err.index,
      error_code: err.code as any,
      message: err.message,
      field: err.field,
    }));
    return {
      stored: [],
      errors,
      autonomous_context: {
        action_performed: 'skipped',
        similar_items_checked: 0,
        duplicates_found: 0,
        contradictions_detected: false,
        recommendation: 'Fix individual item validation errors',
        reasoning: `Found ${validation.errors.length} validation errors`,
        user_message_suggestion: `❌ ${validation.errors.length} validation errors found`,
      }
    };
  }

  const pool = getPool();

  // ✨ AUTO-MAINTENANCE: Check purge thresholds (< 1ms overhead)
  await checkAndPurge(pool, 'memory.store');

  const stored: StoreResult[] = [];
  const errors: StoreError[] = [];

  // Use validated items
  const validatedItems = validation.valid;

  // Track actions for autonomous context
  let similarItemsChecked = 0;
  let duplicatesFound = 0;
  const contradictionsDetected = false;

  for (let i = 0; i < validatedItems.length; i++) {
    try {
      // Check if this is a delete operation (special format)
      const itemAny = validatedItems[i];
      if (itemAny.operation === 'delete') {
        // Handle delete operation
        const deleteRequest: DeleteRequest = {
          entity_type: itemAny.kind || itemAny.entity_type,
          entity_id: itemAny.id || itemAny.entity_id,
          cascade_relations: itemAny.cascade_relations ?? false,
        };

        const deleteResult = await softDelete(pool, deleteRequest);

        if (deleteResult.status === 'deleted') {
          await auditLog(
            pool,
            deleteRequest.entity_type,
            deleteRequest.entity_id,
            'DELETE',
            { operation: 'soft_delete', cascade: deleteRequest.cascade_relations },
            itemAny.source?.actor
          );
          stored.push({
            id: deleteResult.id,
            status: 'updated' as any, // Use 'updated' to indicate deletion
            kind: deleteResult.entity_type,
            created_at: new Date().toISOString(),
          });
        } else {
          errors.push({
            index: i,
            error_code: deleteResult.status === 'immutable' ? 'IMMUTABLE_ENTITY' : 'NOT_FOUND',
            message:
              deleteResult.message ||
              `Failed to delete ${deleteRequest.entity_type}:${deleteRequest.entity_id}`,
          });
        }
        continue;
      }

      // Use enhanced validated item (already validated above)
      const item = validatedItems[i];
      const hash = item.idempotency_key || computeContentHash(JSON.stringify(item.data));

      if (item.kind === 'section') {
        try {
          // Check if this is an update operation
          if (item.data.id) {
            const existing = await decisionService.findDecision(item.data.id); // Using decision service temporarily

            if (existing) {
              // Convert to SectionItem format for validation
              const existingItem: SectionItem = {
                kind: 'section',
                scope: JSON.parse('{}'), // Will be updated with proper scope extraction
                data: {
                  id: existing.id,
                  title: existing.title,
                  heading: existing.title, // Will be updated when section service is complete
                  body_text: '',
                  body_md: '',
                },
                tags: {},
              };

              // Check write-lock violation
              if (violatesSpecWriteLock(existingItem, item)) {
                throw new ImmutabilityViolationError(
                  'Cannot modify approved specification content',
                  'SPEC_WRITE_LOCK',
                  'body_md'
                );
              }

              // Perform update using Prisma (type-safe)
              const updated = await sectionService.updateSection(item.data.id, {
                title: item.data.title,
                heading: item.data.heading || item.data.title,
                bodyMd: item.data.body_md,
                bodyText: item.data.body_text,
                tags: item.scope,
              });

              await auditLog(pool, 'section', updated.id, 'UPDATE', item.data, item.source?.actor);

              stored.push({
                id: updated.id,
                status: 'updated',
                kind: 'section',
                created_at: updated.createdAt.toISOString(),
              });
              continue;
            }
          }

          // Check for duplicates using Prisma
          const existingByHash = await sectionService.findByContentHash(hash);
          if (existingByHash) {
            duplicatesFound++;
            stored.push({
              id: existingByHash.id,
              status: 'skipped_dedupe',
              kind: 'section',
              created_at: existingByHash.createdAt.toISOString(),
            });
            continue;
          }

          // ✨ Check for similar content (for autonomous context)
          if (item.data.title && (item.data.body_md || item.data.body_text)) {
            const similarityResult = await findSimilar(
              pool,
              'section',
              item.data.title,
              item.data.body_md || item.data.body_text || ''
            );
            similarItemsChecked++;
            if (similarityResult.has_similar) {
              duplicatesFound += similarityResult.similar_items.length;
            }
          }

          // Create section using Prisma (type-safe - prevents schema mismatch!)
          const result = await sectionService.createSection({
            title: item.data.title,
            heading: item.data.heading || item.data.title,
            bodyMd: item.data.body_md,
            bodyText: item.data.body_text,
            tags: item.scope,
            metadata: {},
          });

          await auditLog(pool, 'section', result.id, 'INSERT', item.data, item.source?.actor);

          stored.push({
            id: result.id,
            status: 'inserted',
            kind: 'section',
            created_at: result.createdAt.toISOString(),
          });

        } catch (prismaError) {
          // Convert Prisma errors to our error format
          if (prismaError instanceof Error) {
            errors.push({
              index: i,
              error_code: 'DATABASE_ERROR',
              message: `Prisma error: ${prismaError.message}`,
            });
          } else {
            errors.push({
              index: i,
              error_code: 'DATABASE_ERROR',
              message: 'Unknown Prisma error',
            });
          }
        }
      } else if (item.kind === 'runbook') {
        const id = await storeRunbook(pool, item.data, item.scope);
        await auditLog(pool, 'runbook', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'runbook',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'change') {
        const id = await storeChange(pool, item.data, item.scope);
        await auditLog(pool, 'change_log', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'change',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'issue') {
        const id = await storeIssue(pool, item.data, item.scope);
        await auditLog(pool, 'issue_log', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'issue',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'decision') {
        // Check if this is an update operation
        if (item.data.id) {
          const existing = await pool.query('SELECT * FROM adr_decision WHERE id = $1', [
            item.data.id,
          ]);

          if (existing.rows.length > 0) {
            // Convert to DecisionItem format for validation
            const existingItem: DecisionItem = {
              kind: 'decision',
              scope: JSON.parse(existing.rows[0].tags || '{}'),
              data: {
                id: existing.rows[0].id,
                component: existing.rows[0].component,
                status: existing.rows[0].status,
                title: existing.rows[0].title,
                rationale: existing.rows[0].rationale,
                alternatives_considered: existing.rows[0].alternatives_considered,
                consequences: existing.rows[0].consequences,
                supersedes: existing.rows[0].supersedes,
              },
            };

            // Check immutability violation
            if (violatesADRImmutability(existingItem, item)) {
              throw new ImmutabilityViolationError(
                'Cannot modify accepted ADR content. Create new ADR with supersedes reference.',
                'ADR_IMMUTABLE',
                'status'
              );
            }

            // Perform update
            await updateDecision(pool, item.data.id, item.data);
            await auditLog(
              pool,
              'adr_decision',
              item.data.id,
              'UPDATE',
              item.data,
              item.source?.actor
            );

            stored.push({
              id: item.data.id,
              status: 'updated',
              kind: 'decision',
              created_at: new Date().toISOString(),
            });
            continue;
          }
        }

        // Original INSERT logic
        const id = await storeDecision(pool, item.data, item.scope);
        await auditLog(pool, 'adr_decision', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'decision',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'todo') {
        const id = await storeTodo(pool, item.data, item.scope);
        await auditLog(pool, 'todo_log', id, 'INSERT', item.data, item.source?.actor);
        stored.push({ id, status: 'inserted', kind: 'todo', created_at: new Date().toISOString() });
      } else if (item.kind === 'release_note') {
        const id = await storeReleaseNote(pool, item.data, item.scope);
        await auditLog(pool, 'release_note', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'release_note',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'ddl') {
        const id = await storeDDL(pool, item.data);
        await auditLog(pool, 'ddl_history', id, 'INSERT', item.data, item.source?.actor);
        stored.push({ id, status: 'inserted', kind: 'ddl', created_at: new Date().toISOString() });
      } else if (item.kind === 'pr_context') {
        const id = await storePRContext(pool, item.data, item.scope);
        await auditLog(pool, 'pr_context', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'pr_context',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'entity') {
        const id = await storeEntity(pool, item.data, item.scope);
        await auditLog(pool, 'knowledge_entity', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'entity',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'relation') {
        const id = await storeRelation(pool, item.data, item.scope);
        await auditLog(pool, 'knowledge_relation', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'relation',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'observation') {
        const id = await addObservation(pool, item.data, item.scope);
        await auditLog(pool, 'knowledge_observation', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'observation',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'incident') {
        const id = await storeIncident(pool, item.data, item.scope);
        await auditLog(pool, 'incident_log', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'incident',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'release') {
        const id = await storeRelease(pool, item.data, item.scope);
        await auditLog(pool, 'release_log', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'release',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'risk') {
        const id = await storeRisk(pool, item.data, item.scope);
        await auditLog(pool, 'risk_log', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'risk',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'assumption') {
        const id = await storeAssumption(pool, item.data, item.scope);
        await auditLog(pool, 'assumption_log', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'assumption',
          created_at: new Date().toISOString(),
        });
      }
    } catch (err) {
      errors.push({
        index: i,
        error_code: 'DATABASE_ERROR',
        message: (err as Error).message,
      });
    }
  }

  // Build autonomous context for Claude Code decision-making
  const autonomousContext: AutonomousContext = buildAutonomousContext(
    stored,
    errors,
    similarItemsChecked,
    duplicatesFound,
    contradictionsDetected
  );

  logger.info(
    {
      stored_count: stored.length,
      error_count: errors.length,
      action: autonomousContext.action_performed,
    },
    'memory.store completed'
  );

  return { stored, errors, autonomous_context: autonomousContext };
}

/**
 * Build autonomous context for Claude Code decision-making
 *
 * Provides guidance on what action was taken and why,
 * enabling Claude to autonomously decide next steps without prompting user.
 */
function buildAutonomousContext(
  stored: StoreResult[],
  errors: StoreError[],
  similarItemsChecked: number,
  duplicatesFound: number,
  contradictionsDetected: boolean
): AutonomousContext {
  // Determine primary action performed
  let action: AutonomousContext['action_performed'] = 'created';
  const statuses = stored.map((s) => s.status);

  if (stored.length === 0 && errors.length > 0) {
    action = 'skipped';
  } else if (stored.length > 1) {
    action = 'batch';
  } else if (statuses.includes('deleted')) {
    action = 'deleted';
  } else if (statuses.includes('updated')) {
    action = 'updated';
  } else if (statuses.includes('skipped_dedupe')) {
    action = 'skipped';
  }

  // Build reasoning
  let reasoning = '';
  if (action === 'created') {
    reasoning =
      duplicatesFound > 0
        ? `Created new item despite ${duplicatesFound} similar items found. Content was different enough.`
        : 'Created new item. No duplicates detected.';
  } else if (action === 'updated') {
    reasoning = 'Updated existing item with new information.';
  } else if (action === 'deleted') {
    reasoning = contradictionsDetected
      ? 'Deleted item that contradicted new information.'
      : 'Deleted item as requested.';
  } else if (action === 'skipped') {
    reasoning =
      duplicatesFound > 0
        ? 'Skipped operation. Exact duplicate already exists.'
        : errors.length > 0
          ? `Skipped due to errors: ${errors.map((e) => e.error_code).join(', ')}`
          : 'Skipped operation.';
  } else if (action === 'batch') {
    const created = statuses.filter((s) => s === 'inserted').length;
    const updated = statuses.filter((s) => s === 'updated').length;
    const deleted = statuses.filter((s) => s === 'deleted').length;
    const skipped = statuses.filter((s) => s === 'skipped_dedupe').length;
    reasoning = `Batch operation: ${created} created, ${updated} updated, ${deleted} deleted, ${skipped} skipped.`;
  }

  // Build recommendation for Claude Code
  let recommendation = '';
  if (action === 'created') {
    recommendation = 'Inform user: Item saved successfully.';
  } else if (action === 'updated') {
    recommendation = 'Inform user: Updated existing entry with new details.';
  } else if (action === 'deleted') {
    recommendation = contradictionsDetected
      ? 'Inform user: Removed outdated information and added new.'
      : 'Inform user: Item deleted successfully.';
  } else if (action === 'skipped') {
    recommendation =
      duplicatesFound > 0
        ? 'Inform user: Already in memory, no action needed.'
        : 'Inform user: Operation skipped due to errors.';
  } else if (action === 'batch') {
    recommendation = 'Inform user: Batch operation completed with details.';
  }

  // User message suggestion
  const userMessage =
    action === 'created' && stored.length === 1
      ? `✓ Saved ${stored[0].kind}: "${stored[0].id.substring(0, 8)}..."`
      : action === 'updated' && stored.length === 1
        ? `✓ Updated ${stored[0].kind}`
        : action === 'deleted' && stored.length === 1
          ? `✓ Deleted ${stored[0].kind}`
          : action === 'skipped'
            ? '⊘ Already in memory, skipped'
            : action === 'batch'
              ? `✓ Processed ${stored.length} items`
              : '✓ Operation completed';

  return {
    action_performed: action,
    similar_items_checked: similarItemsChecked,
    duplicates_found: duplicatesFound,
    contradictions_detected: contradictionsDetected,
    recommendation,
    reasoning,
    user_message_suggestion: userMessage,
  };
}
