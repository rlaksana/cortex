import { getPool } from '../db/pool.js';
import { auditLog } from '../db/audit.js';
import { computeContentHash } from '../utils/hash.js';
import {
  KnowledgeItemSchema,
  violatesADRImmutability,
  violatesSpecWriteLock,
  type DecisionItem,
  type SectionItem,
} from '../schemas/knowledge-types.js';
import { logger } from '../utils/logger.js';
import { ImmutabilityViolationError } from '../utils/immutability.js';
import { storeRunbook } from './knowledge/runbook.js';
import { storeChange } from './knowledge/change.js';
import { storeIssue } from './knowledge/issue.js';
import { storeDecision, updateDecision } from './knowledge/decision.js';
import { updateSection } from './knowledge/section.js';
import { storeTodo } from './knowledge/todo.js';
import { storeReleaseNote } from './knowledge/release_note.js';
import { storeDDL } from './knowledge/ddl.js';
import { storePRContext } from './knowledge/pr_context.js';
import { storeEntity } from './knowledge/entity.js';
import { storeRelation } from './knowledge/relation.js';
import { addObservation } from './knowledge/observation.js';
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
  const pool = getPool();

  // ✨ AUTO-MAINTENANCE: Check purge thresholds (< 1ms overhead)
  await checkAndPurge(pool, 'memory.store');

  const stored: StoreResult[] = [];
  const errors: StoreError[] = [];

  // Track actions for autonomous context
  let similarItemsChecked = 0;
  let duplicatesFound = 0;
  const contradictionsDetected = false;

  for (let i = 0; i < items.length; i++) {
    try {
      // Check if this is a delete operation (special format)
      const itemAny = items[i] as any;
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

      const validation = KnowledgeItemSchema.safeParse(items[i]);
      if (!validation.success) {
        errors.push({
          index: i,
          error_code: 'INVALID_SCHEMA',
          message: validation.error.errors[0].message,
          field: validation.error.errors[0].path.join('.'),
        });
        continue;
      }

      const item = validation.data;
      const hash = item.idempotency_key || computeContentHash(JSON.stringify(item.data));

      if (item.kind === 'section') {
        // Check if this is an update operation
        if (item.data.id) {
          const existing = await pool.query('SELECT * FROM section WHERE id = $1', [item.data.id]);

          if (existing.rows.length > 0) {
            // Convert to SectionItem format for validation
            const existingItem: SectionItem = {
              kind: 'section',
              scope: JSON.parse(existing.rows[0].tags || '{}'),
              data: {
                id: existing.rows[0].id,
                title: existing.rows[0].heading,
                body_text: existing.rows[0].body_jsonb?.text,
                body_md: existing.rows[0].body_jsonb?.text,
              },
              tags: existing.rows[0].tags ? JSON.parse(existing.rows[0].tags) : undefined,
            };

            // Check write-lock violation
            if (violatesSpecWriteLock(existingItem, item)) {
              throw new ImmutabilityViolationError(
                'Cannot modify approved specification content',
                'SPEC_WRITE_LOCK',
                'body_md'
              );
            }

            // Perform update
            await updateSection(pool, item.data.id, item.data, item.scope);
            await auditLog(pool, 'section', item.data.id, 'UPDATE', item.data, item.source?.actor);

            stored.push({
              id: item.data.id,
              status: 'updated',
              kind: 'section',
              created_at: new Date().toISOString(),
            });
            continue;
          }
        }

        // Original INSERT logic (deduplication)
        const existing = await pool.query('SELECT id FROM section WHERE content_hash = $1', [hash]);

        if (existing.rows.length > 0) {
          duplicatesFound++;
          stored.push({
            id: existing.rows[0].id,
            status: 'skipped_dedupe',
            kind: 'section',
            created_at: new Date().toISOString(),
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

        const result = await pool.query(
          `INSERT INTO section (heading, body_jsonb, content_hash, tags)
           VALUES ($1, $2, $3, $4) RETURNING id, created_at`,
          [
            item.data.title,
            { text: item.data.body_md || item.data.body_text },
            hash,
            JSON.stringify(item.scope),
          ]
        );

        await auditLog(pool, 'section', result.rows[0].id, 'INSERT', item.data, item.source?.actor);

        stored.push({
          id: result.rows[0].id,
          status: 'inserted',
          kind: 'section',
          created_at: result.rows[0].created_at,
        });
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
