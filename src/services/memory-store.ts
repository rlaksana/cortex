import { auditLog } from '../db/audit.js';
// import { computeContentHash } from '../utils/hash.js'; // Unused import
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
import { ImmutabilityViolationError } from '../utils/immutability.js';
import { storeRunbook } from './knowledge/runbook.js';
import { storeChange } from './knowledge/change.js';
import { storeIssue } from './knowledge/issue.js';
// import { storeDecision } from './knowledge/decision.js'; // Unused import
import { storeTodo } from './knowledge/todo.js';
import { storeReleaseNote } from './knowledge/release_note.js';
import { storeDDL } from './knowledge/ddl.js';
import { storePRContext } from './knowledge/pr_context.js';
import { storeEntity } from './knowledge/entity.js';
import { storeRelation } from './knowledge/relation.js';
import { addObservation } from './knowledge/observation.js';
import {
  storeIncident,
  updateIncident,
  storeRelease,
  updateRelease,
  storeRisk,
  updateRisk,
  storeAssumption,
  updateAssumption,
} from './knowledge/session-logs.js';
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
      },
    } as {
      stored: [];
      errors: StoreError[];
      autonomous_context: {
        action_performed: 'skipped';
        similar_items_checked: 0;
        duplicates_found: 0;
        contradictions_detected: false;
        recommendation: 'Fix validation errors before retrying';
        reasoning: 'Request failed validation';
        user_message_suggestion: '❌ Request validation failed';
      };
    };
  }

  // Validate individual items with comprehensive checks
  const validation = validateKnowledgeItems(items);
  if (validation.errors.length > 0) {
    const errors: StoreError[] = validation.errors.map((err) => ({
      index: err.index,
      error_code: err.code as string,
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
      },
    };
  }

  
  // ✨ AUTO-MAINTENANCE: Check purge thresholds (< 1ms overhead)
  await checkAndPurge('memory.store');

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
          entity_type: itemAny.kind,
          entity_id: itemAny.id,
          cascade_relations: itemAny.cascade_relations ?? false,
        };

        const deleteResult = await softDelete(deleteRequest);

        if (deleteResult.status === 'deleted') {
          await auditLog(
            deleteRequest.entity_type,
            deleteRequest.entity_id,
            'DELETE',
            { operation: 'soft_delete', cascade: deleteRequest.cascade_relations, ...itemAny.data },
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
              deleteResult instanceof Error
                ? deleteResult.message
                : `Failed to delete ${deleteRequest.entity_type}:${deleteRequest.entity_id}`,
          });
        }
        continue;
      }

      // Use enhanced validated item (already validated above)
      const item = validatedItems[i];
      // const hash = item.idempotency_key ?? computeContentHash(JSON.stringify(item.data)); // Unused variable

      if (item.kind === 'section') {
        try {
          const prismaClient = (await import('../db/prisma-client.js')).prisma.getClient();

          // Check if this is an update operation
          if (item.data.id) {
            const existing = await prismaClient.section.findUnique({
              where: { id: item.data.id },
            });

            if (existing) {
              // Convert to SectionItem format for validation
              const existingItem: SectionItem = {
                kind: 'section',
                scope: JSON.parse('{}'), // Will be updated with proper scope extraction
                data: {
                  id: existing.id,
                  title: existing.title,
                  heading: existing.title, // Using title as heading since schema doesn't have heading field
                  body_text: '',
                  body_md: existing.content ?? '',
                },
                tags: existing.tags as Record<string, unknown>,
              };

              // Check write-lock violation
              if (violatesSpecWriteLock(existingItem, item)) {
                throw new ImmutabilityViolationError(
                  'Cannot modify approved specification content',
                  'SPEC_WRITE_LOCK',
                  'content'
                );
              }

              // Perform update using Prisma (type-safe)
              const updated = await prismaClient.section.update({
                where: { id: item.data.id },
                data: {
                  title: item.data.title,
                  content: item.data.body_md ?? item.data.body_text,
                  tags: item.scope ? item.scope : existing.tags,
                  metadata: {},
                },
              });

              await auditLog('section', updated.id, 'UPDATE', item.data, item.source?.actor);

              stored.push({
                id: updated.id,
                status: 'updated',
                kind: 'section',
                created_at: updated.created_at.toISOString(),
              });
              continue;
            }
          }

          // Check for duplicates using Prisma - generate content hash for comparison
          // const titleToHash = item.data.title ?? '';
          // const contentToHash = item.data.body_md ?? item.data.body_text ?? '';
          // const content_hash = require('crypto').createHash('sha256').update(`${titleToHash}:${contentToHash}`).digest('hex'); // Unused variable

          // Check for existing sections with same content (simple duplicate detection)
          const existingByContent = await prismaClient.section.findFirst({
            where: {
              title: item.data.title,
              content: item.data.body_md ?? item.data.body_text,
            },
          });

          if (existingByContent) {
            duplicatesFound++;
            stored.push({
              id: existingByContent.id,
              status: 'skipped_dedupe',
              kind: 'section',
              created_at: existingByContent.created_at.toISOString(),
            });
            continue;
          }

          // ✨ Check for similar content (for autonomous context)
          if (item.data.title && (item.data.body_md ?? item.data.body_text)) {
            const similarityResult = await findSimilar(
              'section',
              item.data.title,
              item.data.body_md ?? item.data.body_text ?? ''
            );
            similarItemsChecked++;
            if (similarityResult.has_similar) {
              duplicatesFound += similarityResult.similar_items.length;
            }
          }

          // Create section using Prisma (type-safe - matches actual schema!)
          const result = await prismaClient.section.create({
            data: {
              title: item.data.title,
              content: item.data.body_md ?? item.data.body_text,
              tags: item.scope ?? {},
              metadata: {},
            },
          });

          await auditLog('section', result.id, 'INSERT', item.data, item.source?.actor);

          stored.push({
            id: result.id,
            status: 'inserted',
            kind: 'section',
            created_at: result.created_at.toISOString(),
          });
        } catch (prismaError: unknown) {
          // Convert Prisma errors to our error format
          if (prismaError instanceof Error) {
            errors.push({
              index: i,
              error_code: 'DATABASE_ERROR',
              message: `Prisma error: ${(prismaError as Error).message}`,
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
        const id = await storeRunbook(item.data, item.scope);
        await auditLog('runbook', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'runbook',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'change') {
        const id = await storeChange(item.data, item.scope);
        await auditLog('change_log', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'change',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'issue') {
        const id = await storeIssue(item.data, item.scope);
        await auditLog('issue_log', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'issue',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'decision') {
        try {
          const prismaClient = (await import('../db/prisma-client.js')).prisma.getClient();

          // Check if this is an update operation
          if (item.data.id) {
            const existing = await prismaClient.adrDecision.findUnique({
              where: { id: item.data.id },
            });

            if (existing) {
              // Convert to DecisionItem format for validation using available properties
              const existingItem: DecisionItem = {
                kind: 'decision',
                scope: {
                  project: 'default',
                  branch: 'main'
                }, // Simplified scope for now
                data: {
                  id: existing.id,
                  component: existing.component,
                  status: existing.status as any,
                  title: existing.title,
                  rationale: existing.rationale,
                  alternatives_considered: existing.alternativesConsidered ?? [],
                  consequences: '', // This field doesn't exist in schema
                  supersedes: '', // This field doesn't exist in schema
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

              // Perform update using Prisma client directly
              await prismaClient.adrDecision.update({
                where: { id: item.data.id },
                data: {
                  status: item.data.status,
                  title: item.data.title,
                  rationale: item.data.rationale,
                  alternativesConsidered: item.data.alternatives_considered,
                },
              });

              await auditLog(
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

          // Create new decision using Prisma
          const result = await prismaClient.adrDecision.create({
            data: {
              component: item.data.component ?? 'unknown',
              status: item.data.status ?? 'proposed',
              title: item.data.title,
              rationale: item.data.rationale ?? '',
              alternativesConsidered: item.data.alternatives_considered ?? [],
              tags: item.scope ?? {},
              metadata: {},
            },
          });

          await auditLog('adr_decision', result.id, 'INSERT', item.data, item.source?.actor);
          stored.push({
            id: result.id,
            status: 'inserted',
            kind: 'decision',
            created_at: result.created_at.toISOString(),
          });
        } catch (prismaError: unknown) {
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
      } else if (item.kind === 'todo') {
        const prismaClient = (await import('../db/prisma-client.js')).prisma.getClient();

        // Check if this is an update operation
        if (item.data.id) {
          const existing = await prismaClient.todoLog.findUnique({
            where: { id: item.data.id }
          });

          if (existing) {
            // Update existing todo using direct field access
            const result = await prismaClient.todoLog.update({
              where: { id: item.data.id },
              data: {
                title: item.data.text || item.data.todo_type || existing.title,
                description: item.data.text ?? existing.description,
                status: item.data.status ?? existing.status,
                priority: item.data.priority ?? existing.priority,
                due_date: item.data.due_date ? new Date(item.data.due_date) : existing.due_date,
                todo_type: item.data.todo_type ?? existing.todo_type,
                text: item.data.text ?? existing.text,
                assignee: item.data.assignee ?? existing.assignee,
                tags: {
                  ...(existing.tags as any || {}),
                  ...item.scope
                }
              }
            });

            await auditLog('todo_log', result.id, 'UPDATE', item.data, item.source?.actor);
            stored.push({ id: result.id, status: 'updated', kind: 'todo', created_at: new Date().toISOString() });
            continue;
          }
        }

        // Create new todo
        const id = await storeTodo(item.data, item.scope);
        await auditLog('todo_log', id, 'INSERT', item.data, item.source?.actor);
        stored.push({ id, status: 'inserted', kind: 'todo', created_at: new Date().toISOString() });
      } else if (item.kind === 'release_note') {
        const id = await storeReleaseNote(item.data, item.scope);
        await auditLog('release_note', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'release_note',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'ddl') {
        const id = await storeDDL(item.data);
        await auditLog('ddl_history', id, 'INSERT', item.data, item.source?.actor);
        stored.push({ id, status: 'inserted', kind: 'ddl', created_at: new Date().toISOString() });
      } else if (item.kind === 'pr_context') {
        const id = await storePRContext(item.data, item.scope);
        await auditLog('pr_context', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'pr_context',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'entity') {
        const prismaClient = (await import('../db/prisma-client.js')).prisma.getClient();

        // Check if this is an update operation
        if (item.data.id) {
          const existing = await prismaClient.knowledgeEntity.findUnique({
            where: { id: item.data.id }
          });

          if (existing) {
            // Update existing entity
            const result = await prismaClient.knowledgeEntity.update({
              where: { id: item.data.id },
              data: {
                entity_type: item.data.entity_type ?? existing.entity_type,
                name: item.data.name ?? existing.name,
                data: item.data.data ?? existing.data,
                tags: {
                  ...(existing.tags as any || {}),
                  ...item.scope
                }
              }
            });

            await auditLog('knowledge_entity', result.id, 'UPDATE', item.data, item.source?.actor);
            stored.push({
              id: result.id,
              status: 'updated',
              kind: 'entity',
              created_at: new Date().toISOString(),
            });
            continue;
          }
        }

        // Create new entity
        const id = await storeEntity(item.data, item.scope);
        await auditLog('knowledge_entity', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'entity',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'relation') {
        const id = await storeRelation(item.data, item.scope);
        await auditLog('knowledge_relation', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'relation',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'observation') {
        const id = await addObservation(item.data, item.scope);
        await auditLog('knowledge_observation', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'observation',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'incident') {
        // Check if this is an update operation
        if (item.data.id) {
          const prismaClient = (await import('../db/prisma-client.js')).prisma.getClient();
          const existing = await prismaClient.incidentLog.findUnique({
            where: { id: item.data.id }
          });

          if (existing) {
            // Update existing incident
            await updateIncident(item.data.id, item.data);
            await auditLog('incident_log', item.data.id, 'UPDATE', item.data, item.source?.actor);
            stored.push({
              id: item.data.id,
              status: 'updated',
              kind: 'incident',
              created_at: new Date().toISOString(),
            });
            continue;
          }
        }

        // Create new incident
        const id = await storeIncident(item.data, item.scope);
        await auditLog('incident_log', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'incident',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'release') {
        // Check if this is an update operation
        if (item.data.id) {
          const prismaClient = (await import('../db/prisma-client.js')).prisma.getClient();
          const existing = await prismaClient.releaseLog.findUnique({
            where: { id: item.data.id }
          });

          if (existing) {
            // Update existing release
            await updateRelease(item.data.id, item.data);
            await auditLog('release_log', item.data.id, 'UPDATE', item.data, item.source?.actor);
            stored.push({
              id: item.data.id,
              status: 'updated',
              kind: 'release',
              created_at: new Date().toISOString(),
            });
            continue;
          }
        }

        // Create new release
        const id = await storeRelease(item.data, item.scope);
        await auditLog('release_log', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'release',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'risk') {
        // Check if this is an update operation
        if (item.data.id) {
          const prismaClient = (await import('../db/prisma-client.js')).prisma.getClient();
          const existing = await prismaClient.riskLog.findUnique({
            where: { id: item.data.id }
          });

          if (existing) {
            // Update existing risk
            await updateRisk(item.data.id, item.data);
            await auditLog('risk_log', item.data.id, 'UPDATE', item.data, item.source?.actor);
            stored.push({
              id: item.data.id,
              status: 'updated',
              kind: 'risk',
              created_at: new Date().toISOString(),
            });
            continue;
          }
        }

        // Create new risk
        const id = await storeRisk(item.data, item.scope);
        await auditLog('risk_log', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'risk',
          created_at: new Date().toISOString(),
        });
      } else if (item.kind === 'assumption') {
        // Check if this is an update operation
        if (item.data.id) {
          const prismaClient = (await import('../db/prisma-client.js')).prisma.getClient();
          const existing = await prismaClient.assumptionLog.findUnique({
            where: { id: item.data.id }
          });

          if (existing) {
            // Update existing assumption
            await updateAssumption(item.data.id, item.data);
            await auditLog('assumption_log', item.data.id, 'UPDATE', item.data, item.source?.actor);
            stored.push({
              id: item.data.id,
              status: 'updated',
              kind: 'assumption',
              created_at: new Date().toISOString(),
            });
            continue;
          }
        }

        // Create new assumption
        const id = await storeAssumption(item.data, item.scope);
        await auditLog('assumption_log', id, 'INSERT', item.data, item.source?.actor);
        stored.push({
          id,
          status: 'inserted',
          kind: 'assumption',
          created_at: new Date().toISOString(),
        });
      }
    } catch (err: unknown) {
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
    action_performed: action as 'created' | 'updated' | 'deleted' | 'skipped' | 'batch',
    similar_items_checked: similarItemsChecked,
    duplicates_found: duplicatesFound,
    contradictions_detected: contradictionsDetected,
    recommendation,
    reasoning,
    user_message_suggestion: userMessage,
  };
}
