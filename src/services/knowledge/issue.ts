import { getPrismaClient } from '../../db/prisma.js';
import type { IssueData, ScopeFilter } from '../../types/knowledge-data.js';

/**
 * PRISMA SCHEMA COMPLIANT ISSUELOG SERVICE
 *
 * This service strictly follows the Prisma Schema for IssueLog model:
 * - Direct field access: tracker, external_id, labels, url, assignee
 * - NO metadata/tags workarounds for database fields
 * - Database-first architecture pattern
 */

/**
 * Validates IssueData for Prisma Schema compliance
 * Prevents metadata/tags workarounds for database fields
 */
export function validatePrismaSchemaCompliance(data: IssueData): void {
  // PRISMA SCHEMA COMPLIANCE CHECK: No metadata workarounds
  if (data.metadata && typeof data.metadata === 'object') {
    const metadata = data.metadata as Record<string, unknown>;
    const forbiddenFields = ['tracker', 'external_id', 'url', 'assignee', 'labels'];

    for (const field of forbiddenFields) {
      if (field in metadata) {
        throw new Error(
          `PRISMA SCHEMA VIOLATION: Field '${field}' must use direct field access (data.${field}) ` +
          `instead of metadata workaround (data.metadata.${field}). ` +
          `Database fields must use direct field mapping.`
        );
      }
    }
  }

  // PRISMA SCHEMA COMPLIANCE CHECK: No tags workarounds for database fields
  if (data.tags && typeof data.tags === 'object') {
    const tags = data.tags as Record<string, unknown>;
    const forbiddenFields = ['tracker', 'external_id', 'url', 'assignee', 'labels'];

    for (const field of forbiddenFields) {
      if (field in tags) {
        throw new Error(
          `PRISMA SCHEMA VIOLATION: Field '${field}' must use direct field access (data.${field}) ` +
          `instead of tags workaround (data.tags.${field}). ` +
          `Database fields must use direct field mapping.`
        );
      }
    }
  }

  // Validate field lengths according to Prisma schema constraints
  if (data.tracker && data.tracker.length > 100) {
    throw new Error('Tracker field exceeds maximum length of 100 characters');
  }

  if (data.external_id && data.external_id.length > 100) {
    throw new Error('External ID field exceeds maximum length of 100 characters');
  }

  if (data.assignee && data.assignee.length > 200) {
    throw new Error('Assignee field exceeds maximum length of 200 characters');
  }

  if (data.title && data.title.length > 500) {
    throw new Error('Title field exceeds maximum length of 500 characters');
  }
}

export async function storeIssue(data: IssueData, scope: ScopeFilter): Promise<string> {
  // ENFORCE PRISMA SCHEMA COMPLIANCE
  validatePrismaSchemaCompliance(data);

  const prisma = getPrismaClient();

  // PRISMA SCHEMA COMPLIANCE: Use direct database fields only
  // NO metadata workarounds allowed for tracker/external_id
  const result = await prisma.issueLog.create({
    data: {
      title: data.title,
      description: data.description || null,
      status: data.status,
      // Direct database fields (Prisma Schema compliance)
      tracker: data.tracker || null,
      external_id: data.external_id || null,
      labels: data.labels || [],
      url: data.url || null,
      assignee: data.assignee || null,
      // Scope tags for project isolation only (NOT for database fields)
      tags: scope || {}
    }
  });
  return result.id;
}
