import type { SectionData, ScopeFilter } from '../../types/knowledge-data';
import { validateSpecWriteLock } from '../../utils/immutability';
import { logger } from '../../utils/logger';
// Removed qdrant.js import - using UnifiedDatabaseLayer instead

/**
 * Store a new section in the database
 */
export async function storeSection(data: SectionData, scope?: ScopeFilter): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  // FIXED: Use UnifiedDatabaseLayer instead of direct qdrant access
  const result = await db.create('section', {
    title: data.title || data.heading || 'Untitled Section',
    content: data.body_text || data.body_md || '',
    heading: data.heading || null,
    body_md: data.body_md || null,
    body_text: data.body_text || null,
    document_id: data.document_id || null,
    citation_count: data.citation_count || 0,
    tags: scope || {},
    metadata: {},
  });

  logger.info({ sectionId: result.id, title: data.title }, 'Section stored successfully');
  return result.id;
}

/**
 * Update existing section with write-lock checks
 *
 * @throws ImmutabilityViolationError if section is in approved document
 */
export async function updateSection(
  id: string,
  data: Partial<SectionData>,
  scope?: ScopeFilter
): Promise<void> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();
  // Check write-lock before allowing update
  await validateSpecWriteLock(id);

  const updateData: any = {};

  if (data.title !== undefined) {
    updateData.title = data.title;
  }
  if (data.body_text !== undefined) {
    updateData.content = data.body_text;
  } else if (data.body_md !== undefined) {
    updateData.content = data.body_md;
  }
  if (scope !== undefined) {
    updateData.tags = scope;
  }

  // FIXED: Use direct field access for new fields
  if (data.heading !== undefined) {
    updateData.heading = data.heading;
  }
  if (data.body_md !== undefined) {
    updateData.body_md = data.body_md;
  }
  if (data.body_text !== undefined) {
    updateData.body_text = data.body_text;
  }
  if (data.document_id !== undefined) {
    updateData.document_id = data.document_id;
  }
  if (data.citation_count !== undefined) {
    updateData.citation_count = data.citation_count;
  }

  if (Object.keys(updateData).length === 0) {
    return; // No updates to perform
  }

  await db.update('section', { id }, updateData);
  logger.info(
    { sectionId: id, updates: Object.keys(updateData).length },
    'Section updated successfully'
  );
}

/**
 * Find sections by various criteria
 */
export async function findSections(criteria: {
  title?: string;
  documentId?: string;
  limit?: number;
  offset?: number;
}): Promise<
  Array<{
    id: string;
    title: string;
    heading: string;
    body_text: string;
    body_md: string;
    citation_count: number;
    created_at: Date;
    updated_at: Date;
  }>
> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();

  const whereClause: any = {};

  if (criteria.title) {
    whereClause.OR = [
      { title: { contains: criteria.title, mode: 'insensitive' } },
      { heading: { contains: criteria.title, mode: 'insensitive' } },
    ];
  }

  if (criteria.documentId) {
    // FIXED: Use direct field access instead of metadata
    whereClause.document_id = criteria.documentId;
  }

  const result = await db.find('section', {
    where: whereClause,
    orderBy: { updated_at: 'desc' },
    take: criteria.limit,
    skip: criteria.offset,
    select: {
      id: true,
      title: true,
      content: true,
      heading: true,
      body_md: true,
      body_text: true,
      document_id: true,
      citation_count: true,
      created_at: true,
      updated_at: true,
    },
  });

  return result.map((section) => ({
    id: section.id,
    title: section.title,
    heading: section.heading || section.title,
    body_text: section.body_text || section.content || '',
    body_md: section.body_md || section.content || '',
    citation_count: section.citation_count || 0,
    created_at: section.created_at,
    updated_at: section.updated_at,
  }));
}
