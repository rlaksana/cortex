/**
 * Document Reassembly Service
 *
 * Provides functionality to reconstruct documents from their chunks.
 * This service can retrieve parent documents and all their associated chunks,
 * then reassemble them in the correct order with proper metadata.
 */

import { logger } from '../utils/logger.js';
import { memoryFind } from './memory-find.js';
import type { KnowledgeItem } from '../types/core-interfaces.js';

export interface DocumentWithChunks {
  parent: KnowledgeItem;
  chunks: KnowledgeItem[];
  reassembled_content: string;
  chunking_metadata: {
    total_chunks: number;
    original_length: number;
    chunk_size: number;
    overlap_size: number;
    semantic_analysis_enabled: boolean;
    processing_timestamp: string;
  };
}

export interface ReassemblyOptions {
  include_metadata?: boolean;
  preserve_chunk_markers?: boolean;
  filter_by_scope?: boolean;
  sort_by_position?: boolean;
}

/**
 * Get a document with all its chunks reassembled in order
 */
export async function getDocumentWithChunks(
  docId: string,
  options: ReassemblyOptions = {}
): Promise<DocumentWithChunks | null> {
  const {
    include_metadata = true,
    preserve_chunk_markers = false,
    filter_by_scope = true,
    sort_by_position = true,
  } = options;

  try {
    logger.info({ docId, options }, 'Starting document reassembly');

    // Step 1: Find the parent document
    const parentResult = await memoryFind({
      query: `id:${docId} kind:(section OR runbook OR incident)`,
      limit: 1,
    });

    if (!parentResult.results || parentResult.results.length === 0) {
      logger.warn({ docId }, 'Parent document not found');
      return null;
    }

    const parent = parentResult.results[0] as KnowledgeItem;

    // Step 2: Find all chunks associated with this parent
    const scope = filter_by_scope ? parent.scope : undefined;

    const chunkSearchQuery = buildChunkSearchQuery(docId, parent.kind, scope);
    const searchOptions: any = {
      query: chunkSearchQuery,
      limit: 100, // Reasonable limit for number of chunks
    };

    if (scope) {
      searchOptions.scope = scope;
    }

    const chunkResult = await memoryFind(searchOptions);

    if (!chunkResult.results) {
      logger.warn({ docId }, 'No chunks found for document');
      return null;
    }

    const chunks = chunkResult.results as KnowledgeItem[];

    // Step 3: Sort chunks by position
    const sortedChunks = sort_by_position ? sortChunksByPosition(chunks) : chunks;

    // Step 4: Reassemble content
    const reassembled_content = reassembleContent(sortedChunks, preserve_chunk_markers);

    // Step 5: Extract chunking metadata
    const chunking_metadata = extractChunkingMetadata(parent, sortedChunks);

    const result: DocumentWithChunks = {
      parent,
      chunks: sortedChunks,
      reassembled_content,
      chunking_metadata,
    };

    logger.info(
      {
        docId,
        chunkCount: sortedChunks.length,
        contentLength: reassembled_content.length,
        hasMetadata: include_metadata,
      },
      'Document reassembly completed successfully'
    );

    return result;
  } catch (error) {
    logger.error({ error, docId }, 'Document reassembly failed');
    return null;
  }
}

/**
 * Find documents by parent_id (alternative search method)
 */
export async function getDocumentByParentId(
  parentId: string,
  options: ReassemblyOptions = {}
): Promise<DocumentWithChunks | null> {
  try {
    logger.info({ parentId }, 'Finding document by parent ID');

    // Search for chunks with the specified parent_id
    const chunkResult = await memoryFind({
      query: `parent_id:${parentId}`,
      limit: 100,
    });

    if (!chunkResult.results || chunkResult.results.length === 0) {
      logger.warn({ parentId }, 'No chunks found for parent ID');
      return null;
    }

    const chunks = chunkResult.results as KnowledgeItem[];

    // Extract parent information from the first chunk
    const firstChunk = chunks[0];
    if (!firstChunk.data?.original_content_hash) {
      logger.warn({ parentId }, 'Chunks do not contain expected parent metadata');
      return null;
    }

    // Create a synthetic parent document from chunk metadata
    const syntheticParent = createSyntheticParent(firstChunk, chunks);

    // Sort and reassemble
    const sortedChunks = options.sort_by_position !== false ? sortChunksByPosition(chunks) : chunks;

    const reassembled_content = reassembleContent(
      sortedChunks,
      options.preserve_chunk_markers || false
    );
    const chunking_metadata = extractChunkingMetadata(syntheticParent, sortedChunks);

    const result: DocumentWithChunks = {
      parent: syntheticParent,
      chunks: sortedChunks,
      reassembled_content,
      chunking_metadata,
    };

    logger.info(
      {
        parentId,
        chunkCount: sortedChunks.length,
        contentLength: reassembled_content.length,
      },
      'Document by parent ID reassembly completed'
    );

    return result;
  } catch (error) {
    logger.error({ error, parentId }, 'Document by parent ID reassembly failed');
    return null;
  }
}

/**
 * Build search query for finding chunks
 */
function buildChunkSearchQuery(docId: string, parentKind: string, _scope?: any): string {
  let query = `kind:${parentKind} data.is_chunk:true`;

  // Add parent ID search if supported
  query += ` (data.parent_id:${docId} OR metadata.parent_id:${docId})`;

  return query;
}

/**
 * Sort chunks by their position index
 */
function sortChunksByPosition(chunks: KnowledgeItem[]): KnowledgeItem[] {
  return chunks.sort((a, b) => {
    const aIndex = a.data?.chunk_index ?? 0;
    const bIndex = b.data?.chunk_index ?? 0;
    return aIndex - bIndex;
  });
}

/**
 * Reassemble content from chunks
 */
function reassembleContent(chunks: KnowledgeItem[], preserveMarkers: boolean): string {
  if (chunks.length === 0) {
    return '';
  }

  const contentParts: string[] = [];

  for (const chunk of chunks) {
    let chunkContent = '';

    // Extract content from various possible fields
    if (chunk.data?.content) {
      chunkContent = chunk.data.content;
    } else if (chunk.content) {
      chunkContent = chunk.content;
    } else {
      // Try other common content fields
      const contentFields = ['body_text', 'body_md', 'description', 'rationale'];
      for (const field of contentFields) {
        if (chunk.data?.[field] && typeof chunk.data[field] === 'string') {
          chunkContent = chunk.data[field];
          break;
        }
      }
    }

    if (!chunkContent) {
      logger.warn({ chunkId: chunk.id }, 'Chunk has no extractable content');
      continue;
    }

    // Clean up chunk markers if not preserving them
    if (!preserveMarkers) {
      chunkContent = cleanChunkContent(chunkContent);
    }

    contentParts.push(chunkContent);
  }

  return contentParts.join('\n\n').trim();
}

/**
 * Clean chunk content by removing chunk markers and metadata
 */
function cleanChunkContent(content: string): string {
  return (
    content
      // Remove chunk position markers
      .replace(/^CHUNK \d+ of \d+\n\n/gim, '')
      // Remove title prefixes if they're duplicates
      .replace(/^TITLE: .+\n\n/gim, '')
      // Remove parent markers
      .replace(/^PARENT: .+$/gim, '')
      // Clean up extra whitespace
      .replace(/\n{3,}/g, '\n\n')
      .trim()
  );
}

/**
 * Extract chunking metadata from parent and chunks
 */
function extractChunkingMetadata(
  parent: KnowledgeItem,
  chunks: KnowledgeItem[]
): DocumentWithChunks['chunking_metadata'] {
  const parentMetadata = parent.metadata?.chunking_info || {};
  const firstChunkData = chunks[0]?.data || {};

  return {
    total_chunks: chunks.length,
    original_length: parentMetadata.original_length || firstChunkData.original_length || 0,
    chunk_size: parentMetadata.chunk_size || 1200,
    overlap_size: parentMetadata.overlap_size || 200,
    semantic_analysis_enabled: parentMetadata.semantic_analysis_enabled || false,
    processing_timestamp: parentMetadata.processing_timestamp || new Date().toISOString(),
  };
}

/**
 * Create a synthetic parent document from chunk metadata
 */
function createSyntheticParent(firstChunk: KnowledgeItem, chunks: KnowledgeItem[]): KnowledgeItem {
  const chunkData = firstChunk.data || {};

  return {
    id: chunkData.parent_id || `synthetic-parent-${firstChunk.id}`,
    kind: firstChunk.kind,
    scope: firstChunk.scope,
    data: {
      is_chunk: false,
      is_synthetic_parent: true,
      total_chunks: chunks.length,
      original_length: chunkData.original_length || 0,
      content: `Synthetic parent for ${chunks.length} chunks`,
      ...chunkData,
    },
    metadata: {
      is_synthetic_parent: true,
      created_from_chunks: true,
      chunking_info: {
        was_chunked: true,
        is_parent: true,
        total_chunks: chunks.length,
        processing_timestamp: new Date().toISOString(),
      },
    },
    created_at: firstChunk.created_at || new Date().toISOString(),
  };
}

/**
 * Get reassembly statistics for a document
 */
export async function getDocumentReassemblyStats(docId: string): Promise<{
  has_parent: boolean;
  chunk_count: number;
  total_size: number;
  chunking_info: any;
}> {
  try {
    const result = await getDocumentWithChunks(docId, { include_metadata: false });

    if (!result) {
      return {
        has_parent: false,
        chunk_count: 0,
        total_size: 0,
        chunking_info: null,
      };
    }

    return {
      has_parent: true,
      chunk_count: result.chunks.length,
      total_size: result.reassembled_content.length,
      chunking_info: result.chunking_metadata,
    };
  } catch (error) {
    logger.error({ error, docId }, 'Failed to get reassembly stats');
    return {
      has_parent: false,
      chunk_count: 0,
      total_size: 0,
      chunking_info: null,
    };
  }
}
