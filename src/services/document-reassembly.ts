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
import {
  verifyContentSimilarity,
  type SimilarityAnalysis,
  type VerificationOptions,
} from '../utils/content-similarity-verifier.js';

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
  similarity_analysis?: SimilarityAnalysis;
}

export interface ReassemblyOptions {
  include_metadata?: boolean;
  preserve_chunk_markers?: boolean;
  filter_by_scope?: boolean;
  sort_by_position?: boolean;
  verify_similarity?: boolean;
  similarity_options?: VerificationOptions;
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
    verify_similarity = true,
    similarity_options = { target_similarity: 0.995 },
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

    // Step 6: Verify content similarity if requested
    let similarity_analysis: SimilarityAnalysis | undefined;
    if (verify_similarity && parent.data?.original_content) {
      try {
        similarity_analysis = await verifyContentSimilarity(
          parent.data.original_content,
          reassembled_content,
          similarity_options
        );

        logger.info(
          {
            docId,
            overallSimilarity: similarity_analysis.metrics.overall_similarity,
            targetSimilarity: similarity_options.target_similarity,
            isAcceptable: similarity_analysis.is_acceptable,
            confidenceLevel: similarity_analysis.confidence_level,
          },
          'Content similarity verification completed'
        );

        // Log warnings if similarity is below target
        if (!similarity_analysis.is_acceptable) {
          logger.warn(
            {
              docId,
              overallSimilarity: similarity_analysis.metrics.overall_similarity,
              targetSimilarity: similarity_options.target_similarity,
              missingPhrases: similarity_analysis.details.missing_phrases.length,
              extraPhrases: similarity_analysis.details.extra_phrases.length,
            },
            'Document reassembly similarity below target threshold'
          );
        }
      } catch (error) {
        logger.warn(
          { error, docId },
          'Content similarity verification failed, continuing without verification'
        );
      }
    }

    const result: DocumentWithChunks = {
      parent,
      chunks: sortedChunks,
      reassembled_content,
      chunking_metadata,
      similarity_analysis,
    };

    logger.info(
      {
        docId,
        chunkCount: sortedChunks.length,
        contentLength: reassembled_content.length,
        hasMetadata: include_metadata,
        similarityVerified: !!similarity_analysis,
        similarityScore: similarity_analysis?.metrics.overall_similarity,
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
 * ENHANCED: Deterministic reassembly with validation
 */
function reassembleContent(chunks: KnowledgeItem[], preserveMarkers: boolean): string {
  if (chunks.length === 0) {
    return '';
  }

  // Sort chunks deterministically by reassembly order, chunk_index, or reassembly_key
  const sortedChunks = [...chunks].sort((a, b) => {
    // Priority 1: Use reassembly_order if available
    if (a.data?.reassembly_order !== undefined && b.data?.reassembly_order !== undefined) {
      return a.data.reassembly_order - b.data.reassembly_order;
    }

    // Priority 2: Use chunk_index
    if (a.data?.chunk_index !== undefined && b.data?.chunk_index !== undefined) {
      return a.data.chunk_index - b.data.chunk_index;
    }

    // Priority 3: Use reassembly_key for deterministic ordering
    if (a.data?.reassembly_key && b.data?.reassembly_key) {
      return a.data.reassembly_key.localeCompare(b.data.reassembly_key);
    }

    // Fallback: Sort by ID (not ideal but deterministic)
    return (a.id || '').localeCompare(b.id || '');
  });

  const contentParts: string[] = [];
  let lastEndPos = 0;
  let overlapDetected = false;

  for (let i = 0; i < sortedChunks.length; i++) {
    const chunk = sortedChunks[i];
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

    // Enhanced content cleaning with overlap detection
    if (!preserveMarkers) {
      chunkContent = cleanChunkContentWithOverlapDetection(chunkContent, lastEndPos, i === 0);

      // Check for overlap using chunk boundaries if available
      if (chunk.data?.chunk_start_pos !== undefined && chunk.data?.chunk_end_pos !== undefined) {
        if (chunk.data.chunk_start_pos < lastEndPos) {
          overlapDetected = true;
          logger.debug(
            {
              chunkId: chunk.id,
              chunkStart: chunk.data.chunk_start_pos,
              lastEndPos,
              overlap: lastEndPos - chunk.data.chunk_start_pos,
            },
            'Detected chunk overlap during reassembly'
          );
        }
        lastEndPos = chunk.data.chunk_end_pos;
      }
    }

    contentParts.push(chunkContent);
  }

  const reassembledContent = contentParts.join('\n\n').trim();

  if (overlapDetected) {
    logger.info(
      {
        chunkCount: sortedChunks.length,
        contentLength: reassembledContent.length,
        overlapHandled: true,
      },
      'Reassembled content with overlap handling'
    );
  }

  return reassembledContent;
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
 * Enhanced chunk content cleaning with overlap detection and boundary validation
 */
function cleanChunkContentWithOverlapDetection(
  content: string,
  lastEndPos: number,
  isFirstChunk: boolean
): string {
  let cleanedContent = cleanChunkContent(content);

  // For non-first chunks, detect and handle potential overlap
  if (!isFirstChunk && lastEndPos > 0) {
    // Look for overlap indicators in the content
    const lines = cleanedContent.split('\n');
    let nonOverlapStart = 0;

    // Try to find where the unique content starts by looking for patterns
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();

      // Skip empty lines and common prefix markers
      if (!line || line.startsWith('TITLE:') || line.startsWith('CHUNK') || line.length < 10) {
        continue;
      }

      // This looks like the start of unique content
      nonOverlapStart = i;
      break;
    }

    // If we found overlap, remove the overlapping portion
    if (nonOverlapStart > 0) {
      const beforeRemoval = cleanedContent.length;
      cleanedContent = lines.slice(nonOverlapStart).join('\n').trim();
      const removedChars = beforeRemoval - cleanedContent.length;

      if (removedChars > 50) {
        // Only log significant removals
        logger.debug(
          {
            removedChars,
            originalLength: beforeRemoval,
            newLength: cleanedContent.length,
          },
          'Removed overlapping content during reassembly'
        );
      }
    }
  }

  return cleanedContent;
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
 * Verify document reconstruction completeness and integrity
 * ENHANCED: High-fidelity validation with ≥99% accuracy requirement
 */
export async function verifyDocumentReassembly(docId: string): Promise<{
  is_complete: boolean;
  integrity_verified: boolean;
  missing_chunks: number[];
  duplicate_chunks: number[];
  total_expected: number;
  total_found: number;
  integrity_score: number;
  fidelity_metrics: {
    content_similarity: number;
    boundary_accuracy: number;
    order_correctness: number;
    hash_verification: boolean;
    overlap_handling: number;
  };
  validation_details: {
    chunk_hashes_valid: boolean;
    reassembly_keys_valid: boolean;
    deterministic_order: boolean;
    missing_content_percentage: number;
    extra_content_percentage: number;
  };
}> {
  try {
    const result = await getDocumentWithChunks(docId, {
      include_metadata: true,
      verify_similarity: true,
      similarity_options: { target_similarity: 0.99 }, // 99% similarity target
    });

    if (!result) {
      return {
        is_complete: false,
        integrity_verified: false,
        missing_chunks: [],
        duplicate_chunks: [],
        total_expected: 0,
        total_found: 0,
        integrity_score: 0,
        fidelity_metrics: {
          content_similarity: 0,
          boundary_accuracy: 0,
          order_correctness: 0,
          hash_verification: false,
          overlap_handling: 0,
        },
        validation_details: {
          chunk_hashes_valid: false,
          reassembly_keys_valid: false,
          deterministic_order: false,
          missing_content_percentage: 100,
          extra_content_percentage: 0,
        },
      };
    }

    const { chunks, chunking_metadata, similarity_analysis } = result;
    const totalExpected = chunking_metadata.total_chunks;
    const totalFound = chunks.length;

    // Check for missing chunks
    const expectedIndices = Array.from({ length: totalExpected }, (_, i) => i);
    const foundIndices = chunks.map((chunk) => chunk.data?.chunk_index ?? 0);
    const missingChunks = expectedIndices.filter((index) => !foundIndices.includes(index));

    // Check for duplicate chunks
    const duplicateChunks = foundIndices.filter((index, i) => foundIndices.indexOf(index) !== i);

    // ENHANCED: Verify chunk hashes and reassembly keys
    const chunkHashesValid = await verifyChunkHashes(chunks);
    const reassemblyKeysValid = await verifyReassemblyKeys(chunks);
    const deterministicOrder = verifyDeterministicOrder(chunks);

    // ENHANCED: Calculate fidelity metrics
    const contentSimilarity = similarity_analysis?.metrics?.overall_similarity || 0;
    const boundaryAccuracy = calculateBoundaryAccuracy(chunks);
    const orderCorrectness = calculateOrderCorrectness(chunks, totalExpected);
    const overlapHandling = calculateOverlapHandling(chunks);

    // Verify content integrity with hash comparison
    let hashVerification = false;
    let integrityScore = 0;

    const parentMetadata = result.parent.metadata?.chunking_info;
    if (parentMetadata?.original_content_hash) {
      const combinedContent = result.reassembled_content;
      const { createHash } = await import('node:crypto');
      const recomputedHash = createHash('sha256').update(combinedContent).digest('hex');

      // ENHANCED: More precise hash verification with normalization
      const normalizedOriginal = await normalizeContentForHashing(
        result.parent.data?.original_content || ''
      );
      const normalizedReassembled = await normalizeContentForHashing(combinedContent);

      const originalHash = createHash('sha256').update(normalizedOriginal).digest('hex');
      const reassembledHash = createHash('sha256').update(normalizedReassembled).digest('hex');

      hashVerification = originalHash === reassembledHash;
      integrityScore = hashVerification ? 1.0 : contentSimilarity;
    } else {
      integrityScore =
        totalFound === totalExpected
          ? contentSimilarity
          : (totalFound / totalExpected) * contentSimilarity;
    }

    // Calculate missing/extra content percentages
    const missingContentPercentage =
      missingChunks.length > 0 ? (missingChunks.length / totalExpected) * 100 : 0;
    const extraContentPercentage =
      duplicateChunks.length > 0 ? (duplicateChunks.length / totalExpected) * 100 : 0;

    return {
      is_complete: missingChunks.length === 0 && duplicateChunks.length === 0 && hashVerification,
      integrity_verified: hashVerification && chunkHashesValid && reassemblyKeysValid,
      missing_chunks: missingChunks,
      duplicate_chunks: duplicateChunks,
      total_expected: totalExpected,
      total_found: totalFound,
      integrity_score: Math.round(integrityScore * 100) / 100, // Round to 2 decimal places
      fidelity_metrics: {
        content_similarity: Math.round(contentSimilarity * 100) / 100,
        boundary_accuracy: Math.round(boundaryAccuracy * 100) / 100,
        order_correctness: Math.round(orderCorrectness * 100) / 100,
        hash_verification: hashVerification,
        overlap_handling: Math.round(overlapHandling * 100) / 100,
      },
      validation_details: {
        chunk_hashes_valid: chunkHashesValid,
        reassembly_keys_valid: reassemblyKeysValid,
        deterministic_order: deterministicOrder,
        missing_content_percentage: Math.round(missingContentPercentage * 100) / 100,
        extra_content_percentage: Math.round(extraContentPercentage * 100) / 100,
      },
    };
  } catch (error) {
    logger.error({ error, docId }, 'Failed to verify document reassembly');
    return {
      is_complete: false,
      integrity_verified: false,
      missing_chunks: [],
      duplicate_chunks: [],
      total_expected: 0,
      total_found: 0,
      integrity_score: 0,
      fidelity_metrics: {
        content_similarity: 0,
        boundary_accuracy: 0,
        order_correctness: 0,
        hash_verification: false,
        overlap_handling: 0,
      },
      validation_details: {
        chunk_hashes_valid: false,
        reassembly_keys_valid: false,
        deterministic_order: false,
        missing_content_percentage: 100,
        extra_content_percentage: 0,
      },
    };
  }
}

/**
 * ENHANCED: Verify chunk hashes for integrity
 */
async function verifyChunkHashes(chunks: KnowledgeItem[]): Promise<boolean> {
  try {
    const { createHash } = await import('node:crypto');

    for (const chunk of chunks) {
      if (chunk.data?.content && chunk.data?.chunk_hash) {
        const expectedHash = chunk.data.chunk_hash;
        const actualHash = createHash('sha256').update(chunk.data.content).digest('hex');

        if (expectedHash !== actualHash) {
          logger.warn(
            {
              chunkId: chunk.id,
              expectedHash,
              actualHash,
              chunkIndex: chunk.data.chunk_index,
            },
            'Chunk hash verification failed'
          );
          return false;
        }
      }
    }

    return true;
  } catch (error) {
    logger.error({ error }, 'Failed to verify chunk hashes');
    return false;
  }
}

/**
 * ENHANCED: Verify reassembly keys for deterministic ordering
 */
function verifyReassemblyKeys(chunks: KnowledgeItem[]): Promise<boolean> {
  try {
    for (const chunk of chunks) {
      if (chunk.data?.reassembly_key && chunk.data?.chunk_hash && chunk.data?.parent_id) {
        const { createHash } = require('node:crypto');
        const expectedKey = chunk.data.reassembly_key;
        const keyData = `${chunk.data.parent_id}:${chunk.data.chunk_index}:${chunk.data.chunk_hash}`;
        const actualKey = createHash('sha256').update(keyData).digest('hex').substring(0, 16);

        if (expectedKey !== actualKey) {
          logger.warn(
            {
              chunkId: chunk.id,
              expectedKey,
              actualKey,
              chunkIndex: chunk.data.chunk_index,
            },
            'Reassembly key verification failed'
          );
          return Promise.resolve(false);
        }
      }
    }

    return Promise.resolve(true);
  } catch (error) {
    logger.error({ error }, 'Failed to verify reassembly keys');
    return Promise.resolve(false);
  }
}

/**
 * ENHANCED: Verify deterministic order of chunks
 */
function verifyDeterministicOrder(chunks: KnowledgeItem[]): boolean {
  try {
    // Sort chunks by various deterministic fields and verify consistency
    const byChunkIndex = [...chunks].sort(
      (a, b) => (a.data?.chunk_index ?? 0) - (b.data?.chunk_index ?? 0)
    );
    const byReassemblyOrder = [...chunks].sort(
      (a, b) => (a.data?.reassembly_order ?? 0) - (b.data?.reassembly_order ?? 0)
    );
    const byReassemblyKey = [...chunks].sort((a, b) =>
      (a.data?.reassembly_key || '').localeCompare(b.data?.reassembly_key || '')
    );

    // Verify all sorts produce the same order
    for (let i = 0; i < chunks.length; i++) {
      if (
        byChunkIndex[i].id !== byReassemblyOrder[i].id ||
        byChunkIndex[i].id !== byReassemblyKey[i].id
      ) {
        logger.warn(
          {
            chunkIndex: i,
            byChunkIndexId: byChunkIndex[i].id,
            byReassemblyOrderId: byReassemblyOrder[i].id,
            byReassemblyKeyId: byReassemblyKey[i].id,
          },
          'Deterministic order verification failed'
        );
        return false;
      }
    }

    return true;
  } catch (error) {
    logger.error({ error }, 'Failed to verify deterministic order');
    return false;
  }
}

/**
 * ENHANCED: Calculate boundary accuracy
 */
function calculateBoundaryAccuracy(chunks: KnowledgeItem[]): number {
  try {
    let validBoundaries = 0;
    let totalBoundaries = 0;

    for (const chunk of chunks) {
      if (
        chunk.data?.chunk_start_pos !== undefined &&
        chunk.data?.chunk_end_pos !== undefined &&
        chunk.metadata?.chunking_info?.reassembly_validation?.start_boundary !== undefined &&
        chunk.metadata?.chunking_info?.reassembly_validation?.end_boundary !== undefined
      ) {
        totalBoundaries++;

        const expectedStart = chunk.metadata.chunking_info.reassembly_validation.start_boundary;
        const expectedEnd = chunk.metadata.chunking_info.reassembly_validation.end_boundary;
        const actualStart = chunk.data.chunk_start_pos;
        const actualEnd = chunk.data.chunk_end_pos;

        // Allow small tolerance for boundary matching
        const startTolerance = 50;
        const endTolerance = 50;

        if (
          Math.abs(expectedStart - actualStart) <= startTolerance &&
          Math.abs(expectedEnd - actualEnd) <= endTolerance
        ) {
          validBoundaries++;
        }
      }
    }

    return totalBoundaries > 0 ? validBoundaries / totalBoundaries : 1.0;
  } catch (error) {
    logger.error({ error }, 'Failed to calculate boundary accuracy');
    return 0;
  }
}

/**
 * ENHANCED: Calculate order correctness
 */
function calculateOrderCorrectness(chunks: KnowledgeItem[], totalExpected: number): number {
  try {
    const sortedChunks = [...chunks].sort(
      (a, b) => (a.data?.chunk_index ?? 0) - (b.data?.chunk_index ?? 0)
    );

    let correctOrder = 0;
    for (let i = 0; i < sortedChunks.length; i++) {
      const chunk = sortedChunks[i];
      const expectedIndex = chunk.data?.chunk_index;

      if (expectedIndex !== undefined && expectedIndex === i) {
        correctOrder++;
      }
    }

    return sortedChunks.length > 0 ? correctOrder / sortedChunks.length : 0;
  } catch (error) {
    logger.error({ error }, 'Failed to calculate order correctness');
    return 0;
  }
}

/**
 * ENHANCED: Calculate overlap handling quality
 */
function calculateOverlapHandling(chunks: KnowledgeItem[]): number {
  try {
    let goodOverlapHandling = 0;
    let chunksWithOverlap = 0;

    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];

      if (chunk.data?.chunk_overlap && chunk.data?.chunk_overlap > 0) {
        chunksWithOverlap++;

        // Check if the chunk has proper overlap handling metadata
        if (chunk.metadata?.chunking_info?.has_context !== undefined) {
          goodOverlapHandling++;
        }
      }
    }

    return chunksWithOverlap > 0 ? goodOverlapHandling / chunksWithOverlap : 1.0;
  } catch (error) {
    logger.error({ error }, 'Failed to calculate overlap handling');
    return 0;
  }
}

/**
 * ENHANCED: Normalize content for accurate hash comparison
 */
async function normalizeContentForHashing(content: string): Promise<string> {
  try {
    // Apply consistent normalization for hash comparison
    return (
      content
        // Normalize whitespace
        .replace(/\s+/g, ' ')
        // Remove common chunking artifacts
        .replace(/^CHUNK \d+ of \d+\s*/gim, '')
        .replace(/^TITLE: .+\s*/gim, '')
        .replace(/^PARENT: .+\s*/gim, '')
        // Normalize line endings
        .replace(/\r\n/g, '\n')
        .replace(/\n+/g, ' ')
        // Trim and normalize case for consistent hashing
        .trim()
        .toLowerCase()
    );
  } catch (error) {
    logger.error({ error }, 'Failed to normalize content for hashing');
    return content;
  }
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
