/**
 * MCP Input Transformation Utilities
 *
 * Transforms MCP tool input format to internal schema format
 * Handles the conversion between {content, metadata} and {data} fields
 */

import * as crypto from 'node:crypto';

// Define KnowledgeItem interface to match index.ts requirements
interface KnowledgeItem {
  kind: string;
  id: string;
  content: string;
  metadata?: Record<string, unknown>;
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
  };
  created_at?: Date;
  updated_at?: Date;
  [key: string]: unknown;
}

// Core-interfaces KnowledgeItem for compatibility
export interface CoreKnowledgeItem {
  id?: string;
  kind: string;
  content?: string;
  scope: {
    project?: string;
    branch?: string;
    org?: string;
  };
  data: Record<string, any>;
  metadata?: Record<string, any>;
  created_at?: string;
  updated_at?: string;
}

/**
 * Transform MCP input items to internal knowledge item format
 * Converts {content, metadata} → {data} structure expected by internal schemas
 */
export function transformMcpInputToKnowledgeItems(items: any[]): KnowledgeItem[] {
  return items.map((item) => {
    const { kind, content, data, metadata, scope } = item;

    // Handle both content-based and data-based items
    let finalContent = '';
    let finalMetadata = metadata || {};

    if (content !== undefined) {
      // Content-based item (text types like section, decision, etc.)
      finalContent = content;
    } else if (data !== undefined) {
      // Data-based item (entity, relation, observation, etc.)
      // Store data as JSON string in content for compatibility
      finalContent = JSON.stringify(data);
      // Move structured data to metadata for proper handling
      finalMetadata = {
        ...metadata,
        structured_data: data,
      };
    }

    // Return knowledge item in index.ts format
    const knowledgeItem: KnowledgeItem = {
      id: crypto.randomUUID(),
      kind,
      content: finalContent,
      metadata: finalMetadata,
      scope: scope || {},
    };

    return knowledgeItem;
  });
}

/**
 * Convert index.ts KnowledgeItem to core-interfaces KnowledgeItem
 */
export function transformToCoreKnowledgeItem(item: KnowledgeItem): CoreKnowledgeItem {
  // Check if this item has structured data in metadata
  const hasStructuredData = item.metadata?.structured_data;

  if (hasStructuredData) {
    // Data-based item (entity, relation, observation, etc.)
    return {
      id: item.id,
      kind: item.kind,
      content: item.content, // JSON string of the data
      scope: item.scope || { project: '', branch: '', org: '' },
      data: (item.metadata?.structured_data as Record<string, any>) || {}, // The actual structured data
      metadata: { ...item.metadata },
      created_at: item.created_at?.toISOString() || new Date().toISOString(),
      updated_at: item.updated_at?.toISOString() || new Date().toISOString(),
    };
  } else {
    // Content-based item (text types like section, decision, etc.)
    return {
      id: item.id,
      kind: item.kind,
      content: item.content,
      scope: item.scope || { project: '', branch: '', org: '' },
      data: {
        content: item.content,
        ...item.metadata,
      },
      metadata: item.metadata || {},
      created_at: item.created_at?.toISOString() || new Date().toISOString(),
      updated_at: item.updated_at?.toISOString() || new Date().toISOString(),
    };
  }
}

/**
 * Transform knowledge item back to MCP output format
 * Converts {data} → {content, metadata} structure for MCP responses
 */
export function transformKnowledgeItemToMcpOutput(item: KnowledgeItem): any {
  const { kind, content, metadata, scope, id, created_at, updated_at } = item;

  // Extract content from content field
  const itemContent = content || '';

  // Use metadata field directly

  return {
    id,
    kind,
    content: itemContent,
    metadata: metadata && Object.keys(metadata).length > 0 ? metadata : undefined,
    scope,
    created_at,
    updated_at,
  };
}

/**
 * Validate MCP input format
 */
export function validateMcpInputFormat(items: any[]): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!Array.isArray(items)) {
    errors.push('Items must be an array');
    return { valid: false, errors };
  }

  if (items.length === 0) {
    errors.push('At least one item is required');
  }

  const validKinds = [
    'entity',
    'relation',
    'observation',
    'section',
    'runbook',
    'change',
    'issue',
    'decision',
    'todo',
    'release_note',
    'ddl',
    'pr_context',
    'incident',
    'release',
    'risk',
    'assumption',
  ];

  items.forEach((item, index) => {
    if (!item || typeof item !== 'object') {
      errors.push(`Item ${index}: must be an object`);
      return;
    }

    if (!item.kind || typeof item.kind !== 'string') {
      errors.push(`Item ${index}: kind is required and must be a string`);
    } else if (!validKinds.includes(item.kind)) {
      errors.push(`Item ${index}: invalid kind "${item.kind}"`);
    }

    // Support both content and data fields
    if (!item.content && !item.data) {
      errors.push(`Item ${index}: either content or data must be provided`);
    } else if (item.content && typeof item.content !== 'string') {
      errors.push(`Item ${index}: content must be a string if provided`);
    } else if (item.data && typeof item.data !== 'object') {
      errors.push(`Item ${index}: data must be an object if provided`);
    }

    if (item.scope && typeof item.scope !== 'object') {
      errors.push(`Item ${index}: scope must be an object if provided`);
    }
  });

  return { valid: errors.length === 0, errors };
}
