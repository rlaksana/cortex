/**
 * MCP Input Transformation Utilities
 *
 * Transforms MCP tool input format to internal schema format
 * Handles the conversion between {content, metadata} and {data} fields
 */

import type { KnowledgeItem } from '../types/core-interfaces';

/**
 * Transform MCP input items to internal knowledge item format
 * Converts {content, metadata} → {data} structure expected by internal schemas
 */
export function transformMcpInputToKnowledgeItems(items: any[]): KnowledgeItem[] {
  return items.map(item => {
    const { kind, content, metadata, scope } = item;

    // Transform content/metadata to data field
    const data: Record<string, any> = {
      content,
    };

    // Add metadata to data if present
    if (metadata) {
      Object.assign(data, metadata);
    }

    // Return knowledge item in internal format
    const knowledgeItem: KnowledgeItem = {
      kind,
      content,
      data,
      scope: scope || {},
    };

    return knowledgeItem;
  });
}

/**
 * Transform knowledge item back to MCP output format
 * Converts {data} → {content, metadata} structure for MCP responses
 */
export function transformKnowledgeItemToMcpOutput(item: KnowledgeItem): any {
  const { kind, data, scope, id, created_at, updated_at } = item;

  // Extract content from data
  const content = data?.content || '';

  // Extract metadata (everything except content)
  const metadata = { ...data };
  if (metadata.content) {
    delete metadata.content;
  }

  return {
    id,
    kind,
    content,
    metadata: Object.keys(metadata).length > 0 ? metadata : undefined,
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
    'entity', 'relation', 'observation', 'section', 'runbook',
    'change', 'issue', 'decision', 'todo', 'release_note',
    'ddl', 'pr_context', 'incident', 'release', 'risk', 'assumption'
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

    if (!item.content || typeof item.content !== 'string') {
      errors.push(`Item ${index}: content is required and must be a string`);
    }

    if (item.scope && typeof item.scope !== 'object') {
      errors.push(`Item ${index}: scope must be an object if provided`);
    }
  });

  return { valid: errors.length === 0, errors };
}