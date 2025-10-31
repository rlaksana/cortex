/**
 * Debug test to understand Zod validation failures for relations
 */

import { describe, it, expect } from 'vitest';
import { validateMcpInputFormat, transformMcpInputToKnowledgeItems } from '../../src/utils/mcp-transform.js';
import { validateKnowledgeItems } from '../../src/schemas/enhanced-validation.js';

describe('Debug Zod Validation', () => {
  it('should debug relation validation step by step', async () => {
    const relationItem = {
      kind: 'relation',
      scope: {
        project: 'test-relation-storage',
        branch: 'main'
      },
      data: {
        from_entity_type: 'entity',
        from_entity_id: '550e8400-e29b-41d4-a716-446655440001',
        to_entity_type: 'entity',
        to_entity_id: '550e8400-e29b-41d4-a716-446655440002',
        relation_type: 'relates_to',
        metadata: { strength: 0.8 }
      }
    };

    console.log('Original item:', JSON.stringify(relationItem, null, 2));

    // Step 1: Test MCP input format validation
    const formatValidation = validateMcpInputFormat([relationItem]);
    console.log('MCP format validation:', formatValidation);
    expect(formatValidation.valid).toBe(true);

    // Step 2: Test transformation
    const transformedItems = transformMcpInputToKnowledgeItems([relationItem]);
    console.log('Transformed items:', JSON.stringify(transformedItems[0], null, 2));

    // Step 3: Test Zod validation
    const zodValidation = validateKnowledgeItems([relationItem]);
    console.log('Zod validation result:', zodValidation);

    if (zodValidation.errors.length > 0) {
      console.log('Zod errors:', zodValidation.errors);
    }
  });
});