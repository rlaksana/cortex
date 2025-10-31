/**
 * Debug test to understand why relation validation is failing
 */

import { describe, it, expect } from 'vitest';
import { memoryStore } from '../../src/services/memory-store.js';

describe('Debug Relation Validation', () => {
  it('should show validation error details for relation', async () => {
    const items = [{
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
    }];

    const result = await memoryStore(items);

    console.log('Validation error details:', JSON.stringify(result, null, 2));

    expect(result.items).toHaveLength(1);
    if (result.items[0].status === 'validation_error') {
      console.log('Error details:', result.items[0]);
    }
  });
});