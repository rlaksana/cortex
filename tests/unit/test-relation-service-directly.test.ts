/**
 * Test the relation service directly to isolate the issue
 */

import { describe, it, expect } from 'vitest';
import { storeRelation } from '../../src/services/knowledge/relation.js';

describe('Test Relation Service Directly', () => {
  it('should store relation using the service directly', async () => {
    const relationData = {
      from_entity_type: 'entity',
      from_entity_id: '550e8400-e29b-41d4-a716-446655440001',
      to_entity_type: 'entity',
      to_entity_id: '550e8400-e29b-41d4-a716-446655440002',
      relation_type: 'relates_to',
      metadata: { strength: 0.8 }
    };

    const scope = {
      project: 'test-relation-storage',
      branch: 'main'
    };

    try {
      const result = await storeRelation(relationData, scope);
      console.log('Direct relation store result:', result);
      expect(result).toBeDefined();
      // The function returns an object with id field
      expect(result).toHaveProperty('id');
      expect(typeof result.id).toBe('string');
    } catch (error) {
      console.log('Direct relation store error:', error);
      throw error;
    }
  });
});