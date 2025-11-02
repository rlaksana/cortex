/**
 * Basic working relation test to demonstrate TDD approach
 * This test shows the minimal implementation needed to make relations work
 */

import { describe, it, expect } from 'vitest';
import {
  storeRelation,
  getOutgoingRelations,
  getIncomingRelations,
} from '../../src/services/knowledge/relation.js';

describe('P4-T4.1: Basic Relation Functionality', () => {
  const testScope = {
    project: 'test-relation-storage',
    branch: 'main',
  };

  it('should store and query relations using the service directly', async () => {
    // Step 1: Store a relation
    const relationData = {
      from_entity_type: 'entity',
      from_entity_id: '550e8400-e29b-41d4-a716-446655440001',
      to_entity_type: 'entity',
      to_entity_id: '550e8400-e29b-41d4-a716-446655440002',
      relation_type: 'relates_to',
      metadata: { strength: 0.8 },
    };

    const storeResult = await storeRelation(relationData, testScope);
    expect(storeResult).toHaveProperty('id');
    const relationId = storeResult.id;

    // Step 2: Query outgoing relations (from_id)
    const outgoingRelations = await getOutgoingRelations('entity', relationId);
    expect(outgoingRelations).toHaveLength(1);
    expect(outgoingRelations[0].relation_type).toBe('relates_to');

    // Step 3: Query incoming relations (to_id)
    const incomingRelations = await getIncomingRelations('entity', relationId);
    expect(incomingRelations).toHaveLength(1);
    expect(incomingRelations[0].relation_type).toBe('relates_to');

    console.log('✅ Relation storage and query working correctly');
  });

  it('should store multiple relations and query them', async () => {
    // Create a chain: A -> B -> C
    const entityA = '550e8400-e29b-41d4-a716-446655440001';
    const entityB = '550e8400-e29b-41d4-a716-446655440002';
    const entityC = '550e8400-e29b-41d4-a716-446655440003';

    // Store A -> B relation
    await storeRelation(
      {
        from_entity_type: 'entity',
        from_entity_id: entityA,
        to_entity_type: 'entity',
        to_entity_id: entityB,
        relation_type: 'depends_on',
      },
      testScope
    );

    // Store B -> C relation
    await storeRelation(
      {
        from_entity_type: 'entity',
        from_entity_id: entityB,
        to_entity_type: 'entity',
        to_entity_id: entityC,
        relation_type: 'implements',
      },
      testScope
    );

    // Query relations from B
    const outgoingFromB = await getOutgoingRelations('entity', entityB);
    expect(outgoingFromB).toHaveLength(1);
    expect(outgoingFromB[0].relation_type).toBe('implements');

    // Query relations to B
    const incomingToB = await getIncomingRelations('entity', entityB);
    expect(incomingToB).toHaveLength(1);
    expect(incomingToB[0].relation_type).toBe('depends_on');

    console.log('✅ Multiple relations and complex queries working');
  });
});
