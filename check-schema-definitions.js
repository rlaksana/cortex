#!/usr/bin/env node

/**
 * Quick script to check schema definitions for failing types
 */

import {
  TodoDataSchema,
  DDLDataSchema,
  PRContextDataSchema,
  RelationDataSchema,
  ObservationDataSchema,
  IncidentDataSchema,
  ReleaseDataSchema,
  RiskDataSchema,
  AssumptionDataSchema,
  ChangeDataSchema
} from './dist/schemas/knowledge-types.js';

const schemas = {
  todo: TodoDataSchema,
  ddl: DDLDataSchema,
  pr_context: PRContextDataSchema,
  relation: RelationDataSchema,
  observation: ObservationDataSchema,
  incident: IncidentDataSchema,
  release: ReleaseDataSchema,
  risk: RiskDataSchema,
  assumption: AssumptionDataSchema,
  change: ChangeDataSchema
};

console.log('🔍 Checking schema definitions for failing types...\n');

Object.entries(schemas).forEach(([type, schema]) => {
  try {
    const shape = schema._def.shape();
    const fields = Object.keys(shape);
    console.log(`${type}: ${fields.join(', ')}`);
  } catch (error) {
    console.log(`${type}: Error reading schema - ${error.message}`);
  }
});

console.log('\n✅ Schema definitions checked');