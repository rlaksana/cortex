#!/usr/bin/env node

// Direct test of memoryStore function
import { config } from 'dotenv';
config();

console.log('DATABASE_URL:', process.env.DATABASE_URL);

// Import and test
import('./dist/services/memory-store.js').then(async ({ memoryStore }) => {
  console.log('Testing memory_store directly...');

  const testItem = {
    kind: "entity",
    scope: { project: "mcp-cortex", branch: "001-create-specs-000" },
    data: {
      entity_type: "test_direct",
      name: "direct_test_entity",
      data: { status: "testing", timestamp: new Date().toISOString() }
    }
  };

  try {
    const result = await memoryStore([testItem]);
    console.log('✅ SUCCESS:', JSON.stringify(result, null, 2));
  } catch (error) {
    console.log('❌ ERROR:', error.message);
    console.log('Stack:', error.stack);
  }
}).catch(err => {
  console.log('❌ IMPORT ERROR:', err.message);
});
