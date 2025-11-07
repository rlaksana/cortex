/**
 * Test Profile Setup for MCP Cortex Memory
 *
 * This file sets up the mandatory test profile with mocked embedding service
 * for CI/CD environments and ensures consistent testing across all environments.
 */

import { config } from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Get the directory name
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load test configuration
export function setupTestProfile() {
  // Load base environment variables
  config({ path: path.join(__dirname, '../../.env.test.example') });

  // Override with test-specific settings
  process.env['NODE_ENV'] = 'test';
  process.env['LOG_LEVEL'] = 'error';
  process.env['MOCK_EXTERNAL_SERVICES'] = 'true';
  process.env['SEMANTIC_CHUNKING_OPTIONAL'] = 'true';
  process.env['ENABLE_CACHING'] = 'false';
  process.env['ENABLE_METRICS'] = 'false';
  process.env['ENABLE_AUTH'] = 'false';
  process.env['ENABLE_LOGGING'] = 'true';

  // Test database configuration
  process.env['QDRANT_URL'] = process.env['QDRANT_URL'] || 'http://localhost:6333';
  process.env['QDRANT_COLLECTION_NAME'] = 'cortex-test';
  process.env['VECTOR_SIZE'] = '1536';
  process.env['EMBEDDING_MODEL'] = 'text-embedding-ada-002';
  process.env['EMBEDDING_BATCH_SIZE'] = '10';

  // Mock service configuration
  process.env['MOCK_EMBEDDING_SERVICE'] = 'true';
  process.env['MOCK_EMBEDDING_DETERMINISTIC'] = 'true';
  process.env['MOCK_EMBEDDING_DIMENSION'] = '1536';
  process.env['MOCK_EMBEDDING_LATENCY'] = '0';
  process.env['MOCK_EMBEDDING_SHOULD_FAIL'] = 'false';

  // Test execution settings
  process.env['TEST_TIMEOUT'] = '30000';
  process.env['TEST_RETRIES'] = '3';
  process.env['TEST_PARALLEL'] = 'true';
  process.env['TEST_ISOLATION'] = 'true';

  // CI/CD specific settings
  const isCI = process.env['CI'] === 'true' || process.env['GITHUB_ACTIONS'] === 'true';
  if (isCI) {
    process.env['TEST_HEADLESS'] = 'true';
    process.env['TEST_NO_INTERACTION'] = 'true';
    process.env['TEST_FAIL_FAST'] = 'true';
    process.env['TEST_MAX_WORKERS'] = '4';
  }

  return {
    isCI,
    testConfig: {
      environment: process.env['NODE_ENV'],
      mockEmbedding: process.env['MOCK_EMBEDDING_SERVICE'] === 'true',
      semanticChunkingOptional: process.env['SEMANTIC_CHUNKING_OPTIONAL'] === 'true',
      databaseUrl: process.env['QDRANT_URL'],
      collectionName: process.env['QDRANT_COLLECTION_NAME'],
      logLevel: process.env['LOG_LEVEL'],
    },
  };
}

/**
 * Validate that the test profile is properly configured
 */
export function validateTestProfile(): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  // Check required environment variables
  const requiredVars = [
    'NODE_ENV',
    'QDRANT_URL',
    'QDRANT_COLLECTION_NAME',
    'MOCK_EMBEDDING_SERVICE',
  ];

  requiredVars.forEach((varName) => {
    if (!process.env[varName]) {
      errors.push(`Missing required environment variable: ${varName}`);
    }
  });

  // Check values
  if (process.env['NODE_ENV'] !== 'test') {
    errors.push(`NODE_ENV must be 'test', got: ${process.env['NODE_ENV']}`);
  }

  if (process.env['MOCK_EMBEDDING_SERVICE'] !== 'true') {
    errors.push(`MOCK_EMBEDDING_SERVICE must be 'true' for test profile`);
  }

  if (process.env['SEMANTIC_CHUNKING_OPTIONAL'] !== 'true') {
    errors.push(`SEMANTIC_CHUNKING_OPTIONAL should be 'true' to avoid external dependencies`);
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Get test profile information for reporting
 */
export function getTestProfileInfo() {
  return {
    name: 'mcp-cortex-test-profile-with-mocks',
    description: 'Mandatory test profile with mocked embedding service for CI/CD',
    version: '1.0.0',
    environment: process.env['NODE_ENV'],
    mockServices: {
      embedding: process.env['MOCK_EMBEDDING_SERVICE'] === 'true',
      deterministic: process.env['MOCK_EMBEDDING_DETERMINISTIC'] === 'true',
      latency: parseInt(process.env['MOCK_EMBEDDING_LATENCY'] || '0'),
      shouldFail: process.env['MOCK_EMBEDDING_SHOULD_FAIL'] === 'true',
    },
    database: {
      url: process.env['QDRANT_URL'],
      collection: process.env['QDRANT_COLLECTION_NAME'],
      vectorSize: parseInt(process.env['VECTOR_SIZE'] || '1536'),
    },
    features: {
      semanticChunkingOptional: process.env['SEMANTIC_CHUNKING_OPTIONAL'] === 'true',
      cachingEnabled: process.env['ENABLE_CACHING'] === 'true',
      metricsEnabled: process.env['ENABLE_METRICS'] === 'true',
      authEnabled: process.env['ENABLE_AUTH'] === 'true',
    },
    testing: {
      timeout: parseInt(process.env['TEST_TIMEOUT'] || '30000'),
      retries: parseInt(process.env['TEST_RETRIES'] || '3'),
      parallel: process.env['TEST_PARALLEL'] === 'true',
      isolation: process.env['TEST_ISOLATION'] === 'true',
      headless: process.env['TEST_HEADLESS'] === 'true',
      failFast: process.env['TEST_FAIL_FAST'] === 'true',
    },
  };
}

// Auto-setup when imported
setupTestProfile();
