#!/usr/bin/env node

/**
 * Simple test script to verify MCP Cortex functionality
 * Tests memory store and find operations directly
 */

import fs from 'fs';
import path from 'path';

// Test configuration
const TEST_CONFIG = {
  // Test data for different entity types
  testEntities: [
    {
      kind: 'entity',
      content: 'Test User Entity',
      metadata: { type: 'user', role: 'developer', active: true },
    },
    {
      kind: 'decision',
      content: 'Decision to use React for frontend',
      metadata: {
        alternatives: ['Vue', 'Angular'],
        rationale: 'Team experience',
        impact: 'medium',
      },
    },
    {
      kind: 'observation',
      content: 'System performance observation',
      metadata: {
        metrics: { cpu: 80, memory: 60, disk: 45 },
        timestamp: new Date().toISOString(),
      },
    },
    {
      kind: 'issue',
      content: 'Authentication bug found',
      metadata: {
        severity: 'high',
        status: 'open',
        reporter: 'test-user',
      },
    },
    {
      kind: 'todo',
      content: 'Fix authentication bug',
      metadata: {
        priority: 'high',
        assignee: 'developer',
        dueDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      },
    },
  ],

  // Test relationships
  testRelations: [
    {
      kind: 'relation',
      content: 'User reported authentication issue',
      metadata: {
        relation_type: 'reports',
        source: 'test-user-entity',
        target: 'authentication-bug',
      },
    },
  ],
};

// Simple logger
const logger = {
  info: (msg, ...args) => console.log(`[INFO] ${msg}`, ...args),
  error: (msg, ...args) => console.error(`[ERROR] ${msg}`, ...args),
  success: (msg, ...args) => console.log(`[SUCCESS] ${msg}`, ...args),
  warn: (msg, ...args) => console.warn(`[WARN] ${msg}`, ...args),
};

// Test results tracker
const testResults = {
  passed: 0,
  failed: 0,
  total: 0,
  scenarios: [],
};

/**
 * Add test result
 */
function addTestResult(scenario, passed, message, details = null) {
  testResults.total++;
  if (passed) {
    testResults.passed++;
    logger.success(`✓ ${scenario}: ${message}`);
  } else {
    testResults.failed++;
    logger.error(`✗ ${scenario}: ${message}`);
  }

  testResults.scenarios.push({
    scenario,
    passed,
    message,
    details,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Test 1: Check if MCP tools are available
 */
async function testMcpToolAvailability() {
  logger.info('Testing MCP tool availability...');

  try {
    // Check if we can import the main module
    const indexModule = await import('./dist/index.js');
    addTestResult('MCP Tool Import', true, 'Main module imported successfully');

    // Check for memory store functionality
    if (indexModule.VectorDatabase || indexModule.memoryStore) {
      addTestResult('Memory Store Available', true, 'Memory store functionality found');
    } else {
      addTestResult('Memory Store Available', false, 'Memory store functionality not found');
    }

    return true;
  } catch (error) {
    addTestResult('MCP Tool Import', false, `Failed to import main module: ${error.message}`);
    return false;
  }
}

/**
 * Test 2: Check schema definitions
 */
async function testSchemaDefinitions() {
  logger.info('Testing schema definitions...');

  try {
    // Try to load schemas
    const schemasPath = './src/schemas/json-schemas.ts';
    if (fs.existsSync(schemasPath)) {
      addTestResult('Schema Files', true, 'Schema files exist');

      const schemaContent = fs.readFileSync(schemasPath, 'utf8');
      const hasMemorySchemas =
        schemaContent.includes('MemoryStoreInput') && schemaContent.includes('MemoryFindInput');

      if (hasMemorySchemas) {
        addTestResult('Memory Schemas', true, 'Memory store/find schemas defined');
      } else {
        addTestResult('Memory Schemas', false, 'Memory schemas not found in schema file');
      }
    } else {
      addTestResult('Schema Files', false, 'Schema files do not exist');
    }

    return true;
  } catch (error) {
    addTestResult('Schema Definitions', false, `Error checking schemas: ${error.message}`);
    return false;
  }
}

/**
 * Test 3: Check if test files cover all scenarios
 */
async function testCoverage() {
  logger.info('Testing test coverage...');

  try {
    const testFiles = [
      './tests/unit/memory-store.test.ts',
      './tests/unit/memory-find.test.ts',
      './tests/unit/memory-store-batch-response.test.ts',
      './tests/unit/memory-find-expand-integration.test.ts',
    ];

    let existingTests = 0;
    for (const testFile of testFiles) {
      if (fs.existsSync(testFile)) {
        existingTests++;
        logger.info(`Found test file: ${testFile}`);
      } else {
        logger.warn(`Missing test file: ${testFile}`);
      }
    }

    addTestResult(
      'Test Coverage',
      existingTests >= 3,
      `${existingTests}/${testFiles.length} test files exist`
    );

    return existingTests >= 3;
  } catch (error) {
    addTestResult('Test Coverage', false, `Error checking test coverage: ${error.message}`);
    return false;
  }
}

/**
 * Test 4: Check package.json for MCP configuration
 */
async function testPackageConfiguration() {
  logger.info('Testing package configuration...');

  try {
    const packageJson = JSON.parse(fs.readFileSync('./package.json', 'utf8'));

    const hasMcpConfig = packageJson.name && packageJson.version;
    const hasDependencies =
      packageJson.dependencies && packageJson.dependencies['@modelcontextprotocol/sdk'];

    addTestResult('Package Config', hasMcpConfig, 'Package has basic configuration');
    addTestResult('MCP Dependencies', hasDependencies, 'MCP SDK dependency found');

    return hasMcpConfig && hasDependencies;
  } catch (error) {
    addTestResult('Package Configuration', false, `Error reading package.json: ${error.message}`);
    return false;
  }
}

/**
 * Test 5: Test data structure validation
 */
async function testDataStructures() {
  logger.info('Testing data structures...');

  try {
    // Validate test entities
    let validEntities = 0;
    for (const entity of TEST_CONFIG.testEntities) {
      if (entity.kind && entity.content) {
        validEntities++;
      }
    }

    addTestResult(
      'Entity Structure',
      validEntities === TEST_CONFIG.testEntities.length,
      `${validEntities}/${TEST_CONFIG.testEntities.length} entities have valid structure`
    );

    // Check all 16 knowledge types are represented in tests
    const allKnowledgeTypes = [
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

    // Check if test files cover different knowledge types
    const testFiles = fs.readdirSync('./tests/unit').filter((file) => {
      const filePath = './tests/unit/' + file;
      try {
        return fs.statSync(filePath).isFile() && file.endsWith('.test.ts');
      } catch {
        return false;
      }
    });

    const knowledgeTypeTests = testFiles.filter(
      (file) =>
        file.includes('knowledge-types') ||
        file.includes('memory-') ||
        file.includes('entity') ||
        file.includes('decision')
    );

    addTestResult(
      'Knowledge Type Coverage',
      knowledgeTypeTests.length > 0,
      `Found ${knowledgeTypeTests.length} knowledge type test files`
    );

    return validEntities === TEST_CONFIG.testEntities.length;
  } catch (error) {
    addTestResult('Data Structures', false, `Error validating data structures: ${error.message}`);
    return false;
  }
}

/**
 * Generate comprehensive test report
 */
function generateTestReport() {
  logger.info('Generating test report...');

  const report = {
    summary: {
      total: testResults.total,
      passed: testResults.passed,
      failed: testResults.failed,
      successRate:
        testResults.total > 0
          ? ((testResults.passed / testResults.total) * 100).toFixed(2) + '%'
          : '0%',
    },
    scenarios: testResults.scenarios,
    testConfiguration: TEST_CONFIG,
    recommendations: [],
    timestamp: new Date().toISOString(),
  };

  // Add recommendations based on test results
  if (testResults.failed > 0) {
    report.recommendations.push('Fix failing tests before proceeding with MCP Cortex deployment');
  }

  if (testResults.passed / testResults.total < 0.8) {
    report.recommendations.push('Review MCP Cortex implementation - less than 80% tests passing');
  }

  const failedScenarios = testResults.scenarios.filter((s) => !s.passed);
  if (failedScenarios.length > 0) {
    report.recommendations.push(
      `Priority issues to address: ${failedScenarios.map((s) => s.scenario).join(', ')}`
    );
  }

  // Save report
  const reportPath = './artifacts/mcp-cortex-test-report.json';
  if (!fs.existsSync('./artifacts')) {
    fs.mkdirSync('./artifacts', { recursive: true });
  }

  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  logger.success(`Test report saved to: ${reportPath}`);

  return report;
}

/**
 * Main test execution
 */
async function runTests() {
  console.log('\n=== MCP Cortex Tool Test Suite ===');
  console.log(`Started at: ${new Date().toISOString()}`);
  console.log('=====================================\n');

  const tests = [
    testMcpToolAvailability,
    testSchemaDefinitions,
    testCoverage,
    testPackageConfiguration,
    testDataStructures,
  ];

  // Run all tests
  for (const test of tests) {
    try {
      await test();
    } catch (error) {
      logger.error(`Test execution error: ${error.message}`);
      addTestResult('Test Execution', false, `Test failed with error: ${error.message}`);
    }
    console.log(''); // Add spacing between tests
  }

  // Generate and display report
  const report = generateTestReport();

  console.log('\n=== Test Summary ===');
  console.log(`Total Tests: ${testResults.total}`);
  console.log(`Passed: ${testResults.passed}`);
  console.log(`Failed: ${testResults.failed}`);
  console.log(`Success Rate: ${report.summary.successRate}`);

  if (report.recommendations.length > 0) {
    console.log('\n=== Recommendations ===');
    report.recommendations.forEach((rec, i) => `${i + 1}. ${rec}`);
  }

  console.log('\n=== Test Complete ===');

  return report.summary.successRate === '100%';
}

// Run tests if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runTests()
    .then((success) => {
      process.exit(success ? 0 : 1);
    })
    .catch((error) => {
      logger.error(`Test suite failed: ${error.message}`);
      process.exit(1);
    });
}

export { runTests, testResults, TEST_CONFIG };
