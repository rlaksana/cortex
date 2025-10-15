#!/usr/bin/env tsx

/**
 * MCP Cortex Smoke Test
 *
 * Quick 5-minute test to verify basic functionality
 * Run this BEFORE full test suite
 *
 * Usage: npm run test:smoke
 */

import { Pool, Client } from 'pg';
import net from 'net';
import { loadEnv } from '../../src/config/env.js';

// Load environment
loadEnv();

const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
  yellow: '\x1b[33m',
  magenta: '\x1b[35m',
};

const success = (msg: string) => console.log(`${colors.green}✅ ${msg}${colors.reset}`);
const failure = (msg: string) => console.log(`${colors.red}❌ ${msg}${colors.reset}`);
const info = (msg: string) => console.log(`${colors.cyan}🔍 ${msg}${colors.reset}`);
const section = (msg: string) => {
  console.log(`\n${colors.magenta}${'='.repeat(63)}${colors.reset}`);
  console.log(`${colors.magenta} ${msg}${colors.reset}`);
  console.log(`${colors.magenta}${'='.repeat(63)}${colors.reset}`);
};

const DB_CONFIG = {
  connectionString:
    process.env.DATABASE_URL || 'postgresql://cortex:trust@localhost:5433/cortex_prod',
};

// Test configuration
const TEST_CONFIG = {
  timeout: 5000, // 5 second timeout for tests
};

async function runSmokeTests() {
  let testsPassed = 0;
  let testsFailed = 0;

  section('MCP CORTEX SMOKE TEST');
  console.log(`${colors.yellow}Quick validation of core functionality${colors.reset}\n`);

  // Test 1: TCP Connection
  section('[1/5] TCP CONNECTION');
  try {
    const url = new URL(DB_CONFIG.connectionString);
    await new Promise<void>((resolve, reject) => {
      const socket = net.createConnection(
        { host: url.hostname, port: parseInt(url.port, 10) },
        () => {
          socket.end();
          resolve();
        }
      );
      socket.on('error', reject);
      socket.setTimeout(5000, () => {
        socket.destroy();
        reject(new Error('Timeout'));
      });
    });

    success('TCP connection successful');
    testsPassed++;
  } catch (err) {
    failure(`TCP connection failed: ${err}`);
    testsFailed++;
    console.log(
      `${colors.yellow}\nCannot proceed without connectivity. Please check:${colors.reset}`
    );
    console.log('  1. Server is running: wsl docker-compose ps');
    console.log('  2. Port forwarding: netsh interface portproxy show v4tov4');
    console.log('  3. Firewall allows port 5433\n');
    process.exit(1);
  }

  // Test 2: Authentication
  section('[2/5] AUTHENTICATION');
  let client: Client | null = null;
  try {
    client = new Client(DB_CONFIG);
    await client.connect();
    success('PostgreSQL authentication successful');
    testsPassed++;
  } catch (err) {
    failure(`Authentication failed: ${err}`);
    testsFailed++;
    console.log(`${colors.yellow}\nPlease check:${colors.reset}`);
    console.log('  1. DATABASE_URL is correct');
    console.log('  2. Password is correct\n');
    process.exit(1);
  }

  // Test 3: Simple Query
  section('[3/5] SIMPLE QUERY');
  try {
    const result = await client!.query('SELECT version()');
    success(`Query executed: PostgreSQL ${result.rows[0].version.split(',')[0]}`);
    testsPassed++;
  } catch (err) {
    failure(`Query failed: ${err}`);
    testsFailed++;
  } finally {
    await client?.end();
  }

  // Test 4: Check Tables Exist
  section('[4/5] CHECK TABLES');
  const pool = new Pool(DB_CONFIG);
  try {
    const result = await pool.query(`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = 'public'
      ORDER BY table_name
    `);

    const tables = result.rows.map((r) => r.table_name);
    success(`Found ${tables.length} tables: ${tables.join(', ')}`);
    testsPassed++;
  } catch (err) {
    failure(`Table check failed: ${err}`);
    testsFailed++;
  }

  // Test 5: Test Write Operation
  section('[5/5] TEST WRITE');
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS smoke_test (
        id SERIAL PRIMARY KEY,
        test_data TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    const insertResult = await pool.query(
      `INSERT INTO smoke_test (test_data) VALUES ($1) RETURNING id`,
      ['Smoke test data']
    );

    const selectResult = await pool.query(`SELECT * FROM smoke_test WHERE id = $1`, [
      insertResult.rows[0].id,
    ]);

    await pool.query(`DROP TABLE smoke_test`);

    if (selectResult.rows.length > 0) {
      success(`Write/Read test passed (ID: ${insertResult.rows[0].id})`);
      testsPassed++;
    } else {
      failure('Write/Read test failed');
      testsFailed++;
    }
  } catch (err) {
    failure(`Write test failed: ${err}`);
    testsFailed++;
  } finally {
    await pool.end();
  }

  // Summary
  section('SUMMARY');
  console.log('');
  console.log(`Tests Passed: ${colors.green}${testsPassed}${colors.reset}/5`);
  console.log(`Tests Failed: ${colors.red}${testsFailed}${colors.reset}/5`);
  console.log('');

  if (testsPassed === 5) {
    console.log(
      `${colors.green}${colors.reset}✅✅✅ ALL SMOKE TESTS PASSED ✅✅✅${colors.reset}\n`
    );
    console.log(`${colors.green}MCP Cortex is working correctly!${colors.reset}`);
    console.log(
      `${colors.cyan}You can now run the full test suite: npm run test:functional${colors.reset}\n`
    );
    process.exit(0);
  } else {
    console.log(`${colors.red}❌ SMOKE TESTS FAILED${colors.reset}\n`);
    console.log(
      `${colors.yellow}Please fix the issues above before running full tests${colors.reset}\n`
    );
    process.exit(1);
  }

  // No cleanup needed - smoke test uses temporary table
}

// Run tests
runSmokeTests().catch((err) => {
  console.error(`${colors.red}Unexpected error:${colors.reset}`, err);
  process.exit(1);
});
