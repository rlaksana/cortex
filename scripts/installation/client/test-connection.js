#!/usr/bin/env node

/**
 * MCP Cortex Connection Tester
 *
 * Tests connectivity to MCP Cortex PostgreSQL server
 *
 * Usage:
 *   node test-connection.js <server-ip> [port] [password]
 *   node test-connection.js 192.168.1.100 5433 my-password
 *
 * Version: 1.0.0
 */

import net from 'net';
import { Client } from 'pg';

// ANSI colors
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
};

// Output functions
const success = (msg) => console.log(`${colors.green}✅ ${msg}${colors.reset}`);
const failure = (msg) => console.log(`${colors.red}❌ ${msg}${colors.reset}`);
const info = (msg) => console.log(`${colors.cyan}🔍 ${msg}${colors.reset}`);
const warning = (msg) => console.log(`${colors.yellow}⚠️  ${msg}${colors.reset}`);
const section = (msg) => {
  console.log(`\n${colors.magenta}${'='.repeat(63)}${colors.reset}`);
  console.log(`${colors.magenta} ${msg}${colors.reset}`);
  console.log(`${colors.magenta}${'='.repeat(63)}${colors.reset}`);
};

// Parse arguments
const args = process.argv.slice(2);

if (args.length < 1) {
  failure('Usage: node test-connection.js <server-ip> [port] [password]');
  info('Example: node test-connection.js 192.168.1.100 5433 my-password');
  process.exit(1);
}

const serverIP = args[0];
const port = parseInt(args[1] || '5433', 10);
const password = args[2] || '';

section('MCP CORTEX CONNECTION TESTER');
console.log(`${colors.yellow}Testing connection to MCP Cortex server${colors.reset}\n`);

// Test results
const results = {
  tcpConnection: false,
  databaseConnection: false,
  queryExecution: false,
};

/**
 * Test 1: TCP Connection
 */
async function testTCPConnection() {
  section('[1] TCP CONNECTION TEST');

  return new Promise((resolve) => {
    info(`Testing TCP connection to ${serverIP}:${port}...`);

    const socket = new net.Socket();
    const timeout = setTimeout(() => {
      socket.destroy();
      failure(`Connection timeout (5 seconds)`);
      failure(`Cannot reach ${serverIP}:${port}`);
      console.log('\nPossible issues:');
      console.log('  1. Server IP is incorrect');
      console.log('  2. Server is not running');
      console.log('  3. Firewall blocking port');
      console.log('  4. Not on same network');
      results.tcpConnection = false;
      resolve(false);
    }, 5000);

    socket.connect(port, serverIP, () => {
      clearTimeout(timeout);
      socket.destroy();
      success(`TCP connection successful to ${serverIP}:${port}`);
      results.tcpConnection = true;
      resolve(true);
    });

    socket.on('error', (err) => {
      clearTimeout(timeout);
      failure(`TCP connection failed: ${err.message}`);
      results.tcpConnection = false;
      resolve(false);
    });
  });
}

/**
 * Test 2: Database Connection
 */
async function testDatabaseConnection() {
  section('[2] DATABASE CONNECTION TEST');

  if (!password) {
    warning('No password provided - skipping database authentication test');
    info('To test database auth, provide password as 3rd argument');
    return false;
  }

  const connectionString = `postgresql://cortex:${password}@${serverIP}:${port}/cortex_prod`;

  info('Testing PostgreSQL authentication...');

  const client = new Client({
    connectionString,
    connectionTimeoutMillis: 5000,
  });

  try {
    await client.connect();
    success('Database connection successful');
    success('Authentication verified');
    results.databaseConnection = true;

    // Test 3: Query execution
    section('[3] QUERY EXECUTION TEST');
    info('Testing query execution...');

    const res = await client.query('SELECT version()');
    success('Query executed successfully');
    info(`PostgreSQL version: ${res.rows[0].version.split(',')[0]}`);
    results.queryExecution = true;

    await client.end();
    return true;

  } catch (err) {
    failure(`Database connection failed: ${err.message}`);

    if (err.code === 'ECONNREFUSED') {
      console.log('\nPossible issues:');
      console.log('  1. PostgreSQL is not running');
      console.log('  2. Port forwarding not configured');
    } else if (err.code === '28P01') {
      console.log('\nAuthentication failed:');
      console.log('  1. Incorrect password');
      console.log('  2. Check password with administrator');
    } else if (err.code === '3D000') {
      console.log('\nDatabase does not exist:');
      console.log('  1. Server not properly initialized');
      console.log('  2. Contact administrator');
    }

    results.databaseConnection = false;
    results.queryExecution = false;
    return false;
  }
}

/**
 * Main test runner
 */
async function runTests() {
  try {
    const tcpOk = await testTCPConnection();

    if (!tcpOk) {
      section('TEST SUMMARY');
      failure('TCP connection failed - cannot proceed with database tests');
      process.exit(1);
    }

    await testDatabaseConnection();

    // Final summary
    section('TEST SUMMARY');
    console.log('');
    console.log(`TCP Connection:        ${results.tcpConnection ? colors.green + '✅ PASS' : colors.red + '❌ FAIL'}${colors.reset}`);
    console.log(`Database Connection:   ${results.databaseConnection ? colors.green + '✅ PASS' : colors.red + '❌ FAIL'}${colors.reset}`);
    console.log(`Query Execution:       ${results.queryExecution ? colors.green + '✅ PASS' : colors.red + '❌ FAIL'}${colors.reset}`);
    console.log('');

    if (results.tcpConnection && results.databaseConnection && results.queryExecution) {
      console.log(`${colors.green}${colors.bright}✅✅✅ ALL TESTS PASSED ✅✅✅${colors.reset}\n`);
      console.log(`${colors.green}MCP Cortex server is fully accessible!${colors.reset}`);
      console.log(`${colors.cyan}You can now use MCP Cortex in Claude Desktop${colors.reset}\n`);
      process.exit(0);
    } else {
      console.log(`${colors.red}${colors.bright}❌ SOME TESTS FAILED${colors.reset}\n`);
      console.log(`${colors.yellow}Please check the error messages above and:${colors.reset}`);
      console.log('  1. Verify server IP and port');
      console.log('  2. Confirm server is running');
      console.log('  3. Check firewall settings');
      console.log('  4. Contact administrator if needed\n');
      process.exit(1);
    }

  } catch (err) {
    section('UNEXPECTED ERROR');
    failure(`Test failed with unexpected error: ${err.message}`);
    console.error(err);
    process.exit(1);
  }
}

// Run tests
runTests();
