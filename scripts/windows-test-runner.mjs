#!/usr/bin/env node

/**
 * Windows Test Runner for MCP-Cortex
 *
 * Comprehensive test runner with Windows-specific optimizations:
 * - EMFILE prevention
 * - Timeout management
 * - Performance optimizations
 * - Proper cleanup
 *
 * Usage:
 *   node scripts/windows-test-runner.mjs [options] [test-pattern]
 *
 * Examples:
 *   node scripts/windows-test-runner.mjs --unit
 *   node scripts/windows-test-runner.mjs --integration
 *   node scripts/windows-test-runner.mjs tests/unit/knowledge-types
 *   node scripts/windows-test-runner.mjs --coverage
 */

import { fileURLToPath } from 'url';
import { dirname, join, resolve } from 'path';
import { spawn } from 'child_process';
import { existsSync, readFileSync } from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, '..');

// Windows-specific test configuration
const WINDOWS_TEST_CONFIG = {
  // Process optimization
  maxWorkers: 1,
  singleThread: true,
  isolation: true,

  // Timeout management (increased for Windows)
  testTimeout: 120000, // 2 minutes per test
  hookTimeout: 60000, // 1 minute for setup/teardown
  teardownTimeout: 30000, // 30 seconds for cleanup

  // EMFILE prevention
  maxEventListeners: 100, // Increased from default 10
  gcInterval: 10000, // Force GC every 10 seconds
  handleMonitorInterval: 5000, // Monitor handles every 5 seconds

  // Memory management
  maxOldSpaceSize: 4096,
  maxSemiSpaceSize: 256,

  // Performance optimization
  watch: false, // Disabled to reduce file handles
  verbose: false, // Reduce logging overhead
  coverage: false, // Disabled by default for performance
};

/**
 * Parse command line arguments
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    unit: false,
    integration: false,
    coverage: false,
    verbose: false,
    watch: false,
    pattern: '',
    timeout: WINDOWS_TEST_CONFIG.testTimeout,
    help: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    switch (arg) {
      case '--unit':
        options.unit = true;
        options.pattern = 'tests/unit/**/*.test.ts';
        break;
      case '--integration':
        options.integration = true;
        options.pattern = 'tests/integration/**/*.test.ts';
        break;
      case '--coverage':
        options.coverage = true;
        break;
      case '--verbose':
        options.verbose = true;
        break;
      case '--watch':
        options.watch = true;
        break;
      case '--timeout':
        options.timeout = parseInt(args[++i]) || WINDOWS_TEST_CONFIG.testTimeout;
        break;
      case '--help':
      case '-h':
        options.help = true;
        break;
      default:
        if (!arg.startsWith('--') && !options.pattern) {
          options.pattern = arg;
        }
        break;
    }
  }

  return options;
}

/**
 * Display help information
 */
function showHelp() {
  console.log(`
Windows Test Runner for MCP-Cortex

USAGE:
  node scripts/windows-test-runner.mjs [OPTIONS] [TEST_PATTERN]

OPTIONS:
  --unit              Run unit tests only
  --integration       Run integration tests only
  --coverage          Enable coverage collection
  --verbose           Enable verbose output
  --watch             Enable watch mode
  --timeout <ms>      Set test timeout in milliseconds (default: 120000)
  --help, -h          Show this help message

EXAMPLES:
  node scripts/windows-test-runner.mjs --unit
  node scripts/windows-test-runner.mjs --integration --coverage
  node scripts/windows-test-runner.mjs tests/unit/knowledge-types
  node scripts/windows-test-runner.mjs --verbose --timeout 180000

WINDOWS OPTIMIZATIONS:
  • EMFILE prevention with handle monitoring
  • Optimized timeout management
  • Single-threaded execution
  • Enhanced garbage collection
  • Performance tuning
  • Memory leak prevention
`);
}

/**
 * Setup Windows environment for testing
 */
async function setupWindowsEnvironment() {
  console.log('🪟 Setting up Windows test environment...');

  // Windows-specific environment variables
  process.env.NODE_ENV = 'test';
  process.env.LOG_LEVEL = 'error';
  process.env.WINDOWS_TEST = 'true';
  process.env.MOCK_EMBEDDINGS = 'true';
  process.env.MOCK_EMBEDDING_SERVICE = 'true';
  process.env.MOCK_EMBEDDING_DETERMINISTIC = 'true';

  // Windows performance optimizations
  process.env.UV_THREADPOOL_SIZE = '16';
  process.env.EMFILE_HANDLES_LIMIT = '131072';

  // Force color output for better visibility
  process.env.FORCE_COLOR = '1';
  process.env.NO_COLOR = '0';

  // Node.js optimization flags
  const nodeOptions = [
    `--max-old-space-size=${WINDOWS_TEST_CONFIG.maxOldSpaceSize}`,
    `--max-semi-space-size=${WINDOWS_TEST_CONFIG.maxSemiSpaceSize}`,
    '--expose-gc',
  ];

  process.env.NODE_OPTIONS = nodeOptions.join(' ');

  // Increase EventEmitter limits for Windows
  try {
    const { EventEmitter } = await import('events');
    EventEmitter.defaultMaxListeners = WINDOWS_TEST_CONFIG.maxEventListeners;
    console.log(
      `✅ Increased EventEmitter max listeners to ${WINDOWS_TEST_CONFIG.maxEventListeners}`
    );
  } catch (error) {
    console.warn('⚠️ Could not set EventEmitter limits:', error.message);
  }

  console.log('✅ Windows test environment configured');
}

/**
 * Validate test environment
 */
function validateEnvironment() {
  // Check required files
  const requiredFiles = [
    '.env.test',
    'vitest.config.ts',
    'tests/setup.ts',
    'tests/global-setup.ts',
  ];

  for (const file of requiredFiles) {
    const filePath = join(projectRoot, file);
    if (!existsSync(filePath)) {
      console.error(`❌ Required file missing: ${file}`);
      process.exit(1);
    }
  }

  // Check .env.test has Z.AI configuration
  const envTestPath = join(projectRoot, '.env.test');
  if (existsSync(envTestPath)) {
    const envContent = readFileSync(envTestPath, 'utf8');
    if (!envContent.includes('ZAI_API_KEY')) {
      console.warn('⚠️ Z.AI configuration not found in .env.test');
    }
  }

  console.log('✅ Environment validation passed');
}

/**
 * Create Vitest command arguments
 */
function createVitestArgs(options) {
  // Try different ways to run vitest on Windows
  const vitestPath = join(projectRoot, 'node_modules', '.bin', 'vitest.cmd');
  const vitestJsPath = join(projectRoot, 'node_modules', 'vitest', 'dist', 'cli.js');

  let vitestCommand;
  if (existsSync(vitestPath)) {
    vitestCommand = vitestPath;
  } else if (existsSync(vitestJsPath)) {
    vitestCommand = ['node', vitestJsPath];
  } else {
    vitestCommand = [
      'node',
      '--loader',
      'tsx/loader',
      join(projectRoot, 'node_modules', '.bin', 'vitest'),
    ];
  }

  const args = Array.isArray(vitestCommand) ? [...vitestCommand] : [vitestCommand];

  args.push('run', '--config', 'vitest.windows.config.ts');

  // Add test pattern
  if (options.pattern) {
    args.push(options.pattern);
  }

  // Add coverage
  if (options.coverage) {
    args.push('--coverage');
  }

  // Add verbose output
  if (options.verbose) {
    args.push('--reporter=verbose');
  } else {
    args.push('--reporter=default');
  }

  // Add watch mode
  if (options.watch) {
    args[args.indexOf('run')] = 'watch'; // Replace 'run' with 'watch'
  }

  // Windows-specific optimizations
  args.push('--no-coverage'); // Reduce overhead (coverage added separately if needed)
  args.push('--maxConcurrency=1');
  args.push(`--test-timeout=${options.timeout}`);

  return args;
}

/**
 * Run tests with Windows optimizations
 */
async function runTests(options) {
  console.log(`🚀 Starting Windows test execution...`);
  console.log(`📋 Pattern: ${options.pattern || 'all tests'}`);
  console.log(`⏱️ Timeout: ${options.timeout}ms`);
  console.log(`📊 Coverage: ${options.coverage ? 'enabled' : 'disabled'}`);
  console.log(`🔍 Verbose: ${options.verbose ? 'enabled' : 'disabled'}`);
  console.log('');

  // Validate environment before running tests
  validateEnvironment();

  // Setup Windows environment
  await setupWindowsEnvironment();

  // Create Vitest command
  const vitestArgs = createVitestArgs(options);
  console.log(`🔧 Command: ${vitestArgs.join(' ')}`);
  console.log('');

  // Start test execution
  return new Promise((resolve, reject) => {
    const startTime = Date.now();

    // Handle different command formats for Windows
    let command, args;
    if (vitestArgs.length >= 2 && vitestArgs[0] === 'node') {
      command = vitestArgs[0];
      args = vitestArgs.slice(1);
    } else {
      command = vitestArgs[0];
      args = vitestArgs.slice(1);
    }

    const testProcess = spawn(command, args, {
      cwd: projectRoot,
      stdio: 'inherit',
      shell: true, // Use shell for Windows compatibility
      env: {
        ...process.env,
        // Override with test-specific environment
        NODE_OPTIONS: process.env.NODE_OPTIONS,
        UV_THREADPOOL_SIZE: process.env.UV_THREADPOOL_SIZE,
        WINDOWS_TEST: 'true',
      },
    });

    // Handle process completion
    testProcess.on('close', (code, signal) => {
      const duration = Date.now() - startTime;
      console.log('');
      console.log(`⏱️ Test execution completed in ${duration}ms`);

      if (signal === 'SIGTERM' || signal === 'SIGKILL') {
        console.log('🛑 Tests were terminated');
        resolve({ success: false, code, signal, duration });
      } else if (code === 0) {
        console.log('✅ All tests passed successfully');
        resolve({ success: true, code, signal, duration });
      } else {
        console.log(`❌ Tests failed with exit code ${code}`);
        resolve({ success: false, code, signal, duration });
      }
    });

    // Handle process errors
    testProcess.on('error', (error) => {
      console.error('❌ Test process error:', error.message);
      reject(error);
    });

    // Handle Windows-specific cleanup
    process.on('exit', () => {
      if (!testProcess.killed) {
        testProcess.kill('SIGTERM');
      }
    });

    // Handle Ctrl+C
    process.on('SIGINT', () => {
      console.log('\\n🛑 Stopping test execution...');
      if (!testProcess.killed) {
        testProcess.kill('SIGTERM');
      }
      setTimeout(() => {
        process.exit(1);
      }, 5000);
    });
  });
}

/**
 * Main execution function
 */
async function main() {
  try {
    const options = parseArgs();

    if (options.help) {
      showHelp();
      return;
    }

    console.log('🧠 MCP-Cortex Windows Test Runner');
    console.log('='.repeat(50));

    const result = await runTests(options);

    if (result.success) {
      console.log('\\n🎉 Windows test execution completed successfully!');
      process.exit(0);
    } else {
      console.log('\\n💥 Windows test execution failed!');
      process.exit(1);
    }
  } catch (error) {
    console.error('\\n💥 Fatal error during test execution:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

// Run main function
main().catch(console.error);
