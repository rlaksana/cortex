#!/usr/bin/env node

/**
 * Silent MCP Entry Point - Phase-Based Approach
 *
 * This entry point implements a phase-based stdout redirection strategy:
 * Phase 1: During startup (configurable timeout), redirect stdout to stderr
 * Phase 2: After startup, restore stdout for complete MCP protocol transparency
 *
 * This eliminates JSON-RPC message detection entirely, ensuring no protocol
 * interference during handshake, especially for sensitive clients like Codex CLI.
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Configuration
const STARTUP_TIMEOUT_MS = 5000; // 5 seconds for startup phase

// Store original write functions
const originalStdoutWrite = process.stdout.write;
const originalStderrWrite = process.stderr.write;

// State management
let isInStartupPhase = true;
let startupTimer: NodeJS.Timeout | null = null;

// Restore original stdout function
function restoreStdout(): void {
  if (!isInStartupPhase) return;

  isInStartupPhase = false;
  if (startupTimer) {
    clearTimeout(startupTimer);
    startupTimer = null;
  }

  // Restore original stdout write function
  process.stdout.write = originalStdoutWrite;

  // Optional: Log to stderr that we're in protocol mode
  originalStderrWrite.call(process.stderr, '[MCP-WRAPPER] Startup phase completed, protocol mode enabled\n');
}

// Phase-based stdout interception
process.stdout.write = function (
  str: string | Uint8Array,
  encoding?: any,
  cb?: (_err?: Error | null) => void
): boolean {
  // If we're past startup phase, use original stdout directly
  if (!isInStartupPhase) {
    return originalStdoutWrite.call(process.stdout, str, encoding, cb);
  }

  // During startup phase, redirect everything to stderr
  const args = [str, encoding, cb].filter((arg) => arg !== undefined) as [
    string | Uint8Array,
    any,
    ((_err?: Error | null) => void) | undefined,
  ];

  return originalStderrWrite.apply(process.stderr, args);
};

// Start startup timeout timer
startupTimer = setTimeout(restoreStdout, STARTUP_TIMEOUT_MS);

// Start the actual MCP server process
const serverPath = join(__dirname, 'index');
const child = spawn('node', [serverPath], {
  stdio: 'inherit',
  env: process.env,
});

// Signal handling for graceful termination
function handleSignal(signal: string): void {
  originalStderrWrite.call(process.stderr, `[MCP-WRAPPER] Received ${signal}, shutting down gracefully\n`);

  // Restore stdout before shutdown to ensure proper cleanup
  restoreStdout();

  // Forward signal to child process
  if (child && !child.killed) {
    child.kill(signal as NodeJS.Signals);
  }

  // Force exit after timeout if child doesn't terminate
  setTimeout(() => {
    process.exit(1);
  }, 3000);
}

// Register signal handlers
process.on('SIGINT', () => handleSignal('SIGINT'));
process.on('SIGTERM', () => handleSignal('SIGTERM'));
process.on('SIGHUP', () => handleSignal('SIGHUP'));

// Child process event handlers
child.on('error', (error) => {
  originalStderrWrite.call(process.stderr, `Failed to start MCP server: ${error.message}\n`);
  process.exit(1);
});

child.on('close', (code) => {
  // Restore stdout before exit
  restoreStdout();
  process.exit(code || 0);
});

// Handle process exit to ensure cleanup
process.on('exit', () => {
  restoreStdout();
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  originalStderrWrite.call(process.stderr, `Uncaught exception: ${error.message}\n`);
  restoreStdout();
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  originalStderrWrite.call(process.stderr, `Unhandled rejection at: ${promise}, reason: ${reason}\n`);
  restoreStdout();
  process.exit(1);
});
