#!/usr/bin/env node

/**
 * Silent MCP Entry Point
 *
 * This entry point redirects stdout to stderr during startup to prevent
 * log contamination of the MCP JSON-RPC protocol stdio transport.
 * Only JSON-RPC messages are allowed to pass through stdout.
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Store original write functions
const originalStdoutWrite = process.stdout.write;
const originalStderrWrite = process.stderr.write;

// MCP JSON-RPC message detector
function isJsonRpcMessage(data: string): boolean {
  try {
    const trimmed = data.trim();
    return trimmed.startsWith('{"jsonrpc":"2.0"');
  } catch {
    return false;
  }
}

// Intercept stdout during server startup
process.stdout.write = function (
  str: string | Uint8Array,
  encoding?: any,
  cb?: (_err?: Error | null) => void
): boolean {
  const args = [str, encoding, cb].filter((arg) => arg !== undefined) as [
    string | Uint8Array,
    any,
    ((_err?: Error | null) => void) | undefined,
  ];
  const data = args[0];

  if (typeof data === 'string' && isJsonRpcMessage(data)) {
    // Allow MCP protocol messages to pass through stdout
    return originalStdoutWrite.apply(process.stdout, [str, encoding, cb] as const);
  }

  // Redirect all other output (logs, etc.) to stderr
  return originalStderrWrite.apply(process.stderr, [str, encoding, cb] as const);
};

// Start the actual MCP server process
const serverPath = join(__dirname, 'index');
const child = spawn('node', [serverPath], {
  stdio: 'inherit',
  env: process.env,
});

child.on('error', (error) => {
  process.stderr.write(`Failed to start MCP server: ${error.message}\n`);
  process.exit(1);
});

child.on('close', (code) => {
  process.exit(code || 0);
});
