#!/usr/bin/env node

/**
 * Silent MCP Entry Point — Protocol-Safe Passthrough
 *
 * Fix: Remove stdout interception that delayed/redirected JSON-RPC handshake
 * and start the minimal high‑level server directly. This prevents Codex hangs.
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Target the minimal, quiet entry that only emits MCP protocol on stdout
const serverPath = join(__dirname, 'index-high-level-api');

// Ensure noisy logs do not hit stdout (server logs go to stderr by design)
const env = { ...process.env, LOG_LEVEL: process.env.LOG_LEVEL || 'error', NODE_ENV: process.env.NODE_ENV || 'production' };

const child = spawn('node', [serverPath], {
  stdio: ['inherit', 'inherit', 'inherit'],
  env,
});

function handleSignal(signal: NodeJS.Signals) {
  // Gracefully forward to child; rely on server's handlers
  if (!child.killed) child.kill(signal);
  // Failsafe exit after 3s
  setTimeout(() => process.exit(0), 3000).unref();
}

process.on('SIGINT', () => handleSignal('SIGINT'));
process.on('SIGTERM', () => handleSignal('SIGTERM'));
process.on('SIGHUP', () => handleSignal('SIGHUP'));

child.on('exit', (code) => process.exit(code ?? 0));
child.on('error', (err) => {
  console.error(`[MCP-WRAPPER] Failed to start: ${err?.message || err}`);
  process.exit(1);
});
