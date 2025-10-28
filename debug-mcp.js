#!/usr/bin/env node

/**
 * Debug MCP Cortex Server
 * Injects debug logging to identify connection issues
 */

console.log('=== DEBUG: Starting MCP Cortex Debug Server ===');

import('./dist/index.js').then(module => {
  console.log('=== DEBUG: Module loaded successfully ===');

  // Patch the startServer function if it exists
  if (module.startServer) {
    const originalStartServer = module.startServer;
    module.startServer = async function() {
      console.log('=== DEBUG: startServer() called ===');
      try {
        await originalStartServer.call(this);
        console.log('=== DEBUG: startServer() completed successfully ===');
      } catch (error) {
        console.error('=== DEBUG: startServer() failed:', error.message, '===');
        throw error;
      }
    };
  }

  console.log('=== DEBUG: Waiting for auto-start... ===');

}).catch(error => {
  console.error('=== DEBUG: Failed to load module:', error.message, '===');
  process.exit(1);
});