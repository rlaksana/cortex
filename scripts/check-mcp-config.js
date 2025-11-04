#!/usr/bin/env node

/**
 * Check MCP Configuration Script
 *
 * This script validates the MCP server configuration to ensure it follows
 * the required format and doesn't have conflicting Cortex configurations.
 */

import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🔍 Checking MCP configuration...');

function checkMcpConfig() {
  try {
    // Check for common MCP configuration locations
    const possibleConfigPaths = [
      join(process.env.HOME || '', '.claude_desktop_config.json'),
      join(process.env.HOME || '', '.config', 'claude', 'claude_desktop_config.json'),
      join(process.env.USERPROFILE || '', 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json')
    ];

    let configPath = null;
    let config = null;

    // Find the configuration file
    for (const path of possibleConfigPaths) {
      if (existsSync(path)) {
        configPath = path;
        try {
          config = JSON.parse(readFileSync(path, 'utf8'));
          break;
        } catch (error) {
          console.warn(`⚠️  Found config at ${path} but couldn't parse it`);
        }
      }
    }

    if (!config) {
      console.log('ℹ️  No MCP configuration file found');
      console.log('   This is normal if you haven\'t configured Claude Desktop yet');
      return true;
    }

    console.log(`📁 Found MCP configuration at: ${configPath}`);

    // Check for Cortex configuration issues
    const cortexServers = Object.keys(config.mcpServers || {})
      .filter(key => key.toLowerCase().includes('cortex'));

    if (cortexServers.length === 0) {
      console.log('ℹ️  No Cortex MCP server configuration found');
      return true;
    }

    if (cortexServers.length > 1) {
      console.log('❌ CRITICAL: Multiple Cortex MCP configurations found!');
      console.log('   This violates the single Cortex configuration rule');
      cortexServers.forEach(server => {
        console.log(`   - ${server}`);
      });
      return false;
    }

    const cortexServer = cortexServers[0];
    if (cortexServer !== 'cortex') {
      console.log('⚠️  Warning: Cortex server should be named exactly "cortex"');
      console.log(`   Current name: "${cortexServer}"`);
    }

    console.log('✅ MCP configuration is valid');
    console.log(`   Cortex server: ${cortexServer}`);
    return true;

  } catch (error) {
    console.error('❌ Error checking MCP configuration:', error.message);
    return false;
  }
}

const isValid = checkMcpConfig();
process.exit(isValid ? 0 : 1);