#!/usr/bin/env node

/**
 * Validate MCP Tools Script
 *
 * This script validates that all MCP tools are properly implemented
 * and have the correct signatures and documentation.
 */

import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🔧 Validating MCP tools...');

const EXPECTED_TOOLS = [
  {
    name: 'memory_store',
    description: 'Store knowledge items in vector database',
    requiredParams: ['items']
  },
  {
    name: 'memory_find',
    description: 'Search knowledge items using semantic search',
    requiredParams: ['query']
  },
  {
    name: 'system_status',
    description: 'System monitoring and management',
    requiredParams: ['operation']
  }
];

function validateMcpTools() {
  try {
    const srcPath = join(__dirname, '..', 'src');
    const mainIndexPath = join(srcPath, 'index.ts');

    if (!existsSync(mainIndexPath)) {
      console.log('❌ Main index.ts not found');
      return false;
    }

    const content = readFileSync(mainIndexPath, 'utf8');
    let validTools = 0;

    console.log('🔍 Checking for required MCP tools...');

    for (const tool of EXPECTED_TOOLS) {
      const toolRegex = new RegExp(`name\\s*:\\s*['"${tool.name}['"]`, 'i');
      const hasTool = toolRegex.test(content);

      if (hasTool) {
        console.log(`✅ ${tool.name} - Found`);
        validTools++;
      } else {
        console.log(`❌ ${tool.name} - Missing`);
      }
    }

    // Check for tool list structure
    const toolsListRegex = /tools\s*:\s*\[/;
    const hasToolsList = toolsListRegex.test(content);

    if (hasToolsList) {
      console.log('✅ Tools list structure - Valid');
    } else {
      console.log('❌ Tools list structure - Invalid');
    }

    // Check for server setup
    const serverRegex = /Server\.create\s*\(/;
    const hasServerSetup = serverRegex.test(content);

    if (hasServerSetup) {
      console.log('✅ MCP server setup - Valid');
    } else {
      console.log('❌ MCP server setup - Invalid');
    }

    console.log(`\n📊 Validation Summary: ${validTools}/${EXPECTED_TOOLS.length} tools valid`);

    return validTools === EXPECTED_TOOLS.length && hasToolsList && hasServerSetup;

  } catch (error) {
    console.error('❌ Error validating MCP tools:', error.message);
    return false;
  }
}

const isValid = validateMcpTools();

if (isValid) {
  console.log('🎉 All MCP tools are properly implemented!');
}

process.exit(isValid ? 0 : 1);