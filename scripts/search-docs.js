#!/usr/bin/env node

/**
 * Search Documentation Script
 *
 * This script provides search functionality for the documentation.
 * It can search through all markdown files for specific terms.
 */

import { readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Get search term from command line arguments
const searchTerm = process.argv[2];

if (!searchTerm) {
  console.log('🔍 Documentation Search Tool');
  console.log('Usage: node search-docs.js <search-term>');
  console.log('');
  console.log('Examples:');
  console.log('  node search-docs.js "API reference"');
  console.log('  node search-docs.js "Qdrant"');
  console.log('  node search-docs.js "setup"');
  process.exit(0);
}

console.log(`🔍 Searching documentation for: "${searchTerm}"`);

function searchInDocs() {
  try {
    const docsPath = join(__dirname, '..', 'docs');
    const results = [];

    function searchDirectory(dir, relativePath = '') {
      const items = readdirSync(dir);

      for (const item of items) {
        const itemPath = join(dir, item);
        const itemRelativePath = join(relativePath, item);
        const stat = statSync(itemPath);

        if (stat.isDirectory()) {
          searchDirectory(itemPath, itemRelativePath);
        } else if (item.endsWith('.md')) {
          try {
            const content = readFileSync(itemPath, 'utf8');
            const lines = content.split('\n');

            for (let i = 0; i < lines.length; i++) {
              const line = lines[i].toLowerCase();
              if (line.includes(searchTerm.toLowerCase())) {
                results.push({
                  file: itemRelativePath,
                  lineNumber: i + 1,
                  line: lines[i].trim()
                });
              }
            }
          } catch (error) {
            console.warn(`⚠️  Could not read ${itemRelativePath}: ${error.message}`);
          }
        }
      }
    }

    searchDirectory(docsPath);

    if (results.length === 0) {
      console.log(`❌ No results found for "${searchTerm}"`);
    } else {
      console.log(`✅ Found ${results.length} result(s):`);
      console.log('');

      results.forEach(result => {
        console.log(`📄 ${result.file}:${result.lineNumber}`);
        console.log(`   ${result.line}`);
        console.log('');
      });
    }

  } catch (error) {
    console.error('❌ Error searching documentation:', error.message);
    process.exit(1);
  }
}

searchInDocs();