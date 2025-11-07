#!/usr/bin/env node

/**
 * Validate Documentation Script
 *
 * This script validates that all documentation files are properly formatted
 * and contain the required sections.
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🔍 Validating Cortex Memory MCP documentation...');

const REQUIRED_SECTIONS = ['# ', '## Overview', '## Usage', '## Examples'];

function validateDocs() {
  try {
    const docsPath = join(__dirname, '..', 'docs');
    const mainDocs = [
      'API-REFERENCE.md',
      'ARCH-SYSTEM.md',
      'SETUP-QUICK-START.md',
      'NEW-ENGINEER-GUIDE.md',
    ];

    let validCount = 0;
    let totalCount = mainDocs.length;

    for (const doc of mainDocs) {
      const docPath = join(docsPath, doc);
      if (existsSync(docPath)) {
        const content = readFileSync(docPath, 'utf8');
        const hasRequiredSections = REQUIRED_SECTIONS.some((section) => content.includes(section));

        if (hasRequiredSections) {
          console.log(`✅ ${doc} - Valid`);
          validCount++;
        } else {
          console.log(`⚠️  ${doc} - Missing required sections`);
        }
      } else {
        console.log(`❌ ${doc} - File not found`);
      }
    }

    console.log(`\n📊 Validation Summary: ${validCount}/${totalCount} files valid`);

    if (validCount === totalCount) {
      console.log('🎉 All documentation files are valid!');
      return true;
    } else {
      console.log('⚠️  Some documentation files need attention');
      return false;
    }
  } catch (error) {
    console.error('❌ Error validating documentation:', error.message);
    process.exit(1);
  }
}

const isValid = validateDocs();
process.exit(isValid ? 0 : 1);
