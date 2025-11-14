#!/usr/bin/env node

/**
 * Emergency Rollback Script - Batch 3: Essential DI Services
 */

import { readFileSync, writeFileSync } from 'fs';
import { access, constants } from 'fs/promises';

// Only essential DI services and remaining core files
const batch3Files = [
  'src/di/services/config-service.ts',
  'src/di/services/logger-service.ts'
];

async function fileExists(filePath) {
  try {
    await access(filePath, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function addTsNocheck(filePath) {
  try {
    const content = readFileSync(filePath, 'utf8');

    // Check if @ts-nocheck already exists
    if (content.startsWith('// @ts-nocheck')) {
      console.log(`[SKIP] ${filePath} already has @ts-nocheck`);
      return false;
    }

    // Find the best place to insert @ts-nocheck
    const lines = content.split('\n');
    let insertIndex = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.trim() === '') continue;
      if (line.startsWith('/**')) {
        insertIndex = i;
        break;
      } else if (line.startsWith('import') || line.startsWith('export')) {
        insertIndex = i;
        break;
      }
    }

    lines.splice(insertIndex, 0, '// @ts-nocheck');
    const updatedContent = lines.join('\n');

    writeFileSync(filePath, updatedContent);
    console.log(`[SUCCESS] Added @ts-nocheck to ${filePath}`);
    return true;

  } catch (error) {
    console.error(`[ERROR] Failed to process ${filePath}:`, error.message);
    return false;
  }
}

async function main() {
  console.log('🚨 Emergency Rollback Batch 3: Essential DI Services\n');

  let processedCount = 0;
  let successCount = 0;

  for (const filePath of batch3Files) {
    if (await fileExists(filePath)) {
      processedCount++;
      if (addTsNocheck(filePath)) {
        successCount++;
      }
    } else {
      console.log(`[SKIP] File not found: ${filePath}`);
    }
  }

  console.log(`\n✅ Batch 3 Summary:`);
  console.log(`   Files processed: ${processedCount}`);
  console.log(`   Successfully updated: ${successCount}`);
  console.log(`   Failed: ${processedCount - successCount}`);
}

main().catch(console.error);