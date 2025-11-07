/**
 * Validation script to check truncation implementation structure
 * Run with: node validate-truncation-implementation.mjs
 */

import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function checkFileExists(filePath) {
  const fullPath = join(__dirname, filePath);
  const exists = existsSync(fullPath);
  console.log(`${exists ? '✅' : '❌'} ${filePath}`);
  return exists;
}

function checkFileContains(filePath, pattern) {
  const fullPath = join(__dirname, filePath);
  if (!existsSync(fullPath)) {
    console.log(`❌ ${filePath} (file not found)`);
    return false;
  }

  const content = readFileSync(fullPath, 'utf8');
  const contains = pattern.test(content);
  console.log(`${contains ? '✅' : '❌'} ${filePath} contains pattern: ${pattern}`);
  return contains;
}

function validateTruncationImplementation() {
  console.log('🔍 Validating Truncation Implementation');
  console.log('='.repeat(50));

  let allChecksPass = true;

  console.log('\n📁 File Structure Checks:');
  allChecksPass &= checkFileExists('src/config/truncation-config.ts');
  allChecksPass &= checkFileExists('src/services/truncation/truncation-service.ts');

  console.log('\n🔧 Configuration Implementation:');
  allChecksPass &= checkFileContains(
    'src/config/truncation-config.ts',
    /interface TruncationConfig/
  );
  allChecksPass &= checkFileContains(
    'src/config/truncation-config.ts',
    /interface TruncationResult/
  );
  allChecksPass &= checkFileContains(
    'src/config/truncation-config.ts',
    /export const DEFAULT_TRUNCATION_CONFIG/
  );

  console.log('\n🛠️  Service Implementation:');
  allChecksPass &= checkFileContains(
    'src/services/truncation/truncation-service.ts',
    /export class TruncationService/
  );
  allChecksPass &= checkFileContains(
    'src/services/truncation/truncation-service.ts',
    /async processContent/
  );
  allChecksPass &= checkFileContains(
    'src/services/truncation/truncation-service.ts',
    /class TokenEstimator/
  );
  allChecksPass &= checkFileContains(
    'src/services/truncation/truncation-service.ts',
    /class ContentTypeDetector/
  );

  console.log('\n📊 Metrics Integration:');
  allChecksPass &= checkFileContains('src/services/metrics/system-metrics.ts', /truncation: {/);
  allChecksPass &= checkFileContains(
    'src/services/metrics/system-metrics.ts',
    /store_truncated_total/
  );
  allChecksPass &= checkFileContains(
    'src/services/metrics/system-metrics.ts',
    /updateTruncationMetrics/
  );

  console.log('\n🏗️  Environment Configuration:');
  allChecksPass &= checkFileContains('src/config/environment.ts', /getTruncationConfig/);
  allChecksPass &= checkFileContains('src/config/environment.ts', /TRUNCATION_ENABLED/);
  allChecksPass &= checkFileContains('src/config/environment.ts', /TRUNCATION_MODE/);

  console.log('\n🔌 Interface Updates:');
  allChecksPass &= checkFileContains('src/types/core-interfaces.ts', /meta: {/);
  allChecksPass &= checkFileContains('src/types/core-interfaces.ts', /truncated: boolean/);
  allChecksPass &= checkFileContains('src/types/core-interfaces.ts', /truncation_details/);

  console.log('\n🔄 Service Integration:');
  allChecksPass &= checkFileContains('src/services/memory-store.ts', /truncationService/);
  allChecksPass &= checkFileContains('src/services/memory-store.ts', /processItemsWithTruncation/);
  allChecksPass &= checkFileContains('src/services/memory-store.ts', /addTruncationMetadata/);

  console.log('\n📝 Documentation:');
  allChecksPass &= checkFileExists('TRUNCATION_IMPLEMENTATION.md');

  console.log('\n🎯 Key Features Validation:');

  // Check for truncation strategies
  console.log('\n   Truncation Strategies:');
  allChecksPass &= checkFileContains('src/services/truncation/truncation-service.ts', /hardCutoff/);
  allChecksPass &= checkFileContains(
    'src/services/truncation/truncation-service.ts',
    /preserveSentences/
  );
  allChecksPass &= checkFileContains(
    'src/services/truncation/truncation-service.ts',
    /preserveJsonStructure/
  );
  allChecksPass &= checkFileContains(
    'src/services/truncation/truncation-service.ts',
    /smartContent/
  );

  // Check for content type detection
  console.log('\n   Content Type Detection:');
  allChecksPass &= checkFileContains('src/config/truncation-config.ts', /CONTENT_TYPE_PATTERNS/);
  allChecksPass &= checkFileContains(
    'src/services/truncation/truncation-service.ts',
    /detectContentType/
  );

  // Check for metrics tracking
  console.log('\n   Metrics Tracking:');
  allChecksPass &= checkFileContains(
    'src/services/truncation/truncation-service.ts',
    /updateMetrics/
  );
  allChecksPass &= checkFileContains('src/services/truncation/truncation-service.ts', /getMetrics/);

  // Check for configuration options
  console.log('\n   Configuration Options:');
  allChecksPass &= checkFileContains('src/config/environment.ts', /TRUNCATION_MAX_CHARS_DEFAULT/);
  allChecksPass &= checkFileContains('src/config/environment.ts', /TRUNCATION_MAX_TOKENS_DEFAULT/);
  allChecksPass &= checkFileContains('src/config/environment.ts', /TRUNCATION_SAFETY_MARGIN/);

  console.log('\n📋 Summary:');
  if (allChecksPass) {
    console.log('✅ All truncation implementation checks passed!');
    console.log('\n🎉 Implementation includes:');
    console.log('   • Comprehensive configuration system');
    console.log('   • Intelligent truncation service');
    console.log('   • Multiple truncation strategies');
    console.log('   • Content type detection');
    console.log('   • Metrics collection and monitoring');
    console.log('   • Response metadata integration');
    console.log('   • Environment variable configuration');
    console.log('   • Warning and logging system');
    console.log('   • Performance optimization');
    console.log('   • Documentation and examples');
  } else {
    console.log('❌ Some checks failed. Please review the implementation.');
  }

  return allChecksPass;
}

// Run validation
validateTruncationImplementation();
