#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('🔥 REMOVING ALL @ts-nocheck DIRECTIVES FOR TRUE ERROR ASSESSMENT\n');

const files = [
  'src/services/metrics/performance-benchmark.ts',
  'src/services/orchestrators/memory-find-orchestrator-qdrant.ts',
  'src/services/smart-find.ts',
  'src/services/canary/kill-switch-service.ts',
  'src/services/insights/insight-strategies/knowledge-gap.strategy.ts',
  'src/services/ttl/ttl-validation-service.ts',
  'src/types/type-validation-error-handling.ts',
  'src/services/deduplication/enhanced-deduplication-service.ts',
  'src/types/config-validation-schema.ts',
  'src/types/json-value-conversion.ts',
  'src/utils/database-type-guards.ts',
  'src/http-client/http-validation.ts',
  'src/services/auth/auth-service.ts',
  'src/services/slo-reporting-service.ts',
  'src/types/filter-compatibility-adapter.ts',
  'src/entry-point-factory.ts',
  'src/utils/mcp-error-handler-integration.ts',
  'src/types/type-debug-helpers.ts',
  'src/types/safe-config-builders.ts',
  'src/types/config-validation-decorators.ts',
  'src/types/config-merge-utilities.ts',
  'src/services/__tests__/chaos-testing.service.ts',
  'src/services/workflow/workflow.service.ts',
  'src/services/validation/business-validators.ts',
  'src/services/tenant/tenant-purge.service.ts',
  'src/services/slo-integration-service.ts',
  'src/services/slo-breach-detection-service.ts',
  'src/services/similarity/similarity-service.ts',
  'src/services/orchestrators/optimized-memory-store-orchestrator.ts',
  'src/services/orchestrators/memory-store-orchestrator-qdrant.ts',
  'src/services/orchestrators/memory-find-orchestrator.ts',
  'src/services/orchestrators/idempotent-store-service.ts',
  'src/services/metrics/system-metrics.ts',
  'src/services/metrics/rag-dashboard.ts',
  'src/services/memory-find.ts',
  'src/services/lifecycle/data-lifecycle.service.ts',
  'src/services/lifecycle/compaction/compaction.service.ts',
  'src/services/knowledge/session-logs.ts',
  'src/services/knowledge/section.ts',
  'src/services/knowledge/risk.ts',
  'src/services/knowledge/release.ts',
  'src/services/knowledge/relation.ts',
  'src/services/knowledge/pr_context.ts',
  'src/services/knowledge/incident.ts',
  'src/services/knowledge/entity.ts',
  'src/services/knowledge/assumption.ts',
  'src/services/insights/insight-strategies/relationship-analysis.strategy.ts',
  'src/services/insights/insight-strategies/predictive-insight.strategy.ts',
  'src/services/insights/insight-strategies/pattern-recognition.strategy.ts',
  'src/services/insights/insight-strategies/anomaly-detection.strategy.ts',
  'src/services/expiry-worker.ts',
  'src/services/error-budget-service.ts',
  'src/services/document-reassembly.ts',
  'src/services/deduplication/deduplication-service.ts',
  'src/services/canary/config-validator.ts',
  'src/services/bulk/bulk-store-service.ts',
  'src/schemas/type-guards.ts',
  'src/pool/generic-resource-pool.ts',
  'src/performance/performance-harness.ts',
  'src/monitoring/metrics-service.ts',
  'src/handlers/memory-handlers.ts',
  'src/factories/factory-registry.ts',
  'src/factories/enhanced-mcp-factory.ts',
  'src/di/service-registry.ts',
  'src/di/event-bus.ts',
  'src/di/enhanced-di-container.ts',
  'src/di/di-container.ts',
  'src/di/adapters/metrics-service-adapter.ts',
  'src/di/adapters/memory-find-orchestrator-adapter.ts',
  'src/di/adapters/auth-service-adapter.ts',
  'src/di/adapters/audit-service-adapter.ts',
  'src/db/unified-database-layer-v2.ts',
  'src/db/schema.ts',
  'src/db/qdrant-restore-testing.ts',
  'src/db/qdrant-pooled-client.ts',
  'src/db/qdrant-consistency-validator.ts',
  'src/db/qdrant-client.ts',
  'src/db/qdrant-bootstrap.ts',
  'src/db/qdrant-backup-integration.ts',
  'src/db/qdrant-backup-config.ts',
  'src/db/factory/database-factory.ts',
  'src/db/database-manager.ts'
];

let modifiedCount = 0;

files.forEach(file => {
  try {
    const filePath = path.resolve(process.cwd(), file);

    if (!fs.existsSync(filePath)) {
      console.log(`⚠️  File not found: ${file}`);
      return;
    }

    let content = fs.readFileSync(filePath, 'utf8');
    const originalContent = content;

    // Remove all @ts-nocheck directives
    content = content.replace(/^\/\/\s*@ts-nocheck.*$/gm, '');
    content = content.replace(/^\/\*\s*@ts-nocheck\s*\*\/.*$/gm, '');
    content = content.replace(/^\/\/\s*TODO: Fix systematic type issues before removing @ts-nocheck.*$/gm, '');

    // Clean up extra blank lines
    content = content.replace(/\n\s*\n\s*\n/g, '\n\n');

    if (content !== originalContent) {
      fs.writeFileSync(filePath, content, 'utf8');
      console.log(`✅ Removed @ts-nocheck from: ${file}`);
      modifiedCount++;
    }
  } catch (error) {
    console.error(`❌ Error processing ${file}:`, error.message);
  }
});

console.log(`\n📊 SUMMARY:`);
console.log(`   Files processed: ${files.length}`);
console.log(`   Files modified: ${modifiedCount}`);
console.log(`   @ts-nocheck directives: REMOVED FROM ALL`);

console.log('\n🎯 ALL @TS-NOCHECK DIRECTIVES REMOVED!');
console.log('   Ready for TRUE TypeScript error assessment...');