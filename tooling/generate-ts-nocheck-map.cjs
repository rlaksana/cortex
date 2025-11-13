#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// List of files with @ts-nocheck
const filesWithNoCheck = [
  'src\\services\\knowledge\\incident.ts',
  'src\\utils\\response-builder.ts',
  'src\\utils\\retry-policy.ts',
  'src\\di\\typed-di-container.ts',
  'src\\schemas\\schema-validator.ts',
  'src\\schemas\\unified-knowledge-validator.ts',
  'src\\types\\config-merge-utilities.ts',
  'src\\types\\config-validation-decorators.ts',
  'src\\types\\config-validation-schema.ts',
  'src\\types\\database-types-enhanced.ts',
  'src\\types\\index.ts',
  'src\\types\\json-value-conversion.ts',
  'src\\types\\metrics-types.ts',
  'src\\types\\migration.ts',
  'src\\types\\monitoring-types.ts',
  'src\\types\\safe-config-builders.ts',
  'src\\types\\safe-property-access.ts',
  'src\\types\\type-debug-helpers.ts',
  'src\\types\\type-guards-enhanced.ts',
  'src\\types\\type-validation-error-handling.ts',
  'src\\utils\\config-tester.ts',
  'src\\utils\\correlation-id.ts',
  'src\\utils\\enhanced-expiry-utils.ts',
  'src\\utils\\expiry-utils.ts',
  'src\\utils\\idempotency-manager.ts',
  'src\\utils\\index.ts',
  'src\\utils\\logger.ts',
  'src\\utils\\mcp-logger.ts',
  'src\\utils\\mcp-response-guards.ts',
  'src\\factories\\factory-registry.ts',
  'src\\factories\\factory-types.ts',
  'src\\http-client\\http-validation.ts',
  'src\\http-client\\typed-http-client.ts',
  'src\\main-di.ts',
  'src\\memory-store-manager.ts',
  'src\\middleware\\enhanced-security-middleware.ts',
  'src\\middleware\\error-middleware.ts',
  'src\\middleware\\mcp-auth-wrapper.ts',
  'src\\middleware\\production-security-middleware.ts',
  'src\\middleware\\rate-limit-middleware.ts',
  'src\\middleware\\rate-limiter.ts',
  'src\\middleware\\scope-middleware.ts',
  'src\\middleware\\security-middleware.ts',
  'src\\pool\\database-pool.ts',
  'src\\pool\\generic-resource-pool.ts',
  'src\\schemas\\mcp-validation-integration.ts',
  'src\\schemas\\validation-migration.ts',
  'src\\security\\secrets-scanner.ts',
  'src\\di\\adapters\\metrics-service-adapter.ts',
  'src\\di\\enhanced-di-container.ts',
  'src\\di\\event-bus.ts',
  'src\\di\\service-registry.ts',
  'src\\di\\services\\config-service.ts',
  'src\\di\\services\\logger-service.ts',
  'src\\factories\\enhanced-mcp-factory.ts',
  'src\\handlers\\memory-handlers.ts',
  'src\\db\\qdrant-backup-config.ts',
  'src\\db\\qdrant-backup-integration.ts',
  'src\\db\\qdrant-bootstrap.ts',
  'src\\db\\qdrant-consistency-validator.ts',
  'src\\db\\qdrant-pooled-client.ts',
  'src\\db\\qdrant-restore-testing.ts',
  'src\\db\\schema.ts',
  'src\\db\\unified-database-layer-v2.ts',
  'src\\di\\adapters\\audit-service-adapter.ts',
  'src\\di\\adapters\\auth-service-adapter.ts',
  'src\\di\\adapters\\memory-find-orchestrator-adapter.ts',
  'src\\di\\di-container.ts',
  'src\\validation\\audit-metrics-validator.ts',
  'src\\utils\\type-safety-layer.ts',
  'src\\utils\\type-guards.ts',
  'src\\utils\\tl-utils.ts',
  'src\\utils\\monitoring-type-guards.ts',
  'src\\utils\\mcp-transform.ts',
  'src\\utils\\mcp-compliance.ts',
  'src\\utils\\lru-cache.ts',
  'src\\utils\\logging-patterns.ts',
  'src\\utils\\logger-wrapper.ts',
  'src\\utils\\db-error-handler.ts',
  'src\\utils\\database-type-guards.ts',
  'src\\utils\\configuration-validators.ts',
  'src\\types\\unified-response.interface.ts',
  'src\\types\\slo-interfaces.ts',
  'src\\types\\runtime-type-guard-framework.ts',
  'src\\types\\monitoring-types-enhanced.ts',
  'src\\types\\mcp-response-data.types.ts',
  'src\\types\\http-client-types.ts',
  'src\\types\\discriminated-unions.ts',
  'src\\types\\branded-types.ts',
  'src\\types\\base-types.ts',
  'src\\types\\audit-types.ts',
  'src\\types\\audit-metrics-types.ts',
  'src\\types\\api-types-enhanced.ts',
  'src\\testing\\load-testing\\load-test-framework.ts',
  'src\\services\\__tests__\\chaos-testing.service.ts',
  'src\\services\\workflow\\workflow.service.ts',
  'src\\services\\workers\\retry-worker-service.ts',
  'src\\services\\validation\\enhanced-validation-service.ts',
  'src\\services\\validation\\business-validators.ts',
  'src\\services\\ttl\\ttl-validation-service.ts',
  'src\\services\\ttl\\ttl-safety-service.ts',
  'src\\services\\ttl\\ttl-policy-service.ts',
  'src\\services\\ttl\\ttl-management-service.ts',
  'src\\services\\ttl\\index.ts',
  'src\\services\\tenant\\tenant-purge.service.ts',
  'src\\services\\telemetry\\baseline-telemetry.ts',
  'src\\services\\similarity\\similarity-service.ts',
  'src\\services\\security\\key-vault-service.ts',
  'src\\services\\scaling\\partitioning-service.ts',
  'src\\services\\pii\\pii-redaction.service.ts',
  'src\\services\\orchestrators\\optimized-memory-store-orchestrator.ts',
  'src\\services\\orchestrators\\memory-store-orchestrator.ts',
  'src\\services\\orchestrators\\memory-store-orchestrator-qdrant.ts',
  'src\\services\\orchestrators\\memory-find-orchestrator.ts',
  'src\\services\\orchestrators\\memory-find-orchestrator-qdrant.ts',
  'src\\services\\orchestrators\\idempotent-store-service.ts',
  'src\\services\\metrics\\trend-charts.ts',
  'src\\services\\metrics\\system-metrics.ts',
  'src\\services\\metrics\\sli-slo-monitor.ts',
  'src\\services\\metrics\\rag-dashboard.ts',
  'src\\services\\metrics\\performance-benchmark.ts',
  'src\\services\\memory\\memory-manager-service.ts',
  'src\\services\\logging\\logging-service.ts',
  'src\\services\\lifecycle\\data-lifecycle.service.ts',
  'src\\services\\knowledge\\todo.ts',
  'src\\services\\knowledge\\session-logs.ts',
  'src\\services\\knowledge\\section.ts',
  'src\\services\\knowledge\\runbook.ts',
  'src\\services\\knowledge\\risk.ts',
  'src\\services\\knowledge\\release_note.ts',
  'src\\services\\knowledge\\release.ts',
  'src\\services\\knowledge\\relation.ts',
  'src\\services\\knowledge\\pr_context.ts',
  'src\\services\\knowledge\\observation.ts',
  'src\\services\\knowledge\\issue.ts',
  'src\\services\\knowledge\\entity.ts',
  'src\\services\\knowledge\\decision.ts',
  'src\\services\\knowledge\\assumption.ts',
  'src\\services\\insights\\insight-strategies\\relationship-analysis.strategy.ts',
  'src\\services\\insights\\insight-strategies\\predictive-insight.strategy.ts',
  'src\\services\\insights\\insight-strategies\\pattern-recognition.strategy.ts',
  'src\\services\\insights\\insight-strategies\\knowledge-gap.strategy.ts',
  'src\\services\\insights\\insight-strategies\\anomaly-detection.strategy.ts',
  'src\\services\\insights\\zai-enhanced-insight-service.ts',
  'src\\services\\insights\\insight-guardrails.ts',
  'src\\services\\insights\\insight-generation-service.ts',
  'src\\services\\insights\\insight-cache.service.ts',
  'src\\services\\feature-flag\\feature-flag-service.ts',
  'src\\services\\embeddings\\embedding-service.ts',
  'src\\services\\deduplication\\strategies\\intelligent-strategy.ts',
  'src\\services\\deduplication\\strategies\\deduplication-strategy-factory.ts',
  'src\\services\\deduplication\\strategies\\combine-strategy.ts',
  'src\\services\\deduplication\\enhanced-deduplication-service.ts',
  'src\\services\\deduplication\\deduplication-service.ts',
  'src\\services\\chunking\\chunking-service.ts',
  'src\\services\\canary\\kill-switch-service.ts',
  'src\\services\\canary\\config-validator.ts',
  'src\\services\\bulk\\bulk-store-service.ts',
  'src\\services\\backup\\restore.service.ts',
  'src\\services\\backup\\backup.service.ts',
  'src\\services\\auth\\authorization-service.ts',
  'src\\services\\auth\\auth-service.ts',
  'src\\services\\auth\\auth-service-standardized.ts',
  'src\\services\\auth\\api-key-service.ts',
  'src\\services\\analytics\\analytics.service.ts',
  'src\\services\\ai\\utils\\performance-monitor.ts',
  'src\\services\\ai\\zai-optimized-client.ts',
  'src\\services\\ai\\index.ts',
  'src\\services\\ai\\index-simplified.ts',
  'src\\services\\ai\\background-processor.ts',
  'src\\services\\ai\\background-processor-simplified.ts',
  'src\\services\\smart-find.ts',
  'src\\services\\slo-service.ts',
  'src\\services\\slo-reporting-service.ts',
  'src\\services\\slo-integration-service.ts',
  'src\\services\\slo-breach-detection-service.ts',
  'src\\services\\similarity.ts',
  'src\\services\\memory-store.ts',
  'src\\services\\memory-find.ts',
  'src\\services\\health-check.service.ts',
  'src\\services\\graph-traversal.ts',
  'src\\services\\expiry-worker.ts',
  'src\\services\\error-budget-service.ts',
  'src\\services\\document-reassembly.ts',
  'src\\services\\deps-registry.ts',
  'src\\services\\delete-operations.ts',
  'src\\services\\core-memory-find.ts',
  'src\\services\\cleanup-worker.service.ts',
  'src\\services\\auto-purge.ts',
  'src\\services\\api.service.ts',
  'src\\security\\runtime-checks.ts',
  'src\\schemas\\type-guards.ts',
  'src\\schemas\\knowledge-types.ts',
  'src\\production\\production-optimizer.ts',
  'src\\performance\\performance-targets.ts',
  'src\\performance\\performance-harness.ts',
  'src\\performance\\performance-dashboard.ts',
  'src\\performance\\ci-regression-guard.ts',
  'src\\performance\\artifact-storage.ts',
  'src\\monitoring\\structured-logger.ts',
  'src\\monitoring\\slow-query-logger.ts',
  'src\\monitoring\\slo-monitoring-integration.ts',
  'src\\monitoring\\runbook-integration-service.ts',
  'src\\monitoring\\retry-trend-analyzer.ts',
  'src\\monitoring\\retry-monitoring-integration.ts',
  'src\\monitoring\\retry-metrics-exporter.ts',
  'src\\monitoring\\retry-budget-monitor.ts',
  'src\\monitoring\\retry-budget-index.ts',
  'src\\monitoring\\retry-alert-system.ts',
  'src\\monitoring\\qdrant-health-monitor.ts',
  'src\\monitoring\\production-logger.ts',
  'src\\monitoring\\production-error-handler.ts',
  'src\\monitoring\\performance-monitor.ts',
  'src\\monitoring\\performance-middleware.ts',
  'src\\monitoring\\performance-dashboard.ts',
  'src\\monitoring\\performance-collector.ts',
  'src\\monitoring\\performance-benchmarks.ts',
  'src\\monitoring\\oncall-management-service.ts',
  'src\\monitoring\\observability-dashboards.ts',
  'src\\monitoring\\notification-channels.ts',
  'src\\monitoring\\monitoring-server.ts',
  'src\\monitoring\\metrics-service.ts',
  'src\\monitoring\\health-endpoint.ts',
  'src\\monitoring\\health-check-service.ts',
  'src\\monitoring\\graceful-degradation-manager.ts',
  'src\\monitoring\\enhanced-performance-collector.ts',
  'src\\monitoring\\enhanced-circuit-dashboard.ts',
  'src\\monitoring\\degradation-notifier.ts',
  'src\\monitoring\\degradation-detector.ts',
  'src\\monitoring\\container-probes.ts',
  'src\\monitoring\\comprehensive-retry-dashboard.ts',
  'src\\monitoring\\circuit-breaker-monitor.ts',
  'src\\monitoring\\alert-testing-service.ts',
  'src\\monitoring\\alert-system-integration.ts',
  'src\\monitoring\\alert-metrics-service.ts',
  'src\\monitoring\\alert-management-service.ts',
  'src\\monitoring\\ai-health-monitor.ts',
  'src\\http-client\\http-error-handler.ts',
  'src\\factories\\factory-type-guards.ts',
  'src\\di\\runtime-validation.ts',
  'src\\db\\factory\\database-factory.ts',
  'src\\db\\database-factory.ts',
  'src\\db\\audit.ts',
  'src\\production-startup.ts',
  'src\\minimal-mcp-server.ts',
  'src\\index.ts',
  'src\\entry-point-factory.ts',
  'src\\services\\memory-store-service.ts',
  'src\\monitoring\\health-dashboard-api.ts',
  'src\\db\\qdrant-client.ts',
  'src\\db\\database-manager.ts',
  'src\\db\\adapters\\qdrant-adapter.ts',
  'src\\chaos-testing\\index.ts',
  'src\\chaos-testing\\engine\\chaos-injection-engine.ts',
  'src\\services\\ai\\provider-manager.ts',
  'src\\services\\ai\\zai-client.service.ts',
  'src\\services\\ai\\background-processor.service.ts',
  'src\\services\\ai\\ai-orchestrator.service.ts',
  'fix-all-v15.js',
  'fix-all-v14.js',
  'fix-all-v13.js',
  'fix-all-v12.js',
  'fix-all-v11.js',
  'fix-all-v10.js',
  'fix-all-v9.js',
  'fix-all-v8.js',
  'fix-all-v7.js',
  'fix-all-v6.js',
  'fix-all-v3.js',
  'fix-all-v2.js',
  'fix-all.js'
];

function getFileStats(filePath) {
  try {
    const stats = fs.statSync(filePath);
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n').length;

    return {
      exists: true,
      size: stats.size,
      lines: lines,
      loc_estimate: lines
    };
  } catch (error) {
    return {
      exists: false,
      size: 0,
      lines: 0,
      loc_estimate: 0,
      error: error.message
    };
  }
}

function categorizeFile(filePath) {
  const path = filePath.replace(/\\/g, '/');

  // Core runtime - critical type guards and database adapters
  if (path.includes('type-guards.ts') ||
      path.includes('qdrant-adapter.ts') ||
      path.includes('runtime-type-guard-framework.ts') ||
      path.includes('base-types.ts') ||
      path.includes('branded-types.ts')) {
    return 'core-runtime';
  }

  // Tests
  if (path.includes('__tests__') ||
      path.includes('test.') ||
      path.includes('chaos-testing') ||
      path.includes('load-testing')) {
    return 'tests';
  }

  // Tooling and scripts
  if (path.startsWith('fix-all') ||
      path.includes('tooling') ||
      path.includes('scripts')) {
    return 'tooling';
  }

  // Everything else is supporting infrastructure
  return 'supporting';
}

const resultMap = filesWithNoCheck.map(filePath => {
  const normalizedPath = filePath.replace(/\\/g, '/');
  const stats = getFileStats(filePath);
  const category = categorizeFile(normalizedPath);

  return {
    path: normalizedPath,
    loc_estimate: stats.loc_estimate,
    category: category,
    exists: stats.exists,
    size_bytes: stats.size,
    last_modified: stats.exists ? new Date().toISOString() : null
  };
});

const summary = {
  total_files: resultMap.length,
  core_runtime: resultMap.filter(f => f.category === 'core-runtime').length,
  supporting: resultMap.filter(f => f.category === 'supporting').length,
  tests: resultMap.filter(f => f.category === 'tests').length,
  tooling: resultMap.filter(f => f.category === 'tooling').length,
  total_loc: resultMap.reduce((sum, f) => sum + f.loc_estimate, 0),
  generated_at: new Date().toISOString(),
  batch_02_focus: {
    'src/utils/type-guards.ts': 'core-runtime',
    'src/db/adapters/qdrant-adapter.ts': 'core-runtime'
  }
};

const output = {
  summary,
  files: resultMap
};

// Ensure tooling directory exists
if (!fs.existsSync('tooling')) {
  fs.mkdirSync('tooling');
}

fs.writeFileSync('tooling/ts-nocheck-map.json', JSON.stringify(output, null, 2));
console.log('✅ Generated tooling/ts-nocheck-map.json');
console.log(`📊 Summary: ${summary.total_files} files, ${summary.total_loc} total lines`);
console.log(`🎯 Core runtime files: ${summary.core_runtime}`);
console.log(`📋 Supporting files: ${summary.supporting}`);
console.log(`🧪 Test files: ${summary.tests}`);
console.log(`🔧 Tooling files: ${summary.tooling}`);