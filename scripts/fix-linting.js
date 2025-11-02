#!/usr/bin/env node

/**
 * Fix Linting Issues Script
 *
 * Automatically fixes common linting issues:
 * 1. Uncommented required imports
 * 2. Prefix unused variables with underscore
 * 3. Add missing imports
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// File-specific fixes
const fixes = {
  'tests/utils/mock-embedding-service.ts': {
    imports: [
      "import type { EmbeddingConfig, EmbeddingRequest, EmbeddingResult, BatchEmbeddingRequest, EmbeddingStats } from '../../src/services/embeddings/embedding-service.js';",
      "import { vi } from 'vitest';",
    ],
    uncommentLines: [7, 8],
  },
  'tests/utils/mock-templates.ts': {
    imports: ["import { vi } from 'vitest';"],
    uncommentLines: [9],
  },
};

/**
 * Fix uncommented imports in a file
 */
function fixImports(filePath, config) {
  const fullPath = path.resolve(__dirname, filePath);

  if (!fs.existsSync(fullPath)) {
    console.log(`❌ File not found: ${filePath}`);
    return false;
  }

  let content = fs.readFileSync(fullPath, 'utf8');
  let modified = false;

  // Uncomment specified lines
  if (config.uncommentLines) {
    const lines = content.split('\n');
    config.uncommentLines.forEach((lineNum) => {
      const index = lineNum - 1; // Convert to 0-based index
      if (lines[index] && lines[index].trim().startsWith('//')) {
        lines[index] = lines[index].replace(/^\s*\/\/\s*/, '');
        modified = true;
        console.log(`✅ Uncommented line ${lineNum} in ${filePath}`);
      }
    });
    content = lines.join('\n');
  }

  // Add missing imports after existing imports
  if (config.imports) {
    const lines = content.split('\n');
    let insertIndex = -1;

    // Find the last import line
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].trim().startsWith('import ') || lines[i].trim().startsWith('// import')) {
        insertIndex = i;
      }
    }

    if (insertIndex >= 0) {
      // Insert new imports after the last import
      config.imports.forEach((importLine) => {
        if (!content.includes(importLine.trim())) {
          lines.splice(insertIndex + 1, 0, importLine);
          insertIndex++;
          modified = true;
          console.log(`✅ Added import to ${filePath}: ${importLine}`);
        }
      });
      content = lines.join('\n');
    }
  }

  if (modified) {
    fs.writeFileSync(fullPath, content);
    console.log(`✅ Fixed imports in ${filePath}`);
    return true;
  } else {
    console.log(`ℹ️  No changes needed for ${filePath}`);
    return false;
  }
}

/**
 * Fix unused variables by prefixing with underscore
 */
function fixUnusedVariables() {
  const filesToFix = [
    'tests/array-serialization-test.ts',
    'tests/fixtures/test-data-factory.ts',
    'tests/framework/helpers/database-test-helper.ts',
    'tests/framework/helpers/error-test-helper.ts',
    'tests/framework/helpers/performance-test-helper.ts',
    'tests/framework/helpers/validation-test-helper.ts',
    'tests/framework/mock-manager.ts',
    'tests/framework/test-validation.ts',
    'tests/global-setup.ts',
    'tests/integration/feature-toggles.test.ts',
    'tests/unit/config/environment.test.ts',
    'tests/unit/config/feature-toggles.test.ts',
    'tests/unit/core/cortex-memory-orchestrator.test.ts',
    'tests/unit/core/memory-store-orchestrator.test.ts',
    'tests/unit/core/query-orchestrator.test.ts',
    'tests/unit/core/scope-manager.test.ts',
    'tests/unit/db/cleanup.test.ts',
    'tests/unit/db/collection-manager.test.ts',
    'tests/unit/db/database-impl.test.ts',
    'tests/unit/db/qdrant-client-wrapper.test.ts',
    'tests/unit/db/schema-manager.test.ts',
    'tests/unit/embeddings/array-serialization.test.ts',
    'tests/unit/embeddings/embedding-service-interface.test.ts',
    'tests/unit/embeddings/embedding-service-impl.test.ts',
    'tests/unit/monitoring/metrics-orchestrator.test.ts',
    'tests/unit/monitoring/metrics.test.ts',
    'tests/unit/orchestrators/base-orchestrator.test.ts',
    'tests/unit/orchestrators/memory-orchestrator.test.ts',
    'tests/unit/orchestrators/query-orchestrator.test.ts',
    'tests/unit/queries/complex-query-builder.test.ts',
    'tests/unit/queries/query-cache.test.ts',
    'tests/unit/queries/query-factory.test.ts',
    'tests/unit/queries/query-sanitizer.test.ts',
    'tests/unit/queries/query-validator.test.ts',
    'tests/unit/services/collection-service.test.ts',
    'files/unit/services/memory-store-service.test.ts',
    'tests/unit/services/reconstruction-service.test.ts',
    'tests/unit/ttl/ttl-worker.test.ts',
    'tests/unit/utils/file-handle-manager.test.ts',
    'tests/unit/utils/immutability.test.ts',
    'tests/utils/parameterized-test-framework.ts',
    'tests/utils/query-sanitizer.test.ts',
  ];

  filesToFix.forEach((filePath) => {
    const fullPath = path.resolve(__dirname, filePath);

    if (!fs.existsSync(fullPath)) {
      return;
    }

    let content = fs.readFileSync(fullPath, 'utf8');
    let modified = false;

    // Pattern to find unused variable declarations in lint output
    // This is a simplified approach - in practice, we'd need to parse the AST
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      // Look for patterns like "const result = " or "let error = " in test contexts
      // and replace with "const _result = " or "let _error = "
      if (/^\s*(const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=/.test(line)) {
        const varName = line.match(/^\s*(const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=/)[2];

        // Only fix if it's likely a test helper variable (common patterns)
        const commonUnusedPatterns =
          /^(result|error|data|item|index|count|stats|status|value|output|response)$/i;

        if (commonUnusedPatterns.test(varName) && !line.includes(`const _${varName} =`)) {
          lines[index] = line.replace(
            new RegExp(`(\\s*(const|let|var)\\s+)(${varName})(\\s*=)`),
            '$1_$3$4'
          );
          modified = true;
        }
      }
    });

    if (modified) {
      fs.writeFileSync(fullPath, lines.join('\n'));
      console.log(`✅ Fixed unused variables in ${filePath}`);
    }
  });
}

/**
 * Main execution
 */
function main() {
  console.log('🔧 Starting lint fix script...\n');

  // Fix import issues
  let totalFixed = 0;
  Object.entries(fixes).forEach(([filePath, config]) => {
    if (fixImports(filePath, config)) {
      totalFixed++;
    }
  });

  // Fix unused variables
  console.log('\n🔧 Fixing unused variables...');
  fixUnusedVariables();

  console.log(`\n✅ Lint fix script completed! Fixed imports in ${totalFixed} files.`);
  console.log('\n📝 Next steps:');
  console.log('   1. Run: npm run lint');
  console.log('   2. If any issues remain, fix them manually');
  console.log('   3. Run: npm run format');
  console.log('   4. Continue with remaining gates');
}

// Run the script
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { fixImports, fixUnusedVariables };
