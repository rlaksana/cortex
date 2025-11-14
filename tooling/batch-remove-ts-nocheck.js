import fs from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { spawn } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Batch removal script for @ts-nocheck comments
 * Usage: node tooling/batch-remove-ts-nocheck.js <batch-number>
 * Example: node tooling/batch-remove-ts-nocheck.js 1
 */

async function main() {
  const batchNum = process.argv[2];
  if (!batchNum) {
    console.error('Usage: node tooling/batch-remove-ts-nocheck.js <batch-number>');
    console.error('Example: node tooling/batch-remove-ts-nocheck.js 1');
    process.exit(1);
  }

  const batchFile = join(__dirname, `ts-nocheck-batch-${batchNum}.json`);

  if (!fs.existsSync(batchFile)) {
    console.error(`Batch file not found: ${batchFile}`);
    process.exit(1);
  }

  const batch = JSON.parse(fs.readFileSync(batchFile, 'utf-8'));
  const srcRoot = join(__dirname, '../src');

  console.log(`\n=== Processing Batch ${batchNum}: ${batch.category} ===`);
  console.log(`Total files: ${batch.file_count}\n`);

  // Step 1: Remove @ts-nocheck from all files
  console.log('Step 1: Removing @ts-nocheck comments...');
  let modified = 0;
  const results = [];

  for (const filepath of batch.files) {
    const fullPath = join(srcRoot, filepath);

    if (!fs.existsSync(fullPath)) {
      console.log(`  ⚠ Missing: ${filepath}`);
      continue;
    }

    let content = fs.readFileSync(fullPath, 'utf-8');
    const originalContent = content;

    // Remove @ts-nocheck comment (supports multiple formats)
    // Pattern 1: // @ts-nocheck with or without comment
    content = content.replace(/^\/\/ @ts-nocheck.*$/gm, '');

    // Pattern 2: /* @ts-nocheck */ (unlikely but handle it)
    content = content.replace(/^\/\* @ts-nocheck \*\/$/gm, '');

    // Pattern 3: @ts-nocheck without comment marker
    content = content.replace(/^@ts-nocheck$/gm, '');

    // Remove empty lines at start of file
    content = content.replace(/^\s*\n/, '');

    if (content !== originalContent) {
      fs.writeFileSync(fullPath, content, 'utf-8');
      modified++;
      results.push({ filepath, status: 'removed' });
    } else {
      results.push({ filepath, status: 'no-comment-found' });
    }
  }

  console.log(`  ✓ Removed @ts-nocheck from ${modified} files\n`);

  // Step 2: Run TypeScript compiler to check for errors
  console.log('Step 2: Running TypeScript compiler...');
  console.log('  (This may take a few minutes)\n');

  const tscResult = await runTsc();

  // Step 3: Show results
  console.log('\n=== Results ===\n');

  if (tscResult.errorCount === 0) {
    console.log('✅ SUCCESS: No TypeScript errors detected!');
    console.log(`✓ ${modified} files processed successfully`);
    console.log(`✓ Batch ${batchNum} completed: ${batch.category}\n`);

    // Update batch file with success status
    const completedBatch = { ...batch, status: 'completed', errors_fixed: 0 };
    fs.writeFileSync(
      join(__dirname, `ts-nocheck-batch-${batchNum}-completed.json`),
      JSON.stringify(completedBatch, null, 2)
    );
    return;
  }

  console.log(`⚠️  TypeScript errors: ${tscResult.errorCount}`);
  console.log(`   Warning count: ${tscResult.warningCount}\n`);

  console.log('Category breakdown:');
  for (const [category, count] of Object.entries(tscResult.errorCategories)) {
    console.log(`  • ${category}: ${count}`);
  }

  console.log('\n=== Recommendations ===\n');
  console.log('⚠️  Manual fixes required for this batch');
  console.log('   Review the TypeScript error output above');
  console.log('   Fix errors in individual files');
  console.log('   Run: pnpm tsc --noEmit\n');
  console.log('   After fixing: pnpm build && pnpm test\n');
}

function runTsc() {
  return new Promise((resolve) => {
    const tsc = spawn('npx', ['tsc', '--noEmit'], {
      cwd: join(__dirname, '..'),
      shell: true
    });

    let stderr = '';
    let stdout = '';

    const errorPattern = /(error|warning) TS\d{4}/g;
    const errorCategoryPattern = /TS\d{4}:/g;

    tsc.stdout.on('data', (data) => {
      const str = data.toString();
      stdout += str;

      // Show first 10 errors in real-time
      const lines = str.split('\n');
      for (const line of lines) {
        if (line.includes('error TS') || line.includes('warning TS')) {
          console.log('  ' + line);
        }
      }
    });

    tsc.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    tsc.on('close', (code) => {
      // Count errors and warnings
      const errors = stdout.match(/error TS\d{4}/g) || [];
      const warnings = stdout.match(/warning TS\d{4}/g) || [];

      // Extract error categories (TS codes)
      const errorCategories = {};
      const tsCodes = stdout.match(/TS\d{4}/g) || [];
      tsCodes.forEach(code => {
        errorCategories[code] = (errorCategories[code] || 0) + 1;
      });

      resolve({
        exitCode: code,
        errorCount: errors.length,
        warningCount: warnings.length,
        errorCategories,
        fullOutput: stdout + stderr
      });
    });
  });
}

main().catch(error => {
  console.error('Error:', error);
  process.exit(1);
});