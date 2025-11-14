import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Read the raw list
const rawList = fs.readFileSync('tooling/.ts-nocheck-raw.txt', 'utf-8').trim().split('\n');

// Remove any empty lines
const files = rawList.filter(f => f.trim());

console.log(`Total files to process: ${files.length}`);

// Categorize files by directory
const categories = {
  'core-types': [],
  'core-runtime': [],
  'database': [],
  'dependency-injection': [],
  'http-clients': [],
  'middleware': [],
  'monitoring': [],
  'performance': [],
  'services-ai': [],
  'services-core': [],
  'services-knowledge': [],
  'services-orchestrators': [],
  'services-security': [],
  'services-ttl': [],
  'utilities': [],
  'chaos-testing': [],
  'pool': [],
  'testing': [],
  'validation': [],
  'factories': [],
  'schemas': []
};

files.forEach(file => {
  if (file.startsWith('types/')) {
    categories['core-types'].push(file);
  } else if (file.startsWith('index.ts') || file.startsWith('minimal-mcp-server.ts') || file.startsWith('production-startup.ts') || file.startsWith('entry-point-factory.ts') || file.startsWith('main-di.ts')) {
    categories['core-runtime'].push(file);
  } else if (file.startsWith('db/')) {
    categories['database'].push(file);
  } else if (file.startsWith('di/')) {
    categories['dependency-injection'].push(file);
  } else if (file.startsWith('http-client/')) {
    categories['http-clients'].push(file);
  } else if (file.startsWith('pool/')) {
    categories['pool'].push(file);
  } else if (file.startsWith('middleware/')) {
    categories['middleware'].push(file);
  } else if (file.startsWith('monitoring/')) {
    categories['monitoring'].push(file);
  } else if (file.startsWith('performance/')) {
    categories['performance'].push(file);
  } else if (file.startsWith('services/ai/')) {
    categories['services-ai'].push(file);
  } else if (file.startsWith('services/knowledge/')) {
    categories['services-knowledge'].push(file);
  } else if (file.startsWith('services/orchestrators/')) {
    categories['services-orchestrators'].push(file);
  } else if (file.startsWith('services/') && (file.includes('security') || file.includes('tenant') || file.includes('pii'))) {
    categories['services-security'].push(file);
  } else if (file.startsWith('services/') && file.includes('ttl')) {
    categories['services-ttl'].push(file);
  } else if (file.startsWith('services/')) {
    categories['services-core'].push(file);
  } else if (file.startsWith('utils/')) {
    categories['utilities'].push(file);
  } else if (file.startsWith('validation/')) {
    categories['validation'].push(file);
  } else if (file.startsWith('chaos-testing/')) {
    categories['chaos-testing'].push(file);
  } else if (file.startsWith('testing/')) {
    categories['testing'].push(file);
  } else if (file.startsWith('schemas/')) {
    categories['schemas'].push(file);
  } else if (file.startsWith('factories/')) {
    categories['factories'].push(file);
  } else {
    // Uncategorized
    if (!categories['uncategorized']) categories['uncategorized'] = [];
    categories['uncategorized'].push(file);
  }
});

// Display statistics
let batchNumber = 1;
const batches = [];

console.log('\n=== File Distribution by Category ===\n');
for (const [category, files] of Object.entries(categories)) {
  if (files.length > 0) {
    console.log(`${category}: ${files.length} files`);
    batches.push({
      batch: batchNumber++,
      category,
      files: files,
      file_count: files.length
    });
  }
}

// Save individual batch files
batches.forEach(batch => {
  const filename = `tooling/ts-nocheck-batch-${batch.batch}.json`;
  fs.writeFileSync(filename, JSON.stringify(batch, null, 2));
  console.log(`Saved: ${filename} (${batch.file_count} files)`);
});

// Save master list
const masterFile = 'tooling/ts-nocheck-batches.json';
fs.writeFileSync(masterFile, JSON.stringify({
  total_files: files.length,
  batch_count: batches.length,
  batches: batches,
  generated_at: new Date().toISOString()
}, null, 2));

console.log(`\n✓ Created ${batches.length} batches`);
console.log(`✓ Saved master list: ${masterFile}`);

// Show batch summary
console.log('\n=== Batch Summary ===');
batches.forEach(batch => {
  console.log(`Batch ${batch.batch}: ${batch.category} (${batch.file_count} files)`);
});