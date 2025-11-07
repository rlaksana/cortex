#!/usr/bin/env node

import { execSync } from 'child_process';
import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Dependency cleanup and resolution script
 */

console.log('🔧 Cleaning up dependency issues...');

// 1. Remove unmet optional dependencies
try {
  console.log('\n1️⃣  Removing unmet optional dependencies...');
  execSync('npm ls --depth=1 | grep "UNMET OPTIONAL DEPENDENCY" | cut -d"│" -f3 | xargs npm uninstall --save-optional || true', {
    stdio: 'inherit',
    shell: true
  });
  console.log('✅ Unmet optional dependencies removed');
} catch (error) {
  console.log('⚠️  Optional dependency cleanup failed (non-critical)');
}

// 2. Reinstall production dependencies
try {
  console.log('\n2️⃣  Reinstalling production dependencies...');
  execSync('npm ci --production', { stdio: 'inherit', shell: true });
  console.log('✅ Production dependencies reinstalled');
} catch (error) {
  console.log('⚠️  Production dependency reinstall failed, trying alternative...');
  try {
    execSync('npm install --production', { stdio: 'inherit', shell: true });
    console.log('✅ Production dependencies installed via npm install');
  } catch (fallbackError) {
    console.error('❌ Production dependency installation failed');
  }
}

// 3. Install missing critical dependencies
const criticalDeps = [
  '@modelcontextprotocol/sdk@latest',
  '@qdrant/js-client-rest@^1.15.1',
  'zod@^3.25.76',
  'uuid@^13.0.0',
  'dotenv@^17.2.3'
];

try {
  console.log('\n3️⃣  Installing critical dependencies...');
  execSync(`npm install ${criticalDeps.join(' ')}`, { stdio: 'inherit', shell: true });
  console.log('✅ Critical dependencies installed');
} catch (error) {
  console.error('❌ Critical dependency installation failed:', error.message);
}

// 4. Update package.json to remove problematic optional dependencies
try {
  console.log('\n4️⃣  Cleaning up package.json...');
  const packagePath = join(__dirname, '..', 'package.json');
  const packageJson = JSON.parse(readFileSync(packagePath, 'utf-8'));

  // Remove problematic optional dev dependencies that cause build issues
  const problematicDeps = [
    '@cfworker/json-schema',
    '@vitest/browser',
    'jiti',
    'ws',
    '@swc/core',
    '@swc/wasm',
    'fsevents',
    '@edge-runtime/vm',
    '@types/debug',
    '@vitest/browser-playwright',
    '@vitest/browser-preview',
    '@vitest/browser-webdriverio',
    'happy-dom',
    'jsdom'
  ];

  let cleanedCount = 0;
  problematicDeps.forEach(dep => {
    if (packageJson.devDependencies?.[dep]) {
      delete packageJson.devDependencies[dep];
      cleanedCount++;
    }
    if (packageJson.optionalDependencies?.[dep]) {
      delete packageJson.optionalDependencies[dep];
      cleanedCount++;
    }
  });

  if (cleanedCount > 0) {
    writeFileSync(packagePath, JSON.stringify(packageJson, null, 2));
    console.log(`✅ Removed ${cleanedCount} problematic dependencies from package.json`);
  } else {
    console.log('✅ No problematic dependencies found in package.json');
  }
} catch (error) {
  console.log('⚠️  Package.json cleanup failed:', error.message);
}

console.log('\n🎉 Dependency cleanup completed!');
console.log('\n📋 Next steps:');
console.log('1. Run: npm run type-check');
console.log('2. Run: npm run build');
console.log('3. Run: npm run test:unit');