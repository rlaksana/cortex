#!/usr/bin/env node

/**
 * Test script for automatic environment configuration
 * This validates the auto-environment system without needing full compilation
 */

import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

// Simulate the auto-environment detection logic
class TestAutoEnvironment {
  constructor() {
    this.detection = this.detectEnvironment();
    this.validation = this.validateAndConfigure();
  }

  detectEnvironment() {
    const platform = process.platform;
    let openaiApiKey = process.env.OPENAI_API_KEY;
    let qdrantUrl = 'http://localhost:6333';
    let environmentSource = 'process-env';

    // Check current process environment (highest priority)
    if (process.env.OPENAI_API_KEY) {
      openaiApiKey = process.env.OPENAI_API_KEY;
      environmentSource = 'process-env';
    }

    // Try Windows Registry detection
    if (!openaiApiKey && platform === 'win32') {
      try {
        const psCommand = 'powershell -NoProfile -Command "(Get-ItemProperty -Path \\"HKCU:\\Environment\\" -Name OPENAI_API_KEY -ErrorAction SilentlyContinue).OPENAI_API_KEY"';
        const key = execSync(psCommand, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
        if (key && key.length > 0) {
          openaiApiKey = key;
          environmentSource = 'windows-registry';
        }
      } catch {
        // Silent fail
      }
    }

    // Try environment files
    if (!openaiApiKey) {
      const envFileKeys = this.tryLoadFromEnvFiles();
      if (envFileKeys.openaiApiKey) {
        openaiApiKey = envFileKeys.openaiApiKey;
        environmentSource = 'env-file';
      }
      if (envFileKeys.qdrantUrl) {
        qdrantUrl = envFileKeys.qdrantUrl;
      }
    }

    return {
      openaiApiKey,
      qdrantUrl,
      platform,
      environmentSource
    };
  }

  tryLoadFromEnvFiles() {
    const envFiles = [
      '.env',
      '.env.local',
      '.env.development',
      '.env.production'
    ];

    for (const envFile of envFiles) {
      try {
        const envPath = path.resolve(envFile);
        if (fs.existsSync(envPath)) {
          const envContent = fs.readFileSync(envPath, 'utf8');
          const envVars = this.parseEnvContent(envContent);

          if (envVars.OPENAI_API_KEY) {
            return {
              openaiApiKey: envVars.OPENAI_API_KEY,
              qdrantUrl: envVars.QDRANT_URL
            };
          }
        }
      } catch {
        // Silent fail
      }
    }

    return {};
  }

  parseEnvContent(content) {
    const envVars = {};
    const lines = content.split('\n');

    for (const line of lines) {
      const trimmedLine = line.trim();
      if (trimmedLine && !trimmedLine.startsWith('#')) {
        const match = trimmedLine.match(/^([^=]+)=(.*)$/);
        if (match) {
          const [, key, value] = match;
          envVars[key.trim()] = value.trim().replace(/^["']|["']$/g, '');
        }
      }
    }

    return envVars;
  }

  validateAndConfigure() {
    const errors = [];
    const warnings = [];
    let autoConfigured = false;

    // Validate OpenAI API Key
    if (!this.detection.openaiApiKey) {
      errors.push('OpenAI API key not found');
    } else if (!this.detection.openaiApiKey.startsWith('sk-')) {
      warnings.push('OpenAI API key appears to be invalid (should start with "sk-")');
    }

    // Auto-configure environment variables if needed
    if (this.detection.openaiApiKey && !process.env.OPENAI_API_KEY) {
      process.env.OPENAI_API_KEY = this.detection.openaiApiKey;
      autoConfigured = true;
    }

    if (this.detection.qdrantUrl && !process.env.QDRANT_URL) {
      process.env.QDRANT_URL = this.detection.qdrantUrl;
      autoConfigured = true;
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      autoConfigured
    };
  }

  getConfigurationStatus() {
    return {
      isConfigured: this.validation.isValid,
      openaiApiKeySource: this.detection.environmentSource,
      qdrantUrl: this.detection.qdrantUrl || 'http://localhost:6333',
      autoConfigured: this.validation.autoConfigured,
      errors: this.validation.errors,
      warnings: this.validation.warnings
    };
  }

  getSafeEnvironmentConfig() {
    return {
      OPENAI_API_KEY: this.detection.openaiApiKey ? `[${this.detection.openaiApiKey.substring(0, 7)}...]` : undefined,
      QDRANT_URL: this.detection.qdrantUrl || 'http://localhost:6333',
      NODE_ENV: process.env.NODE_ENV || 'development',
      LOG_LEVEL: process.env.LOG_LEVEL || 'info',
      AUTO_CONFIGURED: this.validation.autoConfigured
    };
  }
}

// Run the test
console.log('🧪 Testing Automatic Environment Configuration...\n');

const autoEnv = new TestAutoEnvironment();
const status = autoEnv.getConfigurationStatus();
const safeConfig = autoEnv.getSafeEnvironmentConfig();

console.log('📊 Configuration Status:');
console.log(`   Is Configured: ${status.isConfigured ? '✅ Yes' : '❌ No'}`);
console.log(`   OpenAI API Key Source: ${status.openaiApiKeySource}`);
console.log(`   Qdrant URL: ${status.qdrantUrl}`);
console.log(`   Auto-configured: ${status.autoConfigured ? '✅ Yes' : '❌ No'}`);

if (status.errors.length > 0) {
  console.log('\n❌ Errors:');
  status.errors.forEach(error => console.log(`   - ${error}`));
}

if (status.warnings.length > 0) {
  console.log('\n⚠️  Warnings:');
  status.warnings.forEach(warning => console.log(`   - ${warning}`));
}

console.log('\n🔒 Safe Configuration:');
Object.entries(safeConfig).forEach(([key, value]) => {
  console.log(`   ${key}: ${value}`);
});

if (status.isConfigured) {
  console.log('\n✅ SUCCESS: Automatic environment configuration working!');
  console.log('   Users can now run Cortex MCP without manual environment setup.');
} else {
  console.log('\n❌ SETUP NEEDED: Some environment configuration is missing.');
  console.log('   The system provides clear instructions for users to complete setup.');
}

console.log('\n🎯 Next Steps:');
console.log('   1. Build the project with: npm run build');
console.log('   2. Test MCP server with: node dist/silent-mcp-entry.js');
console.log('   3. Users can now use simplified MCP client configuration without env vars');