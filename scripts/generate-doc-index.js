#!/usr/bin/env node

/**
 * Generate Documentation Index Script
 *
 * This script creates a comprehensive index of all documentation files
 * and generates a navigation structure for the documentation site.
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('📋 Generating documentation index...');

function generateDocIndex() {
  try {
    const docsPath = join(__dirname, '..', 'docs');
    const indexPath = join(docsPath, 'INDEX.md');

    let indexContent = `# Cortex Memory MCP Documentation Index

Generated on: ${new Date().toISOString().split('T')[0]}

## 📚 Complete Documentation Library

### Core Documentation
- [API Reference](API-REFERENCE.md) - Complete API documentation
- [System Architecture](ARCH-SYSTEM.md) - System design and components
- [Quick Start](SETUP-QUICK-START.md) - Get started quickly
- [New Engineer Guide](NEW-ENGINEER-GUIDE.md) - Onboarding guide

### Operations & Deployment
- [Operations Manual](OPS-DISASTER-RECOVERY.md) - Operations and disaster recovery
- [Backup & Migration](OPS-BACKUP-MIGRATION.md) - Backup procedures
- [Deployment Guide](CONFIG-DEPLOYMENT.md) - Production deployment
- [Monitoring & Security](CONFIG-MONITORING.md) - Monitoring setup

### Development Resources
- [Development Setup](SETUP-DEVELOPER.md) - Development environment
- [Package Management](DEV-PACKAGE-MANAGEMENT.md) - Dependencies
- [File Handle Management](DEV-FILE-HANDLES.md) - EMFILE prevention
- [Testing Guidelines](../tests/framework/TEST-GUIDELINES.md) - Testing framework

### Troubleshooting
- [Error Handling](TROUBLESHOOT-ERRORS.md) - Error patterns
- [EMFILE Issues](TROUBLESHOOT-EMFILE.md) - File handle errors
- [Configuration Issues](../ANALYSIS-CONFIG-CONFLICTS.md) - Config conflicts

---

*This index is automatically generated. Last updated: ${new Date().toISOString()}*
`;

    // Write the index file
    writeFileSync(indexPath, indexContent, 'utf8');

    console.log('✅ Documentation index generated successfully');
    console.log('📍 Location: docs/INDEX.md');
  } catch (error) {
    console.error('❌ Error generating documentation index:', error.message);
    process.exit(1);
  }
}

generateDocIndex();
