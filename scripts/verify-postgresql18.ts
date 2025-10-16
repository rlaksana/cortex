#!/usr/bin/env node

/**
 * Database Schema Verification Script
 *
 * Checks PostgreSQL 18 compatibility and verifies all schema components
 */

import { Pool } from 'pg';
import dotenv from 'dotenv';
import { readFileSync } from 'fs';

// Load environment
dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://cortex:@localhost:5432/cortex_dev',
});

interface SchemaIssue {
  table: string;
  issue: string;
  severity: 'error' | 'warning' | 'info';
  fix?: string;
}

interface SchemaCheck {
  name: string;
  passed: boolean;
  issues: SchemaIssue[];
}

async function checkPostgreSQLVersion(): Promise<SchemaCheck> {
  const issues: SchemaIssue[] = [];

  try {
    const result = await pool.query('SHOW server_version_num');
    const versionNum = parseInt(result.rows[0].server_version_num);
    const versionResult = await pool.query('SHOW server_version');
    const versionString = versionResult.rows[0].server_version;

    console.log(`PostgreSQL version: ${versionString} (${versionNum})`);

    if (versionNum < 180000) {
      issues.push({
        table: 'system',
        issue: `PostgreSQL version ${versionString} is not 18+. Required: PostgreSQL 18+`,
        severity: 'error',
        fix: 'Upgrade PostgreSQL to version 18 or higher'
      });
    } else {
      console.log('✓ PostgreSQL version is compatible');
    }

    return {
      name: 'PostgreSQL Version Check',
      passed: versionNum >= 180000,
      issues
    };
  } catch (error) {
    issues.push({
      table: 'system',
      issue: `Failed to check PostgreSQL version: ${error}`,
      severity: 'error'
    });
    return {
      name: 'PostgreSQL Version Check',
      passed: false,
      issues
    };
  }
}

async function checkExtensions(): Promise<SchemaCheck> {
  const issues: SchemaIssue[] = [];

  try {
    // Check pgcrypto extension (for gen_random_uuid)
    const result = await pool.query(`
      SELECT extname FROM pg_extension WHERE extname = 'pgcrypto'
    `);

    if (result.rows.length === 0) {
      issues.push({
        table: 'system',
        issue: 'pgcrypto extension not found',
        severity: 'error',
        fix: 'CREATE EXTENSION pgcrypto;'
      });
    } else {
      console.log('✓ pgcrypto extension is available');
    }

    // Check for uuid-ossp (should NOT be used in PostgreSQL 18)
    const uuidResult = await pool.query(`
      SELECT extname FROM pg_extension WHERE extname = 'uuid-ossp'
    `);

    if (uuidResult.rows.length > 0) {
      issues.push({
        table: 'system',
        issue: 'uuid-ossp extension found (deprecated in PostgreSQL 18)',
        severity: 'warning',
        fix: 'Consider removing uuid-ossp extension and using gen_random_uuid() instead'
      });
    } else {
      console.log('✓ uuid-ossp extension not found (good for PostgreSQL 18)');
    }

    return {
      name: 'Extensions Check',
      passed: result.rows.length > 0,
      issues
    };
  } catch (error) {
    issues.push({
      table: 'system',
      issue: `Failed to check extensions: ${error}`,
      severity: 'error'
    });
    return {
      name: 'Extensions Check',
      passed: false,
      issues
    };
  }
}

async function checkPurgeMetadataTable(): Promise<SchemaCheck> {
  const issues: SchemaIssue[] = [];

  try {
    // Check if purge_metadata table exists
    const tableCheck = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_name = 'purge_metadata'
      )
    `);

    if (!tableCheck.rows[0].exists) {
      issues.push({
        table: 'purge_metadata',
        issue: 'purge_metadata table does not exist',
        severity: 'error',
        fix: 'Create purge_metadata table according to auto-purge service requirements'
      });
      return {
        name: 'Purge Metadata Table Check',
        passed: false,
        issues
      };
    }

    // Check table structure
    const columns = await pool.query(`
      SELECT column_name, data_type, is_nullable, column_default
      FROM information_schema.columns
      WHERE table_schema = 'public'
      AND table_name = 'purge_metadata'
      ORDER BY ordinal_position
    `);

    const expectedColumns = [
      { name: 'id', type: 'integer', nullable: 'NO', default: '1' },
      { name: 'last_purge_at', type: 'timestamp with time zone', nullable: 'NO' },
      { name: 'operations_since_purge', type: 'integer', nullable: 'NO' },
      { name: 'time_threshold_hours', type: 'integer', nullable: 'NO' },
      { name: 'operation_threshold', type: 'integer', nullable: 'NO' },
      { name: 'deleted_counts', type: 'jsonb', nullable: 'YES' },
      { name: 'last_duration_ms', type: 'integer', nullable: 'YES' },
      { name: 'enabled', type: 'boolean', nullable: 'NO' },
      { name: 'created_at', type: 'timestamp with time zone', nullable: 'NO' },
      { name: 'updated_at', type: 'timestamp with time zone', nullable: 'NO' }
    ];

    const foundColumns = columns.rows.map(row => row.column_name);

    for (const expected of expectedColumns) {
      const found = columns.rows.find(row => row.column_name === expected.name);
      if (!found) {
        issues.push({
          table: 'purge_metadata',
          issue: `Missing column: ${expected.name}`,
          severity: 'error',
          fix: `ALTER TABLE purge_metadata ADD COLUMN ${expected.name} ${expected.type};`
        });
      } else if (found.data_type !== expected.type) {
        issues.push({
          table: 'purge_metadata',
          issue: `Column ${expected.name} has wrong type: ${found.data_type}, expected ${expected.type}`,
          severity: 'error'
        });
      }
    }

    // Check for singleton record
    const recordCheck = await pool.query('SELECT COUNT(*) FROM purge_metadata');
    const count = parseInt(recordCheck.rows[0].count);

    if (count === 0) {
      issues.push({
        table: 'purge_metadata',
        issue: 'No records found in purge_metadata table',
        severity: 'error',
        fix: 'INSERT INTO purge_metadata (id) VALUES (1) ON CONFLICT (id) DO NOTHING;'
      });
    } else if (count > 1) {
      issues.push({
        table: 'purge_metadata',
        issue: `Multiple records found in purge_metadata table: ${count}`,
        severity: 'warning',
        fix: 'Ensure only one record exists (id = 1)'
      });
    }

    console.log('✓ purge_metadata table structure checked');

    return {
      name: 'Purge Metadata Table Check',
      passed: issues.filter(i => i.severity === 'error').length === 0,
      issues
    };
  } catch (error) {
    issues.push({
      table: 'purge_metadata',
      issue: `Failed to check purge_metadata table: ${error}`,
      severity: 'error'
    });
    return {
      name: 'Purge Metadata Table Check',
      passed: false,
      issues
    };
  }
}

async function checkKnowledgeTables(): Promise<SchemaCheck> {
  const issues: SchemaIssue[] = [];

  const expectedTables = [
    'document', 'section', 'runbook', 'change_log', 'issue_log',
    'adr_decision', 'todo_log', 'release_note', 'ddl_history', 'pr_context',
    'knowledge_entity', 'knowledge_relation', 'knowledge_observation',
    'incident_log', 'release_log', 'risk_log', 'assumption_log'
  ];

  try {
    // Check if all expected tables exist
    for (const tableName of expectedTables) {
      const result = await pool.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables
          WHERE table_schema = 'public'
          AND table_name = '${tableName}'
        )
      `);

      if (!result.rows[0].exists) {
        issues.push({
          table: tableName,
          issue: `Table ${tableName} does not exist`,
          severity: 'error'
        });
      }
    }

    // Check for UUID default usage (should use gen_random_uuid)
    const uuidColumns = await pool.query(`
      SELECT table_name, column_name, column_default
      FROM information_schema.columns
      WHERE table_schema = 'public'
      AND data_type = 'uuid'
      AND (column_default IS NULL OR column_default NOT LIKE '%gen_random_uuid()%')
    `);

    for (const row of uuidColumns.rows) {
      if (row.column_default) {
        issues.push({
          table: row.table_name,
          issue: `Column ${row.column_name} uses non-PostgreSQL 18 UUID default: ${row.column_default}`,
          severity: 'warning',
          fix: `Change to DEFAULT gen_random_uuid()`
        });
      } else {
        issues.push({
          table: row.table_name,
          issue: `Column ${row.column_name} has no default UUID generation`,
          severity: 'error',
          fix: `Add DEFAULT gen_random_uuid()`
        });
      }
    }

    console.log('✓ Knowledge tables checked');

    return {
      name: 'Knowledge Tables Check',
      passed: issues.filter(i => i.severity === 'error').length === 0,
      issues
    };
  } catch (error) {
    issues.push({
      table: 'system',
      issue: `Failed to check knowledge tables: ${error}`,
      severity: 'error'
    });
    return {
      name: 'Knowledge Tables Check',
      passed: false,
      issues
    };
  }
}

async function checkIndexesAndConstraints(): Promise<SchemaCheck> {
  const issues: SchemaIssue[] = [];

  try {
    // Check for important indexes
    const expectedIndexes = [
      'idx_section_ts',
      'idx_section_tags',
      'idx_knowledge_entity_type',
      'idx_purge_metadata_enabled',
      'idx_event_audit_changed_at'
    ];

    for (const indexName of expectedIndexes) {
      const result = await pool.query(`
        SELECT EXISTS (
          SELECT FROM pg_indexes
          WHERE schemaname = 'public'
          AND indexname = '${indexName}'
        )
      `);

      if (!result.rows[0].exists) {
        issues.push({
          table: 'system',
          issue: `Missing index: ${indexName}`,
          severity: 'warning',
          fix: `CREATE INDEX ${indexName} ON ...`
        });
      }
    }

    console.log('✓ Indexes and constraints checked');

    return {
      name: 'Indexes and Constraints Check',
      passed: issues.filter(i => i.severity === 'error').length === 0,
      issues
    };
  } catch (error) {
    issues.push({
      table: 'system',
      issue: `Failed to check indexes: ${error}`,
      severity: 'error'
    });
    return {
      name: 'Indexes and Constraints Check',
      passed: false,
      issues
    };
  }
}

async function main() {
  console.log('🔍 PostgreSQL 18 Schema Verification\n');

  const checks = [
    await checkPostgreSQLVersion(),
    await checkExtensions(),
    await checkPurgeMetadataTable(),
    await checkKnowledgeTables(),
    await checkIndexesAndConstraints()
  ];

  console.log('\n📋 Summary Report\n');

  let totalErrors = 0;
  let totalWarnings = 0;

  for (const check of checks) {
    console.log(`\n${check.passed ? '✅' : '❌'} ${check.name}`);

    if (check.issues.length > 0) {
      for (const issue of check.issues) {
        const symbol = issue.severity === 'error' ? '❌' : issue.severity === 'warning' ? '⚠️' : 'ℹ️';
        console.log(`   ${symbol} ${issue.table}: ${issue.issue}`);
        if (issue.fix) {
          console.log(`      💡 Fix: ${issue.fix}`);
        }

        if (issue.severity === 'error') totalErrors++;
        else if (issue.severity === 'warning') totalWarnings++;
      }
    }
  }

  console.log(`\n🎯 Total Issues: ${totalErrors} errors, ${totalWarnings} warnings`);

  if (totalErrors > 0) {
    console.log('\n🚨 Schema verification FAILED. Please fix all errors before proceeding.');
    process.exit(1);
  } else if (totalWarnings > 0) {
    console.log('\n⚠️ Schema verification PASSED with warnings. Review warnings for optimal performance.');
  } else {
    console.log('\n✅ Schema verification PASSED. All PostgreSQL 18 requirements met!');
  }

  await pool.end();
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(error => {
    console.error('Verification failed:', error);
    process.exit(1);
  });
}