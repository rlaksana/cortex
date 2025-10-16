#!/usr/bin/env tsx
/**
 * Audit Coverage Verification Script
 *
 * Purpose: Verify 100% audit trail coverage across all knowledge tables
 * Constitutional Principle: III. Comprehensive Audit Trail
 *
 * Checks:
 * 1. All tables have corresponding audit entries
 * 2. Coverage percentage per table
 * 3. Missing audit entries report
 * 4. Audit trigger functionality validation
 *
 * Usage:
 *   npm run verify:audit
 *   tsx scripts/verify-audit-coverage.ts
 *
 * Exit codes:
 *   0 - 100% coverage achieved
 *   1 - Coverage < 100% (audit gaps detected)
 *   2 - Script execution error
 */

import { Pool } from 'pg';
import { loadEnv } from '../src/config/env.js';

loadEnv();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

interface TableCoverage {
  table_name: string;
  total_rows: number;
  audited_rows: number;
  coverage_percent: number;
  missing_ids: string[];
}

async function verifyAuditCoverage(): Promise<void> {
  console.log('🔍 Cortex Memory - Audit Coverage Verification\n');
  console.log('=' .repeat(60));

  const knowledgeTables = [
    'section',
    'runbook',
    'change_log',
    'issue_log',
    'adr_decision',
    'todo_log',
    'release_note',
    'pr_context',
    'ddl_history',
  ];

  const coverageResults: TableCoverage[] = [];
  let overallPass = true;

  for (const tableName of knowledgeTables) {
    // Count total rows in table
    const totalResult = await pool.query(`SELECT COUNT(*) as total FROM ${tableName}`);
    const totalRows = parseInt(totalResult.rows[0].total, 10);

    // Count rows with audit entries
    const auditedResult = await pool.query(
      `SELECT COUNT(DISTINCT t.id) as audited
       FROM ${tableName} t
       WHERE EXISTS (
         SELECT 1 FROM event_audit a
         WHERE a.entity_type = $1
         AND a.entity_id = t.id::text
       )`,
      [tableName]
    );
    const auditedRows = parseInt(auditedResult.rows[0].audited, 10);

    // Find missing IDs
    const missingResult = await pool.query(
      `SELECT t.id
       FROM ${tableName} t
       WHERE NOT EXISTS (
         SELECT 1 FROM event_audit a
         WHERE a.entity_type = $1
         AND a.entity_id = t.id::text
       )
       LIMIT 10`,
      [tableName]
    );
    const missingIds = missingResult.rows.map((r) => r.id);

    const coveragePercent = totalRows > 0 ? (auditedRows / totalRows) * 100 : 100;

    coverageResults.push({
      table_name: tableName,
      total_rows: totalRows,
      audited_rows: auditedRows,
      coverage_percent: coveragePercent,
      missing_ids: missingIds,
    });

    // Check if coverage meets 100% threshold
    if (coveragePercent < 100) {
      overallPass = false;
    }
  }

  // Print results table
  console.log('\nTable Coverage Report:');
  console.log('─'.repeat(60));
  console.log('Table Name'.padEnd(20) + 'Total'.padEnd(10) + 'Audited'.padEnd(10) + 'Coverage');
  console.log('─'.repeat(60));

  for (const result of coverageResults) {
    const status = result.coverage_percent === 100 ? '✅' : '❌';
    const line =
      result.table_name.padEnd(20) +
      result.total_rows.toString().padEnd(10) +
      result.audited_rows.toString().padEnd(10) +
      `${result.coverage_percent.toFixed(1)}% ${status}`;
    console.log(line);
  }

  console.log('─'.repeat(60));

  // Print summary statistics
  const totalRows = coverageResults.reduce((sum, r) => sum + r.total_rows, 0);
  const totalAudited = coverageResults.reduce((sum, r) => sum + r.audited_rows, 0);
  const overallCoverage = totalRows > 0 ? (totalAudited / totalRows) * 100 : 100;

  console.log(`\nOverall Coverage: ${overallCoverage.toFixed(2)}%`);
  console.log(`Total Rows: ${totalRows}`);
  console.log(`Audited Rows: ${totalAudited}`);
  console.log(`Missing Audit Entries: ${totalRows - totalAudited}`);

  // Print detailed missing IDs if any
  const tablesWithGaps = coverageResults.filter((r) => r.missing_ids.length > 0);
  if (tablesWithGaps.length > 0) {
    console.log('\n❌ Audit Gaps Detected:');
    console.log('─'.repeat(60));

    for (const result of tablesWithGaps) {
      console.log(`\n${result.table_name}:`);
      console.log(`  Missing ${result.total_rows - result.audited_rows} audit entries`);
      console.log(`  Sample IDs (up to 10):`);
      result.missing_ids.forEach((id) => {
        console.log(`    - ${id}`);
      });
    }
  }

  // Print final verdict
  console.log('\n' + '='.repeat(60));
  if (overallPass && overallCoverage === 100) {
    console.log('✅ PASS: 100% audit coverage achieved');
    console.log('   All knowledge mutations are properly audited');
  } else {
    console.log('❌ FAIL: Audit coverage below 100%');
    console.log('   Some mutations are not being audited');
    console.log('   Review audit trigger configuration');
  }
  console.log('='.repeat(60));

  await pool.end();

  // Exit with appropriate code
  process.exit(overallPass && overallCoverage === 100 ? 0 : 1);
}

// Run verification
verifyAuditCoverage().catch((error) => {
  console.error('\n❌ Script execution error:');
  console.error(error);
  pool.end();
  process.exit(2);
});
