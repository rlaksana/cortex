#!/usr/bin/env node

import { config } from 'dotenv';
import { Pool } from 'pg';

/**
 * Comprehensive Database Schema Validation
 *
 * This script validates that the actual database schema matches expected definitions
 * to prevent silent failures and type mismatches like the ts_rank issue.
 */

// Load environment variables
config();
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';

interface ColumnDefinition {
  name: string;
  type: string;
  nullable: boolean;
  default?: string;
}

interface TableDefinition {
  name: string;
  columns: ColumnDefinition[];
}

interface ValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Extract table definitions from SQL migration files
 */
function parseTableDefinitions(sqlContent: string): TableDefinition[] {
  const tables: TableDefinition[] = [];
  const createTableRegex = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\(\s*([^)]+)\);/gis;
  let match;

  while ((match = createTableRegex.exec(sqlContent)) !== null) {
    const tableName = match[1];
    const tableBody = match[2];

    const columns: ColumnDefinition[] = [];
    const columnLines = tableBody.split(',').map(line => line.trim());

    for (const line of columnLines) {
      if (line.startsWith('CONSTRAINT') || line.startsWith('PRIMARY KEY') || line.startsWith('UNIQUE')) {
        continue; // Skip constraints for now
      }

      const columnMatch = line.match(/(\w+)\s+(.+?)(?:\s+DEFAULT\s+([^,\s]+))?\s*(\s*NOT\s+NULL|\s*NULL)?\s*$/i);
      if (columnMatch) {
        const [, name, type, defaultValue, nullability] = columnMatch;
        columns.push({
          name,
          type: type.trim(),
          nullable: !nullability?.includes('NOT NULL'),
          default: defaultValue?.trim()
        });
      }
    }

    tables.push({ name: tableName, columns });
  }

  return tables;
}

/**
 * Get actual table structure from database
 */
async function getActualSchema(pool: Pool, tableName: string): Promise<ColumnDefinition[]> {
  const query = `
    SELECT
      column_name,
      data_type,
      is_nullable,
      column_default
    FROM information_schema.columns
    WHERE table_name = $1
    ORDER BY ordinal_position
  `;

  const result = await pool.query(query, [tableName]);

  return result.rows.map(row => ({
    name: row.column_name,
    type: row.data_type,
    nullable: row.is_nullable === 'YES',
    default: row.column_default
  }));
}

/**
 * Compare expected vs actual schema
 */
function compareSchemas(expected: TableDefinition, actual: ColumnDefinition[]): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Create map of actual columns for easy lookup
  const actualColumns = new Map(actual.map(col => [col.name, col]));

  for (const expectedCol of expected.columns) {
    const actualCol = actualColumns.get(expectedCol.name);

    if (!actualCol) {
      errors.push(`Missing column: ${expected.name}.${expectedCol.name}`);
      continue;
    }

    // Check type compatibility
    if (!isTypeCompatible(expectedCol.type, actualCol.type)) {
      errors.push(
        `Type mismatch in ${expected.name}.${expectedCol.name}: ` +
        `expected ${expectedCol.type}, got ${actualCol.type}`
      );
    }

    // Check nullability
    if (expectedCol.nullable !== actualCol.nullable) {
      warnings.push(
        `Nullability mismatch in ${expected.name}.${expectedCol.name}: ` +
        `expected nullable=${expectedCol.nullable}, got nullable=${actualCol.nullable}`
      );
    }
  }

  // Check for extra columns
  for (const actualCol of actual) {
    if (!expected.columns.find(col => col.name === actualCol.name)) {
      warnings.push(`Extra column: ${expected.name}.${actualCol.name} (${actualCol.type})`);
    }
  }

  return {
    isValid: errors.length === 0,
    errors,
    warnings
  };
}

/**
 * Check type compatibility (handles common variations)
 */
function isTypeCompatible(expected: string, actual: string): boolean {
  // Normalize types
  const normalizeType = (type: string) => type.toLowerCase().replace(/\s+/g, ' ').trim();

  const expectedNorm = normalizeType(expected);
  const actualNorm = normalizeType(actual);

  // Direct match
  if (expectedNorm === actualNorm) return true;

  // Handle common variations
  const typeMappings: Record<string, string[]> = {
    'text': ['character varying', 'varchar'],
    'integer': ['int', 'int4'],
    'bigint': ['int8'],
    'jsonb': ['json'],
    'timestamptz': ['timestamp with time zone', 'timestamp']
  };

  for (const [baseType, variations] of Object.entries(typeMappings)) {
    if ((expectedNorm === baseType || variations.includes(expectedNorm)) &&
        (actualNorm === baseType || variations.includes(actualNorm))) {
      return true;
    }
  }

  return false;
}

/**
 * Main validation function
 */
async function validateDatabaseSchema(): Promise<void> {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.error('DATABASE_URL environment variable is required');
    process.exit(1);
  }

  const pool = new Pool({ connectionString });

  try {
    console.log('🔍 Starting comprehensive database schema validation...\n');

    // Load migration files
    const migrationsDir = join(process.cwd(), 'migrations');
    const migrationFiles = readdirSync(migrationsDir)
      .filter(f => f.endsWith('.sql'))
      .sort();

    let hasErrors = false;

    for (const file of migrationFiles) {
      console.log(`📄 Processing migration: ${file}`);
      const filePath = join(migrationsDir, file);
      const sqlContent = readFileSync(filePath, 'utf8');

      // Parse expected schema
      const expectedTables = parseTableDefinitions(sqlContent);

      for (const expectedTable of expectedTables) {
        console.log(`  📋 Validating table: ${expectedTable.name}`);

        try {
          const actualColumns = await getActualSchema(pool, expectedTable.name);
          const result = compareSchemas(expectedTable, actualColumns);

          if (result.isValid) {
            console.log(`    ✅ Table ${expectedTable.name} schema is valid`);
          } else {
            console.log(`    ❌ Table ${expectedTable.name} has schema errors:`);
            result.errors.forEach(error => console.log(`      - ${error}`));
            hasErrors = true;
          }

          if (result.warnings.length > 0) {
            console.log(`    ⚠️  Table ${expectedTable.name} warnings:`);
            result.warnings.forEach(warning => console.log(`      - ${warning}`));
          }
        } catch (error) {
          console.log(`    ❌ Could not validate table ${expectedTable.name}: ${(error as Error).message}`);
          hasErrors = true;
        }
      }
    }

    // Special validation for critical columns
    console.log('\n🔬 Validating critical function dependencies...');

    try {
      // Test ts_rank function with proper tsvector column
      const testResult = await pool.query(`
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'section' AND column_name = 'ts'
      `);

      if (testResult.rows.length === 0) {
        console.log('    ❌ Critical column "section.ts" does not exist');
        hasErrors = true;
      } else if (testResult.rows[0].data_type !== 'tsvector') {
        console.log(`    ❌ Critical column "section.ts" has wrong type: ${testResult.rows[0].data_type} (expected tsvector)`);
        hasErrors = true;
      } else {
        console.log('    ✅ Critical column "section.ts" has correct type (tsvector)');

        // Test ts_rank function works
        const rankTest = await pool.query(`
          SELECT ts_rank(ts, to_tsquery('english', 'test')) as rank
          FROM section
          WHERE ts @@ to_tsquery('english', 'test')
          LIMIT 1
        `);

        if (rankTest.rows.length > 0) {
          console.log('    ✅ ts_rank function works correctly with section.ts');
        } else {
          console.log('    ⚠️  Could not test ts_rank function (no matching data)');
        }
      }
    } catch (error) {
      console.log(`    ❌ Error validating ts_rank function: ${(error as Error).message}`);
      hasErrors = true;
    }

    console.log('\n' + '='.repeat(60));

    if (hasErrors) {
      console.log('❌ DATABASE SCHEMA VALIDATION FAILED');
      console.log('   Please fix the schema issues before proceeding.');
      process.exit(1);
    } else {
      console.log('✅ DATABASE SCHEMA VALIDATION PASSED');
      console.log('   All schema definitions match the actual database structure.');
    }

  } finally {
    await pool.end();
  }
}

// Run validation if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  validateDatabaseSchema()
    .catch(error => {
      console.error('Schema validation failed:', error);
      process.exit(1);
    });
}