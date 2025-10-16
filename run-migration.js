import { Pool } from 'pg';
import fs from 'fs';
import path from 'path';

const pool = new Pool({
  host: 'localhost',
  port: 5433,
  database: 'cortex_prod',
  user: 'cortex',
  password: '',
});

async function runMigration() {
  try {
    console.log('🔄 Running database schema alignment migration...');

    const migrationPath = path.join(process.cwd(), 'migrations', '20241016000001_fix_section_table.sql');
    const migrationSQL = fs.readFileSync(migrationPath, 'utf8');

    await pool.query(migrationSQL);

    console.log('✅ Migration completed successfully!');
    console.log('📊 Database schema now aligned with Prisma models.');

    // Verify the migration worked
    const result = await pool.query(`
      SELECT column_name, data_type, is_nullable, character_maximum_length
      FROM information_schema.columns
      WHERE table_name = 'section'
      AND column_name IN ('title', 'heading', 'content_hash', 'body_jsonb')
      ORDER BY column_name
    `);

    console.log('\n📋 Section table columns after migration:');
    result.rows.forEach(col => {
      console.log(`  ${col.column_name}: ${col.data_type} (${col.is_nullable}) ${col.character_maximum_length ? `max: ${col.character_maximum_length}` : ''}`);
    });

  } catch (error) {
    console.error('❌ Migration failed:', error.message);
    throw error;
  } finally {
    await pool.end();
  }
}

runMigration().catch(console.error);