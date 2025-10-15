#!/usr/bin/env node

import { config } from 'dotenv';
config();

import pg from 'pg';
const { Pool } = pg;

console.log('Testing PostgreSQL connection...');
console.log('DATABASE_URL:', process.env.DATABASE_URL);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

try {
  const client = await pool.connect();
  console.log('✅ Connection successful!');

  const result = await client.query('SELECT current_database(), current_user, version()');
  console.log('Database:', result.rows[0].current_database);
  console.log('User:', result.rows[0].current_user);
  console.log('Version:', result.rows[0].version.split('\n')[0]);

  client.release();
  await pool.end();
  console.log('✅ Test complete');
} catch (error) {
  console.error('❌ Connection failed:', error.message);
  console.error('Error details:', error);
  process.exit(1);
}
