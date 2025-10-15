import { Pool } from 'pg';
import { loadEnv } from '../config/env.js';
import { logger } from '../utils/logger.js';

let pool: Pool | null = null;

export function getPool(): Pool {
  if (!pool) {
    const env = loadEnv();
    pool = new Pool({
      connectionString: env.DATABASE_URL,
      min: env.DB_POOL_MIN,
      max: env.DB_POOL_MAX,
      idleTimeoutMillis: env.DB_IDLE_TIMEOUT_MS,
    });

    pool.on('error', (err) => {
      logger.error({ err }, 'Database pool error');
    });

    logger.info(
      {
        min: env.DB_POOL_MIN,
        max: env.DB_POOL_MAX,
        idle_timeout_ms: env.DB_IDLE_TIMEOUT_MS,
      },
      'Database pool initialized'
    );
  }
  return pool;
}

export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
    logger.info('Database pool closed');
  }
}
