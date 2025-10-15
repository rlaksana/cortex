/**
 * Category 1: Database Connectivity Tests
 * Priority: P0 - CRITICAL
 *
 * Tests basic database connectivity and connection pooling
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Pool, Client } from 'pg';
import net from 'net';

const DB_CONFIG = {
  connectionString:
    process.env.DATABASE_URL || 'postgresql://cortex:trust@localhost:5433/cortex_prod',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
};

describe('Category 1: Database Connectivity', () => {
  describe('DB-001: TCP Connection', () => {
    it('should establish TCP connection to server', async () => {
      const url = new URL(DB_CONFIG.connectionString);
      const host = url.hostname;
      const port = parseInt(url.port, 10);

      await new Promise((resolve, reject) => {
        const socket = net.createConnection({ host, port }, () => {
          socket.end();
          resolve(true);
        });

        socket.on('error', reject);
        socket.setTimeout(5000, () => {
          socket.destroy();
          reject(new Error('Connection timeout'));
        });
      });
    });
  });

  describe('DB-002: PostgreSQL Authentication', () => {
    it('should authenticate successfully', async () => {
      const client = new Client(DB_CONFIG);

      await expect(client.connect()).resolves.not.toThrow();
      await client.end();
    });

    it('should reject invalid credentials', async () => {
      const badConfig = {
        ...DB_CONFIG,
        connectionString: DB_CONFIG.connectionString.replace(/:[^:@]+@/, ':wrong-password@'),
      };
      const client = new Client(badConfig);

      await expect(client.connect()).rejects.toThrow();
    });
  });

  describe('DB-003: Execute Simple Query', () => {
    let client: Client;

    beforeAll(async () => {
      client = new Client(DB_CONFIG);
      await client.connect();
    });

    afterAll(async () => {
      await client.end();
    });

    it('should execute SELECT query', async () => {
      const result = await client.query('SELECT 1 as test');
      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].test).toBe(1);
    });

    it('should execute version query', async () => {
      const result = await client.query('SELECT version()');
      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].version).toContain('PostgreSQL');
    });

    it('should handle query timeout', async () => {
      const timeoutClient = new Client({
        ...DB_CONFIG,
        query_timeout: 100,
      });
      await timeoutClient.connect();

      await expect(timeoutClient.query('SELECT pg_sleep(1)')).rejects.toThrow();

      await timeoutClient.end();
    });
  });

  describe('DB-004: Connection Pool (10 concurrent)', () => {
    let pool: Pool;

    beforeAll(() => {
      pool = new Pool({ ...DB_CONFIG, max: 10 });
    });

    afterAll(async () => {
      await pool.end();
    });

    it('should handle 10 concurrent connections', async () => {
      const promises = Array.from({ length: 10 }, (_, i) => pool.query('SELECT $1 as id', [i]));

      const results = await Promise.all(promises);

      expect(results).toHaveLength(10);
      results.forEach((result, i) => {
        expect(result.rows[0].id).toBe(i);
      });
    });

    it('should track pool stats', async () => {
      await pool.query('SELECT 1');

      expect(pool.totalCount).toBeGreaterThan(0);
      expect(pool.idleCount).toBeGreaterThanOrEqual(0);
      expect(pool.waitingCount).toBe(0);
    });
  });

  describe('DB-005: Connection Pool Exhaustion', () => {
    let pool: Pool;

    beforeAll(() => {
      pool = new Pool({ ...DB_CONFIG, max: 5 });
    });

    afterAll(async () => {
      await pool.end();
    });

    it('should queue requests when pool is exhausted', async () => {
      const clients: any[] = [];

      // Acquire all 5 connections
      for (let i = 0; i < 5; i++) {
        const client = await pool.connect();
        clients.push(client);
      }

      // 6th request should queue
      const startTime = Date.now();
      const queryPromise = pool.query('SELECT 1');

      // Release one connection after delay
      setTimeout(() => clients[0].release(), 500);

      await queryPromise;
      const elapsed = Date.now() - startTime;

      expect(elapsed).toBeGreaterThan(400); // Queued

      // Release all
      clients.forEach((c) => c.release());
    });

    it('should not crash on pool exhaustion', async () => {
      const clients: any[] = [];

      try {
        for (let i = 0; i < 10; i++) {
          const client = await pool.connect();
          clients.push(client);
        }
      } catch (error) {
        // Should gracefully handle
        expect(error).toBeDefined();
      } finally {
        clients.forEach((c) => c.release());
      }
    });
  });
});
