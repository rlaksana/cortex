/**
 * Prisma Client Wrapper
 *
 * Provides centralized database access with error handling and connection management.
 * Replaces manual SQL queries with type-safe Prisma operations.
 *
 * @version 1.0.0
 */

import { PrismaClient } from '@prisma/client';
import { logger } from '../utils/logger.js';
import { config } from '../config/environment.js';
import { dbErrorHandler, safeDbOperation } from '../utils/db-error-handler.js';

// Singleton pattern for Prisma Client
declare global {
  var __prisma: PrismaClient | undefined;
}

export class PrismaService {
  private client: PrismaClient;

  constructor() {
    this.client = new PrismaClient({
      datasources: {
        db: {
          url: config.getDatabaseConfig().databaseUrl,
        },
      },
      log: [
        {
          emit: 'event',
          level: 'query',
        },
        {
          emit: 'stdout',
          level: 'error',
        },
      ],
    });
  }

  /**
   * Get Prisma Client instance
   */
  getClient(): PrismaClient {
    return this.client;
  }

  /**
   * Initialize database connection
   */
  async initialize(): Promise<void> {
    try {
      await safeDbOperation(
        () => this.client.$connect(),
        'PrismaClient.initialize'
      );
      logger.info('✅ Prisma Client connected successfully');
    } catch (error) {
      logger.error({ error }, '❌ Prisma Client connection failed');
      throw error;
    }
  }

  /**
   * Close database connection
   */
  async disconnect(): Promise<void> {
    try {
      await this.client.$disconnect();
      logger.info('Prisma Client disconnected');
    } catch (error) {
      logger.error({ error }, 'Error disconnecting Prisma Client');
    }
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    return await dbErrorHandler.healthCheck(this.client);
  }

  /**
   * Check if table exists
   */
  async tableExists(table_name: string): Promise<boolean> {
    try {
      const result = await this.client.$queryRaw<Array<{ exists: boolean }>>`
        SELECT EXISTS (
          SELECT FROM information_schema.tables
          WHERE table_schema = 'public'
          AND table_name = ${table_name}
        )
        as exists
      `;
      return result[0]?.exists || false;
    } catch (error) {
      logger.error({ error, table_name }, 'Table existence check failed');
      return false;
    }
  }

  /**
   * Get table count
   */
  async getTableCount(): Promise<number> {
    try {
      const result = await this.client.$queryRaw<Array<{ count: string }>>`
        SELECT COUNT(*) as count
        FROM information_schema.tables
        WHERE table_schema = 'public'
      `;
      return Number(result[0]?.count || 0);
    } catch (error) {
      logger.error({ error }, 'Table count query failed');
      return 0;
    }
  }
}

// Export singleton instance
export const prisma = new PrismaService();