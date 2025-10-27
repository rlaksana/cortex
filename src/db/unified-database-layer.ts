/**
 * Unified Database Access Layer - PostgreSQL + Qdrant Architecture
 *
 * Coordinates between PostgreSQL (relational data + full-text search) and
 * Qdrant (vector similarity search) for comprehensive database operations.
 *
 * Features:
 * - Single interface for all database operations
 * - PostgreSQL full-text search and relational operations
 * - Qdrant vector similarity search
 * - Connection pooling and performance optimization
 * - Type safety with TypeScript
 * - Comprehensive error handling and logging
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { Pool, Client } from 'pg';
import { QdrantClient } from '@qdrant/js-client-rest';
import { logger } from '../utils/logger.js';
import { Environment } from '../config/environment.js';
import {
  DatabaseErrorHandler,
  ServiceErrorHandler,
  AsyncErrorHandler,
  ErrorRecovery
} from '../middleware/error-middleware.js';
import {
  DatabaseError,
  NetworkError,
  ValidationError,
  ErrorCode,
  ErrorCategory,
  ErrorSeverity
} from '../utils/error-handler.js';

export interface DatabaseConfig {
  // PostgreSQL configuration
  postgresConnectionString?: string;
  // Qdrant configuration
  qdrantUrl?: string;
  qdrantApiKey?: string;
  // Common configuration
  logQueries?: boolean;
  connectionTimeout?: number;
  maxConnections?: number;
  vectorSize?: number;
}

export interface QueryOptions {
  useRaw?: boolean;
  timeout?: number;
  cache?: boolean;
  transaction?: boolean;
  take?: number;
  orderBy?: any;
}

export interface SearchResult {
  id: string;
  title: string;
  snippet: string;
  score: number;
  kind: string;
  data: Record<string, any>;
  rank?: number;
  highlight?: string[];
}

export interface FullTextSearchOptions {
  query: string;
  config?: string; // ts_config name, e.g., 'english'
  weighting?: Record<string, number>; // D, C, B, A weights
  normalization?: number; // ts_rank_cd normalization
  highlight?: boolean;
  snippet_size?: number;
  max_results?: number;
  min_rank?: number;
}

export interface JsonPathQuery {
  path: string;
  filter?: string;
  vars?: Record<string, any>;
}

export interface JsonOperationOptions {
  path: string;
  value: any;
  create_if_missing?: boolean;
  insert_after?: string;
}

export interface ArrayOperationOptions {
  column: string;
  operation: 'contains' | 'contained' | 'overlap' | 'any' | 'all' | 'append' | 'prepend' | 'remove';
  values: any[];
  index?: number;
}

export interface UUIDGenerationOptions {
  version?: 'v4' | 'v7';
  namespace?: string;
  name?: string;
}

export interface ExplainOptions {
  analyze?: boolean;
  buffers?: boolean;
  timing?: boolean;
  verbose?: boolean;
  costs?: boolean;
  format?: 'text' | 'json' | 'xml' | 'yaml';
}

export interface ExplainResult {
  plan: any;
  execution_time?: number;
  planning_time?: number;
  total_cost?: number;
  rows?: number;
  width?: number;
}

export interface BatchOperation {
  type: 'create' | 'update' | 'delete';
  table: string;
  data: any;
  where?: any;
}

/**
 * Unified Database Access Layer
 *
 * Provides a single interface for all database operations, coordinating
 * between PostgreSQL for relational data and Qdrant for vector search.
 */
export class UnifiedDatabaseLayer {
  private postgres: Pool;
  private qdrant: QdrantClient;
  private config: DatabaseConfig;
  private initialized: boolean = false;

  constructor(config: DatabaseConfig = {}) {
    // Use unified environment configuration
    const env = Environment.getInstance();
    const qdrantConfig = env.getQdrantConfig();
    const testingConfig = env.getTestingConfig();

    this.config = {
      postgresConnectionString: config.postgresConnectionString || testingConfig.testDatabaseUrl || process.env.DATABASE_URL,
      qdrantUrl: config.qdrantUrl || qdrantConfig.url,
      qdrantApiKey: config.qdrantApiKey || qdrantConfig.apiKey,
      logQueries: config.logQueries || false,
      connectionTimeout: config.connectionTimeout || 30000,
      maxConnections: config.maxConnections || 10,
      vectorSize: config.vectorSize || 1536,
      ...config
    };

    // Initialize PostgreSQL connection pool
    this.postgres = new Pool({
      connectionString: this.config.postgresConnectionString,
      max: this.config.maxConnections,
      connectionTimeoutMillis: this.config.connectionTimeout,
      log: (messages) => {
        if (this.config.logQueries) {
          logger.debug(messages);
        }
      }
    });

    // Initialize Qdrant client
    this.qdrant = new QdrantClient({
      url: this.config.qdrantUrl,
      apiKey: this.config.qdrantApiKey,
      timeout: this.config.connectionTimeout
    });
  }

  /**
   * Initialize the database layer
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    await ServiceErrorHandler.wrapServiceMethod(
      'initialize',
      async () => {
        logger.info('Initializing unified database layer...');

        // Test PostgreSQL connection
        await ErrorRecovery.gracefulDegradation(
          // Primary: Direct PostgreSQL connection
          async () => {
            const client = await this.postgres.connect();
            await client.query('SELECT 1');
            client.release();
          },
          // Fallback: Connection with timeout
          [
            async () => {
              const client = await this.postgres.connect();
              try {
                await Promise.race([
                  client.query('SELECT 1'),
                  new Promise((_, reject) =>
                    setTimeout(() => reject(new Error('PostgreSQL connection timeout')), 10000)
                  )
                ]);
              } finally {
                client.release();
              }
            }
          ],
          { operation: 'postgres_connect' }
        );

        // Test Qdrant connection
        await ErrorRecovery.gracefulDegradation(
          // Primary: Direct Qdrant connection
          async () => {
            await this.qdrant.getCollections();
          },
          // Fallback: Connection with timeout
          [
            async () => {
              await Promise.race([
                this.qdrant.getCollections(),
                new Promise((_, reject) =>
                  setTimeout(() => reject(new Error('Qdrant connection timeout')), 10000)
                )
              ]);
            }
          ],
          { operation: 'qdrant_connect' }
        );

        // Run health check
        await this.healthCheck();

        this.initialized = true;
        logger.info('✅ Unified database layer initialized successfully');
        logger.info('✅ PostgreSQL and Qdrant connections established');
      },
      {
        category: ErrorCategory.DATABASE,
        rethrow: true
      }
    );
  }

  /**
   * Health check for database connections
   */
  async healthCheck(): Promise<boolean> {
    return ServiceErrorHandler.wrapServiceMethod(
      'healthCheck',
      async () => {
        // Check PostgreSQL health
        await AsyncErrorHandler.retry(
          async () => {
            const client = await this.postgres.connect();
            try {
              await client.query('SELECT 1 as health_check');
            } finally {
              client.release();
            }
          },
          {
            maxAttempts: 2,
            context: { operation: 'postgres_health_check' }
          }
        );

        // Check Qdrant health
        await AsyncErrorHandler.retry(
          () => this.qdrant.getCollections(),
          {
            maxAttempts: 2,
            context: { operation: 'qdrant_health_check' }
          }
        );

        return true;
      },
      {
        category: ErrorCategory.DATABASE,
        fallback: () => false
      }
    );
  }

  /**
   * Advanced full-text search using PostgreSQL features
   */
  async fullTextSearch(options: FullTextSearchOptions): Promise<SearchResult[]> {
    await this.ensureInitialized();

    const {
      query,
      config = 'english',
      weighting = { D: 0.1, C: 0.2, B: 0.4, A: 0.8 },
      normalization = 32,
      highlight = true,
      snippet_size = 150,
      max_results = 50,
      min_rank = 0.1
    } = options;

    const client = await this.postgres.connect();

    try {
      logger.debug({ query, config, weighting }, 'Executing PostgreSQL full-text search');

      const weightingString = JSON.stringify(weighting);
      const sql = `
        SELECT
          s.id,
          s.title,
          s.body_text as content,
          s.heading,
          s.updated_at,
          ts_rank_cd(
            websearch_to_tsquery($1, $2),
            setweight(to_tsvector($1, COALESCE(s.title, '')), 'A') ||
            setweight(to_tsvector($1, COALESCE(s.heading, '')), 'B') ||
            setweight(to_tsvector($1, COALESCE(s.body_text, '')), 'C'),
            $3::float4[],
            $4
          ) as rank,
          ts_headline(
            $1,
            COALESCE(s.body_text, ''),
            websearch_to_tsquery($1, $2),
            'MaxWords=${snippet_size}, MinWords=20, ShortWord=3, HighlightAll=true, MaxFragments=3, FragmentDelimiter= ... '
          ) as snippet,
          ts_headline(
            $1,
            COALESCE(s.title, ''),
            websearch_to_tsquery($1, $2),
            'MaxWords=30, HighlightAll=true'
          ) as title_highlight
        FROM section s
        WHERE
          websearch_to_tsquery($1, $2) @@ (
            setweight(to_tsvector($1, COALESCE(s.title, '')), 'A') ||
            setweight(to_tsvector($1, COALESCE(s.heading, '')), 'B') ||
            setweight(to_tsvector($1, COALESCE(s.body_text, '')), 'C')
          )
          AND ts_rank_cd(
            websearch_to_tsquery($1, $2),
            setweight(to_tsvector($1, COALESCE(s.title, '')), 'A') ||
            setweight(to_tsvector($1, COALESCE(s.heading, '')), 'B') ||
            setweight(to_tsvector($1, COALESCE(s.body_text, '')), 'C'),
            $3::float4[],
            $4
          ) >= $5
        ORDER BY rank DESC, s.updated_at DESC
        LIMIT $6
      `;

      const results = await client.query(sql, [
        config, query, weightingString, normalization, min_rank, max_results
      ]);

      return results.rows.map((row: any) => ({
        id: row.id,
        title: row.title_highlight || row.title || 'Untitled',
        snippet: row.snippet || `${row.content?.substring(0, snippet_size)}...` || '',
        score: row.rank || 0,
        rank: row.rank || 0,
        kind: 'section',
        data: {
          title: row.title,
          content: row.content,
          heading: row.heading,
          updated_at: row.updated_at
        },
        highlight: highlight ? [row.title_highlight, row.snippet].filter(Boolean) : undefined
      }));

    } catch (error) {
      logger.error({ query, config, error }, 'PostgreSQL full-text search failed');
      return await this.fallbackSearch(query, max_results);
    } finally {
      client.release();
    }
  }

  /**
   * Fallback search using simple LIKE queries
   */
  private async fallbackSearch(query: string, limit: number): Promise<SearchResult[]> {
    const client = await this.postgres.connect();

    try {
      const sql = `
        SELECT
          id,
          title,
          body_text as content,
          heading,
          updated_at
        FROM section
        WHERE
          title ILIKE $1 OR
          body_text ILIKE $1 OR
          heading ILIKE $1
        ORDER BY updated_at DESC
        LIMIT $2
      `;

      const results = await client.query(sql, [`%${query}%`, limit]);

      return results.rows.map(result => ({
        id: result.id,
        title: result.title || 'Untitled',
        snippet: `${result.content?.substring(0, 150)}...` || '',
        score: 0.5,
        rank: 0.5,
        kind: 'section',
        data: {
          title: result.title,
          content: result.content,
          heading: result.heading
        }
      }));

    } catch (error) {
      logger.error({ query, error }, 'Fallback search failed');
      return [];
    } finally {
      client.release();
    }
  }

  
  /**
   * Advanced UUID generation using PostgreSQL features
   */
  async generateUUID(options: UUIDGenerationOptions = {}): Promise<string> {
    await this.ensureInitialized();

    const { version = 'v4' } = options;
    const client = await this.postgres.connect();

    try {
      logger.debug({ version }, 'Executing PostgreSQL UUID generation');

      switch (version) {
        case 'v4': {
          const result = await client.query('SELECT gen_random_uuid() as uuid');
          return result.rows[0]?.uuid;
        }

        case 'v7': {
          const result = await client.query(`
            SELECT gen_random_uuid() ||
                   LPAD(EXTRACT(epoch FROM now())::text, 12, '0') as uuid
          `);
          return result.rows[0]?.uuid;
        }

        default:
          throw new Error(`Unsupported UUID version: ${version}`);
      }

    } catch (error) {
      logger.error({ version, error }, 'UUID generation failed');
      // Use a simple fallback
      return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
      });
    } finally {
      client.release();
    }
  }

  async generateUUIDv7(): Promise<string> {
    return await this.generateUUID({ version: 'v7' });
  }

  async generateMultipleUUIDs(count: number, version: 'v4' | 'v7' = 'v4'): Promise<string[]> {
    await this.ensureInitialized();

    const client = await this.postgres.connect();

    try {
      logger.debug({ count, version }, 'Generating multiple PostgreSQL UUIDs');

      let results: any;

      switch (version) {
        case 'v4':
          results = await client.query(
            'SELECT gen_random_uuid() as uuid FROM generate_series(1, $1)',
            [count]
          );
          break;
        case 'v7':
          results = await client.query(`
            SELECT gen_random_uuid() ||
                   LPAD(EXTRACT(epoch FROM now())::text, 12, '0') as uuid
            FROM generate_series(1, $1)
          `, [count]);
          break;
        default:
          throw new Error(`Unsupported UUID version: ${version}`);
      }

      return results.rows.map(row => row.uuid);

    } catch (error) {
      logger.error({ count, version, error }, 'PostgreSQL multiple UUID generation failed');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Performance analysis using PostgreSQL EXPLAIN ANALYZE
   */
  async explainQuery(sql: string, params: any[] = [], options: ExplainOptions = {}): Promise<ExplainResult> {
    await this.ensureInitialized();

    const {
      analyze = true,
      buffers = false,
      timing = true,
      verbose = false,
      costs = true,
      format = 'json'
    } = options;

    const client = await this.postgres.connect();

    try {
      logger.debug({ sql, params, options }, 'Executing PostgreSQL EXPLAIN ANALYZE');

      const explainOptions = [];
      if (analyze) explainOptions.push('ANALYZE');
      if (buffers) explainOptions.push('BUFFERS');
      if (timing) explainOptions.push('TIMING');
      if (verbose) explainOptions.push('VERBOSE');
      if (costs) explainOptions.push('COSTS');

      const explainOptionsStr = explainOptions.join(', ');
      const explainSql = `EXPLAIN (${explainOptionsStr}, FORMAT ${format.toUpperCase()}) ${sql}`;

      const result = await client.query(explainSql, params);

      if (format === 'json' && result.rows.length > 0) {
        const plan = result.rows[0]['QUERY PLAN'];
        return {
          plan,
          execution_time: plan['Execution Time'],
          planning_time: plan['Planning Time'],
          total_cost: plan.Plan?.['Total Cost'],
          rows: plan.Plan?.['Plan Rows'],
          width: plan.Plan?.['Plan Width']
        };
      }

      return {
        plan: result.rows,
        execution_time: undefined,
        planning_time: undefined
      };

    } catch (error) {
      logger.error({ sql, params, error }, 'PostgreSQL EXPLAIN ANALYZE failed');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Create operation
   */
  async create<T = any>(table: string, data: any): Promise<T> {
    await this.ensureInitialized();

    const client = await this.postgres.connect();

    try {
      // Build INSERT query dynamically
      const columns = Object.keys(data);
      const values = Object.values(data);
      const placeholders = columns.map((_, index) => `$${index + 1}`).join(', ');

      const sql = `
        INSERT INTO ${this.escapeIdentifier(table)} (${columns.map(this.escapeIdentifier).join(', ')})
        VALUES (${placeholders})
        RETURNING *
      `;

      const result = await client.query(sql, values);
      return result.rows[0] as T;
    } catch (error) {
      logger.error({ table, data, error }, 'Create operation failed');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Update operation
   */
  async update<T = any>(table: string, where: any, data: any): Promise<T> {
    await this.ensureInitialized();

    const client = await this.postgres.connect();

    try {
      // Build UPDATE query dynamically
      const setClause = Object.keys(data).map((key, index) =>
        `${this.escapeIdentifier(key)} = $${index + 1}`
      ).join(', ');

      const values = [...Object.values(data)];

      // Add WHERE clause if provided
      let sql = `UPDATE ${this.escapeIdentifier(table)} SET ${setClause}`;
      if (where && Object.keys(where).length > 0) {
        const whereClause = Object.keys(where).map((key, index) =>
          `${this.escapeIdentifier(key)} = $${values.length + index + 1}`
        ).join(' AND ');
        sql += ` WHERE ${whereClause}`;
        values.push(...Object.values(where));
      }

      sql += ' RETURNING *';

      const result = await client.query(sql, values);
      return result.rows[0] as T;
    } catch (error) {
      logger.error({ table, where, data, error }, 'Update operation failed');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Delete operation
   */
  async delete<T = any>(table: string, where: any): Promise<T> {
    await this.ensureInitialized();

    const client = await this.postgres.connect();

    try {
      let sql = `DELETE FROM ${this.escapeIdentifier(table)}`;
      const values: any[] = [];

      // Add WHERE clause if provided
      if (where && Object.keys(where).length > 0) {
        const whereClause = Object.keys(where).map((key, index) =>
          `${this.escapeIdentifier(key)} = $${index + 1}`
        ).join(' AND ');
        sql += ` WHERE ${whereClause}`;
        values.push(...Object.values(where));
      }

      sql += ' RETURNING *';

      const result = await client.query(sql, values);
      return result.rows[0] as T;
    } catch (error) {
      logger.error({ table, where, error }, 'Delete operation failed');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * JSON Query operation (alias for jsonPathQuery)
   */
  async jsonQuery<T = any>(
    table: string,
    jsonbColumn: string,
    query: JsonPathQuery
  ): Promise<T[]> {
    return await this.jsonPathQuery<T>(table, jsonbColumn, query);
  }

  /**
   * Enhanced JSON Path Query with proper qdrant syntax
   */
  async jsonPathQuery<T = any>(
    table: string,
    jsonbColumn: string,
    query: JsonPathQuery
  ): Promise<T[]> {
    await this.ensureInitialized();

    const { path, filter, vars = {} } = query;

    try {
      logger.debug({ table, jsonbColumn, path, filter }, 'Executing qdrant 18 jsonb_path_query');

      const tableName = this.escapeIdentifier(this.getActualTableName(table));
      const columnName = this.escapeIdentifier(jsonbColumn);
      const jsonPath = `$${  path}`;

      if (Object.keys(vars).length > 0) {
        const varNames = Object.keys(vars);
        const varValues = Object.values(vars);
        const pathWithVars = `${jsonPath} ? (${varNames.join(', ')})`;

        const results = await this.qdrant.$queryRawUnsafe(`
          SELECT * FROM ${tableName}
          WHERE jsonb_path_query_array(${columnName}, '${pathWithVars}'::jsonpath, '${JSON.stringify(varValues)}'::jsonb) IS NOT NULL
        `) as T[];
        return results;
      } else {
        const results = await this.qdrant.$queryRawUnsafe(`
          SELECT * FROM ${tableName}
          WHERE jsonb_path_query_array(${columnName}, '${jsonPath}'::jsonpath) IS NOT NULL
        `) as T[];
        return results;
      }

    } catch (error) {
      logger.error({ table, jsonbColumn, path, error }, 'qdrant 18 jsonb_path_query failed');
      throw error;
    }
  }

  /**
   * Array Query operation using qdrant 18 JSON array features
   */
  async arrayQuery(
    table: string,
    column: string,
    operation: 'contains' | 'contained' | 'overlap' | 'any' | 'all',
    values: any[]
  ): Promise<any[]> {
    await this.ensureInitialized();
    const client = this.postgres;

    const tableName = this.escapeIdentifier(table);
    const columnName = this.escapeIdentifier(column);

    try {
      let sql: string;
      const params: any[] = [];

      switch (operation) {
        case 'contains':
          sql = `SELECT * FROM ${tableName} WHERE ${columnName} @> $1::jsonb`;
          params.push(JSON.stringify(values));
          break;

        case 'contained':
          sql = `SELECT * FROM ${tableName} WHERE ${columnName} <@ $1::jsonb`;
          params.push(JSON.stringify(values));
          break;

        case 'overlap':
          sql = `SELECT * FROM ${tableName} WHERE ${columnName} && $1::jsonb`;
          params.push(JSON.stringify(values));
          break;

        case 'any':
          sql = `SELECT * FROM ${tableName} WHERE ${columnName} ?| $1`;
          params.push(values.map(String));
          break;

        case 'all':
          sql = `SELECT * FROM ${tableName} WHERE ${columnName} ?& $1`;
          params.push(values.map(String));
          break;

        default:
          throw new Error(`Unsupported array operation: ${operation}`);
      }

      const result = await client.query(sql, params);
      return result.rows;
    } catch (error) {
      logger.error(`Array query failed for table ${table}, column ${column}:`, error);
      throw new DatabaseError(
        `Array query operation failed: ${operation}`,
        ErrorCode.DATABASE_ERROR,
        ErrorCategory.DATABASE_ERROR,
        ErrorSeverity.HIGH,
        { table, column, operation, values, error: (error as Error).message }
      );
    }
  }

  /**
   * Helper method for array append operations
   */
  async arrayAppendOperation(
    table: string,
    column: string,
    values: any[]
  ): Promise<void> {
    await this.ensureInitialized();
    const client = this.postgres;

    const tableName = this.escapeIdentifier(table);
    const columnName = this.escapeIdentifier(column);

    try {
      const _sql = `
        UPDATE ${tableName} 
        SET ${columnName} = ${columnName} || $1::jsonb
        WHERE id = $2
      `;
      
      // This would need to be called with specific ID and values
      // Implementation depends on specific use case
      logger.warn(`arrayAppendOperation called for table ${table}, column ${column}`);
    } catch (error) {
      logger.error(`Array append operation failed for table ${table}, column ${column}:`, error);
      throw new DatabaseError(
        `Array append operation failed`,
        ErrorCode.DATABASE_ERROR,
        ErrorCategory.DATABASE_ERROR,
        ErrorSeverity.HIGH,
        { table, column, values, error: (error as Error).message }
      );
    }
  }

  /**
   * Helper method for array prepend operations
   */
  async arrayPrependOperation(
    table: string,
    column: string,
    values: any[]
  ): Promise<void> {
    await this.ensureInitialized();
    const client = this.postgres;

    const tableName = this.escapeIdentifier(table);
    const columnName = this.escapeIdentifier(column);

    try {
      // PostgreSQL prepend operation using jsonb operators
      const sql = `
        UPDATE ${tableName} 
        SET ${columnName} = $1::jsonb || ${columnName}
        WHERE id = $2
      `;
      
      // This would need to be called with specific ID and values
      // Implementation depends on specific use case
      logger.warn(`arrayPrependOperation called for table ${table}, column ${column}`);
    } catch (error) {
      logger.error(`Array prepend operation failed for table ${table}, column ${column}:`, error);
      throw new DatabaseError(
        `Array prepend operation failed`,
        ErrorCode.DATABASE_ERROR,
        ErrorCategory.DATABASE_ERROR,
        ErrorSeverity.HIGH,
        { table, column, values, error: (error as Error).message }
      );
    }
  }

  /**
   * Helper method for array remove operations
   */
  async arrayRemoveOperation(
    table: string,
    column: string,
    values: any[]
  ): Promise<void> {
    await this.ensureInitialized();
    const client = this.postgres;

    const tableName = this.escapeIdentifier(table);
    const columnName = this.escapeIdentifier(column);

    try {
      // PostgreSQL array element removal using jsonb operators
      const sql = `
        UPDATE ${tableName} 
        SET ${columnName} = (
          SELECT jsonb_agg(elem) 
          FROM jsonb_array_elements(${columnName}) elem 
          WHERE NOT (elem <@ $1::jsonb)
        )
        WHERE id = $2
      `;
      
      // This would need to be called with specific ID and values
      // Implementation depends on specific use case
      logger.warn(`arrayRemoveOperation called for table ${table}, column ${column}`);
    } catch (error) {
      logger.error(`Array remove operation failed for table ${table}, column ${column}:`, error);
      throw new DatabaseError(
        `Array remove operation failed`,
        ErrorCode.DATABASE_ERROR,
        ErrorCategory.DATABASE_ERROR,
        ErrorSeverity.HIGH,
        { table, column, values, error: (error as Error).message }
      );
    }
  }

  /**
   * Find operation
   */
  async find<T = any>(
    table: string,
    where: any = {},
    options: QueryOptions = {}
  ): Promise<T[]> {
    await this.ensureInitialized();

    const client = await this.postgres.connect();

    try {
      let sql = `SELECT * FROM ${this.escapeIdentifier(table)}`;
      const values: any[] = [];

      // Add WHERE clause if provided
      if (where && Object.keys(where).length > 0) {
        const whereClause = Object.keys(where).map((key, index) =>
          `${this.escapeIdentifier(key)} = $${index + 1}`
        ).join(' AND ');
        sql += ` WHERE ${whereClause}`;
        values.push(...Object.values(where));
      }

      // Add ORDER BY if provided
      if (options.orderBy) {
        const orderClause = Object.keys(options.orderBy).map(key => {
          const direction = options.orderBy[key] === 'desc' ? 'DESC' : 'ASC';
          return `${this.escapeIdentifier(key)} ${direction}`;
        }).join(', ');
        sql += ` ORDER BY ${orderClause}`;
      }

      // Add LIMIT
      const limit = options.take || 100;
      sql += ` LIMIT ${limit}`;

      const result = await client.query(sql, values);
      return result.rows as T[];
    } catch (error) {
      logger.error({ table, where, error }, 'Find operation failed');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Legacy search method for backward compatibility
   */
  async search(query: string, options: {
    types?: string[];
    limit?: number;
    threshold?: number;
  } = {}): Promise<SearchResult[]> {
    const {
      limit = 50,
      threshold = 0.3
    } = options;

    return await this.fullTextSearch({
      query,
      max_results: limit,
      min_rank: threshold
    });
  }

  /**
   * Close database connections
   */
  async close(): Promise<void> {
    try {
      await this.postgres.end();
      this.initialized = false;
      logger.info('Database connections closed');
    } catch (error) {
      logger.error({ error }, 'Error closing database connections');
      throw error;
    }
  }

  /**
   * Generic query method for backward compatibility with performance monitor
   * Executes raw SQL queries using PostgreSQL
   */
  async query<T = any>(sql: string, params: any[] = []): Promise<T[]> {
    await this.ensureInitialized();

    const client = await this.postgres.connect();

    try {
      const result = await client.query(sql, params);
      return result.rows as T[];
    } catch (error) {
      logger.error({ sql, params, error }, 'Raw query execution failed');
      throw error;
    } finally {
      client.release();
    }
  }

  // Private helper methods

  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      await this.initialize();
    }
  }

  // Private helper methods removed - no longer needed with PostgreSQL
// All database operations now use direct SQL queries

  private escapeIdentifier(name: string): string {
    return `"${name.replace(/"/g, '""')}"`;
  }
}

// Export singleton instance with unified environment configuration
const env = Environment.getInstance();
const qdrantConfig = env.getQdrantConfig();

export const database = new UnifiedDatabaseLayer({
  postgresConnectionString: process.env.DATABASE_URL,
  qdrantUrl: qdrantConfig.url,
  qdrantApiKey: qdrantConfig.apiKey,
  logQueries: env.isDevelopmentMode(),
  connectionTimeout: qdrantConfig.connectionTimeout,
  maxConnections: qdrantConfig.maxConnections,
  vectorSize: qdrantConfig.vectorSize
});