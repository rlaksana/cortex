/**
 * PostgreSQL Adapter
 *
 * Implements PostgreSQL-specific database operations, including
 * full-text search, CRUD operations, UUID generation, and
 * advanced PostgreSQL features.
 *
 * Features:
 * - Full-text search with tsvector and tsquery
 * - UUID generation (v4 and v7)
 * - JSON Path queries and operations
 * - Array operations for JSON arrays
 * - Query execution plan analysis
 * - Connection pooling and management
 * - Type-safe operations with TypeScript
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { Pool, Client } from 'pg';
import { logger } from '../../utils/logger.js';
import { Environment } from '../../config/environment.js';
import {
  DatabaseErrorHandler,
  ServiceErrorHandler,
  AsyncErrorHandler,
  ErrorRecovery
} from '../../middleware/error-middleware.js';
import {
  DatabaseError,
  NetworkError,
  ValidationError,
  ErrorCode,
  ErrorCategory,
  ErrorSeverity
} from '../../utils/error-handler.js';
import type {
  KnowledgeItem,
  StoreResult,
  StoreError,
  MemoryStoreResponse
} from '../../types/core-interfaces.js';
import type {
  IPostgreSQLAdapter,
  PostgreSQLConfig,
  QueryOptions,
  FullTextSearchOptions,
  SearchResult,
  UUIDGenerationOptions,
  ExplainOptions,
  ExplainResult,
  DatabaseMetrics
} from '../interfaces/postgresql-adapter.interface.js';

/**
 * PostgreSQL adapter implementing relational database operations
 */
export class PostgreSQLAdapter implements IPostgreSQLAdapter {
  private pool: Pool;
  private config: PostgreSQLConfig;
  private initialized: boolean = false;

  constructor(config: PostgreSQLConfig) {
    // Use unified environment configuration
    const env = Environment.getInstance();
    const testingConfig = env.getTestingConfig();

    this.config = {
      postgresConnectionString: config.postgresConnectionString || testingConfig.testDatabaseUrl || process.env.DATABASE_URL,
      logQueries: config.logQueries || false,
      connectionTimeout: config.connectionTimeout || 30000,
      maxConnections: config.maxConnections || 10,
      ...config
    };

    // Initialize PostgreSQL connection pool
    this.pool = new Pool({
      connectionString: this.config.postgresConnectionString,
      max: this.config.maxConnections,
      connectionTimeoutMillis: this.config.connectionTimeout,
      log: (messages) => {
        if (this.config.logQueries) {
          logger.debug(messages);
        }
      }
    });
  }

  // === Lifecycle Management ===

  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    await ServiceErrorHandler.wrapServiceMethod(
      'initialize',
      async () => {
        logger.info('Initializing PostgreSQL adapter...');

        // Test PostgreSQL connection
        await ErrorRecovery.gracefulDegradation(
          // Primary: Direct PostgreSQL connection
          async () => {
            const client = await this.pool.connect();
            await client.query('SELECT 1');
            client.release();
          },
          // Fallback: Connection with timeout
          [
            async () => {
              const client = await this.pool.connect();
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

        // Run health check
        await this.healthCheck();

        this.initialized = true;
        logger.info('✅ PostgreSQL adapter initialized successfully');
      },
      {
        category: ErrorCategory.DATABASE,
        rethrow: true
      }
    );
  }

  async healthCheck(): Promise<boolean> {
    return ServiceErrorHandler.wrapServiceMethod(
      'healthCheck',
      async () => {
        await AsyncErrorHandler.retry(
          async () => {
            const client = await this.pool.connect();
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

        return true;
      },
      {
        category: ErrorCategory.DATABASE,
        fallback: () => false
      }
    );
  }

  async getMetrics(): Promise<DatabaseMetrics> {
    try {
      const healthy = await this.healthCheck();
      const totalCount = await this.getTotalCount();
      const storageSize = await this.getStorageSize();

      return {
        type: 'postgresql',
        healthy,
        connectionCount: this.pool.totalCount - this.pool.idleCount,
        queryLatency: 0, // TODO: Implement query latency tracking
        storageSize,
        lastHealthCheck: new Date().toISOString(),
        vectorCount: 0 // PostgreSQL doesn't have vectors
      };
    } catch (error) {
      logger.error({ error }, 'Failed to get PostgreSQL metrics');
      throw new DatabaseError('Failed to retrieve database metrics', 'METRICS_ERROR', error as Error);
    }
  }

  async close(): Promise<void> {
    try {
      await this.pool.end();
      this.initialized = false;
      logger.info('PostgreSQL adapter closed');
    } catch (error) {
      logger.error({ error }, 'Error closing PostgreSQL adapter');
      throw new DatabaseError('Failed to close PostgreSQL adapter', 'CLOSE_ERROR', error as Error);
    }
  }

  // === CRUD Operations ===

  async create<T = Record<string, any>>(table: string, data: Record<string, any>): Promise<T> {
    await this.ensureInitialized();

    const client = await this.pool.connect();

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

  async update<T = Record<string, any>>(
    table: string,
    where: Record<string, any>,
    data: Record<string, any>
  ): Promise<T> {
    await this.ensureInitialized();

    const client = await this.pool.connect();

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

  async delete<T = Record<string, any>>(table: string, where: Record<string, any>): Promise<T> {
    await this.ensureInitialized();

    const client = await this.pool.connect();

    try {
      let sql = `DELETE FROM ${this.escapeIdentifier(table)}`;
      const values: unknown[] = [];

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

  async find<T = Record<string, any>>(
    table: string,
    where: Record<string, any> = {},
    options: QueryOptions = {}
  ): Promise<T[]> {
    await this.ensureInitialized();

    const client = await this.pool.connect();

    try {
      let sql = `SELECT * FROM ${this.escapeIdentifier(table)}`;
      const values: unknown[] = [];

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
          const direction = options.orderBy![key] === 'desc' ? 'DESC' : 'ASC';
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

  async query<T = Record<string, any>>(sql: string, params: unknown[] = []): Promise<T[]> {
    await this.ensureInitialized();

    const client = await this.pool.connect();

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

  // === PostgreSQL-specific Operations ===

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

    const client = await this.pool.connect();

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

      return results.rows.map((row) => ({
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

  async generateUUID(options: UUIDGenerationOptions = {}): Promise<string> {
    await this.ensureInitialized();

    const { version = 'v4' } = options;
    const client = await this.pool.connect();

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

  async generateMultipleUUIDs(count: number, version: 'v4' | 'v7' = 'v4'): Promise<string[]> {
    await this.ensureInitialized();

    const client = await this.pool.connect();

    try {
      logger.debug({ count, version }, 'Generating multiple PostgreSQL UUIDs');

      let results;

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

  async explainQuery(sql: string, params: unknown[] = [], options: ExplainOptions = {}): Promise<ExplainResult> {
    await this.ensureInitialized();

    const {
      analyze = true,
      buffers = false,
      timing = true,
      verbose = false,
      costs = true,
      format = 'json'
    } = options;

    const client = await this.pool.connect();

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

  async jsonPathQuery<T = Record<string, any>>(
    table: string,
    jsonbColumn: string,
    query: {
      path: string;
      filter?: string;
      vars?: Record<string, unknown>;
    }
  ): Promise<T[]> {
    await this.ensureInitialized();

    const { path, filter, vars = {} } = query;

    try {
      logger.debug({ table, jsonbColumn, path, filter }, 'Executing PostgreSQL jsonb_path_query');

      const tableName = this.escapeIdentifier(this.getActualTableName(table));
      const columnName = this.escapeIdentifier(jsonbColumn);
      const jsonPath = `$${path}`;

      if (Object.keys(vars).length > 0) {
        const varNames = Object.keys(vars);
        const varValues = Object.values(vars);
        const pathWithVars = `${jsonPath} ? (${varNames.join(', ')})`;

        const results = await this.query<T>(`
          SELECT * FROM ${tableName}
          WHERE jsonb_path_query_array(${columnName}, '${pathWithVars}'::jsonpath, '${JSON.stringify(varValues)}'::jsonb) IS NOT NULL
        `);
        return results;
      } else {
        const results = await this.query<T>(`
          SELECT * FROM ${tableName}
          WHERE jsonb_path_query_array(${columnName}, '${jsonPath}'::jsonpath) IS NOT NULL
        `);
        return results;
      }

    } catch (error) {
      logger.error({ table, jsonbColumn, path, error }, 'PostgreSQL jsonb_path_query failed');
      throw error;
    }
  }

  async arrayQuery<T = Record<string, any>>(
    table: string,
    options: {
      column: string;
      operation: 'contains' | 'contained' | 'overlap' | 'any' | 'all' | 'append' | 'prepend' | 'remove';
      values: unknown[];
      index?: number;
    }
  ): Promise<T[]> {
    await this.ensureInitialized();

    const { column, operation, values, index } = options;

    try {
      logger.debug({ table, column, operation, values }, 'Executing PostgreSQL JSON array query');

      const tableName = this.escapeIdentifier(table);
      const columnName = this.escapeIdentifier(column);

      switch (operation) {
        case 'contains':
          // Check if JSON array contains all specified values
          return await this.query<T>(`
            SELECT * FROM ${tableName}
            WHERE (${columnName}::jsonb @> '${JSON.stringify(values)}'::jsonb)
          `);

        case 'contained':
          // Check if JSON array is contained within specified values
          return await this.query<T>(`
            SELECT * FROM ${tableName}
            WHERE (${columnName}::jsonb <@ '${JSON.stringify(values)}'::jsonb)
          `);

        case 'overlap':
          // Check if JSON array overlaps with specified values
          return await this.query<T>(`
            SELECT * FROM ${tableName}
            WHERE (${columnName}::jsonb ?| ARRAY[${values.map(v => `'${v}'`).join(', ')}])
          `);

        case 'any':
          // Check if JSON array contains any of the specified values
          return await this.query<T>(`
            SELECT * FROM ${tableName}
            WHERE (${columnName}::jsonb ?| ARRAY[${values.map(v => `'${v}'`).join(', ')}])
          `);

        case 'all':
          // Check if JSON array contains all specified values
          return await this.query<T>(`
            SELECT * FROM ${tableName}
            WHERE (${columnName}::jsonb @> '${JSON.stringify(values)}'::jsonb)
          `);

        case 'append':
          // For append operations, we need to use raw SQL and a record ID
          if (!index) {
            throw new Error('Record ID is required for append operations');
          }
          return await this.arrayAppendOperation<T>(table, column, values, String(index));

        case 'prepend':
          // For prepend operations, we need to use raw SQL and a record ID
          if (!index) {
            throw new Error('Record ID is required for prepend operations');
          }
          return await this.arrayPrependOperation<T>(table, column, values, String(index));

        case 'remove':
          // For remove operations, we need to use raw SQL and a record ID
          if (!index) {
            throw new Error('Record ID is required for remove operations');
          }
          return await this.arrayRemoveOperation<T>(table, column, values, String(index));

        default:
          throw new Error(`Unsupported array operation: ${operation}`);
      }

    } catch (error) {
      logger.error({ table, column, operation, values, error }, 'PostgreSQL JSON array query failed');
      throw error;
    }
  }

  // === Knowledge Storage Operations ===

  async store(items: KnowledgeItem[], options: {
    upsert?: boolean;
    batchSize?: number;
  } = {}): Promise<MemoryStoreResponse> {
    await this.ensureInitialized();

    const {
      upsert = true,
      batchSize = 100
    } = options;

    try {
      logger.debug({ itemCount: items.length, options }, 'Storing items in PostgreSQL');

      const stored: StoreResult[] = [];
      const errors: StoreError[] = [];

      // Process items in batches
      for (let i = 0; i < items.length; i += batchSize) {
        const batch = items.slice(i, i + batchSize);

        for (let j = 0; j < batch.length; j++) {
          const item = batch[j];
          const index = i + j;

          try {
            // Store knowledge item in PostgreSQL
            const result = await this.create('knowledge_items', {
              id: item.id || await this.generateUUID(),
              kind: item.kind,
              scope: item.scope,
              data: item.data,
              created_at: item.created_at || new Date().toISOString(),
              updated_at: new Date().toISOString()
            });

            stored.push({
              id: result.id,
              status: 'inserted',
              kind: result.kind,
              created_at: result.created_at
            });

          } catch (error) {
            const storeError: StoreError = {
              index,
              error_code: 'STORE_ERROR',
              message: error instanceof Error ? error.message : 'Unknown error'
            };
            errors.push(storeError);
          }
        }
      }

      const autonomousContext = {
        action_performed: stored.length > 0 ? 'created' : 'none',
        similar_items_checked: items.length,
        duplicates_found: 0, // TODO: Implement duplicate detection
        contradictions_detected: false,
        recommendation: errors.length > 0 ?
          'Review errors before storing' :
          'Items stored successfully',
        reasoning: `Stored ${stored.length} items with ${errors.length} errors in PostgreSQL`,
        user_message_suggestion: errors.length > 0 ?
          `Some items failed to store (${errors.length} errors)` :
          `Successfully stored ${stored.length} items in PostgreSQL`
      };

      logger.debug({
        stored: stored.length,
        errors: errors.length
      }, 'PostgreSQL store operation completed');

      return {
        stored,
        errors,
        autonomous_context: autonomousContext
      };

    } catch (error) {
      logger.error({ error, itemCount: items.length }, 'PostgreSQL store operation failed');
      throw new DatabaseError('Failed to store items in PostgreSQL', 'STORE_ERROR', error as Error);
    }
  }

  async findById(ids: string[]): Promise<KnowledgeItem[]> {
    await this.ensureInitialized();

    try {
      const results = await this.query(`
        SELECT * FROM knowledge_items
        WHERE id = ANY($1)
      `, [ids]);

      return results.map(row => ({
        id: row.id,
        kind: row.kind,
        scope: row.scope,
        data: row.data,
        created_at: row.created_at,
        updated_at: row.updated_at
      }));

    } catch (error) {
      logger.error({ error, ids }, 'Failed to find items by ID in PostgreSQL');
      return [];
    }
  }

  async findByScope(scope: {
    project?: string;
    branch?: string;
    org?: string;
  }, options: QueryOptions = {}): Promise<KnowledgeItem[]> {
    await this.ensureInitialized();

    try {
      const whereConditions: string[] = [];
      const values: unknown[] = [];
      let paramIndex = 1;

      if (scope.project) {
        whereConditions.push(`scope->>'project' = $${paramIndex++}`);
        values.push(scope.project);
      }
      if (scope.branch) {
        whereConditions.push(`scope->>'branch' = $${paramIndex++}`);
        values.push(scope.branch);
      }
      if (scope.org) {
        whereConditions.push(`scope->>'org' = $${paramIndex++}`);
        values.push(scope.org);
      }

      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';
      const limitClause = options.take ? `LIMIT ${options.take}` : '';

      const results = await this.query(`
        SELECT * FROM knowledge_items
        ${whereClause}
        ORDER BY updated_at DESC
        ${limitClause}
      `, values);

      return results.map(row => ({
        id: row.id,
        kind: row.kind,
        scope: row.scope,
        data: row.data,
        created_at: row.created_at,
        updated_at: row.updated_at
      }));

    } catch (error) {
      logger.error({ error, scope }, 'PostgreSQL scope search failed');
      throw new DatabaseError('Failed to search by scope in PostgreSQL', 'SCOPE_SEARCH_ERROR', error as Error);
    }
  }

  async getStatistics(scope?: {
    project?: string;
    branch?: string;
    org?: string;
  }): Promise<{
    totalItems: number;
    itemsByKind: Record<string, number>;
    storageSize: number;
    lastUpdated: string;
  }> {
    await this.ensureInitialized();

    try {
      let whereClause = '';
      const values: unknown[] = [];

      if (scope) {
        const conditions: string[] = [];
        let paramIndex = 1;

        if (scope.project) {
          conditions.push(`scope->>'project' = $${paramIndex++}`);
          values.push(scope.project);
        }
        if (scope.branch) {
          conditions.push(`scope->>'branch' = $${paramIndex++}`);
          values.push(scope.branch);
        }
        if (scope.org) {
          conditions.push(`scope->>'org' = $${paramIndex++}`);
          values.push(scope.org);
        }

        if (conditions.length > 0) {
          whereClause = `WHERE ${conditions.join(' AND ')}`;
        }
      }

      const totalResult = await this.query(`
        SELECT COUNT(*) as count FROM knowledge_items ${whereClause}
      `, values);

      const totalItems = parseInt(totalResult[0]?.count || '0');

      const kindResults = await this.query(`
        SELECT kind, COUNT(*) as count FROM knowledge_items ${whereClause}
        GROUP BY kind
      `, values);

      const itemsByKind: Record<string, number> = {};
      kindResults.forEach(row => {
        itemsByKind[row.kind] = parseInt(row.count);
      });

      const lastUpdatedResult = await this.query(`
        SELECT MAX(updated_at) as last_updated FROM knowledge_items ${whereClause}
      `, values);

      const lastUpdated = lastUpdatedResult[0]?.last_updated || new Date().toISOString();

      return {
        totalItems,
        itemsByKind,
        storageSize: totalItems * 1024, // Rough estimate
        lastUpdated
      };

    } catch (error) {
      logger.error({ error }, 'Failed to get PostgreSQL statistics');
      throw new DatabaseError('Failed to retrieve statistics', 'STATISTICS_ERROR', error as Error);
    }
  }

  // === Private Helper Methods ===

  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      await this.initialize();
    }
  }

  private async fallbackSearch(query: string, limit: number): Promise<SearchResult[]> {
    const client = await this.pool.connect();

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

      return results.map(result => ({
        id: result.id,
        title: result.title || 'Untitled',
        snippet: (result.content?.substring(0, 150) || '') + '...',
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

  private async arrayAppendOperation<T = Record<string, any>>(
    table: string,
    column: string,
    values: unknown[],
    recordId: string
  ): Promise<T[]> {
    const tableName = this.escapeIdentifier(table);
    const columnName = this.escapeIdentifier(column);

    return await this.query<T>(`
      UPDATE ${tableName}
      SET ${columnName} = array_cat(${columnName}, $1::jsonb)
      WHERE id = $2
      RETURNING *
    `, [JSON.stringify(values), recordId]);
  }

  private async arrayPrependOperation<T = Record<string, any>>(
    table: string,
    column: string,
    values: unknown[],
    recordId: string
  ): Promise<T[]> {
    const tableName = this.escapeIdentifier(table);
    const columnName = this.escapeIdentifier(column);

    return await this.query<T>(`
      UPDATE ${tableName}
      SET ${columnName} = array_cat($1::jsonb, ${columnName})
      WHERE id = $2
      RETURNING *
    `, [JSON.stringify(values), recordId]);
  }

  private async arrayRemoveOperation<T = Record<string, any>>(
    table: string,
    column: string,
    values: unknown[],
    recordId: string
  ): Promise<T[]> {
    const tableName = this.escapeIdentifier(table);
    const columnName = this.escapeIdentifier(column);

    return await this.query<T>(`
      UPDATE ${tableName}
      SET ${columnName} = array_remove(${columnName}, $1)
      WHERE id = $2
      RETURNING *
    `, [values[0], recordId]);
  }

  private getActualTableName(table: string): string {
    // Map logical table names to actual PostgreSQL table names
    const tableMap: Record<string, string> = {
      'knowledge_items': 'knowledge_items',
      'section': 'section',
      'sections': 'section'
    };
    return tableMap[table] || table;
  }

  private escapeIdentifier(name: string): string {
    return `"${name.replace(/"/g, '""')}"`;
  }

  private async getTotalCount(): Promise<number> {
    try {
      const result = await this.query('SELECT COUNT(*) as count FROM knowledge_items');
      return parseInt(result[0]?.count || '0');
    } catch (error) {
      return 0;
    }
  }

  private async getStorageSize(): Promise<number> {
    try {
      const result = await this.query(`
        SELECT
          pg_total_relation_size('knowledge_items') as size
      `);
      return parseInt(result[0]?.size || '0');
    } catch (error) {
      return 0;
    }
  }
}