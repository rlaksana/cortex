/**
 * Unified Database Access Layer - PostgreSQL 18 Features
 *
 * Combines the type safety of Prisma ORM with the flexibility of raw SQL
 * for complex PostgreSQL 18 features.
 *
 * Features:
 * - Single interface for all database operations
 * - PostgreSQL 18 feature support (full-text search, JSONB, arrays, UUID)
 * - Connection pooling and performance optimization
 * - Type safety with TypeScript
 * - Comprehensive error handling and logging
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { PrismaClient } from '@prisma/client';
import { logger } from '../utils/logger.js';

export interface DatabaseConfig {
  connectionString?: string;
  logQueries?: boolean;
  connectionTimeout?: number;
  maxConnections?: number;
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
 * Provides a single interface for all database operations, combining
 * Prisma ORM for type-safe CRUD with raw SQL for complex PostgreSQL features.
 */
export class UnifiedDatabaseLayer {
  private prisma: PrismaClient;
  private config: DatabaseConfig;
  private initialized: boolean = false;

  constructor(config: DatabaseConfig = {}) {
    this.config = {
      connectionString: config.connectionString || process.env.DATABASE_URL,
      logQueries: config.logQueries || false,
      connectionTimeout: config.connectionTimeout || 30000,
      maxConnections: config.maxConnections || 10,
      ...config
    };

    this.prisma = new PrismaClient({
      datasources: {
        db: {
          url: this.config.connectionString
        }
      },
      log: this.config.logQueries ? ['query', 'info', 'warn', 'error'] : ['warn', 'error']
    });
  }

  /**
   * Initialize the database layer
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    try {
      logger.info('Initializing unified database layer...');

      // Test database connection
      await this.prisma.$connect();

      // Run health check
      await this.healthCheck();

      this.initialized = true;
      logger.info('✅ Unified database layer initialized successfully');

    } catch (error) {
      logger.error({ error }, '❌ Failed to initialize unified database layer');
      throw error;
    }
  }

  /**
   * Health check for database connection
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.prisma.$queryRaw`SELECT 1 as health_check`;
      return true;
    } catch (error) {
      logger.error({ error }, 'Database health check failed');
      return false;
    }
  }

  /**
   * Advanced full-text search using PostgreSQL 18 features
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

    try {
      logger.debug({ query, config, weighting }, 'Executing PostgreSQL 18 full-text search');

      const weightingString = JSON.stringify(weighting);

      const results = await this.prisma.$queryRaw`
        SELECT
          s.id,
          s.title,
          s.content,
          s.heading,
          s.updated_at,
          ts_rank_cd(
            websearch_to_tsquery(${config}, ${query}),
            setweight(to_tsvector(${config}, COALESCE(s.title, '')), 'A') ||
            setweight(to_tsvector(${config}, COALESCE(s.heading, '')), 'B') ||
            setweight(to_tsvector(${config}, COALESCE(s.content, '')), 'C'),
            ${weightingString}::float4[],
            ${normalization}
          ) as rank,
          ts_headline(
            ${config},
            COALESCE(s.content, ''),
            websearch_to_tsquery(${config}, ${query}),
            'MaxWords=${snippet_size}, MinWords=20, ShortWord=3, HighlightAll=true, MaxFragments=3, FragmentDelimiter= ... '
          ) as snippet,
          ts_headline(
            ${config},
            COALESCE(s.title, ''),
            websearch_to_tsquery(${config}, ${query}),
            'MaxWords=30, HighlightAll=true'
          ) as title_highlight
        FROM "Section" s
        WHERE
          websearch_to_tsquery(${config}, ${query}) @@ (
            setweight(to_tsvector(${config}, COALESCE(s.title, '')), 'A') ||
            setweight(to_tsvector(${config}, COALESCE(s.heading, '')), 'B') ||
            setweight(to_tsvector(${config}, COALESCE(s.content, '')), 'C')
          )
          AND ts_rank_cd(
            websearch_to_tsquery(${config}, ${query}),
            setweight(to_tsvector(${config}, COALESCE(s.title, '')), 'A') ||
            setweight(to_tsvector(${config}, COALESCE(s.heading, '')), 'B') ||
            setweight(to_tsvector(${config}, COALESCE(s.content, '')), 'C'),
            ${weightingString}::float4[],
            ${normalization}
          ) >= ${min_rank}
        ORDER BY rank DESC, s.updated_at DESC
        LIMIT ${max_results}
      ` as any[];

      return results.map((row: any) => ({
        id: row.id,
        title: row.title_highlight || row.title || 'Untitled',
        snippet: row.snippet || row.content?.substring(0, snippet_size) + '...' || '',
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
      logger.error({ query, config, error }, 'PostgreSQL 18 full-text search failed');
      return await this.fallbackSearch(query, max_results);
    }
  }

  /**
   * Fallback search using simple LIKE queries
   */
  private async fallbackSearch(query: string, limit: number): Promise<SearchResult[]> {
    try {
      const results = await this.prisma.section.findMany({
        where: {
          OR: [
            { title: { contains: query, mode: 'insensitive' } },
            { content: { contains: query, mode: 'insensitive' } },
            { heading: { contains: query, mode: 'insensitive' } }
          ]
        },
        take: limit,
        orderBy: { updated_at: 'desc' }
      });

      return results.map(result => ({
        id: result.id,
        title: result.title || 'Untitled',
        snippet: result.content?.substring(0, 150) + '...' || '',
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
    }
  }

  
  /**
   * Advanced UUID generation using PostgreSQL 18 features
   */
  async generateUUID(options: UUIDGenerationOptions = {}): Promise<string> {
    await this.ensureInitialized();

    const { version = 'v4' } = options;

    try {
      logger.debug({ version }, 'Executing PostgreSQL 18 UUID generation');

      switch (version) {
        case 'v4':
          const v4Result = await this.prisma.$queryRaw`SELECT gen_random_uuid() as uuid` as any[];
          return v4Result[0]?.uuid;

        case 'v7':
          const v7Result = await this.prisma.$queryRaw`
            SELECT gen_random_uuid() ||
                   LPAD(EXTRACT(epoch FROM now())::text, 12, '0') as uuid
          ` as any[];
          return v7Result[0]?.uuid;

        default:
          throw new Error(`Unsupported UUID version: ${version}`);
      }

    } catch (error) {
      logger.error({ version, error }, 'PostgreSQL 18 UUID generation failed');
      const fallbackResult = await this.prisma.$queryRaw`SELECT gen_random_uuid() as uuid` as any[];
      return fallbackResult[0]?.uuid;
    }
  }

  async generateUUIDv7(): Promise<string> {
    return await this.generateUUID({ version: 'v7' });
  }

  async generateMultipleUUIDs(count: number, version: 'v4' | 'v7' = 'v4'): Promise<string[]> {
    await this.ensureInitialized();

    try {
      logger.debug({ count, version }, 'Generating multiple PostgreSQL 18 UUIDs');

      let results: any[];

      switch (version) {
        case 'v4':
          results = await this.prisma.$queryRaw`
            SELECT gen_random_uuid() as uuid FROM generate_series(1, ${count})
          ` as any[];
          break;
        case 'v7':
          results = await this.prisma.$queryRaw`
            SELECT gen_random_uuid() ||
                   LPAD(EXTRACT(epoch FROM now())::text, 12, '0') as uuid
            FROM generate_series(1, ${count})
          ` as any[];
          break;
        default:
          throw new Error(`Unsupported UUID version: ${version}`);
      }

      return results.map(row => row.uuid);

    } catch (error) {
      logger.error({ count, version, error }, 'PostgreSQL 18 multiple UUID generation failed');
      throw error;
    }
  }

  /**
   * Performance analysis using PostgreSQL 18 EXPLAIN ANALYZE
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

    try {
      logger.debug({ sql, params, options }, 'Executing PostgreSQL 18 EXPLAIN ANALYZE');

      const explainOptions = [];
      if (analyze) explainOptions.push('ANALYZE');
      if (buffers) explainOptions.push('BUFFERS');
      if (timing) explainOptions.push('TIMING');
      if (verbose) explainOptions.push('VERBOSE');
      if (costs) explainOptions.push('COSTS');

      const explainOptionsStr = explainOptions.join(', ');
      const explainSql = `EXPLAIN (${explainOptionsStr}, FORMAT ${format.toUpperCase()}) ${sql}`;

      const result = await this.prisma.$queryRaw`${explainSql}` as any[];

      if (format === 'json' && result.length > 0) {
        const plan = result[0];
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
        plan: result,
        execution_time: undefined,
        planning_time: undefined
      };

    } catch (error) {
      logger.error({ sql, params, error }, 'PostgreSQL 18 EXPLAIN ANALYZE failed');
      throw error;
    }
  }

  /**
   * Create operation
   */
  async create<T = any>(table: string, data: any): Promise<T> {
    await this.ensureInitialized();

    try {
      const model = this.getPrismaModel(table);
      return await model.create({ data });
    } catch (error) {
      logger.error({ table, data, error }, 'Create operation failed');
      throw error;
    }
  }

  /**
   * Update operation
   */
  async update<T = any>(table: string, where: any, data: any): Promise<T> {
    await this.ensureInitialized();

    try {
      const model = this.getPrismaModel(table);
      return await model.update({
        where: this.transformWhereClause(where),
        data
      });
    } catch (error) {
      logger.error({ table, where, data, error }, 'Update operation failed');
      throw error;
    }
  }

  /**
   * Delete operation
   */
  async delete<T = any>(table: string, where: any): Promise<T> {
    await this.ensureInitialized();

    try {
      const model = this.getPrismaModel(table);
      return await model.delete({
        where: this.transformWhereClause(where)
      });
    } catch (error) {
      logger.error({ table, where, error }, 'Delete operation failed');
      throw error;
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
   * Enhanced JSON Path Query with proper PostgreSQL syntax
   */
  async jsonPathQuery<T = any>(
    table: string,
    jsonbColumn: string,
    query: JsonPathQuery
  ): Promise<T[]> {
    await this.ensureInitialized();

    const { path, filter, vars = {} } = query;

    try {
      logger.debug({ table, jsonbColumn, path, filter }, 'Executing PostgreSQL 18 jsonb_path_query');

      const tableName = this.escapeIdentifier(this.getActualTableName(table));
      const columnName = this.escapeIdentifier(jsonbColumn);
      const jsonPath = '$' + path;

      if (Object.keys(vars).length > 0) {
        const varNames = Object.keys(vars);
        const varValues = Object.values(vars);
        const pathWithVars = `${jsonPath} ? (${varNames.join(', ')})`;

        const results = await this.prisma.$queryRawUnsafe(`
          SELECT * FROM ${tableName}
          WHERE jsonb_path_query_array(${columnName}, '${pathWithVars}'::jsonpath, '${JSON.stringify(varValues)}'::jsonb) IS NOT NULL
        `) as T[];
        return results;
      } else {
        const results = await this.prisma.$queryRawUnsafe(`
          SELECT * FROM ${tableName}
          WHERE jsonb_path_query_array(${columnName}, '${jsonPath}'::jsonpath) IS NOT NULL
        `) as T[];
        return results;
      }

    } catch (error) {
      logger.error({ table, jsonbColumn, path, error }, 'PostgreSQL 18 jsonb_path_query failed');
      throw error;
    }
  }

  /**
   * Array Query operation using PostgreSQL 18 JSON array features
   */
  async arrayQuery<T = any>(
    table: string,
    options: ArrayOperationOptions
  ): Promise<T[]> {
    await this.ensureInitialized();

    const { column, operation, values, index } = options;

    try {
      logger.debug({ table, column, operation, values }, 'Executing PostgreSQL 18 JSON array query');

      const tableName = this.escapeIdentifier(this.getActualTableName(table));
      const columnName = this.escapeIdentifier(column);

      switch (operation) {
        case 'contains':
          // Check if JSON array contains all specified values
          return await this.prisma.$queryRawUnsafe(`
            SELECT * FROM ${tableName}
            WHERE (${columnName}::jsonb @> '${JSON.stringify(values)}'::jsonb)
          `) as T[];

        case 'contained':
          // Check if JSON array is contained within specified values
          return await this.prisma.$queryRawUnsafe(`
            SELECT * FROM ${tableName}
            WHERE (${columnName}::jsonb <@ '${JSON.stringify(values)}'::jsonb)
          `) as T[];

        case 'overlap':
          // Check if JSON array overlaps with specified values
          return await this.prisma.$queryRawUnsafe(`
            SELECT * FROM ${tableName}
            WHERE (${columnName}::jsonb ?| ARRAY[${values.map(v => `'${v}'`).join(', ')}])
          `) as T[];

        case 'any':
          // Check if JSON array contains any of the specified values
          return await this.prisma.$queryRawUnsafe(`
            SELECT * FROM ${tableName}
            WHERE (${columnName}::jsonb ?| ARRAY[${values.map(v => `'${v}'`).join(', ')}])
          `) as T[];

        case 'all':
          // Check if JSON array contains all specified values
          return await this.prisma.$queryRawUnsafe(`
            SELECT * FROM ${tableName}
            WHERE (${columnName}::jsonb @> '${JSON.stringify(values)}'::jsonb)
          `) as T[];

        case 'append':
          // For append operations, we need to use raw SQL and a record ID
          if (!index) {
            throw new Error('Record ID is required for append operations');
          }
          return await this.arrayAppendOperation(table, column, values, String(index));

        case 'prepend':
          // For prepend operations, we need to use raw SQL and a record ID
          if (!index) {
            throw new Error('Record ID is required for prepend operations');
          }
          return await this.arrayPrependOperation(table, column, values, String(index));

        case 'remove':
          // For remove operations, we need to use raw SQL and a record ID
          if (!index) {
            throw new Error('Record ID is required for remove operations');
          }
          return await this.arrayRemoveOperation(table, column, values, String(index));

        default:
          throw new Error(`Unsupported array operation: ${operation}`);
      }

    } catch (error) {
      logger.error({ table, column, operation, values, error }, 'PostgreSQL 18 JSON array query failed');
      throw error;
    }
  }

  /**
   * Helper method for array append operations
   */
  private async arrayAppendOperation<T = any>(
    table: string,
    column: string,
    values: any[],
    recordId: string
  ): Promise<T[]> {
    const tableName = this.escapeIdentifier(table);
    const columnName = this.escapeIdentifier(column);

    const sql = `
      UPDATE ${tableName}
      SET ${columnName} = array_cat(${columnName}, $1::jsonb)
      WHERE id = $2
      RETURNING *
    `;

    return await this.prisma.$queryRaw`
      UPDATE ${tableName}
      SET ${columnName} = array_cat(${columnName}, ${JSON.stringify(values)}::jsonb)
      WHERE id = ${recordId}
      RETURNING *
    ` as T[];
  }

  /**
   * Helper method for array prepend operations
   */
  private async arrayPrependOperation<T = any>(
    table: string,
    column: string,
    values: any[],
    recordId: string
  ): Promise<T[]> {
    const tableName = this.escapeIdentifier(table);
    const columnName = this.escapeIdentifier(column);

    return await this.prisma.$queryRaw`
      UPDATE ${tableName}
      SET ${columnName} = array_cat(${JSON.stringify(values)}::jsonb, ${columnName})
      WHERE id = ${recordId}
      RETURNING *
    ` as T[];
  }

  /**
   * Helper method for array remove operations
   */
  private async arrayRemoveOperation<T = any>(
    table: string,
    column: string,
    values: any[],
    recordId: string
  ): Promise<T[]> {
    const tableName = this.escapeIdentifier(table);
    const columnName = this.escapeIdentifier(column);

    return await this.prisma.$queryRaw`
      UPDATE ${tableName}
      SET ${columnName} = array_remove(${columnName}, ${values[0]})
      WHERE id = ${recordId}
      RETURNING *
    ` as T[];
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

    try {
      const model = this.getPrismaModel(table);
      let query: any = {
        where: this.transformWhereClause(where),
        take: options.take || 100
      };

      if (options.orderBy) {
        query.orderBy = options.orderBy;
      }

      return await model.findMany(query);
    } catch (error) {
      logger.error({ table, where, error }, 'Find operation failed');
      throw error;
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
      await this.prisma.$disconnect();
      this.initialized = false;
      logger.info('Database connections closed');
    } catch (error) {
      logger.error({ error }, 'Error closing database connections');
      throw error;
    }
  }

  /**
   * Generic query method for backward compatibility with performance monitor
   * Executes raw SQL queries using Prisma's queryRaw
   */
  async query<T = any>(sql: string, params: any[] = []): Promise<T[]> {
    await this.ensureInitialized();

    try {
      if (params.length > 0) {
        return await this.prisma.$queryRawUnsafe(sql, ...params) as T[];
      } else {
        return await this.prisma.$queryRaw`${sql}` as T[];
      }
    } catch (error) {
      logger.error({ sql, params, error }, 'Raw query execution failed');
      throw error;
    }
  }

  // Private helper methods

  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      await this.initialize();
    }
  }

  private getPrismaModel(table: string): any {
    const modelName = this.tableToModelName(table);

    if (!(modelName in this.prisma)) {
      throw new Error(`Model ${modelName} not found in Prisma client`);
    }

    return this.prisma[modelName as keyof PrismaClient];
  }

  private tableToModelName(table: string): string {
    // Handle special case mappings for schema table names
    const tableMappings: Record<string, string> = {
      'section': 'Section',
      'adr_decision': 'AdrDecision',
      'issue_log': 'IssueLog',
      'todo_log': 'TodoLog',
      'runbook': 'Runbook',
      'change_log': 'ChangeLog',
      'release_note': 'ReleaseNote',
      'ddl_history': 'DdlHistory',
      'pr_context': 'PrContext',
      'knowledge_entity': 'KnowledgeEntity',
      'knowledge_relation': 'KnowledgeRelation',
      'knowledge_observation': 'KnowledgeObservation',
      'incident_log': 'IncidentLog',
      'release_log': 'ReleaseLog',
      'risk_log': 'RiskLog',
      'assumption_log': 'AssumptionLog',
      'purge_metadata': 'PurgeMetadata',
      'event_audit': 'EventAudit',
      'user': 'User',
      'api_key': 'ApiKey',
      'auth_session': 'AuthSession',
      'token_revocation_list': 'TokenRevocationList'
    };

    return tableMappings[table] || table
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join('');
  }

  private getActualTableName(table: string): string {
    // Map logical table names to actual PostgreSQL table names from schema
    const tableMappings: Record<string, string> = {
      'section': 'Section',
      'adr_decision': 'AdrDecision',
      'issue_log': 'IssueLog',
      'todo_log': 'TodoLog',
      'runbook': 'Runbook',
      'change_log': 'ChangeLog',
      'release_note': 'ReleaseNote',
      'ddl_history': 'DdlHistory',
      'pr_context': 'PrContext',
      'knowledge_entity': 'KnowledgeEntity',
      'knowledge_relation': 'KnowledgeRelation',
      'knowledge_observation': 'KnowledgeObservation',
      'incident_log': 'IncidentLog',
      'release_log': 'ReleaseLog',
      'risk_log': 'RiskLog',
      'assumption_log': 'AssumptionLog',
      'purge_metadata': 'PurgeMetadata',
      'event_audit': 'EventAudit',
      'user': 'User',
      'api_key': 'ApiKey',
      'auth_session': 'AuthSession',
      'token_revocation_list': 'TokenRevocationList'
    };

    return tableMappings[table] || table;
  }

  private transformWhereClause(where: any): any {
    return where;
  }

  private escapeIdentifier(name: string): string {
    return `"${name.replace(/"/g, '""')}"`;
  }
}

// Export singleton instance
export const database = new UnifiedDatabaseLayer({
  logQueries: process.env.NODE_ENV === 'development',
  connectionTimeout: 30000,
  maxConnections: 10
});