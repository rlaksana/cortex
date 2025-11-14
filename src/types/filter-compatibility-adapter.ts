/**
 * Filter Compatibility Adapter
 *
 * Provides seamless conversion between MongoDB-style QueryFilter, legacy QueryFilters,
 * and VectorFilter patterns to eliminate interface fragmentation across the codebase.
 *
 * @author Cortex Team
 * @version 2.0.1
 * @since 2025
 */

import type { QueryFilter, FilterOperator, LogicalOperators } from './database-generics.js';
import type { QueryFilters, VectorFilter, FilterCondition, ScopeFilter, DateRangeFilter } from './database-types-enhanced.js';

// ============================================================================
// Unified Filter Interface
// ============================================================================

/**
 * Unified filter interface that can accept any filter pattern
 * and automatically convert to the appropriate target format
 */
export type UnifiedFilter<T = Record<string, unknown>> =
  | QueryFilter<T>
  | QueryFilters
  | VectorFilter
  | (QueryFilter<T> & QueryFilters);

// ============================================================================
// Adapter Implementation
// ============================================================================

/**
 * Filter compatibility adapter for seamless conversion between filter patterns
 */
export class FilterAdapter {
  /**
   * Convert any filter format to MongoDB-style QueryFilter
   */
  static toQueryFilter<T = Record<string, unknown>>(filter: UnifiedFilter<T>): QueryFilter<T> {
    if (this.isMongoDBFilter(filter)) {
      return filter as QueryFilter<T>;
    }

    if (this.isLegacyFilter(filter)) {
      return this.legacyToMongoDB(filter as QueryFilters) as QueryFilter<T>;
    }

    if (this.isVectorFilter(filter)) {
      return this.vectorToMongoDB(filter as VectorFilter) as QueryFilter<T>;
    }

    throw new Error('Unsupported filter format');
  }

  /**
   * Convert any filter format to legacy QueryFilters
   */
  static toLegacyFilter(filter: UnifiedFilter): QueryFilters {
    if (this.isLegacyFilter(filter)) {
      return filter as QueryFilters;
    }

    if (this.isMongoDBFilter(filter)) {
      return this.mongoDBToLegacy(filter as QueryFilter);
    }

    if (this.isVectorFilter(filter)) {
      return this.vectorToLegacy(filter as VectorFilter);
    }

    throw new Error('Unsupported filter format');
  }

  /**
   * Convert any filter format to VectorFilter
   */
  static toVectorFilter(filter: UnifiedFilter): VectorFilter {
    if (this.isVectorFilter(filter)) {
      return filter as VectorFilter;
    }

    if (this.isMongoDBFilter(filter)) {
      return this.mongoDBToVector(filter as QueryFilter);
    }

    if (this.isLegacyFilter(filter)) {
      return this.legacyToVector(filter as QueryFilters);
    }

    throw new Error('Unsupported filter format');
  }

  // ============================================================================
  // Type Guards
  // ============================================================================

  private static isMongoDBFilter(filter: unknown): boolean {
    if (!filter || typeof filter !== 'object') return false;

    const f = filter as Record<string, unknown>;
    const mongoOperators = ['$eq', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin', '$exists', '$regex', '$like', '$and', '$or', '$not'];

    return mongoOperators.some(op => op in f);
  }

  private static isLegacyFilter(filter: unknown): boolean {
    if (!filter || typeof filter !== 'object') return false;

    const f = filter as Record<string, unknown>;
    const legacyProperties = ['kinds', 'scope', 'tags', 'metadata', 'dateRange', 'custom'];

    return legacyProperties.some(prop => prop in f);
  }

  private static isVectorFilter(filter: unknown): boolean {
    if (!filter || typeof filter !== 'object') return false;

    const f = filter as Record<string, unknown>;
    const vectorProperties = ['must', 'must_not', 'should'];

    return vectorProperties.some(prop => prop in f);
  }

  // ============================================================================
  // MongoDB QueryFilter Conversions
  // ============================================================================

  private static mongoDBToLegacy(filter: QueryFilter): QueryFilters {
    // Extract logical operators
    const custom: Record<string, unknown> = {};
    const scope: Record<string, unknown> = {};
    const dateRange: Record<string, unknown> = {};
    const metadata: Record<string, unknown> = {};
    const tags: Record<string, unknown> = {};

    if ('$and' in filter) {
      const andValue = (filter as LogicalOperators<unknown>).$and;
      if (Array.isArray(andValue)) {
        custom.$and = andValue as unknown[];
      }
    }

    if ('$or' in filter) {
      const orValue = (filter as LogicalOperators<unknown>).$or;
      if (Array.isArray(orValue)) {
        custom.$or = orValue as unknown[];
      }
    }

    // Extract field-level conditions
    for (const [key, value] of Object.entries(filter)) {
      if (key.startsWith('$')) continue; // Skip operators

      if (this.isScopeCondition(key)) {
        scope[key] = value;
      } else if (this.isDateCondition(key)) {
        this.convertFieldToDateRangeMutable(key, value, dateRange);
      } else if (this.isTagCondition(key)) {
        Object.assign(tags, this.convertToTags(value));
      } else {
        metadata[key] = value;
      }
    }

    // Assemble the legacy filter using type assertions to bypass readonly
    const legacy: QueryFilters = {} as QueryFilters;

    if (Object.keys(custom).length > 0) {
      (legacy as any).custom = custom;
    }
    if (Object.keys(scope).length > 0) {
      (legacy as any).scope = scope as ScopeFilter;
    }
    if (Object.keys(dateRange).length > 0) {
      (legacy as any).dateRange = dateRange as DateRangeFilter;
    }
    if (Object.keys(tags).length > 0) {
      (legacy as any).tags = tags;
    }
    if (Object.keys(metadata).length > 0) {
      (legacy as any).metadata = metadata;
    }

    return legacy;
  }

  private static mongoDBToVector(filter: QueryFilter): VectorFilter {
    // Build all parts separately for immutability
    const mustConditions: FilterCondition[] = [];
    const mustNotConditions: FilterCondition[] = [];
    const shouldConditions: FilterCondition[] = [];

    for (const [key, value] of Object.entries(filter)) {
      if (key === '$and') {
        // Convert $and to must conditions
        const andConditions = (value as QueryFilter[]) || [];
        const convertedMust = andConditions.flatMap(cond => this.mongoDBConditionToVector(cond));
        mustConditions.push(...convertedMust);
      } else if (key === '$or') {
        // Convert $or to should conditions
        const orConditions = (value as QueryFilter[]) || [];
        const convertedShould = orConditions.flatMap(cond => this.mongoDBConditionToVector(cond));
        shouldConditions.push(...convertedShould);
      } else if (key === '$not') {
        // Convert $not to must_not conditions
        const notCondition = value as QueryFilter;
        const convertedMustNot = this.mongoDBConditionToVector(notCondition);
        mustNotConditions.push(...convertedMustNot);
      } else {
        // Convert field conditions
        const vectorConditions = this.mongoDBConditionToVector({ [key]: value });
        mustConditions.push(...vectorConditions);
      }
    }

    // Assemble the vector filter using type assertions to bypass readonly
    const vector: VectorFilter = {} as VectorFilter;

    if (mustConditions.length > 0) {
      (vector as any).must = mustConditions;
    }
    if (mustNotConditions.length > 0) {
      (vector as any).must_not = mustNotConditions;
    }
    if (shouldConditions.length > 0) {
      (vector as any).should = shouldConditions;
    }

    return vector;
  }

  private static mongoDBConditionToVector(condition: QueryFilter): FilterCondition[] {
    const conditions: FilterCondition[] = [];

    for (const [key, value] of Object.entries(condition)) {
      if (key.startsWith('$')) continue; // Skip logical operators handled separately

      if (typeof value === 'object' && value !== null && '$regex' in value) {
        // Handle regex matches
        conditions.push({
          key,
          match: (value as { $regex: RegExp }).$regex.source
        } as FilterCondition);
      } else if (typeof value === 'object' && value !== null && '$in' in value) {
        // Handle $in operator
        const inValue = (value as { $in: readonly unknown[] }).$in;
        if (inValue.length === 1) {
          conditions.push({
            key,
            match: inValue[0] as string | number | boolean
          } as FilterCondition);
        } else {
          // For multiple values, create multiple conditions or handle as range
          for (const val of inValue) {
            conditions.push({
              key,
              match: val as string | number | boolean
            } as FilterCondition);
          }
        }
      } else if (typeof value === 'object' && value !== null) {
        // Handle range operators
        const rangeCondition: FilterCondition = { key } as FilterCondition;
        const range: Record<string, number> = {};

        if ('$gt' in value) range.gt = (value as { $gt: number }).$gt;
        if ('$gte' in value) range.gte = (value as { $gte: number }).$gte;
        if ('$lt' in value) range.lt = (value as { $lt: number }).$lt;
        if ('$lte' in value) range.lte = (value as { $lte: number }).$lte;

        if (Object.keys(range).length > 0) {
          (rangeCondition as any).range = range;
          conditions.push(rangeCondition);
        } else {
          // Fallback to direct match
          conditions.push({
            key,
            match: value as unknown as string | number | boolean
          } as FilterCondition);
        }
      } else {
        // Direct equality match
        conditions.push({
          key,
          match: value as string | number | boolean
        } as FilterCondition);
      }
    }

    return conditions;
  }

  // ============================================================================
  // Legacy QueryFilters Conversions
  // ============================================================================

  private static legacyToMongoDB(filter: QueryFilters): QueryFilter {
    // Build all parts separately before combining
    const scopePart = filter.scope ? this.scopeToMongoDB(filter.scope) : {};
    const dateRangePart = filter.dateRange ? this.dateRangeToMongoDB(filter.dateRange) : {};
    const tagsPart = filter.tags ? { tags: this.tagsToMongoDB(filter.tags) } : {};
    const metadataPart = filter.metadata ? this.metadataToMongoDB(filter.metadata) : {};
    const customPart = filter.custom || {};
    const kindsPart = filter.kinds ? { kind: { $in: filter.kinds } } : {};

    // Combine all parts using object spread for immutability
    return {
      ...scopePart,
      ...dateRangePart,
      ...tagsPart,
      ...metadataPart,
      ...customPart,
      ...kindsPart,
    };
  }

  private static legacyToVector(filter: QueryFilters): VectorFilter {
    const mongodb = this.legacyToMongoDB(filter);
    return this.mongoDBToVector(mongodb);
  }

  // ============================================================================
  // VectorFilter Conversions
  // ============================================================================

  private static vectorToMongoDB(filter: VectorFilter): QueryFilter {
    // Build all parts separately before combining
    const mongodbParts: QueryFilter[] = [];

    // Convert must conditions (AND logic)
    if (filter.must && filter.must.length > 0) {
      const conditions = filter.must.map(condition => this.vectorConditionToMongoDB(condition));
      mongodbParts.push(...conditions);
    }

    // Convert must_not conditions
    let mustNotPart: QueryFilter | undefined;
    if (filter.must_not && filter.must_not.length > 0) {
      const notConditions = filter.must_not.map(condition => this.vectorConditionToMongoDB(condition));
      if (notConditions.length === 1) {
        mustNotPart = notConditions[0];
      } else {
        mustNotPart = { $and: notConditions };
      }
    }

    // Convert should conditions (OR logic)
    let shouldPart: QueryFilter | undefined;
    if (filter.should && filter.should.length > 0) {
      const shouldConditions = filter.should.map(condition => this.vectorConditionToMongoDB(condition));
      if (shouldConditions.length === 1) {
        shouldPart = shouldConditions[0];
      } else {
        shouldPart = { $or: shouldConditions };
      }
    }

    // Combine all parts using type assertions to bypass readonly
    const result: QueryFilter = {} as QueryFilter;

    // Add all mongodb parts with object spread
    if (mongodbParts.length === 1) {
      Object.assign(result, mongodbParts[0]);
    } else if (mongodbParts.length > 1) {
      (result as any).$and = mongodbParts;
    }

    // Add must_not part
    if (mustNotPart) {
      (result as any).$not = mustNotPart;
    }

    // Add should part
    if (shouldPart) {
      if (shouldPart.$or) {
        (result as any).$or = shouldPart.$or;
      } else {
        Object.assign(result, shouldPart);
      }
    }

    return result;
  }

  private static vectorToLegacy(filter: VectorFilter): QueryFilters {
    const mongodb = this.vectorToMongoDB(filter);
    return this.mongoDBToLegacy(mongodb);
  }

  private static vectorConditionToMongoDB(condition: FilterCondition): QueryFilter {
    const mongodb: QueryFilter = {} as QueryFilter;

    if (condition.match !== undefined) {
      (mongodb as any)[condition.key] = condition.match;
    } else if (condition.range) {
      const rangeObj: Record<string, number> = {};
      if (condition.range.gt !== undefined) rangeObj.$gt = condition.range.gt;
      if (condition.range.gte !== undefined) rangeObj.$gte = condition.range.gte;
      if (condition.range.lt !== undefined) rangeObj.$lt = condition.range.lt;
      if (condition.range.lte !== undefined) rangeObj.$lte = condition.range.lte;
      (mongodb as any)[condition.key] = rangeObj;
    } else if (condition.values && condition.values.length > 0) {
      (mongodb as any)[condition.key] = { $in: condition.values };
    }

    return mongodb;
  }

  // ============================================================================
  // Helper Conversion Methods
  // ============================================================================

  private static isScopeCondition(key: string): boolean {
    return ['project', 'branch', 'org', 'service', 'tenant', 'environment'].includes(key);
  }

  private static isDateCondition(key: string): boolean {
    return key.includes('date') || key.includes('time') || key.endsWith('_at');
  }

  private static isTagCondition(key: string): boolean {
    return key === 'tags' || key === 'tag';
  }

  private static convertFieldToScope(key: string, value: unknown, scope: Partial<ScopeFilter>): void {
    (scope as Record<string, unknown>)[key] = value;
  }

  private static convertFieldToDateRange(key: string, value: unknown, dateRange: Partial<DateRangeFilter>): void {
    if (typeof value === 'object' && value !== null) {
      const v = value as Record<string, unknown>;
      if ('$gt' in v || '$gte' in v) {
        (dateRange as any).from = v.$gt || v.$gte;
        (dateRange as any).field = (dateRange as any).field || key as 'created_at' | 'updated_at' | 'timestamp';
      }
      if ('$lt' in v || '$lte' in v) {
        (dateRange as any).to = v.$lt || v.$lte;
        (dateRange as any).field = (dateRange as any).field || key as 'created_at' | 'updated_at' | 'timestamp';
      }
    }
  }

  private static convertFieldToDateRangeMutable(key: string, value: unknown, dateRange: Record<string, unknown>): void {
    if (typeof value === 'object' && value !== null) {
      const v = value as Record<string, unknown>;
      if ('$gt' in v || '$gte' in v) {
        dateRange.from = v.$gt || v.$gte;
        dateRange.field = dateRange.field || key as 'created_at' | 'updated_at' | 'timestamp';
      }
      if ('$lt' in v || '$lte' in v) {
        dateRange.to = v.$lt || v.$lte;
        dateRange.field = dateRange.field || key as 'created_at' | 'updated_at' | 'timestamp';
      }
    }
  }

  private static convertToTags(value: unknown): Record<string, unknown> {
    if (Array.isArray(value)) {
      return value.reduce((tags, tag, index) => ({ ...tags, [`tag_${index}`]: tag }), {});
    }
    return value as Record<string, unknown>;
  }

  private static scopeToMongoDB(scope: ScopeFilter): QueryFilter {
    return scope as QueryFilter;
  }

  private static dateRangeToMongoDB(dateRange: DateRangeFilter): QueryFilter {
    const filter: QueryFilter = {} as QueryFilter;
    const field = dateRange.field || 'created_at';

    const fieldCondition: Record<string, unknown> = {};
    if (dateRange.from) {
      fieldCondition.$gte = dateRange.from;
    }
    if (dateRange.to) {
      fieldCondition.$lte = dateRange.to;
    }

    if (Object.keys(fieldCondition).length > 0) {
      (filter as any)[field] = fieldCondition;
    }

    return filter;
  }

  private static tagsToMongoDB(tags: Record<string, unknown>): unknown {
    return tags;
  }

  private static metadataToMongoDB(metadata: Record<string, unknown>): QueryFilter {
    return metadata as unknown as QueryFilter;
  }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Convenience function to convert any filter to MongoDB QueryFilter
 */
export function toQueryFilter<T = Record<string, unknown>>(filter: UnifiedFilter<T>): QueryFilter<T> {
  return FilterAdapter.toQueryFilter(filter);
}

/**
 * Convenience function to convert any filter to legacy QueryFilters
 */
export function toLegacyFilter(filter: UnifiedFilter): QueryFilters {
  return FilterAdapter.toLegacyFilter(filter);
}

/**
 * Convenience function to convert any filter to VectorFilter
 */
export function toVectorFilter(filter: UnifiedFilter): VectorFilter {
  return FilterAdapter.toVectorFilter(filter);
}

// ============================================================================
// Type Guards for External Use
// ============================================================================

export function isMongoDBFilter(filter: unknown): filter is QueryFilter {
  return FilterAdapter['isMongoDBFilter'](filter);
}

export function isLegacyFilter(filter: unknown): filter is QueryFilters {
  return FilterAdapter['isLegacyFilter'](filter);
}

export function isVectorFilter(filter: unknown): filter is VectorFilter {
  return FilterAdapter['isVectorFilter'](filter);
}

// ============================================================================
// Migration Utilities
// ============================================================================

/**
 * Migration utilities for gradual filter type updates
 */
export namespace FilterMigration {
  export const MongoDB = toQueryFilter;
  export const Legacy = toLegacyFilter;
  export const Vector = toVectorFilter;

  export const Adapter = FilterAdapter;

  /**
   * Auto-detect and convert filter to preferred format
   */
  export function autoConvert<T = Record<string, unknown>>(
    filter: UnifiedFilter<T>,
    targetFormat: 'mongodb' | 'legacy' | 'vector' = 'mongodb'
  ): QueryFilter<T> | QueryFilters | VectorFilter {
    switch (targetFormat) {
      case 'mongodb':
        return toQueryFilter(filter);
      case 'legacy':
        return toLegacyFilter(filter);
      case 'vector':
        return toVectorFilter(filter);
      default:
        throw new Error(`Unsupported target format: ${targetFormat}`);
    }
  }
}