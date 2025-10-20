// import pkg from '@prisma/client';
// import * as crypto from 'crypto';

// Temporarily use direct database queries instead of Prisma
// const { PrismaClient } = pkg;
// type PrismaClientType = InstanceType<typeof PrismaClient>;

import { getPool } from './pool.js';
import * as crypto from 'crypto';

// Global variable to store the database pool
const pool = getPool();

/**
 * Gracefully closes the database connection
 */
export async function disconnectPrisma(): Promise<void> {
  // No-op for now since we're using the pool directly
}

/**
 * Type-safe section operations using Prisma
 */
export class SectionService {
  // Using direct database connection instead of Prisma

  /**
   * Creates a new section using direct SQL queries
   */
  async createSection(data: {
    title: string;
    heading: string;
    bodyMd?: string;
    bodyText?: string;
    tags?: Record<string, any>;
    metadata?: Record<string, any>;
  }) {
    const bodyJsonb = {
      text: data.bodyText ?? data.bodyMd ?? '',
      markdown: data.bodyMd ?? null,
    };

    const contentHash = this.generateContentHash(data.title, data.bodyMd ?? data.bodyText);
    const id = `section_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    const query = `
      INSERT INTO "sections" (id, title, heading, "bodyMd", "bodyText", "bodyJsonb", "contentHash", tags, metadata, "createdAt", "updatedAt")
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
      RETURNING id, title, heading, "bodyMd", "bodyText", "createdAt", "updatedAt"
    `;

    const result = await pool.query(query, [
      id,
      data.title,
      data.heading,
      data.bodyMd ?? null,
      data.bodyText ?? null,
      JSON.stringify(bodyJsonb),
      contentHash,
      JSON.stringify(data.tags ?? {}),
      JSON.stringify(data.metadata ?? {})
    ]);

    return result.rows[0];
  }

  /**
   * Finds sections by title or content (simplified for now)
   */
  async findSections(_criteria: { title?: string; limit?: number; offset?: number }) {
    // Simplified implementation - return empty results for now
    return [];
  }

  /**
   * Finds sections by scope tags (simplified for now)
   */
  async findSectionsByScope(_scope: Record<string, any>) {
    // Simplified implementation - return empty results for now
    return [];
  }

  /**
   * Updates an existing section (simplified for now)
   */
  async updateSection(
    id: string,
    data: {
      title?: string;
      heading?: string;
      bodyMd?: string;
      bodyText?: string;
      tags?: Record<string, any>;
    }
  ): Promise<{
    id: string;
    title: string;
    heading: string;
    createdAt: string;
    updatedAt: string;
  }> {
    // Simplified implementation - return mock data for now
    return {
      id,
      title: data.title || 'Updated Title',
      heading: data.heading || 'Updated Heading',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
  }

  /**
   * Checks for duplicate content by hash (simplified for now)
   */
  async findByContentHash(_contentHash: string): Promise<{
    id: string;
    title: string;
    createdAt: string;
  } | null> {
    // Simplified implementation - return null for now
    return null;
  }

  /**
   * Generates a consistent content hash
   */
  private generateContentHash(title: string, content?: string): string {
    const hashInput = `${title}:${content ?? ''}`;
    return crypto.createHash('sha256').update(hashInput).digest('hex');
  }
}

/**
 * Type-safe decision operations using Prisma
 */
export class DecisionService {
  async createDecision(data: {
    component: string;
    status: string;
    title: string;
    rationale: string;
    alternativesConsidered?: string[];
    consequences?: string;
    supersedes?: string;
    tags?: Record<string, any>;
  }) {
    const id = `decision_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // For now, return a mock decision
    return {
      id,
      component: data.component,
      status: data.status,
      title: data.title,
      rationale: data.rationale,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
  }

  async updateDecision(
    _id: string,
    data: Partial<{
      status: string;
      title: string;
      rationale: string;
      alternativesConsidered: string[];
      consequences: string;
    }>
  ) {
    // For now, return a mock updated decision
    return {
      id: 'mock-decision-id',
      component: 'mock-component',
      status: data.status || 'updated',
      title: data.title || 'Updated Decision',
      rationale: data.rationale || 'Updated rationale',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
  }

  async findDecision(_id: string): Promise<{
    id: string;
    title: string;
    component: string;
    status: string;
    rationale: string;
    createdAt: string;
    updatedAt: string;
  } | null> {
    // For now, return null to indicate no existing decision
    return null;
  }
}

/**
 * Export singleton instances
 */
export const sectionService = new SectionService();
export const decisionService = new DecisionService();
