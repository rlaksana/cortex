import { PrismaClient } from '@prisma/client';
import * as crypto from 'crypto';

// Global Prisma client instance
let prisma: PrismaClient | null = null;

export function getPrismaClient(): PrismaClient {
  if (!prisma) {
    prisma = new PrismaClient({
      log: ['warn', 'error'],
      datasources: {
        db: {
          url: process.env.DATABASE_URL || 'postgresql://localhost:5432/cortex_db'
        }
      }
    });
  }
  return prisma;
}

/**
 * Gracefully closes the database connection
 */
export async function disconnectPrisma(): Promise<void> {
  if (prisma) {
    await prisma.$disconnect();
    prisma = null;
  }
}

/**
 * Type-safe section operations using Prisma
 */
export class SectionService {
  private prisma = getPrismaClient();

  /**
   * Creates a new section using Prisma client
   */
  async createSection(data: {
    title: string;
    content?: string;
    tags?: Record<string, any>;
    metadata?: Record<string, any>;
  }) {
    const id = crypto.randomUUID();

    // Use Prisma's native create method
    const section = await this.prisma.section.create({
      data: {
        id,
        title: data.title,
        content: data.content || null,
        tags: data.tags || {},
        metadata: data.metadata || {},
      },
      select: {
        id: true,
        title: true,
        content: true,
        created_at: true,
        updated_at: true,
      },
    });

    return {
      id: section.id,
      title: section.title,
      content: section.content,
      created_at: section.created_at,
      updated_at: section.updated_at,
    };
  }

  /**
   * Finds sections by title or content using Prisma
   */
  async findSections(criteria: { title?: string; limit?: number; offset?: number }) {
    const whereClause: any = {};

    if (criteria.title) {
      whereClause.title = { contains: criteria.title, mode: 'insensitive' };
    }

    const sections = await this.prisma.section.findMany({
      where: whereClause,
      take: criteria.limit || 50,
      skip: criteria.offset || 0,
      select: {
        id: true,
        title: true,
        content: true,
        created_at: true,
        updated_at: true,
      },
      orderBy: { updated_at: 'desc' },
    });

    return sections.map(section => ({
      id: section.id,
      title: section.title,
      content: section.content,
      created_at: section.created_at,
      updated_at: section.updated_at,
    }));
  }

  /**
   * Finds sections by scope tags using Prisma
   */
  async findSectionsByScope(scope: Record<string, any>) {
    const sections = await this.prisma.section.findMany({
      where: {
        tags: {
          path: [Object.keys(scope)[0]], // Get first key for JSONB path
          equals: Object.values(scope)[0], // Get first value
        },
      },
      select: {
        id: true,
        title: true,
        content: true,
        created_at: true,
        updated_at: true,
      },
      orderBy: { updated_at: 'desc' },
    });

    return sections.map(section => ({
      id: section.id,
      title: section.title,
      content: section.content,
      created_at: section.created_at,
      updated_at: section.updated_at,
    }));
  }

  /**
   * Updates an existing section using Prisma
   */
  async updateSection(
    id: string,
    data: {
      title?: string;
      content?: string;
      tags?: Record<string, any>;
    }
  ): Promise<{
    id: string;
    title: string;
    content: string | null;
    created_at: Date;
    updated_at: Date;
  }> {
    const updateData: any = {};

    if (data.title !== undefined) updateData.title = data.title;
    if (data.content !== undefined) updateData.content = data.content;
    if (data.tags !== undefined) updateData.tags = data.tags;

    const section = await this.prisma.section.update({
      where: { id },
      data: updateData,
      select: {
        id: true,
        title: true,
        content: true,
        created_at: true,
        updated_at: true,
      },
    });

    return {
      id: section.id,
      title: section.title,
      content: section.content,
      created_at: section.created_at,
      updated_at: section.updated_at,
    };
  }

  /**
   * Finds sections by title search (simple content hash lookup not available)
   */
  async findByContentHash(_content_hash: string): Promise<{
    id: string;
    title: string;
    created_at: Date;
  } | null> {
    // Note: content_hash field doesn't exist in the schema
    // This is a simplified implementation
    return null;
  }
}

/**
 * Type-safe decision operations using Prisma
 */
export class DecisionService {
  private prisma = getPrismaClient();

  async createDecision(data: {
    component: string;
    status: string;
    title: string;
    rationale: string;
    alternativesConsidered?: string[];
    tags?: Record<string, any>;
  }) {
    const id = `decision_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // Use Prisma's native create method
    const decision = await this.prisma.adrDecision.create({
      data: {
        id,
        component: data.component,
        status: data.status,
        title: data.title,
        rationale: data.rationale,
        alternativesConsidered: data.alternativesConsidered || [],
        tags: data.tags || {},
      },
      select: {
        id: true,
        component: true,
        status: true,
        title: true,
        rationale: true,
        created_at: true,
        updated_at: true,
      },
    });

    return {
      id: decision.id,
      component: decision.component,
      status: decision.status,
      title: decision.title,
      rationale: decision.rationale,
      created_at: decision.created_at,
      updated_at: decision.updated_at,
    };
  }

  async updateDecision(
    id: string,
    data: Partial<{
      status: string;
      title: string;
      rationale: string;
      alternativesConsidered: string[];
    }>
  ) {
    const updateData: any = {};

    if (data.status !== undefined) updateData.status = data.status;
    if (data.title !== undefined) updateData.title = data.title;
    if (data.rationale !== undefined) updateData.rationale = data.rationale;
    if (data.alternativesConsidered !== undefined) updateData.alternativesConsidered = data.alternativesConsidered;

    const decision = await this.prisma.adrDecision.update({
      where: { id },
      data: updateData,
      select: {
        id: true,
        component: true,
        status: true,
        title: true,
        rationale: true,
        created_at: true,
        updated_at: true,
      },
    });

    return {
      id: decision.id,
      component: decision.component,
      status: decision.status,
      title: decision.title,
      rationale: decision.rationale,
      created_at: decision.created_at,
      updated_at: decision.updated_at,
    };
  }

  async findDecision(id: string): Promise<{
    id: string;
    title: string;
    component: string;
    status: string;
    rationale: string;
    created_at: Date;
    updated_at: Date;
  } | null> {
    const decision = await this.prisma.adrDecision.findUnique({
      where: { id },
      select: {
        id: true,
        title: true,
        component: true,
        status: true,
        rationale: true,
        created_at: true,
        updated_at: true,
      },
    });

    if (!decision) {
      return null;
    }

    return {
      id: decision.id,
      title: decision.title,
      component: decision.component,
      status: decision.status,
      rationale: decision.rationale,
      created_at: decision.created_at,
      updated_at: decision.updated_at,
    };
  }
}

/**
 * Export singleton instances
 */
export const sectionService = new SectionService();
export const decisionService = new DecisionService();
