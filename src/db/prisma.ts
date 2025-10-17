import { PrismaClient } from '@prisma/client';
import * as crypto from 'crypto';

// Global variable to store the Prisma client instance
let globalPrisma: PrismaClient | null = null;

/**
 * Creates a new Prisma client instance or returns the existing one
 * Uses a singleton pattern to avoid multiple connections in development
 */
export function getPrismaClient(): PrismaClient {
  globalPrisma ??= new PrismaClient({
    log: ['warn', 'error'],
    errorFormat: 'pretty',
  });
  return globalPrisma;
}

/**
 * Gracefully closes the Prisma client connection
 */
export async function disconnectPrisma(): Promise<void> {
  if (globalPrisma) {
    await globalPrisma.$disconnect();
    globalPrisma = null;
  }
}

/**
 * Type-safe section operations using Prisma
 */
export class SectionService {
  private getPrisma() {
    return getPrismaClient();
  }

  /**
   * Creates a new section with proper type safety
   */
  async createSection(data: {
    title: string;
    heading: string;
    bodyMd?: string;
    bodyText?: string;
    tags?: Record<string, any>;
    metadata?: Record<string, any>;
  }) {
    const prisma = this.getPrisma();
    const bodyJsonb = {
      text: data.bodyText ?? data.bodyMd ?? '',
      markdown: data.bodyMd ?? null,
    };

    const contentHash = this.generateContentHash(data.title, data.bodyMd ?? data.bodyText);

    return await prisma.section.create({
      data: {
        title: data.title,
        heading: data.heading,
        bodyMd: data.bodyMd ?? null,
        bodyText: data.bodyText ?? null,
        bodyJsonb,
        contentHash,
        tags: data.tags ?? {},
        metadata: data.metadata ?? {},
      },
    });
  }

  /**
   * Finds sections by title or content with type safety
   */
  async findSections(criteria: { title?: string; limit?: number; offset?: number }) {
    const prisma = this.getPrisma();
    const where = criteria.title
      ? {
          OR: [
            { title: { contains: criteria.title, mode: 'insensitive' as const } },
            { heading: { contains: criteria.title, mode: 'insensitive' as const } },
          ],
        }
      : {};

    return await prisma.section.findMany({
      where,
      take: criteria.limit,
      skip: criteria.offset,
      orderBy: { updatedAt: 'desc' },
      select: {
        id: true,
        title: true,
        heading: true,
        bodyText: true,
        bodyMd: true,
        citationCount: true,
        createdAt: true,
        updatedAt: true,
      },
    });
  }

  /**
   * Finds sections by scope tags
   */
  async findSectionsByScope(scope: Record<string, any>) {
    const prisma = this.getPrisma();
    return await prisma.section.findMany({
      where: {
        tags: {
          path: [],
          equals: scope,
        },
      },
      orderBy: { updatedAt: 'desc' },
    });
  }

  /**
   * Updates an existing section
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
  ) {
    const prisma = this.getPrisma();
    const updateData: Record<string, unknown> = { ...data };

    if (data.bodyMd !== undefined || data.bodyText !== undefined) {
      updateData.bodyJsonb = {
        text: data.bodyText ?? '',
        markdown: data.bodyMd ?? null,
      };
    }

    return await prisma.section.update({
      where: { id },
      data: updateData,
    });
  }

  /**
   * Checks for duplicate content by hash
   */
  async findByContentHash(contentHash: string) {
    const prisma = this.getPrisma();
    return await prisma.section.findFirst({
      where: { contentHash },
    });
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
  private getPrisma() {
    return getPrismaClient();
  }

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
    const prisma = this.getPrisma();
    return await prisma.adrDecision.create({
      data,
    });
  }

  async updateDecision(
    id: string,
    data: Partial<{
      status: string;
      title: string;
      rationale: string;
      alternativesConsidered: string[];
      consequences: string;
    }>
  ) {
    const prisma = this.getPrisma();
    return await prisma.adrDecision.update({
      where: { id },
      data,
    });
  }

  async findDecision(id: string) {
    const prisma = this.getPrisma();
    return await prisma.adrDecision.findUnique({
      where: { id },
    });
  }
}

/**
 * Export singleton instances
 */
export const sectionService = new SectionService();
export const decisionService = new DecisionService();
