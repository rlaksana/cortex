import { getPrismaClient } from '../../db/prisma.js';
import { createHash } from 'crypto';
import type { DDLData } from '../../types/knowledge-data.js';

export async function storeDDL(data: DDLData): Promise<string> {
  const prisma = getPrismaClient();
  const checksum = createHash('sha256').update(data.ddl_text).digest('hex');

  // More flexible checksum validation - warn instead of error
  if (data.checksum && checksum !== data.checksum) {
    console.warn(`DDL checksum mismatch: expected ${data.checksum}, calculated ${checksum}. Using calculated checksum.`);
  }

  // Check if this is an update operation (has ID)
  if (data.id) {
    const existing = await prisma.ddlHistory.findUnique({
      where: { id: data.id }
    });

    if (existing) {
      // Update existing DDL (though DDL changes are typically immutable, we allow metadata updates)
      const result = await prisma.ddlHistory.update({
        where: { id: data.id },
        data: {
          migration_id: data.migration_id ?? existing.migration_id,
          ddl_text: data.ddl_text ?? existing.ddl_text,
          checksum: data.ddl_text ? checksum : existing.checksum,
          description: data.description ?? existing.description
        }
      });
      return result.id;
    }
  }

  // Create new DDL
  const result = await prisma.ddlHistory.create({
    data: {
      migration_id: data.migration_id,
      ddl_text: data.ddl_text,
      checksum,
      description: data.description
    }
  });

  return result.id;
}
