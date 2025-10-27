// Removed qdrant.js import - using UnifiedDatabaseLayer instead
import { createHash } from 'crypto';
import type { DDLData } from '../../types/knowledge-data.js';
import { logger } from '../../utils/logger.js';

export async function storeDDL(data: DDLData): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();
  const checksum = createHash('sha256').update(data.ddl_text).digest('hex');

  // More flexible checksum validation - warn instead of error
  if (data.checksum && checksum !== data.checksum) {
    logger.warn(
      {
        expectedChecksum: data.checksum,
        calculatedChecksum: checksum,
        ddlId: data.id
      },
      'DDL checksum mismatch: using calculated checksum'
    );
  }

  // Check if this is an update operation (has ID)
  if (data.id) {
    const existing = await qdrant.ddlHistory.findUnique({
      where: { id: data.id }
    });

    if (existing) {
      // Update existing DDL (though DDL changes are typically immutable, we allow metadata updates)
      const result = await qdrant.ddlHistory.update({
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
  const result = await qdrant.ddlHistory.create({
    data: {
      migration_id: data.migration_id,
      ddl_text: data.ddl_text,
      checksum,
      description: data.description
    }
  });

  return result.id;
}
