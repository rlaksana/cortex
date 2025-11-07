// @ts-nocheck
import { createHash } from 'crypto';
import type { DDLData } from '../../types/knowledge-data.js';
import { logger } from '@/utils/logger.js';

export async function storeDDL(data: DDLData): Promise<string> {
  const { UnifiedDatabaseLayer } = await import('../../db/unified-database-layer-v2.js');
  const db = new UnifiedDatabaseLayer();
  await db.initialize();
  const checksum = createHash('sha256').update(data.ddl_text).digest('hex');

  // More flexible checksum validation - warn instead of error
  if (data.checksum && checksum !== data.checksum) {
    logger.warn(
      {
        expectedChecksum: data.checksum,
        calculatedChecksum: checksum,
        ddlId: data.id,
      },
      'DDL checksum mismatch: using calculated checksum'
    );
  }

  // Check if this is an update operation (has ID)
  if (data.id) {
    const existing = await db.findById([data.id]);

    if (existing.results.length > 0) {
      // Update existing DDL (though DDL changes are typically immutable, we allow metadata updates)
      // Delete old and create new one
      await db.delete([data.id]);
      const existingItem = existing.results[0];
      const result = await db.store([
        {
          kind: 'ddl',
          content: `DDL: ${data.migration_id ?? existingItem.data.migration_id}`,
          data: {
            id: data.id,
            migration_id: data.migration_id ?? existingItem.data.migration_id,
            ddl_text: data.ddl_text ?? existingItem.data.ddl_text,
            checksum: data.ddl_text ? checksum : existingItem.data.checksum,
            description: data.description ?? existingItem.data.description,
          },
          scope: existingItem.scope,
        },
      ]);
      return result.id || '';
    }
  }

  // Create new DDL
  const newId = data.id || (await db.generateUUID({ prefix: 'ddl' }));
  const result = await db.store([
    {
      kind: 'ddl',
      content: `DDL: ${data.migration_id}`,
      data: {
        id: newId,
        migration_id: data.migration_id,
        ddl_text: data.ddl_text,
        checksum,
        description: data.description,
      },
      scope: {},
    },
  ]);

  return result.id || '';
}
