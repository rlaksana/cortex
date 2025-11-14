// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck


/**
 * Metadata Flagging Service
 * Handles flagging items with contradiction metadata and managing pointers
 */

import {
  type ContradictionFlag,
  type ContradictionPointer,
  type ContradictionResult,
  type KnowledgeItem,
} from '../../types/contradiction-detector.interface';

export class MetadataFlaggingService {
  private flags: Map<string, ContradictionFlag[]> = new Map();
  private pointers: Map<string, ContradictionPointer[]> = new Map();

  /**
   * Flags items with contradiction metadata
   */
  async flagContradictions(contradictions: ContradictionResult[]): Promise<ContradictionFlag[]> {
    const flags: ContradictionFlag[] = [];

    for (const contradiction of contradictions) {
      // Flag primary item
      const primaryFlag = this.createFlag(contradiction.primary_item_id, [contradiction.id]);
      flags.push(primaryFlag);
      this.addFlagToMap(contradiction.primary_item_id, primaryFlag);

      // Flag conflicting items
      for (const conflictingItemId of contradiction.conflicting_item_ids) {
        const conflictFlag = this.createFlag(conflictingItemId, [contradiction.id]);
        flags.push(conflictFlag);
        this.addFlagToMap(conflictingItemId, conflictFlag);
      }

      // Create pointers between items
      this.createPointers(contradiction);
    }

    return flags;
  }

  private createFlag(itemId: string, contradictionIds: string[]): ContradictionFlag {
    return {
      item_id: itemId,
      flag_type: 'possible_contradiction',
      contradiction_ids: contradictionIds,
      flagged_at: new Date(),
      review_status: 'pending',
    };
  }

  private addFlagToMap(itemId: string, flag: ContradictionFlag): void {
    if (!this.flags.has(itemId)) {
      this.flags.set(itemId, []);
    }
    this.flags.get(itemId)!.push(flag);
  }

  private createPointers(contradiction: ContradictionResult): void {
    const primaryId = contradiction.primary_item_id;
    const conflictIds = contradiction.conflicting_item_ids;

    // Create pointers from primary to conflicting items
    for (const conflictId of conflictIds) {
      this.createPointer(primaryId, conflictId, 'contradicts', contradiction.confidence_score, {
        contradiction_id: contradiction.id,
        contradiction_type: contradiction.contradiction_type,
        severity: contradiction.severity,
        created_by: 'detection_service',
      });
    }

    // Create reverse pointers from conflicting to primary
    for (const conflictId of conflictIds) {
      this.createPointer(conflictId, primaryId, 'conflicts_with', contradiction.confidence_score, {
        contradiction_id: contradiction.id,
        contradiction_type: contradiction.contradiction_type,
        severity: contradiction.severity,
        created_by: 'detection_service',
      });
    }
  }

  private createPointer(
    sourceId: string,
    targetId: string,
    type: 'contradicts' | 'conflicts_with' | 'supersedes' | 'relates_to',
    strength: number,
    metadata: Record<string, unknown>
  ): void {
    const pointer: ContradictionPointer = {
      source_id: sourceId,
      target_id: targetId,
      pointer_type: type,
      strength,
      created_at: new Date(),
      verified: false,
      metadata,
    };

    this.addPointerToMap(sourceId, pointer);
  }

  private addPointerToMap(sourceId: string, pointer: ContradictionPointer): void {
    if (!this.pointers.has(sourceId)) {
      this.pointers.set(sourceId, []);
    }
    this.pointers.get(sourceId)!.push(pointer);
  }

  /**
   * Updates item metadata with contradiction flags
   */
  async updateItemMetadata(item: KnowledgeItem): Promise<KnowledgeItem> {
    const flags = this.flags.get(item.id || '') || [];

    if (flags.length === 0) {
      return item;
    }

    // Ensure metadata exists
    const metadata = item.metadata ? { ...item.metadata } : {} as Record<string, unknown>;

    // Add contradiction flags
    const contradictionIds = new Set<string>();
    flags.forEach((flag) => {
      flag.contradiction_ids.forEach((id) => contradictionIds.add(id));
    });

    if (contradictionIds.size > 0 && !(metadata.flags as string[])?.includes('possible_contradiction')) {
      metadata.flags = [...((metadata.flags as string[]) || []), 'possible_contradiction'];
      metadata.contradiction_ids = Array.from(contradictionIds);
      metadata.contradiction_flagged_at = new Date().toISOString();
      metadata.contradiction_count = contradictionIds.size;
    }

    // Add pointer metadata
    const pointers = this.pointers.get(item.id || '') || [];
    if (pointers.length > 0) {
      metadata.contradiction_pointers = pointers.map((p) => ({
        target_id: p.target_id,
        pointer_type: p.pointer_type,
        strength: p.strength,
        verified: p.verified,
      }));
    }

    return {
      ...item,
      metadata,
    };
  }

  /**
   * Gets all flags for an item
   */
  getFlagsForItem(itemId: string): ContradictionFlag[] {
    return this.flags.get(itemId) || [];
  }

  /**
   * Gets all pointers from an item
   */
  getPointersFromItem(itemId: string): ContradictionPointer[] {
    return this.pointers.get(itemId) || [];
  }

  /**
   * Updates flag review status
   */
  async updateFlagReviewStatus(
    itemId: string,
    flagId: string,
    status: ContradictionFlag['review_status'],
    reviewerId?: string,
    notes?: string
  ): Promise<void> {
    const flags = this.flags.get(itemId) || [];
    const flag = flags.find((f) => f.contradiction_ids.includes(flagId));

    if (flag) {
      flag.review_status = status;
      flag.last_reviewed = new Date();
      flag.reviewer_id = reviewerId;
      flag.notes = notes;
    }
  }

  /**
   * Marks pointers as verified
   */
  async verifyPointers(itemId: string, pointerIds: string[]): Promise<void> {
    const pointers = this.pointers.get(itemId) || [];

    pointers.forEach((pointer) => {
      if (
        pointerIds.includes(`${pointer.source_id}-${pointer.target_id}-${pointer.pointer_type}`)
      ) {
        pointer.verified = true;
      }
    });
  }

  /**
   * Removes resolved contradictions
   */
  async removeResolvedContradictions(contradictionIds: string[]): Promise<void> {
    // Remove flags
    for (const [itemId, flags] of this.flags.entries()) {
      const updatedFlags = flags.filter(
        (flag) => !flag.contradiction_ids.some((id) => contradictionIds.includes(id))
      );

      if (updatedFlags.length === 0) {
        this.flags.delete(itemId);
      } else {
        this.flags.set(itemId, updatedFlags);
      }
    }

    // Remove pointers
    for (const [itemId, pointers] of this.pointers.entries()) {
      const updatedPointers = pointers.filter(
        (pointer) =>
          !(pointer.metadata as Record<string, unknown>).contradiction_id ||
          !contradictionIds.includes((pointer.metadata as Record<string, unknown>).contradiction_id as string)
      );

      if (updatedPointers.length === 0) {
        this.pointers.delete(itemId);
      } else {
        this.pointers.set(itemId, updatedPointers);
      }
    }
  }

  /**
   * Gets contradiction summary for an item
   */
  getContradictionSummary(itemId: string): {
    flag_count: number;
    pointer_count: number;
    pending_review_count: number;
    verified_pointer_count: number;
    total_strength: number;
    average_strength: number;
  } {
    const flags = this.getFlagsForItem(itemId);
    const pointers = this.getPointersFromItem(itemId);

    const pendingReview = flags.filter((f) => f.review_status === 'pending').length;
    const verifiedPointers = pointers.filter((p) => p.verified).length;
    const totalStrength = pointers.reduce((sum, p) => sum + p.strength, 0);
    const averageStrength = pointers.length > 0 ? totalStrength / pointers.length : 0;

    return {
      flag_count: flags.length,
      pointer_count: pointers.length,
      pending_review_count: pendingReview,
      verified_pointer_count: verifiedPointers,
      total_strength: totalStrength,
      average_strength: averageStrength,
    };
  }

  /**
   * Gets all items with contradiction flags
   */
  getItemsWithContradictionFlags(): string[] {
    return Array.from(this.flags.keys());
  }

  /**
   * Gets high-priority contradictions (high severity or high confidence)
   */
  getHighPriorityContradictions(): Array<{
    itemId: string;
    flags: ContradictionFlag[];
    pointers: ContradictionPointer[];
    priority: 'critical' | 'high' | 'medium' | 'low';
  }> {
    const highPriorityItems: Array<{
      itemId: string;
      flags: ContradictionFlag[];
      pointers: ContradictionPointer[];
      priority: 'critical' | 'high' | 'medium' | 'low';
    }> = [];

    for (const [itemId] of this.flags.entries()) {
      const flags = this.getFlagsForItem(itemId);
      const pointers = this.getPointersFromItem(itemId);

      // Calculate priority based on severity and strength
      const maxStrength = Math.max(...pointers.map((p) => p.strength), 0);
      const pendingCount = flags.filter((f) => f.review_status === 'pending').length;

      let priority: 'critical' | 'high' | 'medium' | 'low' = 'low';

      if (maxStrength >= 0.9 || pendingCount >= 5) {
        priority = 'critical';
      } else if (maxStrength >= 0.8 || pendingCount >= 3) {
        priority = 'high';
      } else if (maxStrength >= 0.6 || pendingCount >= 2) {
        priority = 'medium';
      }

      if (priority !== 'low') {
        highPriorityItems.push({
          itemId,
          flags,
          pointers,
          priority,
        });
      }
    }

    return highPriorityItems;
  }

  /**
   * Exports contradiction data for analysis
   */
  exportContradictionData(): {
    flags: Array<{ item_id: string; flag: ContradictionFlag }>;
    pointers: Array<{ source_id: string; pointer: ContradictionPointer }>;
    statistics: {
      total_flags: number;
      total_pointers: number;
      flagged_items: number;
      pending_reviews: number;
      verified_pointers: number;
      average_pointer_strength: number;
    };
  } {
    const flags: Array<{ item_id: string; flag: ContradictionFlag }> = [];
    const pointers: Array<{ source_id: string; pointer: ContradictionPointer }> = [];

    // Collect all flags
    for (const [itemId, itemFlags] of this.flags.entries()) {
      itemFlags.forEach((flag) => {
        flags.push({ item_id: itemId, flag });
      });
    }

    // Collect all pointers
    for (const [sourceId, sourcePointers] of this.pointers.entries()) {
      sourcePointers.forEach((pointer) => {
        pointers.push({ source_id: sourceId, pointer });
      });
    }

    // Calculate statistics
    const pendingReviews = flags
      .flatMap((f) => f.flag)
      .filter((f) => f.review_status === 'pending').length;
    const verifiedPointers = pointers.flatMap((p) => p.pointer).filter((p) => p.verified).length;
    const totalStrength = pointers.reduce((sum, p) => sum + p.pointer.strength, 0);
    const avgStrength = pointers.length > 0 ? totalStrength / pointers.length : 0;

    return {
      flags,
      pointers,
      statistics: {
        total_flags: flags.length,
        total_pointers: pointers.length,
        flagged_items: this.flags.size,
        pending_reviews: pendingReviews,
        verified_pointers: verifiedPointers,
        average_pointer_strength: avgStrength,
      },
    };
  }

  /**
   * Clears all flags and pointers (for testing or reset)
   */
  clearAll(): void {
    this.flags.clear();
    this.pointers.clear();
  }
}
