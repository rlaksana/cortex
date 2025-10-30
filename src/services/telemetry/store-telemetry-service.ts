import { KnowledgeItem } from '../../types/core-interfaces';

export interface TruncationMetrics {
  total_stores: number;
  truncated_stores: number;
  truncated_ratio: number;
  avg_truncated_len: number;
}

export interface PerKindMetrics {
  [kind: string]: {
    stored: number;
    skipped_dedupe: number;
  };
}

export interface DeduplicationMetrics {
  dedupe_hits: number;
  avg_similarity_of_hits: number;
  top_offenders: { [source: string]: number };
}

export interface EmbeddingMetrics {
  embedding_calls: number;
  embedding_failures: number;
  stored_without_vector: number;
  embedding_success_rate: number;
}

export interface LanguageMetrics {
  total_stores: number;
  lang_distribution: {
    en: number;
    id: number;
    mixed: number;
    unknown: number;
  };
}

export class StoreTelemetryService {
  private truncationData: {
    total: number;
    truncated: number;
    totalTruncatedLength: number;
  } = {
    total: 0,
    truncated: 0,
    totalTruncatedLength: 0,
  };

  private perKindData: { [kind: string]: { stored: number; skipped_dedupe: number } } = {};

  private deduplicationData: {
    hits: number;
    totalSimilarity: number;
    offenders: { [source: string]: number };
  } = {
    hits: 0,
    totalSimilarity: 0,
    offenders: {},
  };

  private embeddingData: {
    calls: number;
    failures: number;
    storedWithoutVector: number;
  } = {
    calls: 0,
    failures: 0,
    storedWithoutVector: 0,
  };

  private languageData: {
    total: number;
    distribution: { en: number; id: number; mixed: number; unknown: number };
  } = {
    total: 0,
    distribution: { en: 0, id: 0, mixed: 0, unknown: 0 },
  };

  async recordStoreAttempt(
    _item: KnowledgeItem,
    originalLength: number,
    finalLength: number
  ): Promise<void> {
    this.truncationData.total++;

    if (originalLength > finalLength) {
      this.truncationData.truncated++;
      this.truncationData.totalTruncatedLength += finalLength;
    }
  }

  async recordSuccessfulStore(item: KnowledgeItem): Promise<void> {
    if (!this.perKindData[item.kind]) {
      this.perKindData[item.kind] = { stored: 0, skipped_dedupe: 0 };
    }
    this.perKindData[item.kind].stored++;
  }

  async recordSkippedDedupe(kind: string): Promise<void> {
    if (!this.perKindData[kind]) {
      this.perKindData[kind] = { stored: 0, skipped_dedupe: 0 };
    }
    this.perKindData[kind].skipped_dedupe++;
  }

  async recordDedupeHit(similarityScore: number, source: string): Promise<void> {
    this.deduplicationData.hits++;
    this.deduplicationData.totalSimilarity += similarityScore;

    if (!this.deduplicationData.offenders[source]) {
      this.deduplicationData.offenders[source] = 0;
    }
    this.deduplicationData.offenders[source]++;
  }

  async recordEmbeddingAttempt(success: boolean): Promise<void> {
    this.embeddingData.calls++;
    if (!success) {
      this.embeddingData.failures++;
    }
  }

  async recordStoreWithoutVector(): Promise<void> {
    this.embeddingData.storedWithoutVector++;
  }

  async recordLanguageDetection(detectedLang: 'en' | 'id' | 'mixed' | 'unknown'): Promise<void> {
    this.languageData.total++;
    this.languageData.distribution[detectedLang]++;
  }

  getTruncationMetrics(): TruncationMetrics {
    const truncated_ratio =
      this.truncationData.total > 0 ? this.truncationData.truncated / this.truncationData.total : 0;

    const avg_truncated_len =
      this.truncationData.truncated > 0
        ? this.truncationData.totalTruncatedLength / this.truncationData.truncated
        : 0;

    return {
      total_stores: this.truncationData.total,
      truncated_stores: this.truncationData.truncated,
      truncated_ratio,
      avg_truncated_len,
    };
  }

  getPerKindMetrics(): PerKindMetrics {
    return { ...this.perKindData };
  }

  getDeduplicationMetrics(): DeduplicationMetrics {
    const avg_similarity_of_hits =
      this.deduplicationData.hits > 0
        ? this.deduplicationData.totalSimilarity / this.deduplicationData.hits
        : 0;

    return {
      dedupe_hits: this.deduplicationData.hits,
      avg_similarity_of_hits,
      top_offenders: { ...this.deduplicationData.offenders },
    };
  }

  getEmbeddingMetrics(): EmbeddingMetrics {
    const embedding_success_rate =
      this.embeddingData.calls > 0
        ? (this.embeddingData.calls - this.embeddingData.failures) / this.embeddingData.calls
        : 0;

    return {
      embedding_calls: this.embeddingData.calls,
      embedding_failures: this.embeddingData.failures,
      stored_without_vector: this.embeddingData.storedWithoutVector,
      embedding_success_rate,
    };
  }

  getLanguageMetrics(): LanguageMetrics {
    return {
      total_stores: this.languageData.total,
      lang_distribution: { ...this.languageData.distribution },
    };
  }

  reset(): void {
    this.truncationData = { total: 0, truncated: 0, totalTruncatedLength: 0 };
    this.perKindData = {};
    this.deduplicationData = { hits: 0, totalSimilarity: 0, offenders: {} };
    this.embeddingData = { calls: 0, failures: 0, storedWithoutVector: 0 };
    this.languageData = { total: 0, distribution: { en: 0, id: 0, mixed: 0, unknown: 0 } };
  }
}
