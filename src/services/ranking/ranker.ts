
export function computeFinalScore(hit: {
  fts_score: number;
  updated_at: string;
  scope_proximity: number;
  citation_count?: number;
}): number {
  const recencyBoost = computeRecencyBoost(hit.updated_at);
  const citationScore = Math.min(1.0, Math.log10(1 + (hit.citation_count ?? 0)) / 2);

  return 0.4 * hit.fts_score + 0.3 * recencyBoost + 0.2 * hit.scope_proximity + 0.1 * citationScore;
}

function computeRecencyBoost(updated_at: string): number {
  const daysSince = (Date.now() - new Date(updated_at).getTime()) / (1000 * 60 * 60 * 24);
  return Math.max(0, 1.0 - Math.log10(1 + daysSince) / Math.log10(180));
}
