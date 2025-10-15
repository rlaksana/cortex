export function buildScopeFilter(scope?: Record<string, string>): { where: string; params: any[] } {
  if (!scope) return { where: '', params: [] };

  const conditions: string[] = [];
  const params: any[] = [];
  let paramIndex = 1;

  if (scope.org) {
    conditions.push(`tags->>'org' = $${paramIndex++}`);
    params.push(scope.org);
  }
  if (scope.project) {
    conditions.push(`tags->>'project' = $${paramIndex++}`);
    params.push(scope.project);
  }
  if (scope.branch) {
    conditions.push(`tags->>'branch' = $${paramIndex++}`);
    params.push(scope.branch);
  }

  return {
    where: conditions.length > 0 ? `AND ${conditions.join(' AND ')}` : '',
    params,
  };
}

export function computeScopeProximity(hitScope: any, queryScope: any): number {
  if (!hitScope || !queryScope) return 0.2;

  if (hitScope.branch === queryScope.branch && hitScope.project === queryScope.project) return 1.0;
  if (hitScope.project === queryScope.project) return 0.5;
  return 0.2;
}
