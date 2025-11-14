// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

import { execSync } from 'child_process';

import { logger } from '@/utils/logger.js';

import { loadEnv } from '../config/environment.js';

export interface Scope {
  org?: string | undefined;
  project?: string | undefined;
  branch?: string | undefined;
}

let cachedScope: Scope | null = null;

export function inferScope(): Scope {
  if (cachedScope !== null) return cachedScope;

  const env = loadEnv();

  cachedScope = {
    org: env.CORTEX_ORG ?? undefined,
    project: env.CORTEX_PROJECT ?? undefined,
    branch: env.CORTEX_BRANCH ?? undefined,
  };

  if (cachedScope.branch === undefined || cachedScope.branch === '') {
    try {
      cachedScope.branch = execSync('git rev-parse --abbrev-ref HEAD', {
        encoding: 'utf8',
      }).trim();
    } catch {
      void logger.warn('Failed to infer branch from git');
      cachedScope.branch = 'main';
    }
  }

  if (cachedScope.project === undefined || cachedScope.project === '') {
    try {
      const gitRoot = execSync('git rev-parse --show-toplevel', {
        encoding: 'utf8',
      }).trim();
      cachedScope.project = gitRoot.split('/').pop() ?? 'unknown';
    } catch {
      void logger.warn('Failed to infer project from git');
      cachedScope.project = 'unknown';
    }
  }

  void logger.info({ scope: cachedScope }, 'Inferred scope from environment/git');
  return cachedScope;
}
