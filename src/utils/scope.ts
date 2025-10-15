import { execSync } from 'child_process';
import { loadEnv } from '../config/env.js';
import { logger } from './logger.js';

export interface Scope {
  org?: string;
  project?: string;
  branch?: string;
}

let cachedScope: Scope | null = null;

export function inferScope(): Scope {
  if (cachedScope) return cachedScope;

  const env = loadEnv();

  cachedScope = {
    org: env.CORTEX_ORG,
    project: env.CORTEX_PROJECT,
    branch: env.CORTEX_BRANCH,
  };

  if (!cachedScope.branch) {
    try {
      cachedScope.branch = execSync('git rev-parse --abbrev-ref HEAD', {
        encoding: 'utf8',
      }).trim();
    } catch (err) {
      logger.warn('Failed to infer branch from git');
    }
  }

  if (!cachedScope.project) {
    try {
      const gitRoot = execSync('git rev-parse --show-toplevel', {
        encoding: 'utf8',
      }).trim();
      cachedScope.project = gitRoot.split('/').pop() || 'unknown';
    } catch (err) {
      logger.warn('Failed to infer project from git');
    }
  }

  logger.info({ scope: cachedScope }, 'Inferred scope from environment/git');
  return cachedScope;
}
