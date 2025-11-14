// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Express type extensions for Cortex MCP
 * Extends Express Request interface to include authentication context
 */


import type { AuthContext } from './auth-types.js';

declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
      user?: {
        id: string;
        username: string;
        role: string;
      };
      apiKey?: {
        id: string;
        name: string;
        scopes: string[];
      };
      tenantId?: string;
      securityContext?: {
        tenantId?: string;
        validatedAt: number;
        warnings?: string[];
      };
      rateLimit?: {
        allowed: boolean;
        tokensAvailable?: number;
        windowCount?: number;
        error?: boolean;
      };
    }
  }
}

export {};
