import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Pool } from 'pg';
import { storeDecision, updateDecision } from '../../src/services/knowledge/decision.js';
import { ImmutabilityViolationError } from '../../src/utils/immutability.js';

/**
 * T064: ADR Immutability Test
 *
 * Validates:
 * - ADRs with status='proposed' can be updated
 * - ADRs with status='accepted' cannot be modified (immutable)
 * - Error code IMMUTABILITY_VIOLATION is returned
 * - Supersedes mechanism works as alternative to modification
 */
describe('ADR Immutability Enforcement', () => {
  let pool: Pool;

  beforeAll(() => {
    pool = new Pool({
      connectionString:
        process.env.DATABASE_URL || 'postgresql://cortex:cortex@localhost:5432/cortex_test',
    });
  });

  afterAll(async () => {
    await pool.end();
  });

  it('should allow updates to proposed ADR', async () => {
    const adrData = {
      component: 'auth',
      status: 'proposed' as const,
      title: 'Use JWT for authentication',
      rationale: 'Industry standard, stateless',
      alternatives_considered: ['Session cookies', 'OAuth only'],
    };

    const scope = { project: 'cortex-memory', branch: 'test' };
    const adrId = await storeDecision(pool, adrData, scope);

    // Update should succeed for proposed status
    await expect(
      updateDecision(pool, adrId, {
        rationale: 'Updated rationale with more details',
      })
    ).resolves.not.toThrow();

    // Cleanup
    await pool.query('DELETE FROM adr_decision WHERE id = $1', [adrId]);
  });

  it('should reject updates to accepted ADR with IMMUTABILITY_VIOLATION', async () => {
    const adrData = {
      component: 'auth',
      status: 'accepted' as const,
      title: 'Use JWT for authentication',
      rationale: 'Industry standard, stateless',
      alternatives_considered: ['Session cookies'],
    };

    const scope = { project: 'cortex-memory', branch: 'test' };
    const adrId = await storeDecision(pool, adrData, scope);

    // Attempt to update accepted ADR should fail
    await expect(
      updateDecision(pool, adrId, {
        rationale: 'Trying to change accepted ADR',
      })
    ).rejects.toThrow(ImmutabilityViolationError);

    // Verify error details
    try {
      await updateDecision(pool, adrId, { title: 'New title' });
    } catch (error) {
      expect(error).toBeInstanceOf(ImmutabilityViolationError);
      if (error instanceof ImmutabilityViolationError) {
        expect(error.errorCode).toBe('IMMUTABILITY_VIOLATION');
        expect(error.message).toContain('accepted ADR');
        expect(error.message).toContain('supersedes');
      }
    }

    // Cleanup
    await pool.query('DELETE FROM adr_decision WHERE id = $1', [adrId]);
  });

  it('should allow creating new ADR with supersedes reference', async () => {
    // Create original accepted ADR
    const originalAdr = {
      component: 'auth',
      status: 'accepted' as const,
      title: 'Use JWT',
      rationale: 'Original rationale',
      alternatives_considered: [],
    };

    const scope = { project: 'cortex-memory', branch: 'test' };
    const originalId = await storeDecision(pool, originalAdr, scope);

    // Create new ADR that supersedes the original
    const newAdr = {
      component: 'auth',
      status: 'accepted' as const,
      title: 'Use JWT with refresh tokens',
      rationale: 'Enhanced security with refresh tokens',
      alternatives_considered: ['Keep old approach'],
      supersedes: originalId,
    };

    const newId = await storeDecision(pool, newAdr, scope);

    // Verify both ADRs exist
    const result = await pool.query(
      'SELECT id, title, supersedes FROM adr_decision WHERE id = ANY($1)',
      [[originalId, newId]]
    );

    expect(result.rows).toHaveLength(2);
    const newRecord = result.rows.find((r) => r.id === newId);
    expect(newRecord?.supersedes).toBe(originalId);

    // Cleanup
    await pool.query('DELETE FROM adr_decision WHERE id = ANY($1)', [[originalId, newId]]);
  });
});
