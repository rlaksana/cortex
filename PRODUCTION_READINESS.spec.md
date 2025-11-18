## Flat TODO — Production Readiness for `cortex-memory-mcp`

### 🔴 P0 — Blockers (must be done before calling it “prod-ready”)

1. **Inventory and eliminate all `@ts-nocheck` usages**

   * **Action**: Search `src` (and tests) for `@ts-nocheck` and list all files.
   * **Action**: For each file, remove `@ts-nocheck`, fix the underlying TS errors, and keep types strict.
   * **Done when**: No `@ts-nocheck` remains in the repo and `tsc` (or `vitest --runInBand --typecheck` equivalent) passes cleanly.

2. **Harden TypeScript config and enable strict CI gating**

   * **Action**: Ensure `tsconfig.*.json` used for CI has strict options (`strict`, `noImplicitAny`, `noUnusedLocals`, `noUnusedParameters`, etc.) enabled.
   * **Action**: Add a dedicated CI job `npm run type-check:ci` (or `pnpm type-check:ci`) that must pass for merge.
   * **Done when**: Any TS error fails CI; local commands and CI use the same effective type-check config.

3. **Make ESLint a non-negotiable quality gate**

   * **Action**: Run `eslint` across the whole `src` and test tree; apply `--fix` where safe.
   * **Action**: Manually fix remaining lint errors (style, imports, unused code, etc.).
   * **Action**: Configure CI to run `lint` with `--max-warnings=0`.
   * **Done when**: `pnpm lint` (or equivalent) passes locally and in CI with 0 errors and 0 warnings.

4. **Stabilize core error handling path for the MCP API**

   * **Action**: Design a standard error model (error types, error codes, HTTP status / MCP error shape).
   * **Action**: Implement a centralized Express error middleware (or equivalent) and route all controller errors through it.
   * **Action**: Replace broad `try { … } catch (e) { console.error(e) }` with domain-specific error handling that feeds into the central handler.
   * **Done when**: All public endpoints surface consistent error structure and logs include structured error context (ids, correlation, cause).

5. **Verify secure secret management and `.env` hygiene**

   * **Action**: Confirm all secrets (Qdrant keys, OpenAI keys, JWT secrets, etc.) come only from env/config providers.
   * **Action**: Ensure `.env*` files are `.gitignore`d and never committed.
   * **Action**: Validate Docker + CI pipelines read secrets from safe sources (vault, secret manager, or CI secret store).
   * **Done when**: No hardcoded secrets in repo; secrets flow is documented and reproducible across dev/stage/prod.

---

### 🟠 P1 — High Priority (stability, maintainability, scaling)

6. **Refactor oversized “god” modules into focused components**

   * **Action**: Identify all files over ~500 lines (or high cyclomatic complexity) using tooling (e.g., `ts-prune`, `madge`, `dependency-cruiser`, complexity tools).
   * **Action**: For the top offenders (e.g., heavy services/tests), define a split plan into smaller modules (e.g., `*Service`, `*Mapper`, `*Validator`, `*Repository`).
   * **Action**: Execute the refactor for 3–5 worst offenders first, keeping behavior identical with tests.
   * **Done when**: No core file exceeds agreed size/complexity thresholds, and tests still pass.

7. **Introduce and document a consistent error-handling strategy**

   * **Action**: Write a short “Error Handling Guide” (levels, expected behavior, log vs throw, when to retry vs fail fast).
   * **Action**: Implement utility helpers (e.g., `wrapAsyncRoute`, `DomainError` base class, `Result` helpers if used).
   * **Action**: Update representative modules to conform; treat them as reference implementations.
   * **Done when**: New code follows the pattern and reviewers have a concrete checklist.

8. **Analyze and reduce module coupling / circular dependencies**

   * **Action**: Run a dependency graph tool (e.g., `madge` / `dependency-cruiser`) to detect cycles and hot coupling.
   * **Action**: For each cycle, decide: extract interface, move shared code to a `core` or `domain` module, or invert dependency via DI.
   * **Done when**: No circular deps remain in core modules; critical paths have clear, one-directional dependencies.

9. **Formalize the dependency injection pattern (and avoid implicit service locator)**

   * **Action**: Decide on DI strategy (manual composition root vs simple DI container vs current “service registry” approach).
   * **Action**: Centralize object creation/wiring in a composition root (e.g., `src/bootstrap` or `src/app.ts`).
   * **Action**: Remove ad-hoc “reach into global service registry” patterns where possible; prefer explicit injection via constructors/factories.
   * **Done when**: Most services have clear, explicit dependencies and test doubles/mocks are easy to swap in.

10. **Review Qdrant client lifecycle and resource management**

    * **Action**: Document how Qdrant connections/clients are created, reused, and disposed.
    * **Action**: Ensure a single shared client per process (pooling as needed), with clean shutdown hooks.
    * **Action**: Add tests or smoke checks to assert behavior on startup/shutdown and on Qdrant failure.
    * **Done when**: No obvious connection leak risks; failure scenarios (Qdrant unavailable/slow) degrade gracefully.

11. **Standardize async/concurrency patterns**

    * **Action**: Audit critical async flows (batch inserts, dedup routines, scheduled jobs, etc.) for race conditions / unawaited promises.
    * **Action**: Introduce clear helpers (e.g., “retry with backoff”, “bounded concurrency” utilities) rather than ad-hoc loops.
    * **Done when**: No `void`-ed promises in critical paths; long-running parallel work has predictable limits and error handling.

12. **Tighten observability: logging, metrics, health checks**

    * **Action**: Define log structure (fields like `requestId`, `tenantId`, `toolName`, `operation`, `durationMs`, `status`).
    * **Action**: Ensure all inbound MCP/API calls log a structured entry at start/end with duration and key tags.
    * **Action**: Extend health checks to cover Qdrant connectivity and any external dependencies.
    * **Action**: Add basic metrics hooks (even if just counters/timers logged for now, with a path to Prometheus/OpenTelemetry).
    * **Done when**: From logs/metrics alone, you can reconstruct what happened for a bad request or incident.

13. **Codify API contract for MCP endpoints**

    * **Action**: Document request/response schemas for each MCP operation (e.g., via Zod schemas or OpenAPI/JSON schema).
    * **Action**: Ensure validators are applied consistently at the boundary (API layer) before business logic.
    * **Done when**: Every public endpoint has a single source of truth schema, enforced at runtime and testable.

14. **Performance baseline and regression protection**

    * **Action**: Identify key operations (e.g., `memory_store`, `memory_find`, batch imports, dedup workflows).
    * **Action**: Implement lightweight performance tests / scripts that measure latency/throughput against a local Qdrant.
    * **Action**: Establish target budgets (p95 latency, acceptable throughput on reference hardware).
    * **Done when**: You have baseline metrics and a simple way to detect large regressions before release.

15. **Tech debt triage for TODO/FIXME and emergency comments**

    * **Action**: Grep for `TODO`, `FIXME`, and comments like “EMERGENCY ROLLBACK”.
    * **Action**: Convert each into a tracked work item with priority and scope (or explicitly close/delete if no longer relevant).
    * **Done when**: No “mystery TODO/FIXME” remains; each one is either resolved or tracked in an issue backlog.

---

### 🟡 P2 — Medium Priority (cleanliness, design quality, future-proofing)

16. **Improve interface segregation for large MCP / domain types**

    * **Action**: Identify oversized TS interfaces/types (particularly MCP protocol contracts and configuration types).
    * **Action**: Split them into smaller, role-specific interfaces where reasonable (`ReadableConfig`, `WritableConfig`, etc.).
    * **Done when**: Core interfaces are easier to understand and more stable; consumers rarely need the entire “kitchen sink”.

17. **Consolidate and simplify configuration management**

    * **Action**: Normalize config loading (single module / small set of modules) with explicit schema validation (Zod).
    * **Action**: Remove duplicate/overlapping config keys; ensure one canonical place for each concern (logging, Qdrant, auth).
    * **Done when**: New env variables / config options have a single, obvious definition and validation path.

18. **Remove unused code and legacy features**

    * **Action**: Use tools (e.g., `ts-prune`, dead-code detection) plus manual review to find unused functions/modules.
    * **Action**: Confirm with stakeholders whether legacy features are truly unused; if yes, remove them.
    * **Done when**: No obviously dead code remains; the code surface matches the active feature set.

19. **Align documentation with actual architecture and operations**

    * **Action**: Reconcile README, architecture diagrams, and API docs with the current reality (Qdrant usage, flows, circuit breaker, etc.).
    * **Action**: Add a short “How this service is run in production” section (ports, env vars, resources, scaling model).
    * **Done when**: A new engineer can read docs and successfully run/tests/understand the service without surprises.

20. **Clarify team conventions and contribution guidelines**

    * **Action**: Define coding standards (TypeScript style, error handling patterns, DI approach, test patterns).
    * **Action**: Update `CONTRIBUTING.md` or a “Development Guide” with expectations for tests, linting, and observability for new changes.
    * **Done when**: PR reviews can point to a single source of truth for style and architectural expectations.
