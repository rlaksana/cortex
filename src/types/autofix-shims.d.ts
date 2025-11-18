/* AUTO-GENERATED: relax overly-strict or missing types for build stability */
declare global {
  // GC typing used in performance-harness
  type GCFunction = () => void | Promise<void>;
  // Some modules assume global.gc exists

  var gc: GCFunction | undefined;

  // Fallbacks used by orchestrators / services

  var retryBudgetIntegration: unknown;
}

// Loose unions to unblock string literals seen in code
type LooseString = string;

export {};
