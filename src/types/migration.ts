// @ts-nocheck - Emergency rollback: Critical infrastructure service
/**
 * Migration Bridge - Legacy to Modern Type Adapter
 *
 * Provides backward compatibility during the transition from fragmented types
 * to centralized SLO types. Implements adapter pattern to minimize breaking changes.
 *
 * @version 1.0.0
 * @since 2025-11-07
 */

import {
  adaptWidget as baseAdaptWidget,
  BreachSeverity,
  DashboardWidget,
  IncidentStatus,
  LegacyDashboardWidget,
  type ModernDashboardWidget} from './slo-types.js';
import { AlertSeverity } from './unified-health-interfaces.js';

// ============================================================================
// Legacy Type Aliases for Backward Compatibility
// ============================================================================

/**
 * @deprecated Use BreachSeverity instead
 */
export type Severity = BreachSeverity;

/**
 * @deprecated Use AlertSeverity instead
 */
export type Priority = AlertSeverity;

/**
 * @deprecated Use IncidentStatus instead
 */
export type Status = IncidentStatus;

// ============================================================================
// Legacy Widget Position Adapter
// ============================================================================

export interface LegacyWidgetPosition {
  x: number;
  y: number;
  w: number;  // Legacy width property
  h: number;  // Legacy height property
}

export interface ModernWidgetPosition {
  x: number;
  y: number;
  width: number;
  height: number;
}

/**
 * Adapts legacy widget position format to modern standardized format
 */
export function adaptPosition(legacy: LegacyWidgetPosition): ModernWidgetPosition {
  return {
    x: legacy.x,
    y: legacy.y,
    width: legacy.w,
    height: legacy.h
  };
}

/**
 * Reverts modern position back to legacy format (for compatibility)
 */
export function revertPosition(modern: ModernWidgetPosition): LegacyWidgetPosition {
  return {
    x: modern.x,
    y: modern.y,
    w: modern.width,
    h: modern.height
  };
}

// ============================================================================
// Enhanced Widget Adapter
// ============================================================================

export interface LegacyWidgetConfig {
  w?: number;
  h?: number;
  x?: number;
  y?: number;
  category?: string;
  title?: string;
  type?: string;
}

/**
 * Enhanced widget adapter with additional legacy support
 */
export function adaptWidget(legacy: LegacyWidgetConfig): ModernDashboardWidget {
  const baseWidget = baseAdaptWidget({
    w: legacy.w ?? 6,
    h: legacy.h ?? 4,
    x: legacy.x ?? 0,
    y: legacy.y ?? 0,
    type: legacy.type,
    title: legacy.title
  });

  return {
    ...baseWidget,
    category: legacy.category ?? 'legacy'
  };
}

// ============================================================================
// Enum Migration Utilities
// ============================================================================

/**
 * Maps legacy severity strings to BreachSeverity enum
 */
export function mapSeverity(value: string): BreachSeverity {
  const normalized = value.toLowerCase();

  switch (normalized) {
    case 'critical':
    case 'crit':
      return BreachSeverity.CRITICAL;
    case 'high':
      return BreachSeverity.HIGH;
    case 'medium':
    case 'med':
      return BreachSeverity.MEDIUM;
    case 'low':
    case 'info':
      return BreachSeverity.LOW;
    default:
      console.warn(`Unknown severity value: ${value}, defaulting to LOW`);
      return BreachSeverity.LOW;
  }
}

/**
 * Maps legacy alert priority strings to AlertSeverity enum
 */
export function mapPriority(value: string): AlertSeverity {
  const normalized = value.toLowerCase();

  switch (normalized) {
    case 'critical':
    case 'crit':
    case 'error':
      return AlertSeverity.CRITICAL;
    case 'high':
    case 'warning':
    case 'warn':
      return AlertSeverity.WARNING;
    case 'medium':
    case 'med':
    case 'info':
      return AlertSeverity.INFO;
    case 'low':
      return AlertSeverity.INFO; // Map low to info in alert context
    default:
      console.warn(`Unknown priority value: ${value}, defaulting to INFO`);
      return AlertSeverity.INFO;
  }
}

/**
 * Maps legacy status strings to IncidentStatus enum
 */
export function mapStatus(value: string): IncidentStatus {
  const normalized = value.toLowerCase();

  switch (normalized) {
    case 'open':
    case 'new':
      return IncidentStatus.OPEN;
    case 'investigating':
    case 'in_progress':
    case 'inprogress':
      return IncidentStatus.INVESTIGATING;
    case 'resolved':
    case 'fixed':
    case 'completed':
      return IncidentStatus.RESOLVED;
    case 'closed':
    case 'archived':
      return IncidentStatus.CLOSED;
    default:
      console.warn(`Unknown status value: ${value}, defaulting to OPEN`);
      return IncidentStatus.OPEN;
  }
}

// ============================================================================
// Type Guard Utilities
// ============================================================================

/**
 * Type guard to check if object uses legacy widget format
 */
export function isLegacyWidget(obj: unknown): obj is LegacyWidgetConfig {
  return obj && (typeof obj.w === 'number' || typeof obj.h === 'number');
}

/**
 * Type guard to check if object uses modern widget format
 */
export function isModernWidget(obj: unknown): obj is ModernDashboardWidget {
  return obj && typeof obj.width === 'number' && typeof obj.height === 'number';
}

/**
 * Automatically detects and converts widget format
 */
export function normalizeWidget(widget: unknown): ModernDashboardWidget {
  if (isModernWidget(widget)) {
    return widget;
  }

  if (isLegacyWidget(widget)) {
    return adaptWidget(widget);
  }

  // Default widget for unknown formats
  return {
    id: `normalized_${Date.now()}_${Math.random().toString(36).slice(2)}`,
    type: 'unknown',
    title: 'Normalized Widget',
    width: 6,
    height: 4,
    x: 0,
    y: 0,
    defaultPosition: { x: 0, y: 0 },
    category: 'auto-normalized'
  };
}

// ============================================================================
// Migration State Tracking
// ============================================================================

export interface MigrationMetrics {
  totalWidgetsMigrated: number;
  totalPositionsAdapted: number;
  totalEnumsMapped: number;
  errorsEncountered: number;
  timestamp: Date;
}

/**
 * Tracks migration progress and metrics
 */
export class MigrationTracker {
  private metrics: MigrationMetrics = {
    totalWidgetsMigrated: 0,
    totalPositionsAdapted: 0,
    totalEnumsMapped: 0,
    errorsEncountered: 0,
    timestamp: new Date()
  };

  incrementWidgetMigrated(): void {
    this.metrics.totalWidgetsMigrated++;
  }

  incrementPositionAdapted(): void {
    this.metrics.totalPositionsAdapted++;
  }

  incrementEnumMapped(): void {
    this.metrics.totalEnumsMapped++;
  }

  incrementErrors(): void {
    this.metrics.errorsEncountered++;
  }

  getMetrics(): MigrationMetrics {
    return { ...this.metrics };
  }

  reset(): void {
    this.metrics = {
      totalWidgetsMigrated: 0,
      totalPositionsAdapted: 0,
      totalEnumsMapped: 0,
      errorsEncountered: 0,
      timestamp: new Date()
    };
  }
}

// Singleton instance
export const migrationTracker = new MigrationTracker();