/**
 * Centralized SLO Types - Unified Type System for MCP Cortex
 *
 * Consolidates and standardizes all SLO-related types across the codebase.
 * Replaces fragmented type definitions with a single source of truth.
 *
 * @version 1.0.0
 * @since 2025-11-07
 */

import { EventEmitter } from 'events';

// ============================================================================
// Socket Server Types (Unified socket handling)
// ============================================================================

export interface SocketServerLike {
  io?: {
    emit?: (channel: string, data: unknown) => void;
    on?: (event: string, callback: (data: unknown) => void) => void;
    close?: () => void;
  };
  status?: 'connected' | 'disconnected' | 'connecting';
}

// ============================================================================
// Core Enums (Consolidated from multiple definitions)
// ============================================================================

export enum BreachSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export enum EscalationLevel {
  TIER_1 = 'tier_1',
  TIER_2 = 'tier_2',
  TIER_3 = 'tier_3'
}

export enum IncidentStatus {
  OPEN = 'open',
  INVESTIGATING = 'investigating',
  RESOLVED = 'resolved',
  CLOSED = 'closed'
}

export enum AlertSeverity {
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical'
}

// ============================================================================
// Core SLO Interfaces (Simplified from slo-interfaces.ts)
// ============================================================================

export interface SLOReference {
  id: string;
  name: string;
}

export interface IncidentData {
  id: string;
  severity: BreachSeverity;
  status: IncidentStatus;
  category: string;
  createdAt: Date;
  updatedAt: Date;
  escalationLevel?: EscalationLevel;
  duration?: number;
  autoRefresh?: boolean;
  slo?: SLOReference;
}

// ============================================================================
// Dashboard Widget Types (Unified position and sizing)
// ============================================================================

export interface Position {
  x: number;
  y: number;
}

export interface DashboardWidget {
  id: string;
  type: string;
  title: string;
  width: number;  // Standardized from 'w'
  height: number; // Standardized from 'h'
  x: number;
  y: number;
  defaultPosition: Position;
  category: string;
  query?: string;
  config?: Record<string, any>;
}

export interface WidgetConfig {
  width?: number;
  height?: number;
  x?: number;
  y?: number;
  category?: string;
}

// ============================================================================
// Circuit Breaker Types (Standardized interface)
// ============================================================================

export interface CircuitBreakerStats {
  state: 'closed' | 'open' | 'half-open';
  failures: number;
  totalCalls: number;
  successRate: number;
  failureRate: number;
  averageResponseTime: number;
  sloCompliance: number; // Added to match slo-interfaces.ts
  performanceScore?: number; // Added to match slo-interfaces.ts
  lastFailureTime?: Date;
  lastStateChange?: Date;
}

// ============================================================================
// Observability Service Types
// ============================================================================

export interface MetricsData {
  timestamp: number;
  value: number;
  labels?: Record<string, string>;
}


export class ObservabilityService extends EventEmitter {
  protected socketServer: SocketServerLike | null = null;

  initSocket(server: SocketServerLike): void {
    this.socketServer = server;
  }

  emitMetrics(data: MetricsData): void {
    const io = this.socketServer?.io;
    if (!io) {
      console.warn('Socket server not initialized');
      return;
    }
    io.emit?.('metrics', data);
  }

  createWidget(config: WidgetConfig = {}): DashboardWidget {
    const width = config.width ?? 6;
    const height = config.height ?? 4;
    const x = config.x ?? 0;
    const y = config.y ?? 0;
    const category = config.category ?? 'monitoring';

    return {
      id: `widget_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      type: 'default',
      title: 'Widget',
      width,
      height,
      x,
      y,
      category,
      defaultPosition: { x: 0, y: 0 }
    };
  }
}

// ============================================================================
// Migration Support
// ============================================================================

export interface LegacyDashboardWidget {
  w: number;
  h: number;
  x?: number;
  y?: number;
  type?: string;
  title?: string;
}

export type ModernDashboardWidget = DashboardWidget;

export function adaptWidget(legacy: LegacyDashboardWidget): ModernDashboardWidget {
  return {
    id: `migrated_${Date.now()}_${Math.random().toString(36).slice(2)}`,
    type: legacy.type ?? 'default',
    title: legacy.title ?? 'Migrated Widget',
    width: legacy.w,
    height: legacy.h,
    x: legacy.x ?? 0,
    y: legacy.y ?? 0,
    defaultPosition: { x: legacy.x ?? 0, y: legacy.y ?? 0 },
    category: 'migrated'
  };
}

// ============================================================================
// Re-exports for Backward Compatibility
// ============================================================================

// Re-export commonly used types from slo-interfaces.ts for compatibility
export type {
  SLI,
  SLO,
  SLA
} from './slo-interfaces';

// Provide access to legacy types during migration
export * from './unified-health-interfaces';