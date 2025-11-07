/**
 * SLO Dashboard Service
 *
 * Real-time dashboard service for visualizing SLO status, compliance, and trends
 * with live updates, customizable widgets, and comprehensive alerting integration.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'events';
// import { Server } from 'socket.io'; // Optional dependency - install if needed
import { createServer } from 'http';
import express from 'express';
import path from 'path';
import {
  SLODashboard,
  DashboardWidget,
  WidgetType,
  SLOEvaluation,
  SLOAlert,
  SLO,
  SLI,
  SLODashboard as DashboardConfig,
  TimeRange,
  DashboardFilter,
  FilterType,
  ChartType,
  Annotation,
  SLOEvaluationStatus,
  AlertSeverity,
  SLOAlertType,
} from '../types/slo-interfaces.js';
import { SLOService } from '../services/slo-service.js';

/**
 * Real-time SLO Dashboard Service
 */
export class SLODashboardService extends EventEmitter {
  private app: express.Application;
  private server: any;
  private io: Server;
  private sloService: SLOService;
  private dashboards: Map<string, SLODashboard> = new Map();
  private connectedClients: Map<string, any> = new Map();
  private isStarted = false;

  constructor(sloService: SLOService, config: { port?: number; host?: string } = {}) {
    super();
    this.sloService = sloService;
    this.app = express();
    this.server = createServer(this.app);
    this.io = new Server(this.server, {
      cors: {
        origin: "*",
        methods: ["GET", "POST"]
      }
    });

    this.setupExpress();
    this.setupSocketIO();
    this.setupSLOEventHandlers();
  }

  /**
   * Start the dashboard service
   */
  async start(): Promise<void> {
    if (this.isStarted) {
      this.emit('warning', 'SLO Dashboard Service is already started');
      return;
    }

    try {
      const port = process.env.SLO_DASHBOARD_PORT || 3001;
      const host = process.env.SLO_DASHBOARD_HOST || '0.0.0.0';

      this.server.listen(port, host, () => {
        this.isStarted = true;
        this.emit('started', `SLO Dashboard Service started on ${host}:${port}`);
        console.log(`🎯 SLO Dashboard Service listening on http://${host}:${port}`);
      });

    } catch (error) {
      this.emit('error', `Failed to start SLO Dashboard Service: ${error}`);
      throw error;
    }
  }

  /**
   * Stop the dashboard service
   */
  async stop(): Promise<void> {
    if (!this.isStarted) {
      this.emit('warning', 'SLO Dashboard Service is not started');
      return;
    }

    try {
      this.io.close();
      this.server.close();
      this.isStarted = false;
      this.emit('stopped', 'SLO Dashboard Service stopped successfully');
    } catch (error) {
      this.emit('error', `Error stopping SLO Dashboard Service: ${error}`);
      throw error;
    }
  }

  // ============================================================================
  // Dashboard Management
  // ============================================================================

  /**
   * Create a new dashboard
   */
  async createDashboard(config: Partial<DashboardConfig>): Promise<SLODashboard> {
    const dashboard: SLODashboard = {
      id: this.generateId(),
      name: config.name || 'New SLO Dashboard',
      description: config.description || '',
      owner: config.owner || 'system',
      layout: config.layout || {
        type: 'grid',
        columns: 12,
        rowHeight: 60,
        margin: 10,
        padding: 10,
      },
      widgets: config.widgets || [],
      filters: config.filters || [],
      refreshInterval: config.refreshInterval || 30000,
      autoRefresh: config.autoRefresh !== false,
      sharing: config.sharing || {
        enabled: false,
        public: false,
      },
      metadata: {
        createdAt: new Date(),
        updatedAt: new Date(),
        version: 1,
      },
    };

    this.dashboards.set(dashboard.id, dashboard);
    this.emit('dashboard:created', dashboard);
    return dashboard;
  }

  /**
   * Get a dashboard by ID
   */
  getDashboard(id: string): SLODashboard | undefined {
    return this.dashboards.get(id);
  }

  /**
   * Get all dashboards
   */
  getAllDashboards(): SLODashboard[] {
    return Array.from(this.dashboards.values());
  }

  /**
   * Update a dashboard
   */
  async updateDashboard(id: string, updates: Partial<DashboardConfig>): Promise<SLODashboard> {
    const existing = this.dashboards.get(id);
    if (!existing) {
      throw new Error(`Dashboard ${id} not found`);
    }

    const updated: SLODashboard = {
      ...existing,
      ...updates,
      id, // Ensure ID doesn't change
      metadata: {
        ...existing.metadata,
        ...updates.metadata,
        updatedAt: new Date(),
        version: existing.metadata.version + 1,
      },
    };

    this.dashboards.set(id, updated);
    this.emit('dashboard:updated', updated);

    // Notify connected clients
    this.broadcastToDashboard(id, 'dashboard:updated', updated);

    return updated;
  }

  /**
   * Delete a dashboard
   */
  async deleteDashboard(id: string): Promise<boolean> {
    const deleted = this.dashboards.delete(id);
    if (deleted) {
      this.emit('dashboard:deleted', id);
      this.broadcastToDashboard(id, 'dashboard:deleted', { id });
    }
    return deleted;
  }

  // ============================================================================
  // Widget Management
  // ============================================================================

  /**
   * Add a widget to a dashboard
   */
  async addWidget(dashboardId: string, widget: Partial<DashboardWidget>): Promise<DashboardWidget> {
    const dashboard = this.dashboards.get(dashboardId);
    if (!dashboard) {
      throw new Error(`Dashboard ${dashboardId} not found`);
    }

    const newWidget: DashboardWidget = {
      id: this.generateId(),
      type: widget.type || WidgetType.SLO_STATUS,
      title: widget.title || 'New Widget',
      position: widget.position || { x: 0, y: 0, width: 4, height: 3 },
      config: widget.config || {},
      dataSource: widget.dataSource || { type: 'slo_evaluations' },
      visualization: widget.visualization || {
        type: ChartType.LINE,
        interactive: true,
      },
      refreshInterval: widget.refreshInterval,
    };

    dashboard.widgets.push(newWidget);
    dashboard.metadata.updatedAt = new Date();

    this.emit('widget:added', { dashboardId, widget: newWidget });
    this.broadcastToDashboard(dashboardId, 'widget:added', newWidget);

    return newWidget;
  }

  /**
   * Update a widget
   */
  async updateWidget(
    dashboardId: string,
    widgetId: string,
    updates: Partial<DashboardWidget>
  ): Promise<DashboardWidget> {
    const dashboard = this.dashboards.get(dashboardId);
    if (!dashboard) {
      throw new Error(`Dashboard ${dashboardId} not found`);
    }

    const widgetIndex = dashboard.widgets.findIndex(w => w.id === widgetId);
    if (widgetIndex === -1) {
      throw new Error(`Widget ${widgetId} not found in dashboard ${dashboardId}`);
    }

    const updatedWidget: DashboardWidget = {
      ...dashboard.widgets[widgetIndex],
      ...updates,
      id: widgetId, // Ensure ID doesn't change
    };

    dashboard.widgets[widgetIndex] = updatedWidget;
    dashboard.metadata.updatedAt = new Date();

    this.emit('widget:updated', { dashboardId, widget: updatedWidget });
    this.broadcastToDashboard(dashboardId, 'widget:updated', updatedWidget);

    return updatedWidget;
  }

  /**
   * Remove a widget from a dashboard
   */
  async removeWidget(dashboardId: string, widgetId: string): Promise<boolean> {
    const dashboard = this.dashboards.get(dashboardId);
    if (!dashboard) {
      throw new Error(`Dashboard ${dashboardId} not found`);
    }

    const widgetIndex = dashboard.widgets.findIndex(w => w.id === widgetId);
    if (widgetIndex === -1) {
      return false;
    }

    dashboard.widgets.splice(widgetIndex, 1);
    dashboard.metadata.updatedAt = new Date();

    this.emit('widget:removed', { dashboardId, widgetId });
    this.broadcastToDashboard(dashboardId, 'widget:removed', { widgetId });

    return true;
  }

  // ============================================================================
  // Data Retrieval
  // ============================================================================

  /**
   * Get data for a widget
   */
  async getWidgetData(dashboardId: string, widgetId: string, filters?: Record<string, any>): Promise<any> {
    const dashboard = this.dashboards.get(dashboardId);
    if (!dashboard) {
      throw new Error(`Dashboard ${dashboardId} not found`);
    }

    const widget = dashboard.widgets.find(w => w.id === widgetId);
    if (!widget) {
      throw new Error(`Widget ${widgetId} not found`);
    }

    return this.generateWidgetData(widget, filters);
  }

  /**
   * Get dashboard summary data
   */
  async getDashboardSummary(dashboardId: string): Promise<{
    status: {
      total: number;
      compliant: number;
      violating: number;
      warning: number;
      insufficientData: number;
    };
    alerts: {
      total: number;
      critical: number;
      warning: number;
      info: number;
    };
    budget: {
      total: number;
      consumed: number;
      remaining: number;
    };
    lastUpdated: Date;
  }> {
    const dashboard = this.dashboards.get(dashboardId);
    if (!dashboard) {
      throw new Error(`Dashboard ${dashboardId} not found`);
    }

    const sloIds = dashboard.widgets
      .filter(w => w.config.sloIds)
      .flatMap(w => w.config.sloIds || []);

    const status = {
      total: sloIds.length,
      compliant: 0,
      violating: 0,
      warning: 0,
      insufficientData: 0,
    };

    const alerts = {
      total: 0,
      critical: 0,
      warning: 0,
      info: 0,
    };

    let totalBudget = 0;
    let consumedBudget = 0;

    for (const sloId of sloIds) {
      const evaluation = this.sloService.getLatestEvaluation(sloId);
      if (evaluation) {
        switch (evaluation.status) {
          case SLOEvaluationStatus.COMPLIANT:
            status.compliant++;
            break;
          case SLOEvaluationStatus.VIOLATION:
            status.violating++;
            break;
          case SLOEvaluationStatus.WARNING:
            status.warning++;
            break;
          case SLOEvaluationStatus.INSUFFICIENT_DATA:
            status.insufficientData++;
            break;
        }

        totalBudget += evaluation.budget.total;
        consumedBudget += evaluation.budget.consumed;

        for (const alert of evaluation.alerts) {
          alerts.total++;
          switch (alert.severity) {
            case AlertSeverity.CRITICAL:
            case AlertSeverity.EMERGENCY:
              alerts.critical++;
              break;
            case AlertSeverity.WARNING:
              alerts.warning++;
              break;
            case AlertSeverity.INFO:
              alerts.info++;
              break;
          }
        }
      } else {
        status.insufficientData++;
      }
    }

    return {
      status,
      alerts,
      budget: {
        total: totalBudget,
        consumed: consumedBudget,
        remaining: Math.max(0, totalBudget - consumedBudget),
      },
      lastUpdated: new Date(),
    };
  }

  // ============================================================================
  // Real-time Updates
  // ============================================================================

  /**
   * Broadcast updates to all dashboard clients
   */
  broadcastToDashboard(dashboardId: string, event: string, data: any): void {
    this.io.to(`dashboard:${dashboardId}`).emit(event, data);
  }

  /**
   * Broadcast to all connected clients
   */
  broadcast(event: string, data: any): void {
    this.io.emit(event, data);
  }

  // ============================================================================
  // Alerting Integration
  // ============================================================================

  /**
   * Get active alerts for dashboard
   */
  async getDashboardAlerts(dashboardId: string): Promise<SLOAlert[]> {
    const dashboard = this.dashboards.get(dashboardId);
    if (!dashboard) {
      throw new Error(`Dashboard ${dashboardId} not found`);
    }

    const sloIds = dashboard.widgets
      .filter(w => w.config.sloIds)
      .flatMap(w => w.config.sloIds || []);

    const alerts: SLOAlert[] = [];

    for (const sloId of sloIds) {
      const evaluation = this.sloService.getLatestEvaluation(sloId);
      if (evaluation) {
        alerts.push(...evaluation.alerts.filter(a => !a.resolved));
      }
    }

    return alerts.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  /**
   * Acknowledge an alert
   */
  async acknowledgeAlert(alertId: string, acknowledgedBy: string): Promise<boolean> {
    // Find the alert across all SLOs
    const slos = this.sloService.getAllSLOs();

    for (const slo of slos) {
      const evaluations = this.sloService.getEvaluations(slo.id);

      for (const evaluation of evaluations) {
        const alert = evaluation.alerts.find(a => a.id === alertId);
        if (alert && !alert.acknowledged) {
          alert.acknowledged = true;
          alert.acknowledgedBy = acknowledgedBy;
          alert.acknowledgedAt = new Date();

          this.emit('alert:acknowledged', alert);
          this.broadcast('alert:acknowledged', alert);

          return true;
        }
      }
    }

    return false;
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  /**
   * Setup Express application
   */
  private setupExpress(): void {
    this.app.use(express.json());
    this.app.use(express.static(path.join(__dirname, '../../public')));

    // API Routes
    this.app.get('/api/dashboards', (req, res) => {
      res.json(Array.from(this.dashboards.values()));
    });

    this.app.get('/api/dashboards/:id', (req, res) => {
      const dashboard = this.dashboards.get(req.params.id);
      if (!dashboard) {
        return res.status(404).json({ error: 'Dashboard not found' });
      }
      res.json(dashboard);
    });

    this.app.post('/api/dashboards', async (req, res) => {
      try {
        const dashboard = await this.createDashboard(req.body);
        res.status(201).json(dashboard);
      } catch (error) {
        res.status(400).json({ error: error instanceof Error ? error.message : 'Unknown error' });
      }
    });

    this.app.put('/api/dashboards/:id', async (req, res) => {
      try {
        const dashboard = await this.updateDashboard(req.params.id, req.body);
        res.json(dashboard);
      } catch (error) {
        res.status(400).json({ error: error instanceof Error ? error.message : 'Unknown error' });
      }
    });

    this.app.delete('/api/dashboards/:id', async (req, res) => {
      try {
        const deleted = await this.deleteDashboard(req.params.id);
        res.status(deleted ? 204 : 404).send();
      } catch (error) {
        res.status(400).json({ error: error instanceof Error ? error.message : 'Unknown error' });
      }
    });

    this.app.get('/api/dashboards/:id/summary', async (req, res) => {
      try {
        const summary = await this.getDashboardSummary(req.params.id);
        res.json(summary);
      } catch (error) {
        res.status(400).json({ error: error instanceof Error ? error.message : 'Unknown error' });
      }
    });

    this.app.get('/api/dashboards/:id/alerts', async (req, res) => {
      try {
        const alerts = await this.getDashboardAlerts(req.params.id);
        res.json(alerts);
      } catch (error) {
        res.status(400).json({ error: error instanceof Error ? error.message : 'Unknown error' });
      }
    });

    this.app.post('/api/dashboards/:id/widgets', async (req, res) => {
      try {
        const widget = await this.addWidget(req.params.id, req.body);
        res.status(201).json(widget);
      } catch (error) {
        res.status(400).json({ error: error instanceof Error ? error.message : 'Unknown error' });
      }
    });

    this.app.get('/api/dashboards/:id/widgets/:widgetId/data', async (req, res) => {
      try {
        const data = await this.getWidgetData(req.params.id, req.params.widgetId, req.query);
        res.json(data);
      } catch (error) {
        res.status(400).json({ error: error instanceof Error ? error.message : 'Unknown error' });
      }
    });

    this.app.post('/api/alerts/:alertId/acknowledge', async (req, res) => {
      try {
        const acknowledged = await this.acknowledgeAlert(req.params.alertId, req.body.acknowledgedBy || 'unknown');
        res.status(acknowledged ? 200 : 404).json({ acknowledged });
      } catch (error) {
        res.status(400).json({ error: error instanceof Error ? error.message : 'Unknown error' });
      }
    });

    // Serve the dashboard HTML
    this.app.get('/dashboards/:id', (req, res) => {
      res.send(this.generateDashboardHTML(req.params.id));
    });
  }

  /**
   * Setup Socket.IO for real-time updates
   */
  private setupSocketIO(): void {
    this.io.on('connection', (socket) => {
      console.log(`🔌 Client connected: ${socket.id}`);
      this.connectedClients.set(socket.id, socket);

      // Handle dashboard subscription
      socket.on('subscribe:dashboard', (dashboardId) => {
        socket.join(`dashboard:${dashboardId}`);
        console.log(`📊 Client ${socket.id} subscribed to dashboard ${dashboardId}`);
      });

      // Handle dashboard unsubscription
      socket.on('unsubscribe:dashboard', (dashboardId) => {
        socket.leave(`dashboard:${dashboardId}`);
        console.log(`📊 Client ${socket.id} unsubscribed from dashboard ${dashboardId}`);
      });

      // Handle widget data requests
      socket.on('get:widget-data', async (data) => {
        try {
          const widgetData = await this.getWidgetData(data.dashboardId, data.widgetId, data.filters);
          socket.emit('widget-data', { dashboardId: data.dashboardId, widgetId: data.widgetId, data: widgetData });
        } catch (error) {
          socket.emit('error', { message: error instanceof Error ? error.message : 'Unknown error' });
        }
      });

      // Handle disconnection
      socket.on('disconnect', () => {
        console.log(`🔌 Client disconnected: ${socket.id}`);
        this.connectedClients.delete(socket.id);
      });
    });
  }

  /**
   * Setup SLO event handlers for real-time updates
   */
  private setupSLOEventHandlers(): void {
    // Handle SLO evaluations
    this.sloService.on('slo:evaluated', (evaluation: SLOEvaluation) => {
      // Find all dashboards that include this SLO
      for (const dashboard of this.dashboards.values()) {
        const relevantWidgets = dashboard.widgets.filter(w =>
          w.config.sloIds?.includes(evaluation.sloId)
        );

        if (relevantWidgets.length > 0) {
          this.broadcastToDashboard(dashboard.id, 'slo:evaluated', evaluation);
        }
      }
    });

    // Handle SLO alerts
    this.sloService.on('alert:created', (alert: SLOAlert) => {
      // Find all dashboards that include this SLO
      for (const dashboard of this.dashboards.values()) {
        const relevantWidgets = dashboard.widgets.filter(w =>
          w.config.sloIds?.includes(alert.sloId)
        );

        if (relevantWidgets.length > 0) {
          this.broadcastToDashboard(dashboard.id, 'alert:created', alert);
        }
      }
    });
  }

  /**
   * Generate data for a widget based on its configuration
   */
  private async generateWidgetData(widget: DashboardWidget, filters?: Record<string, any>): Promise<any> {
    switch (widget.type) {
      case WidgetType.SLO_STATUS:
        return this.generateSLOStatusData(widget, filters);
      case WidgetType.COMPLIANCE_CHART:
        return this.generateComplianceChartData(widget, filters);
      case WidgetType.BURN_RATE:
        return this.generateBurnRateData(widget, filters);
      case WidgetType.ERROR_BUDGET:
        return this.generateErrorBudgetData(widget, filters);
      case WidgetType.TREND_ANALYSIS:
        return this.generateTrendAnalysisData(widget, filters);
      case WidgetType.ALERT_SUMMARY:
        return this.generateAlertSummaryData(widget, filters);
      default:
        return { error: 'Unknown widget type' };
    }
  }

  /**
   * Generate SLO status data
   */
  private async generateSLOStatusData(widget: DashboardWidget, filters?: Record<string, any>): Promise<any> {
    const sloIds = widget.config.sloIds || [];
    const statusData = [];

    for (const sloId of sloIds) {
      const slo = this.sloService.getSLO(sloId);
      const evaluation = this.sloService.getLatestEvaluation(sloId);

      if (slo && evaluation) {
        statusData.push({
          sloId,
          name: slo.name,
          status: evaluation.status,
          compliance: evaluation.objective.compliance,
          target: evaluation.objective.target,
          achieved: evaluation.objective.achieved,
          budgetRemaining: evaluation.budget.remaining,
          burnRate: evaluation.budget.burnRate,
          lastUpdated: evaluation.timestamp,
          alerts: evaluation.alerts.length,
        });
      }
    }

    return {
      type: 'slo_status',
      data: statusData,
      timestamp: new Date(),
    };
  }

  /**
   * Generate compliance chart data
   */
  private async generateComplianceChartData(widget: DashboardWidget, filters?: Record<string, any>): Promise<any> {
    const sloIds = widget.config.sloIds || [];
    const timeRange = widget.config.timeRange || { type: 'relative', duration: 24 * 60 * 60 * 1000 };
    const chartData = [];

    for (const sloId of sloIds) {
      const evaluations = this.sloService.getEvaluations(sloId, 100);
      const slo = this.sloService.getSLO(sloId);

      if (slo && evaluations.length > 0) {
        const seriesData = evaluations.map(e => ({
          timestamp: e.timestamp,
          compliance: e.objective.compliance,
          target: e.objective.target,
        }));

        chartData.push({
          name: slo.name,
          data: seriesData,
        });
      }
    }

    return {
      type: 'compliance_chart',
      data: chartData,
      timeRange,
      timestamp: new Date(),
    };
  }

  /**
   * Generate burn rate data
   */
  private async generateBurnRateData(widget: DashboardWidget, filters?: Record<string, any>): Promise<any> {
    const sloIds = widget.config.sloIds || [];
    const burnRateData = [];

    for (const sloId of sloIds) {
      const slo = this.sloService.getSLO(sloId);
      const evaluation = this.sloService.getLatestEvaluation(sloId);

      if (slo && evaluation) {
        burnRateData.push({
          sloId,
          name: slo.name,
          burnRate: evaluation.budget.burnRate,
          trend: evaluation.budget.trend,
          budgetRemaining: evaluation.budget.remaining,
          budgetTotal: evaluation.budget.total,
          threshold: slo.budgeting.burnRateAlerts[0]?.threshold || 1,
        });
      }
    }

    return {
      type: 'burn_rate',
      data: burnRateData,
      timestamp: new Date(),
    };
  }

  /**
   * Generate error budget data
   */
  private async generateErrorBudgetData(widget: DashboardWidget, filters?: Record<string, any>): Promise<any> {
    const sloIds = widget.config.sloIds || [];
    const budgetData = [];

    for (const sloId of sloIds) {
      const slo = this.sloService.getSLO(sloId);
      const evaluation = this.sloService.getLatestEvaluation(sloId);

      if (slo && evaluation) {
        budgetData.push({
          sloId,
          name: slo.name,
          total: evaluation.budget.total,
          consumed: evaluation.budget.consumed,
          remaining: evaluation.budget.remaining,
          percentageUsed: (evaluation.budget.consumed / evaluation.budget.total) * 100,
          percentageRemaining: (evaluation.budget.remaining / evaluation.budget.total) * 100,
        });
      }
    }

    return {
      type: 'error_budget',
      data: budgetData,
      timestamp: new Date(),
    };
  }

  /**
   * Generate trend analysis data
   */
  private async generateTrendAnalysisData(widget: DashboardWidget, filters?: Record<string, any>): Promise<any> {
    const sloIds = widget.config.sloIds || [];
    const evaluations = this.sloService.getEvaluations(sloIds[0], 50);

    if (evaluations.length === 0) {
      return { type: 'trend_analysis', data: [], timestamp: new Date() };
    }

    const trendData = evaluations.map(e => ({
      timestamp: e.timestamp,
      compliance: e.objective.compliance,
      burnRate: e.budget.burnRate,
      budgetRemaining: e.budget.remaining,
    }));

    return {
      type: 'trend_analysis',
      data: trendData,
      timestamp: new Date(),
    };
  }

  /**
   * Generate alert summary data
   */
  private async generateAlertSummaryData(widget: DashboardWidget, filters?: Record<string, any>): Promise<any> {
    const sloIds = widget.config.sloIds || [];
    const alertSummary = {
      total: 0,
      critical: 0,
      warning: 0,
      info: 0,
      byType: {} as Record<string, number>,
      recent: [] as any[],
    };

    for (const sloId of sloIds) {
      const evaluation = this.sloService.getLatestEvaluation(sloId);

      if (evaluation) {
        for (const alert of evaluation.alerts) {
          alertSummary.total++;

          switch (alert.severity) {
            case AlertSeverity.CRITICAL:
            case AlertSeverity.EMERGENCY:
              alertSummary.critical++;
              break;
            case AlertSeverity.WARNING:
              alertSummary.warning++;
              break;
            case AlertSeverity.INFO:
              alertSummary.info++;
              break;
          }

          alertSummary.byType[alert.type] = (alertSummary.byType[alert.type] || 0) + 1;

          if (!alert.resolved) {
            alertSummary.recent.push({
              id: alert.id,
              sloId,
              title: alert.title,
              message: alert.message,
              severity: alert.severity,
              timestamp: alert.timestamp,
            });
          }
        }
      }
    }

    // Sort recent alerts by timestamp
    alertSummary.recent.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    return {
      type: 'alert_summary',
      data: alertSummary,
      timestamp: new Date(),
    };
  }

  /**
   * Generate dashboard HTML
   */
  private generateDashboardHTML(dashboardId: string): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SLO Dashboard ${dashboardId}</title>
    <script src="/socket.io/socket.io.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .widget { @apply bg-white rounded-lg shadow-md p-4; }
        .status-healthy { @apply text-green-600; }
        .status-warning { @apply text-yellow-600; }
        .status-critical { @apply text-red-600; }
        .status-unknown { @apply text-gray-600; }
    </style>
</head>
<body class="bg-gray-100">
    <div class="container mx-auto p-4">
        <header class="mb-6">
            <h1 class="text-3xl font-bold text-gray-800">SLO Dashboard</h1>
            <p class="text-gray-600">Real-time Service Level Objective Monitoring</p>
        </header>

        <main>
            <div id="loading" class="text-center py-8">
                <p class="text-gray-600">Loading dashboard...</p>
            </div>

            <div id="dashboard-content" class="hidden">
                <!-- Dashboard widgets will be rendered here -->
            </div>
        </main>

        <footer class="mt-8 text-center text-gray-600 text-sm">
            <p>© 2025 Cortex SLO Dashboard</p>
        </footer>
    </div>

    <script>
        const socket = io();
        const dashboardId = '${dashboardId}';

        // Subscribe to dashboard updates
        socket.emit('subscribe:dashboard', dashboardId);

        // Load dashboard data
        loadDashboard();

        socket.on('dashboard:updated', (data) => {
            if (data.id === dashboardId) {
                loadDashboard();
            }
        });

        socket.on('slo:evaluated', (data) => {
            updateWidgetData(data.sloId);
        });

        socket.on('alert:created', (data) => {
            showAlert(data);
        });

        async function loadDashboard() {
            try {
                const response = await fetch('/api/dashboards/' + dashboardId);
                const dashboard = await response.json();

                renderDashboard(dashboard);
                loadWidgetData(dashboard);

                // Hide loading, show content
                document.getElementById('loading').classList.add('hidden');
                document.getElementById('dashboard-content').classList.remove('hidden');

            } catch (error) {
                console.error('Failed to load dashboard:', error);
                document.getElementById('loading').innerHTML =
                    '<p class="text-red-600">Failed to load dashboard. Please try again.</p>';
            }
        }

        function renderDashboard(dashboard) {
            const container = document.getElementById('dashboard-content');
            container.innerHTML = '';

            // Create grid layout
            const grid = document.createElement('div');
            grid.className = 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4';

            dashboard.widgets.forEach(widget => {
                const widgetElement = createWidgetElement(widget);
                grid.appendChild(widgetElement);
            });

            container.appendChild(grid);
        }

        function createWidgetElement(widget) {
            const div = document.createElement('div');
            div.className = 'widget';
            div.id = 'widget-' + widget.id;
            div.style.gridColumn = 'span ' + (widget.position.width || 4);

            div.innerHTML = \`
                <h3 class="text-lg font-semibold mb-2">\${widget.title}</h3>
                <div class="widget-content" data-widget-id="\${widget.id}">
                    <div class="text-gray-500 text-center py-4">Loading...</div>
                </div>
            \`;

            return div;
        }

        async function loadWidgetData(dashboard) {
            for (const widget of dashboard.widgets) {
                try {
                    const response = await fetch(\`/api/dashboards/\${dashboardId}/widgets/\${widget.id}/data\`);
                    const data = await response.json();

                    renderWidgetData(widget.id, data);
                } catch (error) {
                    console.error('Failed to load widget data:', error);
                }
            }
        }

        function renderWidgetData(widgetId, data) {
            const content = document.querySelector(\`[data-widget-id="\${widgetId}"]\`);
            if (!content) return;

            switch (data.type) {
                case 'slo_status':
                    renderSLOStatus(content, data.data);
                    break;
                case 'compliance_chart':
                    renderComplianceChart(content, data);
                    break;
                case 'burn_rate':
                    renderBurnRate(content, data.data);
                    break;
                case 'error_budget':
                    renderErrorBudget(content, data.data);
                    break;
                case 'alert_summary':
                    renderAlertSummary(content, data.data);
                    break;
                default:
                    content.innerHTML = '<div class="text-gray-500">Unknown widget type</div>';
            }
        }

        function renderSLOStatus(container, data) {
            let html = '<div class="space-y-2">';
            data.forEach(item => {
                const statusClass = getStatusClass(item.status);
                html += \`
                    <div class="flex justify-between items-center p-2 bg-gray-50 rounded">
                        <span class="font-medium">\${item.name}</span>
                        <span class="\${statusClass}">\${item.compliance.toFixed(1)}%</span>
                    </div>
                \`;
            });
            html += '</div>';
            container.innerHTML = html;
        }

        function renderComplianceChart(container, data) {
            const canvas = document.createElement('canvas');
            container.innerHTML = '';
            container.appendChild(canvas);

            // Chart implementation would go here
            container.innerHTML += '<p class="text-sm text-gray-500 mt-2">Compliance trend chart</p>';
        }

        function renderBurnRate(container, data) {
            let html = '<div class="space-y-2">';
            data.forEach(item => {
                const rateClass = item.burnRate > item.threshold ? 'text-red-600' : 'text-green-600';
                html += \`
                    <div class="p-2 bg-gray-50 rounded">
                        <div class="flex justify-between items-center">
                            <span class="font-medium">\${item.name}</span>
                            <span class="\${rateClass}">\${item.burnRate.toFixed(2)}x</span>
                        </div>
                        <div class="text-sm text-gray-600">
                            Budget: \${item.budgetRemaining.toFixed(1)}% remaining
                        </div>
                    </div>
                \`;
            });
            html += '</div>';
            container.innerHTML = html;
        }

        function renderErrorBudget(container, data) {
            let html = '<div class="space-y-2">';
            data.forEach(item => {
                const percentage = item.percentageRemaining;
                const color = percentage > 50 ? 'green' : percentage > 20 ? 'yellow' : 'red';

                html += \`
                    <div class="p-2 bg-gray-50 rounded">
                        <div class="flex justify-between items-center mb-1">
                            <span class="font-medium">\${item.name}</span>
                            <span class="text-\${color}-600">\${percentage.toFixed(1)}%</span>
                        </div>
                        <div class="w-full bg-gray-200 rounded-full h-2">
                            <div class="bg-\${color}-600 h-2 rounded-full" style="width: \${percentage}%"></div>
                        </div>
                    </div>
                \`;
            });
            html += '</div>';
            container.innerHTML = html;
        }

        function renderAlertSummary(container, data) {
            let html = \`
                <div class="grid grid-cols-2 gap-2 mb-4">
                    <div class="text-center p-2 bg-red-50 rounded">
                        <div class="text-2xl font-bold text-red-600">\${data.critical}</div>
                        <div class="text-sm text-gray-600">Critical</div>
                    </div>
                    <div class="text-center p-2 bg-yellow-50 rounded">
                        <div class="text-2xl font-bold text-yellow-600">\${data.warning}</div>
                        <div class="text-sm text-gray-600">Warning</div>
                    </div>
                </div>
            \`;

            if (data.recent.length > 0) {
                html += '<div class="space-y-2">';
                data.recent.slice(0, 5).forEach(alert => {
                    const severityClass = getSeverityClass(alert.severity);
                    html += \`
                        <div class="p-2 bg-gray-50 rounded text-sm">
                            <div class="font-medium \${severityClass}">\${alert.title}</div>
                            <div class="text-gray-600">\${alert.message}</div>
                        </div>
                    \`;
                });
                html += '</div>';
            } else {
                html += '<p class="text-gray-500 text-center">No active alerts</p>';
            }

            container.innerHTML = html;
        }

        function getStatusClass(status) {
            switch (status) {
                case 'compliant': return 'status-healthy';
                case 'warning': return 'status-warning';
                case 'violation': return 'status-critical';
                default: return 'status-unknown';
            }
        }

        function getSeverityClass(severity) {
            switch (severity) {
                case 'critical':
                case 'emergency': return 'text-red-600';
                case 'warning': return 'text-yellow-600';
                case 'info': return 'text-blue-600';
                default: return 'text-gray-600';
            }
        }

        function showAlert(alert) {
            // Simple alert notification
            const notification = document.createElement('div');
            notification.className = 'fixed top-4 right-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded shadow-lg max-w-sm';
            notification.innerHTML = \`
                <div class="flex justify-between items-start">
                    <div>
                        <h4 class="font-bold">\${alert.title}</h4>
                        <p class="text-sm">\${alert.message}</p>
                    </div>
                    <button onclick="this.parentElement.parentElement.remove()" class="ml-4 text-red-500 hover:text-red-700">×</button>
                </div>
            \`;
            document.body.appendChild(notification);

            // Auto-remove after 10 seconds
            setTimeout(() => {
                if (notification.parentElement) {
                    notification.remove();
                }
            }, 10000);
        }

        function updateWidgetData(sloId) {
            // Find widgets that reference this SLO and update them
            document.querySelectorAll('[data-slo-id]').forEach(element => {
                if (element.dataset.sloId === sloId) {
                    // Trigger data refresh for this widget
                    const widgetId = element.closest('[data-widget-id]').dataset.widgetId;
                    if (widgetId) {
                        socket.emit('get:widget-data', { dashboardId, widgetId });
                    }
                }
            });
        }
    </script>
</body>
</html>
    `;
  }

  /**
   * Generate unique ID
   */
  private generateId(): string {
    return Math.random().toString(36).substr(2, 9);
  }

  broadcastToAll?: unknown|undefined}

// Export singleton instance
export const sloDashboardService = new SLODashboardService(
  // Will be injected later
  null as any,
  {
    port: parseInt(process.env.SLO_DASHBOARD_PORT || '3001'),
    host: process.env.SLO_DASHBOARD_HOST || '0.0.0.0',
  }
);