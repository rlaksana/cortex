/**
 * SLO Framework Example
 *
 * Comprehensive example demonstrating how to use the SLO/SLI framework
 * for monitoring service level objectives, tracking error budgets, and
 * managing alerting and reporting.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import {
  SLOIntegrationService,
  sloIntegrationService,
} from '../src/services/slo-integration-service.js';
import {
  SLI,
  SLO,
  SLIType,
  SLIAggregation,
  SLOPeriod,
  AlertSeverity,
  NotificationChannel,
} from '../src/types/slo-interfaces.js';

/**
 * Example: Setting up SLO monitoring for a web service
 */
async function setupWebServiceMonitoring() {
  console.log('🚀 Setting up SLO monitoring for web service...');

  try {
    // 1. Start the SLO integration service
    await sloIntegrationService.start();
    console.log('✅ SLO Integration Service started');

    // 2. Define Service Level Indicators (SLIs)
    const availabilitySLI: SLI = {
      id: 'web-service-availability',
      name: 'Web Service Availability',
      description: 'Percentage of successful HTTP requests',
      type: SLIType['AVAILABILITY'],
      unit: 'percent',
      measurement: {
        source: 'prometheus',
        method: 'http_requests_total',
        aggregation: SLIAggregation['RATE'],
        window: {
          type: 'rolling',
          duration: 5 * 60 * 1000, // 5 minutes
        },
      },
      thresholds: {
        target: 99.9,
        warning: 99.5,
        critical: 99.0,
      },
      tags: {
        service: 'web-api',
        environment: 'production',
      },
      metadata: {
        description: 'Measures the percentage of successful HTTP responses',
        owner: 'platform-team',
      },
    };

    const latencySLI: SLI = {
      id: 'web-service-latency',
      name: 'Web Service Response Time',
      description: '95th percentile response time',
      type: SLIType['LATENCY'],
      unit: 'milliseconds',
      measurement: {
        source: 'prometheus',
        method: 'http_request_duration_seconds',
        aggregation: SLIAggregation['P95'],
        window: {
          type: 'rolling',
          duration: 5 * 60 * 1000,
        },
      },
      thresholds: {
        target: 500, // 500ms
        warning: 1000,
        critical: 2000,
      },
      tags: {
        service: 'web-api',
        environment: 'production',
      },
      metadata: {
        description: '95th percentile HTTP response time',
        owner: 'platform-team',
      },
    };

    // 3. Create SLIs
    await sloIntegrationService['services'].sloService.createSLI(availabilitySLI);
    await sloIntegrationService['services'].sloService.createSLI(latencySLI);
    console.log('✅ SLIs created');

    // 4. Define Service Level Objectives (SLOs)
    const availabilitySLO: SLO = {
      id: 'web-service-availability-slo',
      name: 'Web Service Availability SLO',
      description: '99.9% availability over 30 days',
      sli: 'web-service-availability',
      objective: {
        target: 99.9,
        period: SLOPeriod['ROLLING_30_DAYS'],
        window: {
          type: 'rolling',
          duration: 30 * 24 * 60 * 60 * 1000,
        },
      },
      budgeting: {
        errorBudget: 0.1, // 0.1% allowed errors
        burnRateAlerts: [
          {
            name: 'High Burn Rate',
            threshold: 2.0,
            window: {
              type: 'rolling',
              duration: 24 * 60 * 60 * 1000,
            },
            severity: AlertSeverity['WARNING'],
            alertWhenRemaining: 50,
          },
        ],
      },
      alerting: {
        enabled: true,
        thresholds: [
          {
            name: 'Availability Drop',
            condition: {
              operator: 'lt',
              value: 99.5,
              evaluationWindow: {
                type: 'rolling',
                duration: 15 * 60 * 1000,
              },
            },
            severity: AlertSeverity['WARNING'],
            threshold: 99.5,
            duration: 5 * 60 * 1000,
            cooldown: 15 * 60 * 1000,
            enabled: true,
          },
        ],
        notificationChannels: ['slack', 'email'],
      },
      ownership: {
        team: 'platform-team',
        individuals: ['alice@example.com', 'bob@example.com'],
        contact: {
          email: 'platform-team@example.com',
          slack: '#platform-alerts',
          pager: 'platform-oncall',
        },
      },
      status: 'active',
      metadata: {
        createdAt: new Date(),
        updatedAt: new Date(),
        lastEvaluated: new Date(),
        businessImpact: 'Critical revenue-generating service',
        dependencies: ['database', 'cache', 'cdn'],
        relatedSLOs: ['web-service-latency-slo'],
      },
    };

    const latencySLO: SLO = {
      id: 'web-service-latency-slo',
      name: 'Web Service Latency SLO',
      description: '95th percentile response time under 500ms over 30 days',
      sli: 'web-service-latency',
      objective: {
        target: 95, // 95% of requests under 500ms
        period: SLOPeriod['ROLLING_30_DAYS'],
        window: {
          type: 'rolling',
          duration: 30 * 24 * 60 * 60 * 1000,
        },
      },
      budgeting: {
        errorBudget: 5.0, // 5% of requests can exceed 500ms
        burnRateAlerts: [
          {
            name: 'Latency Burn Rate',
            threshold: 1.5,
            window: {
              type: 'rolling',
              duration: 6 * 60 * 60 * 1000,
            },
            severity: AlertSeverity['WARNING'],
            alertWhenRemaining: 70,
          },
        ],
      },
      alerting: {
        enabled: true,
        thresholds: [
          {
            name: 'High Latency',
            condition: {
              operator: 'gt',
              value: 1000, // 1 second
              evaluationWindow: {
                type: 'rolling',
                duration: 10 * 60 * 1000,
              },
            },
            severity: AlertSeverity['CRITICAL'],
            threshold: 1000,
            duration: 2 * 60 * 1000,
            cooldown: 10 * 60 * 1000,
            enabled: true,
          },
        ],
        notificationChannels: ['slack', 'pagerduty'],
      },
      ownership: {
        team: 'platform-team',
        individuals: ['alice@example.com', 'bob@example.com'],
        contact: {
          email: 'platform-team@example.com',
          slack: '#platform-alerts',
          pager: 'platform-oncall',
        },
      },
      status: 'active',
      metadata: {
        createdAt: new Date(),
        updatedAt: new Date(),
        lastEvaluated: new Date(),
        businessImpact: 'User experience critical',
        dependencies: ['database', 'cache'],
        relatedSLOs: ['web-service-availability-slo'],
      },
    };

    // 5. Create SLOs with full integration
    const availabilityResult = await sloIntegrationService.createSLO(availabilitySLO);
    const latencyResult = await sloIntegrationService.createSLO(latencySLO);

    console.log('✅ SLOs created:', {
      availability: availabilityResult.slo.name,
      latency: latencyResult.slo.name,
    });

    // 6. Setup notification channels
    await setupNotificationChannels();

    // 7. Create monitoring dashboard
    const dashboard = await sloIntegrationService.createDefaultDashboard();
    console.log('✅ Dashboard created:', dashboard.url);

    // 8. Simulate some measurements (in real scenario, these would come from your monitoring system)
    await simulateMeasurements();

    // 9. Monitor SLO performance
    await monitorSLOPerformance();

    return {
      availabilitySLO: availabilityResult,
      latencySLO: latencyResult,
      dashboard,
    };
  } catch (error) {
    console.error('❌ Failed to setup SLO monitoring:', error);
    throw error;
  }
}

/**
 * Setup notification channels
 */
async function setupNotificationChannels() {
  const slackChannel: NotificationChannel = {
    id: 'slack',
    name: 'Slack Notifications',
    type: 'slack',
    config: {
      webhookUrl: process.env['SLACK_WEBHOOK_URL'] || 'https://hooks.slack.com/services/...',
      channel: '#slo-alerts',
      username: 'SLO Bot',
    },
    enabled: true,
  };

  const emailChannel: NotificationChannel = {
    id: 'email',
    name: 'Email Notifications',
    type: 'email',
    config: {
      smtp: {
        host: 'smtp.example.com',
        port: 587,
        secure: false,
      },
      from: 'slo-alerts@example.com',
      to: ['platform-team@example.com'],
    },
    enabled: true,
  };

  const pagerDutyChannel: NotificationChannel = {
    id: 'pagerduty',
    name: 'PagerDuty Notifications',
    type: 'pagerduty',
    config: {
      integrationKey: process.env['PAGERDUTY_INTEGRATION_KEY'] || '...',
      severity: 'critical',
    },
    enabled: true,
  };

  // Register channels with breach detection service
  const breachService = sloIntegrationService['services'].breachDetectionService;
  breachService.registerNotificationChannel(slackChannel);
  breachService.registerNotificationChannel(emailChannel);
  breachService.registerNotificationChannel(pagerDutyChannel);

  console.log('✅ Notification channels configured');
}

/**
 * Simulate measurements (for demonstration)
 */
async function simulateMeasurements() {
  console.log('📊 Simulating SLO measurements...');

  const sloService = sloIntegrationService['services'].sloService;

  // Simulate availability measurements
  for (let i = 0; i < 10; i++) {
    const availabilityMeasurement = {
      id: `availability-${i}`,
      sliId: 'web-service-availability',
      timestamp: new Date(Date.now() - (9 - i) * 60 * 1000),
      value: 99.5 + Math.random() * 0.4, // 99.5% - 99.9%
      quality: {
        completeness: 100,
        accuracy: 0.95,
        timeliness: 100,
        validity: true,
      },
      metadata: {
        source: 'prometheus',
        environment: 'production',
      },
    };

    const latencyMeasurement = {
      id: `latency-${i}`,
      sliId: 'web-service-latency',
      timestamp: new Date(Date.now() - (9 - i) * 60 * 1000),
      value: 85 + Math.random() * 10, // 85% - 95% compliance
      quality: {
        completeness: 100,
        accuracy: 0.9,
        timeliness: 100,
        validity: true,
      },
      metadata: {
        source: 'prometheus',
        environment: 'production',
      },
    };

    await sloService.addMeasurements([availabilityMeasurement, latencyMeasurement]);

    // Small delay between measurements
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  console.log('✅ Simulated measurements added');
}

/**
 * Monitor SLO performance
 */
async function monitorSLOPerformance() {
  console.log('📈 Monitoring SLO performance...');

  // Get comprehensive SLO overview
  const availabilityOverview = await sloIntegrationService.getSLOOverview(
    'web-service-availability-slo'
  );
  const latencyOverview = await sloIntegrationService.getSLOOverview('web-service-latency-slo');

  console.log('📊 Availability SLO Overview:', {
    target: availabilityOverview.slo.objective.target,
    current: availabilityOverview.evaluation?.objective.achieved,
    status: availabilityOverview.evaluation?.status,
    errorBudget: `${availabilityOverview.errorBudget.remaining.toFixed(2)}% remaining`,
    burnRate: availabilityOverview.burnRateAnalysis.currentRates.daily.toFixed(2),
  });

  console.log('📊 Latency SLO Overview:', {
    target: latencyOverview.slo.objective.target,
    current: latencyOverview.evaluation?.objective.achieved,
    status: latencyOverview.evaluation?.status,
    errorBudget: `${latencyOverview.errorBudget.remaining.toFixed(2)}% remaining`,
    burnRate: latencyOverview.burnRateAnalysis.currentRates.daily.toFixed(2),
  });

  // Get system-wide report
  const systemReport = await sloIntegrationService.generateSystemReport();
  console.log('📊 System Report:', {
    totalSLOs: systemReport.summary.totalSLOs,
    activeSLOs: systemReport.summary.activeSLOs,
    compliantSLOs: systemReport.summary.compliantSLOs,
    overallHealth: systemReport.summary.overallHealth,
    totalErrorBudget: `${systemReport.summary.totalErrorBudget.toFixed(2)}%`,
    consumedErrorBudget: `${systemReport.summary.consumedErrorBudget.toFixed(2)}%`,
  });

  // Display recommendations
  if (systemReport.recommendations.length > 0) {
    console.log('💡 Recommendations:');
    systemReport.recommendations.forEach((rec, index) => {
      console.log(`  ${index + 1}. ${rec}`);
    });
  }

  // Monitor for alerts
  setupAlertMonitoring();
}

/**
 * Setup alert monitoring
 */
function setupAlertMonitoring() {
  console.log('🚨 Setting up alert monitoring...');

  const sloService = sloIntegrationService['services'].sloService;
  const breachService = sloIntegrationService['services'].breachDetectionService;

  // Listen for SLO evaluations
  sloService.on('slo:evaluated', (evaluation) => {
    console.log(`📊 SLO Evaluated: ${evaluation.sloId} - ${evaluation.status.toUpperCase()}`);
    console.log(`   Compliance: ${evaluation.objective.compliance.toFixed(2)}%`);
    console.log(`   Error Budget: ${evaluation.budget.remaining.toFixed(2)}% remaining`);

    if (evaluation.alerts.length > 0) {
      console.log(`   🚨 Alerts: ${evaluation.alerts.length}`);
      evaluation.alerts.forEach((alert) => {
        console.log(`      - ${alert.title}: ${alert.message}`);
      });
    }
  });

  // Listen for incidents
  breachService.on('incident:created', (incident) => {
    console.log(`🚨 INCIDENT CREATED: ${incident.sloName}`);
    console.log(`   Severity: ${incident.severity}`);
    console.log(`   Impact Score: ${incident.impactAssessment.score}/100`);
    console.log(`   Affected Services: ${incident.metadata['affectedServices'].join(', ')}`);
  });

  // Listen for budget alerts
  const errorBudgetService = sloIntegrationService['services'].errorBudgetService;
  errorBudgetService.on('alert:generated', (alert) => {
    console.log(`💰 BUDGET ALERT: ${alert.title}`);
    console.log(`   Type: ${alert.type}`);
    console.log(`   Current Value: ${alert.currentValue}`);
    console.log(`   Threshold: ${alert.threshold}`);
  });

  console.log('✅ Alert monitoring configured');
}

/**
 * Example: Generate custom reports
 */
async function generateCustomReports() {
  console.log('📋 Generating custom reports...');

  const reportingService = sloIntegrationService['services'].reportingService;

  // Generate monthly report
  const now = new Date();
  const monthlyReport = await reportingService.generateMonthlyReport(
    now.getFullYear(),
    now.getMonth() + 1
  );

  console.log('📊 Monthly Report Generated:', {
    period: `${monthlyReport.metadata['title']}`,
    slos: monthlyReport.metadata['slos'].length,
    generatedAt: monthlyReport.metadata['generatedAt'],
  });

  // Generate executive summary
  const executiveSummary = await reportingService.generateExecutiveSummary();
  console.log('📊 Executive Summary Generated:', {
    overallCompliance: `${executiveSummary.overall.overallCompliance.toFixed(1)}%`,
    compliantSLOs: executiveSummary.overall.compliantSLOs,
    totalSLOs: executiveSummary.overall.totalSLOs,
    criticalIncidents: executiveSummary.highlights.criticalIncidents.length,
  });

  // Generate trend analysis
  const trendAnalysis = await reportingService.getMultiSLOTrendAnalysis([
    'web-service-availability-slo',
    'web-service-latency-slo',
  ]);

  console.log('📈 Trend Analysis Generated for', trendAnalysis.length, 'SLOs');

  return {
    monthlyReport,
    executiveSummary,
    trendAnalysis,
  };
}

/**
 * Example: Demonstrate error budget management
 */
async function demonstrateErrorBudgetManagement() {
  console.log('💰 Demonstrating error budget management...');

  const errorBudgetService = sloIntegrationService['services'].errorBudgetService;

  // Get current error budgets
  const availabilityBudget = await errorBudgetService.calculateErrorBudget(
    'web-service-availability-slo'
  );
  const latencyBudget = await errorBudgetService.calculateErrorBudget('web-service-latency-slo');

  console.log('💰 Current Error Budgets:', {
    availability: {
      total: `${availabilityBudget.total}%`,
      remaining: `${availabilityBudget.remaining.toFixed(2)}%`,
      consumed: `${availabilityBudget.consumed.toFixed(2)}%`,
      utilization: `${availabilityBudget.utilization.percentage.toFixed(1)}%`,
    },
    latency: {
      total: `${latencyBudget.total}%`,
      remaining: `${latencyBudget.remaining.toFixed(2)}%`,
      consumed: `${latencyBudget.consumed.toFixed(2)}%`,
      utilization: `${latencyBudget.utilization.percentage.toFixed(1)}%`,
    },
  });

  // Get burn rate analysis
  const availabilityBurnRate = await errorBudgetService.calculateBurnRateAnalysis(
    'web-service-availability-slo'
  );
  const latencyBurnRate =
    await errorBudgetService.calculateBurnRateAnalysis('web-service-latency-slo');

  console.log('🔥 Burn Rate Analysis:', {
    availability: {
      current: availabilityBurnRate.currentRates.daily.toFixed(2),
      trend: availabilityBurnRate.trend.direction,
      health: availabilityBurnRate.health.status,
    },
    latency: {
      current: latencyBurnRate.currentRates.daily.toFixed(2),
      trend: latencyBurnRate.trend.direction,
      health: latencyBurnRate.health.status,
    },
  });

  // Generate projections
  const availabilityProjection = await errorBudgetService.generateBudgetProjection(
    'web-service-availability-slo'
  );
  const latencyProjection =
    await errorBudgetService.generateBudgetProjection('web-service-latency-slo');

  console.log('🔮 Budget Projections:', {
    availability: {
      exhaustionProbability: `${(availabilityProjection.exhaustionProbability * 100).toFixed(1)}%`,
      recommendations: availabilityProjection.recommendations.length,
    },
    latency: {
      exhaustionProbability: `${(latencyProjection.exhaustionProbability * 100).toFixed(1)}%`,
      recommendations: latencyProjection.recommendations.length,
    },
  });

  return {
    budgets: { availabilityBudget, latencyBudget },
    burnRates: { availabilityBurnRate, latencyBurnRate },
    projections: { availabilityProjection, latencyProjection },
  };
}

/**
 * Cleanup function
 */
async function cleanup() {
  console.log('🧹 Cleaning up SLO framework...');

  try {
    await sloIntegrationService.stop();
    console.log('✅ SLO Integration Service stopped');
  } catch (error) {
    console.error('❌ Error during cleanup:', error);
  }
}

/**
 * Main execution function
 */
async function main() {
  console.log('🎯 SLO Framework Example Starting...');
  console.log('=====================================');

  try {
    // Setup SLO monitoring
    const setupResult = await setupWebServiceMonitoring();

    // Wait a bit for initial evaluations
    await new Promise((resolve) => setTimeout(resolve, 2000));

    // Monitor performance
    await monitorSLOPerformance();

    // Generate custom reports
    const reports = await generateCustomReports();

    // Demonstrate error budget management
    const budgetManagement = await demonstrateErrorBudgetManagement();

    console.log('✅ Example completed successfully!');
    console.log('🌐 Dashboard available at:', setupResult.dashboard.url);

    // Keep running for demonstration
    console.log('⏳ Keeping services running for 30 seconds...');
    setTimeout(async () => {
      await cleanup();
      process.exit(0);
    }, 30000);
  } catch (error) {
    console.error('❌ Example failed:', error);
    await cleanup();
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Received SIGINT, gracefully shutting down...');
  await cleanup();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n🛑 Received SIGTERM, gracefully shutting down...');
  await cleanup();
  process.exit(0);
});

// Run the example
if (require.main === module) {
  main().catch((error) => {
    console.error('❌ Unhandled error:', error);
    process.exit(1);
  });
}

export {
  setupWebServiceMonitoring,
  generateCustomReports,
  demonstrateErrorBudgetManagement,
  cleanup,
};
