#!/usr/bin/env node

/**
 * Monitoring Verification Script
 *
 * This script verifies that the Cortex MCP monitoring stack is working correctly
 * by checking metrics endpoints, dashboard availability, and alert configuration.
 */

import http from 'http';
import https from 'https';

const config = {
  monitoring: {
    host: 'localhost',
    port: process.env.MONITORING_PORT || 9090,
    path: '/metrics',
  },
  grafana: {
    host: 'localhost',
    port: process.env.GRAFANA_PORT || 3000,
    path: '/api/health',
  },
  prometheus: {
    host: 'localhost',
    port: process.env.PROMETHEUS_PORT || 9091,
    path: '/api/v1/query',
  },
  alertmanager: {
    host: 'localhost',
    port: process.env.ALERTMANAGER_PORT || 9093,
    path: '/api/v1/alerts',
  },
};

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
};

function log(level, message) {
  const timestamp = new Date().toISOString();
  const color = colors[level] || colors.reset;
  console.log(`${color}[${level.toUpperCase()}]${colors.reset} ${timestamp} - ${message}`);
}

function makeRequest(options, data = null) {
  return new Promise((resolve, reject) => {
    const protocol = options.port === 443 ? https : http;

    const req = protocol.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: body,
        });
      });
    });

    req.on('error', (err) => {
      reject(err);
    });

    if (data) {
      req.write(data);
    }
    req.end();
  });
}

async function checkService(name, options, expectedStatus = 200) {
  try {
    const response = await makeRequest(options);

    if (response.statusCode === expectedStatus) {
      log('success', `${name} is healthy (${response.statusCode})`);
      return true;
    } else {
      log('warning', `${name} returned unexpected status: ${response.statusCode}`);
      return false;
    }
  } catch (error) {
    log('error', `${name} is not accessible: ${error.message}`);
    return false;
  }
}

async function checkMetrics() {
  log('info', 'Checking Cortex MCP metrics endpoint...');

  try {
    const response = await makeRequest(config.monitoring);
    const metrics = response.body;

    // Check for key metrics
    const keyMetrics = [
      'cortex_service_info',
      'cortex_qps',
      'cortex_latency_milliseconds',
      'cortex_memory_bytes',
      'cortex_errors_total',
    ];

    const foundMetrics = keyMetrics.filter((metric) => metrics.includes(metric));

    if (foundMetrics.length === keyMetrics.length) {
      log('success', `All key metrics found (${foundMetrics.length}/${keyMetrics.length})`);
      return true;
    } else {
      log('warning', `Some key metrics missing (${foundMetrics.length}/${keyMetrics.length})`);
      log('info', `Found: ${foundMetrics.join(', ')}`);
      return false;
    }
  } catch (error) {
    log('error', `Failed to check metrics: ${error.message}`);
    return false;
  }
}

async function checkPrometheusTargets() {
  log('info', 'Checking Prometheus targets...');

  try {
    const options = {
      ...config.prometheus,
      path: '/api/v1/targets',
    };

    const response = await makeRequest(options);
    const data = JSON.parse(response.body);

    const cortexTarget = data.data.activeTargets.find(
      (target) => target.labels.job === 'cortex-mcp'
    );

    if (cortexTarget) {
      const health = cortexTarget.health;
      const lastError = cortexTarget.lastError;

      if (health === 'up') {
        log('success', `Cortex MCP target is healthy (${health})`);
        return true;
      } else {
        log('warning', `Cortex MCP target is ${health}`);
        if (lastError) {
          log('error', `Last error: ${lastError}`);
        }
        return false;
      }
    } else {
      log('error', 'Cortex MCP target not found in Prometheus');
      return false;
    }
  } catch (error) {
    log('error', `Failed to check Prometheus targets: ${error.message}`);
    return false;
  }
}

async function checkGrafanaDatasource() {
  log('info', 'Checking Grafana datasources...');

  try {
    const options = {
      ...config.grafana,
      path: '/api/datasources',
      headers: {
        Authorization: 'Basic ' + Buffer.from('admin:admin123').toString('base64'),
      },
    };

    const response = await makeRequest(options);
    const datasources = JSON.parse(response.body);

    const prometheusDs = datasources.find(
      (ds) => ds.name === 'Prometheus' && ds.type === 'prometheus'
    );

    if (prometheusDs) {
      log('success', 'Prometheus datasource found in Grafana');
      return true;
    } else {
      log('error', 'Prometheus datasource not found in Grafana');
      return false;
    }
  } catch (error) {
    log('error', `Failed to check Grafana datasources: ${error.message}`);
    return false;
  }
}

async function checkAlerts() {
  log('info', 'Checking for active alerts...');

  try {
    const response = await makeRequest(config.prometheus);

    // Query for active alerts
    const queryOptions = {
      ...config.prometheus,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    };

    const postData = 'query=ALERTS_FOR_STATE';
    const alertsResponse = await makeRequest(queryOptions, postData);
    const alertsData = JSON.parse(alertsResponse.body);

    const activeAlerts = alertsData.data.result;

    if (activeAlerts.length > 0) {
      log('warning', `${activeAlerts.length} active alerts found`);
      activeAlerts.forEach((alert) => {
        const alertName = alert.metric.alertname;
        const severity = alert.metric.severity || 'unknown';
        log('info', `  - ${alertName} (${severity})`);
      });
    } else {
      log('success', 'No active alerts (system is healthy)');
    }

    return true;
  } catch (error) {
    log('warning', `Could not check alerts: ${error.message}`);
    return false;
  }
}

async function checkDashboardAvailability() {
  log('info', 'Checking dashboard availability...');

  try {
    const options = {
      ...config.grafana,
      path: '/api/dashboards/home',
      headers: {
        Authorization: 'Basic ' + Buffer.from('admin:admin123').toString('base64'),
      },
    };

    const response = await makeRequest(options);

    if (response.statusCode === 200) {
      log('success', 'Grafana dashboards are accessible');
      return true;
    } else {
      log('warning', `Grafana dashboards returned status: ${response.statusCode}`);
      return false;
    }
  } catch (error) {
    log('error', `Failed to check dashboards: ${error.message}`);
    return false;
  }
}

async function generateHealthReport(results) {
  log('info', 'Generating health report...');

  const totalChecks = Object.keys(results).length;
  const passedChecks = Object.values(results).filter(Boolean).length;
  const healthScore = Math.round((passedChecks / totalChecks) * 100);

  console.log('\n' + '='.repeat(50));
  console.log('🧠 CORTEX MCP MONITORING HEALTH REPORT');
  console.log('='.repeat(50));
  console.log(`Health Score: ${healthScore}% (${passedChecks}/${totalChecks} checks passed)`);
  console.log('');

  Object.entries(results).forEach(([check, passed]) => {
    const status = passed ? '✅ PASS' : '❌ FAIL';
    const formattedName = check.replace(/([A-Z])/g, ' $1').trim();
    console.log(`${status} ${formattedName}`);
  });

  console.log('='.repeat(50));

  if (healthScore === 100) {
    log('success', 'All monitoring components are healthy!');
  } else if (healthScore >= 75) {
    log('warning', 'Most monitoring components are healthy. Check failed items.');
  } else {
    log('error', 'Multiple monitoring components have issues. Immediate attention required.');
  }

  console.log('\n📊 Access URLs:');
  console.log(`  • Grafana:     http://localhost:${config.grafana.port} (admin/admin123)`);
  console.log(`  • Prometheus:   http://localhost:${config.prometheus.port}`);
  console.log(`  • Alertmanager: http://localhost:${config.alertmanager.port}`);
  console.log(`  • Metrics:      http://localhost:${config.monitoring.port}/metrics`);

  return healthScore;
}

async function main() {
  console.log('🧠 Cortex MCP Monitoring Verification');
  console.log('=====================================');
  console.log('');

  const results = {};

  // Run all checks
  results.servicesHealth = await checkService('Cortex MCP Metrics', config.monitoring);
  results.grafanaHealth = await checkService('Grafana', config.grafana);
  results.prometheusHealth = await checkService('Prometheus', config.prometheus);

  if (results.servicesHealth) {
    results.metricsAvailable = await checkMetrics();
  }

  if (results.prometheusHealth) {
    results.prometheusTargets = await checkPrometheusTargets();
    results.alertsStatus = await checkAlerts();
  }

  if (results.grafanaHealth) {
    results.grafanaDatasource = await checkGrafanaDatasource();
    results.dashboardAvailability = await checkDashboardAvailability();
  }

  // Generate final report
  const healthScore = await generateHealthReport(results);

  // Exit with appropriate code
  process.exit(healthScore === 100 ? 0 : 1);
}

// Handle script arguments
const command = process.argv[2];

if (command === '--help' || command === '-h') {
  console.log('Cortex MCP Monitoring Verification Script');
  console.log('');
  console.log('Usage: node scripts/verify-monitoring.js [options]');
  console.log('');
  console.log('Options:');
  console.log('  --help, -h     Show this help message');
  console.log('  --verbose      Enable verbose logging');
  console.log('');
  console.log('Environment Variables:');
  console.log('  MONITORING_PORT     Cortex MCP monitoring port (default: 9090)');
  console.log('  GRAFANA_PORT        Grafana port (default: 3000)');
  console.log('  PROMETHEUS_PORT     Prometheus port (default: 9091)');
  console.log('  ALERTMANAGER_PORT   Alertmanager port (default: 9093)');
  console.log('');
  process.exit(0);
} else {
  main().catch((error) => {
    log('error', `Verification failed: ${error.message}`);
    process.exit(1);
  });
}
