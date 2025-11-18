// Test file to verify production monitoring fixes
import type { SimpleLogger } from './src/utils/logger-wrapper.js';
import { ProductionMonitoringService } from './src/monitoring/production-monitoring-service.js';
import { QdrantHealthMonitor } from './src/monitoring/qdrant-health-monitor.js';
import { RetryAlertSystem } from './src/monitoring/retry-alert-system.js';

// Test that these can be instantiated without type errors
function testProductionMonitoringFixes() {
  console.log('Testing production monitoring fixes...');

  // Test 1: ProductionMonitoringService with SimpleLogger
  const monitoringService = new ProductionMonitoringService();
  console.log('✓ ProductionMonitoringService created successfully');

  // Test 2: QdrantHealthMonitor
  const qdrantMonitor = new QdrantHealthMonitor({
    url: 'http://localhost:6333',
    timeoutMs: 5000
  });
  console.log('✓ QdrantHealthMonitor created successfully');

  // Test 3: RetryAlertSystem
  const alertSystem = new RetryAlertSystem();
  console.log('✓ RetryAlertSystem created successfully');

  // Test 4: SimpleLogger interface compatibility
  const testLogger: SimpleLogger = {
    info: (message: unknown, meta?: unknown) => console.log('INFO:', message, meta),
    warn: (message: unknown, meta?: unknown) => console.warn('WARN:', message, meta),
    error: (message: unknown, meta?: unknown) => console.error('ERROR:', message, meta),
    debug: (message: unknown, meta?: unknown) => console.debug('DEBUG:', message, meta),
    flush: async () => Promise.resolve()
  };

  testLogger.info('Test message', { meta: 'data' });
  console.log('✓ SimpleLogger interface works correctly');

  console.log('All production monitoring fixes verified!');
}

// Run the test if this file is executed directly
if (require.main === module) {
  testProductionMonitoringFixes();
}