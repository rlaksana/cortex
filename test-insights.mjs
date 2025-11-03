#!/usr/bin/env node

/**
 * Simple test script to verify insight generation functionality
 */

import { insightGenerationService } from './src/services/insights/insight-generation-service.js';

async function testInsightGeneration() {
  console.log('🧠 Testing Insight Generation Service...\n');

  // Test data with various patterns
  const testItems = [
    {
      id: 'item-1',
      kind: 'entity',
      content: 'Development team is working on authentication system',
      data: { content: 'Development team is working on authentication system' },
      scope: { project: 'auth-service' },
      created_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    },
    {
      id: 'item-2',
      kind: 'entity',
      content: 'Development team completed authentication module',
      data: { content: 'Development team completed authentication module' },
      scope: { project: 'auth-service' },
      created_at: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
    },
    {
      id: 'item-3',
      kind: 'issue',
      content: 'Critical bug found in payment processing system',
      data: { content: 'Critical bug found in payment processing system' },
      scope: { project: 'payment-service' },
      created_at: new Date().toISOString(),
    },
    {
      id: 'item-4',
      kind: 'issue',
      content: 'Performance issue in database queries',
      data: { content: 'Performance issue in database queries' },
      scope: { project: 'payment-service' },
      created_at: new Date().toISOString(),
    },
    {
      id: 'item-5',
      kind: 'issue',
      content: 'Security vulnerability in API endpoint',
      data: { content: 'Security vulnerability in API endpoint' },
      scope: { project: 'payment-service' },
      created_at: new Date().toISOString(),
    },
    {
      id: 'item-6',
      kind: 'todo',
      content: 'Implement user authentication feature',
      data: { content: 'Implement user authentication feature' },
      scope: { project: 'auth-service' },
      created_at: new Date().toISOString(),
    },
    {
      id: 'item-7',
      kind: 'todo',
      content: 'Add password reset functionality',
      data: { content: 'Add password reset functionality' },
      scope: { project: 'auth-service' },
      created_at: new Date().toISOString(),
    },
    {
      id: 'item-8',
      kind: 'decision',
      content: 'Decided to use OAuth 2.0 for authentication',
      data: { content: 'Decided to use OAuth 2.0 for authentication' },
      scope: { project: 'auth-service' },
      created_at: new Date().toISOString(),
    },
  ];

  try {
    console.log(`📝 Processing ${testItems.length} test items...\n`);

    // Generate insights
    const startTime = Date.now();
    const response = await insightGenerationService.generateInsights({
      items: testItems,
      options: {
        enabled: true,
        insight_types: ['patterns', 'connections', 'recommendations'],
        max_insights_per_item: 3,
        confidence_threshold: 0.5, // Lower threshold for testing
        include_metadata: true,
      },
      scope: { project: 'test-project' },
    });

    const processingTime = Date.now() - startTime;

    console.log('✅ Insight Generation Results:');
    console.log(`   Total Insights: ${response.metadata.total_insights}`);
    console.log(`   Processing Time: ${processingTime}ms`);
    console.log(`   Items Processed: ${response.metadata.items_processed}`);
    console.log(`   Average Confidence: ${response.metadata.average_confidence.toFixed(3)}`);
    console.log(`   Performance Impact: ${response.metadata.performance_impact.toFixed(2)}%\n`);

    // Group insights by type
    const insightsByType = response.metadata.insights_by_type;
    console.log('📊 Insights by Type:');
    Object.entries(insightsByType).forEach(([type, count]) => {
      console.log(`   ${type}: ${count}`);
    });

    if (response.insights.length > 0) {
      console.log('\n🔍 Generated Insights:');
      response.insights.forEach((insight, index) => {
        console.log(`\n${index + 1}. [${insight.type.toUpperCase()}] ${insight.title}`);
        console.log(`   Confidence: ${(insight.confidence * 100).toFixed(1)}%`);
        console.log(`   Priority: ${insight.priority}`);
        console.log(`   Actionable: ${insight.actionable ? 'Yes' : 'No'}`);
        console.log(`   Description: ${insight.description}`);

        if (insight.item_ids.length > 0) {
          console.log(`   Related Items: ${insight.item_ids.join(', ')}`);
        }

        // Show type-specific data
        if (insight.type === 'pattern' && insight.pattern_data) {
          console.log(`   Pattern: ${insight.pattern_data.pattern_type} (strength: ${insight.pattern_data.strength.toFixed(3)})`);
        } else if (insight.type === 'connection' && insight.connection_data) {
          console.log(`   Connection: ${insight.connection_data.connection_type} (strength: ${insight.connection_data.relationship_strength.toFixed(3)})`);
        } else if (insight.type === 'recommendation' && insight.recommendation_data) {
          console.log(`   Recommendation: ${insight.recommendation_data.action_type} (${insight.recommendation_data.priority} priority)`);
        }
      });
    }

    // Show any warnings
    if (response.warnings.length > 0) {
      console.log('\n⚠️  Warnings:');
      response.warnings.forEach(warning => {
        console.log(`   - ${warning}`);
      });
    }

    // Show any errors
    if (response.errors.length > 0) {
      console.log('\n❌ Errors:');
      response.errors.forEach(error => {
        console.log(`   - ${error.error_type}: ${error.message}`);
      });
    }

    // Get service metrics
    const metrics = insightGenerationService.getMetrics();
    console.log('\n📈 Service Metrics:');
    console.log(`   Total Insights Generated: ${metrics.total_insights_generated}`);
    console.log(`   Generation Success Rate: ${(metrics.generation_success_rate * 100).toFixed(1)}%`);
    console.log(`   Average Processing Time: ${metrics.processing_time_avg.toFixed(1)}ms`);
    console.log(`   Average Performance Impact: ${metrics.performance_impact_avg.toFixed(2)}%`);
    console.log(`   Cache Hit Rate: ${(metrics.cache_hit_rate * 100).toFixed(1)}%`);
    console.log(`   Error Rate: ${(metrics.error_rate * 100).toFixed(1)}%`);
    console.log(`   Last Updated: ${new Date(metrics.last_updated).toISOString()}`);

    console.log('\n🎉 Insight generation test completed successfully!');

  } catch (error) {
    console.error('❌ Error during insight generation test:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

// Check if we can import the required modules
try {
  // Test if we can import the insight service
  console.log('📦 Loading insight generation service...');
  await testInsightGeneration();
} catch (error) {
  console.error('❌ Failed to load insight generation service:', error.message);
  console.error('\n💡 Make sure you have built the project:');
  console.error('   npm run build');
  console.error('   # or');
  console.error('   npm run dev');
  process.exit(1);
}