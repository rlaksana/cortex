# Z.AI Services Integration

Production-ready Z.AI service infrastructure with glm-4.6 model integration, comprehensive error handling, circuit breakers, and background job processing.

## Overview

This integration provides a complete AI service layer with:

- **Z.AI Client Service**: Direct integration with Z.AI's glm-4.6 model
- **AI Orchestrator**: Dual provider management with automatic failover
- **Background Processor**: Asynchronous job processing with priority queues
- **Configuration Management**: Environment-based configuration with validation
- **Comprehensive Monitoring**: Health checks, metrics, and performance tracking

## Architecture

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│   Z.AI Client       │    │   OpenAI Client     │    │  Background Jobs   │
│   (glm-4.6)         │    │   (Embeddings)      │    │  Processor          │
└─────────┬───────────┘    └─────────┬───────────┘    └─────────┬───────────┘
          │                        │                        │
          └────────────────────────┼────────────────────────┘
                                   │
                    ┌─────────────┴─────────────┐
                    │   AI Orchestrator        │
                    │   (Dual Provider Mgmt)    │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │   Services Manager        │
                    │   (Integration Layer)      │
                    └───────────────────────────┘
```

## Features

### Z.AI Client Service

- **Model Integration**: glm-4.6 model with full feature support
- **Circuit Breaker**: Automatic failure detection and recovery
- **Rate Limiting**: Configurable request throttling
- **Caching**: Intelligent response caching with TTL
- **Error Handling**: Comprehensive error classification and retry logic
- **Performance Monitoring**: Real-time metrics and health tracking

### AI Orchestrator

- **Dual Provider Support**: Z.AI (primary) + OpenAI (fallback)
- **Automatic Failover**: Seamless provider switching on failures
- **Health Monitoring**: Continuous provider health checks
- **Load Balancing**: Intelligent request distribution
- **Recovery Logic**: Automatic return to primary provider when healthy

### Background Processor

- **Priority Queues**: 4-level priority system (critical, high, normal, low)
- **Concurrent Processing**: Configurable worker pool
- **Retry Logic**: Exponential backoff with max attempts
- **Job Types**: Multiple AI operation types supported
- **Memory Management**: Automatic cleanup and job history limits
- **Persistence**: Optional job persistence for reliability

## Configuration

### Environment Variables

```bash
# Z.AI Configuration
ZAI_API_KEY=your_zai_api_key
ZAI_BASE_URL=https://api.z.ai/api/anthropic
ZAI_MODEL=glm-4.6
ZAI_TIMEOUT=30000
ZAI_MAX_RETRIES=3
ZAI_RATE_LIMIT_RPM=60

# OpenAI Configuration (for fallback)
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4-turbo-preview

# Orchestrator Configuration
ZAI_PRIMARY_PROVIDER=zai
ZAI_FALLBACK_PROVIDER=openai
ZAI_AUTO_FAILOVER=true
ZAI_HEALTH_CHECK_INTERVAL=30000

# Background Processor Configuration
ZAI_MAX_CONCURRENCY=10
ZAI_QUEUE_SIZE=1000
ZAI_RETRY_ATTEMPTS=3
ZAI_ENABLE_PRIORITY_QUEUE=true
```

### Programmatic Configuration

```typescript
import { zaiConfigManager } from './config/zai-config.js';

// Load configuration
await zaiConfigManager.loadConfig();

// Get configuration
const zaiConfig = zaiConfigManager.getZAIConfig();
const orchestratorConfig = zaiConfigManager.getOrchestratorConfig();
const processorConfig = zaiConfigManager.getBackgroundProcessorConfig();

// Update configuration
await zaiConfigManager.updateConfig({
  timeout: 60000,
  maxRetries: 5,
});
```

## Usage

### Basic Usage

```typescript
import { zaiServicesManager } from './services/ai/index.js';

// Initialize services
await zaiServicesManager.initialize();

// Generate completion
const response = await zaiServicesManager.generateCompletion({
  messages: [
    { role: 'system', content: 'You are a helpful assistant.' },
    { role: 'user', content: 'Hello, how are you?' },
  ],
  maxTokens: 1000,
  temperature: 0.7,
});

console.log(response.choices[0].message.content);
```

### Background Jobs

```typescript
// Submit text transformation job
const jobId = await zaiServicesManager.submitJob(
  'text_transformation',
  {
    text: 'Hello, World!',
    transformation: 'uppercase',
  },
  {
    priority: 'high',
    timeout: 30000,
    retries: 3,
  }
);

// Check job status
const jobStatus = backgroundProcessorService.getJobStatus(jobId);
console.log('Job status:', jobStatus?.status);
```

### Streaming Responses

```typescript
// Generate streaming completion
for await (const chunk of aiOrchestratorService.generateStreamingCompletion(request)) {
  if (chunk.choices[0].delta.content) {
    process.stdout.write(chunk.choices[0].delta.content);
  }
}
```

### Health Monitoring

```typescript
// Check service health
const health = await zaiServicesManager.healthCheck();
console.log('Overall status:', health.status);
console.log('Active provider:', health.orchestrator.activeProvider);

// Get comprehensive metrics
const metrics = zaiServicesManager.getMetrics();
console.log('Total requests:', metrics.zai.totalRequests);
console.log('Success rate:', 1 - metrics.zai.errorRate);
console.log('Average latency:', metrics.zai.averageResponseTime);
```

## Job Types

### Supported Background Job Types

1. **chat_completion**: Standard chat completion requests
2. **batch_completion**: Multiple chat completions in batch
3. **embedding_generation**: Text embedding generation
4. **content_analysis**: Content analysis and insights
5. **text_transformation**: Text transformation (uppercase, lowercase, etc.)
6. **summarization**: Text summarization with length options
7. **classification**: Text classification with custom categories

### Job Examples

```typescript
// Content Analysis
const analysisJobId = await zaiServicesManager.submitJob('content_analysis', {
  content: 'Your text content here',
  analysisType: 'sentiment',
});

// Summarization
const summaryJobId = await zaiServicesManager.submitJob('summarization', {
  text: 'Long text to summarize...',
  summaryLength: 'medium', // 'short', 'medium', 'long'
});

// Classification
const classificationJobId = await zaiServicesManager.submitJob('classification', {
  text: 'Text to classify',
  categories: ['urgent', 'normal', 'low'],
});
```

## Error Handling

### Error Types

```typescript
import { ZAIError, ZAIErrorType } from './types/zai-interfaces.js';

try {
  await zaiServicesManager.generateCompletion(request);
} catch (error) {
  if (error instanceof ZAIError) {
    switch (error.type) {
      case ZAIErrorType.AUTHENTICATION_ERROR:
        // Handle authentication issues
        break;
      case ZAIErrorType.RATE_LIMIT_ERROR:
        // Handle rate limiting
        break;
      case ZAIErrorType.NETWORK_ERROR:
        // Handle network issues
        break;
      // ... other error types
    }
  }
}
```

### Circuit Breaker

The system includes automatic circuit breaker functionality:

- **Failure Detection**: Tracks consecutive failures
- **Circuit Opening**: Stops requests after threshold
- **Half-Open State**: Tests recovery with limited requests
- **Automatic Recovery**: Returns to normal operation when healthy

## Performance Targets

- **Z.AI API Response Time**: <5s
- **Circuit Breaker Activation**: Within 3 failures
- **Background Job Processing**: <1s latency
- **Core Operations**: N=100 <1s

### Monitoring Metrics

```typescript
const metrics = zaiServicesManager.getMetrics();

// Z.AI Client Metrics
console.log('Z.AI Requests:', metrics.zai.totalRequests);
console.log('Z.AI Success Rate:', 1 - metrics.zai.errorRate);
console.log('Z.AI Avg Response Time:', metrics.zai.averageResponseTime);

// Background Processor Metrics
console.log('Jobs Processed:', metrics.backgroundProcessor.processor.totalJobsProcessed);
console.log('Job Success Rate:', metrics.backgroundProcessor.performance.successRate);
console.log('Avg Processing Time:', metrics.backgroundProcessor.performance.averageProcessingTime);
```

## Testing

Run the comprehensive test suite:

```bash
# Run all Z.AI integration tests
npm test -- src/services/ai/__tests__/zai-integration.test.ts

# Run with coverage
npm test -- --coverage src/services/ai
```

### Test Coverage

- Configuration management
- Service initialization and shutdown
- Error handling and recovery
- Background job processing
- Health monitoring
- Performance metrics
- Integration flows

## Monitoring and Observability

### Health Checks

```typescript
// Comprehensive health check
const health = await zaiServicesManager.healthCheck();

if (health.status === 'unhealthy') {
  // Implement alerting or recovery logic
  console.error('Z.AI services unhealthy:', health);
}
```

### Event Listeners

```typescript
import { zaiClientService, aiOrchestratorService } from './services/ai/index.js';

// Listen to Z.AI client events
zaiClientService.addEventListener(async (event) => {
  switch (event.type) {
    case 'request_started':
      console.log('Request started:', event.data.requestId);
      break;
    case 'request_completed':
      console.log('Request completed:', event.data.duration);
      break;
    case 'request_failed':
      console.error('Request failed:', event.data.error);
      break;
    case 'circuit_breaker_opened':
      console.warn('Circuit breaker opened:', event.data.provider);
      break;
  }
});

// Listen to orchestrator events
aiOrchestratorService.addEventListener(async (event) => {
  if (event.type === 'provider_failed_over') {
    console.warn('Provider failover:', event.data);
  }
});
```

## Production Deployment

### Environment Setup

1. **Required Environment Variables**:

   ```bash
   ZAI_API_KEY=your_production_api_key
   OPENAI_API_KEY=your_production_openai_key
   ```

2. **Configuration Validation**:

   ```typescript
   // Validate configuration before startup
   try {
     await zaiConfigManager.loadConfig();
     console.log('Configuration validated successfully');
   } catch (error) {
     console.error('Configuration validation failed:', error);
     process.exit(1);
   }
   ```

3. **Graceful Shutdown**:
   ```typescript
   process.on('SIGTERM', async () => {
     console.log('Shutting down Z.AI services...');
     await zaiServicesManager.shutdown();
     process.exit(0);
   });
   ```

### Scaling Considerations

- **Horizontal Scaling**: Each instance maintains its own circuit breaker state
- **Rate Limiting**: Configure per-instance limits to stay within API quotas
- **Background Processing**: Consider shared job queue for multi-instance deployments
- **Monitoring**: Implement centralized logging and metrics collection

## Troubleshooting

### Common Issues

1. **API Key Errors**:
   - Verify ZAI_API_KEY is set correctly
   - Check key vault configuration if using secure storage

2. **Rate Limiting**:
   - Monitor ZAI_RATE_LIMIT_RPM settings
   - Implement client-side rate limiting

3. **Circuit Breaker Issues**:
   - Check consecutive failure thresholds
   - Review timeout configurations

4. **Background Job Failures**:
   - Monitor job retry attempts
   - Check memory usage and queue sizes

### Debug Mode

```typescript
// Enable debug logging
process.env.ZAI_ENABLE_LOGGING = 'true';

// Get detailed status
const detailedHealth = await zaiServicesManager.healthCheck();
console.log('Detailed health:', JSON.stringify(detailedHealth, null, 2));
```

## API Reference

### Main Services

- **zaiServicesManager**: Main service orchestrator
- **zaiClientService**: Direct Z.AI API client
- **aiOrchestratorService**: Dual provider management
- **backgroundProcessorService**: Asynchronous job processing
- **zaiConfigManager**: Configuration management

### Key Interfaces

- **ZAIChatRequest**: Chat completion request format
- **ZAIChatResponse**: Chat completion response format
- **ZAIJob**: Background job definition
- **ZAIHealthCheckResponse**: Health check response format

See `types/zai-interfaces.ts` for complete type definitions.

## License

© 2025 Cortex Team. All rights reserved.
