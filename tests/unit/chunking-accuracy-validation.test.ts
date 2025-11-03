/**
 * Comprehensive Chunking Accuracy Validation Tests
 *
 * Validates the ≥99.5% accuracy requirement for the Cortex MCP chunking system.
 * Tests semantic boundary detection, content preservation, and performance metrics.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { KnowledgeItem } from '../../src/types/core-interfaces.js';
import { ChunkingService } from '../../src/services/chunking/chunking-service.js';
import { MockEmbeddingService } from '../utils/mock-embedding-service.js';
import {
  getDocumentWithChunks,
  verifyDocumentReassembly,
  type DocumentWithChunks
} from '../../src/services/document-reassembly.js';

describe('Chunking Accuracy Validation - ≥99.5% Requirement', () => {
  let chunkingService: ChunkingService;
  let embeddingService: MockEmbeddingService;

  beforeEach(() => {
    // Create mock embedding service configured for semantic analysis
    embeddingService = new MockEmbeddingService({
      shouldFail: false,
      failMethod: 'none',
      latency: 0,
      semanticBoundaries: true,
    });

    chunkingService = new ChunkingService(
      1200, // maxCharsPerChunk
      200,  // overlapSize
      embeddingService as any
    );
  });

  afterEach(() => {
    // Clean up resources
  });

  /**
   * Calculate comprehensive text similarity metrics
   */
  function calculateTextSimilarity(text1: string, text2: string): number {
    // Character-based similarity (Levenshtein distance)
    const charSimilarity = calculateCharSimilarity(text1, text2);

    // Word-based similarity (Jaccard index)
    const wordSimilarity = calculateWordSimilarity(text1, text2);

    // Sequence-based similarity (n-gram overlap)
    const sequenceSimilarity = calculateSequenceSimilarity(text1, text2, 3);

    // Semantic similarity (weighted by importance)
    // For testing purposes, we use a weighted average
    return (charSimilarity * 0.2) + (wordSimilarity * 0.4) + (sequenceSimilarity * 0.4);
  }

  function calculateCharSimilarity(text1: string, text2: string): number {
    const longer = text1.length > text2.length ? text1 : text2;
    const shorter = text1.length > text2.length ? text2 : text1;

    if (longer.length === 0) return 1.0;

    const editDistance = calculateLevenshteinDistance(longer, shorter);
    return (longer.length - editDistance) / longer.length;
  }

  function calculateWordSimilarity(text1: string, text2: string): number {
    const words1 = text1.toLowerCase().split(/\s+/).filter(w => w.length > 0);
    const words2 = text2.toLowerCase().split(/\s+/).filter(w => w.length > 0);

    const set1 = new Set(words1);
    const set2 = new Set(words2);

    const intersection = new Set([...set1].filter(x => set2.has(x)));
    const union = new Set([...set1, ...set2]);

    return intersection.size / union.size;
  }

  function calculateSequenceSimilarity(text1: string, text2: string, n: number = 3): number {
    function getNGrams(text: string, n: number): Set<string> {
      const ngrams = new Set<string>();
      const words = text.toLowerCase().split(/\s+/).filter(w => w.length > 0);

      for (let i = 0; i <= words.length - n; i++) {
        ngrams.add(words.slice(i, i + n).join(' '));
      }

      return ngrams;
    }

    const ngrams1 = getNGrams(text1, n);
    const ngrams2 = getNGrams(text2, n);

    const intersection = new Set([...ngrams1].filter(x => ngrams2.has(x)));
    const union = new Set([...ngrams1, ...ngrams2]);

    return union.size > 0 ? intersection.size / union.size : 1.0;
  }

  function calculateLevenshteinDistance(str1: string, str2: string): number {
    const matrix = [];

    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  /**
   * Test data generators for different content types
   */
  function generateLargeTechnicalDocument(size: number = 15000): string {
    const sections = [
      `# Advanced Machine Learning Systems Architecture

## Executive Summary

This comprehensive document outlines the architecture and implementation of large-scale machine learning systems designed for enterprise deployment. The system processes millions of data points daily while maintaining high availability and performance standards.

## System Overview

Our machine learning platform consists of multiple interconnected components that work together to provide end-to-end ML pipeline capabilities:

1. **Data Ingestion Layer**
   - Real-time data streaming via Apache Kafka
   - Batch data processing with Apache Spark
   - Data validation and quality assurance
   - Schema management and evolution

2. **Feature Engineering Pipeline**
   - Automated feature extraction and selection
   - Real-time feature computation
   - Feature store for online and offline serving
   - Feature monitoring and drift detection

3. **Model Training Infrastructure**
   - Distributed training on GPU clusters
   - Hyperparameter optimization with Bayesian methods
   - Experiment tracking and model registry
   - Automated model evaluation and validation

4. **Serving and Deployment**
   - Real-time inference via REST APIs
   - Batch inference for large-scale predictions
   - Model versioning and A/B testing
   - Performance monitoring and auto-scaling

## Technical Architecture

### Data Flow Architecture

The system follows a lambda architecture pattern with separate paths for real-time and batch processing:

**Real-time Path:**
- Data arrives through Kafka topics
- Stream processing with Apache Flink
- Real-time feature computation
- Online model serving with sub-second latency

**Batch Path:**
- Historical data processed with Spark
- Feature recomputation and backfilling
- Model retraining on updated datasets
- Batch predictions for offline use cases

### Model Management

Our approach to model management includes:

**Model Lifecycle:**
- Development: Local experimentation and validation
- Staging: Pre-production testing and validation
- Production: Live serving with monitoring
- Retirement: Graceful model deprecation and replacement

**Versioning Strategy:**
- Semantic versioning for model releases
- Immutable model artifacts
- Rollback capabilities for quick recovery
- Canary deployments for gradual rollout

### Scalability Considerations

The system is designed to handle:

**Horizontal Scaling:**
- Stateless services for easy scaling
- Load balancing across multiple instances
- Database sharding for large datasets
- Caching layers for performance optimization

**Performance Optimization:**
- Vectorized operations for numerical computing
- GPU acceleration for deep learning models
- Memory management for large datasets
- Network optimization for distributed computing`,

      `## Implementation Details

### Core Technologies

Our technology stack includes:

**Backend Services:**
- Python 3.9+ with FastAPI for API services
- Node.js with TypeScript for frontend services
- Java with Spring Boot for enterprise integration
- Go for high-performance microservices

**Data Technologies:**
- PostgreSQL for relational data
- MongoDB for document storage
- Redis for caching and session management
- Elasticsearch for search and analytics

**ML/AI Technologies:**
- TensorFlow and PyTorch for deep learning
- Scikit-learn for traditional ML algorithms
- MLflow for experiment tracking
- Kubeflow for ML pipeline orchestration

### Security and Compliance

**Data Protection:**
- Encryption at rest and in transit
- Role-based access control (RBAC)
- Data masking for sensitive information
- Audit logging for compliance requirements

**Model Security:**
- Model validation and sanitization
- Adversarial attack detection
- Input validation and preprocessing
- Output validation and monitoring

### Monitoring and Observability

**System Monitoring:**
- Prometheus for metrics collection
- Grafana for visualization
- AlertManager for notifications
- Jaeger for distributed tracing

**ML Monitoring:**
- Model performance tracking
- Data drift detection
- Concept drift monitoring
- Prediction confidence scoring`,

      `## Performance Benchmarks

### System Performance

Our system achieves the following performance metrics:

**Throughput:**
- Real-time inference: 10,000 requests/second
- Batch processing: 1TB data/hour
- Feature computation: 100,000 features/second
- Model training: 1M samples/hour on GPU cluster

**Latency:**
- API response time: P95 < 100ms
- Real-time inference: P95 < 50ms
- Data processing: P95 < 1 second
- Model loading: < 30 seconds

**Reliability:**
- System uptime: 99.9%
- Error rate: < 0.1%
- Data loss: 0% with replication
- Recovery time: < 5 minutes

### Model Performance

**Accuracy Metrics:**
- Classification tasks: 85-95% accuracy
- Regression tasks: R² > 0.8
- Recommendation systems: 70-80% precision@10
- Anomaly detection: 90%+ F1-score

**Efficiency Metrics:**
- Model size: < 100MB for deployment
- Inference time: < 50ms per prediction
- Memory usage: < 1GB per model
- CPU utilization: < 80% during peak load`,

      `## Best Practices and Guidelines

### Development Practices

**Code Quality:**
- Comprehensive unit test coverage (>90%)
- Integration tests for critical paths
- Code reviews for all changes
- Static analysis and security scanning

**Documentation:**
- API documentation with OpenAPI specs
- Model documentation with feature importance
- Architecture diagrams and decision records
- Runbooks for operational procedures

### Operational Excellence

**Deployment Practices:**
- Infrastructure as Code with Terraform
- Blue-green deployments for zero downtime
- Automated testing and validation
- Monitoring and alerting for all services

**Incident Response:**
- 24/7 on-call rotation
- Incident severity classification
- Post-incident reviews and improvement
- Knowledge base for common issues

### Continuous Improvement

**Performance Optimization:**
- Regular performance benchmarking
- Resource usage optimization
- Algorithm improvements and research
- Technology evaluation and adoption

**Innovation and Research:**
- Dedicated R&D time for engineers
- Collaboration with academic institutions
- Industry conference participation
- Internal tech talks and knowledge sharing`
    ];

    // Repeat sections to reach desired size
    let content = sections.join('\n\n');
    while (content.length < size) {
      content += '\n\n' + sections.join('\n\n');
    }

    return content.substring(0, size);
  }

  function generateMixedContentDocument(): string {
    return `
# Comprehensive Technical Documentation

## Overview

This document demonstrates various content types that the chunking system must handle correctly, including code blocks, tables, mathematical formulas, and structured data.

## Code Examples

### JavaScript Implementation

\`\`\`javascript
class DataProcessor {
  constructor(config) {
    this.config = config;
    this.cache = new Map();
    this.metrics = {
      processed: 0,
      errors: 0,
      startTime: Date.now()
    };
  }

  async processData(data) {
    try {
      // Validate input
      if (!Array.isArray(data)) {
        throw new Error('Input must be an array');
      }

      const results = [];
      for (const item of data) {
        const result = await this.processItem(item);
        results.push(result);
        this.metrics.processed++;
      }

      return results;
    } catch (error) {
      this.metrics.errors++;
      throw error;
    }
  }

  async processItem(item) {
    // Check cache first
    const cacheKey = this.generateCacheKey(item);
    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey);
    }

    // Process the item
    const processed = await this.transform(item);

    // Cache the result
    this.cache.set(cacheKey, processed);

    return processed;
  }

  generateCacheKey(item) {
    return JSON.stringify(item);
  }

  async transform(item) {
    // Simulate processing time
    await new Promise(resolve => setTimeout(resolve, 1));

    return {
      ...item,
      processed: true,
      timestamp: Date.now()
    };
  }

  getMetrics() {
    return {
      ...this.metrics,
      cacheSize: this.cache.size,
      uptime: Date.now() - this.metrics.startTime
    };
  }
}
\`\`\`

### Python Implementation

\`\`\`python
import asyncio
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ProcessingResult:
    success: bool
    data: Optional[Dict[str, Any]]
    error: Optional[str]
    timestamp: datetime
    processing_time: float

class AsyncDataProcessor:
    def __init__(self, max_concurrent: int = 10):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.logger = logging.getLogger(__name__)

    async def process_batch(self, items: List[Dict[str, Any]]) -> List[ProcessingResult]:
        """Process a batch of items concurrently"""
        tasks = [self.process_single_item(item) for item in items]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to error results
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append(ProcessingResult(
                    success=False,
                    data=None,
                    error=str(result),
                    timestamp=datetime.now(),
                    processing_time=0.0
                ))
            else:
                processed_results.append(result)

        return processed_results

    async def process_single_item(self, item: Dict[str, Any]) -> ProcessingResult:
        """Process a single item with semaphore control"""
        async with self.semaphore:
            start_time = datetime.now()

            try:
                # Simulate processing time
                await asyncio.sleep(0.01)

                processed_data = {
                    **item,
                    'processed': True,
                    'processing_id': f"proc_{id(item)}",
                    'timestamp': datetime.now().isoformat()
                }

                processing_time = (datetime.now() - start_time).total_seconds()

                return ProcessingResult(
                    success=True,
                    data=processed_data,
                    error=None,
                    timestamp=datetime.now(),
                    processing_time=processing_time
                )

            except Exception as e:
                processing_time = (datetime.now() - start_time).total_seconds()
                self.logger.error(f"Error processing item: {e}")

                return ProcessingResult(
                    success=False,
                    data=None,
                    error=str(e),
                    timestamp=datetime.now(),
                    processing_time=processing_time
                )
\`\`\`

## Mathematical Formulas

### Machine Learning Algorithms

**Linear Regression:**
The hypothesis function for linear regression is:

\$\$h_\\theta(x) = \\theta_0 + \\theta_1 x_1 + \\theta_2 x_2 + ... + \\theta_n x_n\$\$

The cost function (Mean Squared Error) is:

\$\$J(\\theta) = \\frac{1}{2m} \\sum_{i=1}^{m} (h_\\theta(x^{(i)}) - y^{(i)})^2\$\$

**Logistic Regression:**
The sigmoid function:

\$\$\\sigma(z) = \\frac{1}{1 + e^{-z}}\$\$

The cost function for logistic regression:

\$\$J(\\theta) = -\\frac{1}{m} \\sum_{i=1}^{m} [y^{(i)} \\log(h_\\theta(x^{(i)})) + (1 - y^{(i)}) \\log(1 - h_\\theta(x^{(i)}))]\$\$

**Neural Networks:**
Forward propagation for layer \$l\$:

\$\$z^{[l]} = W^{[l]} a^{[l-1]} + b^{[l]}\$\$
\$\$a^{[l]} = g(z^{[l]})\$\$

Where \$g\$ is the activation function (ReLU, sigmoid, tanh, etc.)

## Data Tables

### Performance Metrics

| Algorithm | Accuracy | Precision | Recall | F1-Score | Training Time |
|-----------|----------|-----------|--------|----------|---------------|
| Random Forest | 0.92 | 0.91 | 0.93 | 0.92 | 45s |
| SVM | 0.89 | 0.87 | 0.91 | 0.89 | 2.3s |
| Neural Network | 0.94 | 0.93 | 0.95 | 0.94 | 3.2s |
| Logistic Regression | 0.85 | 0.84 | 0.86 | 0.85 | 0.8s |

### System Configuration

| Component | Version | Memory | CPU | Status |
|-----------|---------|---------|-----|--------|
| Database | PostgreSQL 14 | 16GB | 4 cores | Active |
| Cache | Redis 7.0 | 8GB | 2 cores | Active |
| Message Queue | Kafka 3.2 | 32GB | 8 cores | Active |
| Web Server | Nginx 1.22 | 4GB | 2 cores | Active |

## Configuration Files

### Docker Compose

\`\`\`yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://user:pass@db:5432/myapp
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    volumes:
      - ./logs:/app/logs
    deploy:
      replicas: 3
      resources:
        limits:
          memory: 512M
          cpus: '0.5'

  db:
    image: postgres:14
    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
\`\`\`

### Kubernetes Deployment

\`\`\`yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ml-app
  labels:
    app: ml-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ml-app
  template:
    metadata:
      labels:
        app: ml-app
    spec:
      containers:
      - name: ml-app
        image: my-registry/ml-app:latest
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: url
        - name: REDIS_URL
          valueFrom:
            configMapKeyRef:
              name: app-config
              key: redis-url
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
\`\`\`

## JSON Schemas

### API Response Schema

\`\`\`json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "success": {
      "type": "boolean",
      "description": "Whether the operation was successful"
    },
    "data": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "id": {
            "type": "string",
            "format": "uuid"
          },
          "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 100
          },
          "value": {
            "type": "number",
            "minimum": 0
          },
          "category": {
            "type": "string",
            "enum": ["type1", "type2", "type3"]
          },
          "timestamp": {
            "type": "string",
            "format": "date-time"
          }
        },
        "required": ["id", "name", "value", "category", "timestamp"]
      }
    },
    "pagination": {
      "type": "object",
      "properties": {
        "page": {
          "type": "integer",
          "minimum": 1
        },
        "limit": {
          "type": "integer",
          "minimum": 1,
          "maximum": 100
        },
        "total": {
          "type": "integer",
          "minimum": 0
        },
        "totalPages": {
          "type": "integer",
          "minimum": 0
        }
      },
      "required": ["page", "limit", "total", "totalPages"]
    },
    "errors": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "code": {
            "type": "string"
          },
          "message": {
            "type": "string"
          },
          "field": {
            "type": "string"
          }
        }
      }
    }
  },
  "required": ["success", "data", "pagination"]
}
\`\`\`

## Additional Content for Size Requirements

${'Extended technical documentation covering advanced topics including microservices architecture, distributed systems design, data engineering pipelines, machine learning operations (MLOps), cloud deployment strategies, security best practices, performance optimization techniques, monitoring and alerting systems, CI/CD pipeline implementation, infrastructure as code, container orchestration, API design principles, database optimization, caching strategies, load balancing, fault tolerance, disaster recovery, compliance and governance, team collaboration workflows, agile development methodologies, and quality assurance processes. '.repeat(20)}
    `.trim();
  }

  function generateVeryShortContent(): string {
    return 'Short content that should not be chunked.';
  }

  function generateEdgeCaseContent(): string {
    return `
# Edge Case Document

## Special Characters

This document contains special characters: é à ñ ç ü ø 中文 العربية русский

## Unicode and Emoji

Testing Unicode support: 🚀 🎯 ✅ ❌ 💡 📊 📈 💻 🌍

## Extreme Lengths

${'This is a very long paragraph that tests the chunking system\'s ability to handle extreme content lengths. '.repeat(1000)}

## Mixed Formats

- Bullet points with **bold** and *italic* text
- [Links](https://example.com) and \`code spans\`
- Numbers: 1, 2, 3 and symbols: @#$%^&*()

## Code Blocks

\`\`\`python
def edge_case_function(param1, param2, param3=None, param4="default", param5=42):
    """Function with many parameters"""
    result = []
    for i in range(100):
        result.append({
            'id': i,
            'value': param1 * i,
            'name': f'item_{i}',
            'metadata': {
                'created': datetime.now(),
                'modified': datetime.now(),
                'version': '1.0.0'
            }
        })
    return result
\`\`\`

## Empty Sections

## Conclusion

This document tests various edge cases for the chunking system.
    `.trim();
  }

  describe('Core Chunking Accuracy Tests', () => {
    it('should achieve ≥99.5% accuracy on large technical documents', async () => {
      const largeContent = generateLargeTechnicalDocument(15000);

      const knowledgeItem: KnowledgeItem = {
        id: 'large-tech-doc-test',
        kind: 'section', // This type should be chunked
        scope: {
          project: 'chunking-accuracy-test',
          branch: 'main',
          org: 'test-organization'
        },
        data: {
          content: largeContent,
          title: 'Large Technical Document for Accuracy Testing',
          category: 'technical-documentation',
          author: 'test-team',
          complexity: 'high',
          expected_chunks: Math.ceil(largeContent.length / 1200)
        },
        metadata: {
          version: '1.0.0',
          test_type: 'accuracy-validation',
          content_hash: createHash('sha256').update(largeContent).digest('hex')
        },
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };

      // Apply chunking
      const startTime = Date.now();
      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);
      const chunkingTime = Date.now() - startTime;

      // Verify chunking results
      expect(chunkedItems.length).toBeGreaterThan(2);

      const parentItem = chunkedItems.find(item => !item.data.is_chunk);
      const childChunks = chunkedItems.filter(item => item.data.is_chunk);

      expect(parentItem).toBeDefined();
      expect(childChunks.length).toBeGreaterThan(1);
      expect(parentItem?.data.total_chunks).toBe(childChunks.length);

      // Test document reassembly
      const reassemblyStartTime = Date.now();
      const reassembledDoc = await getDocumentWithChunks(parentItem!.id, {
        include_metadata: true,
        preserve_chunk_markers: false,
        sort_by_position: true
      });
      const reassemblyTime = Date.now() - reassemblyStartTime;

      expect(reassembledDoc).toBeDefined();
      expect(reassembledDoc!.chunks.length).toBe(childChunks.length);

      // Calculate accuracy metrics
      const originalContent = largeContent;
      const reassembledContent = reassembledDoc!.reassembled_content;

      // Normalize contents for comparison
      const normalizedOriginal = originalContent.replace(/\s+/g, ' ').trim();
      const normalizedReassembled = reassembledContent.replace(/\s+/g, ' ').trim();

      const similarityRatio = calculateTextSimilarity(normalizedOriginal, normalizedReassembled);

      // Verify ≥99.5% accuracy requirement
      expect(similarityRatio).toBeGreaterThanOrEqual(0.995);

      // Verify content preservation - key sections should be present
      expect(reassembledContent).toContain('Advanced Machine Learning Systems Architecture');
      expect(reassembledContent).toContain('System Overview');
      expect(reassembledContent).toContain('Technical Architecture');
      expect(reassembledContent).toContain('Implementation Details');
      expect(reassembledContent).toContain('Performance Benchmarks');
      expect(reassembledContent).toContain('Best Practices and Guidelines');

      // Performance validation
      expect(chunkingTime).toBeLessThan(5000); // Should complete within 5 seconds
      expect(reassemblyTime).toBeLessThan(2000); // Should complete within 2 seconds

      // Verify document reassembly verification
      const verificationResult = await verifyDocumentReassembly(parentItem!.id);
      expect(verificationResult.is_complete).toBe(true);
      expect(verificationResult.integrity_verified).toBe(true);
      expect(verificationResult.integrity_score).toBeGreaterThanOrEqual(0.95);
      expect(verificationResult.missing_chunks.length).toBe(0);
      expect(verificationResult.duplicate_chunks.length).toBe(0);

      // Log results for reporting
      console.log(`Large Document Accuracy Test Results:`);
      console.log(`- Document size: ${originalContent.length} characters`);
      console.log(`- Chunks created: ${childChunks.length}`);
      console.log(`- Chunking time: ${chunkingTime}ms`);
      console.log(`- Reassembly time: ${reassemblyTime}ms`);
      console.log(`- Accuracy: ${(similarityRatio * 100).toFixed(3)}%`);
      console.log(`- Integrity score: ${(verificationResult.integrity_score * 100).toFixed(3)}%`);
    });

    it('should handle mixed content types with ≥99.5% accuracy', async () => {
      const mixedContent = generateMixedContentDocument();

      expect(mixedContent.length).toBeGreaterThan(10000);

      const knowledgeItem: KnowledgeItem = {
        id: 'mixed-content-test',
        kind: 'runbook', // This type should be chunked
        scope: {
          project: 'mixed-content-test',
          branch: 'main',
          org: 'test-organization'
        },
        data: {
          content: mixedContent,
          title: 'Mixed Content Document',
          category: 'comprehensive-documentation',
          author: 'test-team',
          content_types: ['code', 'tables', 'formulas', 'config']
        },
        metadata: {
          version: '1.0.0',
          test_type: 'mixed-content-validation'
        }
      };

      // Apply chunking
      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);
      const parentItem = chunkedItems.find(item => !item.data.is_chunk);
      const childChunks = chunkedItems.filter(item => item.data.is_chunk);

      // Test reassembly
      const reassembledDoc = await getDocumentWithChunks(parentItem!.id);
      const reassembledContent = reassembledDoc!.reassembled_content;

      // Verify code blocks are preserved
      expect(reassembledContent).toContain('class DataProcessor');
      expect(reassembledContent).toContain('async processData(data)');
      expect(reassembledContent).toContain('class AsyncDataProcessor');
      expect(reassembledContent).toContain('async process_batch');

      // Verify mathematical formulas
      expect(reassembledContent).toContain('$h_\\theta(x) = \\theta_0');
      expect(reassembledContent).toContain('$\\sigma(z) = \\frac{1}{1 + e^{-z}}$');
      expect(reassembledContent).toContain('$z^{[l]} = W^{[l]} a^{[l-1]} + b^{[l]}$');

      // Verify tables are preserved
      expect(reassembledContent).toContain('Random Forest');
      expect(reassembledContent).toContain('PostgreSQL 14');
      expect(reassembledContent).toContain('16GB');

      // Verify configuration files
      expect(reassembledContent).toContain('version: \'3.8\'');
      expect(reassembledContent).toContain('POSTGRES_DB: myapp');
      expect(reassembledContent).toContain('apiVersion: apps/v1');

      // Verify JSON schema
      expect(reassembledContent).toContain('$schema": "http://json-schema.org/draft-07/schema#"');
      expect(reassembledContent).toContain('"success": { "type": "boolean" }');

      // Calculate accuracy
      const normalizedOriginal = mixedContent.replace(/\s+/g, ' ').trim();
      const normalizedReassembled = reassembledContent.replace(/\s+/g, ' ').trim();
      const similarityRatio = calculateTextSimilarity(normalizedOriginal, normalizedReassembled);

      expect(similarityRatio).toBeGreaterThanOrEqual(0.995);

      console.log(`Mixed Content Test Results:`);
      console.log(`- Document size: ${mixedContent.length} characters`);
      console.log(`- Chunks created: ${childChunks.length}`);
      console.log(`- Accuracy: ${(similarityRatio * 100).toFixed(3)}%`);
    });

    it('should correctly handle very short content without chunking', async () => {
      const shortContent = generateVeryShortContent();

      const knowledgeItem: KnowledgeItem = {
        id: 'short-content-test',
        kind: 'section',
        scope: {
          project: 'short-content-test',
          branch: 'main'
        },
        data: {
          content: shortContent,
          title: 'Short Content Test'
        }
      };

      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);

      // Should not be chunked
      expect(chunkedItems).toHaveLength(1);
      expect(chunkedItems[0].data.is_chunk).toBe(false);
      expect(chunkedItems[0].data.total_chunks).toBe(1);
      expect(chunkedItems[0].data.content).toBe(shortContent);

      console.log(`Short Content Test Results:`);
      console.log(`- Document size: ${shortContent.length} characters`);
      console.log(`- Chunks created: 1 (no chunking applied)`);
      console.log(`- Accuracy: 100% (no processing needed)`);
    });

    it('should handle edge cases and special characters with ≥99.5% accuracy', async () => {
      const edgeCaseContent = generateEdgeCaseContent();

      const knowledgeItem: KnowledgeItem = {
        id: 'edge-case-test',
        kind: 'incident',
        scope: {
          project: 'edge-case-test',
          branch: 'main'
        },
        data: {
          content: edgeCaseContent,
          title: 'Edge Case Document',
          test_type: 'edge_cases'
        }
      };

      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);
      const parentItem = chunkedItems.find(item => !item.data.is_chunk);
      const childChunks = chunkedItems.filter(item => item.data.is_chunk);

      const reassembledDoc = await getDocumentWithChunks(parentItem!.id);
      const reassembledContent = reassembledDoc!.reassembled_content;

      // Verify special characters are preserved
      expect(reassembledContent).toContain('é à ñ ç ü ø');
      expect(reassembledContent).toContain('中文');
      expect(reassembledContent).toContain('العربية');
      expect(reassembledContent).toContain('русский');

      // Verify emojis are preserved
      expect(reassembledContent).toContain('🚀 🎯 ✅ ❌ 💡 📊 📈 💻 🌍');

      // Verify code blocks with special content
      expect(reassembledContent).toContain('def edge_case_function');
      expect(reassembledContent).toContain('datetime.now()');
      expect(reassembledContent).toContain("'item_{i}'");

      // Calculate accuracy
      const normalizedOriginal = edgeCaseContent.replace(/\s+/g, ' ').trim();
      const normalizedReassembled = reassembledContent.replace(/\s+/g, ' ').trim();
      const similarityRatio = calculateTextSimilarity(normalizedOriginal, normalizedReassembled);

      expect(similarityRatio).toBeGreaterThanOrEqual(0.995);

      console.log(`Edge Case Test Results:`);
      console.log(`- Document size: ${edgeCaseContent.length} characters`);
      console.log(`- Chunks created: ${childChunks.length}`);
      console.log(`- Accuracy: ${(similarityRatio * 100).toFixed(3)}%`);
    });
  });

  describe('Performance and Scalability Tests', () => {
    it('should handle very large documents (>20k characters) efficiently', async () => {
      const veryLargeContent = generateLargeTechnicalDocument(25000);

      const knowledgeItem: KnowledgeItem = {
        id: 'very-large-doc-test',
        kind: 'section',
        scope: {
          project: 'performance-test',
          branch: 'main'
        },
        data: {
          content: veryLargeContent,
          title: 'Very Large Document Performance Test'
        }
      };

      // Measure chunking performance
      const chunkingStartTime = Date.now();
      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);
      const chunkingTime = Date.now() - chunkingStartTime;

      // Performance assertions
      expect(chunkingTime).toBeLessThan(10000); // Should complete within 10 seconds

      const parentItem = chunkedItems.find(item => !item.data.is_chunk);
      const childChunks = chunkedItems.filter(item => item.data.is_chunk);

      // Verify chunk distribution
      const chunkSizes = childChunks.map(chunk => chunk.data.content.length);
      const avgChunkSize = chunkSizes.reduce((a, b) => a + b, 0) / chunkSizes.length;
      const minChunkSize = Math.min(...chunkSizes);
      const maxChunkSize = Math.max(...chunkSizes);

      expect(avgChunkSize).toBeGreaterThan(800); // Reasonable chunk size
      expect(avgChunkSize).toBeLessThan(1500);  // Not too large
      expect(minChunkSize).toBeGreaterThan(50); // No extremely small chunks
      expect(maxChunkSize).toBeLessThan(2500);  // No extremely large chunks

      // Test reassembly performance
      const reassemblyStartTime = Date.now();
      const reassembledDoc = await getDocumentWithChunks(parentItem!.id);
      const reassemblyTime = Date.now() - reassemblyStartTime;

      expect(reassemblyTime).toBeLessThan(3000); // Should complete within 3 seconds

      // Calculate accuracy
      const normalizedOriginal = veryLargeContent.replace(/\s+/g, ' ').trim();
      const normalizedReassembled = reassembledDoc!.reassembled_content.replace(/\s+/g, ' ').trim();
      const similarityRatio = calculateTextSimilarity(normalizedOriginal, normalizedReassembled);

      expect(similarityRatio).toBeGreaterThanOrEqual(0.995);

      console.log(`Very Large Document Performance Test Results:`);
      console.log(`- Document size: ${veryLargeContent.length} characters`);
      console.log(`- Chunks created: ${childChunks.length}`);
      console.log(`- Chunking time: ${chunkingTime}ms`);
      console.log(`- Reassembly time: ${reassemblyTime}ms`);
      console.log(`- Average chunk size: ${Math.round(avgChunkSize)} characters`);
      console.log(`- Min/Max chunk size: ${minChunkSize}/${maxChunkSize} characters`);
      console.log(`- Accuracy: ${(similarityRatio * 100).toFixed(3)}%`);
    });

    it('should maintain performance with multiple concurrent chunking operations', async () => {
      const documents = Array.from({ length: 5 }, (_, i) => ({
        id: `concurrent-test-${i}`,
        kind: 'section' as const,
        scope: {
          project: 'concurrent-test',
          branch: 'main'
        },
        data: {
          content: generateLargeTechnicalDocument(12000),
          title: `Concurrent Test Document ${i + 1}`
        }
      }));

      // Process all documents concurrently
      const startTime = Date.now();
      const results = await Promise.all(
        documents.map(doc => chunkingService.processItemsForStorage([doc]))
      );
      const totalTime = Date.now() - startTime;

      // Verify all documents were processed successfully
      expect(results).toHaveLength(5);

      // Verify accuracy for each document
      for (let index = 0; index < results.length; index++) {
        const chunkedItems = results[index];
        expect(chunkedItems.length).toBeGreaterThan(1);
        const parentItem = chunkedItems.find(item => !item.data.is_chunk);
        const childChunks = chunkedItems.filter(item => item.data.is_chunk);
        expect(childChunks.length).toBeGreaterThan(1);

        const reassembledDoc = await getDocumentWithChunks(parentItem!.id);
        const normalizedOriginal = documents[index].data.content.replace(/\s+/g, ' ').trim();
        const normalizedReassembled = reassembledDoc!.reassembled_content.replace(/\s+/g, ' ').trim();
        const similarityRatio = calculateTextSimilarity(normalizedOriginal, normalizedReassembled);
        expect(similarityRatio).toBeGreaterThanOrEqual(0.995);
      }

      // Performance should be reasonable (concurrent processing should be faster than sequential)
      expect(totalTime).toBeLessThan(20000); // Should complete within 20 seconds

      const totalCharacters = documents.reduce((sum, doc) => sum + doc.data.content.length, 0);
      const throughput = totalCharacters / (totalTime / 1000); // characters per second

      console.log(`Concurrent Processing Test Results:`);
      console.log(`- Documents processed: 5`);
      console.log(`- Total characters: ${totalCharacters}`);
      console.log(`- Total time: ${totalTime}ms`);
      console.log(`- Throughput: ${Math.round(throughput)} chars/sec`);
      console.log(`- Average time per document: ${Math.round(totalTime / 5)}ms`);
    });
  });

  describe('Chunk Quality and Consistency Tests', () => {
    it('should maintain consistent chunk sizes within acceptable ranges', async () => {
      const content = generateLargeTechnicalDocument(15000);

      const knowledgeItem: KnowledgeItem = {
        id: 'chunk-size-test',
        kind: 'section',
        scope: {
          project: 'chunk-quality-test',
          branch: 'main'
        },
        data: {
          content: content,
          title: 'Chunk Size Consistency Test'
        }
      };

      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);
      const childChunks = chunkedItems.filter(item => item.data.is_chunk);

      // Analyze chunk size distribution
      const chunkSizes = childChunks.map(chunk => chunk.data.content.length);
      const avgSize = chunkSizes.reduce((a, b) => a + b, 0) / chunkSizes.length;
      const variance = chunkSizes.reduce((sum, size) => sum + Math.pow(size - avgSize, 2), 0) / chunkSizes.length;
      const stdDev = Math.sqrt(variance);
      const minSize = Math.min(...chunkSizes);
      const maxSize = Math.max(...chunkSizes);

      // Consistency requirements
      expect(stdDev).toBeLessThan(avgSize * 0.5); // Standard deviation should be less than 50% of average
      expect(minSize).toBeGreaterThan(avgSize * 0.3); // Min should be at least 30% of average
      expect(maxSize).toBeLessThan(avgSize * 2.0); // Max should be at most 200% of average

      // Verify overlap is working correctly
      for (let i = 1; i < childChunks.length; i++) {
        const prevChunk = childChunks[i - 1].data.content;
        const currChunk = childChunks[i].data.content;

        // Check for overlap (last 200 chars of previous chunk should appear in current chunk)
        const prevEnd = prevChunk.slice(-200);
        const hasOverlap = currChunk.includes(prevEnd.slice(-100)); // At least some overlap
        expect(hasOverlap).toBe(true);
      }

      console.log(`Chunk Size Consistency Test Results:`);
      console.log(`- Number of chunks: ${childChunks.length}`);
      console.log(`- Average size: ${Math.round(avgSize)} characters`);
      console.log(`- Standard deviation: ${Math.round(stdDev)} characters`);
      console.log(`- Size range: ${minSize} - ${maxSize} characters`);
      console.log(`- Consistency ratio: ${(1 - stdDev / avgSize).toFixed(3)}`);
    });

    it('should preserve semantic boundaries and context', async () => {
      const structuredContent = `
# Research Paper: Quantum Computing Applications

## Abstract

This paper explores the practical applications of quantum computing in modern computational problems. We analyze the current state of quantum technology and its potential impact on various industries including cryptography, drug discovery, and financial modeling.

## 1. Introduction

Quantum computing represents a paradigm shift in computational capabilities, leveraging quantum mechanical phenomena such as superposition and entanglement to perform calculations that would be infeasible for classical computers.

The fundamental difference between quantum and classical computing lies in the basic unit of information: while classical computers use bits (0 or 1), quantum computers use qubits, which can exist in superposition of both states simultaneously.

## 2. Quantum Computing Fundamentals

### 2.1 Qubits and Superposition

A qubit is described by a state vector:
$$|\psi\\rangle = \\alpha|0\\rangle + \\beta|1\\rangle$$

where $\\alpha$ and $\\beta$ are complex amplitudes satisfying $|\\alpha|^2 + |\\beta|^2 = 1$.

### 2.2 Quantum Entanglement

Entanglement is a quantum phenomenon where qubits become correlated in such a way that the state of one qubit cannot be described independently of the others.

### 2.3 Quantum Gates

Quantum gates are the quantum equivalent of classical logic gates, operating on qubits to transform their states according to the laws of quantum mechanics.

## 3. Applications

### 3.1 Cryptography

Quantum computers pose a significant threat to current cryptographic systems, particularly RSA encryption, which relies on the difficulty of factoring large numbers.

### 3.2 Drug Discovery

Quantum computing can simulate molecular interactions at the quantum level, potentially revolutionizing drug discovery and development processes.

### 3.3 Financial Modeling

Complex financial calculations and optimization problems can benefit from quantum computing capabilities.

## 4. Current Challenges

Despite the promise of quantum computing, several challenges remain:

- Hardware limitations and error rates
- Qubit coherence times
- Scalability issues
- Algorithm development
- Cost and accessibility

## 5. Future Outlook

The field of quantum computing is rapidly evolving, with significant investments from both government and private sectors. Experts predict that practical quantum advantage for certain problems may be achieved within the next decade.

## 6. Conclusion

Quantum computing represents one of the most exciting frontiers in technology, with the potential to revolutionize multiple industries. While challenges remain, the progress in recent years suggests a bright future for quantum applications.

${'Extended research content, detailed technical explanations, mathematical derivations, experimental results, case studies, and comprehensive analysis to ensure adequate document size for chunking accuracy testing. '.repeat(50)}
      `.trim();

      const knowledgeItem: KnowledgeItem = {
        id: 'semantic-boundaries-test',
        kind: 'section',
        scope: {
          project: 'semantic-test',
          branch: 'main'
        },
        data: {
          content: structuredContent,
          title: 'Quantum Computing Research Paper',
          document_type: 'research_paper',
          has_structured_sections: true
        }
      };

      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);
      const childChunks = chunkedItems.filter(item => item.data.is_chunk);
      const reassembledDoc = await getDocumentWithChunks(chunkedItems[0].id);
      const reassembledContent = reassembledDoc!.reassembled_content;

      // Verify that major section boundaries are preserved
      const expectedSections = [
        '## Abstract',
        '## 1. Introduction',
        '## 2. Quantum Computing Fundamentals',
        '### 2.1 Qubits and Superposition',
        '### 2.2 Quantum Entanglement',
        '### 2.3 Quantum Gates',
        '## 3. Applications',
        '### 3.1 Cryptography',
        '### 3.2 Drug Discovery',
        '### 3.3 Financial Modeling',
        '## 4. Current Challenges',
        '## 5. Future Outlook',
        '## 6. Conclusion'
      ];

      expectedSections.forEach(section => {
        expect(reassembledContent).toContain(section);
      });

      // Verify mathematical formulas are preserved
      expect(reassembledContent).toContain('$|\\psi\\rangle = \\alpha|0\\rangle + \\beta|1\\rangle$');
      expect(reassembledContent).toContain('$|\\alpha|^2 + |\\beta|^2 = 1$');

      // Calculate accuracy
      const normalizedOriginal = structuredContent.replace(/\s+/g, ' ').trim();
      const normalizedReassembled = reassembledContent.replace(/\s+/g, ' ').trim();
      const similarityRatio = calculateTextSimilarity(normalizedOriginal, normalizedReassembled);

      expect(similarityRatio).toBeGreaterThanOrEqual(0.995);

      // Verify that chunks respect semantic boundaries where possible
      const chunksWithBoundaries = childChunks.filter(chunk => {
        const content = chunk.data.content;
        return expectedSections.some(section => content.includes(section));
      });

      // Most chunks should contain some section markers
      expect(chunksWithBoundaries.length).toBeGreaterThan(childChunks.length * 0.7);

      console.log(`Semantic Boundaries Test Results:`);
      console.log(`- Document size: ${structuredContent.length} characters`);
      console.log(`- Chunks created: ${childChunks.length}`);
      console.log(`- Chunks with section boundaries: ${chunksWithBoundaries.length}`);
      console.log(`- Accuracy: ${(similarityRatio * 100).toFixed(3)}%`);
    });
  });

  describe('Error Handling and Resilience Tests', () => {
    it('should handle malformed input gracefully', async () => {
      const malformedContent = `
# Malformed Content Test

This document contains various types of malformed content that the chunking system should handle gracefully.

${'Lorem ipsum dolor sit amet, '.repeat(1000)}${'incomplete sentence without punctuation'}

${''.repeat(100)}  // Multiple empty lines

\`\`\`javascript
function malformedFunction( {
  // Missing parameter
  return
}
\`\`\`

## Table without proper formatting

| Header 1 | Header 2 | Header 3
| Cell 1 | Cell 2
| Cell 4 | Cell 5 | Cell 6

## Mixed newlines


Inconsistent spacing    between    words

${'x'.repeat(10000)}  // Very long word
      `.trim();

      const knowledgeItem: KnowledgeItem = {
        id: 'malformed-content-test',
        kind: 'incident',
        scope: {
          project: 'error-handling-test',
          branch: 'main'
        },
        data: {
          content: malformedContent,
          title: 'Malformed Content Test',
          test_type: 'error_resilience'
        }
      };

      // Should not throw errors
      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);

      expect(chunkedItems.length).toBeGreaterThan(0);

      const parentItem = chunkedItems.find(item => !item.data.is_chunk);
      const childChunks = chunkedItems.filter(item => item.data.is_chunk);

      if (childChunks.length > 0) {
        // Test reassembly
        const reassembledDoc = await getDocumentWithChunks(parentItem!.id);
        const reassembledContent = reassembledDoc!.reassembled_content;

        // Verify key content is preserved despite malformed sections
        expect(reassembledContent).toContain('Malformed Content Test');
        expect(reassembledContent).toContain('Lorem ipsum dolor sit amet');
        expect(reassembledContent).toContain('function malformedFunction');

        // Calculate accuracy
        const normalizedOriginal = malformedContent.replace(/\s+/g, ' ').trim();
        const normalizedReassembled = reassembledContent.replace(/\s+/g, ' ').trim();
        const similarityRatio = calculateTextSimilarity(normalizedOriginal, normalizedReassembled);

        expect(similarityRatio).toBeGreaterThanOrEqual(0.995);
      }

      console.log(`Error Handling Test Results:`);
      console.log(`- Document size: ${malformedContent.length} characters`);
      console.log(`- Chunks created: ${childChunks.length}`);
      console.log(`- Error handling: SUCCESS (no exceptions thrown)`);
    });
  });
});