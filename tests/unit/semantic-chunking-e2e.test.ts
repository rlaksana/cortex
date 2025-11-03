/**
 * Semantic Chunking End-to-End Test with 99.5% Accuracy Requirements
 *
 * This test validates the complete semantic chunking pipeline:
 * 1. Large content (>8k characters) semantic chunking
 * 2. Proper metadata assignment (parent_id, order, total_chunks)
 * 3. Document reassembly with 99.5%+ accuracy
 * 4. Edge cases and semantic coherence validation
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { KnowledgeItem } from '../../src/types/core-interfaces.js';
import { ChunkingService } from '../../src/services/chunking/chunking-service.js';
import { MockEmbeddingService } from '../utils/mock-embedding-service.js';
import { createMockSemanticAnalyzer } from '../utils/mock-semantic-analyzer.js';
import {
  getDocumentWithChunks,
  verifyDocumentReassembly,
  type DocumentWithChunks
} from '../../src/services/document-reassembly.js';

describe('Semantic Chunking End-to-End with 99.5% Accuracy', () => {
  let chunkingService: ChunkingService;
  let embeddingService: MockEmbeddingService;

  beforeEach(() => {
    // Create mock embedding service configured for semantic analysis
    embeddingService = new MockEmbeddingService({
      shouldFail: false,
      failMethod: 'none',
      latency: 0,
      semanticBoundaries: true, // Enable semantic boundary simulation
    });

    chunkingService = new ChunkingService(
      1200, // maxCharsPerChunk
      200,  // overlapSize
      embeddingService as any
    );

    // Replace semantic analyzer with enhanced mock
    const mockSemanticAnalyzer = createMockSemanticAnalyzer(embeddingService as any, {
      shouldFail: false,
      enableRealBoundaries: true,
    });
    (chunkingService as any).semanticAnalyzer = mockSemanticAnalyzer;
  });

  afterEach(() => {
    // Clean up resources
  });

  describe('Large Content Semantic Chunking (>8k characters)', () => {
    it('should chunk 10k+ character document with semantic boundaries', async () => {
      // Create a large technical document with clear semantic sections
      const largeTechnicalDoc = `
# Artificial Intelligence in Modern Healthcare

## Introduction

The integration of artificial intelligence (AI) technologies into healthcare systems represents one of the most significant technological advances of the 21st century. This comprehensive analysis explores the current state, applications, challenges, and future prospects of AI in healthcare delivery.

AI technologies are transforming every aspect of healthcare, from diagnostic imaging and drug discovery to personalized treatment plans and operational efficiency. The convergence of big data, computational power, and advanced algorithms has created unprecedented opportunities for improving patient outcomes while reducing costs.

## Machine Learning in Medical Diagnostics

### Diagnostic Imaging Analysis

Machine learning algorithms have demonstrated remarkable accuracy in medical image analysis. Deep learning models, particularly convolutional neural networks (CNNs), can identify patterns in medical images that may be subtle or invisible to human observers.

Key applications include:
- Radiology: Detecting tumors, fractures, and abnormalities in X-rays, CT scans, and MRIs
- Pathology: Analyzing tissue samples for cancerous cells and other diseases
- Dermatology: Identifying skin cancers and conditions from digital images
- Ophthalmology: Screening for diabetic retinopathy and other eye diseases

Studies have shown that AI systems can achieve diagnostic accuracy comparable to or exceeding that of human experts in specific domains. For example, Google's DeepMind algorithm for diabetic retinopathy screening achieved 94% accuracy, matching human ophthalmologists.

### Predictive Analytics for Disease Risk

Predictive models leverage patient data to identify individuals at high risk for various conditions. These models analyze electronic health records (EHRs), genetic information, lifestyle factors, and environmental data to generate risk scores.

Common predictive applications include:
- Cardiovascular disease risk assessment using factors like age, blood pressure, cholesterol levels, and family history
- Cancer risk prediction based on genetic markers, lifestyle factors, and environmental exposures
- Sepsis prediction in hospital settings using real-time vital signs and lab results
- Hospital readmission risk analysis to identify patients requiring additional support

## Natural Language Processing in Healthcare

### Clinical Documentation Enhancement

Natural Language Processing (NLP) technologies are revolutionizing clinical documentation. These systems can:
- Automatically transcribe physician-patient conversations
- Extract structured data from unstructured clinical notes
- Assist with medical coding and billing
- Generate clinical summaries and reports

Advanced NLP models like GPT-4 and specialized medical language models such as BioBERT can understand medical terminology, context, and relationships within clinical text.

### Clinical Decision Support Systems

NLP-powered decision support systems provide real-time assistance to healthcare providers:
- Drug interaction checking and allergy alerts
- Treatment guideline recommendations based on patient characteristics
- Clinical trial matching for eligible patients
- Evidence-based medicine retrieval at point of care

These systems can analyze vast amounts of medical literature and clinical guidelines to provide relevant, evidence-based recommendations tailored to individual patient cases.

## Robotics and Automation in Healthcare

### Surgical Robotics

Robotic surgical systems, such as the da Vinci Surgical System, enhance surgical precision and capabilities. These systems provide:
- Enhanced visualization with 3D high-definition cameras
- Improved dexterity with instruments that can rotate beyond human wrist capabilities
- Reduced tremor and hand motion scaling
- Remote surgery capabilities for specialized care

The global surgical robotics market is projected to reach $20 billion by 2025, driven by increasing adoption of minimally invasive procedures and technological advancements.

### Automated Laboratory Systems

Automation is transforming clinical laboratories with:
- Automated sample processing and analysis
- High-throughput screening systems
- Robotic specimen handling
- Integrated laboratory information management systems

These systems increase efficiency, reduce errors, and enable 24/7 laboratory operations, significantly improving turnaround times for critical tests.

## Challenges and Ethical Considerations

### Data Privacy and Security

The healthcare AI ecosystem faces significant data privacy challenges:
- Compliance with regulations like HIPAA and GDPR
- Secure data sharing for model training while protecting patient privacy
- Blockchain and federated learning as potential solutions
- The need for robust cybersecurity measures

### Algorithm Bias and Fairness

AI systems can perpetuate or amplify existing healthcare disparities:
- Training data may underrepresent certain populations
- Socioeconomic factors influencing healthcare access and outcomes
- Gender and racial biases in medical research data
- The importance of diverse and representative training datasets

### Regulatory and Legal Frameworks

The regulatory landscape for healthcare AI is evolving:
- FDA approval processes for AI-powered medical devices
- Liability considerations for AI-assisted diagnoses
- International standards and certification requirements
- The need for ongoing monitoring and validation

## Future Directions and Emerging Technologies

### Quantum Computing in Drug Discovery

Quantum computing promises revolutionary advances in pharmaceutical research:
- Molecular simulation at quantum mechanical accuracy
- Optimization of drug discovery processes
- Protein folding predictions for personalized medicine
- Accelerated clinical trial design and analysis

### Augmented Reality in Medical Training

AR technologies are transforming medical education:
- Interactive 3D anatomical models for learning
- Simulated surgical procedures with haptic feedback
- Remote assistance and mentoring capabilities
- Real-time data visualization during procedures

### Personalized Medicine and Genomics

AI-driven personalized medicine approaches include:
- Genomic analysis for targeted therapies
- Pharmacogenomics for drug response optimization
- Lifestyle and environmental factor integration
- Real-time treatment adjustment based on patient response

## Implementation Strategies and Best Practices

### Healthcare AI Integration Roadmap

Successful AI implementation requires:
1. Comprehensive needs assessment and stakeholder engagement
2. Infrastructure development and data standardization
3. Change management and workforce training
4. Phased implementation with continuous evaluation
5. Ongoing monitoring and improvement cycles

### Interdisciplinary Collaboration

Effective healthcare AI development requires collaboration between:
- Clinicians and healthcare providers
- Data scientists and AI researchers
- Engineers and software developers
- Policy makers and regulatory experts
- Patients and advocacy groups

## Conclusion

The integration of AI into healthcare represents a paradigm shift in medicine. While challenges remain, the potential benefits for patient outcomes, operational efficiency, and medical knowledge are unprecedented. Success will require thoughtful implementation, ongoing evaluation, and commitment to ethical principles.

As we move forward, the focus must remain on augmenting rather than replacing human healthcare providers, ensuring that AI technologies serve as tools to enhance human expertise and compassion in healing. The future of healthcare lies in the synergistic combination of human intelligence and artificial intelligence, working together to improve health outcomes for all.

${'Additional technical content and detailed case studies to extend document beyond 10,000 characters for comprehensive semantic chunking testing: '.repeat(100)}
      `.trim();

      // Validate document size meets requirements
      expect(largeTechnicalDoc.length).toBeGreaterThan(10000);

      // Create knowledge item for chunking
      const knowledgeItem: KnowledgeItem = {
        id: 'ai-healthcare-doc-001',
        kind: 'section', // This type should be chunked
        scope: {
          project: 'healthcare-ai-analysis',
          branch: 'main',
          org: 'medical-research'
        },
        data: {
          content: largeTechnicalDoc,
          title: 'Artificial Intelligence in Modern Healthcare',
          category: 'technical-analysis',
          author: 'ai-research-team',
          peer_reviewed: true,
          publication_date: '2025-01-15T10:00:00Z',
          tags: ['healthcare', 'artificial-intelligence', 'machine-learning', 'medical-diagnostics'],
        },
        metadata: {
          version: '2.1.0',
          reviewers: ['dr-smith', 'dr-jones', 'dr-chen'],
          confidence_score: 0.95,
          content_hash: createHash('sha256').update(largeTechnicalDoc).digest('hex'),
        },
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      // Apply semantic chunking
      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);

      // Verify chunking results
      expect(chunkedItems.length).toBeGreaterThan(2); // Should create multiple chunks

      // Find parent and child items
      const parentItem = chunkedItems.find(item => !item.data.is_chunk);
      const childChunks = chunkedItems.filter(item => item.data.is_chunk);

      expect(parentItem).toBeDefined();
      expect(childChunks.length).toBeGreaterThan(1);
      expect(parentItem?.data.total_chunks).toBe(childChunks.length);

      // Validate metadata integrity
      expect(parentItem?.data.original_length).toBe(largeTechnicalDoc.length);
      expect(parentItem?.metadata?.chunking_info?.was_chunked).toBe(true);
      expect(parentItem?.metadata?.chunking_info?.semantic_analysis_enabled).toBe(true);

      // Validate chunk metadata
      childChunks.forEach((chunk, index) => {
        expect(chunk.data.parent_id).toBe(parentItem!.id);
        expect(chunk.data.chunk_index).toBe(index);
        expect(chunk.data.total_chunks).toBe(childChunks.length);
        expect(chunk.data.is_chunk).toBe(true);
        expect(chunk.data.original_length).toBe(largeTechnicalDoc.length);
        expect(chunk.data.extracted_title).toBe('Artificial Intelligence in Modern Healthcare');
        expect(chunk.data.position_ratio).toBeCloseTo(index / (childChunks.length - 1), 1);
      });

      // Test document reassembly
      const reassembledDoc = await getDocumentWithChunks(parentItem!.id, {
        include_metadata: true,
        preserve_chunk_markers: false,
        sort_by_position: true,
      });

      expect(reassembledDoc).toBeDefined();
      expect(reassembledDoc!.chunks.length).toBe(childChunks.length);
      expect(reassembledDoc!.reassembled_content.length).toBeGreaterThan(8000);

      // Calculate reassembly accuracy
      const originalContent = largeTechnicalDoc;
      const reassembledContent = reassembledDoc!.reassembled_content;

      // Normalize both contents for comparison (remove extra whitespace)
      const normalizedOriginal = originalContent.replace(/\s+/g, ' ').trim();
      const normalizedReassembled = reassembledContent.replace(/\s+/g, ' ').trim();

      // Calculate similarity metrics
      const similarityRatio = calculateTextSimilarity(normalizedOriginal, normalizedReassembled);

      // Verify 99.5% accuracy requirement
      expect(similarityRatio).toBeGreaterThanOrEqual(0.995);

      // Verify content integrity - key sections should be preserved
      expect(reassembledContent).toContain('Artificial Intelligence in Modern Healthcare');
      expect(reassembledContent).toContain('Machine Learning in Medical Diagnostics');
      expect(reassembledContent).toContain('Natural Language Processing in Healthcare');
      expect(reassembledContent).toContain('Robotics and Automation in Healthcare');
      expect(reassembledContent).toContain('Challenges and Ethical Considerations');
      expect(reassembledContent).toContain('Future Directions and Emerging Technologies');
      expect(reassembledContent).toContain('Conclusion');

      // Verify document reassembly verification
      const verificationResult = await verifyDocumentReassembly(parentItem!.id);
      expect(verificationResult.is_complete).toBe(true);
      expect(verificationResult.integrity_verified).toBe(true);
      expect(verificationResult.integrity_score).toBeGreaterThanOrEqual(0.95);
      expect(verificationResult.missing_chunks.length).toBe(0);
      expect(verificationResult.duplicate_chunks.length).toBe(0);
    });

    it('should handle diverse content types with semantic coherence', async () => {
      // Create a mixed content document with various formats
      const mixedContentDoc = `
# Project Implementation Guide

## Executive Summary

This comprehensive guide outlines the implementation strategy for our enterprise-wide digital transformation initiative. The project spans multiple departments and requires careful coordination across technical, business, and operational teams.

## Technical Architecture

### System Components

Our implementation consists of the following key components:

1. **Frontend Application**
   - React-based web application with TypeScript
   - Responsive design supporting desktop and mobile devices
   - Progressive Web App (PWA) capabilities
   - Real-time updates using WebSockets

2. **Backend Services**
   - Node.js with Express framework
   - Microservices architecture
   - RESTful APIs and GraphQL endpoints
   - Event-driven communication using message queues

3. **Database Infrastructure**
   - PostgreSQL for relational data
   - Redis for caching and session management
   - Elasticsearch for search capabilities
   - MongoDB for document storage

### Integration Points

The system integrates with external services:
- Payment gateway: Stripe API
- Email service: SendGrid
- Cloud storage: AWS S3
- Monitoring: DataDog

## Implementation Timeline

### Phase 1: Foundation (Weeks 1-4)
- Infrastructure setup and configuration
- Development environment standardization
- CI/CD pipeline implementation
- Security framework establishment

\`\`\`javascript
// Example: CI/CD Pipeline Configuration
const pipeline = {
  stages: ['build', 'test', 'security-scan', 'deploy'],
  environment: {
    NODE_ENV: 'production',
    DATABASE_URL: process.env.DATABASE_URL,
    API_KEYS: {
      STRIPE: process.env.STRIPE_SECRET_KEY,
      SENDGRID: process.env.SENDGRID_API_KEY
    }
  },
  deployment: {
    strategy: 'blue-green',
    rollback_enabled: true,
    health_checks: ['/health', '/api/health']
  }
};
\`\`\`

### Phase 2: Core Features (Weeks 5-12)
- User authentication and authorization
- Core business logic implementation
- Database schema design and migration
- API development and testing

### Phase 3: Advanced Features (Weeks 13-20)
- Advanced search and filtering
- Analytics and reporting dashboard
- Real-time notifications
- Mobile application development

## Team Structure and Responsibilities

### Development Teams

| Team | Lead | Size | Focus Areas |
|------|------|------|-------------|
| Frontend | Sarah Chen | 4 | React, TypeScript, UX/UI |
| Backend | Mike Johnson | 5 | Node.js, APIs, Database |
| DevOps | Alex Rivera | 3 | Infrastructure, CI/CD, Security |
| QA | Lisa Wang | 3 | Testing, Automation, Quality |

### Communication Protocols

- Daily standup meetings at 9:00 AM UTC
- Weekly sprint planning on Mondays
- Bi-weekly stakeholder reviews
- Monthly retrospectives and process improvements

## Risk Management

### Technical Risks

1. **Scalability Concerns**
   - Risk: System may not handle projected load
   - Mitigation: Load testing and auto-scaling configuration

2. **Security Vulnerabilities**
   - Risk: Data breaches or unauthorized access
   - Mitigation: Regular security audits and penetration testing

3. **Integration Complexity**
   - Risk: Third-party service dependencies
   - Mitigation: Circuit breakers and fallback mechanisms

### Business Risks

1. **Timeline Delays**
   - Risk: Project may not meet deadlines
   - Mitigation: Agile methodology and regular progress tracking

2. **Budget Overruns**
   - Risk: Costs may exceed allocated budget
   - Mitigation: Regular financial reviews and scope management

## Quality Assurance

### Testing Strategy

- Unit tests: Jest and Supertest for Node.js services
- Integration tests: Docker Compose test environment
- E2E tests: Cypress for frontend automation
- Performance tests: Artillery for load testing

### Code Quality Standards

- ESLint and Prettier for code formatting
- SonarQube for code quality analysis
- Code reviews: Minimum 2 approvals required
- Documentation: JSDoc comments for all functions

## Monitoring and Observability

### Key Metrics

- Application Performance Index (Apdex): Target > 0.95
- Error Rate: Target < 0.1%
- Response Time: 95th percentile < 500ms
- Availability: Target 99.9%

### Monitoring Stack

- Application monitoring: New Relic
- Infrastructure monitoring: Datadog
- Log aggregation: ELK Stack
- Error tracking: Sentry

## Success Criteria

### Technical Metrics

- System availability: 99.9%
- Page load time: < 2 seconds
- API response time: < 200ms
- Test coverage: > 80%

### Business Metrics

- User adoption: > 70% within 3 months
- Customer satisfaction: > 4.5/5 rating
- Support ticket reduction: > 30%
- ROI: Positive within 12 months

${'Additional implementation details, technical specifications, and project documentation to ensure comprehensive semantic chunking analysis: '.repeat(80)}
      `.trim();

      // Verify document size
      expect(mixedContentDoc.length).toBeGreaterThan(9000);

      const knowledgeItem: KnowledgeItem = {
        id: 'implementation-guide-001',
        kind: 'runbook', // This type should be chunked
        scope: {
          project: 'digital-transformation',
          branch: 'main',
          org: 'enterprise-tech'
        },
        data: {
          content: mixedContentDoc,
          title: 'Project Implementation Guide',
          category: 'project-management',
          author: 'project-management-office',
          priority: 'high',
          stakeholders: ['cto', 'ceo', 'department-heads'],
        },
        metadata: {
          version: '1.0.0',
          approval_status: 'approved',
          last_updated: '2025-01-15T14:30:00Z',
        },
      };

      // Apply chunking
      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);
      const parentItem = chunkedItems.find(item => !item.data.is_chunk);
      const childChunks = chunkedItems.filter(item => item.data.is_chunk);

      // Test reassembly
      const reassembledDoc = await getDocumentWithChunks(parentItem!.id);

      // Verify content structure preservation
      const reassembledContent = reassembledDoc!.reassembled_content;

      // Check code blocks are preserved
      expect(reassembledContent).toContain('CI/CD Pipeline Configuration');
      expect(reassembledContent).toContain('pipeline.stages');
      expect(reassembledContent).toContain('blue-green');

      // Check tables are preserved
      expect(reassembledContent).toContain('Sarah Chen');
      expect(reassembledContent).toContain('Mike Johnson');
      expect(reassembledContent).toContain('Frontend');
      expect(reassembledContent).toContain('React, TypeScript, UX/UI');

      // Check markdown formatting
      expect(reassembledContent).toContain('## Executive Summary');
      expect(reassembledContent).toContain('### System Components');

      // Calculate accuracy
      const normalizedOriginal = mixedContentDoc.replace(/\s+/g, ' ').trim();
      const normalizedReassembled = reassembledContent.replace(/\s+/g, ' ').trim();
      const similarityRatio = calculateTextSimilarity(normalizedOriginal, normalizedReassembled);

      expect(similarityRatio).toBeGreaterThanOrEqual(0.995);
    });

    it('should preserve semantic boundaries in structured content', async () => {
      // Create content with clear semantic sections
      const structuredContent = `
# Research Paper: Neural Networks in Climate Science

## Abstract

This paper presents a comprehensive analysis of neural network applications in climate science research. We examine how deep learning models are revolutionizing climate prediction, weather forecasting, and environmental monitoring. Our study covers the period from 2015 to 2024 and includes analysis of over 200 research papers and 50 real-world applications.

## 1. Introduction

Climate change represents one of the most significant challenges facing humanity in the 21st century. The increasing availability of climate data, combined with advances in computational power and machine learning algorithms, has created unprecedented opportunities for improving our understanding of climate systems.

Traditional climate models, while sophisticated, often struggle with capturing complex non-linear relationships in climate data. Neural networks, with their ability to learn intricate patterns from high-dimensional data, offer promising alternatives for climate modeling and prediction.

## 2. Background and Related Work

### 2.1 Traditional Climate Modeling

Conventional climate models are based on numerical solutions to partial differential equations describing atmospheric and oceanic dynamics. These models, such as General Circulation Models (GCMs), have been the cornerstone of climate research for decades.

However, traditional models face several limitations:
- High computational requirements
- Difficulty in capturing sub-grid scale processes
- Uncertainty in parameterization schemes
- Limited ability to assimilate real-time observational data

### 2.2 Early Machine Learning Applications

Early applications of machine learning in climate science focused on:
- Statistical downscaling of climate model outputs
- Pattern recognition in climate data
- Anomaly detection in weather patterns
- Optimization of model parameters

These early approaches demonstrated the potential but were limited by the available algorithms and computational resources.

## 3. Neural Network Architectures for Climate Applications

### 3.1 Convolutional Neural Networks (CNNs)

CNNs have found extensive applications in:
- Spatial pattern analysis in climate data
- Extreme weather event detection
- Ocean feature identification
- Atmospheric pattern recognition

The hierarchical feature extraction capabilities of CNNs make them particularly suitable for analyzing gridded climate data with complex spatial relationships.

### 3.2 Recurrent Neural Networks (RNNs) and LSTMs

RNNs and their variants (LSTMs, GRUs) are effective for:
- Time series prediction in climate data
- Seasonal pattern analysis
- Long-term climate trend modeling
- Multi-step ahead forecasting

These architectures excel at capturing temporal dependencies in climate sequences, making them valuable for time-series climate predictions.

### 3.3 Transformer Models

Recent transformer architectures have shown promise in:
- Climate sequence modeling with long-range dependencies
- Multi-variate climate data analysis
- Attention-based feature selection
- Transfer learning across climate domains

The self-attention mechanism in transformers allows for capturing complex relationships between different climate variables and spatial regions.

## 4. Applications and Case Studies

### 4.1 Weather Prediction

Neural networks have significantly improved short-term weather forecasting:
- 24-hour temperature prediction with 95% accuracy
- Precipitation forecasting with 85% accuracy
- Severe weather event prediction 6 hours in advance
- Multi-variate weather pattern analysis

### 4.2 Climate Modeling

Long-term climate prediction applications include:
- Global temperature trend prediction
- Sea-level rise forecasting
- Ocean current pattern analysis
- Carbon cycle modeling

### 4.3 Extreme Event Detection

Early warning systems for extreme events:
- Hurricane formation prediction
- Wildfire risk assessment
- Flood prediction systems
- Drought monitoring and prediction

## 5. Methodology

### 5.1 Data Collection and Processing

Our analysis utilized multiple climate datasets:
- ERA5 reanalysis data (1979-2024)
- NOAA climate data archives
- Satellite observation data
- Station measurements from 50,000+ weather stations

Data preprocessing steps included:
- Quality control and outlier removal
- Spatial and temporal interpolation
- Feature engineering and selection
- Data normalization and standardization

### 5.2 Model Development

We developed and tested multiple neural network architectures:
- Custom CNN architectures for spatial analysis
- LSTM-based models for temporal prediction
- Transformer models for sequence modeling
- Ensemble methods combining multiple approaches

Model training utilized:
- Transfer learning from pre-trained models
- Data augmentation techniques
- Regularization methods to prevent overfitting
- Hyperparameter optimization using Bayesian methods

## 6. Results and Discussion

### 6.1 Performance Metrics

Our models achieved the following performance:
- Temperature prediction: RMSE of 1.2°C
- Precipitation prediction: correlation coefficient of 0.87
- Extreme event detection: F1-score of 0.91
- Long-term climate prediction: 78% accuracy over 5-year horizon

### 6.2 Comparison with Traditional Methods

Neural network models outperformed traditional approaches in:
- Computational efficiency (3x faster training time)
- Prediction accuracy (15-25% improvement)
- Uncertainty quantification (better calibrated predictions)
- Adaptability to new data (online learning capabilities)

## 7. Limitations and Future Work

### 7.1 Current Limitations

Several challenges remain:
- Interpretability of neural network predictions
- Data quality and availability issues
- Computational requirements for large-scale models
- Transferability across different climate regions

### 7.2 Future Research Directions

Promising areas for future research:
- Physics-informed neural networks
- Hybrid models combining traditional and ML approaches
- Real-time climate prediction systems
- Improved uncertainty quantification methods

## 8. Conclusion

Neural networks have demonstrated significant potential in advancing climate science research and applications. Our analysis shows substantial improvements in prediction accuracy, computational efficiency, and adaptability compared to traditional methods.

The integration of neural networks with domain expertise and physical understanding of climate systems will be crucial for continued progress. Future research should focus on developing interpretable, physically-constrained models that can provide reliable predictions while maintaining scientific rigor.

As climate change continues to pose significant challenges, neural networks and other machine learning approaches will play an increasingly important role in our ability to understand, predict, and mitigate climate impacts.

## References

1. Reichstein, M., et al. (2019). "Deep learning and process understanding for data-driven Earth system science." Nature, 566(7743), 195-204.
2. Krasnopolsky, V. M., & Fox-Rabinovitz, M. S. (2020). "Complex hybrid neural network parameterizations." Neural Networks, 123, 187-197.
3. Rasp, S., et al. (2020). "Machine learning for weather and climate." Nature Machine Intelligence, 2(5), 258-260.

${'Additional research content, detailed methodologies, and extended case studies to ensure document exceeds 12,000 characters for comprehensive testing: '.repeat(120)}
      `.trim();

      expect(structuredContent.length).toBeGreaterThan(12000);

      const knowledgeItem: KnowledgeItem = {
        id: 'climate-research-001',
        kind: 'section',
        scope: {
          project: 'climate-research',
          branch: 'neural-networks',
          org: 'scientific-institute'
        },
        data: {
          content: structuredContent,
          title: 'Neural Networks in Climate Science',
          category: 'research-paper',
          author: 'climate-research-team',
          peer_reviewed: true,
          journal: 'Nature Climate Science',
          doi: '10.1038/s41558-024-00123',
        },
        metadata: {
          version: '2.0.0',
          citations: 45,
          impact_factor: 12.5,
        },
      };

      // Apply chunking
      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);
      const parentItem = chunkedItems.find(item => !item.data.is_chunk);
      const childChunks = chunkedItems.filter(item => item.data.is_chunk);

      // Verify semantic sections are preserved across chunk boundaries
      const reassembledDoc = await getDocumentWithChunks(parentItem!.id);
      const reassembledContent = reassembledDoc!.reassembled_content;

      // Verify all major sections are preserved
      expect(reassembledContent).toContain('## Abstract');
      expect(reassembledContent).toContain('## 1. Introduction');
      expect(reassembledContent).toContain('## 2. Background and Related Work');
      expect(reassembledContent).toContain('## 3. Neural Network Architectures');
      expect(reassembledContent).toContain('## 4. Applications and Case Studies');
      expect(reassembledContent).toContain('## 5. Methodology');
      expect(reassembledContent).toContain('## 6. Results and Discussion');
      expect(reassembledContent).toContain('## 7. Limitations and Future Work');
      expect(reassembledContent).toContain('## 8. Conclusion');
      expect(reassembledContent).toContain('## References');

      // Verify subsections
      expect(reassembledContent).toContain('### 2.1 Traditional Climate Modeling');
      expect(reassembledContent).toContain('### 3.1 Convolutional Neural Networks (CNNs)');
      expect(reassembledContent).toContain('### 5.1 Data Collection and Processing');

      // Verify specific content details
      expect(reassembledContent).toContain('Reichstein, M., et al. (2019)');
      expect(reassembledContent).toContain('95% accuracy');
      expect(reassembledContent).toContain('RMSE of 1.2°C');
      expect(reassembledContent).toContain('Nature Climate Science');

      // Calculate accuracy
      const normalizedOriginal = structuredContent.replace(/\s+/g, ' ').trim();
      const normalizedReassembled = reassembledContent.replace(/\s+/g, ' ').trim();
      const similarityRatio = calculateTextSimilarity(normalizedOriginal, normalizedReassembled);

      expect(similarityRatio).toBeGreaterThanOrEqual(0.995);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle documents with special formatting and code blocks', async () => {
      const specialContent = `
# Advanced Development Guide

## Code Examples

### JavaScript Implementation

\`\`\`javascript
class NeuralNetwork {
  constructor(layers, learningRate = 0.01) {
    this.layers = layers;
    this.learningRate = learningRate;
    this.weights = this.initializeWeights();
    this.biases = this.initializeBiases();
  }

  forward(input) {
    this.activations = [input];
    let activation = input;

    for (let i = 0; i < this.weights.length; i++) {
      activation = this.activate(
        this.add(
          this.multiply(this.weights[i], activation),
          this.biases[i]
        )
      );
      this.activations.push(activation);
    }

    return activation;
  }

  backward(target) {
    let error = this.subtract(target, this.activations[this.activations.length - 1]);
    let delta = error;

    for (let i = this.weights.length - 1; i >= 0; i--) {
      let activationDerivative = this.derivative(this.activations[i + 1]);
      delta = this.multiplyElementwise(delta, activationDerivative);

      if (i > 0) {
        let weightTranspose = this.transpose(this.weights[i]);
        error = this.multiply(weightTranspose, delta);
        delta = error;
      }

      let activationTranspose = this.transpose(this.activations[i]);
      let weightGradient = this.multiply(delta, activationTranspose);
      this.weights[i] = this.subtract(
        this.weights[i],
        this.multiply(this.learningRate, weightGradient)
      );
      this.biases[i] = this.subtract(
        this.biases[i],
        this.multiply(this.learningRate, delta)
      );
    }
  }
}
\`\`\`

### Python Implementation

\`\`\`python
import numpy as np
from typing import List, Tuple

class ClimateDataProcessor:
    def __init__(self, config: dict):
        self.config = config
        self.scaler = StandardScaler()
        self.model = None

    def preprocess_data(self, data: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Preprocess climate data with normalization and feature engineering

        Args:
            data: Raw climate data array

        Returns:
            Tuple of (processed_data, labels)
        """
        # Remove NaN values
        clean_data = self.remove_outliers(data)

        # Normalize features
        normalized_data = self.scaler.fit_transform(clean_data)

        # Create temporal features
        features = self.create_temporal_features(normalized_data)

        # Generate labels for supervised learning
        labels = self.generate_labels(features)

        return features, labels

    def remove_outliers(self, data: np.ndarray) -> np.ndarray:
        """Remove outliers using IQR method"""
        Q1 = np.percentile(data, 25, axis=0)
        Q3 = np.percentile(data, 75, axis=0)
        IQR = Q3 - Q1

        lower_bound = Q1 - 1.5 * IQR
        upper_bound = Q3 + 1.5 * IQR

        mask = (data >= lower_bound) & (data <= upper_bound)
        return data[mask]

    def create_temporal_features(self, data: np.ndarray) -> np.ndarray:
        """Create temporal features from sequential data"""
        features = []

        for i in range(len(data) - 10):
            # Create sliding window features
            window = data[i:i+10]

            # Statistical features
            mean_val = np.mean(window, axis=0)
            std_val = np.std(window, axis=0)
            trend = np.polyfit(range(10), window, 1)[0]

            features.append(np.concatenate([mean_val, std_val, trend]))

        return np.array(features)
\`\`\`

## Mathematical Formulas

The neural network training process uses the following mathematical formulations:

### Forward Propagation

For each layer \$l\$ in the network:

\$\$z^{[l]} = W^{[l]} a^{[l-1]} + b^{[l]}\$\$

\$\$a^{[l]} = \sigma(z^{[l]})\$\$

Where:
- \$W^{[l]}\$ is the weight matrix for layer \$l\$
- \$b^{[l]}\$ is the bias vector for layer \$l\$
- \$\sigma\$ is the activation function
- \$a^{[l]}\$ is the activation output for layer \$l\$

### Backpropagation

The gradient computation uses:

\$\$\\frac{\\partial L}{\\partial W^{[l]}} = \\frac{1}{m} \\frac{\\partial L}{\\partial z^{[l]}} a^{[l-1]T}\$\$

\$\$\\frac{\\partial L}{\\partial b^{[l]}} = \\frac{1}{m} \\sum_{i=1}^{m} \\frac{\\partial L}{\\partial z^{[l]}}\$\$

## Configuration Files

### Docker Compose

\`\`\`yaml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://user:pass@db:5432/climate_db
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    volumes:
      - ./logs:/app/logs
      - ./data:/app/data

  db:
    image: postgres:15
    environment:
      POSTGRES_DB: climate_db
      POSTGRES_USER: climate_user
      POSTGRES_PASSWORD: secure_password
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

## Data Formats

### JSON Schema

\`\`\`json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "timestamp": {
      "type": "string",
      "format": "date-time"
    },
    "temperature": {
      "type": "number",
      "minimum": -50,
      "maximum": 60,
      "unit": "celsius"
    },
    "humidity": {
      "type": "number",
      "minimum": 0,
      "maximum": 100,
      "unit": "percent"
    },
    "pressure": {
      "type": "number",
      "minimum": 900,
      "maximum": 1100,
      "unit": "hPa"
    },
    "coordinates": {
      "type": "array",
      "items": {
        "type": "number"
      },
      "minItems": 2,
      "maxItems": 2
    }
  },
  "required": ["timestamp", "temperature", "humidity", "pressure"]
}
\`\`\`

${'Additional technical content, code examples, and documentation to ensure comprehensive testing of semantic chunking with special formatting: '.repeat(100)}
      `.trim();

      expect(specialContent.length).toBeGreaterThan(10000);

      const knowledgeItem: KnowledgeItem = {
        id: 'advanced-dev-guide-001',
        kind: 'section',
        scope: {
          project: 'development-documentation',
          branch: 'main'
        },
        data: {
          content: specialContent,
          title: 'Advanced Development Guide',
          category: 'technical-documentation',
          author: 'development-team',
        },
      };

      // Apply chunking
      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);
      const parentItem = chunkedItems.find(item => !item.data.is_chunk);
      const childChunks = chunkedItems.filter(item => item.data.is_chunk);

      // Test reassembly
      const reassembledDoc = await getDocumentWithChunks(parentItem!.id);
      const reassembledContent = reassembledDoc!.reassembled_content;

      // Verify code blocks are preserved intact
      expect(reassembledContent).toContain('class NeuralNetwork');
      expect(reassembledContent).toContain('constructor(layers, learningRate = 0.01)');
      expect(reassembledContent).toContain('forward(input)');
      expect(reassembledContent).toContain('backward(target)');

      expect(reassembledContent).toContain('class ClimateDataProcessor');
      expect(reassembledContent).toContain('def preprocess_data(self, data: np.ndarray)');
      expect(reassembledContent).toContain('def remove_outliers(self, data: np.ndarray)');

      // Verify mathematical formulas
      expect(reassembledContent).toContain('$z^{[l]} = W^{[l]} a^{[l-1]} + b^{[l]}$');
      expect(reassembledContent).toContain('$a^{[l]} = \\sigma(z^{[l]})$');

      // Verify YAML and JSON configurations
      expect(reassembledContent).toContain('version: \'3.8\'');
      expect(reassembledContent).toContain('POSTGRES_DB: climate_db');
      expect(reassembledContent).toContain('$schema": "http://json-schema.org/draft-07/schema#"');

      // Calculate accuracy
      const normalizedOriginal = specialContent.replace(/\s+/g, ' ').trim();
      const normalizedReassembled = reassembledContent.replace(/\s+/g, ' ').trim();
      const similarityRatio = calculateTextSimilarity(normalizedOriginal, normalizedReassembled);

      expect(similarityRatio).toBeGreaterThanOrEqual(0.995);
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large documents efficiently with performance metrics', async () => {
      // Create a very large document (20k+ characters)
      const veryLargeContent = `
# Comprehensive System Documentation

## Overview

This document provides comprehensive technical documentation for our enterprise-scale distributed system. The system handles millions of requests daily and maintains high availability and performance standards.

${'Detailed technical documentation sections covering all aspects of the system including architecture, implementation, deployment, monitoring, and maintenance procedures. '.repeat(200)}
      `.trim();

      expect(veryLargeContent.length).toBeGreaterThan(20000);

      const startTime = Date.now();

      const knowledgeItem: KnowledgeItem = {
        id: 'large-system-doc-001',
        kind: 'runbook',
        scope: { project: 'system-documentation', branch: 'main' },
        data: {
          content: veryLargeContent,
          title: 'Comprehensive System Documentation',
          category: 'system-documentation',
        },
      };

      // Apply chunking
      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);
      const chunkingTime = Date.now() - startTime;

      // Performance assertions
      expect(chunkingTime).toBeLessThan(5000); // Should complete within 5 seconds
      expect(chunkedItems.length).toBeGreaterThan(10); // Should create multiple chunks

      const parentItem = chunkedItems.find(item => !item.data.is_chunk);
      const childChunks = chunkedItems.filter(item => item.data.is_chunk);

      // Verify chunk distribution
      const chunkSizes = childChunks.map(chunk => chunk.data.content.length);
      const avgChunkSize = chunkSizes.reduce((a, b) => a + b, 0) / chunkSizes.length;

      expect(avgChunkSize).toBeGreaterThan(800); // Reasonable chunk size
      expect(avgChunkSize).toBeLessThan(1500);  // Not too large

      // Test reassembly performance
      const reassemblyStartTime = Date.now();
      const reassembledDoc = await getDocumentWithChunks(parentItem!.id);
      const reassemblyTime = Date.now() - reassemblyStartTime;

      expect(reassemblyTime).toBeLessThan(2000); // Should complete within 2 seconds
      expect(reassembledDoc).toBeDefined();

      // Calculate accuracy
      const normalizedOriginal = veryLargeContent.replace(/\s+/g, ' ').trim();
      const normalizedReassembled = reassembledDoc!.reassembled_content.replace(/\s+/g, ' ').trim();
      const similarityRatio = calculateTextSimilarity(normalizedOriginal, normalizedReassembled);

      expect(similarityRatio).toBeGreaterThanOrEqual(0.995);
    });
  });
});

/**
 * Calculate text similarity using multiple metrics
 */
function calculateTextSimilarity(text1: string, text2: string): number {
  // Simple character-based similarity
  const charSimilarity = calculateCharSimilarity(text1, text2);

  // Word-based similarity
  const wordSimilarity = calculateWordSimilarity(text1, text2);

  // Return weighted average (more weight to word similarity for semantic content)
  return (charSimilarity * 0.3) + (wordSimilarity * 0.7);
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