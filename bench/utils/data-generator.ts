/**
 * Benchmark Data Generator
 *
 * Generates realistic test datasets for benchmarking Cortex Memory MCP performance
 */

import { writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { v4 as uuidv4 } from 'uuid';
import type {
  DataGeneratorConfig,
  TestDataset,
  TestItem,
  TestRelationship
} from '../framework/types.js';

export class BenchmarkDataGenerator {
  private readonly CONTENT_TEMPLATES = {
    entity: [
      'User account for {name} with email {email} and role {role}',
      'Product {product} in category {category} priced at ${price}',
      'Organization {company} founded in {year} with {employees} employees',
      'Service {service} providing {features} to customers in {region}',
      'Device {device} model {model} with serial number {serial}'
    ],
    observation: [
      'User {user} logged in from {location} at {time}',
      'Product {product} viewed {count} times in the last {period}',
      'Service {service} responded with latency {latency}ms',
      'System alert: {alert_type} detected on {component}',
      'Performance metric: {metric} = {value} at {timestamp}'
    ],
    decision: [
      'Approved request for {request} by {approver} on {date}',
      'Rejected {action} due to {reason}',
      'Implemented {feature} with priority {priority}',
      'Decided to migrate from {old_system} to {new_system}',
      'Chose {vendor} for {service} contract'
    ],
    issue: [
      'Bug reported in {component}: {description}',
      'Performance issue: {metric} exceeding threshold',
      'Security vulnerability identified in {system}',
      'Data inconsistency detected in {table}',
      'Integration failure with {external_service}'
    ],
    todo: [
      'Implement {feature} for {module}',
      'Fix bug {bug_id} in {component}',
      'Review pull request #{pr_number}',
      'Update documentation for {api}',
      'Optimize {operation} for better performance'
    ],
    incident: [
      'Service outage: {service} unavailable for {duration}',
      'Database connection failure in {region}',
      'High memory usage detected on {server}',
      'Network partition affecting {services}',
      'Deployment failure for {version}'
    ],
    release: [
      'Version {version} released with {features_count} features',
      'Hotfix {hotfix_version} deployed to production',
      'Feature branch {branch} merged to main',
      'Rollback initiated for {deployment}',
      'Canary deployment of {feature} to {percentage}% users'
    ],
    risk: [
      'Security risk: {vulnerability} in {component}',
      'Performance risk: {bottleneck} under load',
      'Data loss risk: {backup_issue}',
      'Compliance risk: {regulation} violation',
      'Operational risk: {process_failure}'
    ],
    assumption: [
      'Assume {system} can handle {load}',
      'Users will prefer {feature} over {alternative}',
      'Migration will complete within {timeframe}',
      'Third-party API {api} remains stable',
      'Database queries will maintain {performance}'
    ],
    runbook: [
      'Procedure for {incident_type} resolution',
      'Steps to deploy {service} to {environment}',
      'Recovery process for {failure_scenario}',
      'Maintenance checklist for {system}',
      'Troubleshooting guide for {symptom}'
    ]
  };

  private readonly SAMPLE_DATA = {
    names: ['Alice Johnson', 'Bob Smith', 'Carol Davis', 'David Wilson', 'Eva Brown'],
    emails: ['alice@example.com', 'bob@company.com', 'carol@org.com', 'david@business.com', 'eva@startup.com'],
    roles: ['admin', 'user', 'manager', 'developer', 'analyst'],
    products: ['Widget Pro', 'Gadget X', 'Device Plus', 'Tool Master', 'System Core'],
    categories: ['electronics', 'software', 'hardware', 'services', 'infrastructure'],
    companies: ['TechCorp', 'DataSoft', 'CloudBase', 'InfoSys', 'NetWorks'],
    services: ['Authentication', 'Database', 'Storage', 'Compute', 'Network'],
    locations: ['New York', 'San Francisco', 'London', 'Tokyo', 'Sydney'],
    components: ['API Gateway', 'Database', 'Cache', 'Message Queue', 'Load Balancer']
  };

  /**
   * Generate a test dataset
   */
  async generateDataset(config: DataGeneratorConfig): Promise<TestDataset> {
    console.log(`🏭 Generating test dataset: ${config.itemCount} items`);

    const dataset: TestDataset = {
      metadata: {
        name: `benchmark-dataset-${config.itemCount}`,
        version: '1.0.0',
        created: new Date().toISOString(),
        itemCount: config.itemCount,
        totalSize: 0
      },
      items: [],
      relationships: []
    };

    // Generate items
    for (let i = 0; i < config.itemCount; i++) {
      const item = this.generateTestItem(config, i);
      dataset.items.push(item);
    }

    // Generate relationships
    const relationshipCount = Math.floor(config.itemCount * (config.relationshipDensity || 0.1));
    for (let i = 0; i < relationshipCount; i++) {
      const relationship = this.generateTestRelationship(dataset.items);
      if (relationship) {
        dataset.relationships.push(relationship);
      }
    }

    // Calculate total size
    dataset.metadata.totalSize = dataset.items.reduce((sum, item) => sum + item.size, 0);

    console.log(`✅ Generated ${dataset.items.length} items and ${dataset.relationships.length} relationships`);
    console.log(`📊 Total dataset size: ${(dataset.metadata.totalSize / 1024 / 1024).toFixed(2)}MB`);

    return dataset;
  }

  /**
   * Save dataset to file
   */
  async saveDataset(dataset: TestDataset, outputPath: string): Promise<void> {
    const dir = join(outputPath, '..');
    mkdirSync(dir, { recursive: true });

    // Save as JSON
    const jsonPath = join(dir, `${dataset.metadata.name}.json`);
    writeFileSync(jsonPath, JSON.stringify(dataset, null, 2));

    // Save as NDJSON for streaming
    const ndjsonPath = join(dir, `${dataset.metadata.name}.ndjson`);
    const ndjsonContent = [
      JSON.stringify(dataset.metadata),
      ...dataset.items.map(item => JSON.stringify(item)),
      ...dataset.relationships.map(rel => JSON.stringify(rel))
    ].join('\n');
    writeFileSync(ndjsonPath, ndjsonContent);

    console.log(`💾 Dataset saved:`);
    console.log(`   JSON: ${jsonPath}`);
    console.log(`   NDJSON: ${ndjsonPath}`);
  }

  /**
   * Load dataset from file
   */
  async loadDataset(filePath: string): Promise<TestDataset> {
    const content = await import('fs').then(fs => fs.readFileSync(filePath, 'utf-8'));
    return JSON.parse(content) as TestDataset;
  }

  /**
   * Generate a single test item
   */
  private generateTestItem(config: DataGeneratorConfig, index: number): TestItem {
    const type = this.selectItemByWeight(config.itemTypes, index);
    const template = this.selectRandomTemplate(type);
    const content = this.generateContent(template);
    const size = this.calculateSize(content, config.sizeDistribution);

    return {
      id: uuidv4(),
      type,
      content,
      size,
      created: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000).toISOString(),
      tags: this.generateTags(type),
      metadata: this.generateMetadata(type, index)
    };
  }

  /**
   * Generate a test relationship
   */
  private generateTestRelationship(items: TestItem[]): TestRelationship | null {
    if (items.length < 2) return null;

    const source = items[Math.floor(Math.random() * items.length)];
    const target = items[Math.floor(Math.random() * items.length)];

    if (source.id === target.id) return null;

    const relationshipTypes = ['relates_to', 'depends_on', 'references', 'contains', 'extends'];
    const type = relationshipTypes[Math.floor(Math.random() * relationshipTypes.length)];

    return {
      source: source.id,
      target: target.id,
      type,
      weight: Math.random(),
      created: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString()
    };
  }

  /**
   * Select item type by weighted distribution
   */
  private selectItemByWeight(types: string[], index: number): string {
    // Default weights based on typical usage patterns
    const weights: Record<string, number> = {
      entity: 0.25,
      observation: 0.20,
      decision: 0.10,
      issue: 0.08,
      todo: 0.12,
      incident: 0.05,
      release: 0.05,
      risk: 0.05,
      assumption: 0.05,
      runbook: 0.05
    };

    // Use index-based selection for reproducible results
    const weightedTypes: string[] = [];
    types.forEach(type => {
      const count = Math.ceil((weights[type] || 0.1) * 100);
      for (let i = 0; i < count; i++) {
        weightedTypes.push(type);
      }
    });

    const selectedIndex = index % weightedTypes.length;
    return weightedTypes[selectedIndex];
  }

  /**
   * Select a random template for the given type
   */
  private selectRandomTemplate(type: string): string {
    const templates = this.CONTENT_TEMPLATES[type as keyof typeof this.CONTENT_TEMPLATES];
    return templates[Math.floor(Math.random() * templates.length)];
  }

  /**
   * Generate content from template
   */
  private generateContent(template: string): string {
    let content = template;

    // Replace placeholders with sample data
    const replacements: Record<string, () => string> = {
      '{name}': () => this.randomElement(this.SAMPLE_DATA.names),
      '{email}': () => this.randomElement(this.SAMPLE_DATA.emails),
      '{role}': () => this.randomElement(this.SAMPLE_DATA.roles),
      '{product}': () => this.randomElement(this.SAMPLE_DATA.products),
      '{category}': () => this.randomElement(this.SAMPLE_DATA.categories),
      '{company}': () => this.randomElement(this.SAMPLE_DATA.companies),
      '{service}': () => this.randomElement(this.SAMPLE_DATA.services),
      '{location}': () => this.randomElement(this.SAMPLE_DATA.locations),
      '{component}': () => this.randomElement(this.SAMPLE_DATA.components),
      '{price}': () => `$${(Math.random() * 1000).toFixed(2)}`,
      '{year}': () => String(2010 + Math.floor(Math.random() * 14)),
      '{employees}': () => String(10 + Math.floor(Math.random() * 10000)),
      '{features}': () => this.generateFeatures(),
      '{user}': () => this.randomElement(this.SAMPLE_DATA.names),
      '{time}': () => new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000).toISOString(),
      '{count}': () => String(Math.floor(Math.random() * 1000)),
      '{period}': () => this.randomElement(['hour', 'day', 'week', 'month']),
      '{latency}': () => String(Math.floor(Math.random() * 1000)),
      '{alert_type}': () => this.randomElement(['CPU', 'Memory', 'Disk', 'Network']),
      '{metric}': () => this.randomElement(['Response Time', 'Throughput', 'Error Rate', 'CPU Usage']),
      '{value}': () => String(Math.random() * 100),
      '{timestamp}': () => new Date().toISOString(),
      '{request}': () => `REQ-${Math.floor(Math.random() * 100000)}`,
      '{approver}': () => this.randomElement(this.SAMPLE_DATA.names),
      '{date}': () => new Date().toISOString().split('T')[0],
      '{action}': () => this.randomElement(['deployment', 'migration', 'update', 'deletion']),
      '{reason}': () => this.randomElement(['security concerns', 'budget constraints', 'technical limitations', 'policy violation']),
      '{feature}': () => this.randomElement(['Authentication', 'Authorization', 'Logging', 'Monitoring', 'Caching']),
      '{priority}': () => this.randomElement(['high', 'medium', 'low']),
      '{old_system}': () => this.randomElement(['Legacy System', 'Old Database', 'Previous Version']),
      '{new_system}': () => this.randomElement(['Modern Platform', 'New Database', 'Current Version']),
      '{vendor}': () => this.randomElement(['AWS', 'Azure', 'Google Cloud', 'Oracle']),
      '{bug_id}': () => `BUG-${Math.floor(Math.random() * 10000)}`,
      '{pr_number}': () => String(Math.floor(Math.random() * 1000)),
      '{api}': () => this.randomElement(['User API', 'Order API', 'Product API', 'Payment API']),
      '{operation}': () => this.randomElement(['search', 'store', 'update', 'delete']),
      '{duration}': () => `${Math.floor(Math.random() * 60)} minutes`,
      '{region}': () => this.randomElement(['US-East', 'US-West', 'EU-West', 'AP-Southeast']),
      '{server}': () => `server-${Math.floor(Math.random() * 10)}`,
      '{services}': () => this.randomServices(),
      '{version}': () => `v${Math.floor(Math.random() * 5)}.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 20)}`,
      '{features_count}': () => String(Math.floor(Math.random() * 20) + 1),
      '{hotfix_version}': () => `v${Math.floor(Math.random() * 5)}.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 20)}.${Math.floor(Math.random() * 10)}`,
      '{branch}': () => this.randomElement(['feature/new-auth', 'bugfix/payment', 'refactor/database', 'hotfix/security']),
      '{deployment}': () => this.randomElement(['API Gateway', 'Database Migration', 'Frontend Update', 'Service Upgrade']),
      '{percentage}': () => String(Math.floor(Math.random() * 100)),
      '{vulnerability}': () => this.randomElement(['SQL Injection', 'XSS', 'CSRF', 'Buffer Overflow']),
      '{bottleneck}': () => this.randomElement(['Database Query', 'API Response', 'Memory Allocation', 'Network I/O']),
      '{load}': () => `${Math.floor(Math.random() * 10000)} requests/second`,
      '{backup_issue}': () => this.randomElement(['Incomplete backup', 'Corrupted backup', 'Missing backup', 'Backup delay']),
      '{regulation}': () => this.randomElement(['GDPR', 'HIPAA', 'PCI-DSS', 'SOX']),
      '{process_failure}': () => this.randomElement(['Deploy Pipeline', 'CI/CD Process', 'Monitoring Alert', 'Security Scan']),
      '{timeframe}': () => this.randomElement(['1 week', '2 weeks', '1 month', '1 quarter']),
      '{performance}': () => this.randomElement(['sub-second response', '99.9% uptime', '1000 req/s throughput', 'low memory usage']),
      '{incident_type}': () => this.randomElement(['Service Outage', 'Performance Degradation', 'Security Incident', 'Data Loss']),
      '{environment}': () => this.randomElement(['development', 'staging', 'production']),
      '{failure_scenario}': () => this.randomElement(['Database Connection Lost', 'Memory Exhaustion', 'Network Partition', 'Disk Full']),
      '{system}': () => this.randomElement(['Authentication Service', 'Payment Gateway', 'User Management', 'Analytics Platform']),
      '{symptom}': () => this.randomElement(['High CPU Usage', 'Memory Leaks', 'Slow Response Times', 'Connection Timeouts'])
    };

    for (const [placeholder, generator] of Object.entries(replacements)) {
      content = content.replace(new RegExp(placeholder.replace(/[{}]/g, '\\$&'), 'g'), generator());
    }

    return content;
  }

  /**
   * Generate features list
   */
  private generateFeatures(): string {
    const features = ['authentication', 'authorization', 'logging', 'monitoring', 'caching', 'encryption', 'backup', 'scalability'];
    const count = Math.floor(Math.random() * 3) + 1;
    const selected = features.sort(() => Math.random() - 0.5).slice(0, count);
    return selected.join(', ');
  }

  /**
   * Generate random services list
   */
  private randomServices(): string {
    const count = Math.floor(Math.random() * 3) + 2;
    const services = this.SAMPLE_DATA.services.sort(() => Math.random() - 0.5).slice(0, count);
    return services.join(', ');
  }

  /**
   * Calculate content size with variance
   */
  private calculateSize(content: string, sizeDistribution: DataGeneratorConfig['sizeDistribution']): number {
    const baseSize = Buffer.byteLength(content, 'utf8');
    const variance = sizeDistribution.max - sizeDistribution.min;
    const targetSize = sizeDistribution.min + (Math.random() * variance);

    // Adjust content to match target size
    if (baseSize < targetSize) {
      const padding = 'x'.repeat(Math.floor(targetSize - baseSize));
      return baseSize + padding.length;
    } else if (baseSize > targetSize) {
      return Math.floor(targetSize);
    }

    return baseSize;
  }

  /**
   * Generate tags for item type
   */
  private generateTags(type: string): string[] {
    const tagSets: Record<string, string[]> = {
      entity: ['user', 'system', 'resource'],
      observation: ['event', 'metric', 'log'],
      decision: ['approval', 'policy', 'strategy'],
      issue: ['bug', 'problem', 'incident'],
      todo: ['task', 'action', 'work'],
      incident: ['outage', 'emergency', 'critical'],
      release: ['deployment', 'version', 'launch'],
      risk: ['threat', 'vulnerability', 'exposure'],
      assumption: ['hypothesis', 'premise', 'belief'],
      runbook: ['procedure', 'guide', 'process']
    };

    const tags = tagSets[type] || ['general'];
    const count = Math.floor(Math.random() * 3) + 1;
    return tags.sort(() => Math.random() - 0.5).slice(0, count);
  }

  /**
   * Generate metadata for item type
   */
  private generateMetadata(type: string, index: number): Record<string, any> {
    const baseMetadata = {
      index,
      generated: true,
      benchmark: true
    };

    const typeSpecific: Record<string, Record<string, any>> = {
      entity: { category: 'resource', active: true },
      observation: { source: 'system', level: 'info' },
      decision: { status: 'approved', impact: 'medium' },
      issue: { severity: 'medium', status: 'open' },
      todo: { priority: 'medium', completed: false },
      incident: { severity: 'high', resolved: false },
      release: { status: 'deployed', rollback: false },
      risk: { probability: 'medium', impact: 'high' },
      assumption: { validated: false, confidence: 'medium' },
      runbook: { category: 'operational', automated: false }
    };

    return { ...baseMetadata, ...(typeSpecific[type] || {}) };
  }

  /**
   * Get random element from array
   */
  private randomElement<T>(array: T[]): T {
    return array[Math.floor(Math.random() * array.length)];
  }

  /**
   * Generate predefined datasets for common benchmark scenarios
   */
  async generatePredefinedDataset(type: 'small' | 'medium' | 'large' | 'enterprise'): Promise<TestDataset> {
    const configs: Record<string, DataGeneratorConfig> = {
      small: {
        itemCount: 1000,
        itemTypes: ['entity', 'observation', 'decision'],
        sizeDistribution: { min: 100, max: 1000, average: 500 },
        relationshipDensity: 0.1,
        embeddingDimensions: 512
      },
      medium: {
        itemCount: 10000,
        itemTypes: ['entity', 'observation', 'decision', 'issue', 'todo'],
        sizeDistribution: { min: 200, max: 2000, average: 1000 },
        relationshipDensity: 0.15,
        embeddingDimensions: 1024
      },
      large: {
        itemCount: 100000,
        itemTypes: ['entity', 'observation', 'decision', 'issue', 'todo', 'incident', 'release'],
        sizeDistribution: { min: 500, max: 5000, average: 2000 },
        relationshipDensity: 0.2,
        embeddingDimensions: 1536
      },
      enterprise: {
        itemCount: 1000000,
        itemTypes: Object.keys(this.CONTENT_TEMPLATES),
        sizeDistribution: { min: 1000, max: 10000, average: 5000 },
        relationshipDensity: 0.25,
        embeddingDimensions: 1536
      }
    };

    return this.generateDataset(configs[type]);
  }
}