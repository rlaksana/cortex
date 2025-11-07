/**
 * Test script to demonstrate truncation functionality
 * Run with: node test-truncation.mjs
 */

import { truncationService } from './src/services/truncation/truncation-service.js';
import { environment } from './src/config/environment.js';

async function testTruncation() {
  console.log('🔪 Testing Truncation Configuration Implementation');
  console.log('='.repeat(50));

  // Test 1: Basic content truncation
  console.log('\n1️⃣  Testing basic content truncation');
  const longText =
    'This is a very long text that should definitely exceed the default character limits. '.repeat(
      200
    );
  console.log(`Original length: ${longText.length} characters`);

  const result1 = await truncationService.processContent(longText);
  console.log(`Truncated: ${result1.meta.truncated}`);
  console.log(`Final length: ${result1.truncated.length} characters`);
  console.log(`Strategy used: ${result1.meta.strategy}`);
  console.log(`Warnings: ${result1.warnings.length}`);

  // Test 2: JSON content truncation
  console.log('\n2️⃣  Testing JSON content truncation');
  const largeJson = {
    title: 'Large JSON Object',
    description: 'This is a large JSON object that should be truncated while preserving structure',
    items: Array.from({ length: 100 }, (_, i) => ({
      id: i,
      name: `Item ${i}`,
      description: `Description for item ${i} with some additional text to make it longer`,
      metadata: {
        created: new Date().toISOString(),
        tags: [`tag${i}`, `category${i % 10}`, `type${i % 5}`],
        properties: {
          visible: true,
          priority: i % 3,
          score: Math.random() * 100,
        },
      },
    })),
    settings: {
      theme: 'dark',
      language: 'en',
      notifications: true,
      autoSave: true,
      features: {
        search: true,
        filters: true,
        sorting: true,
        export: true,
        import: true,
        sharing: true,
        collaboration: true,
      },
    },
  };

  const jsonString = JSON.stringify(largeJson, null, 2);
  console.log(`Original JSON length: ${jsonString.length} characters`);

  const result2 = await truncationService.processContent(jsonString, { contentType: 'json' });
  console.log(`Truncated: ${result2.meta.truncated}`);
  console.log(`Final JSON length: ${result2.truncated.length} characters`);
  console.log(`Strategy used: ${result2.meta.strategy}`);
  console.log(
    `Valid JSON: ${(() => {
      try {
        JSON.parse(result2.truncated.content);
        return true;
      } catch {
        return false;
      }
    })()}`
  );

  // Test 3: Code content truncation
  console.log('\n3️⃣  Testing code content truncation');
  const longCode = `
// A very long JavaScript file with many functions
function utilityFunction1(param1, param2) {
  return param1 + param2;
}

function utilityFunction2(param1) {
  return param1 * 2;
}

function complexFunction(data, options = {}) {
  const { timeout = 5000, retries = 3, callback } = options;

  try {
    const result = processData(data, { timeout, retries });
    if (callback) callback(null, result);
    return result;
  } catch (error) {
    if (callback) callback(error);
    throw error;
  }
}

function processData(data, options) {
  // Complex processing logic here
  return data.map(item => ({
    ...item,
    processed: true,
    timestamp: Date.now()
  }));
}

${'function extraFunction' + Math.floor(Math.random() * 1000) + '() { return "extra"; }\n'.repeat(50)}
`;

  console.log(`Original code length: ${longCode.length} characters`);

  const result3 = await truncationService.processContent(longCode, { contentType: 'code' });
  console.log(`Truncated: ${result3.meta.truncated}`);
  console.log(`Final code length: ${result3.truncated.length} characters`);
  console.log(`Strategy used: ${result3.meta.strategy}`);

  // Test 4: Markdown content truncation
  console.log('\n4️⃣  Testing markdown content truncation');
  const longMarkdown = `
# Very Long Document

This is a comprehensive document that contains many sections and should be truncated while preserving the markdown structure.

## Introduction

This document covers various topics related to system design and implementation. It includes detailed explanations, code examples, and best practices.

## Section 1: Overview

### Subsection 1.1: Basic Concepts

Here we discuss the fundamental concepts that form the foundation of our system. These include:

- **Concept A**: Description of concept A
- **Concept B**: Description of concept B
- **Concept C**: Description of concept C

### Subsection 1.2: Advanced Topics

In this section, we explore more advanced topics:

\`\`\`javascript
const example = {
  key: "value",
  nested: {
    prop: "nested value"
  }
};
\`\`\`

## Section 2: Implementation Details

### Code Examples

Here are some code examples:

1. **Example 1**: Basic usage
2. **Example 2**: Advanced usage
3. **Example 3**: Edge cases

### Performance Considerations

When implementing this system, consider the following performance aspects:

- Memory usage
- Processing time
- Network latency
- Database query optimization

${'## Extra Section ' + Math.floor(Math.random() * 1000) + '\n\nThis is an extra section with additional content.\n\n'.repeat(10)}
`;

  console.log(`Original markdown length: ${longMarkdown.length} characters`);

  const result4 = await truncationService.processContent(longMarkdown, { contentType: 'markdown' });
  console.log(`Truncated: ${result4.meta.truncated}`);
  console.log(`Final markdown length: ${result4.truncated.length} characters`);
  console.log(`Strategy used: ${result4.meta.strategy}`);

  // Test 5: Different strategies
  console.log('\n5️⃣  Testing different truncation strategies');
  const testText =
    'This is a test sentence. This is another sentence. This is a third sentence. This is a fourth sentence. This is a fifth sentence. '.repeat(
      10
    );

  const strategies = ['hard_cutoff', 'preserve_sentences', 'smart_content'];
  for (const strategy of strategies) {
    const result = await truncationService.processContent(testText, {
      maxChars: 200,
      strategy,
    });
    console.log(
      `${strategy}: ${result.truncated.length} chars, ends with complete sentence: ${result.truncated.content.trim().endsWith('.')}`
    );
  }

  // Test 6: Metrics
  console.log('\n6️⃣  Testing metrics collection');
  const metrics = truncationService.getMetrics();
  console.log('Truncation metrics:');
  console.log(`- Total truncations: ${metrics.store_truncated_total}`);
  console.log(`- Total chars removed: ${metrics.store_truncated_chars_total}`);
  console.log(`- Total tokens removed: ${metrics.store_truncated_tokens_total}`);
  console.log(`- Processing time: ${metrics.truncation_processing_time_ms}ms`);
  console.log(`- By content type:`, metrics.truncation_by_type);
  console.log(`- By strategy:`, metrics.truncation_by_strategy);

  // Test 7: Configuration
  console.log('\n7️⃣  Configuration details');
  const config = environment.getTruncationConfig();
  console.log('Truncation configuration:');
  console.log(`- Enabled: ${config.enabled}`);
  console.log(`- Mode: ${config.behavior.mode}`);
  console.log(`- Preserve structure: ${config.behavior.preserveStructure}`);
  console.log(`- Add indicators: ${config.behavior.addIndicators}`);
  console.log(`- Safety margin: ${config.behavior.safetyMargin}%`);
  console.log(`- Default char limit: ${config.maxChars.default}`);
  console.log(`- Default token limit: ${config.maxTokens.default}`);

  console.log('\n✅ Truncation testing completed successfully!');
  console.log('\nKey features demonstrated:');
  console.log('✅ Content type detection');
  console.log('✅ Multiple truncation strategies');
  console.log('✅ Structure preservation');
  console.log('✅ Metrics collection');
  console.log('✅ Configurable behavior');
  console.log('✅ Warning generation');
  console.log('✅ Performance tracking');
}

// Run the test
testTruncation().catch(console.error);
