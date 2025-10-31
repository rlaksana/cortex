import { MemoryStoreOrchestrator } from '../../src/services/orchestrators/memory-store-orchestrator';

describe('Memory Store Chunking Integration (TDD - Failing Test)', () => {
  let orchestrator: MemoryStoreOrchestrator;

  beforeEach(() => {
    orchestrator = new MemoryStoreOrchestrator();
  });

  describe('Large Content Chunking for Section, Runbook, and Incident Types', () => {
    const generateLargeContent = (charCount: number): string => {
      const paragraphs = [];
      const baseParagraph = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. ' +
        'Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ' +
        'Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris ' +
        'nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in ' +
        'reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla ' +
        'pariatur. Excepteur sint occaecat cupidatat non proident, sunt in ' +
        'culpa qui officia deserunt mollit anim id est laborum.';

      while (paragraphs.join('\n\n').length < charCount) {
        paragraphs.push(`Paragraph ${paragraphs.length + 1}: ${baseParagraph}`);
      }

      return paragraphs.join('\n\n').substring(0, charCount);
    };

    const CHUNKING_TARGET_SIZE = 1200; // Expected chunk size
    const CHUNKING_OVERLAP = 200; // Expected overlap size
    const LARGE_CONTENT_SIZE = 10000; // 10k+ characters to trigger chunking

    describe('Section Type Chunking', () => {
      it('should chunk large section content into parent + children structure', async () => {
        const largeSectionContent = generateLargeContent(LARGE_CONTENT_SIZE);

        const sectionItem = {
          kind: 'section',
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Large Architecture Documentation',
            heading: 'Architecture Overview',
            body_text: largeSectionContent
          }
        };

        const response = await orchestrator.storeItems([sectionItem]);

        // Test should fail initially - chunking not yet integrated
        // Expected behavior after implementation:
        expect(response.items).toHaveLength(greaterThan(1)); // Should have parent + children

        const parentItem = response.items.find(item =>
          !item.reason?.includes('chunk') && item.status === 'stored'
        );
        expect(parentItem).toBeDefined();
        expect(parentItem?.kind).toBe('section');

        const childItems = response.items.filter(item =>
          item.reason?.includes('chunk') || item.id !== parentItem?.id
        );
        expect(childItems.length).toBeGreaterThan(0);
        expect(childItems.length).toBeLessThan(15); // Reasonable number of chunks

        // Verify parent-child relationships and chunk metadata linking
        childItems.forEach((child, index) => {
          expect(child.kind).toBe('section');
          expect(child.data.is_chunk).toBe(true);
          expect(child.data.parent_id).toBe(parentItem?.id);
          expect(child.data.chunk_index).toBe(index);
          expect(child.data.total_chunks).toBe(childItems.length);
          expect(child.data.original_length).toBe(LARGE_CONTENT_SIZE);
          expect(child.data.chunk_overlap).toBe(CHUNKING_OVERLAP);
        });

        // Verify content preservation
        const totalChildContent = childItems.reduce((total, child) => {
          return total + (child.content || '').length;
        }, 0);
        expect(totalChildContent).toBeGreaterThanOrEqual(LARGE_CONTENT_SIZE * 0.9); // Allow for some overlap
      });

      it('should not chunk small section content', async () => {
        const smallSectionContent = generateLargeContent(1000); // Below chunking threshold

        const sectionItem = {
          kind: 'section',
          content: smallSectionContent,
          scope: { project: 'test-project', branch: 'main' },
          metadata: {
            title: 'Small Documentation',
            heading: 'Overview',
            tags: { component: 'docs' }
          }
        };

        const response = await orchestrator.storeItems([sectionItem]);

        // Should only have one item (no chunking)
        expect(response.items).toHaveLength(1);
        expect(response.items[0].status).toBe('stored');
        expect(response.items[0].kind).toBe('section');
        expect(response.items[0].content).toBe(smallSectionContent);
      });
    });

    describe('Runbook Type Chunking', () => {
      it('should chunk large runbook content into parent + children structure', async () => {
        const largeRunbookSteps = Array.from({ length: 50 }, (_, i) => ({
          step_number: i + 1,
          description: generateLargeContent(200), // Each step is 200 chars
          command: `echo "Step ${i + 1} completed"`,
          expected_output: `Step ${i + 1} executed successfully`,
          troubleshooting_notes: generateLargeContent(100)
        }));

        const largeRunbookContent = JSON.stringify(largeRunbookSteps, null, 2);

        const runbookItem = {
          kind: 'runbook',
          content: JSON.stringify(largeRunbookSteps, null, 2),
          scope: { project: 'test-project', branch: 'main' },
          metadata: {
            title: 'Comprehensive System Recovery Runbook',
            description: 'Detailed procedures for system recovery and maintenance',
            steps: largeRunbookSteps,
            category: 'disaster_recovery',
            severity: 'critical',
            estimated_duration: '4 hours'
          }
        };

        const response = await orchestrator.storeItems([runbookItem]);

        // Test should fail initially - chunking not yet integrated
        // Expected behavior after implementation:
        expect(response.items).toHaveLength(greaterThan(1)); // Should have parent + children

        const parentItem = response.items.find(item =>
          !item.reason?.includes('chunk') && item.status === 'stored'
        );
        expect(parentItem).toBeDefined();
        expect(parentItem?.kind).toBe('runbook');

        const childItems = response.items.filter(item =>
          item.reason?.includes('chunk') || item.id !== parentItem?.id
        );
        expect(childItems.length).toBeGreaterThan(0);
        expect(childItems.length).toBeLessThan(10); // Reasonable number of chunks

        // Verify runbook-specific structure is preserved and chunk metadata linking
        childItems.forEach((child, index) => {
          expect(child.kind).toBe('runbook');
          // Child should maintain runbook structure with chunk of steps
          expect(child.content).toContain('step_number');

          // Verify chunk metadata linking
          expect(child.data.is_chunk).toBe(true);
          expect(child.data.parent_id).toBe(parentItem?.id);
          expect(child.data.chunk_index).toBe(index);
          expect(child.data.total_chunks).toBe(childItems.length);
        });
      });

      it('should preserve runbook metadata across chunks', async () => {
        const largeRunbookContent = generateLargeContent(LARGE_CONTENT_SIZE);

        const runbookItem = {
          kind: 'runbook',
          content: largeRunbookContent,
          scope: { project: 'test-project', branch: 'main', org: 'test-org' },
          metadata: {
            author: 'test-author',
            version: '1.0',
            last_reviewed: '2025-01-01',
            title: 'Critical Incident Response Runbook',
            description: 'Procedures for handling critical incidents',
            steps: largeRunbookContent,
            category: 'incident_response',
            severity: 'critical',
            estimated_duration: '2 hours',
            prerequisites: ['Admin access', 'Monitoring tools'],
            related_documents: ['INC-001', 'RUNBOOK-002']
          }
        };

        const response = await orchestrator.storeItems([runbookItem]);

        const parentItem = response.items.find(item =>
          !item.reason?.includes('chunk') && item.status === 'stored'
        );
        const childItems = response.items.filter(item =>
          item.reason?.includes('chunk') || item.id !== parentItem?.id
        );

        // Verify metadata is preserved in all chunks
        childItems.forEach((child, index) => {
          expect(child.kind).toBe('runbook');
          expect(child.scope).toEqual({ project: 'test-project', branch: 'main', org: 'test-org' });
          expect(child.data.author).toBe('test-author');
          expect(child.data.version).toBe('1.0');
          expect(child.data.last_reviewed).toBe('2025-01-01');

          // Verify chunk metadata linking
          expect(child.data.is_chunk).toBe(true);
          expect(child.data.parent_id).toBe(parentItem?.id);
          expect(child.data.chunk_index).toBe(index);
          expect(child.data.total_chunks).toBe(childItems.length);
        });
      });
    });

    describe('Incident Type Chunking', () => {
      it('should chunk large incident content into parent + children structure', async () => {
        const largeIncidentDescription = generateLargeContent(LARGE_CONTENT_SIZE);
        const largeTimeline = Array.from({ length: 100 }, (_, i) => ({
          timestamp: new Date(Date.now() - (100 - i) * 60000).toISOString(),
          event: `Timeline event ${i + 1}: ${generateLargeContent(50)}`,
          severity: i % 10 === 0 ? 'high' : 'medium',
          source: 'monitoring'
        }));

        const incidentItem = {
          kind: 'incident',
          content: largeIncidentDescription,
          scope: { project: 'test-project', branch: 'main' },
          metadata: {
            incident_id: 'INC-2025-001',
            title: 'Major System Outage',
            description: largeIncidentDescription,
            severity: 'critical',
            resolution_status: 'investigating',
            impact_assessment: generateLargeContent(1000),
            affected_systems: ['api-gateway', 'database', 'cache'],
            timeline: largeTimeline,
            root_cause_analysis: generateLargeContent(2000),
            mitigation_steps: generateLargeContent(1500),
            incident_commander: 'john.doe@company.com',
            stakeholders: ['engineering@company.com', 'support@company.com']
          }
        };

        const response = await orchestrator.storeItems([incidentItem]);

        // Test should fail initially - chunking not yet integrated
        // Expected behavior after implementation:
        expect(response.items).toHaveLength(greaterThan(1)); // Should have parent + children

        const parentItem = response.items.find(item =>
          !item.reason?.includes('chunk') && item.status === 'stored'
        );
        expect(parentItem).toBeDefined();
        expect(parentItem?.kind).toBe('incident');

        const childItems = response.items.filter(item =>
          item.reason?.includes('chunk') || item.id !== parentItem?.id
        );
        expect(childItems.length).toBeGreaterThan(0);

        // Verify incident-specific structure is preserved and chunk metadata linking
        childItems.forEach((child, index) => {
          expect(child.kind).toBe('incident');
          expect(child.data.incident_id).toBe('INC-2025-001'); // Incident ID should be preserved

          // Verify chunk metadata linking
          expect(child.data.is_chunk).toBe(true);
          expect(child.data.parent_id).toBe(parentItem?.id);
          expect(child.data.chunk_index).toBe(index);
          expect(child.data.total_chunks).toBe(childItems.length);
        });
      });

      it('should maintain incident critical fields across chunks', async () => {
        const largeIncidentContent = generateLargeContent(LARGE_CONTENT_SIZE);

        const incidentItem = {
          kind: 'incident',
          content: largeIncidentContent,
          scope: { project: 'test-project', branch: 'main' },
          metadata: {
            incident_id: 'INC-2025-002',
            title: 'Security Incident',
            severity: 'critical',
            resolution_status: 'investigating',
            description: largeIncidentContent,
            incident_commander: 'security@company.com',
            affected_systems: ['auth-service', 'user-database']
          }
        };

        const response = await orchestrator.storeItems([incidentItem]);

        const parentItem = response.items.find(item =>
          !item.reason?.includes('chunk') && item.status === 'stored'
        );
        const childItems = response.items.filter(item =>
          item.reason?.includes('chunk') || item.id !== parentItem?.id
        );

        // Critical incident fields should be preserved
        expect(parentItem?.kind).toBe('incident');
        childItems.forEach((child, index) => {
          expect(child.kind).toBe('incident');
          expect(child.data.incident_id).toBe('INC-2025-002');
          expect(child.data.severity).toBe('critical');
          expect(child.data.resolution_status).toBe('investigating');

          // Verify chunk metadata linking
          expect(child.data.is_chunk).toBe(true);
          expect(child.data.parent_id).toBe(parentItem?.id);
          expect(child.data.chunk_index).toBe(index);
          expect(child.data.total_chunks).toBe(childItems.length);
        });
      });
    });

    describe('Non-Chunking Types Should Not Be Chunked', () => {
      it('should not chunk decision type regardless of size', async () => {
        const largeDecisionContent = generateLargeContent(LARGE_CONTENT_SIZE);

        const decisionItem = {
          kind: 'decision',
          content: largeDecisionContent,
          scope: { project: 'test-project', branch: 'main' },
          metadata: {
            title: 'Architecture Decision',
            status: 'accepted',
            component: 'api-gateway',
            rationale: largeDecisionContent,
            alternatives_considered: ['Option A', 'Option B', 'Option C']
          }
        };

        const response = await orchestrator.storeItems([decisionItem]);

        // Should not be chunked - decisions are not in the chunking list
        expect(response.items).toHaveLength(1);
        expect(response.items[0].status).toBe('stored');
        expect(response.items[0].kind).toBe('decision');
      });

      it('should not chunk observation type regardless of size', async () => {
        const largeObservationContent = generateLargeContent(LARGE_CONTENT_SIZE);

        const observationItem = {
          kind: 'observation',
          content: largeObservationContent,
          scope: { project: 'test-project', branch: 'main' },
          metadata: {
            title: 'System Performance Observation',
            content: largeObservationContent,
            category: 'performance',
            metrics: { cpu_usage: '85%', memory_usage: '78%' }
          }
        };

        const response = await orchestrator.storeItems([observationItem]);

        // Should not be chunked - observations are not in the chunking list
        expect(response.items).toHaveLength(1);
        expect(response.items[0].status).toBe('stored');
        expect(response.items[0].kind).toBe('observation');
      });
    });

    describe('Chunking Quality and Validation', () => {
      it('should create chunks with appropriate size boundaries', async () => {
        const largeContent = generateLargeContent(LARGE_CONTENT_SIZE);

        const sectionItem = {
          kind: 'section',
          content: largeContent,
          scope: { project: 'test-project', branch: 'main' },
          metadata: {
            title: 'Large Documentation',
            heading: 'Overview'
          }
        };

        const response = await orchestrator.storeItems([sectionItem]);

        const childItems = response.items.filter(item =>
          item.reason?.includes('chunk') || item.id !== response.items[0]?.id
        );

        // Test should fail until chunking is implemented
        if (childItems.length > 0) {
          childItems.forEach(child => {
            const contentLength = (child.content || '').length;
            // Each chunk should be roughly the target size (allowing 50% variance)
            expect(contentLength).toBeGreaterThan(CHUNKING_TARGET_SIZE * 0.5);
            expect(contentLength).toBeLessThan(CHUNKING_TARGET_SIZE * 1.5);
          });
        } else {
          // This will fail until chunking is implemented
          expect.fail('Expected chunks to be created for large content');
        }
      });

      it('should maintain content continuity between chunks', async () => {
        const largeContent = generateLargeContent(LARGE_CONTENT_SIZE);

        const sectionItem = {
          kind: 'section',
          content: largeContent,
          scope: { project: 'test-project', branch: 'main' },
          metadata: {
            title: 'Continuity Test Document',
            heading: 'Test Content'
          }
        };

        const response = await orchestrator.storeItems([sectionItem]);

        const childItems = response.items.filter(item =>
          item.reason?.includes('chunk') || item.id !== response.items[0]?.id
        );

        if (childItems.length > 1) {
          // Check for overlap between consecutive chunks
          for (let i = 1; i < childItems.length; i++) {
            const prevChunkEnd = childItems[i - 1].content?.slice(-CHUNKING_OVERLAP);
            const currChunkStart = childItems[i].content?.slice(0, CHUNKING_OVERLAP);

            if (prevChunkEnd && currChunkStart) {
              // Should have some overlapping content
              const overlapRatio = calculateOverlap(prevChunkEnd, currChunkStart);
              expect(overlapRatio).toBeGreaterThan(0.1); // At least 10% overlap
            }
          }
        } else {
          // This will fail until chunking is implemented
          expect.fail('Expected multiple chunks for large content');
        }
      });
    });
  });
});

// Helper function to calculate text overlap
function calculateOverlap(text1: string, text2: string): number {
  const maxOverlap = Math.min(text1.length, text2.length);
  let matchingChars = 0;

  for (let i = 0; i < maxOverlap; i++) {
    if (text1[text1.length - 1 - i] === text2[i]) {
      matchingChars++;
    } else {
      break;
    }
  }

  return matchingChars / maxOverlap;
}

// Helper function for Jest expect
function greaterThan(value: number) {
  return {
    asymmetricMatch: (actual: number) => actual > value,
    toString: () => `> ${value}`
  };
}