/**
 * Comprehensive Unit Tests for Storage Service
 *
 * Tests advanced storage service functionality including:
 * - File upload and download operations
 * - Storage bucket management and lifecycle
 * - Object versioning and metadata handling
 * - Multi-part upload processing
 * - Compression and optimization strategies
 * - Caching mechanisms and bandwidth management
 * - Authentication, authorization, and security
 * - Data encryption and secure URL generation
 * - Storage analytics and usage metrics
 * - Performance optimization and recommendations
 * - Backup, replication, and disaster recovery
 * - Data integrity verification and recovery procedures
 * - Integration with knowledge assets and services
 * - Export file management and cache storage
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { StorageService } from '../../../src/services/storage/storage.service';
import type {
  StorageBucket,
  StorageObject,
  StorageMetrics,
  StorageAnalytics,
  StorageConfig,
  UploadRequest,
  DownloadRequest,
  StoragePermissions,
  StorageBackup,
  StorageIntegrity,
  StorageOptimization,
  StoragePerformance,
  StorageSecurity,
  StorageUsageMetrics
} from '../../../src/types/core-interfaces';

// Mock dependencies
vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn()
  }
}));

vi.mock('../../../src/db/qdrant', () => ({
  getQdrantClient: () => mockQdrantClient
}));

// Mock storage provider clients
const mockS3Client = {
  createBucket: vi.fn(),
  deleteBucket: vi.fn(),
  headBucket: vi.fn(),
  listBuckets: vi.fn(),
  putObject: vi.fn(),
  getObject: vi.fn(),
  deleteObject: vi.fn(),
  headObject: vi.fn(),
  listObjectsV2: vi.fn(),
  createMultipartUpload: vi.fn(),
  uploadPart: vi.fn(),
  completeMultipartUpload: vi.fn(),
  abortMultipartUpload: vi.fn(),
  generatePresignedUrl: vi.fn(),
  getBucketVersioning: vi.fn(),
  putBucketVersioning: vi.fn(),
  getObjectTagging: vi.fn(),
  putObjectTagging: vi.fn(),
  getBucketLifecycleConfiguration: vi.fn(),
  putBucketLifecycleConfiguration: vi.fn(),
  getBucketEncryption: vi.fn(),
  putBucketEncryption: vi.fn(),
  getBucketPolicy: vi.fn(),
  putBucketPolicy: vi.fn()
};

const mockCloudFrontClient = {
  createInvalidation: vi.fn(),
  getInvalidation: vi.fn(),
  listInvalidations: vi.fn()
};

const mockQdrantClient = {
  storageAsset: {
    create: vi.fn(),
    findMany: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    findUnique: vi.fn(),
    count: vi.fn()
  },
  storageMetrics: {
    create: vi.fn(),
    findMany: vi.fn(),
    aggregate: vi.fn()
  }
};

describe('StorageService - Comprehensive Storage Functionality', () => {
  let storageService: StorageService;

  beforeEach(() => {
    storageService = new StorageService({
      provider: 's3',
      region: 'us-east-1',
      bucket: 'test-storage-bucket',
      encryption: true,
      versioning: true,
      compression: true,
      caching: true,
      cdn: true
    });

    // Reset all mocks
    vi.clearAllMocks();

    // Setup default successful mock responses
    mockS3Client.createBucket.mockResolvedValue({ Location: 'test-bucket' });
    mockS3Client.headBucket.mockResolvedValue({});
    mockS3Client.listBuckets.mockResolvedValue({ Buckets: [] });
    mockS3Client.putObject.mockResolvedValue({ ETag: 'test-etag', VersionId: 'test-version' });
    mockS3Client.getObject.mockResolvedValue({ Body: Buffer.from('test content'), ETag: 'test-etag' });
    mockS3Client.deleteObject.mockResolvedValue({});
    mockS3Client.headObject.mockResolvedValue({ ContentLength: 1024, ETag: 'test-etag' });
    mockS3Client.listObjectsV2.mockResolvedValue({ Contents: [] });
    mockS3Client.createMultipartUpload.mockResolvedValue({ UploadId: 'test-upload-id' });
    mockS3Client.uploadPart.mockResolvedValue({ ETag: 'part-etag' });
    mockS3Client.completeMultipartUpload.mockResolvedValue({ Location: 'test-location' });
    mockS3Client.abortMultipartUpload.mockResolvedValue({});
    mockS3Client.generatePresignedUrl.mockReturnValue('https://test-url.com/file');
    mockS3Client.getBucketVersioning.mockResolvedValue({ Status: 'Enabled' });
    mockS3Client.putBucketVersioning.mockResolvedValue({});
    mockS3Client.getObjectTagging.mockResolvedValue({ TagSet: [] });
    mockS3Client.putObjectTagging.mockResolvedValue({});
    mockS3Client.getBucketLifecycleConfiguration.mockResolvedValue({ Rules: [] });
    mockS3Client.putBucketLifecycleConfiguration.mockResolvedValue({});
    mockS3Client.getBucketEncryption.mockResolvedValue({ ServerSideEncryptionConfiguration: {} });
    mockS3Client.putBucketEncryption.mockResolvedValue({});
    mockS3Client.getBucketPolicy.mockResolvedValue({ Policy: '{}' });
    mockS3Client.putBucketPolicy.mockResolvedValue({});

    mockCloudFrontClient.createInvalidation.mockResolvedValue({ Invalidation: { Id: 'test-invalidation' } });
    mockCloudFrontClient.getInvalidation.mockResolvedValue({ Invalidation: { Status: 'Completed' } });
    mockCloudFrontClient.listInvalidations.mockResolvedValue({ InvalidationList: { Items: [] } });

    mockQdrantClient.storageAsset.create.mockResolvedValue({ id: 'test-asset-id' });
    mockQdrantClient.storageAsset.findMany.mockResolvedValue([]);
    mockQdrantClient.storageAsset.findUnique.mockResolvedValue(null);
    mockQdrantClient.storageAsset.update.mockResolvedValue({});
    mockQdrantClient.storageAsset.delete.mockResolvedValue({});
    mockQdrantClient.storageAsset.count.mockResolvedValue(0);
    mockQdrantClient.storageMetrics.aggregate.mockResolvedValue({ _sum: { size: 1024, count: 1 } });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. Storage Operations Tests
  describe('Storage Operations', () => {
    it('should upload files successfully', async () => {
      const uploadRequest: UploadRequest = {
        key: 'test-file.txt',
        body: Buffer.from('test content'),
        contentType: 'text/plain',
        metadata: { originalName: 'test-file.txt' }
      };

      const result = await storageService.uploadFile(uploadRequest);

      expect(result.key).toBe(uploadRequest.key);
      expect(result.etag).toBe('test-etag');
      expect(result.versionId).toBe('test-version');
      expect(result.url).toBeDefined();
      expect(mockS3Client.putObject).toHaveBeenCalledWith(expect.objectContaining({
        Key: uploadRequest.key,
        Body: uploadRequest.body,
        ContentType: uploadRequest.contentType
      }));
      expect(mockQdrantClient.storageAsset.create).toHaveBeenCalled();
    });

    it('should handle large files with multi-part upload', async () => {
      const largeContent = Buffer.alloc(100 * 1024 * 1024); // 100MB file
      const uploadRequest: UploadRequest = {
        key: 'large-file.bin',
        body: largeContent,
        contentType: 'application/octet-stream'
      };

      const result = await storageService.uploadFile(uploadRequest);

      expect(result.key).toBe(uploadRequest.key);
      expect(mockS3Client.createMultipartUpload).toHaveBeenCalled();
      expect(mockS3Client.uploadPart).toHaveBeenCalled();
      expect(mockS3Client.completeMultipartUpload).toHaveBeenCalled();
    });

    it('should download files successfully', async () => {
      const downloadRequest: DownloadRequest = {
        key: 'test-file.txt',
        versionId: 'test-version'
      };

      const result = await storageService.downloadFile(downloadRequest);

      expect(result.body).toBeInstanceOf(Buffer);
      expect(result.etag).toBe('test-etag');
      expect(result.contentType).toBeDefined();
      expect(mockS3Client.getObject).toHaveBeenCalledWith(expect.objectContaining({
        Key: downloadRequest.key,
        VersionId: downloadRequest.versionId
      }));
    });

    it('should delete files successfully', async () => {
      const deleteRequest = {
        key: 'test-file.txt',
        versionId: 'test-version'
      };

      const result = await storageService.deleteFile(deleteRequest.key, deleteRequest.versionId);

      expect(result.success).toBe(true);
      expect(mockS3Client.deleteObject).toHaveBeenCalledWith(expect.objectContaining({
        Key: deleteRequest.key,
        VersionId: deleteRequest.versionId
      }));
      expect(mockQdrantClient.storageAsset.delete).toHaveBeenCalled();
    });

    it('should list files with pagination', async () => {
      mockS3Client.listObjectsV2.mockResolvedValue({
        Contents: [
          { Key: 'file1.txt', ETag: 'etag1', Size: 1024, LastModified: new Date() },
          { Key: 'file2.txt', ETag: 'etag2', Size: 2048, LastModified: new Date() }
        ],
        NextContinuationToken: 'next-token',
        IsTruncated: true
      });

      const result = await storageService.listFiles({
        prefix: 'test/',
        maxKeys: 1000,
        continuationToken: 'token'
      });

      expect(result.objects).toHaveLength(2);
      expect(result.objects[0].key).toBe('file1.txt');
      expect(result.isTruncated).toBe(true);
      expect(result.nextContinuationToken).toBe('next-token');
    });

    it('should handle file metadata operations', async () => {
      const metadataRequest = {
        key: 'test-file.txt',
        metadata: { category: 'document', priority: 'high' }
      };

      const result = await storageService.updateFileMetadata(metadataRequest.key, metadataRequest.metadata);

      expect(result.success).toBe(true);
      expect(mockS3Client.putObjectTagging).toHaveBeenCalledWith(expect.objectContaining({
        Key: metadataRequest.key,
        Tagging: expect.stringContaining('category=document')
      }));
    });

    it('should compress files when compression is enabled', async () => {
      const uncompressedContent = Buffer.from('repeated content repeated content repeated content');
      const uploadRequest: UploadRequest = {
        key: 'compressible.txt',
        body: uncompressedContent,
        contentType: 'text/plain'
      };

      const result = await storageService.uploadFile(uploadRequest);

      expect(result.compressed).toBe(true);
      expect(result.originalSize).toBeGreaterThan(result.compressedSize);
    });

    it('should handle upload errors gracefully', async () => {
      mockS3Client.putObject.mockRejectedValue(new Error('Network error'));

      const uploadRequest: UploadRequest = {
        key: 'error-file.txt',
        body: Buffer.from('content'),
        contentType: 'text/plain'
      };

      await expect(storageService.uploadFile(uploadRequest)).rejects.toThrow('Failed to upload file');
    });

    it('should handle concurrent upload operations', async () => {
      const uploadRequests = Array.from({ length: 10 }, (_, i) => ({
        key: `concurrent-file-${i}.txt`,
        body: Buffer.from(`content ${i}`),
        contentType: 'text/plain'
      }));

      const results = await Promise.all(uploadRequests.map(req => storageService.uploadFile(req)));

      expect(results).toHaveLength(10);
      results.forEach((result, index) => {
        expect(result.key).toBe(uploadRequests[index].key);
        expect(result.etag).toBeDefined();
      });
    });
  });

  // 2. Storage Bucket Management Tests
  describe('Storage Bucket Management', () => {
    it('should create storage buckets successfully', async () => {
      const bucketConfig: Partial<StorageBucket> = {
        name: 'new-test-bucket',
        region: 'us-west-2',
        versioning: true,
        encryption: true,
        lifecycleRules: [
          {
            id: 'delete-old-objects',
            status: 'Enabled',
            transitions: [
              { days: 30, storageClass: 'STANDARD_IA' },
              { days: 90, storageClass: 'GLACIER' }
            ],
            expiration: { days: 365 }
          }
        ]
      };

      const result = await storageService.createBucket(bucketConfig);

      expect(result.name).toBe(bucketConfig.name);
      expect(result.versioning).toBe(true);
      expect(result.encryption).toBe(true);
      expect(mockS3Client.createBucket).toHaveBeenCalled();
      expect(mockS3Client.putBucketVersioning).toHaveBeenCalled();
      expect(mockS3Client.putBucketEncryption).toHaveBeenCalled();
      expect(mockS3Client.putBucketLifecycleConfiguration).toHaveBeenCalled();
    });

    it('should delete storage buckets safely', async () => {
      const bucketName = 'test-bucket-to-delete';

      const result = await storageService.deleteBucket(bucketName);

      expect(result.success).toBe(true);
      expect(result.deletedObjectsCount).toBeGreaterThanOrEqual(0);
      expect(mockS3Client.listObjectsV2).toHaveBeenCalled();
      expect(mockS3Client.deleteObject).toHaveBeenCalled();
      expect(mockS3Client.deleteBucket).toHaveBeenCalled();
    });

    it('should list buckets with metadata', async () => {
      mockS3Client.listBuckets.mockResolvedValue({
        Buckets: [
          { Name: 'bucket1', CreationDate: new Date('2024-01-01') },
          { Name: 'bucket2', CreationDate: new Date('2024-01-02') }
        ]
      });

      const result = await storageService.listBuckets();

      expect(result.buckets).toHaveLength(2);
      expect(result.buckets[0].name).toBe('bucket1');
      expect(result.buckets[0].creationDate).toBeInstanceOf(Date);
      expect(result.buckets[0].objectCount).toBeGreaterThanOrEqual(0);
      expect(result.buckets[0].sizeBytes).toBeGreaterThanOrEqual(0);
    });

    it('should update bucket configurations', async () => {
      const bucketName = 'test-bucket';
      const updates = {
        versioning: false,
        encryption: { algorithm: 'AES256' },
        lifecycleRules: [
          {
            id: 'new-rule',
            status: 'Enabled',
            expiration: { days: 180 }
          }
        ]
      };

      const result = await storageService.updateBucketConfiguration(bucketName, updates);

      expect(result.success).toBe(true);
      expect(mockS3Client.putBucketVersioning).toHaveBeenCalled();
      expect(mockS3Client.putBucketEncryption).toHaveBeenCalled();
      expect(mockS3Client.putBucketLifecycleConfiguration).toHaveBeenCalled();
    });

    it('should validate bucket health', async () => {
      const bucketName = 'healthy-bucket';
      mockS3Client.headBucket.mockResolvedValue({});

      const health = await storageService.checkBucketHealth(bucketName);

      expect(health.isHealthy).toBe(true);
      expect(health.accessible).toBe(true);
      expect(health.responseTime).toBeGreaterThan(0);
      expect(health.errorCount).toBe(0);
    });

    it('should handle bucket health issues', async () => {
      const bucketName = 'unhealthy-bucket';
      mockS3Client.headBucket.mockRejectedValue(new Error('Access denied'));

      const health = await storageService.checkBucketHealth(bucketName);

      expect(health.isHealthy).toBe(false);
      expect(health.accessible).toBe(false);
      expect(health.errorCount).toBeGreaterThan(0);
      expect(health.errors).toContain('Access denied');
    });
  });

  // 3. Object Versioning Tests
  describe('Object Versioning', () => {
    it('should enable versioning on buckets', async () => {
      const bucketName = 'versioned-bucket';

      const result = await storageService.enableVersioning(bucketName);

      expect(result.enabled).toBe(true);
      expect(result.status).toBe('Enabled');
      expect(mockS3Client.putBucketVersioning).toHaveBeenCalledWith({
        Bucket: bucketName,
        VersioningConfiguration: { Status: 'Enabled' }
      });
    });

    it('should list object versions', async () => {
      const key = 'versioned-file.txt';
      mockS3Client.listObjectVersions = vi.fn().mockResolvedValue({
        Versions: [
          { Key: key, VersionId: 'version1', LastModified: new Date(), Size: 1024 },
          { Key: key, VersionId: 'version2', LastModified: new Date(), Size: 1080 }
        ],
        DeleteMarkers: []
      });

      const result = await storageService.listObjectVersions(key);

      expect(result.versions).toHaveLength(2);
      expect(result.versions[0].versionId).toBe('version1');
      expect(result.versions[1].versionId).toBe('version2');
    });

    it('should restore specific object versions', async () => {
      const restoreRequest = {
        key: 'versioned-file.txt',
        sourceVersionId: 'version1',
        destinationKey: 'restored-file.txt'
      };

      const result = await storageService.restoreVersion(restoreRequest);

      expect(result.success).toBe(true);
      expect(result.restoredKey).toBe(restoreRequest.destinationKey);
      expect(result.sourceVersionId).toBe(restoreRequest.sourceVersionId);
    });

    it('should delete specific object versions', async () => {
      const deleteRequest = {
        key: 'versioned-file.txt',
        versionId: 'version-to-delete'
      };

      const result = await storageService.deleteVersion(deleteRequest.key, deleteRequest.versionId);

      expect(result.success).toBe(true);
      expect(mockS3Client.deleteObject).toHaveBeenCalledWith(expect.objectContaining({
        Key: deleteRequest.key,
        VersionId: deleteRequest.versionId
      }));
    });

    it('should prevent accidental deletion with versioning safety', async () => {
      const safetyConfig = {
        enableMfaDelete: true,
        retentionPeriod: 30, // days
        requireConfirmation: true
      };

      const protectedKey = 'critical-file.txt';

      await expect(storageService.deleteFile(protectedKey)).rejects.toThrow('Version protection enabled');
    });
  });

  // 4. Storage Lifecycle Management Tests
  describe('Storage Lifecycle Management', () => {
    it('should create lifecycle rules', async () => {
      const lifecycleRules = [
        {
          id: 'transition-to-ia',
          status: 'Enabled',
          filter: { prefix: 'documents/' },
          transitions: [{ days: 30, storageClass: 'STANDARD_IA' }]
        },
        {
          id: 'archive-old-data',
          status: 'Enabled',
          filter: { prefix: 'archive/' },
          transitions: [
            { days: 60, storageClass: 'GLACIER' },
            { days: 365, storageClass: 'DEEP_ARCHIVE' }
          ]
        }
      ];

      const result = await storageService.createLifecycleRules('test-bucket', lifecycleRules);

      expect(result.success).toBe(true);
      expect(result.rulesCreated).toBe(2);
      expect(mockS3Client.putBucketLifecycleConfiguration).toHaveBeenCalled();
    });

    it('should apply retention policies', async () => {
      const retentionPolicy = {
        mode: 'GOVERNANCE' as const,
        retainUntilDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        enableLegalHold: false
      };

      const result = await storageService.applyRetentionPolicy('test-bucket', 'important-file.txt', retentionPolicy);

      expect(result.applied).toBe(true);
      expect(result.retentionUntil).toBe(retentionPolicy.retainUntilDate);
    });

    it('should handle legal holds', async () => {
      const legalHoldRequest = {
        key: 'legal-hold-file.txt',
        status: 'ON' as const,
        reason: 'Pending litigation case #12345'
      };

      const result = await storageService.setLegalHold(legalHoldRequest.key, legalHoldRequest.status, legalHoldRequest.reason);

      expect(result.success).toBe(true);
      expect(result.status).toBe('ON');
      expect(result.reason).toBe(legalHoldRequest.reason);
    });

    it('should cleanup expired objects', async () => {
      const cleanupRequest = {
        bucketName: 'cleanup-test-bucket',
        olderThan: 90, // days
        dryRun: false
      };

      mockS3Client.listObjectsV2.mockResolvedValue({
        Contents: [
          { Key: 'old-file1.txt', LastModified: new Date(Date.now() - 100 * 24 * 60 * 60 * 1000) },
          { Key: 'old-file2.txt', LastModified: new Date(Date.now() - 95 * 24 * 60 * 60 * 1000) }
        ]
      });

      const result = await storageService.cleanupExpiredObjects(cleanupRequest);

      expect(result.objectsScanned).toBe(2);
      expect(result.objectsDeleted).toBe(2);
      expect(result.spaceReclaimed).toBeGreaterThan(0);
    });
  });

  // 5. Performance and Optimization Tests
  describe('Performance and Optimization', () => {
    it('should optimize multipart upload chunk size', async () => {
      const largeFileSize = 500 * 1024 * 1024; // 500MB
      const uploadRequest: UploadRequest = {
        key: 'large-file.bin',
        body: Buffer.alloc(largeFileSize),
        contentType: 'application/octet-stream'
      };

      await storageService.uploadFile(uploadRequest);

      // Verify optimal chunk size was used
      expect(mockS3Client.uploadPart).toHaveBeenCalledTimes(
        Math.ceil(largeFileSize / storageService.getOptimalChunkSize(largeFileSize))
      );
    });

    it('should implement intelligent caching', async () => {
      const cacheConfig = {
        enabled: true,
        ttl: 3600, // 1 hour
        maxSize: 1000, // items
        evictionPolicy: 'LRU' as const
      };

      storageService.updateCacheConfig(cacheConfig);

      const downloadRequest: DownloadRequest = { key: 'cached-file.txt' };

      // First download
      const result1 = await storageService.downloadFile(downloadRequest);

      // Second download should hit cache
      const result2 = await storageService.downloadFile(downloadRequest);

      expect(result1.etag).toBe(result2.etag);
      expect(storageService.getCacheStats().hitRate).toBeGreaterThan(0);
    });

    it('should implement bandwidth throttling', async () => {
      const throttlingConfig = {
        enabled: true,
        maxBandwidthMBps: 10, // 10 MB/s
        burstAllowance: 50 // MB
      };

      storageService.updateThrottlingConfig(throttlingConfig);

      const largeUploadRequest: UploadRequest = {
        key: 'throttled-upload.bin',
        body: Buffer.alloc(100 * 1024 * 1024), // 100MB
        contentType: 'application/octet-stream'
      };

      const startTime = Date.now();
      await storageService.uploadFile(largeUploadRequest);
      const duration = Date.now() - startTime;

      // Should take at least 10 seconds due to throttling (100MB at 10MB/s)
      expect(duration).toBeGreaterThan(9000); // Allow some margin
    });

    it('should generate performance recommendations', async () => {
      const performanceData = {
        averageUploadSpeed: 5.2, // MB/s
        averageDownloadSpeed: 45.8, // MB/s
        errorRate: 0.02, // 2%
        cacheHitRate: 0.65, // 65%
        compressionRatio: 0.72 // 28% compression
      };

      const recommendations = await storageService.generateOptimizationRecommendations(performanceData);

      expect(recommendations).toContain('Consider enabling multipart uploads for files larger than 100MB');
      expect(recommendations).toContain('Upload speeds are below optimal range');
      expect(recommendations).toContain('Error rate is within acceptable range');
    });

    it('should monitor storage performance in real-time', async () => {
      const performanceMonitor = storageService.enableRealTimeMonitoring({
        intervalMs: 5000,
        metrics: ['throughput', 'latency', 'error_rate', 'cache_hit_rate']
      });

      await new Promise(resolve => setTimeout(resolve, 100)); // Allow monitoring to start

      const metrics = performanceMonitor.getCurrentMetrics();

      expect(metrics.throughput).toBeGreaterThanOrEqual(0);
      expect(metrics.latency).toBeGreaterThanOrEqual(0);
      expect(metrics.errorRate).toBeGreaterThanOrEqual(0);
      expect(metrics.cacheHitRate).toBeGreaterThanOrEqual(0);
      expect(metrics.timestamp).toBeInstanceOf(Date);
    });
  });

  // 6. Security and Access Control Tests
  describe('Security and Access Control', () => {
    it('should generate secure presigned URLs', async () => {
      const urlRequest = {
        key: 'secure-file.pdf',
        expiresIn: 3600, // 1 hour
        operation: 'getObject' as const,
        allowedIp: '192.168.1.100',
        requireTls: true
      };

      const result = await storageService.generatePresignedUrl(urlRequest);

      expect(result.url).toContain('AWSAccessKeyId');
      expect(result.url).toContain('Signature');
      expect(result.url).toContain('Expires');
      expect(result.expiresAt).toBeInstanceOf(Date);
      expect(mockS3Client.generatePresignedUrl).toHaveBeenCalled();
    });

    it('should implement bucket-level access policies', async () => {
      const policyConfig = {
        version: '2012-10-17',
        statements: [
          {
            effect: 'Allow' as const,
            principal: { AWS: 'arn:aws:iam::123456789012:user/test-user' },
            action: ['s3:GetObject', 's3:PutObject'],
            resource: 'arn:aws:s3:::test-bucket/*'
          },
          {
            effect: 'Deny' as const,
            principal: '*',
            action: 's3:DeleteObject',
            resource: 'arn:aws:s3:::test-bucket/critical/*'
          }
        ]
      };

      const result = await storageService.setBucketPolicy('test-bucket', policyConfig);

      expect(result.applied).toBe(true);
      expect(result.statementCount).toBe(2);
      expect(mockS3Client.putBucketPolicy).toHaveBeenCalled();
    });

    it('should implement server-side encryption', async () => {
      const encryptionConfig = {
        algorithm: 'AES256' as const,
        kmsKeyId: 'arn:aws:kms:us-east-1:123456789012:key/test-key',
        bucketKeyEnabled: true
      };

      const uploadRequest: UploadRequest = {
        key: 'encrypted-file.txt',
        body: Buffer.from('sensitive content'),
        contentType: 'text/plain',
        encryption: encryptionConfig
      };

      const result = await storageService.uploadFile(uploadRequest);

      expect(result.encrypted).toBe(true);
      expect(result.encryptionAlgorithm).toBe(encryptionConfig.algorithm);
      expect(mockS3Client.putObject).toHaveBeenCalledWith(expect.objectContaining({
        ServerSideEncryption: encryptionConfig.algorithm,
        SSEKMSKeyId: encryptionConfig.kmsKeyId
      }));
    });

    it('should validate and sanitize file paths', async () => {
      const maliciousPaths = [
        '../../../etc/passwd',
        '..\\..\\windows\\system32\\config\\sam',
        '/absolute/path/file.txt',
        'path/with/../../backreferences.txt'
      ];

      for (const path of maliciousPaths) {
        await expect(storageService.uploadFile({
          key: path,
          body: Buffer.from('content'),
          contentType: 'text/plain'
        })).rejects.toThrow('Invalid file path');
      }
    });

    it('should implement content scanning for malware', async () => {
      const scanningConfig = {
        enabled: true,
        engines: ['clamav', 'virustotal'],
        scanOnUpload: true,
        quarantineSuspicious: true
      };

      storageService.updateSecurityConfig(scanningConfig);

      const suspiciousFile = Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');

      await expect(storageService.uploadFile({
        key: 'test-eicar.txt',
        body: suspiciousFile,
        contentType: 'text/plain'
      })).rejects.toThrow('Malware detected');
    });

    it('should handle access denied scenarios gracefully', async () => {
      mockS3Client.getObject.mockRejectedValue({
        name: 'AccessDenied',
        message: 'Access Denied'
      });

      const downloadRequest: DownloadRequest = { key: 'restricted-file.txt' };

      await expect(storageService.downloadFile(downloadRequest)).rejects.toThrow('Access denied');
    });
  });

  // 7. Storage Analytics Tests
  describe('Storage Analytics', () => {
    it('should collect comprehensive storage metrics', async () => {
      const metrics = await storageService.getStorageMetrics();

      expect(metrics.totalObjects).toBeGreaterThanOrEqual(0);
      expect(metrics.totalSizeBytes).toBeGreaterThanOrEqual(0);
      expect(metrics.averageObjectSize).toBeGreaterThanOrEqual(0);
      expect(metrics.storageUtilization).toBeGreaterThanOrEqual(0);
      expect(metrics.storageUtilization).toBeLessThanOrEqual(1);
      expect(metrics.objectCountByType).toBeDefined();
      expect(metrics.sizeDistribution).toBeDefined();
      expect(metrics.growthRate).toBeDefined();
    });

    it('should analyze storage usage patterns', async () => {
      mockQdrantClient.storageMetrics.aggregate.mockResolvedValue({
        _sum: { size: 1024000, count: 100 },
        _avg: { size: 10240 }
      });

      const usageAnalytics = await storageService.getUsageAnalytics({
        timeRange: {
          startDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
          endDate: new Date()
        },
        granularity: 'daily'
      });

      expect(usageAnalytics.timeSeriesData).toBeDefined();
      expect(usageAnalytics.timeSeriesData.length).toBeGreaterThan(0);
      expect(usageAnalytics.topConsumers).toBeDefined();
      expect(usageAnalytics.growthTrends).toBeDefined();
      expect(usageAnalytics.forecastedUsage).toBeDefined();
    });

    it('should generate storage optimization recommendations', async () => {
      const storageAnalysis = {
        totalSize: 10 * 1024 * 1024 * 1024, // 10GB
        duplicateFiles: 150, // MB
        oldFiles: 2 * 1024 * 1024 * 1024, // 2GB
        compressedFiles: 8 * 1024 * 1024 * 1024, // 8GB
        uncompressedFiles: 2 * 1024 * 1024 * 1024 // 2GB
      };

      const recommendations = await storageService.generateOptimizationReport(storageAnalysis);

      expect(recommendations.potentialSavings).toBeGreaterThan(0);
      expect(recommendations.recommendations).toContain('Enable compression for text files');
      expect(recommendations.recommendations).toContain('Archive or delete files older than 1 year');
      expect(recommendations.recommendations).toContain('Remove duplicate files');
    });

    it('should track storage costs by category', async () => {
      const costAnalysis = await storageService.getStorageCosts({
        region: 'us-east-1',
        storageClasses: ['STANDARD', 'STANDARD_IA', 'GLACIER'],
        includeOperations: true,
        includeDataTransfer: true
      });

      expect(costAnalysis.totalMonthlyCost).toBeGreaterThan(0);
      expect(costAnalysis.costByStorageClass).toBeDefined();
      expect(costAnalysis.costByOperations).toBeDefined();
      expect(costAnalysis.costByDataTransfer).toBeDefined();
      expect(costAnalysis.forecastedCost).toBeGreaterThan(0);
    });

    it('should detect storage anomalies', async () => {
      const anomalyDetection = await storageService.detectStorageAnomalies({
        lookbackDays: 30,
        thresholdMultiplier: 2.5,
        metrics: ['growth_rate', 'delete_rate', 'access_patterns']
      });

      expect(anomalyDetection.anomalies).toBeInstanceOf(Array);
      expect(anomalyDetection.anomalies.length).toBeGreaterThanOrEqual(0);
      expect(anomalyDetection.confidenceScore).toBeGreaterThanOrEqual(0);
      expect(anomalyDetection.confidenceScore).toBeLessThanOrEqual(1);

      if (anomalyDetection.anomalies.length > 0) {
        expect(anomalyDetection.anomalies[0]).toHaveProperty('type');
        expect(anomalyDetection.anomalies[0]).toHaveProperty('severity');
        expect(anomalyDetection.anomalies[0]).toHaveProperty('description');
      }
    });
  });

  // 8. Disaster Recovery Tests
  describe('Disaster Recovery', () => {
    it('should create storage backups', async () => {
      const backupConfig: Partial<StorageBackup> = {
        sourceBucket: 'primary-bucket',
        destinationBucket: 'backup-bucket',
        destinationRegion: 'us-west-2',
        includeVersions: true,
        encryption: {
          enabled: true,
          algorithm: 'AES256'
        },
        compression: true,
        retentionDays: 90
      };

      const backup = await storageService.createStorageBackup(backupConfig);

      expect(backup.backupId).toBeDefined();
      expect(backup.status).toBe('in_progress');
      expect(backup.sourceBucket).toBe(backupConfig.sourceBucket);
      expect(backup.destinationBucket).toBe(backupConfig.destinationBucket);
      expect(backup.totalObjects).toBeGreaterThanOrEqual(0);
      expect(backup.totalSizeBytes).toBeGreaterThanOrEqual(0);
    });

    it('should monitor backup progress', async () => {
      const backupId = 'backup-12345';

      const progress = await storageService.getBackupProgress(backupId);

      expect(progress.backupId).toBe(backupId);
      expect(progress.status).toMatch(/^(in_progress|completed|failed)$/);
      expect(progress.objectsProcessed).toBeGreaterThanOrEqual(0);
      expect(progress.totalObjects).toBeGreaterThanOrEqual(0);
      expect(progress.bytesTransferred).toBeGreaterThanOrEqual(0);
      expect(progress.totalBytes).toBeGreaterThanOrEqual(0);
      expect(progress.percentageComplete).toBeGreaterThanOrEqual(0);
      expect(progress.percentageComplete).toBeLessThanOrEqual(100);
    });

    it('should restore from backup', async () => {
      const restoreConfig = {
        backupId: 'backup-12345',
        targetBucket: 'restored-bucket',
        restorePoint: new Date('2024-01-15T10:30:00Z'),
        includeVersions: true,
        overwriteExisting: false,
        dryRun: false
      };

      const restore = await storageService.restoreFromBackup(restoreConfig);

      expect(restore.restoreId).toBeDefined();
      expect(restore.status).toBe('in_progress');
      expect(restore.sourceBackupId).toBe(restoreConfig.backupId);
      expect(restore.targetBucket).toBe(restoreConfig.targetBucket);
    });

    it('should verify data integrity after restore', async () => {
      const integrityCheck = await storageService.verifyRestoreIntegrity({
        restoreId: 'restore-12345',
        checkMethod: 'checksum' as const,
        samplePercentage: 10, // Check 10% of files
        deepVerification: false
      });

      expect(integrityCheck.restoreId).toBe('restore-12345');
      expect(integrityCheck.verifiedFiles).toBeGreaterThanOrEqual(0);
      expect(integrityCheck.totalFiles).toBeGreaterThanOrEqual(0);
      expect(integrityCheck.successRate).toBeGreaterThanOrEqual(0);
      expect(integrityCheck.successRate).toBeLessThanOrEqual(1);
      expect(integrityCheck.issues).toBeInstanceOf(Array);
    });

    it('should handle cross-region replication', async () => {
      const replicationConfig = {
        sourceBucket: 'primary-bucket',
        sourceRegion: 'us-east-1',
        destinationBucket: 'replica-bucket',
        destinationRegion: 'eu-west-1',
        replicationRules: [
          {
            prefix: 'critical/',
            status: 'Enabled',
            storageClass: 'STANDARD'
          }
        ],
        deleteReplication: false
      };

      const replication = await storageService.configureCrossRegionReplication(replicationConfig);

      expect(replication.configured).toBe(true);
      expect(replication.rulesConfigured).toBe(1);
      expect(replication.replicationLatency).toBeGreaterThan(0);
    });

    it('should execute disaster recovery drills', async () => {
      const drillConfig = {
        drillType: 'restore_test' as const,
        scope: 'full_bucket' as const,
        backupRetention: 'keep_existing' as const,
        notificationRecipients: ['admin@company.com'],
        rollbackAfterTest: true,
        testDurationMinutes: 60
      };

      const drill = await storageService.executeDisasterRecoveryDrill(drillConfig);

      expect(drill.drillId).toBeDefined();
      expect(drill.status).toMatch(/^(scheduled|in_progress|completed|failed)$/);
      expect(drill.startTime).toBeInstanceOf(Date);
      expect(drill.expectedDuration).toBe(drillConfig.testDurationMinutes);
    });
  });

  // 9. Integration with Services Tests
  describe('Integration with Services', () => {
    it('should store knowledge assets in storage', async () => {
      const knowledgeAsset = {
        id: 'knowledge-123',
        type: 'document',
        title: 'Technical Specification',
        content: 'Detailed technical specification content...',
        metadata: {
          author: 'John Doe',
          version: '1.2.0',
          category: 'specification'
        },
        attachments: [
          { name: 'diagram.png', size: 1024000, type: 'image/png' },
          { name: 'appendix.pdf', size: 2048000, type: 'application/pdf' }
        ]
      };

      const result = await storageService.storeKnowledgeAsset(knowledgeAsset);

      expect(result.assetId).toBe(knowledgeAsset.id);
      expect(result.primaryFileKey).toBeDefined();
      expect(result.attachmentKeys).toHaveLength(2);
      expect(result.totalSize).toBeGreaterThan(0);
      expect(mockQdrantClient.storageAsset.create).toHaveBeenCalled();
    });

    it('should manage export files efficiently', async () => {
      const exportRequest = {
        format: 'json' as const,
        filters: {
          scope: { project: 'test-project' },
          dateRange: {
            startDate: new Date('2024-01-01'),
            endDate: new Date('2024-12-31')
          },
          types: ['entity', 'relation', 'decision']
        },
        compression: true,
        encryption: false
      };

      const exportResult = await storageService.generateExportFile(exportRequest);

      expect(exportResult.exportId).toBeDefined();
      expect(exportResult.fileKey).toBeDefined();
      expect(exportResult.downloadUrl).toBeDefined();
      expect(exportResult.fileSize).toBeGreaterThan(0);
      expect(exportResult.recordCount).toBeGreaterThan(0);
      expect(exportResult.expiresAt).toBeInstanceOf(Date);
    });

    it('should handle backup file management', async () => {
      const backupFile = {
        type: 'scheduled' as const,
        scope: 'full' as const,
        compression: true,
        encryption: true,
        retentionDays: 30,
        includeVersions: true
      };

      const backupResult = await storageService.createBackupFile(backupFile);

      expect(backupResult.backupId).toBeDefined();
      expect(backupResult.fileKey).toBeDefined();
      expect(backupResult.checksum).toBeDefined();
      expect(backupResult.encrypted).toBe(true);
      expect(backupResult.compressed).toBe(true);
      expect(backupResult.createdAt).toBeInstanceOf(Date);
    });

    it('should integrate with cache storage', async () => {
      const cacheConfig = {
        type: 'distributed' as const,
        ttl: 3600,
        maxSize: 1024 * 1024 * 1024, // 1GB
        evictionPolicy: 'LRU' as const,
        persistenceEnabled: true
      };

      const cacheResult = await storageService.initializeCacheStorage(cacheConfig);

      expect(cacheResult.initialized).toBe(true);
      expect(cacheResult.cacheId).toBeDefined();
      expect(cacheResult.maxSize).toBe(cacheConfig.maxSize);
      expect(cacheResult.persistenceEnabled).toBe(true);
    });

    it('should handle temporary file storage', async () => {
      const tempFileRequest = {
        content: Buffer.from('temporary content'),
        filename: 'temp-file.txt',
        ttl: 3600, // 1 hour
        maxDownloads: 1,
        autoDelete: true
      };

      const tempFile = await storageService.createTemporaryFile(tempFileRequest);

      expect(tempFile.fileId).toBeDefined();
      expect(tempFile.downloadUrl).toBeDefined();
      expect(tempFile.expiresAt).toBeInstanceOf(Date);
      expect(tempFile.downloadCount).toBe(0);
      expect(tempFile.maxDownloads).toBe(1);
    });

    it('should manage file versioning for knowledge assets', async () => {
      const versionedAsset = {
        assetId: 'knowledge-456',
        newVersion: {
          content: 'Updated content with new information...',
          version: '2.0.0',
          changelog: 'Added new section on security considerations',
          author: 'Jane Smith'
        },
        keepPreviousVersions: true,
        maxVersions: 10
      };

      const versionResult = await storageService.createAssetVersion(versionedAsset);

      expect(versionResult.newVersionId).toBeDefined();
      expect(versionResult.versionNumber).toBe('2.0.0');
      expect(versionResult.previousVersionsCount).toBeGreaterThanOrEqual(0);
      expect(versionResult.totalVersions).toBeGreaterThan(0);
      expect(versionResult.storageUsed).toBeGreaterThan(0);
    });
  });

  // 10. Configuration and Utility Tests
  describe('Configuration and Utilities', () => {
    it('should accept custom storage configuration', () => {
      const customConfig: StorageConfig = {
        provider: 's3',
        region: 'eu-west-1',
        bucket: 'custom-bucket',
        accessKeyId: 'custom-key',
        secretAccessKey: 'custom-secret',
        encryption: {
          enabled: true,
          algorithm: 'AES256',
          kmsKeyId: 'custom-kms-key'
        },
        versioning: true,
        compression: {
          enabled: true,
          algorithm: 'gzip',
          level: 6
        },
        caching: {
          enabled: true,
          ttl: 7200,
          maxSize: 2000
        },
        cdn: {
          enabled: true,
          distributionId: 'custom-distribution'
        },
        monitoring: {
          enabled: true,
          metrics: ['all'],
          alertThresholds: {
            errorRate: 0.05,
            latency: 2000
          }
        }
      };

      const customService = new StorageService(customConfig);
      const config = customService.getConfig();

      expect(config.provider).toBe('s3');
      expect(config.region).toBe('eu-west-1');
      expect(config.bucket).toBe('custom-bucket');
      expect(config.encryption.enabled).toBe(true);
      expect(config.encryption.algorithm).toBe('AES256');
      expect(config.versioning).toBe(true);
      expect(config.compression.enabled).toBe(true);
      expect(config.caching.enabled).toBe(true);
      expect(config.cdn.enabled).toBe(true);
    });

    it('should update configuration dynamically', () => {
      const initialConfig = storageService.getConfig();

      storageService.updateConfig({
        compression: { enabled: false },
        caching: { ttl: 7200 },
        monitoring: { enabled: false }
      });

      const updatedConfig = storageService.getConfig();

      expect(updatedConfig.compression.enabled).toBe(false);
      expect(updatedConfig.caching.ttl).toBe(7200);
      expect(updatedConfig.monitoring.enabled).toBe(false);
      expect(updatedConfig.encryption.enabled).toBe(initialConfig.encryption.enabled); // Should preserve other settings
    });

    it('should validate configuration settings', () => {
      const invalidConfigs = [
        { provider: 'invalid-provider' },
        { region: '' },
        { bucket: 'invalid-bucket-name-' },
        { encryption: { algorithm: 'INVALID-ALGORITHM' } },
        { compression: { level: 15 } },
        { caching: { ttl: -1 } }
      ];

      for (const config of invalidConfigs) {
        expect(() => new StorageService(config as any)).toThrow();
      }
    });

    it('should handle storage client initialization errors', () => {
      const invalidConfig = {
        provider: 's3',
        region: 'us-east-1',
        bucket: 'test-bucket',
        accessKeyId: 'invalid-key',
        secretAccessKey: 'invalid-secret'
      };

      expect(() => new StorageService(invalidConfig)).not.toThrow();
    });

    it('should provide comprehensive service health check', async () => {
      const health = await storageService.performHealthCheck();

      expect(health.status).toMatch(/^(healthy|degraded|unhealthy)$/);
      expect(health.timestamp).toBeInstanceOf(Date);
      expect(health.components).toBeDefined();
      expect(health.components.storage).toBeDefined();
      expect(health.components.database).toBeDefined();
      expect(health.components.cdn).toBeDefined();
      expect(health.metrics).toBeDefined();
      expect(health.uptime).toBeGreaterThanOrEqual(0);
    });

    it('should calculate optimal chunk sizes for different file sizes', () => {
      const testCases = [
        { fileSize: 1024, expectedMinChunk: 5 * 1024 * 1024 },
        { fileSize: 50 * 1024 * 1024, expectedMinChunk: 5 * 1024 * 1024 },
        { fileSize: 500 * 1024 * 1024, expectedMinChunk: 10 * 1024 * 1024 },
        { fileSize: 5 * 1024 * 1024 * 1024, expectedMinChunk: 100 * 1024 * 1024 }
      ];

      testCases.forEach(({ fileSize, expectedMinChunk }) => {
        const chunkSize = storageService.getOptimalChunkSize(fileSize);
        expect(chunkSize).toBeGreaterThanOrEqual(expectedMinChunk);
        expect(chunkSize).toBeLessThanOrEqual(5 * 1024 * 1024 * 1024); // Max 5GB chunks
      });
    });

    it('should generate proper storage statistics', () => {
      const stats = storageService.getStorageStatistics();

      expect(stats.totalOperations).toBeGreaterThanOrEqual(0);
      expect(stats.successfulOperations).toBeGreaterThanOrEqual(0);
      expect(stats.failedOperations).toBeGreaterThanOrEqual(0);
      expect(stats.totalBytesTransferred).toBeGreaterThanOrEqual(0);
      expect(stats.averageLatency).toBeGreaterThanOrEqual(0);
      expect(stats.cacheHitRate).toBeGreaterThanOrEqual(0);
      expect(stats.errorRate).toBeGreaterThanOrEqual(0);
      expect(stats.startTime).toBeInstanceOf(Date);
    });

    it('should handle service cleanup gracefully', async () => {
      await expect(storageService.cleanup()).resolves.not.toThrow();

      // Verify cleanup tasks were performed
      expect(storageService.getCacheStats().size).toBe(0);
      expect(storageService.getStatistics().activeConnections).toBe(0);
    });
  });

  // 11. Error Handling and Edge Cases Tests
  describe('Error Handling and Edge Cases', () => {
    it('should handle network timeouts during upload', async () => {
      mockS3Client.putObject.mockRejectedValue(new Error('Timeout'));

      const uploadRequest: UploadRequest = {
        key: 'timeout-test.txt',
        body: Buffer.from('content'),
        contentType: 'text/plain'
      };

      await expect(storageService.uploadFile(uploadRequest)).rejects.toThrow('Failed to upload file');
    });

    it('should handle quota exceeded scenarios', async () => {
      mockS3Client.putObject.mockRejectedValue({
        name: 'QuotaExceeded',
        message: 'Your quota has been exceeded'
      });

      const uploadRequest: UploadRequest = {
        key: 'quota-test.txt',
        body: Buffer.alloc(100 * 1024 * 1024), // 100MB
        contentType: 'application/octet-stream'
      };

      await expect(storageService.uploadFile(uploadRequest)).rejects.toThrow('quota has been exceeded');
    });

    it('should handle invalid file formats', async () => {
      const invalidFiles = [
        { key: 'empty.txt', body: Buffer.alloc(0), contentType: 'text/plain' },
        { key: 'too-large.bin', body: Buffer.alloc(5 * 1024 * 1024 * 1024), contentType: 'application/octet-stream' },
        { key: 'invalid-name', body: Buffer.from('content'), contentType: 'application/octet-stream' }
      ];

      for (const file of invalidFiles) {
        await expect(storageService.uploadFile(file)).rejects.toThrow();
      }
    });

    it('should handle concurrent access to the same file', async () => {
      const fileKey = 'concurrent-access.txt';
      const uploadRequests = Array.from({ length: 5 }, (_, i) => ({
        key: fileKey,
        body: Buffer.from(`content ${i}`),
        contentType: 'text/plain'
      }));

      const results = await Promise.allSettled(uploadRequests.map(req => storageService.uploadFile(req)));

      // At least one should succeed
      const successful = results.filter(r => r.status === 'fulfilled');
      expect(successful.length).toBeGreaterThan(0);
    });

    it('should handle storage service unavailability', async () => {
      mockS3Client.listBuckets.mockRejectedValue(new Error('Service unavailable'));

      await expect(storageService.listBuckets()).rejects.toThrow('Failed to list buckets');
    });

    it('should handle malformed responses from storage provider', async () => {
      mockS3Client.getObject.mockResolvedValue({ malformed: 'response' });

      const downloadRequest: DownloadRequest = { key: 'malformed.txt' };

      await expect(storageService.downloadFile(downloadRequest)).rejects.toThrow('Invalid response from storage provider');
    });

    it('should handle rate limiting gracefully', async () => {
      mockS3Client.putObject.mockRejectedValue({
        name: 'SlowDown',
        message: 'Rate exceeded'
      });

      const uploadRequest: UploadRequest = {
        key: 'rate-limit-test.txt',
        body: Buffer.from('content'),
        contentType: 'text/plain'
      };

      await expect(storageService.uploadFile(uploadRequest)).rejects.toThrow('rate limit');
    });
  });

  // 12. Performance Tests
  describe('Performance Tests', () => {
    it('should handle high-volume concurrent operations', async () => {
      const concurrentUploads = 50;
      const uploadRequests = Array.from({ length: concurrentUploads }, (_, i) => ({
        key: `perf-test-${i}.txt`,
        body: Buffer.alloc(1024, `${i}`),
        contentType: 'text/plain'
      }));

      const startTime = Date.now();
      const results = await Promise.all(uploadRequests.map(req => storageService.uploadFile(req)));
      const duration = Date.now() - startTime;

      expect(results).toHaveLength(concurrentUploads);
      expect(duration).toBeLessThan(10000); // Should complete within 10 seconds

      const avgLatency = duration / concurrentUploads;
      expect(avgLatency).toBeLessThan(200); // Average latency should be under 200ms
    });

    it('should maintain performance with large files', async () => {
      const largeFileSizes = [10, 50, 100, 200]; // MB
      const performanceResults = [];

      for (const sizeMB of largeFileSizes) {
        const uploadRequest: UploadRequest = {
          key: `perf-large-${sizeMB}mb.bin`,
          body: Buffer.alloc(sizeMB * 1024 * 1024),
          contentType: 'application/octet-stream'
        };

        const startTime = Date.now();
        await storageService.uploadFile(uploadRequest);
        const duration = Date.now() - startTime;
        const throughput = (sizeMB * 1024 * 1024) / (duration / 1000) / (1024 * 1024); // MB/s

        performanceResults.push({ sizeMB, duration, throughput });
      }

      // Throughput should not degrade significantly with larger files
      const throughputs = performanceResults.map(r => r.throughput);
      const minThroughput = Math.min(...throughputs);
      const maxThroughput = Math.max(...throughputs);

      expect(maxThroughput / minThroughput).toBeLessThan(3); // Performance should not vary more than 3x
    });

    it('should demonstrate efficient memory usage', async () => {
      const initialMemory = process.memoryUsage().heapUsed;

      const uploadRequests = Array.from({ length: 100 }, (_, i) => ({
        key: `memory-test-${i}.txt`,
        body: Buffer.alloc(10240, `${i}`),
        contentType: 'text/plain'
      }));

      await Promise.all(uploadRequests.map(req => storageService.uploadFile(req)));

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be reasonable (less than 100MB for 100 small files)
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);
    });
  });
});