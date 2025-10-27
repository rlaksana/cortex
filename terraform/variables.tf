# ============================================================================
# CORTEX MEMORY MCP - TERRAFORM VARIABLES
# ============================================================================

variable "environment" {
  description = "Deployment environment (development, staging, production)"
  type        = string
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be one of: development, staging, production."
  }
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "azs" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "kubernetes_version" {
  description = "Kubernetes version"
  type        = string
  default     = "1.28"
}

variable "cortex_version" {
  description = "Cortex Memory MCP version"
  type        = string
  default     = "2.0.0"
}

# PostgreSQL Configuration
variable "postgres_version" {
  description = "PostgreSQL version"
  type        = string
  default     = "18"
}

variable "postgres_instance_type" {
  description = "PostgreSQL RDS instance type"
  type        = string
  default     = "db.r6g.large"
}

variable "postgres_allocated_storage" {
  description = "PostgreSQL allocated storage in GB"
  type        = number
  default     = 100
}

variable "postgres_max_allocated_storage" {
  description = "PostgreSQL maximum allocated storage in GB"
  type        = number
  default     = 1000
}

variable "postgres_backup_retention_period" {
  description = "PostgreSQL backup retention period in days"
  type        = number
  default     = 30
}

# Qdrant Configuration
variable "qdrant_version" {
  description = "Qdrant version"
  type        = string
  default     = "v1.13.2"
}

variable "qdrant_replicas" {
  description = "Number of Qdrant replicas"
  type        = number
  default     = 1
}

variable "qdrant_cpu_limit" {
  description = "Qdrant CPU limit"
  type        = string
  default     = "2000m"
}

variable "qdrant_memory_limit" {
  description = "Qdrant memory limit"
  type        = string
  default     = "8Gi"
}

variable "qdrant_storage_size" {
  description = "Qdrant persistent storage size"
  type        = string
  default     = "200Gi"
}

# Node Group Configuration
variable "general_instance_types" {
  description = "Instance types for general node group"
  type        = list(string)
  default     = ["t3.large", "t3a.large"]
}

variable "general_node_min_size" {
  description = "Minimum size for general node group"
  type        = number
  default     = 1
}

variable "general_node_max_size" {
  description = "Maximum size for general node group"
  type        = number
  default     = 5
}

variable "general_node_desired_size" {
  description = "Desired size for general node group"
  type        = number
  default     = 2
}

variable "database_instance_types" {
  description = "Instance types for database node group"
  type        = list(string)
  default     = ["r6g.large", "r6g.xlarge"]
}

variable "database_node_min_size" {
  description = "Minimum size for database node group"
  type        = number
  default     = 1
}

variable "database_node_max_size" {
  description = "Maximum size for database node group"
  type        = number
  default     = 3
}

variable "database_node_desired_size" {
  description = "Desired size for database node group"
  type        = number
  default     = 1
}

variable "vector_instance_types" {
  description = "Instance types for vector processing node group"
  type        = list(string)
  default     = ["c6g.2xlarge", "c6g.4xlarge"]
}

variable "vector_node_min_size" {
  description = "Minimum size for vector node group"
  type        = number
  default     = 1
}

variable "vector_node_max_size" {
  description = "Maximum size for vector node group"
  type        = number
  default     = 5
}

variable "vector_node_desired_size" {
  description = "Desired size for vector node group"
  type        = number
  default     = 2
}

# Application Configuration
variable "cortex_replicas" {
  description = "Number of Cortex application replicas"
  type        = number
  default     = 3
}

variable "cortex_cpu_request" {
  description = "Cortex CPU request"
  type        = string
  default     = "500m"
}

variable "cortex_cpu_limit" {
  description = "Cortex CPU limit"
  type        = string
  default     = "2000m"
}

variable "cortex_memory_request" {
  description = "Cortex memory request"
  type        = string
  default     = "512Mi"
}

variable "cortex_memory_limit" {
  description = "Cortex memory limit"
  type        = string
  default     = "2Gi"
}

# Security Configuration
variable "enable_vpn_gateway" {
  description = "Enable VPN gateway for private connectivity"
  type        = bool
  default     = false
}

variable "ssh_key_name" {
  description = "SSH key name for EC2 instances"
  type        = string
  default     = ""
}

variable "allowed_cidr_blocks" {
  description = "Allowed CIDR blocks for access"
  type        = list(string)
  default     = []
}

# Monitoring and Logging
variable "enable_cloudwatch_container_insights" {
  description = "Enable CloudWatch Container Insights"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Log retention period in days"
  type        = number
  default     = 30
}

variable "enable_prometheus" {
  description = "Enable Prometheus monitoring"
  type        = bool
  default     = true
}

variable "enable_grafana" {
  description = "Enable Grafana dashboard"
  type        = bool
  default     = true
}

# Backup and Disaster Recovery
variable "enable_cross_region_backup" {
  description = "Enable cross-region backup"
  type        = bool
  default     = false
}

variable "backup_region" {
  description = "Backup region for cross-region backup"
  type        = string
  default     = "us-west-2"
}

variable "enable_point_in_time_recovery" {
  description = "Enable point-in-time recovery for databases"
  type        = bool
  default     = true
}

# Cost Optimization
variable "enable_spot_instances" {
  description = "Enable spot instances for cost optimization"
  type        = bool
  default     = false
}

variable "spot_instance_pools" {
  description = "Number of spot instance pools"
  type        = number
  default     = 3
}

variable "enable_autoscaling" {
  description = "Enable cluster autoscaling"
  type        = bool
  default     = true
}

# Feature Flags
variable "enable_dual_database_mode" {
  description = "Enable dual database mode (PostgreSQL + Qdrant)"
  type        = bool
  default     = true
}

variable "enable_vector_search" {
  description = "Enable vector search capabilities"
  type        = bool
  default     = true
}

variable "enable_fulltext_search" {
  description = "Enable full-text search capabilities"
  type        = bool
  default     = true
}

variable "enable_semantic_search" {
  description = "Enable semantic search capabilities"
  type        = bool
  default     = true
}

variable "enable_caching" {
  description = "Enable caching layer"
  type        = bool
  default     = true
}

variable "enable_metrics" {
  description = "Enable metrics collection"
  type        = bool
  default     = true
}

variable "enable_tracing" {
  description = "Enable distributed tracing"
  type        = bool
  default     = false
}

# Advanced Configuration
variable "custom_tags" {
  description = "Custom tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "enable_aws_cost_explorer" {
  description = "Enable AWS Cost Explorer integration"
  type        = bool
  default     = false
}

variable "enable_aws_guardduty" {
  description = "Enable AWS GuardDuty threat detection"
  type        = bool
  default     = true
}

variable "enable_aws_config" {
  description = "Enable AWS Config for compliance monitoring"
  type        = bool
  default     = true
}

variable "enable_aws_cloudtrail" {
  description = "Enable AWS CloudTrail for audit logging"
  type        = bool
  default     = true
}

variable "enable_waf" {
  description = "Enable AWS WAF for application protection"
  type        = bool
  default     = false
}

variable "enable_shield" {
  description = "Enable AWS Shield for DDoS protection"
  type        = bool
  default     = false
}

# Compliance and Governance
variable "compliance_standards" {
  description = "Compliance standards to enforce"
  type        = list(string)
  default     = ["SOC2", "ISO27001", "GDPR"]
}

variable "enable_encryption_at_rest" {
  description = "Enable encryption at rest for all resources"
  type        = bool
  default     = true
}

variable "enable_encryption_in_transit" {
  description = "Enable encryption in transit for all communications"
  type        = bool
  default     = true
}

variable "enable_private_link" {
  description = "Enable AWS PrivateLink for private connectivity"
  type        = bool
  default     = true
}