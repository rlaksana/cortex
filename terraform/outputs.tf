# ============================================================================
# CORTEX MEMORY MCP - TERRAFORM OUTPUTS
# ============================================================================

# Cluster Information
output "cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "cluster_certificate_authority_data" {
  description = "EKS cluster certificate authority data"
  value       = module.eks.cluster_certificate_authority_data
  sensitive   = true
}

output "cluster_arn" {
  description = "EKS cluster ARN"
  value       = module.eks.cluster_arn
}

# Network Information
output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "vpc_cidr_block" {
  description = "VPC CIDR block"
  value       = module.vpc.vpc_cidr_block
}

output "private_subnets" {
  description = "List of private subnet IDs"
  value       = module.vpc.private_subnets
}

output "public_subnets" {
  description = "List of public subnet IDs"
  value       = module.vpc.public_subnets
}

output "database_subnets" {
  description = "List of database subnet IDs"
  value       = module.vpc.database_subnets
}

output "nat_gateway_ids" {
  description = "List of NAT gateway IDs"
  value       = module.vpc.natgw_ids
}

output "internet_gateway_id" {
  description = "Internet Gateway ID"
  value       = module.vpc.igw_id
}

# Node Groups Information
output "general_node_group_name" {
  description = "General node group name"
  value       = module.eks.eks_managed_node_groups["general"].name
}

output "database_node_group_name" {
  description = "Database node group name"
  value       = module.eks.eks_managed_node_groups["database"].name
}

output "vector_node_group_name" {
  description = "Vector node group name"
  value       = module.eks.eks_managed_node_groups["vector"].name
}

output "node_group_arns" {
  description = "List of node group ARNs"
  value = {
    general  = module.eks.eks_managed_node_groups["general"].arn
    database = module.eks.eks_managed_node_groups["database"].arn
    vector   = module.eks.eks_managed_node_groups["vector"].arn
  }
}

# Security Information
output "cluster_security_group_id" {
  description = "Cluster security group ID"
  value       = module.eks.cluster_security_group_id
}

output "node_security_group_id" {
  description = "Node security group ID"
  value       = module.eks.node_security_group_id
}

output "database_nodes_security_group_id" {
  description = "Database nodes security group ID"
  value       = aws_security_group.database_nodes.id
}

output "vector_nodes_security_group_id" {
  description = "Vector nodes security group ID"
  value       = aws_security_group.vector_nodes.id
}

# KMS Information
output "eks_kms_key_arn" {
  description = "EKS KMS key ARN"
  value       = aws_kms_key.eks.arn
}

output "eks_kms_key_id" {
  description = "EKS KMS key ID"
  value       = aws_kms_key.eks.key_id
}

# Storage Classes
output "fast_ssd_storage_class" {
  description = "Fast SSD storage class name"
  value       = kubernetes_storage_class.fast_ssd.metadata[0].name
}

output "high_performance_storage_class" {
  description = "High performance storage class name"
  value       = kubernetes_storage_class.high_performance.metadata[0].name
}

# IAM Information
output "cluster_iam_role_name" {
  description = "Cluster IAM role name"
  value       = module.eks.iam_role_name
}

output "cluster_iam_role_arn" {
  description = "Cluster IAM role ARN"
  value       = module.eks.iam_role_arn
}

output "ebs_csi_driver_role_arn" {
  description = "EBS CSI driver IAM role ARN"
  value       = aws_iam_role.ebs_csi_driver.arn
}

# OIDC Information
output "oidc_provider_arn" {
  description = "OIDC provider ARN"
  value       = module.eks.oidc_provider_arn
}

# CloudWatch Information
output "cloudwatch_log_group_name" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.cortex.name
}

output "cloudwatch_log_group_arn" {
  description = "CloudWatch log group ARN"
  value       = aws_cloudwatch_log_group.cortex.arn
}

# Placement Groups
output "database_placement_group_name" {
  description = "Database placement group name"
  value       = aws_placement_group.database.name
}

output "vector_placement_group_name" {
  description = "Vector placement group name"
  value       = aws_placement_group.vector.name
}

# Configuration Information
output "configure_kubectl" {
  description = "Command to configure kubectl for the cluster"
  value       = "aws eks update-kubeconfig --name ${module.eks.cluster_name} --region ${var.aws_region}"
}

output "database_connection_info" {
  description = "Database connection information (sensitive)"
  value = {
    host     = "postgres.${module.eks.cluster_name}.svc.cluster.local"
    port     = 5432
    database = "cortex_prod"
    user     = "cortex"
  }
  sensitive = true
}

output "qdrant_connection_info" {
  description = "Qdrant connection information"
  value = {
    host = "qdrant.${module.eks.cluster_name}.svc.cluster.local"
    port = 6333
  }
}

# Monitoring Information
output "prometheus_endpoint" {
  description = "Prometheus endpoint (if enabled)"
  value       = var.enable_prometheus ? "http://prometheus.${module.eks.cluster_name}.svc.cluster.local:9090" : null
}

output "grafana_endpoint" {
  description = "Grafana endpoint (if enabled)"
  value       = var.enable_grafana ? "http://grafana.${module.eks.cluster_name}.svc.cluster.local:3000" : null
}

# Additional Information
output "aws_region" {
  description = "AWS region"
  value       = var.aws_region
}

output "account_id" {
  description = "AWS account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "terraform_workspace" {
  description = "Current Terraform workspace"
  value       = terraform.workspace
}

# Cost Information
output "estimated_monthly_cost" {
  description = "Estimated monthly cost for this infrastructure"
  value = {
    general_nodes = var.general_node_desired_size * 50  # Rough estimate
    database_nodes = var.database_node_desired_size * 120
    vector_nodes = var.vector_node_desired_size * 200
    storage = var.qdrant_storage_size + var.postgres_allocated_storage
    networking = 30
    monitoring = var.enable_prometheus ? 20 : 0
  }
}