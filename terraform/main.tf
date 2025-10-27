# ============================================================================
# CORTEX MEMORY MCP - INFRASTRUCTURE AS CODE (TERRAFORM)
# ============================================================================
# Dual database infrastructure with PostgreSQL 18 + Qdrant vector database
# Supports multi-environment deployment with proper resource management

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.24"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }

  backend "s3" {
    bucket = "cortex-mcp-terraform-state"
    key    = "terraform.tfstate"
    region = "us-east-1"
    encrypt = true
    dynamodb_table = "terraform-locks"
  }
}

# Provider configuration
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "cortex-mcp"
      Environment = var.environment
      ManagedBy   = "terraform"
      Component   = "dual-database-infrastructure"
    }
  }
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  token                  = data.aws_eks_cluster_auth.cortex.token

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    token                  = data.aws_eks_cluster_auth.cortex.token

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

# Data sources
data "aws_eks_cluster_auth" "cortex" {
  name = module.eks.cluster_name
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# Local values
locals {
  name_prefix = "cortex-mcp-${var.environment}"

  tags = {
    Project     = "cortex-mcp"
    Environment = var.environment
    ManagedBy   = "terraform"
    Component   = "dual-database-infrastructure"
    Version     = var.cortex_version
  }

  # Enhanced security CIDR blocks
  private_subnets_cidr = [
    cidrsubnet(var.vpc_cidr, 4, 1),
    cidrsubnet(var.vpc_cidr, 4, 2),
    cidrsubnet(var.vpc_cidr, 4, 3)
  ]

  public_subnets_cidr = [
    cidrsubnet(var.vpc_cidr, 4, 0),
    cidrsubnet(var.vpc_cidr, 4, 4),
    cidrsubnet(var.vpc_cidr, 4, 5)
  ]

  # Database subnets (isolated)
  database_subnets_cidr = [
    cidrsubnet(var.vpc_cidr, 4, 6),
    cidrsubnet(var.vpc_cidr, 4, 7),
    cidrsubnet(var.vpc_cidr, 4, 8)
  ]
}

# VPC Configuration with enhanced networking
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.5.3"

  name = local.name_prefix
  cidr = var.vpc_cidr

  azs             = local.azs
  private_subnets = local.private_subnets_cidr
  public_subnets  = local.public_subnets_cidr
  database_subnets = local.database_subnets_cidr

  # Enhanced networking features
  enable_nat_gateway     = true
  single_nat_gateway     = false
  one_nat_gateway_per_az = true
  enable_vpn_gateway     = var.enable_vpn_gateway

  # DNS support
  enable_dns_hostnames = true
  enable_dns_support   = true

  # Enhanced security
  manage_default_security_group = true
  default_security_group_ingress = []
  default_security_group_egress  = []

  # Flow logs for security monitoring
  enable_flow_log                      = true
  flow_log_destination_type            = "cloud-watch-logs"
  create_flow_log_cloud_watch_log_group = true
  flow_log_cloud_watch_log_group_retention = 30

  tags = merge(local.tags, {
    Component = "vpc"
  })
}

# EKS Cluster with enhanced security
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.0.1"

  cluster_name    = local.name_prefix
  cluster_version = var.kubernetes_version
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = var.environment == "development"

  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnets

  # Enhanced security configuration
  cluster_encryption_config = {
    resources = ["secrets"]
    provider_key_arn = aws_kms_key.eks.arn
  }

  # IAM role for service accounts
  iam_role_name = "${local.name_prefix}-eks-cluster-role"
  iam_role_use_name_prefix = false

  # Node groups
  eks_managed_node_groups = {
    general = {
      name = "${local.name_prefix}-general-nodes"
      instance_types = var.general_instance_types

      min_size     = var.general_node_min_size
      max_size     = var.general_node_max_size
      desired_size = var.general_node_desired_size

      # Enhanced security
      iam_role_attach_cni_policy = true

      # Disk configuration
      disk_size = 50
      disk_type = "gp3"

      # Auto-scaling
      capacity_type = "ON_DEMAND"

      tags = merge(local.tags, {
        Component = "general-nodes"
        Role = "application"
      })
    }

    database = {
      name = "${local.name_prefix}-database-nodes"
      instance_types = var.database_instance_types

      min_size     = var.database_node_min_size
      max_size     = var.database_node_max_size
      desired_size = var.database_node_desired_size

      # Dedicated for database workloads
      capacity_type = "ON_DEMAND"
      disk_size = 100
      disk_type = "io2"
      iops = 5000

      # Placement
      placement = {
        group_name = aws_placement_group.database.name
      }

      # Security groups
      vpc_security_group_ids = [aws_security_group.database_nodes.id]

      tags = merge(local.tags, {
        Component = "database-nodes"
        Role = "database"
      })
    }

    vector = {
      name = "${local.name_prefix}-vector-nodes"
      instance_types = var.vector_instance_types

      min_size     = var.vector_node_min_size
      max_size     = var.vector_node_max_size
      desired_size = var.vector_node_desired_size

      # Optimized for vector workloads
      capacity_type = "ON_DEMAND"
      disk_size = 200
      disk_type = "io2"
      iops = 10000

      # Placement for vector processing
      placement = {
        group_name = aws_placement_group.vector.name
      }

      # Security groups
      vpc_security_group_ids = [aws_security_group.vector_nodes.id]

      tags = merge(local.tags, {
        Component = "vector-nodes"
        Role = "vector-processing"
      })
    }
  }

  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
      configuration_values = jsonencode({
        env = {
          ENABLE_PREFIX_DELEGATION = "true"
          WARM_PREFIX_TARGET = "1"
        }
      })
    }
    aws-ebs-csi-driver = {
      most_recent = true
      service_account_role_arn = aws_iam_role.ebs_csi_driver.arn
    }
  }

  tags = merge(local.tags, {
    Component = "eks-cluster"
  })
}

# Enhanced security resources
resource "aws_kms_key" "eks" {
  description             = "EKS cluster encryption key for ${local.name_prefix}"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow EKS to use the key"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(local.tags, {
    Component = "kms-key-eks"
  })
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${local.name_prefix}-eks"
  target_key_id = aws_kms_key.eks.key_id
}

# Placement groups for optimal performance
resource "aws_placement_group" "database" {
  name     = "${local.name_prefix}-database"
  strategy = "cluster"
}

resource "aws_placement_group" "vector" {
  name     = "${local.name_prefix}-vector"
  strategy = "cluster"
}

# Enhanced security groups
resource "aws_security_group" "database_nodes" {
  name        = "${local.name_prefix}-database-nodes"
  description = "Security group for database worker nodes"
  vpc_id      = module.vpc.vpc_id

  # Allow PostgreSQL traffic
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    description = "PostgreSQL access"
    cidr_blocks = [var.vpc_cidr]
  }

  # Allow Qdrant traffic
  ingress {
    from_port   = 6333
    to_port     = 6334
    protocol    = "tcp"
    description = "Qdrant access"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, {
    Component = "security-group-database-nodes"
  })
}

resource "aws_security_group" "vector_nodes" {
  name        = "${local.name_prefix}-vector-nodes"
  description = "Security group for vector processing nodes"
  vpc_id      = module.vpc.vpc_id

  # Allow all internal traffic
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    description = "Allow all internal traffic"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, {
    Component = "security-group-vector-nodes"
  })
}

# IAM role for EBS CSI driver
resource "aws_iam_role" "ebs_csi_driver" {
  name = "${local.name_prefix}-ebs-csi-driver"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = module.eks.oidc_provider_arn
        }
        Condition = {
          StringEquals = {
            "${module.eks.oidc_provider}:sub" = "system:serviceaccount:kube-system:ebs-csi-controller-sa"
          }
        }
      }
    ]
  })

  tags = merge(local.tags, {
    Component = "iam-role-ebs-csi-driver"
  })
}

resource "aws_iam_role_policy_attachment" "ebs_csi_driver" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
  role       = aws_iam_role.ebs_csi_driver.name
}

# Storage classes for optimized workloads
resource "kubernetes_storage_class" "fast_ssd" {
  metadata {
    name = "fast-ssd"
    annotations = {
      "storageclass.kubernetes.io/is-default-class" = "true"
    }
  }

  storage_provisioner = "ebs.csi.aws.com"
  parameters = {
    type      = "gp3"
    iops      = "3000"
    throughput = "125"
    encrypted = "true"
  }

  allow_volume_expansion = true
  volume_binding_mode    = "WaitForFirstConsumer"
}

resource "kubernetes_storage_class" "high_performance" {
  metadata {
    name = "high-performance"
  }

  storage_provisioner = "ebs.csi.aws.com"
  parameters = {
    type      = "io2"
    iops      = "10000"
    encrypted = "true"
  }

  allow_volume_expansion = true
  volume_binding_mode    = "WaitForFirstConsumer"
}

# Monitoring and observability
resource "aws_cloudwatch_log_group" "cortex" {
  name              = "/aws/eks/${local.name_prefix}/cluster"
  retention_in_days = 30

  tags = merge(local.tags, {
    Component = "cloudwatch-log-group"
  })
}

# Output values
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
}

output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "private_subnets" {
  description = "List of private subnet IDs"
  value       = module.vpc.private_subnets
}

output "database_subnets" {
  description = "List of database subnet IDs"
  value       = module.vpc.database_subnets
}