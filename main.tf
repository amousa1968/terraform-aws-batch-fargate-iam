data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name       = "${var.namespace}-${var.name}"
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
}


# ------------------------------
# IAM roles and policies
# ------------------------------

resource "aws_iam_role" "batch_fargate_execution_role" {
  name = var.role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role" "batch_service_role" {
  name = "AWSBatchServiceRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "batch.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "AWSBatchServiceRole"
  }
}

resource "aws_iam_role_policy_attachment" "batch_service_role_attach" {
  role       = aws_iam_role.batch_service_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
}

resource "aws_iam_policy" "batch_fargate_policy" {
  name        = "${var.role_name}-policy"
  description = "Least privilege policy for AWS Batch Fargate with encryption and TLS"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [

      # Allow logging to CloudWatch
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = var.cloudwatch_log_group_arn
      },

      # Encrypted S3 bucket access (at-rest encryption)
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ],
        Resource = "${var.s3_bucket_arn}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-server-side-encryption": "AES256"
          }
        }
      },

      # Deny access to S3 if not using TLS (in-transit encryption)
      {
        Effect = "Deny",
        Action = "s3:*",
        Resource = "*",
        Condition = {
          Bool = {
            "aws:SecureTransport": "false"
          }
        }
      },

      # EBS + KMS access if EFS or EBS volumes are attached (future proof)
      {
        Effect = "Allow",
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKeyWithoutPlaintext",
          "ec2:CreateVolume",
          "ec2:AttachVolume",
          "ec2:DeleteVolume",
          "ec2:DescribeVolumes"
        ],
        Resource = "*",
        Condition = {
          "BoolIfExists": {
            "kms:ViaService": "ec2.${var.aws_region}.amazonaws.com"
          }
        }
      },

      # ECS / VPC descriptions (Batch CE Fargate setup)
      {
        Effect = "Allow",
        Action = [
          "ecs:DescribeTasks",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "batch_fargate_attach" {
  role       = aws_iam_role.batch_fargate_execution_role.name
  policy_arn = aws_iam_policy.batch_fargate_policy.arn
}


#------------------------------------------------
# Batch Compute Environment (Fargate)
#------------------------------------------------
# --------------------------
# VPC for Batch Environment
# --------------------------
resource "aws_vpc" "batch_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "batch-vpc"
  }
}

# --------------------------
# Private Subnets
# --------------------------
resource "aws_subnet" "private_subnets" {
  count                   = length(var.private_subnet_cidrs)
  vpc_id                  = aws_vpc.batch_vpc.id
  cidr_block              = var.private_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "batch-private-subnet-${count.index}"
  }
}

# --------------------------
# Network ACL (NACL)
# --------------------------
resource "aws_network_acl" "batch_nacl" {
  vpc_id = aws_vpc.batch_vpc.id

  tags = {
    Name = "batch-private-nacl"
  }
}

# Allow all egress
resource "aws_network_acl_rule" "egress_all" {
  network_acl_id = aws_network_acl.batch_nacl.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

# Allow internal ingress from within VPC CIDR
resource "aws_network_acl_rule" "ingress_internal" {
  network_acl_id = aws_network_acl.batch_nacl.id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = var.vpc_cidr
}

# --------------------------
# Security Group
# --------------------------
resource "aws_security_group" "batch_sg" {
  name        = "batch-fargate-sg"
  description = "Restrictive SG for Batch Fargate jobs"
  vpc_id      = aws_vpc.batch_vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "batch-fargate-sg"
  }
}

# ----------------------------------------
# AWS Batch Compute Environment (FARGATE)
# ----------------------------------------

resource "aws_batch_compute_environment" "batch_fargate_ce" {
  name = "fargate-ce"

  compute_resources {
    type               = "FARGATE"
    max_vcpus          = 16
    subnets            = aws_subnet.private_subnets[*].id
    security_group_ids = [aws_security_group.batch_sg.id]
  }

  service_role = aws_iam_role.batch_service_role.arn
  type         = "MANAGED"
}


# --------------------------------------------------
# Enable AWS CloudTrail logging for Batch API calls
# --------------------------------------------------

resource "aws_cloudtrail" "batch_trail" {
  name                          = "batch-api-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = {
    Name = "batch-trail"
  }
}

##################
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "my-batch-cloudtrail-logs-secure"
  force_destroy = true

  tags = {
    Name = "cloudtrail-logs"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_encryption" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_lifecycle" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "expire-old-versions"
    status = "Enabled"

    filter {} # REQUIRED: Even an empty filter is valid

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_s3_bucket_policy" "restrict_access_by_tag" {
  bucket = aws_s3_bucket.batch_data.bucket

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AllowS3AccessByTag",
        Effect    = "Allow",
        Principal = "*",
        Action    = ["s3:GetObject", "s3:PutObject"],
        Resource  = "arn:aws:s3:::${aws_s3_bucket.batch_data.bucket}/*",
        Condition = {
          StringEquals = {
            "aws:PrincipalTag/Department" = var.allowed_department
          }
        }
      }
    ]
  })
}

#### new
resource "aws_s3_bucket" "batch_data" {
  bucket = "my-batch-data-bucket-123456" # Change to a unique name

  tags = {
    Name        = "BatchDataBucket"
    Environment = "prod"
  }
}


#########################
# --------------------------------------------------
# Enable Amazon Inspector for container image scanning
# --------------------------------------------------

resource "aws_inspector2_enabler" "ecr_scanning" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["ECR"]
}

resource "aws_inspector2_delegated_admin_account" "inspector_admin" {
  account_id = data.aws_caller_identity.current.account_id
}


resource "aws_guardduty_detector" "main" {
  enable = true
}

/*
resource "aws_inspector2_enabler" "ecs_runtime_monitoring" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["ECS"]
}
*/


# --------------------------------------------------
# IAM role creation and deletion for AWS Batch jobs
# --------------------------------------------------

resource "aws_iam_role" "batch_job_role" {
  name = "batch-job-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Purpose        = "BatchJobExecution"
    AutoDelete     = "true"
    ReviewDate     = "2025-12-31"  # Used for regular access reviews
    CreatedBy      = "Terraform"
  }
}

resource "aws_iam_policy" "batch_job_policy" {
  name        = "BatchJobMinimalPolicy"
  description = "Least privilege access policy for ECS Fargate Batch jobs"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:CreateLogGroup"
        ],
        Resource = "*"
      },
      {
        Effect   = "Allow",
        Action   = [
          "s3:GetObject",
          "s3:PutObject"
        ],
        Resource = "arn:aws:s3:::my-batch-data-bucket/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "batch_attach_policy" {
  role       = aws_iam_role.batch_job_role.name
  policy_arn = aws_iam_policy.batch_job_policy.arn
}


# --------------------------------------------------
# TLS Compliance Fargate Batch Job
# --------------------------------------------------

resource "aws_batch_job_definition" "fargate_job" {
  name = "${var.namespace}-${var.name}-job"
  type = "container"

  platform_capabilities = ["FARGATE"]

  container_properties = jsonencode({
    image      = var.container_image
    jobRoleArn = aws_iam_role.batch_job_role.arn
    executionRoleArn = aws_iam_role.batch_execution_role.arn
    resourceRequirements = [
      {
        type  = "VCPU"
        value = "1"
      },
      {
        type  = "MEMORY"
        value = "2048"
      }
    ]
    environment = [
      {
        name  = "API_ENDPOINT"
        value = "https://api.mysecureapp.com" # Enforcing TLS endpoint
      },
      {
        name  = "S3_BUCKET_URL"
        value = "https://mybucket.s3.amazonaws.com" # TLS
      },
      {
        name  = "ENFORCE_TLS"
        value = "true"
      }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/aws/batch/job/${var.namespace}-${var.name}"
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "fargate"
      }
    }
    networkConfiguration = {
      assignPublicIp = "DISABLED"
    }
  })
}


resource "aws_iam_role" "batch_execution_role" {
  name = "${var.namespace}-${var.name}-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "${var.namespace}-${var.name}-execution-role"
  }
}

resource "aws_iam_role_policy_attachment" "ecs_execution_policy" {
  role       = aws_iam_role.batch_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}


# -------------------------------------------------------------------
# Restrict Batch resource access based on user attributes and context
# -------------------------------------------------------------------

resource "aws_iam_policy" "batch_access_control_policy" {
  name        = "BatchAccessControlByDepartment"
  description = "Restrict AWS Batch access based on IAM user tags"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "batch:SubmitJob",
          "batch:DescribeJobs",
          "batch:ListJobs",
          "batch:TerminateJob"
        ],
        Resource = "*",
        Condition = {
          StringEquals = {
            "aws:PrincipalTag/Department" = var.allowed_department
          }
        }
      },
      {
        Effect = "Deny",
        Action = "batch:*",
        Resource = "*",
        Condition = {
          StringNotEquals = {
            "aws:PrincipalTag/Department" = var.allowed_department
          }
        }
      }
    ]
  })
}


#

# -------------------------------------------------------------------
# Restrict access to AWS Batch resources on Fargate ECS
# based on user tags and context
# -------------------------------------------------------------------

resource "aws_iam_policy" "batch_restricted_access" {
  name        = "BatchAccessRestrictedByTag"
  description = "Allow access to Batch only for principals tagged with allowed department"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AllowBatchAccessWithTag",
        Effect = "Allow",
        Action = [
          "batch:SubmitJob",
          "batch:DescribeJobs",
          "batch:ListJobs",
          "batch:TerminateJob",
          "batch:DescribeJobQueues",
          "batch:DescribeJobDefinitions"
        ],
        Resource = "*",
        Condition = {
          StringEquals = {
            "aws:PrincipalTag/Department" = var.allowed_department
          }
        }
      },
      {
        Sid    = "DenyBatchAccessWithoutTag",
        Effect = "Deny",
        Action = "batch:*",
        Resource = "*",
        Condition = {
          StringNotEquals = {
            "aws:PrincipalTag/Department" = var.allowed_department
          }
        }
      }
    ]
  })
}

# Attach policy to a role used by developers or CI/CD system
resource "aws_iam_role_policy_attachment" "batch_access_attachment" {
  role       = aws_iam_role.batch_job_role.name
  policy_arn = aws_iam_policy.batch_restricted_access.arn
}
