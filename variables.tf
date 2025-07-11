variable "namespace" {
  type 		= string
description = "A simple namespace value for this resource."
}

variable "name" {
  type		= string
description = "A simple name value for this resource."
}

variable "tags" {
  type		= map (any)
description = "A mapping of tags for this resource."
}

/*
variable "namespace" {
  description = "Project or environment prefix used for naming resources"
  type        = string
  default     = "myproject"  # Change this to suit your use case
}
*/

/*
variable "name" {
  description = "Name suffix for uniquely identifying resources"
  type        = string
  default     = "batch"  # Change this to something meaningful like 'job' or 'pipeline'
}
*/

variable "role_name" {
  type        = string
  description = "IAM role name for Fargate Batch execution"
}

variable "cloudwatch_log_group_arn" {
  type        = string
  description = "ARN of the CloudWatch Log Group for job output"
}

variable "s3_bucket_arn" {
  type        = string
  description = "ARN of S3 bucket used by Batch jobs"
}

variable "aws_region" {
  type        = string
  description = "AWS Region for KMS encryption and ECS context (e.g., us-west-2)"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  default     = "10.0.0.0/16"
}

variable "private_subnet_cidrs" {
  type        = list(string)
  description = "CIDRs for private subnets"
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}


variable "availability_zones" {
  type        = list(string)
  description = "Availability zones for each subnet"
}

/*
variable "availability_zones" {
  description = "List of availability zones for subnets"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]  # Adjust for your region
}
*/

variable "region" {
  description = "The AWS region to deploy resources into."
  type        = string
  default     = "us-west-2" # Change to your preferred region
}


#####
variable "allowed_department" {
  description = "IAM user tag required to access Batch resources"
  type        = string
  default     = "DataScience"
}

variable "batch_resources_arn_prefix" {
  description = "ARN prefix for Batch resources (used in IAM policy)"
  type        = string
  default     = "arn:aws:batch:*:*:job-definition/"
}

variable "container_image" {
  description = "The URI of the container image to use for the Batch job"
  type        = string
  default     = "public.ecr.aws/amazonlinux/amazonlinux:latest" # or your image
}

########################### TLC #
variable "job_definition_name" {
  description = "Name of the Batch job definition"
  type        = string
  default     = "tls-batch-job"
}

variable "container_image" {
  description = "Container image URI with TLS support"
  type        = string
}

variable "execution_role_arn" {
  description = "ARN of the execution role"
  type        = string
}

variable "job_role_arn" {
  description = "ARN of the job role"
  type        = string
}
