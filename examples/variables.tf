variable "role_name" {
  description = "Name of the IAM role"
  type        = string
}

variable "cloudwatch_log_group_arn" {
  description = "CloudWatch Log Group ARN"
  type        = string
}

variable "s3_bucket_arn" {
  description = "S3 Bucket ARN"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

