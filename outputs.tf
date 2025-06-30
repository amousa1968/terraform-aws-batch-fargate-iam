output "fargate_batch_execution_role_arn" {
  description = "ARN of the IAM role for Fargate Batch"
  value       = aws_iam_role.batch_fargate_execution_role.arn
}
