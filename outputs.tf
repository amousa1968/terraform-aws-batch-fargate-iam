output "fargate_batch_execution_role_arn" {
  description = "ARN of the IAM role for Fargate Batch"
  value       = aws_iam_role.batch_fargate_execution_role.arn
}

output "batch_role_arn" {
  description = "Batch service role ARN"
  value       = aws_iam_role.batch_service_role.arn
}

output "batch_instance_profile_name" {
  description = "Batch instance profile name"
  value       = "" # Removed reference to undeclared resource
}
