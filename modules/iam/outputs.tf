output "batch_role_arn" {
  description = "Batch service role ARN"
  value       = aws_iam_role.batch_service_role.arn
}

output "batch_instance_profile_name" {
  description = "Batch instance profile name"
  value       = aws_iam_instance_profile.batch_instance_profile.name
}