resource "aws_batch_compute_environment" "batch_ce" {
  name = "batch-compute-env"

  compute_resources {
    type               = "FARGATE"
    instance_role      = var.batch_service_role_arn
    instance_type      = var.batch_instance_type
    min_vcpus          = 0
    max_vcpus          = 16
    desired_vcpus      = 0
    subnets            = var.private_subnet_ids
    security_group_ids = [var.security_group_id]
  }
  service_role = var.batch_service_role_arn
  type         = "MANAGED"
}