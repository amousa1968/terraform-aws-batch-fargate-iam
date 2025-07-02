# example/main.tf - Modularized structure for AWS Batch infrastructure

module "iam" {
  source = "./modules/iam"

  role_name               = var.role_name
  cloudwatch_log_group_arn = var.cloudwatch_log_group_arn
  s3_bucket_arn           = var.s3_bucket_arn
  aws_region              = var.aws_region
}

module "network" {
  source = "./modules/network"

  vpc_cidr             = var.vpc_cidr
  private_subnet_cidrs = var.private_subnet_cidrs
  availability_zones   = var.availability_zones
}

module "batch" {
  source = "./modules/batch"

  batch_instance_type      = var.batch_instance_type
  batch_service_role_arn   = module.iam.batch_role_arn
  private_subnet_ids       = module.network.private_subnet_ids
  security_group_id        = module.network.batch_sg_id
  instance_profile_name    = module.iam.batch_instance_profile_name
}

module "monitoring" {
  source = "./modules/monitoring"

  batch_role_name = var.role_name
}

module "ecr" {
  source = "./modules/ecr"
}