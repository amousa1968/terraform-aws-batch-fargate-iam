provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

module "namespace" {	
  source		   = "../"	#replace with url as needed
  application_name = var.application_name
  application_code = var.application_code
  application_id   = var.application_id
  service_name	   = var.service_name
  environment	   = var.environment
  cost_center	   = var.cost_center
  created_by	   = var.created_by
  supported_by	   = var.supported_by
  scm_namespace	   = var.scm_namespace
  scm_repo_id	   = var.scm_repo_id
  scm_repo	       = var.scm_repo
  scm_branch	   = var.scm_branch
}


module "iam" {
  source 		= "../"
  name 			= "iam"
  namespace 	= module.namespace.short
  tags 			= module.namespace.tags
# availability_zones = var.availability_zones
  availability_zones = ["us-east-1a", "us-east-1b", "us-east"]
  role_name 	= var.role_name
  cloudwatch_log_group_arn = var.cloudwatch_log_group_arn
  s3_bucket_arn = var.s3_bucket_arn
  aws_region = var.aws_region
}

module "network" {
  source 				="../"
  namespace 			= module.namespace.short
  name 					= "network"
  tags 					= module.namespace.tags
  vpv_cidr 				= var.vpc_cidr
  availability_zones 	= ["us-east-1a", "us-east-1b", "us-east"]
  role_name 			= var.role_name
  cloudwatch_log_group_arn = var.cloudwatch_log_group_arn
  s3_bucket_arn			 = var.s3_bucket_arn
    private_subnet_cidrs = [ 
    "10.0.1.0/24",
    "10.0.2.0/24",
  ]
  aws_region 			= var.aws_region

}

module "batch" {
  source 				= "../"
  namespace 			= module.namespace.short
  name 					= "batch"
  tags 					= module.namespace.tags
  availability_zones 	= ["us-east-1a", "us-east-1b", "us-east"]
  role_name 			= var.role_name
  cloudwatch_log_group_arn = var.cloudwatch_log_group_arn
  s3_bucket_arn			 = var.s3_bucket_arn
  aws_region 			= var.aws_region

# batch_instance_type 	= var.batch_instance_type
# batch_service_role_arn = module.iam.batch_role_arn
# private_subnet_ids 	= module.network.private_subnet_ids
# security_group_id		 = module.network.batch_sg_id
# instance profile name = module.iam.batch_instance_profile_name

}

module "monitoring" {
  source 					= "../" 
  namespace 				= module.namespace.short
  name 						= "monitoring"
  tags 						= module.namespace.tags
  availability_zones 		= ["us-east-1a", "us-east-1b", "us-east"]
  role_name 				= var.role_name
  s3_bucket_arn 			= var.s3_bucket_arn
  cloudwatch_log_group_arn 	= var.cloudwatch_log_group_arn
  aws_region 				= var.aws_region
# batch role name 			= var.role_name

}

module "ecr" {
  source 			= "../"
  namespace 		= module.namespace.short
  name  			= "ecr"
  tags 				= module.namespace.tags 
  availability_zones = var.availability_zones
  role_name = var.role_name
  s3_bucket_arn 	= var.s3_bucket_arn
  cloudwatch_log_group_arn = var.cloudwatch_log_group_arn
  aws_region 		= var.aws_region
# batch_role_name 	= var.role_name

}
