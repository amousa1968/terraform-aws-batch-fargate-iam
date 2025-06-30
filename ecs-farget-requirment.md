lac - Implement IAM roles and policies using CloudFormation or Terraform with least privilege principles for Batch job queues, compute environments, and job definitions ----  fargate/ecs

basic, least-privilege Terraform module to implement IAM roles and policies for AWS Batch resources: 

* Job Queues
* Compute Environments
* Job Definitions
* It adheres to least privilege by only allowing required actions, scoped to relevant resources.
# Least Privilege Notes:
* ECS actions (RunTask, DescribeTasks, etc.) are necessary if Batch jobs run containers.
* CloudWatch permissions limited to specific log group ARN.
* EC2 describes are needed by Batch to place jobs in VPC compute environments.



laC - Configure EBS encryption, s3 bucket encryption, and TLS/SSL for data in transit through Batch job definitions and compute environment configurations - done

laC - Configure VPC security groups, NACLs, and private subnets for Batch compute environments with proper network segmentation - done

Platform - Enable AWS CloudTrail logging for Batch API calls and implement container image scanning for vulnerabilities - done

Platform - Enable Amazon Inspector for ECS instances in Batch compute environments and configure GuardDuty for threat detection - done

laC - Implement automated IAM role creation and deletion for Batch jobs with defined access policies and regular access reviews - done

laC - Configure resource-based policies and IAM policies with condition statements to restrict Batch resource access based on user attributes and context - done

laC - Configure TLS encryption for all data transmission in Batch job definitions and ensure secure communication channels - done

Platform - Enable CloudTrail logging for all Batch API operations and configure EventBridge for real-time monitoring of Batch events - done

###
Platform - Implement CloudWatch monitoring for Batch job metrics and configure alarms for anomalous behavior detection 

laC - Configure Batch compute environment subnets parameter to reference private subnets only and ensure NAT gateway access for outbound connectivity 

laC - Create specific IAM roles for each Batch job type with minimal required permissions and attach to job definitions 

laC - Define job queue priorities, compute environment order, and resource quotas in CloudFormation templates 

Platform - Enable Security Hub in the AWS account and configure Batch-related security standards and custom insights 

User - Configure ECR image scanning or integrate third-party vulnerability scanners in the CI/CD pipeline before deploying Batch jobs

