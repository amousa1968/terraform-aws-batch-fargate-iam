resource "aws_ecr_repository" "batch_job_repo" {
  name                 = "batch-job-container"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_iam_policy" "ecr_scan_read_policy" {
  name        = "BatchECRScanRead"
  description = "Allow Batch to read ECR image scan results"
  policy      = data.aws_iam_policy_document.ecr_scan_policy.json
}