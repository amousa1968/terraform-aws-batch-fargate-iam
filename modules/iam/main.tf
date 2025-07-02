resource "aws_iam_role" "batch_service_role" {
  name = var.role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "batch.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "batch_custom_policy" {
  name        = "${var.role_name}-policy"
  description = "Least privilege IAM policy for AWS Batch"
  policy      = data.aws_iam_policy_document.batch_policy.json
}

resource "aws_iam_role_policy_attachment" "batch_attach_policy" {
  role       = aws_iam_role.batch_service_role.name
  policy_arn = aws_iam_policy.batch_custom_policy.arn
}

resource "aws_iam_instance_profile" "batch_instance_profile" {
  name = "batch-ec2-instance-profile"
  role = aws_iam_role.batch_service_role.name
}