resource "aws_iam_role" "batch_service" {
  name               = "batch-service-role"
  assume_role_policy = data.aws_iam_policy_document.batch_assume_role.json
}

data "aws_iam_policy_document" "batch_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["batch.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "batch_service" {
  role       = aws_iam_role.batch_service.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
}