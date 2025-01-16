provider "aws" {
  region = "us-east-1"  # Change to your preferred region
}

resource "aws_s3_bucket" "github_logs" {
  bucket = "github-logs-forwarder-yourname"  # Change this to a unique name
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "github_logs" {
  bucket = aws_s3_bucket.github_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "github_logs" {
  bucket = aws_s3_bucket.github_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "github_logs" {
  bucket = aws_s3_bucket.github_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_iam_role" "lambda_role" {
  name = "github-logs-forwarder-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Service = "github-logs-forwarder"
  }
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "github-logs-forwarder-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = [
          "${aws_s3_bucket.github_logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:aws:logs:*:*:/aws/lambda/github-logs-forwarder*"
        ]
      }
    ]
  })
}

resource "aws_lambda_function" "github_logs_forwarder" {
  filename         = "lambda_function.zip"
  function_name    = "github-logs-forwarder"
  role            = aws_iam_role.lambda_role.arn
  handler         = "lambda_function.lambda_handler"
  runtime         = "python3.9"

  environment {
    variables = {
      S3_BUCKET_NAME = aws_s3_bucket.github_logs.id
      GITHUB_WEBHOOK_SECRET = "your-webhook-secret"  # Generate this with: openssl rand -hex 32
    }
  }
}

resource "aws_lambda_function_url" "github_logs_forwarder" {
  function_name      = aws_lambda_function.github_logs_forwarder.function_name
  authorization_type = "NONE"

  cors {
    allow_origins = ["*"]
    allow_methods = ["POST"]
  }
}