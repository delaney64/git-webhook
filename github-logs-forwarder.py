# lambda_function.py
import json
import boto3
import os
import hmac
import hashlib
import base64
from datetime import datetime

def verify_signature(event):
    # Get the signature from GitHub
    github_signature = event['headers'].get('X-Hub-Signature-256')
    if not github_signature:
        return False
    
    # Get the webhook secret from environment variables
    webhook_secret = os.environ['GITHUB_WEBHOOK_SECRET']
    
    # Get the payload body
    payload_body = event['body']
    
    # Calculate expected signature
    expected_signature = 'sha256=' + hmac.new(
        webhook_secret.encode('utf-8'),
        payload_body.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(github_signature, expected_signature)

def lambda_handler(event, context):
    try:
        # Verify webhook signature
        if not verify_signature(event):
            return {
                'statusCode': 401,
                'body': json.dumps('Signature verification failed')
            }
        
        # Parse the webhook payload
        payload = json.loads(event['body'])
        
        # Get S3 bucket name from environment variable
        bucket_name = os.environ['S3_BUCKET_NAME']
        
        # Create a unique key for the log file
        timestamp = datetime.now().strftime('%Y/%m/%d/%H-%M-%S')
        event_type = event['headers'].get('X-GitHub-Event', 'unknown')
        key = f'github-logs/{event_type}/{timestamp}.json'
        
        # Initialize S3 client
        s3 = boto3.client('s3')
        
        # Add metadata to the payload
        enriched_payload = {
            'event_type': event_type,
            'timestamp': timestamp,
            'repository': payload.get('repository', {}).get('full_name'),
            'sender': payload.get('sender', {}).get('login'),
            'raw_payload': payload
        }
        
        # Upload to S3
        s3.put_object(
            Bucket=bucket_name,
            Key=key,
            Body=json.dumps(enriched_payload, indent=2),
            ContentType='application/json'
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps('Successfully processed GitHub webhook')
        }
    
    except Exception as e:
        print(f'Error: {str(e)}')
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error processing webhook: {str(e)}')
        }

# terraform/main.tf
provider "aws" {
  region = "us-east-1"  # Change to your preferred region
}

resource "aws_s3_bucket" "github_logs" {
  bucket = "your-github-logs-bucket"  # Change this to your desired bucket name
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
  filename         = "lambda_function.zip"  # You'll need to create this
  function_name    = "github-logs-forwarder"
  role            = aws_iam_role.lambda_role.arn
  handler         = "lambda_function.lambda_handler"
  runtime         = "python3.9"

  environment {
    variables = {
      S3_BUCKET_NAME = aws_s3_bucket.github_logs.id
      GITHUB_WEBHOOK_SECRET = "your-webhook-secret"  # Change this!
    }
  }
}

resource "aws_lambda_function_url" "github_logs_forwarder" {
  function_name      = aws_lambda_function.github_logs_forwarder.function_name
  authorization_type = "NONE"
}
