terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name_prefix = "honeypot-${random_id.suffix.hex}"
}

# ── S3 Lure Bucket (bait for attackers) ──────────────────────

resource "aws_s3_bucket" "lure" {
  bucket        = "${local.name_prefix}-lure"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "lure" {
  bucket                  = aws_s3_bucket.lure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "bait_files" {
  for_each = {
    "credentials.csv"        = "username,password\nadmin,admin123\nroot,toor\n"
    "aws_keys_backup.txt"    = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=EXAMPLEKEY\n"
    "database_dump.sql"      = "-- Production DB Export\nCREATE TABLE users (id INT, email VARCHAR);\n"
    "internal_api_keys.json" = "{\"stripe\":\"sk_live_FAKEKEY\",\"sendgrid\":\"SG.FAKETOKEN\"}\n"
  }
  bucket  = aws_s3_bucket.lure.id
  key     = each.key
  content = each.value
}

# ── S3 Log Bucket ─────────────────────────────────────────────

resource "aws_s3_bucket" "logs" {
  bucket        = "${local.name_prefix}-logs"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── DynamoDB — attacker event log ────────────────────────────

resource "aws_dynamodb_table" "events" {
  name         = "${local.name_prefix}-events"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "attacker_ip"
  range_key    = "timestamp"

  attribute {
    name = "attacker_ip"
    type = "S"
  }
  attribute {
    name = "timestamp"
    type = "S"
  }

  ttl {
    attribute_name = "expiry"
    enabled        = true
  }
}

# ── SNS — alert emails ────────────────────────────────────────

resource "aws_sns_topic" "alerts" {
  name = "${local.name_prefix}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ── IAM Role for Lambda ───────────────────────────────────────

resource "aws_iam_role" "lambda" {
  name = "${local.name_prefix}-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda" {
  name = "${local.name_prefix}-lambda-policy"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:*"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.events.arn
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.logs.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["guardduty:ListFindings", "guardduty:GetFindings"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = aws_lambda_function.fake_env.arn
      }
    ]
  })
}
# ── Lambda — Detector ─────────────────────────────────────────

data "archive_file" "detector" {
  type        = "zip"
  output_path = "/tmp/detector.zip"
  source_file = "${path.module}/lambda/detector.py"
}

resource "aws_lambda_function" "detector" {
  function_name    = "${local.name_prefix}-detector"
  role             = aws_iam_role.lambda.arn
  handler          = "detector.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.detector.output_path
  source_code_hash = data.archive_file.detector.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      LOG_BUCKET     = aws_s3_bucket.logs.bucket
      SNS_TOPIC_ARN  = aws_sns_topic.alerts.arn
      DYNAMODB_TABLE = aws_dynamodb_table.events.name
    }
  }
}

# ── Lambda — Fake Env Provisioner ────────────────────────────

data "archive_file" "fake_env" {
  type        = "zip"
  output_path = "/tmp/fake_env.zip"
  source_file = "${path.module}/lambda/fake_env.py"
}

resource "aws_lambda_function" "fake_env" {
  function_name    = "${local.name_prefix}-fake-env"
  role             = aws_iam_role.lambda.arn
  handler          = "fake_env.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.fake_env.output_path
  source_code_hash = data.archive_file.fake_env.output_base64sha256
  timeout          = 60

  environment {
    variables = {
      LOG_BUCKET     = aws_s3_bucket.logs.bucket
      SNS_TOPIC_ARN  = aws_sns_topic.alerts.arn
      DYNAMODB_TABLE = aws_dynamodb_table.events.name
    }
  }
}

# ── EventBridge — trigger on GuardDuty findings ───────────────

resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "${local.name_prefix}-guardduty-rule"
  description = "Trigger honeypot on GuardDuty finding"
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "detector" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "DetectorLambda"
  arn       = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "eventbridge_detector" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty.arn
}
