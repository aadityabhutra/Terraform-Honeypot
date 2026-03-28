output "lure_bucket_name" {
  description = "Name of the honeypot lure bucket"
  value       = aws_s3_bucket.lure.bucket
}

output "log_bucket_name" {
  description = "Name of the log bucket"
  value       = aws_s3_bucket.logs.bucket
}

output "dynamodb_table" {
  description = "DynamoDB table storing attacker events"
  value       = aws_dynamodb_table.events.name
}

output "sns_topic_arn" {
  description = "SNS topic ARN for alerts"
  value       = aws_sns_topic.alerts.arn
}

output "detector_lambda" {
  description = "Detector Lambda function name"
  value       = aws_lambda_function.detector.function_name
}

output "fake_env_lambda" {
  description = "Fake environment Lambda function name"
  value       = aws_lambda_function.fake_env.function_name
}
