variable "aws_region" {
  description = "AWS region to deploy honeypot"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "honeypot"
}

variable "alert_email" {
  description = "Email to receive attacker alerts"
  type        = string
}

variable "log_retention_days" {
  description = "How long to keep logs in days"
  type        = number
  default     = 90
}

variable "block_attackers" {
  description = "Auto-block attacker IPs via WAF"
  type        = bool
  default     = true
}

variable "enable_waf" {
  description = "Enable WAF IP blocking"
  type        = bool
  default     = true
}

variable "multi_region_trail" {
  description = "Enable CloudTrail across all regions"
  type        = bool
  default     = false
}
