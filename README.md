# Serverless Honeypot — AWS + Terraform

Defensive security project that auto-deploys a fake AWS 
environment the moment an attacker scans your infrastructure.

## Architecture
- **GuardDuty** — detects port scans and threats
- **EventBridge** — routes findings instantly
- **Lambda** — fingerprints attacker and deploys decoy
- **S3** — stores bait files and logs
- **DynamoDB** — logs every attacker session
- **SNS** — sends real-time email alerts

## Deploy
terraform init
terraform apply

## Tear Down
terraform destroy
