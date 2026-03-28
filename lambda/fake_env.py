import json
import boto3
import os
import uuid
from datetime import datetime, timezone

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")

FAKE_FILES = {
    "credentials.csv": (
        "username,password,role\n"
        "admin,Admin@1234,superadmin\n"
        "deploy-user,Deploy#567,developer\n"
        "backup-admin,Backup!890,backup\n"
    ),
    "aws_keys_backup.txt": (
        "# Internal AWS Keys — DO NOT SHARE\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    ),
    "database_config.json": json.dumps({
        "host":     "prod-db.internal.example.com",
        "port":     5432,
        "user":     "db_admin",
        "password": "Pr0d#DB!2024",
        "dbname":   "production"
    }, indent=2),
    "internal_notes.txt": (
        "Internal use only\n"
        "VPN: vpn.internal.example.com\n"
        "Admin panel: http://admin.internal.example.com:8080\n"
        "Jenkins: http://ci.internal.example.com:8080\n"
    ),
    "employee_data.csv": (
        "name,email,salary\n"
        "John Smith,jsmith@example.com,95000\n"
        "Jane Doe,jdoe@example.com,105000\n"
    )
}

def lambda_handler(event, context):
    print("Fake env triggered for:", json.dumps(event))

    attacker_ip = event.get("attacker_ip", "unknown")
    timestamp   = event.get("timestamp", datetime.now(timezone.utc).isoformat())
    country     = event.get("country", "unknown")

    try:
        # Create a unique fake bucket per attacker session
        session_id  = str(uuid.uuid4())[:8]
        fake_bucket = f"internal-backup-{session_id}"

        s3.create_bucket(Bucket=fake_bucket)
        print(f"Fake bucket created: {fake_bucket}")

        # Block all public access on fake bucket
        s3.put_public_access_block(
            Bucket=fake_bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls":       True,
                "IgnorePublicAcls":      True,
                "BlockPublicPolicy":     True,
                "RestrictPublicBuckets": True
            }
        )

        # Seed fake files into the bucket
        for filename, content in FAKE_FILES.items():
            s3.put_object(
                Bucket=fake_bucket,
                Key=filename,
                Body=content.encode("utf-8")
            )
            print(f"Seeded fake file: {filename}")

        # Log the fake env deployment to DynamoDB
        table = dynamodb.Table(os.environ["DYNAMODB_TABLE"])
        table.put_item(Item={
            "attacker_ip": attacker_ip,
            "timestamp":   timestamp + "_fakeenv",
            "action":      "fake_environment_deployed",
            "session_id":  session_id,
            "fake_bucket": fake_bucket,
            "country":     country
        })

        # Notify you that fake env is live
        sns.publish(
            TopicArn=os.environ["SNS_TOPIC_ARN"],
            Subject="HONEYPOT — Fake Environment Deployed",
            Message=(
                f"Fake environment deployed for attacker\n\n"
                f"Attacker IP : {attacker_ip}\n"
                f"Country     : {country}\n"
                f"Session ID  : {session_id}\n"
                f"Fake Bucket : {fake_bucket}\n"
                f"Time        : {timestamp}\n\n"
                f"Monitor DynamoDB for attacker activity."
            )
        )

        return {
            "statusCode": 200,
            "body": f"Fake env deployed: {fake_bucket}"
        }

    except Exception as e:
        print(f"Error deploying fake env: {str(e)}")
        raise e
