import json
import boto3
import os
from datetime import datetime, timezone

dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")
lambda_client = boto3.client("lambda")

def lambda_handler(event, context):
    print("GuardDuty event received:", json.dumps(event))

    try:
        detail = event.get("detail", {})
        finding_type = detail.get("type", "Unknown")
        severity = detail.get("severity", 0)
        region = detail.get("region", "unknown")

        # Extract attacker IP
        service = detail.get("service", {})
        action = service.get("action", {})
        remote_ip_details = (
            action.get("networkConnectionAction", {})
            .get("remoteIpDetails", {})
        )
        attacker_ip = remote_ip_details.get("ipAddressV4", "unknown")
        country = (
            remote_ip_details.get("country", {})
            .get("countryName", "unknown")
        )
        city = (
            remote_ip_details.get("city", {})
            .get("cityName", "unknown")
        )

        timestamp = datetime.now(timezone.utc).isoformat()

        print(f"Attacker detected: {attacker_ip} from {city}, {country}")

        # Log to DynamoDB
        table = dynamodb.Table(os.environ["DYNAMODB_TABLE"])
        table.put_item(Item={
            "attacker_ip":    attacker_ip,
            "timestamp":      timestamp,
            "finding_type":   finding_type,
            "severity":       str(severity),
            "country":        country,
            "city":           city,
            "region":         region,
            "raw_event":      json.dumps(detail)
        })

        # Send alert email
        message = f"""
HONEYPOT ALERT — Intrusion Detected

Attacker IP   : {attacker_ip}
Location      : {city}, {country}
Finding Type  : {finding_type}
Severity      : {severity}
Time          : {timestamp}
Region        : {region}

Fake environment is being deployed for this attacker.
Check DynamoDB table for full session logs.
        """
        sns.publish(
            TopicArn=os.environ["SNS_TOPIC_ARN"],
            Subject="HONEYPOT ALERT — Attacker Detected",
            Message=message
        )

        # Trigger fake environment deployment
        lambda_client.invoke(
            FunctionName=os.environ.get("FAKE_ENV_FUNCTION", "honeypot-f4747db4-fake-env"),
            InvocationType="Event",  # async
            Payload=json.dumps({
                "attacker_ip": attacker_ip,
                "timestamp":   timestamp,
                "country":     country
            })
        )

        return {"statusCode": 200, "body": "Attacker logged and fake env triggered"}

    except Exception as e:
        print(f"Error in detector: {str(e)}")
        raise e