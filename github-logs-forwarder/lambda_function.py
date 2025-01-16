import json
import boto3
import os
import hmac
import hashlib
from datetime import datetime

def verify_signature(event):
    github_signature = event['headers'].get('X-Hub-Signature-256')
    if not github_signature:
        return False

    webhook_secret = os.environ['5sZsPR2xetIm6+5/TSLaO2nyeU71EIaYqPgg8uuhjsQ=']
    payload_body = event['body']

    expected_signature = 'sha256=' + hmac.new(
        webhook_secret.encode('utf-8'),
        payload_body.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(github_signature, expected_signature)

def lambda_handler(event, context):
    try:
        if not verify_signature(event):
            return {
                'statusCode': 401,
                'body': json.dumps('Signature verification failed')
            }

        payload = json.loads(event['body'])

        bucket_name = os.environ['S3_BUCKET_NAME']

        timestamp = datetime.now().strftime('%Y/%m/%d/%H-%M-%S')
        event_type = event['headers'].get('X-GitHub-Event', 'unknown')
        key = f'github-logs/{event_type}/{timestamp}.json'

        s3 = boto3.client('s3')

        enriched_payload = {
            'event_type': event_type,
            'timestamp': timestamp,
            'repository': payload.get('repository', {}).get('full_name'),
            'sender': payload.get('sender', {}).get('login'),
            'raw_payload': payload
        }

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