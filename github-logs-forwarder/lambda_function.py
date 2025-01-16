import json
import boto3
import os
import hmac
import hashlib
import base64
from datetime import datetime

def verify_signature(event):
    if not event.get('headers'):
        print("No headers found in event")
        return False

    github_signature = event.get('headers', {}).get('X-Hub-Signature-256')
    if not github_signature:
        print("No signature found in headers")
        return False

    # Your actual webhook secret (base64 encoded)
    webhook_secret = "5sZsPR2xetIm6+5/TSLaO2nyeU71EIaYqPgg8uuhjsQ="
    # Decode the base64 secret
    webhook_secret_bytes = base64.b64decode(webhook_secret)

    payload_body = event.get('body', '')

    # Create expected signature
    expected_signature = 'sha256=' + hmac.new(
        webhook_secret_bytes,
        payload_body.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    print(f"Expected signature: {expected_signature}")
    print(f"Received signature: {github_signature}")

    return hmac.compare_digest(github_signature, expected_signature)

def lambda_handler(event, context):
    try:
        print(f"Received event: {json.dumps(event, indent=2)}")

        if not verify_signature(event):
            return {
                'statusCode': 401,
                'body': json.dumps({
                    'error': 'Signature verification failed',
                    'headers_present': bool(event.get('headers')),
                    'signature_present': bool(event.get('headers', {}).get('X-Hub-Signature-256'))
                })
            }

        payload = json.loads(event.get('body', '{}'))

        bucket_name = os.environ['S3_BUCKET_NAME']

        timestamp = datetime.now().strftime('%Y/%m/%d/%H-%M-%S')
        event_type = event.get('headers', {}).get('X-GitHub-Event', 'unknown')
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
        error_message = f'Error: {str(e)}'
        print(error_message)
        print(f'Event structure: {json.dumps(event, indent=2)}')
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': error_message,
                'event': event
            })
        }