import json
import boto3
import os
import random
import string
from datetime import datetime

# Initialize boto3 clients for S3 and Comprehend
comprehend_client = boto3.client('comprehend')

def lambda_handler(event, context):
    # Generate a random string to avoid conflicts with S3 bucket names
    random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    # Extract bucket name and file key from the S3 event trigger
    bucket_name = event['Records'][0]['s3']['bucket']['name']
    file_key = event['Records'][0]['s3']['object']['key']
    
    # Define the IAM role ARN for Comprehend (ensure it's available in your environment)
    comprehend_role_arn = os.environ.get('COMPREHEND_ROLE_ARN')  # Replace with your IAM role ARN

    try:
        # Start the PII entities detection job using the `start_pii_entities_detection_job` API
        response = comprehend_client.start_pii_entities_detection_job(
            InputDataConfig={
                'S3Uri': f's3://{bucket_name}/{file_key}',  # S3 input file
                'InputFormat': 'ONE_DOC_PER_FILE',  # The format of the input file
            },
            OutputDataConfig={
                'S3Uri': f's3://{bucket_name}/redacted_output/{random_string}/',  # Output location for results
            },
            Mode='ONLY_REDACTION',  # Only redact PII entities
            RedactionConfig={
                'PiiEntityTypes': [
                    'BANK_ACCOUNT_NUMBER',
                    'BANK_ROUTING',
                    'CREDIT_DEBIT_NUMBER',
                    'CREDIT_DEBIT_CVV',
                    'CREDIT_DEBIT_EXPIRY',
                    'PIN',
                    'EMAIL',
                    'ADDRESS',
                    'NAME',
                    'PHONE',
                    'SSN'
                ],
                'MaskMode': 'MASK',
                'MaskCharacter': '*'
            },
            DataAccessRoleArn=comprehend_role_arn,  # IAM role with necessary permissions
            JobName=f"PII_Detection_Job_{datetime.utcnow().strftime('%Y-%m-%dT%H-%M-%SZ')}",  # Unique job name
            LanguageCode='en'  # Specify language code (English in this case)
        )

        # Extract the JobId from the response
        job_id = response['JobId']
        print(f"Job started successfully with JobId: {job_id}")
        
        # Return success response with JobId
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'PII detection and redaction job started successfully.',
                'jobId': job_id
            })
        }

    except Exception as e:
        print(f"Error starting PII detection job: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error starting PII detection job: {str(e)}")
        }
