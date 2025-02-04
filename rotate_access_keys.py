import boto3 # type: ignore
import json
from botocore.exceptions import ClientError # type: ignore

secrets_manager_client = boto3.client('secretsmanager')
iam_client = boto3.client('iam')

def lambda_handler(event, context):
    try:
        # Extract event details
        secret_arn = event['SecretId']
        token = event['ClientRequestToken']
        step = event['Step']

        # Extract username from the secret's name
        secret_metadata = secrets_manager_client.describe_secret(SecretId=secret_arn)
        username = secret_metadata['Name'].replace("Access-Keys-", "").rsplit("-", 1)[0]

        print(f"Secret ARN: {secret_arn}")
        print(f"Secret Name: {secret_metadata['Name']}")
        print(f"Derived Username: {username}")

        # Ensure the user exists or create it
        try:
            iam_client.get_user(UserName=username)
            print(f"IAM user '{username}' exists.")
        except iam_client.exceptions.NoSuchEntityException:
            iam_client.create_user(UserName=username)
            print(f"IAM user '{username}' was created.")

        # Handle rotation steps
        if step == "createSecret":
            print(f"Creating a new access key for user '{username}'.")

            # List existing access keys
            access_keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
            print(f"Existing access keys for user '{username}': {access_keys}")

            # If the user already has 2 access keys, delete the oldest one
            if len(access_keys) >= 2:
                oldest_key = sorted(access_keys, key=lambda x: x['CreateDate'])[0]
                iam_client.delete_access_key(UserName=username, AccessKeyId=oldest_key['AccessKeyId'])
                print(f"Deleted oldest access key: {oldest_key['AccessKeyId']} for user '{username}'.")

            # Create a new IAM access key
            new_access_key = iam_client.create_access_key(UserName=username)
            new_secret = {
                "access_key_id": new_access_key['AccessKey']['AccessKeyId'],
                "secret_access_key": new_access_key['AccessKey']['SecretAccessKey']
            }

            # Store the new access key in Secrets Manager
            secrets_manager_client.put_secret_value(
                SecretId=secret_arn,
                ClientRequestToken=token,
                SecretString=json.dumps(new_secret)
            )
            print(f"Created and stored new access key for user '{username}'.")

        elif step == "finishSecret":
            print(f"Finishing secret rotation for user '{username}'.")

            # Retrieve the current access key from the secret
            old_secret = secrets_manager_client.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")
            old_secret_data = json.loads(old_secret['SecretString'])
            old_access_key_id = old_secret_data['access_key_id']

            # Mark the new key as active and remove the old one
            secrets_manager_client.update_secret_version_stage(
                SecretId=secret_arn,
                VersionStage="AWSCURRENT",
                MoveToVersionId=token,
                RemoveFromVersionId=old_secret['VersionId']
            )

            # Delete the old access key
            iam_client.delete_access_key(UserName=username, AccessKeyId=old_access_key_id)
            print(f"Deleted old access key for user '{username}'.")

        return {"status": "success"}

    except ClientError as e:
        print(f"AWS ClientError: {e}")
        raise

    except Exception as e:
        print(f"An error occurred: {e}")
        raise
