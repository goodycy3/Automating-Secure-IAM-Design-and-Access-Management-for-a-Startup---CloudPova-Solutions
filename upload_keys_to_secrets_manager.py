import csv
import boto3
import json

# Initialize AWS Secrets Manager client with a specific profile and region
session = boto3.Session(profile_name="mini-acct-goody-terra", region_name="us-east-1")
secrets_manager_client = session.client("secretsmanager")

def upload_to_secrets_manager(secret_name, access_key_id, secret_access_key):
    """
    Uploads the access key and secret access key to Secrets Manager.
    If the secret exists, updates it. If it is marked for deletion, restores it.
    If the secret does not exist, creates a new one.
    """
    secret_string = json.dumps({
        "access_key_id": access_key_id,
        "secret_access_key": secret_access_key
    })

    try:
        # Check if the secret exists in Secrets Manager
        response = secrets_manager_client.describe_secret(SecretId=secret_name)

        # If the secret is marked for deletion, restore it
        if 'DeletedDate' in response:
            secrets_manager_client.restore_secret(SecretId=secret_name)
            print(f"Restored secret from deletion: {secret_name}")

        # Update the existing secret with new access keys
        secrets_manager_client.put_secret_value(
            SecretId=secret_name,
            SecretString=secret_string
        )
        print(f"Updated secret: {secret_name}")

    except secrets_manager_client.exceptions.ResourceNotFoundException:
        # Create a new secret if it doesn't exist
        secrets_manager_client.create_secret(
            Name=secret_name,
            SecretString=secret_string
        )
        print(f"Created new secret: {secret_name}")

    except Exception as e:
        print(f"An error occurred while processing secret {secret_name}: {e}")

def main():
    """
    Main function to process the access_keys.csv file and upload secrets to Secrets Manager.
    """
    try:
        # Open the CSV file
        with open('access_keys.csv', 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # Extract data from the CSV row
                username = row['username']
                access_key_id = row['access_key_id']
                secret_access_key = row['secret_access_key']

                # Construct the secret name (unique for each user)
                secret_name = f"Access-Keys-{username}"

                # Upload access keys to Secrets Manager
                upload_to_secrets_manager(secret_name, access_key_id, secret_access_key)

    except FileNotFoundError:
        print("Error: The file 'access_keys.csv' was not found.")
    except KeyError as e:
        print(f"Error: Missing required column in CSV file: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
