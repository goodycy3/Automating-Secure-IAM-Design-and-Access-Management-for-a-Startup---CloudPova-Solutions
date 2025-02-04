# This Python Script is used to Export access_keys for all IAM users from the file terraform_output.json
import json
import csv

try:
    # Load Terraform output
    with open('terraform_output.json', 'r') as f:
        data = json.load(f)

    # Validate that 'user_access_keys' exists in the JSON data
    if 'user_access_keys' not in data:
        raise KeyError("The key 'user_access_keys' was not found in the Terraform output.")

    # Access the user access keys
    user_access_keys = data['user_access_keys']['value']

    # Write the keys to a CSV file
    with open('access_keys.csv', 'w', newline='') as csvfile:
        fieldnames = ['username', 'access_key_id', 'secret_access_key']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for entry in user_access_keys:
            writer.writerow(entry)

    print("Access keys exported to access_keys.csv")

except (KeyError, json.JSONDecodeError) as e:
    print(f"Error processing the Terraform output: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
