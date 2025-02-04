# Outputs for IAM resources

output "user_list" {
  description = "List of IAM users created"
  value       = [for user in aws_iam_user.users : user.name]
}

output "access_analyzer_name" {
  description = "Access Analyzer created for the account"
  value       = aws_accessanalyzer_analyzer.access_analyzer.id
}


# Output access keys in a format suitable for CSV export
output "user_access_keys" {
  description = "Access keys for programmatic access"
  value = [
    for user, details in aws_iam_access_key.user_access_keys :
    {
      username          = user,
      access_key_id     = details.id,
      secret_access_key = details.secret
    }
  ]
  sensitive = true # Mark this output as sensitive to prevent accidental exposure
}

# Output Initial Console Passwords
output "initial_console_passwords" {
  description = "Initial console passwords for IAM users"
  value = { for user, profile in aws_iam_user_login_profile.console_password :
    user => profile.password }
  sensitive = true # Mark as sensitive to hide from logs and accidental exposure
}