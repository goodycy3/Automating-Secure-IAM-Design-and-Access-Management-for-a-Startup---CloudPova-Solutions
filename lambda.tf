# Fetch the AWS account ID of the current caller
data "aws_caller_identity" "current" {}

# ================= IAM Role for Lambda Function =================
# IAM Role that allows the Lambda function to assume a role
resource "aws_iam_role" "access_key_rotation_role" {
  name = "IAMAccessKeyRotationRole"

  # Define the trust policy for Lambda
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com" # Lambda service assumes this role
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# ================= IAM Policy for Access Key Rotation =================
# Attach policy to the IAM role for the Lambda function
resource "aws_iam_role_policy" "access_key_rotation_policy" {
  name       = "AccessKeyRotationPolicy"
  role       = aws_iam_role.access_key_rotation_role.name
  depends_on = [aws_iam_role.access_key_rotation_role] # Ensure role is created before policy is attached

  # Define permissions for the Lambda function
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        # Permissions to manage IAM access keys
        Effect   = "Allow",
        Action   = [
          "iam:GetUser",
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey",
          "iam:ListAccessKeys"
        ],
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*" # Use dynamic account ID
      },
      {
        # Permissions to interact with Secrets Manager
        Effect   = "Allow",
        Action   = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecretVersionStage"
        ],
        Resource = "arn:aws:secretsmanager:${var.region}:${data.aws_caller_identity.current.account_id}:secret:Access-Keys-*"
      },
      {
        # Permissions to write logs to CloudWatch
        Effect   = "Allow",
        Action   = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "*"
      }
    ]
  })
}

# ================= Lambda Function =================
# Create the Lambda function to handle access key rotation
resource "aws_lambda_function" "rotate_access_keys" {
  function_name    = "RotateAccessKeysFunction"
  runtime          = "python3.9"                           # Lambda runtime version
  role             = aws_iam_role.access_key_rotation_role.arn # Use the IAM role ARN
  handler          = "rotate_access_keys.lambda_handler"   # Entry point in the Python script
  filename         = "rotate_access_keys.zip"              # Path to the ZIP file containing the Lambda function code
  source_code_hash = filebase64sha256("rotate_access_keys.zip") # To track code changes and trigger updates
}

# ================= Secrets Manager =================
# Define a secret in Secrets Manager for each IAM user's access keys
resource "aws_secretsmanager_secret" "access_keys" {
  for_each = tomap({
    Mark_Taylor    = "Access-Keys-Mark_Taylor"
    Jane_Smith     = "Access-Keys-Jane_Smith"
    Sarah_Johnson  = "Access-Keys-Sarah_Johnson"
    John_Doe       = "Access-Keys-John_Doe"
  })
  name        = each.value
  description = "Access keys for IAM user ${each.key}"
}

# Configure automatic rotation for each secret
resource "aws_secretsmanager_secret_rotation" "access_key_rotation" {
  for_each          = aws_secretsmanager_secret.access_keys
  secret_id          = each.value.id
  rotation_lambda_arn = aws_lambda_function.rotate_access_keys.arn
  rotation_rules {
    automatically_after_days = 30  # Rotate every 30 days
  }
}






# ================= Lambda Permissions =================
# Allow Secrets Manager to invoke the Lambda function
resource "aws_lambda_permission" "allow_secrets_manager" {
  statement_id  = "AllowSecretsManagerInvocation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotate_access_keys.function_name # Lambda function name
  principal     = "secretsmanager.amazonaws.com"                      # Secrets Manager service principal
}
