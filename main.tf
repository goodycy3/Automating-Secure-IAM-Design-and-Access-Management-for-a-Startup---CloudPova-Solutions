# Main Terraform configuration file for IAM setup

# ========= IAM Groups and Policies =========
# Create Admin Group and Attach Full Access Policy
resource "aws_iam_group" "admin_group" {
  name = "AdminGroup"
}

resource "aws_iam_group_policy_attachment" "admin_attach" {
  group      = aws_iam_group.admin_group.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Create Developers Group
resource "aws_iam_group" "developers_group" {
  name = "DevelopersGroup"
}

# Create Custom Policy for Developers Group
resource "aws_iam_policy" "developers_policy" {
  name        = "DevelopersPolicy"
  description = "Policy for Developers Group with permissions for development resources"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Allow full EC2 access for resources tagged with Environment=Dev
      {
        Effect   = "Allow",
        Action   = "ec2:*",
        Resource = "arn:aws:ec2:*:*:instance/*",
        Condition = {
          StringEquals = {
            "aws:RequestTag/Environment" : "Dev"
          }
        }
      },
      # Allow full S3 bucket access for buckets tagged with Environment=Dev
      {
        Effect = "Allow",
        Action = ["s3:ListBucket", "s3:GetObject", "s3:PutObject"],
        Resource = [
          "arn:aws:s3:::*",
          "arn:aws:s3:::*/*"
        ],
        Condition = {
          StringEquals = {
            "s3:RequestObjectTag/Environment" : "Dev"
          }
        }
      },
      # Permissions for AWS CodeCommit
      {
        Effect = "Allow",
        Action = [
          "codecommit:CreateRepository",
          "codecommit:BatchGetRepositories",
          "codecommit:GetRepository",
          "codecommit:GitPull",
          "codecommit:GitPush"
        ],
        Resource = "arn:aws:codecommit:*:*:*"
      },
      # Permissions for AWS CodePipeline
      {
        Effect = "Allow",
        Action = [
          "codepipeline:StartPipelineExecution",
          "codepipeline:GetPipelineState",
          "codepipeline:ListPipelines",
          "codepipeline:GetPipeline"
        ],
        Resource = "*"
      },
      # Permissions for AWS Elastic Beanstalk
      {
        Effect = "Allow",
        Action = [
          "elasticbeanstalk:CreateApplication",
          "elasticbeanstalk:CreateEnvironment",
          "elasticbeanstalk:DescribeEnvironments",
          "elasticbeanstalk:TerminateEnvironment",
          "elasticbeanstalk:UpdateEnvironment",
          "elasticbeanstalk:ListAvailableSolutionStacks"
        ],
        Resource = "*"
      },
      # Permissions to view CloudWatch logs for debugging
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
          "logs:GetLogEvents"
        ],
        Resource = "*"
      },
      # Allow read-only access to RDS for database insights
      {
        Effect = "Allow",
        Action = [
          "rds:DescribeDBInstances",
          "rds:DescribeDBClusters",
          "rds:ListTagsForResource"
        ],
        Resource = "*"
      }
    ]
  })
}

# Attach Custom Policy to Developers Group
resource "aws_iam_group_policy_attachment" "developers_attach" {
  group      = aws_iam_group.developers_group.name
  policy_arn = aws_iam_policy.developers_policy.arn
}


# Create Finance Group and Attach Read-Only Policy for AWS Cost Management

# Create an IAM Group for Finance Users
resource "aws_iam_group" "finance_group" {
  name = "FinanceGroup" # The group name is 'FinanceGroup', intended for finance-related users
}

# Define a Custom Policy for Read-Only Access to AWS Cost Explorer and Billing
resource "aws_iam_policy" "finance_policy" {
  name        = "FinancePolicy"            # The policy name is 'FinancePolicy'
  description = "Policy for Finance Group" # Description for clarity on policy usage
  policy = jsonencode({
    Version = "2012-10-17", # IAM policy version, always use the latest version
    Statement = [
      {
        Effect = "Allow", # Allows actions specified in the 'Action' field
        Action = [
          "ce:Get*",     # Grants permission to retrieve Cost Explorer data
          "ce:Describe*" # Grants permission to describe billing-related resources
        ],
        Resource = "*" # Grants access to all Cost Explorer resources
      }
    ]
  })
}

# Attach the Finance Policy to the Finance Group
resource "aws_iam_group_policy_attachment" "finance_attach" {
  group      = aws_iam_group.finance_group.name  # Specifies the Finance Group to attach the policy to
  policy_arn = aws_iam_policy.finance_policy.arn # Links the ARN of the custom Finance Policy
}


# ========= IAM Users =========
# Create Users and Assign to Groups
# Create IAM users dynamically
resource "aws_iam_user" "users" {
  for_each      = var.iam_users # Iterate over the map of users defined in the variable
  name          = each.key      # Assign the user name based on the map key
  force_destroy = true          # Automatically delete associated resources when the user is destroyed (e.g., access keys)
}

# Create programmatic access keys only for users where create_access_key is true
resource "aws_iam_access_key" "user_access_keys" {
  for_each = { for k, v in var.iam_users : k => v if v.create_access_key }
  user     = aws_iam_user.users[each.key].name
}

# Create console passwords for all users with console_password = true
resource "aws_iam_user_login_profile" "console_password" {
  for_each           = { for k, v in var.iam_users : k => v if v.console_password }
  user               = aws_iam_user.users[each.key].name
  password_length    = 16
  password_reset_required = true
}



# Attach IAMUserChangePassword Policy
resource "aws_iam_user_policy_attachment" "change_password_policy" {
  for_each   = aws_iam_user.users
  user       = aws_iam_user.users[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/IAMUserChangePassword" # AWS Managed Policy for password change
}



# Assign users to IAM groups
resource "aws_iam_user_group_membership" "user_groups" {
  for_each = var.iam_users                     # Iterate over the same user map
  user     = aws_iam_user.users[each.key].name # Reference the created user
  groups   = [each.value.group]                # Assign the user to the group defined in the map
}


# ========= MFA Enforcement =========
# Policy to Deny Actions if MFA is Not Enabled
resource "aws_iam_policy" "mfa_policy" {
  name        = "EnforceMFA"
  description = "Policy to enforce MFA"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Deny",
        Action   = "*",
        Resource = "*",
        Condition = {
          BoolIfExists = { "aws:MultiFactorAuthPresent" : "false" }
        }
      }
    ]
  })
}

# Attaches the MFA enforcement policy (mfa_policy) to each IAM user defined in the aws_iam_user.users map.
resource "aws_iam_user_policy_attachment" "mfa_attach" {
  for_each   = aws_iam_user.users
  user       = each.value.name
  policy_arn = aws_iam_policy.mfa_policy.arn
}

/** 
for_each: Iterates over the map of IAM users created earlier.
user: Specifies the name of the IAM user to attach the policy to.
policy_arn: References the ARN of the MFA enforcement policy (mfa_policy).
**/





# ========= S3 Bucket for CloudTrail Logs =========
# Create an S3 bucket to store CloudTrail logs securely
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "cloudnova-cloudtrail-logs" # Name of the S3 bucket for CloudTrail logs
  force_destroy = true                     # Ensures the bucket and its contents are deleted
}

# Add a bucket policy to allow CloudTrail to write logs to the bucket
resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id # Attach the policy to the CloudTrail bucket

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Statement 1: Allow CloudTrail to write logs to the bucket
      {
        Sid    = "AllowCloudTrailWrite", # Unique ID for this policy statement
        Effect = "Allow",                # Grant permission
        Principal = {
          Service = "cloudtrail.amazonaws.com" # CloudTrail service needs this access
        },
        Action   = "s3:PutObject",                             # Permission to write objects to the bucket
        Resource = "${aws_s3_bucket.cloudtrail_bucket.arn}/*", # Target all objects in the bucket
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control" # Ensure the bucket owner has full control
          }
        }
      },
      # Statement 2: Allow CloudTrail to get the bucket's ACL
      {
        Sid    = "AllowBucketAccess", # Unique ID for this policy statement
        Effect = "Allow",             # Grant permission
        Principal = {
          Service = "cloudtrail.amazonaws.com" # CloudTrail service needs this access
        },
        Action   = "s3:GetBucketAcl",                  # Permission to read the bucket's ACL
        Resource = aws_s3_bucket.cloudtrail_bucket.arn # Target the bucket itself
      }
    ]
  })
}


