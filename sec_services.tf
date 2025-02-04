# # AWS Caller Identity (Required for policies)
# data "aws_caller_identity" "current" {}

# ========= Access Analyzer =========
# IAM Access Analyzer automatically analyzes permissions for resources to detect 
# overly permissive policies and identifies potential security risks.
resource "aws_accessanalyzer_analyzer" "access_analyzer" {
  analyzer_name = "CloudPovaAccessAnalyzer" # Name of the Access Analyzer
  type          = "ACCOUNT"                 # Analyzes policies at the account level
}

# ========= AWS Secrets Manager =========
# Create a secret in AWS Secrets Manager to securely store sensitive information.
resource "aws_secretsmanager_secret" "CloudPova-Creds-Access" {
  name        = "Mini-Admin-secrets-CloudPova"                             # Unique name for the secret
  description = "An example secret for CloudPova Solutions" # Descriptive purpose of the secret
}

# Create a version of the secret containing the actual sensitive data (key-value pairs).
resource "aws_secretsmanager_secret_version" "Creds-secrets_version1" {
  secret_id = aws_secretsmanager_secret.CloudPova-Creds-Access.id # Links the version to the created secret
  secret_string = jsonencode({                                    # JSON-encoded sensitive data
    username = "admin",                                           # Example username
    password = "$as_!swo%d1@033/@"                                # Example password
  })
}




# ========= CloudTrail Logging =========
# Create a CloudTrail instance to monitor and log all API calls and events
resource "aws_cloudtrail" "cloudtrail" {
  name                          = "CloudPovaTrail"                       # Name of the CloudTrail instance
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.bucket # Reference the S3 bucket for log storage
  include_global_service_events = false                                  # Disable global service events
  is_multi_region_trail         = false                                  # Log events only in the current region
  enable_logging                = true                                   # Enable logging for this trail
}



# ========= Password Policy =========
# Create an account-level password policy
resource "aws_iam_account_password_policy" "password_policy" {
  minimum_password_length        = 12    # Set minimum password length
  require_symbols                = true  # Require at least one symbol (e.g., @, #, $)
  require_numbers                = true  # Require at least one numeric character
  require_uppercase_characters   = true  # Require at least one uppercase letter
  require_lowercase_characters   = true  # Require at least one lowercase letter
  allow_users_to_change_password = true  # Allow users to change their password
  hard_expiry                    = false # Do not immediately expire passwords upon policy change
  max_password_age               = 90    # Set maximum password age to 90 days
  password_reuse_prevention      = 5     # Prevent reuse of the last 5 passwords
}


# ========= GuardDuty =========
# Enable GuardDuty to monitor and detect malicious activities
# resource "aws_guardduty_detector" "CloudNovaTrail_guardduty" {
#   enable = true # Enable GuardDuty in the region specified in the provider block
# }

# ========= S3 Bucket for Storing GuardDuty Findings =========
resource "aws_s3_bucket" "guardduty_findings" {
  bucket        = "cloudpova-guardduty-findings"
  force_destroy = true

  tags = {
    Environment = "Production"
    Purpose     = "GuardDutyFindings"
  }
}

# S3 Bucket Policy to Allow GuardDuty Access
resource "aws_s3_bucket_policy" "guardduty_policy" {
  bucket = aws_s3_bucket.guardduty_findings.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AllowGetBucketLocation",
        Effect    = "Allow",
        Principal = { Service = "guardduty.amazonaws.com" },
        Action    = "s3:GetBucketLocation",
        Resource  = "${aws_s3_bucket.guardduty_findings.arn}",
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id,
            "aws:SourceArn"     = "arn:aws:guardduty:${var.region}:${data.aws_caller_identity.current.account_id}:detector/${aws_guardduty_detector.guardduty.id}"
          }
        }
      },
      {
        Sid       = "AllowPutObject",
        Effect    = "Allow",
        Principal = { Service = "guardduty.amazonaws.com" },
        Action    = "s3:PutObject",
        Resource  = "${aws_s3_bucket.guardduty_findings.arn}/*",
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id,
            "aws:SourceArn"     = "arn:aws:guardduty:${var.region}:${data.aws_caller_identity.current.account_id}:detector/${aws_guardduty_detector.guardduty.id}"
          }
        }
      },
      {
        Sid       = "DenyUnencryptedObjectUploads",
        Effect    = "Deny",
        Principal = { Service = "guardduty.amazonaws.com" },
        Action    = "s3:PutObject",
        Resource  = "${aws_s3_bucket.guardduty_findings.arn}/*",
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

# ========= GuardDuty Detector =========
resource "aws_guardduty_detector" "guardduty" {
  enable = true
}

# ========= GuardDuty Publishing Destination =========
resource "aws_guardduty_publishing_destination" "findings_destination" {
  detector_id     = aws_guardduty_detector.guardduty.id
  destination_arn = aws_s3_bucket.guardduty_findings.arn
  destination_type = "S3"
  kms_key_arn      = aws_kms_key.guardduty_kms.arn

  depends_on = [aws_s3_bucket_policy.guardduty_policy]
}

# ========= KMS Key for GuardDuty Findings =========
resource "aws_kms_key" "guardduty_kms" {
  description             = "KMS key for GuardDuty findings"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Environment = "Production"
    Purpose     = "GuardDutyEncryption"
  }
}

# KMS Key Policy for GuardDuty
resource "aws_kms_key_policy" "guardduty_kms_policy" {
  key_id = aws_kms_key.guardduty_kms.key_id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AllowGuardDutyAccess",
        Effect    = "Allow",
        Principal = { Service = "guardduty.amazonaws.com" },
        Action    = "kms:GenerateDataKey",
        Resource  = "${aws_kms_key.guardduty_kms.arn}",
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id,
            "aws:SourceArn"     = "arn:aws:guardduty:${var.region}:${data.aws_caller_identity.current.account_id}:detector/${aws_guardduty_detector.guardduty.id}"
          }
        }
      },
      {
        Sid       = "AllowRootAccess",
        Effect    = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action    = "kms:*",
        Resource  = "${aws_kms_key.guardduty_kms.arn}"
      },
      {
        Sid       = "AllowAllUsersToModifyKey",
        Effect    = "Allow",
        Action    = [
          "kms:*"
        ],
        Resource  = "arn:aws:kms:${var.region}:${data.aws_caller_identity.current.account_id}:key/*",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    ]
  })
}
