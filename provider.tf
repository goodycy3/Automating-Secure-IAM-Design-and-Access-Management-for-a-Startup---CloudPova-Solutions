# Provider configuration for AWS
provider "aws" {
  region  = var.region # Update this to your preferred region
  profile = "goody-terra" # Update with your AWS CLI Configured.
}
