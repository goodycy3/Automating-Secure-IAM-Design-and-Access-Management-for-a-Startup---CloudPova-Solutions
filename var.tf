# Define a variable for IAM users
variable "iam_users" {
  default = {
    "John_Doe"      = { group = "AdminGroup", create_access_key = true, console_password = true }
    "Jane_Smith"    = { group = "DevelopersGroup", create_access_key = true, console_password = true }
    "Mark_Taylor"   = { group = "DevelopersGroup", create_access_key = true, console_password = true }
    "Sarah_Johnson" = { group = "DevelopersGroup", create_access_key = true, console_password = true }
    "Emily_White"   = { group = "FinanceGroup", create_access_key = false, console_password = true }
  }
}

variable "region" {
  default = "us-east-1"
}

resource "random_id" "suffix" {
  byte_length = 4
}