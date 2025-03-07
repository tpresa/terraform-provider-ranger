# Example configuration for the Apache Ranger provider

# Configuration for the Ranger provider
provider "ranger" {
  endpoint = "http://ranger.example.com:6080"  # Ranger Admin REST API URL
  username = "admin"                           # Ranger admin username
  password = var.ranger_password               # Using variable for sensitive value
  insecure = false                             # Set to true to skip TLS verification
}

# Define variables for sensitive information
variable "ranger_password" {
  description = "Password for Apache Ranger admin user"
  type        = string
  sensitive   = true
}

# Create a Ranger policy to allow access to HDFS path
resource "ranger_policy" "hdfs_finance_reports" {
  name        = "finance_reports_access"
  service     = "hdfs"
  description = "Policy to allow access to finance reports directory"
  is_enabled  = true

  # Define resource scope: finance reports directory
  resources {
    type        = "path"
    values      = ["/data/finance/reports"]
    is_exclude  = false
    is_recursive = true  # Apply to subdirectories
  }

  # Allow rule for finance team
  policy_item {
    users         = []
    groups        = ["finance", "finance_analysts"]
    roles         = []
    permissions   = ["read", "write", "execute"]
    delegate_admin = false
  }

  # Allow rule for auditors (read-only)
  policy_item {
    users         = []
    groups        = ["auditors"]
    roles         = []
    permissions   = ["read", "execute"]
    delegate_admin = false
  }
}

# Example of using the data source to reference an existing policy
data "ranger_policy" "existing_hive_policy" {
  service = "hive"
  name    = "existing_hive_database_policy"
}

# Output policy details
output "hive_policy_id" {
  value = data.ranger_policy.existing_hive_policy.id
}

output "hive_policy_resources" {
  value = data.ranger_policy.existing_hive_policy.resources
}
