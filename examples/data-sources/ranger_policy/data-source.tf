# Example: Reading Apache Ranger policies using data sources

# Read a policy by service and name (most common approach)
data "ranger_policy" "hdfs_policy" {
  service = "hdfs"
  name    = "finance_reports_access"
}

# Read a policy directly by ID (if you know it)
data "ranger_policy" "hive_policy_by_id" {
  id = "42"  # The numeric ID of the policy in Ranger
}

# Example outputs to demonstrate accessing policy information
output "hdfs_policy_details" {
  description = "Details about the HDFS policy"
  value = {
    id             = data.ranger_policy.hdfs_policy.id
    name           = data.ranger_policy.hdfs_policy.name
    description    = data.ranger_policy.hdfs_policy.description
    is_enabled     = data.ranger_policy.hdfs_policy.is_enabled
    is_audit_enabled = data.ranger_policy.hdfs_policy.is_audit_enabled
    policy_type    = data.ranger_policy.hdfs_policy.policy_type
  }
}

# Example of getting users with access from the first policy item
output "users_with_access" {
  description = "Users who have access in the first policy item"
  value       = data.ranger_policy.hdfs_policy.policy_item[0].users
}

# Example of getting groups with access from the first policy item
output "groups_with_access" {
  description = "Groups who have access in the first policy item"
  value       = data.ranger_policy.hdfs_policy.policy_item[0].groups
}

# Example of getting permissions from the first policy item
output "allowed_permissions" {
  description = "Permissions allowed in the first policy item"
  value       = data.ranger_policy.hdfs_policy.policy_item[0].permissions
}

# Example of converting resources to a more friendly format
output "protected_resources" {
  description = "Resources protected by this policy"
  value = [
    for resource in data.ranger_policy.hdfs_policy.resources : {
      type = resource.type
      paths = resource.values
      recursive = resource.is_recursive
    }
  ]
}

# Using policy data for conditional logic in your Terraform configuration
locals {
  has_deny_rules = length(data.ranger_policy.hdfs_policy.deny_item) > 0
}

output "policy_has_deny_rules" {
  value = local.has_deny_rules
} 