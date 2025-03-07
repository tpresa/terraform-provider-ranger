terraform {
  required_providers {
    ranger = {
      source  = "hashicorp/ranger"
      version = "0.0.1"
    }
  }
}

# Configuration for the Ranger provider
provider "ranger" {
  endpoint = "http://localhost:6080"  # Example endpoint (doesn't need to exist for init/plan with -var)
  username = "admin"
  password = var.ranger_password
}

# Define variables for sensitive information
variable "ranger_password" {
  description = "Password for Apache Ranger admin user"
  type        = string
  sensitive   = true
}

# Simple resource for testing
resource "ranger_policy" "test_policy" {
  name        = "test_policy"
  service     = "hdfs"
  description = "Test policy for validation"
  is_enabled  = true

  resources {
    type        = "path"
    values      = ["/data/test"]
    is_exclude  = false
    is_recursive = true
  }

  policy_item {
    users         = []
    groups        = ["test_group"]
    roles         = []
    permissions   = ["read", "write"]
    delegate_admin = false
  }
} 