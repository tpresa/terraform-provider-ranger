terraform {
  required_providers {
    ranger = {
      source  = "hashicorp/ranger"
      version = "0.0.1"
    }
  }
}

provider "ranger" {
  endpoint = "http://localhost:6080"
  username = "admin"
  password = "rangerR0cks!"
}

# Simple test policy resource
resource "ranger_policy" "test" {
  name        = "test_policy"
  service     = "dev_hdfs"
  description = "Test policy for verification"
  is_enabled  = true

  resources = [{
    type        = "path"
    values      = ["/test/data"]
    is_exclude  = false
    is_recursive = true
  }]

  policy_item = [{
    users         = []
    groups        = ["public"]
    permissions   = ["read", "write", "execute"]
    delegate_admin = false
  }]
}
