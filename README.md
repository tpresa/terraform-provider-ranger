# Terraform Provider for Apache Ranger

This Terraform provider allows you to manage [Apache Ranger](https://ranger.apache.org/) resources through Terraform. Apache Ranger is a framework to enable, monitor, and manage comprehensive data security across the Hadoop platform.

## Features

- Manage Apache Ranger access policies via Terraform
- Create, update, and delete policies for various Ranger services (HDFS, Hive, etc.)
- Read existing policies using data sources
- Support for basic authentication with Ranger Admin REST API

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.19
- An Apache Ranger instance with Admin REST API accessible

## Building The Provider

1. Clone the repository
2. Enter the repository directory
3. Build the provider using `make build`

```shell
git clone https://github.com/example/terraform-provider-ranger
cd terraform-provider-ranger
make build
```

## Using the provider

To use the provider, include it in your Terraform configuration:

```hcl
terraform {
  required_providers {
    ranger = {
      source  = "hashicorp/ranger"
      version = "~> 1.0"
    }
  }
}

provider "ranger" {
  endpoint = "http://ranger.example.com:6080"
  username = "admin"
  password = var.ranger_password # using a variable for sensitive information
  insecure = false  # Set to true to disable TLS verification
}
```

### Example: Creating a Ranger policy for HDFS

```hcl
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
```

### Example: Reading an existing policy

```hcl
data "ranger_policy" "existing_policy" {
  service = "hive"
  name    = "existing_hive_database_policy"
}

output "policy_id" {
  value = data.ranger_policy.existing_policy.id
}
```

## Documentation

Full documentation is available in the [docs](./docs) directory.

## Development

If you wish to work on the provider, you'll need [Go](http://www.golang.org) installed on your machine (version 1.19+ recommended).

To compile the provider:

```shell
make build
```

To run the full suite of tests:

```shell
make test
```

## License

[MPL-2.0](LICENSE)
