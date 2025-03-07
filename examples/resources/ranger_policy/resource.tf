# Example: Complex Apache Ranger policy for Hive service

resource "ranger_policy" "hive_sales_database" {
  name           = "sales_database_policy"
  service        = "hive"
  description    = "Policy controlling access to the sales database and tables"
  is_enabled     = true
  is_audit_enabled = true
  policy_type    = 0  # Access policy (0 is the default)

  # Resource definition for the database
  resources {
    type         = "database"
    values       = ["sales"]
    is_exclude   = false
    is_recursive = false
  }
  
  # Resource definition for tables
  resources {
    type         = "table"
    values       = ["transactions", "customers", "products"]
    is_exclude   = false
    is_recursive = false
  }
  
  # Resource definition for columns
  resources {
    type         = "column"
    values       = ["*"]  # All columns
    is_exclude   = false
    is_recursive = false
  }

  # Allow rule for data scientists (read-only access)
  policy_item {
    groups       = ["data_scientists"]
    users        = []
    roles        = []
    permissions  = ["SELECT"]
    delegate_admin = false
  }

  # Allow rule for sales analysts (more privileges)
  policy_item {
    groups       = ["sales_analysts"]
    users        = []
    roles        = []
    permissions  = ["SELECT", "UPDATE", "CREATE", "DROP", "ALTER", "INDEX", "LOCK"]
    delegate_admin = false
  }

  # Allow rule for specific admin users (full access)
  policy_item {
    groups       = []
    users        = ["admin1", "admin2"]
    roles        = []
    permissions  = ["SELECT", "UPDATE", "CREATE", "DROP", "ALTER", "INDEX", "LOCK", "ALL"]
    delegate_admin = true  # Can delegate these permissions
  }

  # Deny rule for temporary contractors
  deny_item {
    groups       = ["temp_contractors"]
    users        = []
    roles        = []
    permissions  = ["DROP", "ALTER"]  # Prevent schema modifications
    delegate_admin = false
  }

  # Example with time-based condition (if supported by your Ranger installation)
  policy_item {
    groups       = ["weekend_batch_jobs"]
    users        = []
    roles        = []
    permissions  = ["SELECT", "UPDATE", "CREATE"]
    delegate_admin = false
    conditions   = {
      "time" = ["weekends"]  # If your Ranger supports time-based conditions
    }
  }
}

# Example: Policy with row-level filtering (if supported)
resource "ranger_policy" "hive_filtered_sales" {
  name           = "filtered_sales_data_policy"
  service        = "hive"
  description    = "Row-filtered access to sales data by region"
  is_enabled     = true
  policy_type    = 2  # Row-filter policy type

  # Resource for row-filtered table
  resources {
    type         = "database"
    values       = ["sales"]
    is_exclude   = false
    is_recursive = false
  }
  
  resources {
    type         = "table"
    values       = ["regional_sales"]
    is_exclude   = false
    is_recursive = false
  }

  # Grant rule with row filter (specifics depend on your Ranger version)
  policy_item {
    groups       = ["north_region_users"]
    users        = []
    roles        = []
    permissions  = ["SELECT"]
    delegate_admin = false
    # Conditions would be used to define the row filter in a real implementation
  }
} 