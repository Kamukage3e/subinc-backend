// Define the database provider
env "local" {
  src = "postgres://postgres:postgres@localhost:5432/billing_system?sslmode=disable"
  
  // Use shadow database for comparison-driven migrations
  dev = "postgres://postgres:postgres@localhost:5432/billing_system_shadow?sslmode=disable"
  
  // Migration directory
  migration {
    dir = "file://migrations"
    format = atlas
  }
  
  // Format for SQL generation
  format {
    migrate {
      diff = "{{ sql . \"  \" }}"
    }
  }
}

// Set the global variable
variable "migration_dir" {
  type = string
  default = "migrations"
}

// Define the PostgreSQL dialect version
data "external_schema" "pg" {
  program = [
    "sh", "-c",
    "echo '{\"name\": \"pg\", \"schema\": {\"charset\": \"utf8mb4\", \"collate\": \"utf8mb4_general_ci\", \"tables\": []}}'"
  ]
} 