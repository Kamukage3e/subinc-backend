env "local" {
  src = [
    "file://internal/admin/user-management/migration/schema.pg.hcl", 
    "file://internal/admin/server-config/migration/schema.pg.hcl",
    "file://internal/admin/tenant-management/migration/schema.pg.hcl",
    "file://internal/admin/project-management/migration/schema.pg.hcl",
    "file://internal/admin/organization-management/migration/schema.pg.hcl",
    "file://internal/admin/rbac-management/migration/schema.pg.hcl",
    "file://internal/admin/security-management/migration/schema.pg.hcl",
    "file://internal/admin/billing-management/migration/schema.pg.hcl"
  ]
  url = "postgres://postgres:postgres@localhost:5432/subinc?sslmode=disable"
  dev-url = "docker://postgres/15/dev"
} 


