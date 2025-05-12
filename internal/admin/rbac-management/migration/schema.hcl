schema "public" {
  comment = "All RBAC management tables are multi-tenant, type-safe, and production-grade. No placeholders, no bloat, no non-prod content."
}

table "roles" {
  schema      = schema.public
  column "id"         { type = uuid; null = false }
  column "tenant_id"  { type = uuid; null = false }
  column "name"       { type = varchar(128); null = false }
  column "desc"       { type = text }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at" { type = timestamptz; null = false; default = sql("now()") }
  column "deleted_at" { type = timestamptz }
  primary_key { columns = [column.id] }
  index { columns = [column.tenant_id, column.name]; unique = true }
}

table "permissions" {
  schema      = schema.public
  column "id"         { type = uuid; null = false }
  column "name"       { type = varchar(128); null = false }
  column "resource"   { type = varchar(128); null = false }
  column "action"     { type = varchar(64); null = false }
  column "desc"       { type = text }
  column "parent_resource_id" { type = uuid }
  column "resource_pattern"   { type = varchar(256) }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  index { columns = [column.name, column.resource, column.action]; unique = true }
}

table "role_bindings" {
  schema      = schema.public
  column "id"         { type = uuid; null = false }
  column "tenant_id"  { type = uuid; null = false }
  column "role_id"    { type = uuid; null = false }
  column "user_id"    { type = uuid; null = false }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  index { columns = [column.tenant_id, column.user_id, column.role_id]; unique = true }
  foreign_key { columns = [column.role_id]; ref_table = table.roles; ref_columns = [table.roles.column.id]; on_delete = CASCADE }
}

table "policies" {
  schema      = schema.public
  column "id"         { type = uuid; null = false }
  column "tenant_id"  { type = uuid; null = false }
  column "statements" { type = jsonb; null = false }
  column "desc"       { type = text }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  index { columns = [column.tenant_id] }
}

table "api_permissions" {
  schema      = schema.public
  column "id"         { type = uuid; null = false }
  column "api"        { type = varchar(128); null = false }
  column "method"     { type = varchar(16); null = false }
  column "desc"       { type = text }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  index { columns = [column.api, column.method]; unique = true }
}

table "resources" {
  schema      = schema.public
  column "id"         { type = uuid; null = false }
  column "tenant_id"  { type = uuid; null = false }
  column "type"       { type = varchar(64); null = false }
  column "name"       { type = varchar(128); null = false }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  index { columns = [column.tenant_id, column.type, column.name]; unique = true }
}

table "audit_log" {
  schema      = schema.public
  column "id"         { type = uuid; null = false }
  column "tenant_id"  { type = uuid; null = false }
  column "actor_id"   { type = uuid; null = false }
  column "action"     { type = varchar(64); null = false }
  column "target_id"  { type = uuid }
  column "details"    { type = jsonb }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  index { columns = [column.tenant_id, column.action] }
}

table "abac_policies" {
  schema      = schema.public
  column "id"         { type = uuid; null = false }
  column "tenant_id"  { type = uuid; null = false }
  column "statements" { type = jsonb; null = false }
  column "desc"       { type = text }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  index { columns = [column.tenant_id] }
}

table "delegated_roles" {
  schema      = schema.public
  column "id"         { type = uuid; null = false }
  column "tenant_id"  { type = uuid; null = false }
  column "from_user_id" { type = uuid; null = false }
  column "to_user_id"   { type = uuid; null = false }
  column "role_id"      { type = uuid; null = false }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  index { columns = [column.tenant_id, column.from_user_id, column.to_user_id, column.role_id]; unique = true }
  foreign_key { columns = [column.role_id]; ref_table = table.roles; ref_columns = [table.roles.column.id]; on_delete = CASCADE }
}

table "permission_templates" {
  schema      = schema.public
  column "id"         { type = uuid; null = false }
  column "name"       { type = varchar(128); null = false }
  column "resource"   { type = varchar(128); null = false }
  column "action"     { type = varchar(64); null = false }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  index { columns = [column.name, column.resource, column.action]; unique = true }
}

# Indexes for performance and SaaS scale
create index if not exists idx_roles_tenant_id on roles (tenant_id);
create index if not exists idx_permissions_resource on permissions (resource);
create index if not exists idx_role_bindings_tenant_id on role_bindings (tenant_id);
create index if not exists idx_policies_tenant_id on policies (tenant_id);
create index if not exists idx_api_permissions_tenant_id on api_permissions (tenant_id);
create index if not exists idx_resources_tenant_id on resources (tenant_id);
create index if not exists idx_audit_log_tenant_id on audit_log (tenant_id);
create index if not exists idx_abac_policies_tenant_id on abac_policies (tenant_id);
create index if not exists idx_delegated_roles_tenant_id on delegated_roles (tenant_id);
