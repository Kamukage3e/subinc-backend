schema "public" {
  comment = "All organization management tables are multi-tenant, type-safe, and production-grade. No placeholders, no bloat, no non-prod content."
}

table "organizations" {
  schema      = schema.public
  column "id"         { type = uuid; null = false }
  column "name"       { type = varchar(128); null = false }
  column "slug"       { type = varchar(128); null = false }
  column "owner_id"   { type = uuid; null = false }
  column "status"     { type = varchar(32); null = false }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  unique { columns = [column.slug] }
  index { columns = [column.owner_id] }
}

table "org_settings" {
  schema      = schema.public
  column "org_id"    { type = uuid; null = false }
  column "settings"  { type = jsonb; null = false }
  column "updated_at"{ type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.org_id] }
  foreign_key { columns = [column.org_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
}

table "org_audit_log" {
  schema      = schema.public
  column "id"         { type = uuid; null = false }
  column "org_id"     { type = uuid; null = false }
  column "actor_id"   { type = uuid }
  column "action"     { type = varchar(64); null = false }
  column "target_id"  { type = uuid }
  column "details"    { type = jsonb }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  index { columns = [column.org_id] }
  index { columns = [column.actor_id] }
  comment = "Audit logs for all org actions. JSON details for extensibility."
}

# Indexes for performance and SaaS scale
create index if not exists idx_organizations_owner_id on organizations (owner_id); 