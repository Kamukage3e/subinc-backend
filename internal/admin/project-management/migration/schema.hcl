schema "public" {
  comment = "All project management tables are multi-tenant, type-safe, and production-grade. No placeholders, no bloat, no non-prod content."
}

table "projects" {
  schema      = schema.public
  column "id"          { type = uuid; null = false }
  column "org_id"      { type = uuid; null = false }
  column "name"        { type = varchar(128); null = false }
  column "description" { type = text }
  column "status"      { type = varchar(32); null = false }
  column "tags"        { type = jsonb }
  column "created_at"  { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at"  { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  index { columns = [column.org_id] }
  index { columns = [column.name] }
}

// All project settings are now runtime, DB-backed, and managed via server_config (key: project_settings_{projectID})

table "project_audit_log" {
  schema      = schema.public
  column "id"         { type = uuid; null = false }
  column "project_id" { type = uuid; null = false }
  column "actor_id"   { type = uuid }
  column "action"     { type = varchar(64); null = false }
  column "target_id"  { type = uuid }
  column "details"    { type = jsonb }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  index { columns = [column.project_id] }
  index { columns = [column.actor_id] }
  comment = "Audit logs for all project actions. JSON details for extensibility."
}

# Indexes for performance and SaaS scale
create index if not exists idx_projects_org_id on projects (org_id);
create index if not exists idx_projects_name on projects (name); 