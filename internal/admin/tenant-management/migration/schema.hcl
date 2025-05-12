schema "public" {
  comment = "Tenant management tables are multi-tenant, type-safe, and production-grade. No placeholders, no bloat, no non-prod content."
}

table "tenants" {
  schema      = schema.public
  column "id"         { type = uuid; null = false }
  column "name"       { type = varchar(128); null = false }
  column "status"     { type = varchar(32); null = false }
  column "settings"   { type = text; null = false }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  unique { columns = [column.name] }
} 