schema "public" {
  comment = "All organization management tables are multi-tenant, type-safe, and production-grade. No placeholders, no bloat, no non-prod content."
}

table "organizations" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "name" {
    type = varchar(128)
    null = false
  }
  column "slug" {
    type = varchar(128)
    null = false
  }
  column "owner_id" {
    type = uuid
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  column "updated_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.id]
  }
  unique "organizations_slug_key" {
    columns = [column.slug]
  }
  index "organizations_owner_id_idx" {
    columns = [column.owner_id]
  }
}

# All org settings are now runtime, DB-backed, and managed via server_config (key: org_settings_{orgID})

table "org_audit_log" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "org_id" {
    type = uuid
    null = false
  }
  column "actor_id" {
    type = uuid
  }
  column "action" {
    type = varchar(64)
    null = false
  }
  column "target_id" {
    type = uuid
  }
  column "details" {
    type = jsonb
  }
  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.id]
  }
  index "org_audit_log_org_id_idx" {
    columns = [column.org_id]
  }
  index "org_audit_log_actor_id_idx" {
    columns = [column.actor_id]
  }
  comment = "Audit logs for all org actions. JSON details for extensibility."
}

