schema "public" {
  comment = "All user management tables are multi-tenant, type-safe, and production-grade. No placeholders, no bloat, no non-prod content."
}

table "users" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "email" {
    type = varchar(256)
    null = false
  }
  column "password" {
    type = varchar(256)
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
  unique "users_email_key" {
    columns = [column.email]
  }
}

table "user_profiles" {
  schema = schema.public
  column "user_id" {
    type = uuid
    null = false
  }
  column "full_name" {
    type = varchar(128)
  }
  column "avatar_url" {
    type = varchar(512)
  }
  column "bio" {
    type = text
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
    columns = [column.user_id]
  }
  foreign_key "user_profiles_user_id_fkey" {
    columns     = [column.user_id]
    ref_columns = [table.users.column.id]
    on_delete   = CASCADE
  }
}

# All user settings are now runtime, DB-backed, and managed via server_config (key: user_settings_{userID})

table "user_sessions" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "user_id" {
    type = uuid
    null = false
  }
  column "ip" {
    type = varchar(64)
  }
  column "user_agent" {
    type = varchar(256)
  }
  column "expires_at" {
    type = timestamptz
    null = false
  }
  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.id]
  }
  foreign_key "user_sessions_user_id_fkey" {
    columns     = [column.user_id]
    ref_columns = [table.users.column.id]
    on_delete   = CASCADE
  }
  index "user_sessions_user_id_idx" {
    columns = [column.user_id]
  }
}

table "user_audit_log" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "user_id" {
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
    type = text
  }
  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.id]
  }
  index "user_audit_log_user_id_idx" {
    columns = [column.user_id]
  }
  index "user_audit_log_actor_id_idx" {
    columns = [column.actor_id]
  }
}

table "org_members" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "org_id" {
    type = uuid
    null = false
  }
  column "user_id" {
    type = uuid
    null = false
  }
  column "role" {
    type = varchar(64)
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "invited_by" {
    type = uuid
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
  unique "org_members_org_id_user_id_key" {
    columns = [column.org_id, column.user_id]
  }
  index "org_members_org_id_idx" {
    columns = [column.org_id]
  }
  index "org_members_user_id_idx" {
    columns = [column.user_id]
  }
}

table "org_invites" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "org_id" {
    type = uuid
    null = false
  }
  column "email" {
    type = varchar(256)
    null = false
  }
  column "role" {
    type = varchar(64)
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "token" {
    type = varchar(128)
    null = false
  }
  column "expires_at" {
    type = timestamptz
    null = false
  }
  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.id]
  }
  unique "org_invites_org_id_email_key" {
    columns = [column.org_id, column.email]
  }
  index "org_invites_org_id_idx" {
    columns = [column.org_id]
  }
  index "org_invites_email_idx" {
    columns = [column.email]
  }
}

table "project_members" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "project_id" {
    type = uuid
    null = false
  }
  column "user_id" {
    type = uuid
    null = false
  }
  column "role" {
    type = varchar(64)
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "invited_by" {
    type = uuid
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
  unique "project_members_project_id_user_id_key" {
    columns = [column.project_id, column.user_id]
  }
  index "project_members_project_id_idx" {
    columns = [column.project_id]
  }
  index "project_members_user_id_idx" {
    columns = [column.user_id]
  }
}

table "project_invites" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "project_id" {
    type = uuid
    null = false
  }
  column "email" {
    type = varchar(256)
    null = false
  }
  column "role" {
    type = varchar(64)
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "token" {
    type = varchar(128)
    null = false
  }
  column "expires_at" {
    type = timestamptz
    null = false
  }
  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.id]
  }
  unique "project_invites_project_id_email_key" {
    columns = [column.project_id, column.email]
  }
  index "project_invites_project_id_idx" {
    columns = [column.project_id]
  }
  index "project_invites_email_idx" {
    columns = [column.email]
  }
} 