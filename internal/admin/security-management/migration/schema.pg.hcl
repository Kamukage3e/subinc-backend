// NOTE: All runtime configuration, secrets, and feature flags for security-management are managed via the server_config table/service (DB-backed, hot-reloadable, multi-tenant). No direct DB columns or static config files are used for runtime config. All config endpoints read/write via server_config using key patterns (e.g., security_mfa_{tenantID}, provider_config_{channel}_{provider}_{tenantID}, etc.).
//
// Deprecated: notification_configs, provider_configs, and any other config tables/columns. Remove if present.
//
// See OpenAPI doc for config key patterns and schemas.

schema "public" {
  comment = "Security management tables for SaaS. All tables are multi-tenant, type-safe, and production-grade."
}

table "security_events" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "user_id" {
    type = uuid
    null = false
  }
  column "event_type" {
    type = varchar(64)
    null = false
  }
  column "details" {
    type = text
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
  index "security_events_user_id_idx" {
    columns = [column.user_id]
  }
}

table "login_history" {
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
    null = false
  }
  column "device" {
    type = varchar(128)
    null = false
  }
  column "location" {
    type = varchar(128)
    null = false
  }
  column "success" {
    type = boolean
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
  index "login_history_user_id_idx" {
    columns = [column.user_id]
  }
}

table "sessions" {
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
    null = false
  }
  column "device" {
    type = varchar(128)
    null = false
  }
  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  column "expires_at" {
    type = timestamptz
    null = false
  }
  primary_key {
    columns = [column.id]
  }
  index "sessions_user_id_idx" {
    columns = [column.user_id]
  }
}

table "security_audit_logs" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "actor_id" {
    type = uuid
    null = false
  }
  column "action" {
    type = varchar(64)
    null = false
  }
  column "target_id" {
    type = uuid
    null = false
  }
  column "details" {
    type = text
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
  index "security_audit_logs_actor_id_idx" {
    columns = [column.actor_id]
  }
  index "security_audit_logs_target_id_idx" {
    columns = [column.target_id]
  }
}

table "api_keys" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "user_id" {
    type = uuid
    null = false
  }
  column "name" {
    type = varchar(128)
    null = false
  }
  column "key" {
    type = varchar(256)
    null = false
  }
  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  column "revoked_at" {
    type = timestamptz
  }
  primary_key {
    columns = [column.id]
  }
  index "api_keys_user_id_idx" {
    columns = [column.user_id]
  }
}

table "devices" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "user_id" {
    type = uuid
    null = false
  }
  column "trusted" {
    type    = boolean
    null    = false
    default = false
  }
  column "type" {
    type = varchar(64)
    null = false
  }
  column "name" {
    type = varchar(128)
    null = false
  }
  column "ip" {
    type = varchar(64)
    null = false
  }
  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  column "revoked_at" {
    type = timestamptz
  }
  primary_key {
    columns = [column.id]
  }
  index "devices_user_id_idx" {
    columns = [column.user_id]
  }
}

table "breaches" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "type" {
    type = varchar(64)
    null = false
  }
  column "details" {
    type = text
    null = false
  }
  column "detected_at" {
    type = timestamptz
    null = false
  }
  primary_key {
    columns = [column.id]
  }
}

table "security_policies" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "name" {
    type = varchar(128)
    null = false
  }
  column "rules" {
    type = text
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
}

table "security_event_webhooks" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "url" {
    type = varchar(256)
    null = false
  }
  column "event_types" {
    type = text
    null = false
  }
  column "secret" {
    type = varchar(128)
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
  index "security_event_webhooks_tenant_id_idx" {
    columns = [column.tenant_id]
  }
}

table "password_reset_tokens" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "user_id" {
    type = uuid
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
  column "used" {
    type    = boolean
    null    = false
    default = false
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
  index "password_reset_tokens_user_id_idx" {
    columns = [column.user_id]
  }
}

table "rate_limit_configs" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "scope" {
    type = varchar(32)
    null = false
  }
  column "scope_id" {
    type = uuid
    null = false
  }
  column "limit" {
    type = integer
    null = false
  }
  column "window_seconds" {
    type = integer
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
  index "rate_limit_configs_scope_scope_id_idx" {
    columns = [column.scope, column.scope_id]
  }
}

table "security_analytics" {
  schema = schema.public
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "risk_score" {
    type = double_precision
    null = false
  }
  column "posture" {
    type = varchar(64)
    null = false
  }
  column "anomalies" {
    type = text
    null = false
  }
  column "generated_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.tenant_id, column.generated_at]
  }
}

table "anomalies" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "type" {
    type = varchar(64)
    null = false
  }
  column "details" {
    type = text
    null = false
  }
  column "detected_at" {
    type = timestamptz
    null = false
  }
  primary_key {
    columns = [column.id]
  }
}

table "invites" {
  schema = schema.public
  column "id" {
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
  column "token" {
    type = varchar(128)
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
  index "invites_email_idx" {
    columns = [column.email]
  }
}

table "consents" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "user_id" {
    type = uuid
    null = false
  }
  column "consent" {
    type = varchar(128)
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
  index "consents_user_id_idx" {
    columns = [column.user_id]
  }
}

table "account_recoveries" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "user_id" {
    type = uuid
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
  column "used" {
    type    = boolean
    null    = false
    default = false
  }
  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.id]
  }
  index "account_recoveries_user_id_idx" {
    columns = [column.user_id]
  }
}

table "notification_queue" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "provider" {
    type = varchar(64)
    null = false
  }
  column "to" {
    type = jsonb
    null = false
  }
  column "event" {
    type = varchar(128)
    null = false
  }
  column "details" {
    type = jsonb
    null = false
  }
  column "retry" {
    type = integer
    null = false
  }
  column "max_retry" {
    type = integer
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "last_error" {
    type = text
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
}