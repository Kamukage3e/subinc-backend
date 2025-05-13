schema "public" {
  comment = "Server config tables for SaaS. All tables are type-safe, versioned, auditable, and production-grade."
}

table "server_config" {
  schema = schema.public
  column "key" {
    type = varchar(128)
    null = false
  }
  column "value" {
    type = text
    null = false
  }
  column "version" {
    type = integer
    null = false
  }
  column "updated_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.key]
  }
}

table "server_config_history" {
  schema = schema.public
  column "id" {
    type = serial
    null = false
  }
  column "key" {
    type = varchar(128)
    null = false
  }
  column "value" {
    type = text
    null = false
  }
  column "version" {
    type = integer
    null = false
  }
  column "updated_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  column "updated_by" {
    type = varchar(128)
    null = false
  }
  primary_key {
    columns = [column.id]
  }
  index "idx_server_config_history_key" {
    columns = [column.key]
  }
}

table "tenant_server_config" {
  schema = schema.public
  column "tenant_id" {
    type = varchar(128)
    null = false
  }
  column "key" {
    type = varchar(128)
    null = false
  }
  column "value" {
    type = text
    null = false
  }
  column "version" {
    type = integer
    null = false
  }
  column "updated_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.tenant_id, column.key]
  }
  index "idx_tenant_server_config_tenant_id" {
    columns = [column.tenant_id]
  }
  index "idx_tenant_server_config_key" {
    columns = [column.key]
  }
}

table "tenant_server_config_history" {
  schema = schema.public
  column "id" {
    type = serial
    null = false
  }
  column "tenant_id" {
    type = varchar(128)
    null = false
  }
  column "key" {
    type = varchar(128)
    null = false
  }
  column "value" {
    type = text
    null = false
  }
  column "version" {
    type = integer
    null = false
  }
  column "updated_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  column "updated_by" {
    type = varchar(128)
    null = false
  }
  primary_key {
    columns = [column.id]
  }
  index "idx_tenant_server_config_history_tenant_id" {
    columns = [column.tenant_id]
  }
  index "idx_tenant_server_config_history_key" {
    columns = [column.key]
  }
}

table "migration_status" {
  schema = schema.public
  column "name" {
    type = varchar(128)
    null = false
  }
  column "version" {
    type = integer
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "started_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  column "completed_at" {
    type = timestamptz
  }
  column "error" {
    type = text
  }
  primary_key {
    columns = [column.name]
  }
} 