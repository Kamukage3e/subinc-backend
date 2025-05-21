schema "public" {
  comment = "Billing management plugin tables for multi-tenant SaaS"
}

table "plugins" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "name" {
    type = varchar(64)
    null = false
  }
  column "type" {
    type = varchar(32)
    null = false
  }
  column "config" {
    type = jsonb
    null = true
  }
  column "status" {
    type = varchar(32)
    null = false
    default = "active"
  }
  column "created_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  column "updated_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  column "last_used_at" {
    type = timestamptz
    null = true
  }
  
  primary_key {
    columns = [column.id]
  }
  
  unique "idx_plugins_tenant_name_type" {
    columns = [column.tenant_id, column.name, column.type]
  }
  
  index "idx_plugins_tenant_id" {
    columns = [column.tenant_id]
  }
  
  index "idx_plugins_type" {
    columns = [column.type]
  }
  
  index "idx_plugins_status" {
    columns = [column.status]
  }
  
  index "idx_plugins_created_at" {
    columns = [column.created_at]
  }
}

table "plugin_configs" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "plugin_id" {
    type = uuid
    null = false
  }
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "config" {
    type = jsonb
    null = false
  }
  column "created_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  column "updated_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  
  primary_key {
    columns = [column.id]
  }
  
  index "idx_plugin_configs_plugin_id" {
    columns = [column.plugin_id]
  }
  
  index "idx_plugin_configs_tenant_id" {
    columns = [column.tenant_id]
  }
  
  foreign_key "fk_plugin_configs_plugin_id" {
    columns     = [column.plugin_id]
    ref_columns = [table.plugins.column.id]
    on_delete   = CASCADE
  }
}

table "fee_plugin_configs" {
  schema = schema.public
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "plugin_name" {
    type = varchar(64)
    null = false
  }
  column "config" {
    type = jsonb
    null = false
  }
  column "updated_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  
  primary_key {
    columns = [column.tenant_id, column.plugin_name]
  }
}

table "tax_plugin_configs" {
  schema = schema.public
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "plugin_name" {
    type = varchar(64)
    null = false
  }
  column "config" {
    type = jsonb
    null = false
  }
  column "updated_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  
  primary_key {
    columns = [column.tenant_id, column.plugin_name]
  }
}

table "payment_plugin_configs" {
  schema = schema.public
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "plugin_name" {
    type = varchar(64)
    null = false
  }
  column "config" {
    type = jsonb
    null = false
  }
  column "updated_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  
  primary_key {
    columns = [column.tenant_id, column.plugin_name]
  }
}

table "discount_plugin_configs" {
  schema = schema.public
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "plugin_name" {
    type = varchar(64)
    null = false
  }
  column "config" {
    type = jsonb
    null = false
  }
  column "updated_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  
  primary_key {
    columns = [column.tenant_id, column.plugin_name]
  }
}

table "subscription_plugin_configs" {
  schema = schema.public
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "plugin_name" {
    type = varchar(64)
    null = false
  }
  column "config" {
    type = jsonb
    null = false
  }
  column "updated_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  
  primary_key {
    columns = [column.tenant_id, column.plugin_name]
  }
}

table "invoice_plugin_configs" {
  schema = schema.public
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "plugin_name" {
    type = varchar(64)
    null = false
  }
  column "updated_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  
  primary_key {
    columns = [column.tenant_id, column.plugin_name]
  }
} 