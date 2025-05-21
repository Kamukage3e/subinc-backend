schema "public" {
  comment = "Billing management invoice tables for multi-tenant SaaS"
}

table "invoices" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "account_id" {
    type = uuid
    null = false
  }
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "amount" {
    type = numeric(18, 2)
    null = false
  }
  column "currency" {
    type = varchar(8)
    null = false
    default = "USD"
  }
  column "original_amount" {
    type = numeric(18, 2)
    null = true
  }
  column "original_currency" {
    type = varchar(8)
    null = true
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "due_date" {
    type = timestamptz
    null = false
  }
  column "tax_amount" {
    type = numeric(18, 2)
    null = false
    default = 0
  }
  column "tax_rate" {
    type = numeric(10, 4)
    null = false
    default = 0
  }
  column "fees" {
    type = jsonb
    null = true
  }
  column "plugin_name" {
    type = varchar(64)
    null = true
  }
  column "dunning_attempts" {
    type = integer
    null = false
    default = 0
  }
  column "dunning_next_attempt_at" {
    type = timestamptz
    null = true
  }
  column "dunning_status" {
    type = varchar(32)
    null = true
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
  
  index "idx_invoices_account_id" {
    columns = [column.account_id]
  }
  
  index "idx_invoices_tenant_id" {
    columns = [column.tenant_id]
  }
  
  index "idx_invoices_status" {
    columns = [column.status]
  }
  
  index "idx_invoices_due_date" {
    columns = [column.due_date]
  }
  
  index "idx_invoices_created_at" {
    columns = [column.created_at]
  }
  
  index "idx_invoices_dunning_status" {
    columns = [column.dunning_status, column.dunning_next_attempt_at]
    where = "dunning_status = 'active'"
  }
}

table "invoice_adjustments" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "invoice_id" {
    type = uuid
    null = false
  }
  column "type" {
    type = varchar(32)
    null = false
  }
  column "amount" {
    type = numeric(18, 2)
    null = false
  }
  column "currency" {
    type = varchar(8)
    null = false
    default = "USD"
  }
  column "original_amount" {
    type = numeric(18, 2)
    null = true
  }
  column "original_currency" {
    type = varchar(8)
    null = true
  }
  column "reason" {
    type = text
    null = true
  }
  column "metadata" {
    type = jsonb
    null = true
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
  
  index "idx_invoice_adjustments_invoice_id" {
    columns = [column.invoice_id]
  }
  
  index "idx_invoice_adjustments_type" {
    columns = [column.type]
  }
  
  foreign_key "fk_invoice_adjustments_invoice_id" {
    columns     = [column.invoice_id]
    ref_columns = [table.invoices.column.id]
    on_delete   = CASCADE
  }
}

table "billing_config" {
  schema = schema.public
  column "key" {
    type = varchar(128)
    null = false
  }
  column "value" {
    type = jsonb
    null = false
  }
  column "updated_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  
  primary_key {
    columns = [column.key]
  }
}

table "dunning_events" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "invoice_id" {
    type = uuid
    null = false
  }
  column "account_id" {
    type = uuid
    null = true
  }
  column "event_type" {
    type = varchar(64)
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "details" {
    type = jsonb
    null = true
  }
  column "created_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  
  primary_key {
    columns = [column.id]
  }
  
  index "idx_dunning_events_invoice_id" {
    columns = [column.invoice_id]
  }
  
  index "idx_dunning_events_account_id" {
    columns = [column.account_id]
  }
  
  index "idx_dunning_events_created_at" {
    columns = [column.created_at]
  }
  
  foreign_key "fk_dunning_events_invoice_id" {
    columns     = [column.invoice_id]
    ref_columns = [table.invoices.column.id]
    on_delete   = CASCADE
  }
}

table "dunning_configs" {
  schema = schema.public
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "max_attempts" {
    type = integer
    null = false
    default = 3
  }
  column "retry_intervals" {
    type = jsonb
    null = false
    default = sql("'[\"24h\", \"72h\", \"168h\"]'::jsonb")
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
    columns = [column.tenant_id]
  }
} 