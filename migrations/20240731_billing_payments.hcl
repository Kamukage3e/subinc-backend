schema "public" {
  comment = "Billing management payment tables for multi-tenant SaaS"
}

table "payments" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "invoice_id" {
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
  column "method" {
    type = varchar(32)
    null = false
  }
  column "last4" {
    type = varchar(4)
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
  
  index "idx_payments_invoice_id" {
    columns = [column.invoice_id]
  }
  
  index "idx_payments_tenant_id" {
    columns = [column.tenant_id]
  }
  
  index "idx_payments_status" {
    columns = [column.status]
  }
  
  index "idx_payments_created_at" {
    columns = [column.created_at]
  }
  
  index "idx_payments_method" {
    columns = [column.method]
  }
  
  index "idx_payments_idempotency_key" {
    columns = [(sql("(metadata->>'idempotency_key')"))]
    where = "metadata->>'idempotency_key' IS NOT NULL"
  }
  
  foreign_key "fk_payments_invoice_id" {
    columns     = [column.invoice_id]
    ref_columns = [table.invoices.column.id]
    on_delete   = CASCADE
  }
}

table "payment_methods" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "account_id" {
    type = uuid
    null = false
  }
  column "type" {
    type = varchar(32)
    null = false
  }
  column "provider" {
    type = varchar(32)
    null = false
  }
  column "token_id" {
    type = varchar(128)
    null = true
  }
  column "last4" {
    type = varchar(4)
    null = true
  }
  column "expiry_month" {
    type = integer
    null = true
  }
  column "expiry_year" {
    type = integer
    null = true
  }
  column "name" {
    type = varchar(128)
    null = true
  }
  column "is_default" {
    type = boolean
    null = false
    default = false
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
  
  index "idx_payment_methods_account_id" {
    columns = [column.account_id]
  }
  
  index "idx_payment_methods_tenant_id" {
    columns = [column.tenant_id]
  }
  
  index "idx_payment_methods_type" {
    columns = [column.type, column.provider]
  }
  
  index "idx_payment_methods_is_default" {
    columns = [column.is_default, column.account_id]
    where = "is_default = true"
  }
  
  index "idx_payment_methods_token_id" {
    columns = [column.token_id]
    where = "token_id IS NOT NULL"
  }
}

table "refunds" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "payment_id" {
    type = uuid
    null = false
  }
  column "invoice_id" {
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
  column "reason" {
    type = text
    null = true
  }
  column "status" {
    type = varchar(32)
    null = false
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
  
  index "idx_refunds_payment_id" {
    columns = [column.payment_id]
  }
  
  index "idx_refunds_invoice_id" {
    columns = [column.invoice_id]
  }
  
  index "idx_refunds_tenant_id" {
    columns = [column.tenant_id]
  }
  
  index "idx_refunds_status" {
    columns = [column.status]
  }
  
  index "idx_refunds_created_at" {
    columns = [column.created_at]
  }
  
  foreign_key "fk_refunds_payment_id" {
    columns     = [column.payment_id]
    ref_columns = [table.payments.column.id]
    on_delete   = CASCADE
  }
  
  foreign_key "fk_refunds_invoice_id" {
    columns     = [column.invoice_id]
    ref_columns = [table.invoices.column.id]
    on_delete   = CASCADE
  }
}

table "disputes" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "payment_id" {
    type = uuid
    null = false
  }
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "provider" {
    type = varchar(32)
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "reason" {
    type = varchar(128)
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
  column "evidence_due" {
    type = timestamptz
    null = true
  }
  column "evidence_submitted" {
    type = timestamptz
    null = true
  }
  column "raw_json" {
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
  
  index "idx_disputes_payment_id" {
    columns = [column.payment_id]
  }
  
  index "idx_disputes_tenant_id" {
    columns = [column.tenant_id]
  }
  
  index "idx_disputes_status" {
    columns = [column.status]
  }
  
  index "idx_disputes_created_at" {
    columns = [column.created_at]
  }
  
  foreign_key "fk_disputes_payment_id" {
    columns     = [column.payment_id]
    ref_columns = [table.payments.column.id]
    on_delete   = CASCADE
  }
}

table "dispute_evidence" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "dispute_id" {
    type = uuid
    null = false
  }
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "file_url" {
    type = varchar(512)
    null = false
  }
  column "file_name" {
    type = varchar(256)
    null = false
  }
  column "file_type" {
    type = varchar(64)
    null = false
  }
  column "uploaded_by" {
    type = uuid
    null = false
  }
  column "uploaded_at" {
    type = timestamptz
    null = false
  }
  column "provider_status" {
    type = varchar(32)
    null = false
  }
  column "provider_response" {
    type = text
    null = true
  }
  column "raw_json" {
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
  
  index "idx_dispute_evidence_dispute_id" {
    columns = [column.dispute_id]
  }
  
  index "idx_dispute_evidence_tenant_id" {
    columns = [column.tenant_id]
  }
  
  index "idx_dispute_evidence_created_at" {
    columns = [column.created_at]
  }
  
  foreign_key "fk_dispute_evidence_dispute_id" {
    columns     = [column.dispute_id]
    ref_columns = [table.disputes.column.id]
    on_delete   = CASCADE
  }
} 