schema "public" {
  comment = "Billing management discount and credit tables for multi-tenant SaaS"
}

table "credits" {
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
  column "initial_amount" {
    type = numeric(18, 2)
    null = false
  }
  column "invoice_id" {
    type = uuid
    null = true
  }
  column "description" {
    type = text
    null = true
  }
  column "status" {
    type = varchar(32)
    null = false
    default = "active"
  }
  column "expires_at" {
    type = timestamptz
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
  
  index "idx_credits_account_id" {
    columns = [column.account_id]
  }
  
  index "idx_credits_tenant_id" {
    columns = [column.tenant_id]
  }
  
  index "idx_credits_invoice_id" {
    columns = [column.invoice_id]
    where = "invoice_id IS NOT NULL"
  }
  
  index "idx_credits_status" {
    columns = [column.status]
  }
  
  index "idx_credits_expires_at" {
    columns = [column.expires_at]
    where = "expires_at IS NOT NULL"
  }
  
  index "idx_credits_created_at" {
    columns = [column.created_at]
  }
}

table "discounts" {
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
  column "name" {
    type = varchar(128)
    null = false
  }
  column "type" {
    type = varchar(32)
    null = false
  }
  column "value" {
    type = numeric(18, 2)
    null = false
  }
  column "is_percentage" {
    type = boolean
    null = false
    default = false
  }
  column "currency" {
    type = varchar(8)
    null = true
  }
  column "description" {
    type = text
    null = true
  }
  column "code" {
    type = varchar(64)
    null = true
  }
  column "status" {
    type = varchar(32)
    null = false
    default = "active"
  }
  column "starts_at" {
    type = timestamptz
    null = true
  }
  column "expires_at" {
    type = timestamptz
    null = true
  }
  column "max_uses" {
    type = integer
    null = true
  }
  column "current_uses" {
    type = integer
    null = false
    default = 0
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
  
  index "idx_discounts_tenant_id" {
    columns = [column.tenant_id]
  }
  
  index "idx_discounts_account_id" {
    columns = [column.account_id]
  }
  
  index "idx_discounts_code" {
    columns = [column.code]
    where = "code IS NOT NULL"
  }
  
  index "idx_discounts_status" {
    columns = [column.status]
  }
  
  index "idx_discounts_starts_at" {
    columns = [column.starts_at]
    where = "starts_at IS NOT NULL"
  }
  
  index "idx_discounts_expires_at" {
    columns = [column.expires_at]
    where = "expires_at IS NOT NULL"
  }
  
  index "idx_discounts_created_at" {
    columns = [column.created_at]
  }
}

table "discount_usage" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "discount_id" {
    type = uuid
    null = false
  }
  column "account_id" {
    type = uuid
    null = false
  }
  column "invoice_id" {
    type = uuid
    null = true
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
  column "created_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  
  primary_key {
    columns = [column.id]
  }
  
  index "idx_discount_usage_discount_id" {
    columns = [column.discount_id]
  }
  
  index "idx_discount_usage_account_id" {
    columns = [column.account_id]
  }
  
  index "idx_discount_usage_invoice_id" {
    columns = [column.invoice_id]
    where = "invoice_id IS NOT NULL"
  }
  
  index "idx_discount_usage_created_at" {
    columns = [column.created_at]
  }
  
  foreign_key "fk_discount_usage_discount_id" {
    columns     = [column.discount_id]
    ref_columns = [table.discounts.column.id]
    on_delete   = CASCADE
  }
}

table "subscription_tiers" {
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
  column "description" {
    type = text
    null = true
  }
  column "price" {
    type = numeric(18, 2)
    null = false
  }
  column "currency" {
    type = varchar(8)
    null = false
    default = "USD"
  }
  column "billing_period" {
    type = varchar(32)
    null = false
    default = "monthly"
  }
  column "features" {
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
  
  unique "idx_subscription_tiers_tenant_name" {
    columns = [column.tenant_id, column.name]
  }
  
  index "idx_subscription_tiers_tenant_id" {
    columns = [column.tenant_id]
  }
  
  index "idx_subscription_tiers_created_at" {
    columns = [column.created_at]
  }
}

table "subscriptions" {
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
  column "tier_id" {
    type = uuid
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
    default = "active"
  }
  column "start_date" {
    type = timestamptz
    null = false
  }
  column "end_date" {
    type = timestamptz
    null = true
  }
  column "auto_renew" {
    type = boolean
    null = false
    default = true
  }
  column "next_billing_date" {
    type = timestamptz
    null = true
  }
  column "payment_method_id" {
    type = uuid
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
  
  index "idx_subscriptions_tenant_id" {
    columns = [column.tenant_id]
  }
  
  index "idx_subscriptions_account_id" {
    columns = [column.account_id]
  }
  
  index "idx_subscriptions_tier_id" {
    columns = [column.tier_id]
  }
  
  index "idx_subscriptions_status" {
    columns = [column.status]
  }
  
  index "idx_subscriptions_next_billing_date" {
    columns = [column.next_billing_date]
    where = "next_billing_date IS NOT NULL"
  }
  
  index "idx_subscriptions_created_at" {
    columns = [column.created_at]
  }
  
  foreign_key "fk_subscriptions_tier_id" {
    columns     = [column.tier_id]
    ref_columns = [table.subscription_tiers.column.id]
    on_delete   = RESTRICT
  }
} 