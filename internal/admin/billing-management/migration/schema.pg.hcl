schema "public" {
  comment = "All billing management tables are multi-tenant, type-safe, and production-grade. No placeholders, no bloat, no non-prod content."
}

table "org_billing_accounts" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "org_id" {
    type = uuid
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "default_method_id" {
    type = uuid
    null = true
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
    columns = [
      column.id
    ]
  }
  unique "uq_org_billing_accounts_id" {
    columns = [column.id]
  }
  foreign_key "fk_org_billing_accounts_org_id" {
    columns     = [column.org_id]
    ref_columns = [table.organizations.column.id]
    on_delete   = CASCADE
  }
  index "idx_org_billing_accounts_org_id" {
    columns = [column.id]
  }
}

table "billing_methods" {
  schema = schema.public
  column "id" {
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
  column "details" {
    type = jsonb
    null = false
  }
  column "is_default" {
    type    = boolean
    null    = false
    default = false
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
  foreign_key "fk_billing_methods_account_id" {
    columns     = [column.account_id]
    ref_columns = [table.org_billing_accounts.column.id]
    on_delete   = CASCADE
  }
  index "idx_billing_methods_account_id" {
    columns = [column.account_id]
  }
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
  column "org_id" {
    type = uuid
    null = false
  }
  column "number" {
    type = varchar(64)
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "total" {
    type = numeric(18, 2)
    null = false
  }
  column "currency" {
    type = varchar(8)
    null = false
  }
  column "issued_at" {
    type = timestamptz
    null = false
  }
  column "due_at" {
    type = timestamptz
    null = false
  }
  column "paid_at" {
    type = timestamptz
    null = true
  }
  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.id]
  }
  unique "uq_invoices_number" {
    columns = [column.number]
  }
  foreign_key "fk_invoices_account_id" {
    columns     = [column.account_id]
    ref_columns = [table.org_billing_accounts.column.id]
    on_delete   = CASCADE
  }
  foreign_key "fk_invoices_org_id" {
    columns     = [column.org_id]
    ref_columns = [table.organizations.column.id]
    on_delete   = CASCADE
  }
  index "idx_invoices_account_id" {
    columns = [column.account_id]
  }
  index "idx_invoices_id" {
    columns = [column.id]
  }
}

table "invoice_items" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "invoice_id" {
    type = uuid
    null = false
  }
  column "description" {
    type = varchar(256)
    null = false
  }
  column "amount" {
    type = numeric(18, 2)
    null = false
  }
  column "quantity" {
    type = int
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
  foreign_key "fk_invoice_items_invoice_id" {
    columns = [column.invoice_id]

    ref_columns = [table.invoices.column.id]
    on_delete   = CASCADE
  }
  index "idx_invoice_items_invoice_id" {
    columns = [column.invoice_id]
  }
}

table "billing_audit_log" {
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
    null = true
  }
  column "action" {
    type = varchar(64)
    null = false
  }
  column "target_id" {
    type = uuid
    null = true
  }
  column "details" {
    type = jsonb
    null = true
  }
  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.id]
  }
  index "idx_billing_audit_log_id" {
    columns = [column.id]
  }
  index "idx_billing_audit_log_actor_id" {
    columns = [column.actor_id]
  }
}

table "org_subscriptions" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "org_id" {
    type = uuid
    null = false
  }
  column "plan" {
    type = varchar(64)
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "started_at" {
    type = timestamptz
    null = false
  }
  column "ends_at" {
    type = timestamptz
    null = true
  }
  column "canceled_at" {
    type = timestamptz
    null = true
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
  foreign_key "fk_org_subscriptions_org_id" {
    columns     = [column.org_id]
    ref_columns = [table.organizations.column.id]
    on_delete   = CASCADE
  }
  index "idx_org_subscriptions_id" {
    columns = [column.id]
  }
}

table "org_usage" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "org_id" {
    type = uuid
    null = false
  }
  column "period_start" {
    type = timestamptz
    null = false
  }
  column "period_end" {
    type = timestamptz
    null = false
  }
  column "usage" {
    type = jsonb
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
  foreign_key "fk_org_usage_org_id" {
    columns = [column.org_id]
    ref_columns = [table.organizations.column.id]
    on_delete   = CASCADE
  }
  index "idx_org_usage_id" {
    columns = [column.id]
  }
  index "idx_org_usage_period_start_end" {
    columns = [column.period_start, column.period_end]
  }
}

table "org_credits" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "org_id" {
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
  }
  column "source" {
    type = varchar(64)
    null = false
  }
  column "expires_at" {
    type = timestamptz
    null = true
  }
  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.id]
  }
  foreign_key "fk_org_credits_org_id" {
    columns     = [column.org_id]
    ref_columns = [table.organizations.column.id]
    on_delete   = CASCADE
  }
  index "idx_org_credits_id" {
    columns = [column.id]
  }
}

table "payment_transactions" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "org_id" {
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
  column "method_id" {
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
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "gateway" {
    type = varchar(32)
    null = false
  }
  column "gateway_txn_id" {
    type = varchar(128)
    null = true
  }
  column "error_code" {
    type = varchar(64)
    null = true
  }
  column "error_message" {
    type = varchar(256)
    null = true
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
  foreign_key "fk_payment_transactions_org_id" {
    columns     = [column.org_id]
    ref_columns = [table.organizations.column.id]
    on_delete   = CASCADE
  }
  foreign_key "fk_payment_transactions_account_id" {
    columns     = [column.account_id]
    ref_columns = [table.org_billing_accounts.column.id]
    on_delete   = CASCADE
  }
  foreign_key "fk_payment_transactions_invoice_id" {
    columns     = [column.invoice_id]
    ref_columns = [table.invoices.column.id]
    on_delete   = CASCADE
  }
  foreign_key "fk_payment_transactions_method_id" {
    columns     = [column.method_id]
    ref_columns = [table.billing_methods.column.id]
    on_delete   = CASCADE
  }
  index "idx_payment_transactions_id" {
    columns = [column.id]
  }
  index "idx_payment_transactions_account_id" {
    columns = [column.account_id]
  }
  index "idx_payment_transactions_invoice_id" {
    columns = [column.invoice_id]
  }
  index "idx_payment_transactions_method_id" {
    columns = [column.method_id]
  }
  index "idx_payment_transactions_status" {
    columns = [column.status]
  }
  index "idx_payment_transactions_gateway" {
    columns = [column.gateway]
  }
}

table "refunds" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "org_id" {
    type = uuid
    null = false
  }
  column "transaction_id" {
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
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "reason" {
    type = varchar(128)
    null = true
  }
  column "gateway" {
    type = varchar(32)
    null = false
  }
  column "gateway_refund_id" {
    type = varchar(128)
    null = true
  }
  column "error_code" {
    type = varchar(64)
    null = true
  }
  column "error_message" {
    type = varchar(256)
    null = true
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
  foreign_key "fk_refunds_org_id" {
    columns     = [column.org_id]
    ref_columns = [table.organizations.column.id]
    on_delete   = CASCADE
  }
  foreign_key "fk_refunds_transaction_id" {
    columns     = [column.transaction_id]
    ref_columns = [table.payment_transactions.column.id]
    on_delete   = CASCADE
  }
  index "idx_refunds_id" {
    columns = [column.id]
  }
  index "idx_refunds_transaction_id" {
    columns = [column.transaction_id]
  }
  index "idx_refunds_status" {
    columns = [column.status]
  }
  index "idx_refunds_gateway" {
    columns = [column.gateway]
  }
}

table "tax_rates" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "org_id" {
    type = uuid
    null = true
  }
  column "country" {
    type = varchar(2)
    null = false
  }
  column "region" {
    type = varchar(64)
    null = true
  }
  column "rate" {
    type = numeric(5, 4)
    null = false
  }
  column "name" {
    type = varchar(64)
    null = false
  }
  column "active" {
    type    = boolean
    null    = false
    default = true
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
  foreign_key "fk_tax_rates_org_id" {
    columns     = [column.org_id]
    ref_columns = [table.organizations.column.id]
    on_delete   = CASCADE
  }
  index "idx_tax_rates_id" {
    columns = [column.id]
  }
  index "idx_tax_rates_country_region" {
    columns = [column.country, column.region]
  }
  index "idx_tax_rates_active" {
    columns = [column.active]
  }
}

table "invoice_taxes" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "invoice_id" {
    type = uuid
    null = false
  }
  column "tax_rate_id" {
    type = uuid
    null = false
  }
  column "amount" {
    type = numeric(18, 2)
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
  foreign_key "fk_invoice_taxes_invoice_id" {
    columns     = [column.invoice_id]
    ref_columns = [table.invoices.column.id]
    on_delete   = CASCADE
  }
  foreign_key "fk_invoice_taxes_tax_rate_id" {
    columns     = [column.tax_rate_id]
    ref_columns = [table.tax_rates.column.id]
    on_delete   = CASCADE
  }
  index "idx_invoice_taxes_invoice_id" {
    columns = [column.invoice_id]
  }
  index "idx_invoice_taxes_tax_rate_id" {
    columns = [column.tax_rate_id]
  }
}

table "pricing_plans" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "name" {
    type = varchar(64)
    null = false
  }
  column "slug" {
    type = varchar(64)
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "price" {
    type = numeric(18, 2)
    null = false
  }
  column "currency" {
    type = varchar(8)
    null = false
  }
  column "interval" {
    type    = varchar(16)
    null    = false
    comment = "e.g. month, year"
  }
  column "trial_days" {
    type    = int
    null    = false
    default = 0
  }
  column "metadata" {
    type = jsonb
    null = true
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
  unique "uq_pricing_plans_slug" {
    columns = [column.slug]
  }
  index "idx_pricing_plans_status" {
    columns = [column.status]
  }
  index "idx_pricing_plans_interval" {
    columns = [column.interval]
  }
}

table "plan_features" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "plan_id" {
    type = uuid
    null = false
  }
  column "feature" {
    type = varchar(64)
    null = false
  }
  column "value" {
    type = varchar(128)
    null = true
  }
  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.id]
  }
  foreign_key "fk_plan_features_plan_id" {
    columns     = [column.plan_id]
    ref_columns = [table.pricing_plans.column.id]
    on_delete   = CASCADE
  }
  index "idx_plan_features_plan_id" {
    columns = [column.plan_id]
  }
  index "idx_plan_features_feature" {
    columns = [column.feature]
  }
}

table "discounts" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "code" {
    type = varchar(64)
    null = false
  }
  column "type" {
    type    = varchar(32)
    null    = false
    comment = "percent, fixed"
  }
  column "amount" {
    type = numeric(18, 2)
    null = true
  }
  column "percent" {
    type = numeric(5, 2)
    null = true
  }
  column "currency" {
    type = varchar(8)
    null = true
  }
  column "max_redemptions" {
    type = int
    null = true
  }
  column "expires_at" {
    type = timestamptz
    null = true
  }
  column "metadata" {
    type = jsonb
    null = true
  }
  column "active" {
    type    = boolean
    null    = false
    default = true
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
  unique "uq_discounts_code" {
    columns = [column.code]
  }
  index "idx_discounts_active" {
    columns = [column.active]
  }
  index "idx_discounts_expires_at" {
    columns = [column.expires_at]
  }
}

table "coupon_redemptions" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "discount_id" {
    type = uuid
    null = false
  }
  column "org_id" {
    type = uuid
    null = false
  }
  column "user_id" {
    type = uuid
    null = true
  }
  column "invoice_id" {
    type = uuid
    null = true
  }
  column "redeemed_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.id]
  }
  foreign_key "fk_coupon_redemptions_discount_id" {
    columns     = [column.discount_id]
    ref_columns = [table.discounts.column.id]
    on_delete   = CASCADE
  }
  foreign_key "fk_coupon_redemptions_org_id" {
    columns     = [column.org_id]
    ref_columns = [table.organizations.column.id]
    on_delete   = CASCADE
  }
  foreign_key "fk_coupon_redemptions_invoice_id" {
    columns     = [column.invoice_id]
    ref_columns = [table.invoices.column.id]
    on_delete   = CASCADE
  }
  index "idx_coupon_redemptions_discount_id" {
    columns = [column.discount_id]
  }
  index "idx_coupon_redemptions_id" {
    columns = [column.id]
  }
  index "idx_coupon_redemptions_user_id" {
    columns = [column.user_id]
  }
  index "idx_coupon_redemptions_invoice_id" {
    columns = [column.invoice_id]
  }
}

table "dunning_events" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "org_id" {
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
  column "event_type" {
    type    = varchar(32)
    null    = false
    comment = "payment_failed, retry, canceled"
  }
  column "details" {
    type = jsonb
    null = true
  }
  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.id]
  }
  foreign_key "fk_dunning_events_org_id" {
    columns     = [column.org_id]
    ref_columns = [table.organizations.column.id]
    on_delete   = CASCADE
  }
  foreign_key "fk_dunning_events_account_id" {
    columns     = [column.account_id]
    ref_columns = [table.org_billing_accounts.column.id]
    on_delete   = CASCADE
  }
  foreign_key "fk_dunning_events_invoice_id" {
    columns     = [column.invoice_id]
    ref_columns = [table.invoices.column.id]
    on_delete   = CASCADE
  }
  index "idx_dunning_events_id" {
    columns = [column.id]
  }
  index "idx_dunning_events_account_id" {
    columns = [column.account_id]
  }
  index "idx_dunning_events_invoice_id" {
    columns = [column.invoice_id]
  }
  index "idx_dunning_events_event_type" {
    columns = [column.event_type]
  }
}

table "billing_webhooks" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "org_id" {
    type = uuid
    null = false
  }
  column "event_type" {
    type = varchar(64)
    null = false
  }
  column "payload" {
    type = jsonb
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "response_code" {
    type = int
    null = true
  }
  column "response_body" {
    type = text
    null = true
  }
  column "delivered_at" {
    type = timestamptz
    null = true
  }
  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.id]
  }
  foreign_key "fk_billing_webhooks_org_id" {
    columns     = [column.org_id]
    ref_columns = [table.organizations.column.id]
    on_delete   = CASCADE
  }
  index "idx_billing_webhooks_id" {
    columns = [column.id]
  }
  index "idx_billing_webhooks_event_type" {
    columns = [column.event_type]
  }
  index "idx_billing_webhooks_status" {
    columns = [column.status]
  }
}

table "billing_notifications" {
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
    null = true
  }
  column "type" {
    type = varchar(32)
    null = false
  }
  column "message" {
    type = text
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "sent_at" {
    type = timestamptz
    null = true
  }
  column "created_at" {
    type    = timestamptz
    null    = false
    default = sql("now()")
  }
  primary_key {
    columns = [column.id]
  }
  foreign_key "fk_billing_notifications_org_id" {
    columns     = [column.org_id]
    ref_columns = [table.organizations.column.id]
    on_delete   = CASCADE
  }
  index "idx_billing_notifications_id" {
    columns = [column.id]
  }
  index "idx_billing_notifications_user_id" {
    columns = [column.user_id]
  }
  index "idx_billing_notifications_type" {
    columns = [column.type]
  }
  index "idx_billing_notifications_status" {
    columns = [column.status]
  }
}

table "usage_metering" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "org_id" {
    type = uuid
    null = false
  }
  column "period_start" {
    type = timestamptz
    null = false
  }
  column "period_end" {
    type = timestamptz
    null = false
  }
  column "metric" {
    type = varchar(64)
    null = false
  }
  column "value" {
    type = numeric(18, 4)
    null = false
  }
  column "unit" {
    type = varchar(16)
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
  foreign_key "fk_usage_metering_org_id" {
    columns     = [column.org_id]
    ref_columns = [table.organizations.column.id]
    on_delete   = CASCADE
  }
  index "idx_usage_metering_id" {
    columns = [column.id]
  }
  index "idx_usage_metering_period_start_end" {
    columns = [column.period_start, column.period_end]
  }
  index "idx_usage_metering_metric" {
    columns = [column.metric]
  }
}

table "org_legal_entities" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "org_id" {
    type = uuid
    null = false
  }
  column "name" {
    type = varchar(128)
    null = false
  }
  column "tax_id" {
    type = varchar(64)
    null = true
  }
  column "address" {
    type = text
    null = true
  }
  column "country" {
    type = varchar(2)
    null = false
  }
  column "region" {
    type = varchar(64)
    null = true
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
  foreign_key "fk_org_legal_entities_org_id" {
    columns     = [column.org_id]
    ref_columns = [table.organizations.column.id]
    on_delete   = CASCADE
  }
  index "idx_org_legal_entities_id" {
    columns = [column.id]
  }
  index "idx_org_legal_entities_country_region" {
    columns = [column.country, column.region]
  }
}