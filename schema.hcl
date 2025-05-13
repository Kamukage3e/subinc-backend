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


table "projects" {
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
  column "description" {
    type = text
  }
  column "status" {
    type = varchar(32)
    null = false
  }
  column "tags" {
    type = jsonb
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
  index "projects_org_id_idx" {
    columns = [column.org_id]
  }
  index "projects_name_idx" {
    columns = [column.name]
  }
}

// All project settings are now runtime, DB-backed, and managed via server_config (key: project_settings_{projectID})

table "project_audit_log" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "project_id" {
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
  index "project_audit_log_project_id_idx" {
    columns = [column.project_id]
  }
  index "project_audit_log_actor_id_idx" {
    columns = [column.actor_id]
  }
  comment = "Audit logs for all project actions. JSON details for extensibility."
}

table "roles" {
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
    type = varchar(128)
    null = false
  }
  column "desc" {
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
  column "deleted_at" {
    type = timestamptz
  }
  primary_key {
    columns = [column.id]
  }
  index "roles_tenant_id_name_idx" {
    columns = [column.tenant_id, column.name]
    unique  = true
  }
}

table "permissions" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "name" {
    type = varchar(128)
    null = false
  }
  column "resource" {
    type = varchar(128)
    null = false
  }
  column "action" {
    type = varchar(64)
    null = false
  }
  column "desc" {
    type = text
  }
  column "parent_resource_id" {
    type = uuid
  }
  column "resource_pattern" {
    type = varchar(256)
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
  index "permissions_name_resource_action_idx" {
    columns = [column.name, column.resource, column.action]
    unique  = true
  }
}

table "role_bindings" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "role_id" {
    type = uuid
    null = false
  }
  column "user_id" {
    type = uuid
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
  index "role_bindings_tenant_id_user_id_role_id_idx" {
    columns = [column.tenant_id, column.user_id, column.role_id]
    unique  = true
  }
  foreign_key "role_bindings_role_id_fkey" {
    columns     = [column.role_id]
    ref_columns = [table.roles.column.id]
    on_delete   = CASCADE
  }
}

table "policies" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "statements" {
    type = jsonb
    null = false
  }
  column "desc" {
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
    columns = [column.id]
  }
  index "policies_tenant_id_idx" {
    columns = [column.tenant_id]
  }
}

table "api_permissions" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "api" {
    type = varchar(128)
    null = false
  }
  column "method" {
    type = varchar(16)
    null = false
  }
  column "desc" {
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
    columns = [column.id]
  }
  index "api_permissions_api_method_idx" {
    columns = [column.api, column.method]
    unique  = true
  }
}

table "resources" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "type" {
    type = varchar(64)
    null = false
  }
  column "name" {
    type = varchar(128)
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
  index "resources_tenant_id_type_name_idx" {
    columns = [column.tenant_id, column.type, column.name]
    unique  = true
  }
}

table "audit_log" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "tenant_id" {
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
  index "audit_log_tenant_id_action_idx" {
    columns = [column.tenant_id, column.action]
  }
}

table "abac_policies" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "statements" {
    type = jsonb
    null = false
  }
  column "desc" {
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
    columns = [column.id]
  }
  index "abac_policies_tenant_id_idx" {
    columns = [column.tenant_id]
  }
}

table "delegated_roles" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "from_user_id" {
    type = uuid
    null = false
  }
  column "to_user_id" {
    type = uuid
    null = false
  }
  column "role_id" {
    type = uuid
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
  index "delegated_roles_tenant_id_from_to_role_idx" {
    columns = [column.tenant_id, column.from_user_id, column.to_user_id, column.role_id]
    unique  = true
  }
  foreign_key "delegated_roles_role_id_fkey" {
    columns     = [column.role_id]
    ref_columns = [table.roles.column.id]
    on_delete   = CASCADE
  }
}

table "permission_templates" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "name" {
    type = varchar(128)
    null = false
  }
  column "resource" {
    type = varchar(128)
    null = false
  }
  column "action" {
    type = varchar(64)
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
  index "permission_templates_name_resource_action_idx" {
    columns = [column.name, column.resource, column.action]
    unique  = true
  }
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


table "tenants" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "name" {
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
  unique "tenants_name_key" {
    columns = [column.name]
  }
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
  column "deleted_at" {
    type = timestamptz
    null = true
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

table "documents" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "title" {
    type = varchar(256)
    null = false
  }
  column "content" {
    type = text
    null = false
  }
  column "owner_id" {
    type = uuid
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
  index "idx_documents_owner_id" {
    columns = [column.owner_id]
  }
}