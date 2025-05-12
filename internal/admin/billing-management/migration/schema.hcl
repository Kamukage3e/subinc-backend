schema "public" {
  comment = "All billing management tables are multi-tenant, type-safe, and production-grade. No placeholders, no bloat, no non-prod content."
}

table "org_billing_accounts" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "org_id"       { type = uuid; null = false }
  column "status"       { type = varchar(32); null = false }
  column "default_method_id" { type = uuid }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  unique { columns = [column.org_id] }
  foreign_key { columns = [column.org_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.org_id] }
}

table "billing_methods" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "account_id"   { type = uuid; null = false }
  column "type"         { type = varchar(32); null = false }
  column "details"      { type = jsonb; null = false }
  column "is_default"   { type = boolean; null = false; default = false }
  column "status"       { type = varchar(32); null = false }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.account_id]; ref_table = table.org_billing_accounts; ref_columns = [table.org_billing_accounts.column.id]; on_delete = CASCADE }
  index { columns = [column.account_id] }
}

table "invoices" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "account_id"   { type = uuid; null = false }
  column "org_id"       { type = uuid; null = false }
  column "number"       { type = varchar(64); null = false }
  column "status"       { type = varchar(32); null = false }
  column "total"        { type = numeric(18,2); null = false }
  column "currency"     { type = varchar(8); null = false }
  column "issued_at"    { type = timestamptz; null = false }
  column "due_at"       { type = timestamptz; null = false }
  column "paid_at"      { type = timestamptz }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  unique { columns = [column.number] }
  foreign_key { columns = [column.account_id]; ref_table = table.org_billing_accounts; ref_columns = [table.org_billing_accounts.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.org_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.account_id] }
  index { columns = [column.org_id] }
}

table "invoice_items" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "invoice_id"   { type = uuid; null = false }
  column "description"  { type = varchar(256); null = false }
  column "amount"       { type = numeric(18,2); null = false }
  column "quantity"     { type = int; null = false }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.invoice_id]; ref_table = table.invoices; ref_columns = [table.invoices.column.id]; on_delete = CASCADE }
  index { columns = [column.invoice_id] }
}

table "billing_audit_log" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "org_id"       { type = uuid; null = false }
  column "actor_id"     { type = uuid }
  column "action"       { type = varchar(64); null = false }
  column "target_id"    { type = uuid }
  column "details"      { type = jsonb }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  index { columns = [column.org_id] }
  index { columns = [column.actor_id] }
}

table "org_subscriptions" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "org_id"       { type = uuid; null = false }
  column "plan"         { type = varchar(64); null = false }
  column "status"       { type = varchar(32); null = false }
  column "started_at"   { type = timestamptz; null = false }
  column "ends_at"      { type = timestamptz }
  column "canceled_at"  { type = timestamptz }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.org_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.org_id] }
}

table "org_usage" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "org_id"       { type = uuid; null = false }
  column "period_start" { type = timestamptz; null = false }
  column "period_end"   { type = timestamptz; null = false }
  column "usage"        { type = jsonb; null = false }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.org_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.org_id] }
  index { columns = [column.period_start, column.period_end] }
}

table "org_credits" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "org_id"       { type = uuid; null = false }
  column "amount"       { type = numeric(18,2); null = false }
  column "currency"     { type = varchar(8); null = false }
  column "source"       { type = varchar(64); null = false }
  column "expires_at"   { type = timestamptz }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.org_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.org_id] }
}

table "payment_transactions" {
  schema      = schema.public
  column "id"             { type = uuid; null = false }
  column "org_id"         { type = uuid; null = false }
  column "account_id"     { type = uuid; null = false }
  column "invoice_id"     { type = uuid }
  column "method_id"      { type = uuid }
  column "amount"         { type = numeric(18,2); null = false }
  column "currency"       { type = varchar(8); null = false }
  column "status"         { type = varchar(32); null = false }
  column "gateway"        { type = varchar(32); null = false }
  column "gateway_txn_id" { type = varchar(128) }
  column "error_code"     { type = varchar(64) }
  column "error_message"  { type = varchar(256) }
  column "created_at"     { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at"     { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.org_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.account_id]; ref_table = table.org_billing_accounts; ref_columns = [table.org_billing_accounts.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.invoice_id]; ref_table = table.invoices; ref_columns = [table.invoices.column.id]; on_delete = SET NULL }
  foreign_key { columns = [column.method_id]; ref_table = table.billing_methods; ref_columns = [table.billing_methods.column.id]; on_delete = SET NULL }
  index { columns = [column.org_id] }
  index { columns = [column.account_id] }
  index { columns = [column.invoice_id] }
  index { columns = [column.method_id] }
  index { columns = [column.status] }
  index { columns = [column.gateway] }
}

table "refunds" {
  schema      = schema.public
  column "id"             { type = uuid; null = false }
  column "org_id"         { type = uuid; null = false }
  column "transaction_id" { type = uuid; null = false }
  column "amount"         { type = numeric(18,2); null = false }
  column "currency"       { type = varchar(8); null = false }
  column "status"         { type = varchar(32); null = false }
  column "reason"         { type = varchar(128) }
  column "gateway"        { type = varchar(32); null = false }
  column "gateway_refund_id" { type = varchar(128) }
  column "error_code"     { type = varchar(64) }
  column "error_message"  { type = varchar(256) }
  column "created_at"     { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at"     { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.org_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.transaction_id]; ref_table = table.payment_transactions; ref_columns = [table.payment_transactions.column.id]; on_delete = CASCADE }
  index { columns = [column.org_id] }
  index { columns = [column.transaction_id] }
  index { columns = [column.status] }
  index { columns = [column.gateway] }
}

table "tax_rates" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "org_id"       { type = uuid }
  column "country"      { type = varchar(2); null = false }
  column "region"       { type = varchar(64) }
  column "rate"         { type = numeric(5,4); null = false }
  column "name"         { type = varchar(64); null = false }
  column "active"       { type = boolean; null = false; default = true }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.org_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = SET NULL }
  index { columns = [column.org_id] }
  index { columns = [column.country, column.region] }
  index { columns = [column.active] }
}

table "invoice_taxes" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "invoice_id"   { type = uuid; null = false }
  column "tax_rate_id"  { type = uuid; null = false }
  column "amount"       { type = numeric(18,2); null = false }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.invoice_id]; ref_table = table.invoices; ref_columns = [table.invoices.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.tax_rate_id]; ref_table = table.tax_rates; ref_columns = [table.tax_rates.column.id]; on_delete = CASCADE }
  index { columns = [column.invoice_id] }
  index { columns = [column.tax_rate_id] }
}

table "pricing_plans" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "name"         { type = varchar(64); null = false }
  column "slug"         { type = varchar(64); null = false }
  column "status"       { type = varchar(32); null = false }
  column "price"        { type = numeric(18,2); null = false }
  column "currency"     { type = varchar(8); null = false }
  column "interval"     { type = varchar(16); null = false } # e.g. month, year
  column "trial_days"   { type = int; null = false; default = 0 }
  column "metadata"     { type = jsonb }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  unique { columns = [column.slug] }
  index { columns = [column.status] }
  index { columns = [column.interval] }
}

table "plan_features" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "plan_id"      { type = uuid; null = false }
  column "feature"      { type = varchar(64); null = false }
  column "value"        { type = varchar(128) }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.plan_id]; ref_table = table.pricing_plans; ref_columns = [table.pricing_plans.column.id]; on_delete = CASCADE }
  index { columns = [column.plan_id] }
  index { columns = [column.feature] }
}

table "discounts" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "code"         { type = varchar(64); null = false }
  column "type"         { type = varchar(32); null = false } # percent, fixed
  column "amount"       { type = numeric(18,2) }
  column "percent"      { type = numeric(5,2) }
  column "currency"     { type = varchar(8) }
  column "max_redemptions" { type = int }
  column "expires_at"   { type = timestamptz }
  column "metadata"     { type = jsonb }
  column "active"       { type = boolean; null = false; default = true }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  unique { columns = [column.code] }
  index { columns = [column.active] }
  index { columns = [column.expires_at] }
}

table "coupon_redemptions" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "discount_id"  { type = uuid; null = false }
  column "org_id"       { type = uuid; null = false }
  column "user_id"      { type = uuid }
  column "invoice_id"   { type = uuid }
  column "redeemed_at"  { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.discount_id]; ref_table = table.discounts; ref_columns = [table.discounts.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.org_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.invoice_id]; ref_table = table.invoices; ref_columns = [table.invoices.column.id]; on_delete = SET NULL }
  index { columns = [column.discount_id] }
  index { columns = [column.org_id] }
  index { columns = [column.user_id] }
  index { columns = [column.invoice_id] }
}

table "dunning_events" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "org_id"       { type = uuid; null = false }
  column "account_id"   { type = uuid; null = false }
  column "invoice_id"   { type = uuid }
  column "event_type"   { type = varchar(32); null = false } # payment_failed, retry, canceled
  column "details"      { type = jsonb }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.org_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.account_id]; ref_table = table.org_billing_accounts; ref_columns = [table.org_billing_accounts.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.invoice_id]; ref_table = table.invoices; ref_columns = [table.invoices.column.id]; on_delete = SET NULL }
  index { columns = [column.org_id] }
  index { columns = [column.account_id] }
  index { columns = [column.invoice_id] }
  index { columns = [column.event_type] }
}

table "billing_webhooks" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "org_id"       { type = uuid; null = false }
  column "event_type"   { type = varchar(64); null = false }
  column "payload"      { type = jsonb; null = false }
  column "status"       { type = varchar(32); null = false }
  column "response_code"{ type = int }
  column "response_body"{ type = text }
  column "delivered_at" { type = timestamptz }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.org_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.org_id] }
  index { columns = [column.event_type] }
  index { columns = [column.status] }
}

table "billing_notifications" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "org_id"       { type = uuid; null = false }
  column "user_id"      { type = uuid }
  column "type"         { type = varchar(32); null = false }
  column "message"      { type = text; null = false }
  column "status"       { type = varchar(32); null = false }
  column "sent_at"      { type = timestamptz }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.org_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.org_id] }
  index { columns = [column.user_id] }
  index { columns = [column.type] }
  index { columns = [column.status] }
}

table "usage_metering" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "org_id"       { type = uuid; null = false }
  column "period_start" { type = timestamptz; null = false }
  column "period_end"   { type = timestamptz; null = false }
  column "metric"       { type = varchar(64); null = false }
  column "value"        { type = numeric(18,4); null = false }
  column "unit"         { type = varchar(16); null = false }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.org_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.org_id] }
  index { columns = [column.period_start, column.period_end] }
  index { columns = [column.metric] }
}

table "org_legal_entities" {
  schema      = schema.public
  column "id"           { type = uuid; null = false }
  column "org_id"       { type = uuid; null = false }
  column "name"         { type = varchar(128); null = false }
  column "tax_id"       { type = varchar(64) }
  column "address"      { type = text }
  column "country"      { type = varchar(2); null = false }
  column "region"       { type = varchar(64) }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.org_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.org_id] }
  index { columns = [column.country, column.region] }
}

# Per-tenant feature flags (runtime, DB-backed)
table "billing_feature_flags" {
  schema = schema.public
  column "id"        { type = uuid; null = false }
  column "tenant_id" { type = uuid; null = false }
  column "key"       { type = varchar(64); null = false }
  column "enabled"   { type = boolean; null = false; default = false }
  column "updated_at"{ type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  unique { columns = [column.tenant_id, column.key] }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.tenant_id] }
}

# Per-tenant payment provider config (dynamic, secure)
table "tenant_provider_secret" {
  schema = schema.public
  column "id"        { type = uuid; null = false }
  column "tenant_id" { type = uuid; null = false }
  column "provider"  { type = varchar(64); null = false }
  column "config_json" { type = jsonb; null = false }
  column "updated_at"{ type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  unique { columns = [column.tenant_id, column.provider] }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.tenant_id] }
}

# Per-tenant dunning policy
table "dunning_config" {
  schema = schema.public
  column "id"           { type = uuid; null = false }
  column "tenant_id"    { type = uuid; null = false }
  column "max_attempts" { type = int; null = false }
  column "retry_intervals" { type = jsonb; null = false } # array of durations
  column "updated_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  unique { columns = [column.tenant_id] }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
}

# Failed payments for dunning tracking
table "failed_payments" {
  schema = schema.public
  column "id"                 { type = uuid; null = false }
  column "invoice_id"         { type = uuid; null = false }
  column "dunning_attempts"   { type = int; null = false }
  column "dunning_state"      { type = varchar(32); null = false }
  column "last_dunning_attempt" { type = timestamptz }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.invoice_id]; ref_table = table.invoices; ref_columns = [table.invoices.column.id]; on_delete = CASCADE }
  index { columns = [column.invoice_id] }
}

# Payment disputes
table "disputes" {
  schema = schema.public
  column "id"         { type = uuid; null = false }
  column "payment_id" { type = uuid; null = false }
  column "tenant_id"  { type = uuid; null = false }
  column "provider"   { type = varchar(64); null = false }
  column "status"     { type = varchar(32); null = false }
  column "reason"     { type = varchar(128) }
  column "amount"     { type = numeric(18,2); null = false }
  column "currency"   { type = varchar(8); null = false }
  column "evidence_due" { type = timestamptz }
  column "evidence_submitted" { type = timestamptz }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.payment_id]; ref_table = table.payment_transactions; ref_columns = [table.payment_transactions.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.tenant_id] }
  index { columns = [column.payment_id] }
}

# Dispute evidence files
table "dispute_evidence" {
  schema = schema.public
  column "id"         { type = uuid; null = false }
  column "dispute_id" { type = uuid; null = false }
  column "tenant_id"  { type = uuid; null = false }
  column "file_url"   { type = text; null = false }
  column "file_name"  { type = varchar(256); null = false }
  column "file_type"  { type = varchar(64); null = false }
  column "uploaded_by"{ type = uuid; null = false }
  column "uploaded_at"{ type = timestamptz; null = false; default = sql("now()") }
  column "provider_status" { type = varchar(32) }
  column "provider_response" { type = text }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.dispute_id]; ref_table = table.disputes; ref_columns = [table.disputes.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.tenant_id] }
  index { columns = [column.dispute_id] }
}

# API usage metering
table "api_usage" {
  schema = schema.public
  column "id"        { type = uuid; null = false }
  column "tenant_id" { type = uuid; null = false }
  column "api_key_id"{ type = uuid; null = false }
  column "endpoint"  { type = varchar(128); null = false }
  column "count"     { type = int; null = false }
  column "period"    { type = timestamptz; null = false }
  column "created_at"{ type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.api_key_id]; ref_table = table.api_keys; ref_columns = [table.api_keys.column.id]; on_delete = CASCADE }
  index { columns = [column.tenant_id] }
  index { columns = [column.api_key_id] }
}

# API keys
table "api_keys" {
  schema = schema.public
  column "id"         { type = uuid; null = false }
  column "tenant_id"  { type = uuid; null = false }
  column "key"        { type = varchar(128); null = false }
  column "secret_hash"{ type = varchar(256); null = false }
  column "status"     { type = varchar(32); null = false }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at" { type = timestamptz; null = false; default = sql("now()") }
  column "last_used_at" { type = timestamptz }
  column "expires_at" { type = timestamptz }
  column "metadata"   { type = jsonb }
  primary_key { columns = [column.id] }
  unique { columns = [column.key] }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.tenant_id] }
}

# API key rotations
table "api_key_rotations" {
  schema = schema.public
  column "id"         { type = uuid; null = false }
  column "api_key_id" { type = uuid; null = false }
  column "tenant_id"  { type = uuid; null = false }
  column "rotated_at" { type = timestamptz; null = false; default = sql("now()") }
  column "actor_id"   { type = uuid; null = false }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.api_key_id]; ref_table = table.api_keys; ref_columns = [table.api_keys.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.tenant_id] }
  index { columns = [column.api_key_id] }
}

# Rate limits
table "rate_limits" {
  schema = schema.public
  column "id"        { type = uuid; null = false }
  column "tenant_id" { type = uuid; null = false }
  column "api_key_id"{ type = uuid }
  column "limit"     { type = int; null = false }
  column "period"    { type = varchar(32); null = false }
  column "created_at"{ type = timestamptz; null = false; default = sql("now()") }
  column "updated_at"{ type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.api_key_id]; ref_table = table.api_keys; ref_columns = [table.api_keys.column.id]; on_delete = SET NULL }
  index { columns = [column.tenant_id] }
  index { columns = [column.api_key_id] }
}

# SLAs
table "slas" {
  schema = schema.public
  column "id"            { type = uuid; null = false }
  column "tenant_id"     { type = uuid; null = false }
  column "uptime_target" { type = numeric(5,2); null = false }
  column "response_time" { type = int; null = false }
  column "support_level" { type = varchar(32); null = false }
  column "created_at"    { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at"    { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.tenant_id] }
}

# Plugins
table "plugins" {
  schema = schema.public
  column "id"         { type = uuid; null = false }
  column "tenant_id"  { type = uuid; null = false }
  column "name"       { type = varchar(64); null = false }
  column "type"       { type = varchar(32); null = false }
  column "config"     { type = jsonb; null = false }
  column "status"     { type = varchar(32); null = false }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at" { type = timestamptz; null = false; default = sql("now()") }
  column "last_used_at" { type = timestamptz }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.tenant_id] }
}

# Webhook subscriptions
table "webhook_subscriptions" {
  schema = schema.public
  column "id"         { type = uuid; null = false }
  column "tenant_id"  { type = uuid; null = false }
  column "url"        { type = text; null = false }
  column "event_types"{ type = jsonb; null = false } # array of event types
  column "secret"     { type = varchar(128); null = false }
  column "status"     { type = varchar(32); null = false }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.tenant_id] }
}

# Tax info
table "tax_info" {
  schema = schema.public
  column "id"        { type = uuid; null = false }
  column "tenant_id" { type = uuid; null = false }
  column "country"   { type = varchar(2); null = false }
  column "region"    { type = varchar(64) }
  column "tax_id"    { type = varchar(64) }
  column "tax_rate"  { type = numeric(5,4); null = false }
  column "currency"  { type = varchar(8); null = false }
  column "created_at"{ type = timestamptz; null = false; default = sql("now()") }
  column "updated_at"{ type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  unique { columns = [column.tenant_id] }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
}

# Exchange rates
table "exchange_rates" {
  schema = schema.public
  column "id"             { type = uuid; null = false }
  column "base_currency"  { type = varchar(8); null = false }
  column "quote_currency" { type = varchar(8); null = false }
  column "rate"           { type = numeric(18,8); null = false }
  column "source"         { type = varchar(64); null = false }
  column "updated_at"     { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  unique { columns = [column.base_currency, column.quote_currency, column.source] }
}

# Tenant currency
table "tenant_currency" {
  schema = schema.public
  column "tenant_id"  { type = uuid; null = false }
  column "currency"   { type = varchar(8); null = false }
  column "updated_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.tenant_id] }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
}

# Tax plugin config
table "tax_plugin_config" {
  schema = schema.public
  column "tenant_id"   { type = uuid; null = false }
  column "plugin_name" { type = varchar(64); null = false }
  column "updated_at"  { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.tenant_id] }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
}

# Indexes for performance and SaaS scale
create index if not exists idx_org_billing_accounts_org_id on org_billing_accounts (org_id);
create index if not exists idx_billing_methods_account_id on billing_methods (account_id);
create index if not exists idx_invoices_account_id on invoices (account_id);
create index if not exists idx_invoices_org_id on invoices (org_id);
create index if not exists idx_invoice_items_invoice_id on invoice_items (invoice_id);
create index if not exists idx_billing_audit_log_org_id on billing_audit_log (org_id);
create index if not exists idx_org_subscriptions_org_id on org_subscriptions (org_id);
create index if not exists idx_org_usage_org_id on org_usage (org_id);
create index if not exists idx_org_credits_org_id on org_credits (org_id);

# Indexes for new tables
create index if not exists idx_payment_transactions_org_id on payment_transactions (org_id);
create index if not exists idx_payment_transactions_account_id on payment_transactions (account_id);
create index if not exists idx_payment_transactions_invoice_id on payment_transactions (invoice_id);
create index if not exists idx_payment_transactions_method_id on payment_transactions (method_id);
create index if not exists idx_payment_transactions_status on payment_transactions (status);
create index if not exists idx_payment_transactions_gateway on payment_transactions (gateway);
create index if not exists idx_refunds_org_id on refunds (org_id);
create index if not exists idx_refunds_transaction_id on refunds (transaction_id);
create index if not exists idx_refunds_status on refunds (status);
create index if not exists idx_refunds_gateway on refunds (gateway);
create index if not exists idx_tax_rates_org_id on tax_rates (org_id);
create index if not exists idx_tax_rates_country_region on tax_rates (country, region);
create index if not exists idx_tax_rates_active on tax_rates (active);
create index if not exists idx_invoice_taxes_invoice_id on invoice_taxes (invoice_id);
create index if not exists idx_invoice_taxes_tax_rate_id on invoice_taxes (tax_rate_id);
create index if not exists idx_pricing_plans_status on pricing_plans (status);
create index if not exists idx_pricing_plans_interval on pricing_plans (interval);
create index if not exists idx_plan_features_plan_id on plan_features (plan_id);
create index if not exists idx_plan_features_feature on plan_features (feature);
create index if not exists idx_discounts_active on discounts (active);
create index if not exists idx_discounts_expires_at on discounts (expires_at);
create index if not exists idx_coupon_redemptions_discount_id on coupon_redemptions (discount_id);
create index if not exists idx_coupon_redemptions_org_id on coupon_redemptions (org_id);
create index if not exists idx_coupon_redemptions_user_id on coupon_redemptions (user_id);
create index if not exists idx_coupon_redemptions_invoice_id on coupon_redemptions (invoice_id);
create index if not exists idx_dunning_events_org_id on dunning_events (org_id);
create index if not exists idx_dunning_events_account_id on dunning_events (account_id);
create index if not exists idx_dunning_events_invoice_id on dunning_events (invoice_id);
create index if not exists idx_dunning_events_event_type on dunning_events (event_type);
create index if not exists idx_billing_webhooks_org_id on billing_webhooks (org_id);
create index if not exists idx_billing_webhooks_event_type on billing_webhooks (event_type);
create index if not exists idx_billing_webhooks_status on billing_webhooks (status);
create index if not exists idx_billing_notifications_org_id on billing_notifications (org_id);
create index if not exists idx_billing_notifications_user_id on billing_notifications (user_id);
create index if not exists idx_billing_notifications_type on billing_notifications (type);
create index if not exists idx_billing_notifications_status on billing_notifications (status);
create index if not exists idx_usage_metering_org_id on usage_metering (org_id);
create index if not exists idx_usage_metering_period on usage_metering (period_start, period_end);
create index if not exists idx_usage_metering_metric on usage_metering (metric);
create index if not exists idx_org_legal_entities_org_id on org_legal_entities (org_id);
create index if not exists idx_org_legal_entities_country_region on org_legal_entities (country, region);

# --- SaaS Billing: Additional Tables for Full Coverage ---

# Manual invoice/account adjustments (admin-initiated, auditable)
table "manual_adjustments" {
  schema = schema.public
  column "id"           { type = uuid; null = false }
  column "invoice_id"   { type = uuid }
  column "account_id"   { type = uuid }
  column "org_id"       { type = uuid; null = false }
  column "amount"       { type = numeric(18,2); null = false }
  column "currency"     { type = varchar(8); null = false }
  column "reason"       { type = varchar(256); null = false }
  column "actor_id"     { type = uuid; null = false }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.invoice_id]; ref_table = table.invoices; ref_columns = [table.invoices.column.id]; on_delete = SET NULL }
  foreign_key { columns = [column.account_id]; ref_table = table.org_billing_accounts; ref_columns = [table.org_billing_accounts.column.id]; on_delete = SET NULL }
  foreign_key { columns = [column.org_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.org_id] }
}

# Manual refunds (admin-initiated, auditable)
table "manual_refunds" {
  schema = schema.public
  column "id"         { type = uuid; null = false }
  column "refund_id"  { type = uuid; null = false }
  column "actor_id"   { type = uuid; null = false }
  column "reason"     { type = varchar(256); null = false }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.refund_id]; ref_table = table.refunds; ref_columns = [table.refunds.column.id]; on_delete = CASCADE }
  index { columns = [column.refund_id] }
}

# Account-level actions (suspend, activate, etc, with audit)
table "account_actions" {
  schema = schema.public
  column "id"         { type = uuid; null = false }
  column "account_id" { type = uuid; null = false }
  column "org_id"     { type = uuid; null = false }
  column "action"     { type = varchar(64); null = false }
  column "params"     { type = jsonb }
  column "actor_id"   { type = uuid; null = false }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.account_id]; ref_table = table.org_billing_accounts; ref_columns = [table.org_billing_accounts.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.org_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.account_id] }
  index { columns = [column.org_id] }
}

# Invoice adjustments (discount, credit, manual, etc)
table "invoice_adjustments" {
  schema = schema.public
  column "id"           { type = uuid; null = false }
  column "invoice_id"   { type = uuid; null = false }
  column "type"         { type = varchar(32); null = false }
  column "amount"       { type = numeric(18,2); null = false }
  column "currency"     { type = varchar(8); null = false }
  column "original_amount" { type = numeric(18,2) }
  column "original_currency" { type = varchar(8) }
  column "reason"       { type = varchar(256) }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at"   { type = timestamptz; null = false; default = sql("now()") }
  column "metadata"     { type = jsonb }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.invoice_id]; ref_table = table.invoices; ref_columns = [table.invoices.column.id]; on_delete = CASCADE }
  index { columns = [column.invoice_id] }
}

# Webhook event logs (for all billing webhooks)
table "webhook_events" {
  schema = schema.public
  column "id"         { type = uuid; null = false }
  column "provider"   { type = varchar(64); null = false }
  column "event_type" { type = varchar(64); null = false }
  column "payload"    { type = jsonb; null = false }
  column "status"     { type = varchar(32); null = false }
  column "received_at"{ type = timestamptz; null = false; default = sql("now()") }
  column "processed_at" { type = timestamptz }
  column "error"      { type = text }
  column "metadata"   { type = jsonb }
  primary_key { columns = [column.id] }
  index { columns = [column.provider] }
  index { columns = [column.event_type] }
}

# Per-tenant payment provider config (non-secret, e.g. settings)
table "tenant_payment_provider_config" {
  schema = schema.public
  column "id"        { type = uuid; null = false }
  column "tenant_id" { type = uuid; null = false }
  column "provider"  { type = varchar(64); null = false }
  column "config"    { type = jsonb; null = false }
  column "updated_at"{ type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  unique { columns = [column.tenant_id, column.provider] }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.tenant_id] }
}

# API key usage (per-key, per-period granularity)
table "api_key_usage" {
  schema = schema.public
  column "id"        { type = uuid; null = false }
  column "api_key_id"{ type = uuid; null = false }
  column "tenant_id" { type = uuid; null = false }
  column "endpoint"  { type = varchar(128); null = false }
  column "count"     { type = int; null = false }
  column "period"    { type = timestamptz; null = false }
  column "created_at"{ type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.api_key_id]; ref_table = table.api_keys; ref_columns = [table.api_keys.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.api_key_id] }
  index { columns = [column.tenant_id] }
}

# SLA events (violations, escalations, etc)
table "sla_events" {
  schema = schema.public
  column "id"         { type = uuid; null = false }
  column "sla_id"     { type = uuid; null = false }
  column "tenant_id"  { type = uuid; null = false }
  column "event_type" { type = varchar(64); null = false }
  column "details"    { type = jsonb }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.sla_id]; ref_table = table.slas; ref_columns = [table.slas.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.sla_id] }
  index { columns = [column.tenant_id] }
}

# Plugin events (execution, errors, audit)
table "plugin_events" {
  schema = schema.public
  column "id"         { type = uuid; null = false }
  column "plugin_id"  { type = uuid; null = false }
  column "tenant_id"  { type = uuid; null = false }
  column "event_type" { type = varchar(64); null = false }
  column "details"    { type = jsonb }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.plugin_id]; ref_table = table.plugins; ref_columns = [table.plugins.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  index { columns = [column.plugin_id] }
  index { columns = [column.tenant_id] }
}

# --- End of SaaS Billing: Final Tables ---

# --- SaaS Billing: Advanced Pricing Tables ---

# Track historical price changes for each plan
table "plan_price_history" {
  schema = schema.public
  column "id"         { type = uuid; null = false }
  column "plan_id"    { type = uuid; null = false }
  column "old_price"  { type = numeric(18,2); null = false }
  column "new_price"  { type = numeric(18,2); null = false }
  column "currency"   { type = varchar(8); null = false }
  column "changed_at" { type = timestamptz; null = false; default = sql("now()") }
  column "actor_id"   { type = uuid }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.plan_id]; ref_table = table.pricing_plans; ref_columns = [table.pricing_plans.column.id]; on_delete = CASCADE }
  index { columns = [column.plan_id] }
}

# Per-tenant plan/feature/price overrides (custom deals, enterprise, etc)
table "tenant_plan_overrides" {
  schema = schema.public
  column "id"         { type = uuid; null = false }
  column "tenant_id"  { type = uuid; null = false }
  column "plan_id"    { type = uuid; null = false }
  column "price"      { type = numeric(18,2) }
  column "currency"   { type = varchar(8) }
  column "features"   { type = jsonb } # map of feature overrides
  column "active"     { type = boolean; null = false; default = true }
  column "created_at" { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at" { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  unique { columns = [column.tenant_id, column.plan_id] }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.plan_id]; ref_table = table.pricing_plans; ref_columns = [table.pricing_plans.column.id]; on_delete = CASCADE }
  index { columns = [column.tenant_id] }
  index { columns = [column.plan_id] }
}

# Per-region/currency price mapping for global SaaS
table "regional_prices" {
  schema = schema.public
  column "id"            { type = uuid; null = false }
  column "plan_id"       { type = uuid; null = false }
  column "region"        { type = varchar(64); null = false }
  column "currency"      { type = varchar(8); null = false }
  column "price"         { type = numeric(18,2); null = false }
  column "active"        { type = boolean; null = false; default = true }
  column "created_at"    { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at"    { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  unique { columns = [column.plan_id, column.region, column.currency] }
  foreign_key { columns = [column.plan_id]; ref_table = table.pricing_plans; ref_columns = [table.pricing_plans.column.id]; on_delete = CASCADE }
  index { columns = [column.plan_id] }
  index { columns = [column.region] }
  index { columns = [column.currency] }
}

# Price book for custom enterprise deals, one-off pricing, etc
table "price_book" {
  schema = schema.public
  column "id"           { type = uuid; null = false }
  column "tenant_id"    { type = uuid; null = false }
  column "plan_id"      { type = uuid; null = false }
  column "price"        { type = numeric(18,2); null = false }
  column "currency"     { type = varchar(8); null = false }
  column "start_date"   { type = timestamptz; null = false }
  column "end_date"     { type = timestamptz }
  column "active"       { type = boolean; null = false; default = true }
  column "created_at"   { type = timestamptz; null = false; default = sql("now()") }
  column "updated_at"   { type = timestamptz; null = false; default = sql("now()") }
  primary_key { columns = [column.id] }
  foreign_key { columns = [column.tenant_id]; ref_table = table.organizations; ref_columns = [table.organizations.column.id]; on_delete = CASCADE }
  foreign_key { columns = [column.plan_id]; ref_table = table.pricing_plans; ref_columns = [table.pricing_plans.column.id]; on_delete = CASCADE }
  index { columns = [column.tenant_id] }
  index { columns = [column.plan_id] }
}

# --- End of SaaS Billing: Advanced Pricing Tables ---