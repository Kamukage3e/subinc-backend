schema "public" {
  comment = "Billing management account tables for multi-tenant SaaS"
}

table "project_billing_accounts" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "project_id" {
    type = uuid
    null = false
  }
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "email" {
    type = varchar(256)
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
    default = "active"
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
  column "updated_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  
  primary_key {
    columns = [column.id]
  }
  
  index "idx_project_billing_accounts_project_id" {
    columns = [column.project_id]
  }
  
  index "idx_project_billing_accounts_tenant_id" {
    columns = [column.tenant_id]
  }
  
  index "idx_project_billing_accounts_status" {
    columns = [column.status]
  }
  
  index "idx_project_billing_accounts_created_at" {
    columns = [column.created_at]
  }
}

table "user_billing_accounts" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "user_id" {
    type = uuid
    null = false
  }
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "email" {
    type = varchar(256)
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
    default = "active"
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
  column "updated_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  
  primary_key {
    columns = [column.id]
  }
  
  index "idx_user_billing_accounts_user_id" {
    columns = [column.user_id]
  }
  
  index "idx_user_billing_accounts_tenant_id" {
    columns = [column.tenant_id]
  }
  
  index "idx_user_billing_accounts_status" {
    columns = [column.status]
  }
  
  index "idx_user_billing_accounts_created_at" {
    columns = [column.created_at]
  }
}

table "organization_billing_accounts" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "org_id" {
    type = uuid
    null = false
  }
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "email" {
    type = varchar(256)
    null = false
  }
  column "status" {
    type = varchar(32)
    null = false
    default = "active"
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
  column "updated_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  
  primary_key {
    columns = [column.id]
  }
  
  index "idx_organization_billing_accounts_org_id" {
    columns = [column.org_id]
  }
  
  index "idx_organization_billing_accounts_tenant_id" {
    columns = [column.tenant_id]
  }
  
  index "idx_organization_billing_accounts_status" {
    columns = [column.status]
  }
  
  index "idx_organization_billing_accounts_created_at" {
    columns = [column.created_at]
  }
}

table "tenant_currencies" {
  schema = schema.public
  column "tenant_id" {
    type = uuid
    null = false
  }
  column "currency" {
    type = varchar(8)
    null = false
    default = "USD"
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

table "exchange_rates" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "base_currency" {
    type = varchar(8)
    null = false
  }
  column "quote_currency" {
    type = varchar(8)
    null = false
  }
  column "rate" {
    type = numeric(18, 8)
    null = false
  }
  column "source" {
    type = varchar(32)
    null = false
  }
  column "updated_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  
  primary_key {
    columns = [column.id]
  }
  
  unique "idx_exchange_rates_currency_pair" {
    columns = [column.base_currency, column.quote_currency]
  }
  
  index "idx_exchange_rates_base_currency" {
    columns = [column.base_currency]
  }
  
  index "idx_exchange_rates_quote_currency" {
    columns = [column.quote_currency]
  }
  
  index "idx_exchange_rates_updated_at" {
    columns = [column.updated_at]
  }
} 