schema "public" {
  comment = "Billing management webhook and event tables for multi-tenant SaaS"
}

table "webhook_subscriptions" {
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
    type = varchar(512)
    null = false
  }
  column "event_types" {
    type = jsonb
    null = false
  }
  column "secret" {
    type = varchar(128)
    null = false
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
  
  primary_key {
    columns = [column.id]
  }
  
  index "idx_webhook_subscriptions_tenant_id" {
    columns = [column.tenant_id]
  }
  
  index "idx_webhook_subscriptions_status" {
    columns = [column.status]
  }
  
  index "idx_webhook_subscriptions_created_at" {
    columns = [column.created_at]
  }
}

table "webhook_events" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "provider" {
    type = varchar(32)
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
  column "received_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  column "processed_at" {
    type = timestamptz
    null = true
  }
  column "error" {
    type = text
    null = true
  }
  column "metadata" {
    type = jsonb
    null = true
  }
  
  primary_key {
    columns = [column.id]
  }
  
  index "idx_webhook_events_provider" {
    columns = [column.provider]
  }
  
  index "idx_webhook_events_event_type" {
    columns = [column.event_type]
  }
  
  index "idx_webhook_events_status" {
    columns = [column.status]
  }
  
  index "idx_webhook_events_received_at" {
    columns = [column.received_at]
  }
}

table "webhook_delivery_logs" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
  }
  column "webhook_id" {
    type = uuid
    null = false
  }
  column "event_type" {
    type = varchar(64)
    null = false
  }
  column "url" {
    type = varchar(512)
    null = false
  }
  column "request_headers" {
    type = jsonb
    null = false
  }
  column "request_body" {
    type = jsonb
    null = false
  }
  column "response_status" {
    type = integer
    null = true
  }
  column "response_headers" {
    type = jsonb
    null = true
  }
  column "response_body" {
    type = text
    null = true
  }
  column "delivery_attempts" {
    type = integer
    null = false
    default = 1
  }
  column "success" {
    type = boolean
    null = false
    default = false
  }
  column "error_message" {
    type = text
    null = true
  }
  column "created_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  column "delivered_at" {
    type = timestamptz
    null = true
  }
  column "next_retry_at" {
    type = timestamptz
    null = true
  }
  column "last_retry_failed_at" {
    type = timestamptz
    null = true
  }
  
  primary_key {
    columns = [column.id]
  }
  
  index "idx_webhook_delivery_logs_webhook_id" {
    columns = [column.webhook_id]
  }
  
  index "idx_webhook_delivery_logs_success" {
    columns = [column.success]
  }
  
  index "idx_webhook_delivery_logs_created_at" {
    columns = [column.created_at]
  }
  
  index "idx_webhook_delivery_logs_next_retry_at" {
    columns = [column.next_retry_at]
    where = "next_retry_at IS NOT NULL"
  }
  
  foreign_key "fk_webhook_delivery_logs_webhook_id" {
    columns     = [column.webhook_id]
    ref_columns = [table.webhook_subscriptions.column.id]
    on_delete   = CASCADE
  }
}

table "audit_logs" {
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
  column "resource" {
    type = varchar(64)
    null = false
  }
  column "target_id" {
    type = uuid
    null = false
  }
  column "details" {
    type = text
    null = true
  }
  column "metadata" {
    type = jsonb
    null = true
  }
  column "hash" {
    type = varchar(128)
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
  
  index "idx_audit_logs_actor_id" {
    columns = [column.actor_id]
  }
  
  index "idx_audit_logs_resource" {
    columns = [column.resource]
  }
  
  index "idx_audit_logs_target_id" {
    columns = [column.target_id]
  }
  
  index "idx_audit_logs_action" {
    columns = [column.action]
  }
  
  index "idx_audit_logs_created_at" {
    columns = [column.created_at]
  }
} 