table "security_audit_logs" {
  schema = schema.public
  column "id" {
    type = varchar(36)
    null = false
  }
  column "user_id" {
    type = varchar(36)
    null = false
  }
  column "actor_id" {
    type = varchar(36)
    null = false
  }
  column "action" {
    type = varchar(64)
    null = false
  }
  column "resource" {
    type = varchar(128)
    null = true
  }
  column "resource_id" {
    type = varchar(36)
    null = true
  }
  column "ip" {
    type = varchar(45)
    null = true
  }
  column "user_agent" {
    type = text
    null = true
  }
  column "created_at" {
    type = timestamptz
    null = false
    default = sql("CURRENT_TIMESTAMP")
  }
  column "details" {
    type = text
    null = true
  }
  
  primary_key {
    columns = [column.id]
  }
  
  index "idx_security_audit_logs_user_id" {
    columns = [column.user_id]
  }
  
  index "idx_security_audit_logs_actor_id" {
    columns = [column.actor_id]
  }
  
  index "idx_security_audit_logs_action" {
    columns = [column.action]
  }
  
  index "idx_security_audit_logs_resource" {
    columns = [column.resource]
  }
  
  index "idx_security_audit_logs_created_at" {
    columns = [column.created_at]
  }
}

// Extension for TimescaleDB
sql {
  engine = "postgresql"
  schema = schema.public
  
  // Add TimescaleDB extension
  query = <<-SQL
    CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
    
    -- Convert security_audit_logs table to hypertable
    SELECT create_hypertable('security_audit_logs', 'created_at', 
      chunk_time_interval => interval '1 month',
      if_not_exists => TRUE
    );
    
    -- Create a retention policy (90 days for example, adjust as needed)
    SELECT add_retention_policy('security_audit_logs', 
      INTERVAL '90 days',
      if_not_exists => TRUE
    );
    
    -- Create a compression policy for older data
    SELECT add_compression_policy('security_audit_logs', 
      INTERVAL '7 days',
      if_not_exists => TRUE
    );
  SQL
}

// Add appropriate access policy
sql {
  engine = "postgresql"
  schema = schema.public
  
  query = <<-SQL
    -- Make sure audit logs can't be modified or deleted
    CREATE OR REPLACE RULE security_audit_logs_no_update AS
      ON UPDATE TO security_audit_logs
      DO INSTEAD NOTHING;
      
    CREATE OR REPLACE RULE security_audit_logs_no_delete AS
      ON DELETE TO security_audit_logs
      DO INSTEAD NOTHING;
  SQL
} 