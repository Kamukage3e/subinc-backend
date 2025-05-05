CREATE TABLE
    IF NOT EXISTS subscriptions (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL,
        plan_id TEXT NOT NULL,
        status TEXT NOT NULL,
        trial_start TIMESTAMPTZ,
        trial_end TIMESTAMPTZ,
        current_period_start TIMESTAMPTZ,
        current_period_end TIMESTAMPTZ,
        cancel_at TIMESTAMPTZ,
        canceled_at TIMESTAMPTZ,
        grace_period_end TIMESTAMPTZ,
        dunning_until TIMESTAMPTZ,
        scheduled_plan_id TEXT,
        scheduled_change_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        metadata JSONB NOT NULL DEFAULT '{}'
    );

CREATE INDEX IF NOT EXISTS idx_subscriptions_account_id ON subscriptions (account_id);

CREATE INDEX IF NOT EXISTS idx_subscriptions_plan_id ON subscriptions (plan_id);

CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions (status);