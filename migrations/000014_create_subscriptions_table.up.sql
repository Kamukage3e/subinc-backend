-- Subscriptions table for SaaS billing
CREATE TABLE
    subscriptions (
        id UUID PRIMARY KEY,
        account_id UUID NOT NULL REFERENCES billing_accounts (id) ON DELETE CASCADE,
        plan_id UUID NOT NULL,
        status TEXT NOT NULL CHECK (
            status IN (
                'active',
                'trialing',
                'canceled',
                'grace',
                'dunning',
                'past_due',
                'scheduled',
                'expired'
            )
        ),
        trial_start TIMESTAMPTZ,
        trial_end TIMESTAMPTZ,
        current_period_start TIMESTAMPTZ NOT NULL,
        current_period_end TIMESTAMPTZ NOT NULL,
        cancel_at TIMESTAMPTZ,
        canceled_at TIMESTAMPTZ,
        grace_period_end TIMESTAMPTZ,
        dunning_until TIMESTAMPTZ,
        scheduled_plan_id UUID,
        scheduled_change_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        metadata TEXT
    );

CREATE INDEX idx_subscriptions_account_id ON subscriptions (account_id);

CREATE INDEX idx_subscriptions_plan_id ON subscriptions (plan_id);

CREATE INDEX idx_subscriptions_status ON subscriptions (status);