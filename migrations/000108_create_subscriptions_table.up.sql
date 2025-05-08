-- Subscriptions table for SaaS billing
CREATE TABLE
    IF NOT EXISTS subscriptions (
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
        current_period_start TIMESTAMPTZ,
        current_period_end TIMESTAMPTZ,
        cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
        canceled_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now (),
        metadata JSONB NOT NULL DEFAULT '{}'
    );

CREATE INDEX IF NOT EXISTS idx_subscriptions_account_id ON subscriptions (account_id);