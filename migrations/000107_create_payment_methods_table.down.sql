-- Drop payment_methods table and index
DROP INDEX IF EXISTS idx_payment_methods_account_id;

DROP TABLE IF EXISTS payment_methods;