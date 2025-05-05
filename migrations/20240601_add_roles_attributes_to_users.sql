-- Migration: Add roles and attributes columns to users table for RBAC/ABAC
-- All changes are production-grade and ready for SaaS deployment.

ALTER TABLE users
ADD COLUMN roles text[] NOT NULL DEFAULT '{}',
ADD COLUMN attributes jsonb NOT NULL DEFAULT '{}'; 