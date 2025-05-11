rbac-management
Missing:
- [x] Bulk role/permission assignment/removal (batch ops)
- [x] Role/permission versioning/history (audit trail for changes)
- [x] Fine-grained resource scoping (hierarchical resources, wildcards, regex)
- [x] Delegation/impersonation with expiry and audit
- [x] Policy simulation for "what-if" scenarios (partially present, but not full coverage)
- [x] RBAC/ABAC policy import/export (for migration/backup)
- [x] Custom permission templates (predefined sets)
- [x] API for permission discovery (list all possible actions/resources)
- [x] Soft delete/restore for roles/policies
billing-management
Missing:
- [x] Multi-currency support
  - [x] Currency conversion (exchange rates)
  - [x] Per-tenant currency config
  - [x] Exchange rate CRUD endpoints
  - [x] Multi-currency invoice/payment/credit/refund/adjustment
  - [x] Original amount/currency audit fields
  - [x] Handler/store logic for all affected resources
  - [x] All list/get endpoints return new fields
- [ ] Tax/VAT calculation plugins (region-specific, pluggable)
- [ ] Invoice PDF generation and download
- [ ] Payment provider abstraction (Stripe, PayPal, Adyen, etc. – only Stripe is implied)
- [ ] Dunning management (automated retries, notifications)
- [ ] Dispute/chargeback handling
- [ ] Subscription proration, scheduled changes, and metered billing (some present, but not full)
- [ ] Audit log for all billing actions (not just some)
- [ ] Webhook event replay/retry
- [ ] Custom invoice fields (per-tenant branding, notes)
- [ ] Data export (CSV/JSON for finance ops)
- [ ] Rate limiting/throttling for billing endpoints
security-management
Missing:
- [ ] Security event streaming (webhooks, SIEM integration)
- [ ] Custom anomaly detection rules (pluggable, per-tenant)
- [ ] Security policy versioning and rollback
- [ ] Device fingerprinting and risk scoring
- [ ] Self-service security settings (user-facing API for security controls)
- [ ] API for security event search/filter (not just list)
- [ ] Notification templates (customizable per tenant)
- [ ] Security incident workflow (escalation, resolution tracking)
- [ ] Integration with external identity providers (OIDC/SAML config endpoints)
- [ ] API for managing security providers/configs (not just get/set)
user-management
Missing:
- [ ] User import/export (CSV, bulk API)
- [ ] Advanced search/filter (by role, org, project, status, etc.)
- [ ] User merge/deduplication
- [ ] Custom user attributes (schema extension per tenant)
- [ ] Login as user (impersonation, with audit)
- [ ] User consent management (GDPR, CCPA)
- [ ] API for password reset/verification flows (token-based, not just admin reset)
- [ ] API for user lockout/unlock
- [ ] API for user activity logs (not just sessions)
- [ ] API for user notification preferences
tenant-management
Missing:
- [ ] Tenant lifecycle states (pending, active, suspended, deleted)
- [ ] Tenant-level quotas/limits (API, storage, users, etc.)
- [ ] Tenant branding (logo, theme, custom domains)
- [ ] Tenant invite/approval workflow
- [ ] Tenant data export/delete (compliance, GDPR)
- [ ] Tenant-level feature flags/toggles
- [ ] Tenant impersonation (admin can "see as" tenant)
- [ ] Tenant-level API keys/secrets management
project-management
Missing:
- [ ] Project archiving/restore (soft delete)
- [ ] Project-level quotas/limits
- [ ] Project tags/labels (for search/filter)
- [ ] Project membership roles (not just user list)
- [ ] Project activity/audit logs
- [ ] Project import/export (for migration)
- [ ] Project-level API keys/secrets
- [ ] Project template/clone API
organization-management
Missing:
- [ ] Org hierarchy (parent/child orgs, subsidiaries)
- [ ] Org-level quotas/limits
- [ ] Org-wide notification settings
- [ ] Org-wide audit logs (not just per action)
- [ ] Org invite/approval workflow
- [ ] Org branding (logo, theme)
- [ ] Org-level API keys/secrets
- [ ] Org data export/delete
General (cross-cutting, all managements)
- [ ] API rate limiting/throttling per tenant/org/user
- [ ] API versioning and deprecation
- [ ] Webhook management (subscribe/unsubscribe, delivery logs)
- [ ] Full audit log search/filter/export
- [ ] Pluggable event hooks (pre/post action)
- [ ] Multi-region/data residency controls
- [ ] API for system health/status
- [ ] API for admin notifications/messages
- [ ] API for admin action approval (multi-admin workflows)
- [ ] API for custom dashboards/metrics (backend only)