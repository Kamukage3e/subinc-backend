rbac-management
Missing:
- [x] Bulk role/permission assignment/removal (batch ops) [P0]
- [x] Role/permission versioning/history (audit trail for changes) [P0]
- [x] Fine-grained resource scoping (hierarchical resources, wildcards, regex) [P1]
- [x] Delegation/impersonation with expiry and audit [P1]
- [x] Policy simulation for "what-if" scenarios (partially present, but not full coverage) [P2]
- [x] RBAC/ABAC policy import/export (for migration/backup) [P1]
- [x] Custom permission templates (predefined sets) [P2]
- [x] API for permission discovery (list all possible actions/resources) [P1]
- [x] Soft delete/restore for roles/policies [P1]
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
- [x] Tax/VAT calculation plugins (region-specific, pluggable)
  - [x] TaxPlugin interface and registry
  - [x] Default and EU VAT plugins
  - [x] Per-tenant plugin config CRUD
  - [x] Endpoints for plugin list/set
  - [x] Invoice creation uses plugin for tax
  - [x] Robust error handling and audit logging
- [x] Invoice PDF generation and download
- [x] Payment provider abstraction (Stripe, PayPal, Braintree, native Google Pay, Apple Pay, card via Braintree)
- [x] Per-tenant runtime config for all payment providers
- [x] All provider API keys/config loaded from DB, never env/static
- [x] Audit logging and error logging for all payment actions
- [x] Provider connection check (runtime, per-tenant)
- [x] Dunning management (automated retries, notifications, audit)
- [x] Dispute/chargeback handling (ingest, persist, list, update, audit, notify)
- [x] Dispute evidence upload/management (provider sync, admin UI, audit, notify) [P0]
- [x] Admin endpoints for dispute management [P0]
- [ ] Webhook ingestion for all providers (Stripe, PayPal, Braintree) [P1]
- [ ] SaaS-specific business logic for payment/dispute flows [P1]
- [ ] Subscription proration, scheduled changes, and metered billing (some present, but not full) [P1]
- [ ] Audit log for all billing actions (not just some) [P1]
- [ ] Webhook event replay/retry [P2]
- [ ] Custom invoice fields (per-tenant branding, notes) [P2]
- [ ] Data export (CSV/JSON for finance ops) [P2]
- [ ] Rate limiting/throttling for billing endpoints [P1]
security-management
Missing:
- [x] Security event streaming (webhooks, SIEM integration) [P0] (webhooks implemented, SIEM future)
- [ ] Custom anomaly detection rules (pluggable, per-tenant) [P1]
- [ ] Security policy versioning and rollback [P1]
- [ ] Device fingerprinting and risk scoring [P2]
- [ ] Self-service security settings (user-facing API for security controls) [P1]
- [ ] API for security event search/filter (not just list) [P1]
- [ ] Notification templates (customizable per tenant) [P2]
- [ ] Security incident workflow (escalation, resolution tracking) [P1]
- [ ] Integration with external identity providers (OIDC/SAML config endpoints) [P1]
- [ ] API for managing security providers/configs (not just get/set) [P1]
user-management
Missing:
- [ ] User import/export (CSV, bulk API) [P1]
- [ ] Advanced search/filter (by role, org, project, status, etc.) [P1]
- [ ] User merge/deduplication [P2]
- [ ] Custom user attributes (schema extension per tenant) [P2]
- [ ] Login as user (impersonation, with audit) [P1]
- [ ] User consent management (GDPR, CCPA) [P1]
- [x] API for password reset/verification flows (token-based, not just admin reset) [P0]
- [ ] API for user lockout/unlock [P1]
- [ ] API for user activity logs (not just sessions) [P1]
- [ ] API for user notification preferences [P2]
tenant-management
Missing:
- [ ] Tenant lifecycle states (pending, active, suspended, deleted) [P0]
- [ ] Tenant-level quotas/limits (API, storage, users, etc.) [P1]
- [ ] Tenant branding (logo, theme, custom domains) [P2]
- [ ] Tenant invite/approval workflow [P1]
- [ ] Tenant data export/delete (compliance, GDPR) [P1]
- [ ] Tenant-level feature flags/toggles [P2]
- [ ] Tenant impersonation (admin can "see as" tenant) [P1]
- [ ] Tenant-level API keys/secrets management [P1]
project-management
Missing:
- [ ] Project archiving/restore (soft delete) [P1]
- [ ] Project-level quotas/limits [P2]
- [ ] Project tags/labels (for search/filter) [P2]
- [ ] Project membership roles (not just user list) [P1]
- [ ] Project activity/audit logs [P1]
- [ ] Project import/export (for migration) [P2]
- [ ] Project-level API keys/secrets [P1]
- [ ] Project template/clone API [P2]
organization-management
Missing:
- [ ] Org hierarchy (parent/child orgs, subsidiaries) [P2]
- [ ] Org-level quotas/limits [P2]
- [ ] Org-wide notification settings [P2]
- [ ] Org-wide audit logs (not just per action) [P1]
- [ ] Org invite/approval workflow [P1]
- [ ] Org branding (logo, theme) [P2]
- [ ] Org-level API keys/secrets [P1]
- [ ] Org data export/delete [P1]
General (cross-cutting, all managements)
- [x] API rate limiting/throttling per tenant/org/user [P0]
- [ ] API versioning and deprecation [P1]
- [ ] Webhook management (subscribe/unsubscribe, delivery logs) [P1]
- [ ] Full audit log search/filter/export [P1]
- [ ] Pluggable event hooks (pre/post action) [P2]
- [ ] Multi-region/data residency controls [P2]
- [ ] API for system health/status [P1]
- [ ] API for admin notifications/messages [P2]
- [ ] API for admin action approval (multi-admin workflows) [P1]
- [ ] API for custom dashboards/metrics (backend only) [P2]

## Next

- Admin endpoints for dispute management [P0]