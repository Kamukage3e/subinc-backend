# Billing Management Documentation

## API
- All endpoints are defined in `openapi.yaml` (OpenAPI 3.1)
- Endpoints: /invoices (GET, POST), /invoices/{invoiceId} (GET), /features (GET)
- All endpoints are RBAC-protected, JWT-secured, and auditable

## Migrations
- All schema migrations are in `../migration/`
- Tables: invoices, invoice_items, billing_feature_flags
- All tables are multi-tenant, type-safe, and production-grade

## OpenAPI
- See `openapi.yaml` for full schema, request/response types, and error handling

## Enforcement
- No placeholders, no bloat, no non-prod content
- All code and docs are production-grade, real, and ready for SaaS deployment 