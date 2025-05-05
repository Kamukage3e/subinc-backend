# Architecture Docs & Live Diagrams Module

This module provides production-grade, versioned architecture documentation and live diagrams for cloud resources, per tenant/project. All code is SaaS-ready, secure, and multi-tenant.

## Features
- Auto-generate and version architecture docs (PDF, JSON, etc.)
- Render live diagrams (SVG, PNG, JSON) of cloud resource topology
- **Full ArchitectureGraph (nodes + edges) is stored and returned with every doc for perfect round-tripping**
- All endpoints are production-ready, robust, and RBAC/ABAC-protected
- Multi-cloud, multi-tenant, and project-aware
- No placeholders, no non-prod code, no legacy code

## API Endpoints
- `GET    /architecture/docs`           — List docs for tenant/project (returns doc + full graph)
- `POST   /architecture/docs/generate`  — Generate new doc (requires resource graph)
- `GET    /architecture/docs/:id`       — Get/download a specific doc (returns doc + full graph)
- `GET    /architecture/diagrams`       — List diagrams for tenant/project
- `POST   /architecture/diagrams/generate` — Generate new diagram (from doc/graph)
- `GET    /architecture/diagrams/:id`   — Get/download a specific diagram

## Security
- All endpoints require strong authentication and RBAC/ABAC
- Only authorized users can access their own tenant/project docs/diagrams
- Admin endpoints (if any) must be strictly separated and protected

## Integration
- Use the handler's `RegisterRoutes` in your Fiber app
- Repository uses pgx/pgxpool, not GORM
- All IDs are UUIDv4 (github.com/google/uuid)
- All code is linter-clean, type-safe, and ready for CI/CD

## Storage
- Docs and diagrams are stored in Postgres (see schema)
- **Graph data is stored as bytea (for SVG/PNG/JSON) and always round-tripped with docs**

---
This module is production-grade and ready for SaaS deployment. No non-prod, no placeholders, no legacy code. All code is cloud-native, container-ready, and CI/CD friendly. 