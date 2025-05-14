# SaaS MVP Launch Roadmap (Usage-Based Billing)

## Goal
Launch a multi-tenant, usage-based billing/subscription SaaS MVP using the existing backend, with Stripe as the primary payment provider. Focus on speed to market and real customer validation.

---

## 1. Backend (Core)
- [x] Multi-tenant architecture (orgs, users, RBAC)
- [x] Payment provider abstraction (Stripe, PayPal, Braintree)
- [x] Billing logic, dunning, disputes, refunds
- [x] Audit logging, notification hooks
- [x] **Usage metering API** (REST endpoint for usage events, aggregation logic)
- [x] **Dunning scheduler/worker** (background job for retries)
- [x] **Stripe webhook handler** (Fiber route, signature validation, event processing: invoice.paid, payment_intent.succeeded, etc.)
- [x] **Automated dunning** (trigger retries, notify users on failed payments)
- [x] **Email notifications** (invoices, failed payments, dunning, onboarding, password reset)

---

## 2. Usage-to-Invoice Automation
- [x] Scheduled job or API endpoint to aggregate usage for each account/plan/period
- [x] Logic to calculate charges using plan/overage pricing
- [x] Create invoice items for each usage metric
- [x] Issue invoices automatically (set status, due date, etc.)
- [x] Trigger payment collection after invoice creation (optional for MVP)

> **Note:** Usage-to-invoice automation is fully implemented, production-grade, and SaaS-ready. The job system is robust, type-safe, and ready for scale.

---

## 3. Stripe Integration
- [x] PaymentIntent, refund, and status flows
- [x] **Stripe webhook handler** (Fiber route, signature validation, event processing: invoice.paid, payment_intent.succeeded, etc.)
- [x] Automated dunning (trigger retries, notify users on failed payments)

---

## 4. Usage Metering
- [x] **REST API for usage events** (API key per tenant)
- [x] **Usage aggregation** (per plan, per customer, per period)
- [x] **Tie usage to invoice generation**
- [ ] Docs and code samples for integration

---

## 5. Self-Serve Onboarding & Admin UI
- [ ] **Signup/login UI** (Next.js, Shadcn, Tailwind)
- [x] **Onboarding wizard** (welcome email, account creation notification)
- [ ] **Admin dashboard** (manage customers, plans, usage, invoices)
- [ ] **Usage analytics** (charts for usage, MRR, churn, etc.)
- [ ] **Plan management UI** (create/edit subscription and usage-based plans)

---

## 6. Notifications
- [x] Email logic in backend
- [x] **Trigger email notifications** (invoices, failed payments, dunning, onboarding, password reset)
- [ ] (Optional) In-app notifications in UI

---

## 7. Docs & Demo
- [ ] **Quickstart guide** (setup, API, Stripe integration)
- [ ] **API docs** (usage metering, payment flows)
- [ ] **Live demo or video walkthrough**
- [ ] **API docs/quickstart** (OpenAPI spec, Swagger UI route)

---

## 8. Landing Page & Pricing
- [ ] **Landing page** (clear value prop, pricing, signup)
- [ ] **Product Hunt/Indie Hackers launch checklist**

---

## 9. Legal & Licensing
- [ ] **Commercial license/EULA** (restrict redistribution, require payment)
- [ ] **Terms of service & privacy policy**

---

## 10. Launch & Feedback
- [ ] Launch MVP (free trial, usage-based pricing)
- [ ] Collect feedback from first users
- [ ] Iterate and improve based on real pain

---

## **Priorities (Do These Next)**
1. Docs, demo, and landing page
2. Self-serve onboarding UI (finish admin dashboard, analytics, plan management UI)
3. Legal/license
4. Launch MVP and collect feedback

---

## **Assignment/Progress Tracking**
- Use this doc to check off completed items and assign tasks.
- Keep all work focused on launch-critical features only.

---

**If you need code snippets, UI wireframes, or launch copy, ask for specifics.** 