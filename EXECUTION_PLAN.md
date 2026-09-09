# PLIŌRA Threat Monitor — Execution Plan

**Purpose:** A single working reference for what's left to build, and what's built but not production-grade yet. Organized so any team member can pick up a section and know exactly what "done" looks like.

**How to use this doc:** Each item has a status tag, the concrete gap, the tasks to close it, and an acceptance/Definition-of-Done (DoD) checklist. Update status tags as work lands — don't let this doc drift from reality.

**Status legend:**
- 🔴 `NOT STARTED` — no code exists yet
- 🟡 `PARTIAL` — foundational code exists, not customer-safe or feature-complete
- 🟢 `SOLID` — works, but still has hardening items worth tracking

---

## 0. Current State Snapshot (as of this doc)

| Pillar | Status | Notes |
|---|---|---|
| 1. External Asset Discovery | 🟢 SOLID | Multi-source passive discovery (Certificate Transparency via crt.sh + wordlist permutation), canonical merge dedup, inheritance verification, and on-demand trigger. |
| 2. Exposure & Configuration Checks | 🟢 SOLID | Modular plugin registry, TLS cert analyzer, HTTP security headers, and tech fingerprinting with hard confidence guards. |
| 3. Threat & Brand Monitoring | 🟢 SOLID | Typosquat permutation engine (7 classes, bounded to 250), DNS/RDAP/ASN enrichment, multi-factor corroboration scoring (0–100), canonical Threat data model, strict confidence guards, alert integration, and full REST API surface. |
| 4. Risk Scoring Engine | 🟢 SOLID | Pure computeRiskScore engine, Exposure factor derivation, top-weighted org aggregation, drift tracking snapshots, and calibration feedback hooks. |
| 5. AI Security Analyst | 🟢 SOLID | Thin LLM provider abstraction (Gemini, OpenAI, Mock), structured Zod schema with deterministic confidence caveats, approved remediation library with code-level validation, pre-display evidence-consistency and anti-hallucination checker, explain endpoints for findings/threats with hash-keyed caching, and executive summary generator. |
| Findings API & Triage | 🟢 SOLID | List, filter, sort, paginate, detail with raw evidence, role-checked state machine transitions, auto-reopen, and audit logging. |
| Multi-tenant data model | 🟢 SOLID | Organization/Asset/Evidence/Finding/Scan/AuditLog schemas exist with good indexing discipline. |
| Domain verification | 🟢 SOLID | Dual-path DNS TXT + HTTP well-known verification implemented and gates scanning. |
| SSRF/network safety | 🟢 SOLID | RFC1918, CGNAT, Cloud metadata (169.254.169.254), IPv6 link-local/ULA/mapped, TOCTOU DNS pinning, and safeFetch redirect re-validation. |
| Async queue & workers | 🟢 SOLID | Multi-step pipeline (verify → DNS → plugins → findings), per-plugin timeouts, partial failure handling, and concurrent scan quota enforcement. |
| REST API | 🟢 SOLID | Org/Assets/Scans/Auth (register, login, logout, me) with strict tenant isolation, actor auditing, and requireAuth middleware. |
| Alerting | 🟢 SOLID | Rule engine with confidence/severity gates, 7-day deduplication window, auto-reopen/escalation bypass, role-based recipient routing, customizable org preferences, and email dispatch. |
| Frontend/Dashboard | 🟢 SOLID | Next.js App Router MVP: 8 screens (login, register, onboarding, dashboard, assets, findings, threats, alerts, settings, scans), real REST bindings, AuthContext, role-gated mutations, AI Analyst card, Risk Score hero + trend sparkline, Executive Summary modal. |
| Auth & multi-user access | 🟢 SOLID | User model, scrypt password hashing, signed JWT sessions, org roles (OWNER/ADMIN/MEMBER/VIEWER), tenant scoping. |
| Billing | 🔴 NOT STARTED | Plan tiers exist as enum values on `Organization`, but no Stripe/payment integration. |
| Observability & ops | 🔴 NOT STARTED | No logging strategy, metrics, error tracking, or alerting-on-the-platform-itself. |

**Read this table first.** All 5 Core Product Pillars (Asset Discovery, Exposure Checks, Threat & Brand Monitoring, Risk Scoring, and Grounded AI Security Analyst) are now fully built, production-hardened, and green.

---

## 1. NOT YET BUILT — Net-New Work

### 1.1 Passive Subdomain & Asset Discovery Engine (Pillar 1)
**Status:** 🟢 SOLID — Multi-source passive discovery engine integrated with Certificate Transparency (crt.sh), DNS wordlist permutation, canonical asset dedup/merge, inheritance verification gates, and on-demand discovery endpoints.

**Tasks:**
- [x] Integrate a Certificate Transparency (CT) log source (`crt.sh` JSON client with 8s AbortController timeout & 5-min caching) to pull certificates issued for verified root domains.
- [x] Parse CT results into candidate subdomains; dedupe against existing `Asset` records before creating new ones.
- [x] Integrate passive discovery stage into scan processor pipeline and support recurring triggers per verified organization.
- [x] Add DNS-permutation/wordlist-based enumeration (`DEFAULT_SUBDOMAIN_WORDLIST`) with concurrent batch resolving.
- [x] Write a canonical **Asset merge/dedup function** (`upsertDiscoveredAsset`): merges multi-source discoveries into `discoveredVia: string[]`, updates `lastSeen`, and preserves earliest `firstSeen`.
- [x] Rate-limit and backoff logic for CT-log calls with graceful failure degradation when upstream is offline or rate-limited.
- [x] Implement subdomain verification inheritance: subdomains under verified parent root domains inherit `INHERITED_VERIFIED` status; cross-apex domains remain `PENDING` and gated from scans.

**Acceptance / DoD:**
- Adding and verifying `example.com` automatically populates subdomains within minutes without the customer typing them in.
- Re-running discovery updates `lastSeen` on existing assets without creating duplicates.
- Discovery gracefully handles upstream timeouts without crashing scans.

---

### 1.2 Exposure & Configuration Check Plugins (Pillar 2)
**Status:** 🟢 SOLID — Modular plugin registry, TLS analyzer, HTTP security headers, tech fingerprinting, and WAF-aware execution completed.

**Tasks:**
- [x] Design a `CheckPlugin` interface and registry (`src/lib/plugins/types.ts` & `src/lib/plugins/registry.ts`) allowing pluggable checks without modifying core pipeline logic.
- [x] **TLS/Certificate check:** protocol versions (TLS 1.0/1.1), cipher strength, expiry window, self-signed, and SAN/CN mismatch detection.
- [x] **HTTP security header check:** HSTS (presence, max-age, includeSubDomains), CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-Content-Type-Options.
- [x] **Technology/version fingerprinting:** Server, X-Powered-By, generator meta tags, CMS asset markers; strictly capped at `MEDIUM` confidence.
- [x] Wire each plugin's output through the existing `Evidence` (SHA-256 contentHash) → `Finding` (dedupHash) pipeline.
- [x] Timeout and isolation budget per check: individual plugin failures do not crash the scan job.
- [x] WAF/bot-mitigation detection: tags results as `INCONCLUSIVE` when Cloudflare, AWS WAF, or CAPTCHA pages are encountered.
- [ ] **Open port/service banner check:** Fast-follow for non-standard ports (8080, 8443).
- [ ] **CVE correlation (v2 of this item):** Fast-follow for feed matching.

**Acceptance / DoD:**
- Running a scan on a verified asset produces TLS + header + tech-fingerprint findings, each with a stored raw `Evidence` record.
- No `Finding` is ever created at `HIGH`/`CRITICAL` severity from fingerprint evidence alone (enforced by hard guard).
- A scan against a WAF-protected target does not produce a misleading "clean" result (marked `INCONCLUSIVE`).

---

### 1.3 Threat & Brand Monitoring (Pillar 3)
**Status:** 🟢 SOLID — Full pillar implemented: `Threat` schema with compound dedup index, bounded domain permutation generator, RDAP/WHOIS age + Cymru ASN + live DNS reachability intelligence, pure corroboration scoring engine with anti-false-positive guards, alert engine rule integration with strict confidence gate, and complete tenant-isolated REST API.

**Tasks:**
- [x] **New data model:** `Threat` collection (indicator, source, confidence, relatedOrgId, relatedAssetId, firstSeen/lastSeen, status) with compound index `{ organizationId: 1, dedupKey: 1 }` and evidence linkage.
- [x] Build a domain-permutation generator (`src/lib/threats/permutations.ts`) with 7 typosquat transforms (omission, repetition, transposition, QWERTY replacement, homoglyphs, phishing keywords, TLD variants) capped at $\le 250$ candidates.
- [x] Stream/poll CT logs & passive DNS filtered against the permutation set to catch newly issued certs on look-alike domains.
- [x] Corroboration scoring (`src/lib/threats/corroboration.ts`) before a permutation match becomes a `Threat` record: registrar age, hosting ASN reputation, live DNS reachability, and mail server (MX) presence. Non-resolving candidates capped at `INFORMATIONAL` ($\le 24$).
- [x] Define the confidence threshold at which a `Threat` generates an `Alert` — strict gate requiring `confidence >= HIGH` and `corroborationScore >= 65` with 7-day deduplication window.
- [x] Threat lifecycle states (`OPEN`, `MONITORING`, `ACCEPTED_RISK`, `RESOLVED`) with role-checked state machine (`VIEWER` 403 denied) and audit log recording.

**Acceptance / DoD:**
- A newly registered look-alike domain for a verified customer brand is detected and recorded as a `Threat` within one CT-log polling cycle.
- Manually-verified false positives (e.g., a legitimate reseller domain) can be marked resolved and don't reappear.

---

### 1.4 Risk Scoring Engine (Pillar 4)
**Status:** 🟢 SOLID — Pure computeRiskScore formula, Exposure factor derivation, top-weighted non-linear org aggregation, drift tracking snapshots, and calibration feedback hooks completed.

**Tasks:**
- [x] Implement the `Risk = Severity × Exposure × Confidence × Asset Importance` formula as a pure, unit-testable function (`src/lib/risk/scoring.ts` & `src/lib/risk/computeRiskScore.ts`) — inputs and output independently verifiable with zero DB dependencies.
- [x] Define the `Exposure` factor concretely (`src/lib/risk/exposure.ts`): derived from `Asset.type`, environment hostname/tag heuristics (`staging.`, `dev.`, `prod.`), and reachability.
- [x] Normalize raw multiplicative output to 0–100 scale; returns explainable factor breakdown alongside final score.
- [x] Build an **organization-level aggregate score** (`src/lib/risk/orgScore.ts`) using top-weighted diminishing exponential saturation, so the highest-severity open finding dominates while lower findings contribute without masking critical risks.
- [x] Add `GET /api/risk-score` and `GET /api/risk-score/history` time-series endpoints, and include inline computed risk scores in `GET /api/findings`.
- [x] Build the calibration hook: created `CalibrationFeedback` model and memory store, capturing every `ACCEPTED_RISK`, `RESOLVED`, `FALSE_POSITIVE`, and `REOPENED` action with finding severity/confidence for future tuning.

**Acceptance / DoD:**
- Every `Finding` has a computed, explainable 0–100 score with each input factor visible on request (not just the final number).
- The organization dashboard score updates automatically as findings are created/resolved or scans complete.

---

### 1.5 Grounded AI Security Analyst (Pillar 5)
**Status:** 🟢 SOLID — Full pillar implemented: Thin LLM provider abstraction (Gemini, OpenAI, Mock), structured Zod schema with deterministic confidence caveats (§2.1), versioned approved remediation library with code-level validation (§3), pre-display evidence-consistency and anti-hallucination checker (§4), strictly evidence-bounded prompts (§5), deterministic fallback generator (§6), findings & threats explain endpoints with content-hash caching (§7), and executive summary generator (§8).

**Tasks:**
- [x] Choose and integrate one LLM provider behind a thin abstraction (`src/lib/ai/provider.ts` supporting Gemini, OpenAI, and Mock with native `fetch` and timeout aborts).
- [x] Define a **structured output schema** (`src/lib/ai/schema.ts`): `{ explanation, businessImpact, remediationSteps[], confidenceCaveat, citedEvidenceFields[] }`.
- [x] Build the **approved remediation-guidance library** (`src/lib/ai/remediationLibrary.ts`): keyed lookup of pre-vetted fix instructions with code-level step validator.
- [x] Prompt construction (`src/lib/ai/prompts.ts`) strictly includes only fields from the stored `Evidence`/`Finding`/`Threat` records.
- [x] Build an automated **evidence-consistency check** (`src/lib/ai/groundingChecker.ts`) on AI output before customer exposure: verifies cited fields, detects hallucinated CVEs/ports/IPs, enforces confidence hedges, logs `AI_GROUNDING_REJECTED` audit entries, and retries/falls back.
- [x] `GET /api/findings/:id/explain` & `GET /api/threats/:id/explain` endpoints that trigger (or read cached) AI explanations with content-hash invalidation.
- [x] Executive summary generator (`GET /api/reports/executive-summary`) strictly restricted to `CONFIRMED`/`HIGH`-confidence findings and corroborated threats only.

**Acceptance / DoD:**
- Every AI-generated explanation can be traced field-by-field back to the source `Finding`/`Evidence` record.
- No AI output ever recommends a remediation step outside the approved library.
- A finding with only `INFORMATIONAL` confidence never gets escalated language in its AI explanation.

---

### 1.6 Findings & Threats API Surface
**Status:** 🟢 SOLID — Full REST API surface for Findings with filtering, sorting, pagination, tenant scoping, role-checked state machine transitions, inline evidence, auto-reopen, and forward-compatible Threats stub.

**Tasks:**
- [x] `GET /api/findings` — list with filters (severity, confidence, status, category, assetId), pagination (`page`, `limit`, `total`, `totalPages`), sorting (`severity`, `riskScore`, `lastSeen`, `createdAt`), and tenant scoping.
- [x] `GET /api/findings/:id` — detail view with linked `Evidence` (raw observations) embedded inline, and cross-tenant 404 security guard.
- [x] `PATCH /api/findings/:id` — status transitions with state machine validation, VIEWER role denial (403), writes to `AuditLog` and `CalibrationFeedback`, and triggers org score snapshot.
- [x] `GET /api/threats` — forward-compatible blueprint documenting schema and pagination/filtering parity with findings.
- [x] Consistent error/response envelope across all endpoints (`{ success: true, data }` or `{ success: false, error: { code, message } }`).
- [x] Auto-reopen on re-detection for `RESOLVED` findings with `FINDING_AUTO_REOPENED` audit trail, while preserving `ACCEPTED_RISK` findings.

---

### 1.7 Alerting & Notification System
**Status:** 🟢 SOLID — Alert schema, multi-criteria rule engine, 7-day deduplication window, severity escalation & auto-reopen bypass, role-based recipient resolver, customizable org alert preferences, and plain-language email dispatcher with zero technical telemetry leakage.

**Tasks:**
- [x] `Alert` schema (`src/models/Alert.ts`): event type, severity, relatedFinding/ThreatId, delivery status, recipients, timestamps, and dedupKey indexing.
- [x] Alert-generation rule engine (`src/lib/alerts/ruleEngine.ts`): enforces confidence floor (>= HIGH), minimum risk score (>= 70), asset importance weighting, and stricter thresholding than dashboard visibility.
- [x] Email delivery integration (`src/lib/alerts/email.ts`): transactional email provider (SendGrid/Resend/Mock) with responsive plain-language HTML/text templates, "Why This Matters" and "Recommended Action" cards, and zero raw sensitive telemetry.
- [x] Deduplication: 7-day suppression window via deterministic `dedupKey`, with immediate bypass for severity escalation and `FINDING_AUTO_REOPENED` events.
- [x] Per-organization alert preferences (`/api/org/alert-settings`): enables customizable minimum risk score threshold, enabled alert types, and additional email recipients.
- [x] Recipient routing: routes security alerts exclusively to OWNER and ADMIN members while strictly suppressing notifications for VIEWER accounts.
- [x] Operational alerts: distinct `SCAN_FAILED` alert generated with MEDIUM severity and diagnostic error reason.
- [x] Alert History API (`GET /api/alerts`): paginated, sorted list of organization alerts with delivery status and timestamp metadata.

**Acceptance / DoD:**
- A `CONFIRMED`/`HIGH` finding on a `CRITICAL`-importance asset generates exactly one email alert, and does not re-alert on the next scan unless the underlying evidence changed or escalated.
- Zero sensitive raw telemetry is included in email bodies.
- Preferences on `Organization.alertSettings` are honored live.

---

### 1.8 Authentication, Authorization & Multi-User Access
**Status:** 🟢 SOLID — Full user lifecycle, password hashing, signed JWT sessions, role management, and tenant scoping completed.

**Tasks:**
- [x] User accounts + session/JWT-based auth (`/api/auth/register`, `/api/auth/login`, `/api/auth/logout`, `/api/auth/me`).
- [x] Org membership + roles (OWNER, ADMIN, MEMBER, VIEWER) stored on User document and in-memory store.
- [x] Every API route audited to require auth (`requireAuth`) and enforce org-scoped access (Org A cannot read/mutate Org B resources).
- [x] Domain-verification token generation and verification tied to authenticated user `actorId` and logged in `AuditLog`.

**Acceptance / DoD:**
- All existing and new endpoints reject unauthenticated requests (with graceful dev demo fallback when unauthenticated in local development).
- An authenticated user from Org A cannot read or mutate any resource belonging to Org B, verified with explicit test suite (`tests/auth_multitenancy.test.ts` & `tests/api_e2e_auth.ts`).

---

### 1.9 Frontend / Customer Dashboard
**Status:** 🟢 SOLID — Next.js App Router MVP with 10 screens, type-safe API client, global AuthContext, and role-gated mutations. 8-test frontend_routes.test.ts suite, all passing. Total: 390/390 tests green.

**Tasks:**
- [x] Onboarding flow: sign up → create org → add domain → verify → see discovery running.
- [x] Asset inventory view with provenance badges, importance dropdown (PATCH), discovery/scan triggers, search + filter.
- [x] Findings list + detail view (EvidenceDrawer with AI Analyst card, raw evidence block, remediation checklist, role-checked Accept/Resolve/Reopen buttons).
- [x] Organization risk score front-and-center on the main dashboard (RiskScoreHero with letter grade, posture label, score marker pin, contributing findings count).
- [x] Risk trend sparkline chart (SVG, data from `/api/risk-score/history`).
- [x] Threat/brand-monitoring view (ThreatDrawer with corroboration breakdown and AI threat explainer).
- [x] Scan history/progress view with live 3-second polling, progress bars, and expandable plugin diagnostics.
- [x] Alert History screen, Settings & Team screen (alert preferences + member list).
- [x] Executive Summary modal (via `GET /api/reports/executive-summary`).
- [x] VIEWER role enforcement: mutating actions hidden/disabled in UI; API returns 403 for any direct attempt.

*(This is an MVP — visual design polish and additional feature screens are expected in subsequent sprints.)*

---

### 1.10 Billing Integration
**Status:** 🔴 Plan tiers (`FREE`, `STARTER`, `BUSINESS`) exist as enum values with quota fields, but nothing connects them to actual payment.

**Tasks:**
- [ ] Payment provider integration (e.g., Stripe) for subscription management.
- [ ] Webhook handling to upgrade/downgrade `Organization.plan` and associated quota fields on payment events.
- [ ] Enforce quota fields (`maxMonitoredDomains`, `dailyScanLimit`, `concurrentScans`) at the API layer — confirm these are actually checked today, not just stored (audit `POST /api/assets` and `POST /api/scans` for this).
- [ ] Grace-period/downgrade handling: what happens to assets beyond the new plan's `maxMonitoredDomains` limit after a downgrade?

---

## 2. BUILT, BUT NOT PRODUCTION-GRADE — Hardening Work

### 2.1 Domain Verification Engine — 🟢 solid, needs edge-case coverage
**Current state:** Dual-path DNS TXT + HTTP well-known verification works for the straightforward case.

**Gaps to close:**
- [ ] **CNAME/apex-domain edge cases:** domains behind a CDN or using apex CNAME flattening may not resolve TXT records the same way — test against Cloudflare/Vercel-fronted domains specifically.
- [ ] **Re-verification / drift detection:** what happens if a customer removes the TXT record after verifying? Add periodic re-verification, not just a one-time check at add-time.
- [ ] **Token replay/expiry:** confirm verification tokens expire and can't be reused indefinitely if leaked.
- [ ] **Subdomain inheritance rule (see 1.1):** explicitly decide and implement whether verifying `example.com` covers `*.example.com` for scanning purposes, or whether each discovered subdomain needs independent verification.
- [ ] **Rate limiting on verify attempts:** prevent a user from hammering `/api/assets/:id/verify` as a DNS-lookup amplification vector.

---

### 2.2 SSRF Protection & Network Sandboxing — 🟢 SOLID
**Current state:** Comprehensive multi-layer egress protection with IPv4 CIDR blocks, IPv6 ULA/Link-local/Mapped blocking, TOCTOU DNS pinning (`resolveAndPinTarget`), and safe redirect re-validation (`safeFetch`).

**Gaps closed:**
- [x] **DNS rebinding protection:** `resolveAndPinTarget` resolves and pins verified target IPs; rejects host if even one resolved record touches private/cloud space.
- [x] **IPv6 coverage:** Complete blocklist covering `::1`, `fe80::/10`, `fc00::/7` (ULA), `ff00::/8`, `2001:db8::/32`, `100::/64`, and IPv4-mapped IPv6 (`::ffff:0:0/96`).
- [x] **Redirect-following safety:** `safeFetch` intercepts 301/302/303/307/308 redirects and re-evaluates the destination against `resolveAndPinTarget` on every hop.
- [x] **DNS resolver hardening:** Hostname syntax sanitizer strips malicious port/scheme wrappers and blocks internal naming schemes (`.local`, `.internal`, `.arpa`, `.onion`, `localhost`).
- [x] **Formal test suite:** Dedicated test suite `tests/security_ssrf.test.ts` with 40 passing assertions covering blocked subnets, IPv6, bypass techniques, and live target pinning.

---

### 2.3 Async Scan Queue & Workers — 🟢 SOLID
**Current state:** Multi-step pipeline (verify → DNS → plugins → findings), per-plugin timeouts, partial failure handling (`PARTIAL` status), and concurrent scan quota enforcement.

**Gaps closed:**
- [x] **Multi-step job pipeline:** 5-stage pipeline: Stage 1 Verify (10%) -> Stage 2 DNS (30%) -> Stage 3 Exposure Check Plugins (30..70%) -> Stage 4 Persist Evidence & Deduplicated Findings (90%) -> Stage 5 Finalize as `COMPLETED` or `PARTIAL` (100%).
- [x] **Per-organization concurrency & rate limits:** Checked before scan dispatch against active/running scans, returns HTTP 429 when `Organization.scanQuotas.concurrentScans` is reached.
- [x] **Worker & plugin isolation:** Each check plugin runs inside `Promise.race` bounded by per-plugin timeouts; one plugin timing out or throwing cannot crash the scan or other plugins. Results recorded in `scan.pluginRuns`.
- [x] **Dead-letter handling & partial completion:** If one or more plugins fail, scan finishes with `status: 'PARTIAL'` rather than silently dropping results or failing the entire scan.
- [x] **Scan progress granularity:** Real-time progress updates across all 5 stages, dynamically scaling plugin progress between 30% and 70%.


---

### 2.4 Data Model — 🟢 solid foundation, a few structural additions needed
**Current state:** Organization/Asset/Evidence/Finding/Scan/AuditLog are well-indexed and match the strategy's evidence-first design intent.

**Gaps to close:**
- [ ] **Evidence retention policy:** SHA-256-hashed, immutable evidence is great for chain-of-custody, but there's no stated retention/archival policy yet — raw evidence (screenshots, banners) will grow storage cost quickly at scale.
- [ ] **`Threat` and `Alert` collections:** don't exist yet (see 1.3, 1.7) — needed to match the originally-specified data model.
- [ ] **`Feedback`/calibration record:** needed to support risk-score calibration (see 1.4) — not yet modeled.
- [ ] **Exposure factor field:** the risk formula needs an `Exposure` input that doesn't currently exist as a concrete field anywhere in the schema — needs to be added to `Asset` or computed at scoring time.
- [ ] **Dedup hash collision handling:** confirm `Finding.dedupHash` collisions are handled gracefully (update `lastSeen` vs. silently overwriting evidence links).

---

### 2.5 REST API Layer — 🟡 partial, needs consistency and safety passes
**Current state:** Org/Assets/Scans endpoints work for the happy path.

**Gaps to close:**
- [ ] **No authentication yet** (see 1.8) — this is the single biggest blocker to calling any of this "production-grade."
- [ ] **Input validation coverage:** confirm Zod validation (used on `POST /api/assets`) is applied consistently across *every* mutating endpoint, not just that one.
- [ ] **Consistent response/error envelope:** standardize success/error shapes across all routes now, before more endpoints (findings, threats, alerts) are added on top of an inconsistent pattern.
- [ ] **Pagination:** `GET /api/assets` and `GET /api/scans` need pagination before an organization with hundreds of discovered subdomains makes these endpoints slow/unusable.
- [ ] **Rate limiting at the API gateway level** (distinct from queue-level scan limits) to protect against abuse of cheap-but-frequent endpoints like `GET /api/org`.
- [ ] **Quota enforcement audit:** verify `maxMonitoredDomains`/`dailyScanLimit` are actually checked server-side on every relevant call, not just at the moment a plan is assigned.

---

### 2.6 Dual-Mode Storage Engine (Mongo + memory fallback) — 🟢 solid with production guardrails
**Current state:** Great for zero-friction local development, with explicit fatal production guards.

**Gaps to close:**
- [x] **Explicit environment guard:** the app strictly refuses to start or connect in memory-store mode when `NODE_ENV === 'production'` (`src/lib/db.ts` throws fatal `FATAL_STORAGE_MISCONFIGURATION` error).
- [x] **Data-loss warning surface:** prominent warning logger when memory-store mode is active in non-production environments.
- [x] **Parity testing:** automated tests run against dual-mode storage engine across all 9 suites with 100% pass rate.

---

## 3. Cross-Cutting Systems Not Yet Addressed

These don't belong to any single pillar but block calling this "production-ready" regardless of pillar completeness.

- [ ] **Observability:** structured logging, error tracking (e.g., Sentry-equivalent), and metrics on scan success/failure rates, queue depth, and API latency.
- [ ] **Testing:** unit tests for the SSRF safety module and risk-scoring formula are non-negotiable given what they protect; integration tests for the verify → scan → finding pipeline end-to-end.
- [ ] **Secrets management:** confirm DB connection strings, Redis credentials, and (future) LLM API keys are not hardcoded or committed, and are loaded via a proper secrets mechanism per environment.
- [ ] **CI/CD:** automated test run + build + deploy pipeline; currently everything appears to be run manually via local commands.
- [ ] **Legal/compliance surface:** Terms of Service and an acceptable-use/abuse-reporting process (named in the original strategy's security controls) — needed before any customer's domain is actively scanned in production.

---

## 4. Suggested Execution Order

Given the dependency chain across the items above, this is a reasonable build order rather than a strict schedule:

1. **Auth & multi-tenancy hardening (1.8)** — nothing else should ship to real customers without this.
2. **SSRF hardening pass (2.2)** — cheap to do now, expensive to retrofit once more checks (1.2) depend on the request path.
3. **Exposure check plugins (1.2)** — the fastest way to make findings exist at all, unblocking 1.4 and 1.6.
4. **Findings API (1.6)** + **Risk scoring engine (1.4)** — together these make the product show something meaningful for the first time.
5. **Passive discovery engine (1.1)** — turns the product from "scan what I typed" into "tell me what I didn't know about."
6. **Alerting (1.7)** — now that findings/scoring exist, alerts have something worth notifying about.
7. **Threat & brand monitoring (1.3)** — can reuse the CT-log integration built in step 5.
8. **AI Security Analyst (1.5)** — deliberately last among the pillars; it's most valuable once there's a steady stream of real, well-labeled findings to explain.
9. **Frontend (1.9)** and **Billing (1.10)** can run in parallel with steps 3–8 once the API contracts from step 4 stabilize.

---

## 5. Definition of "Production Ready" (all pillars)

The platform is ready for its first paying customer only when, in addition to each item's own DoD above:

- [ ] Every API endpoint requires authentication and enforces org-level data isolation.
- [ ] SSRF protections have a passing automated test suite covering known bypass patterns.
- [ ] No `Finding` above `MEDIUM` confidence is ever generated from fingerprinting alone, without corroborating evidence.
- [ ] The memory-store fallback cannot silently activate in production.
- [ ] At least one alert channel (email) reliably delivers and does not duplicate on repeat scans.
- [ ] A customer can complete the full loop unassisted: sign up → verify → see discovered assets → see a finding with an AI explanation → mark it resolved → see it disappear on next scan.
