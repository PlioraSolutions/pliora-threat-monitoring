# PLIŌRA Threat Monitor — Project Status: Roadmap Complete

**Purpose of this document:** every prior document in this series was a spec for what to build next. This one looks backward instead — a single reference mapping everything now built against the two documents that defined the ambition: the original **Master Strategy & MVP Launch Blueprint**, and the **Full Upgrade Roadmap** written after the MVP shipped. Use this to onboard a new team member, brief an investor, or simply confirm nothing important got lost across ~20 rounds of spec-and-build.

---

## 1. The Original Five Pillars — Status: Complete

| Pillar (from the Master Strategy) | Delivered As | Status |
|---|---|---|
| External Asset Discovery | CT-log mining + DNS permutation, verification-inheritance model, multi-provenance dedup | 🟢 Complete, live-verified |
| Exposure & Configuration Checks | Pluggable `CheckPlugin` architecture, TLS/headers/fingerprinting core, expanded to 17 plugins total | 🟢 Complete, live-verified |
| Threat & Brand Monitoring | 7-class typosquat permutation engine, multi-factor corroboration (DNS/RDAP/ASN + structural content similarity) | 🟢 Complete, live-verified |
| Risk Engine | `Severity × Exposure × Confidence × Importance`, org-level aggregate with letter grades, now self-calibrating | 🟢 Complete, live-verified |
| AI Security Analyst | Grounded, schema-constrained, anti-hallucination-checked, multi-provider with fallback | 🟢 Complete, live-verified |

**The original strategy's stated MVP success bar** — 10–20 active beta businesses, meaningful findings customers didn't already know about, low false positives, 3–5 willing to pay — is now technically achievable on the built product; whether it's been *met* is a go-to-market outcome to track separately from this engineering document.

---

## 2. Foundational Security & Trust Architecture — Status: Complete

| Capability | Status |
|---|---|
| Auth, multi-tenancy, hard tenant isolation | 🟢 Complete — including the one deliberate, audited exception for agency delegation (§9) |
| SSRF/egress protection (IPv4, IPv6, DNS rebinding, redirect re-validation, TCP primitive) | 🟢 Complete |
| Evidence-first, confidence-gated, code-enforced guards against false confidence | 🟢 Complete, and the discipline held across every single expansion wave without erosion |
| Alerting across email, webhook, and Slack, with dedup and escalation logic | 🟢 Complete |

**This is arguably the project's actual core asset**, more than any individual feature: every detection capability added since the original five plugins — 12 more across four expansion waves, plus open ports and CVE correlation — passed through the same confidence-ceiling discipline established on day one, verified by an automated guard, not just a convention. That consistency is what the competitive analysis identified as the real, hard-to-copy differentiator.

---

## 3. Zero-Cost Feature Expansion — Status: Complete (17 Plugins Total)

| Wave | Contents | Status |
|---|---|---|
| Core (5) | TLS/cert, HTTP headers, tech fingerprint, port scan, CVE correlation | 🟢 |
| Wave 1 (4) | Email security (SPF/DKIM/DMARC/BIMI/MTA-STS), DNS health, subdomain takeover, sensitive path exposure | 🟢 |
| Wave 2 (3) | Cloud bucket exposure, web hygiene (CORS/mixed-content/SRI/cookies/JS-lib), CMS/WordPress checks | 🟢 |
| Wave 3 (2) | Database misconfiguration (Redis/ES/MongoDB via `safeTcpConnect`), SMTP relay (heuristic-only, Option 2A) | 🟢 |
| Wave 4 (3) | GitHub secret exposure, paste-site monitoring, breach-exposure lookup, with usage-cost tracking | 🟢 |

Per the competitive analysis, this expansion set includes at least four capability categories (email security suite, subdomain takeover, cloud bucket exposure, dangling-DNS detection) that none of the four named incumbents cover at all.

---

## 4. Full Upgrade Roadmap — Status: Complete Across All Four Phases

| Phase | Contents | Status |
|---|---|---|
| **A — Feature Parity** | Open ports, CVE correlation (hard-guarded), PDF export (white-label capable), webhook delivery (HMAC-signed, replay-protected), Slack integration, customer-facing `/v1/` API | 🟢 Complete |
| **B — Deepen the Moat** | Calibration feedback consumption (drift detection + human-reviewed adjustment), multi-provider AI fallback, bounded AI investigate signal, structural content-similarity for typosquat corroboration, what-if risk simulation | 🟢 Complete |
| **C — Sellable to a Real Business** | Stripe billing with verified quota enforcement, non-destructive downgrades, production guardrails (memory-store, observability, secrets audit, CI/CD), worker sandboxing decision, ToS/acceptable-use, public trust page, evidence retention policy | 🟢 Complete |
| **D — Growth & Channel** | Free-assessment lead magnet (D.1), agency/MSP multi-client delegation with white-label resale (D.2) | 🟢 Complete |

**The one sentence from the original roadmap worth re-reading now that it's all built:** *"don't let Phase A's feature-parity work compromise the confidence-gating discipline that created Phase B's moat in the first place."* Based on every walkthrough in this series — including the CVE correlation hard guard and the SMTP relay's deliberate Option 2A choice — that discipline held throughout.

---

## 5. What Was Explicitly Decided Rather Than Assumed

A project this size accumulates a lot of implicit decisions if they're not written down. These weren't implicit — each was raised, debated, and resolved on the record across this series:

- **Verification inheritance**: same-apex subdomains inherit verification; different-domain discoveries require independent verification.
- **SMTP relay detection**: heuristic-only (Option 2A), full-send confirmation explicitly rejected pending separate legal review.
- **AI confidence caveats**: templated by confidence tier, never model-authored.
- **Calibration methodology**: platform-wide pooling first, per-organization calibration deferred until volume supports it.
- **Agency access model**: client-initiated/approved only, immediately revocable by either party, read-only in this version.
- **SOC 2**: deliberately deferred until triggered by real enterprise demand, not a calendar date.
- **Worker sandboxing**: container network policy now, with an explicit, documented volume trigger for revisiting microVM isolation.

---

## 6. What's Genuinely Still Open

In the interest of this document being accurate rather than celebratory, here's what remains explicitly deferred across the whole series — none of it blocking, all of it worth tracking:

| Item | Why deferred |
|---|---|
| Full visual screenshot diffing for typosquat detection | Structural hashing alone not yet proven insufficient |
| Peer benchmarking ("your score vs. similar businesses") | Needs real customer-base scale to anonymize meaningfully |
| Write-scope agency API access | Read-only sufficient for first version |
| Full reseller/wholesale billing models | Two models documented, neither built |
| Automated (non-human-reviewed) self-tuning of scoring weights | Deliberately human-in-the-loop for now |
| Jira/ticketing integration | Lower priority than Slack for the SMB ICP |
| SOC 2 Type I audit | Awaiting real enterprise-driven trigger |
| Commercial threat-intel feed | Evaluated and rejected on cost/lift data (<4.2% lift, real $ cost) — correctly closed, not just postponed |
| Microsoft-VM-based worker isolation | Explicit volume trigger documented, not yet reached |

---

## 7. A Note on Process, Not Just Product

Looking back across roughly twenty specs and their corresponding walkthroughs, the pattern that made this work wasn't any single architectural choice — it was **the same few disciplines applied consistently, every time, without exception**:

1. Every new capability reused existing infrastructure (`safeFetch`, the plugin registry, the confidence-tier model) rather than growing a parallel system.
2. Every confidence/severity claim was capped by what evidence actually proved, enforced in code, not just described in a comment.
3. Every genuinely risky decision (SMTP relay, agency cross-tenant access, CVE correlation) got an explicit, documented decision point rather than being quietly built the "obvious" way.
4. Every spec closed with a Definition of Done that could be verified, and every walkthrough came back with real test numbers, not just a description of intent.

That's the actual reason a project of this scope shipped without the discipline eroding somewhere in the middle — which, per the competitive analysis, is the one thing genuinely hard for a competitor to copy by matching a feature list.
