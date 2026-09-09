# PLIŌRA Threat Monitor

> **External Attack Surface Management (EASM), Threat Intelligence & Exposure Monitoring Platform**

[![Live Production](https://img.shields.io/badge/Vercel-Live_Production-black?style=for-the-badge&logo=vercel)](https://pliora-threat-monitor.vercel.app)
[![Tests](https://img.shields.io/badge/Tests-111%2F111_Passing-success?style=for-the-badge)](REAL_WORLD_E2E_REPORT.md)
[![Next.js](https://img.shields.io/badge/Next.js-14_App_Router-black?style=for-the-badge&logo=next.js)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict_0_Errors-blue?style=for-the-badge&logo=typescript)](tsconfig.json)

---

## 🌐 Live Production Deployment
- **Official Live App:** [https://pliora-threat-monitor.vercel.app](https://pliora-threat-monitor.vercel.app)
- **Live Free Assessment:** [https://pliora-threat-monitor.vercel.app/free-assessment](https://pliora-threat-monitor.vercel.app/free-assessment)
- **Deployment Guide:** [`DEPLOYMENT.md`](DEPLOYMENT.md)

---

## 🛡️ Core Capabilities

1. **Pluggable Scan Pipeline (17 Detection Plugins):**
   - **Core:** TLS/SSL Certificate Analyzer, HTTP Security Headers, Technology Banners, Open Port Scanner, CVE Correlation.
   - **Wave 1:** Email Security Suite (SPF/DKIM/DMARC/BIMI/MTA-STS), DNS Health & DNSSEC, Subdomain Takeover, Sensitive File Exposure.
   - **Wave 2:** Public Cloud Storage Bucket Analyzer (S3/GCS/Azure), Web Hygiene & Mixed Content, WordPress/CMS Attack Surface.
   - **Wave 3:** Database Exposure Scanner (Redis, MongoDB, Elasticsearch via `safeTcpConnect`), Heuristic SMTP Mail Relay.
   - **Wave 4:** GitHub Secret Exposure, Pastebin/Paste Dumps Monitoring, Corporate Identity & Breach Lookup.
2. **Deterministic Risk Engine:**
   - Mathematical formula: $\text{RiskScore} = \text{Severity} \times \text{Exposure} \times \text{Confidence} \times \text{Importance}$.
   - Organization security posture (0–100) and letter grades ($A$–$F$) dominated by highest-severity vulnerabilities.
   - What-if risk simulation engine projecting score improvements before remediating.
3. **Passive Discovery & Typosquat Engine:**
   - Continuous Certificate Transparency (CT) log mining (`crt.sh`) and active DNS permutation.
   - 7-class brand typosquat permutation engine with structural DOM similarity scoring.
4. **Grounded AI Security Analyst:**
   - Evidence-cited vulnerability explanations with deterministically prepended confidence caveats.
   - Multi-provider fallback chain (Gemini $\rightarrow$ Secondary $\rightarrow$ Offline Rule Template).
5. **Multi-Channel Alerting & Customer API:**
   - Transactional Email, HMAC SHA-256 Webhooks, and Slack Block Kit interactive alerts.
   - Customer REST API v1 (`/api/v1/findings`, `/api/v1/assets`) with scrypt-hashed API keys and token-bucket rate limiting.
6. **White-Label PDF Reports & Agency / MSP Resale:**
   - Server-side binary PDF report generation with 4-tier white-label branding precedence.
   - MSP multi-client delegated console with virtual session scoping (`VIEWER` read-only) and dual audit trails.

---

## 🚀 Quick Start

### Prerequisites
- Node.js 20+
- npm 10+
- Optional: MongoDB & Redis (system automatically falls back to an in-memory development store if offline)

### Installation
```bash
# Clone the repository
git clone https://github.com/PlioraSolutions/pliora-threat-monitoring.git
cd pliora-threat-monitoring

# Install dependencies
npm install

# Copy environment variables template
cp .env.example .env.local

# Run development server
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🧪 Testing & Verification

```bash
# Run the complete automated test suite (16 test suites, 445+ tests)
npm test

# Run TypeScript compilation check (0 errors)
npx tsc --noEmit

# Run the live full-system real-world E2E test runner (111 tests)
npx tsx tests/live_full_system_e2e.ts
```

For the full test execution report, see [`REAL_WORLD_E2E_REPORT.md`](REAL_WORLD_E2E_REPORT.md).

---

## 📚 Documentation

- [Catalog of Implemented & Tested Features](IMPLEMENTED_AND_TESTED_FEATURES.md)
- [Full-System Real-World Test Plan & Report](REAL_WORLD_E2E_REPORT.md)
- [Production Deployment Guide (Vercel & Docker)](DEPLOYMENT.md)
- [Customer API v1 Reference](docs/API_REFERENCE.md)
- [Partner & Reseller Billing Architecture](docs/PARTNER_RESELLER_BILLING_MODELS.md)
- [Execution Plan & Blueprint](EXECUTION_PLAN.md)

---

## 📄 License
Private & Confidential — © 2026 PLIŌRA Threat Monitor. All Rights Reserved.
