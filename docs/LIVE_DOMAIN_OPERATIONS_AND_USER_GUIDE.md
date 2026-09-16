# PLIŌRA Threat Monitor — Master User & Live Operations Guide

> **Official Operating Manual for External Attack Surface Management (EASM), Digital Threat Intelligence & Live Domain Security Operations.**

---

## Table of Contents
1. [Live Domain Readiness & Safety Architecture](#1-live-domain-readiness--safety-architecture)
2. [Quick Access & Credentials](#2-quick-access--credentials)
3. [Navigation Directory: Where to Go](#3-navigation-directory-where-to-go)
4. [Step-by-Step Live Domain Lifecycle](#4-step-by-step-live-domain-lifecycle)
   - [Phase 1: Free Assessment (No-Login Lead Magnet)](#phase-1-free-assessment-no-login-lead-magnet)
   - [Phase 2: Asset Inventory & Domain Registration](#phase-2-asset-inventory--domain-registration)
   - [Phase 3: Domain Verification & Authorization Model](#phase-3-domain-verification--authorization-model)
   - [Phase 4: Passive Asset Discovery (CT Logs & DNS)](#phase-4-passive-asset-discovery-ct-logs--dns)
   - [Phase 5: Attack Surface Scan (All 17 Plugins Explained)](#phase-5-attack-surface-scan-all-17-plugins-explained)
   - [Phase 6: Risk Scoring, Grades & Findings Triage](#phase-6-risk-scoring-grades--findings-triage)
   - [Phase 7: Grounded AI Security Analyst](#phase-7-grounded-ai-security-analyst)
   - [Phase 8: What-If Risk Simulation](#phase-8-what-if-risk-simulation)
   - [Phase 9: Brand Protection & Typosquat Monitoring](#phase-9-brand-protection--typosquat-monitoring)
   - [Phase 10: Multi-Channel Alerting & Webhooks](#phase-10-multi-channel-alerting--webhooks)
   - [Phase 11: Executive PDF Reports & White-Labeling](#phase-11-executive-pdf-reports--white-labeling)
   - [Phase 12: MSP & Agency Multi-Client Resale](#phase-12-msp--agency-multi-client-resale)
5. [Summary Operations Cheat Sheet](#5-summary-operations-cheat-sheet)

---

## 1. Live Domain Readiness & Safety Architecture

PLIŌRA Threat Monitor is engineered specifically to interact with **real-world live domains on the public internet**. It has been tested and verified against live targets (e.g. `dns.google`, `one.one.one.one`, `google.com`, enterprise websites).

### How PLIŌRA Interacts with Live Websites
- **Safe & Non-Destructive Scanning:** PLIŌRA behaves as an external reconnaissance auditor. It performs passive OSINT queries, standard TLS handshakes, HTTP `GET`/`HEAD` requests, and non-invasive network probes. It never launches destructive exploitation or DoS vectors.
- **Strict Anti-Spam (SMTP Option 2A):** When testing mail servers for open relaying, PLIŌRA executes the standard RFC `EHLO` and `RCPT TO` handshake, and **immediately aborts with `QUIT` before `DATA`**. Zero emails are ever transmitted.
- **Egress Firewall & SSRF Protection (`safeFetch` / `safeTcpConnect`):** Custom socket-level wrappers prevent the scanner from being tricked into scanning private intranets (`10.0.0.0/8`, `192.168.0.0/16`), AWS metadata (`169.254.169.254`), or loopback addresses.
- **DNS Rebinding Defense (TOCTOU):** The scanner resolves the live domain's IP once, validates that it is a public routable IP, and pins that specific IP address for subsequent socket connections.
- **WAF & Anti-Bot Awareness:** If a live target is behind Cloudflare, Akamai, or Turnstile, PLIŌRA detects the WAF signature and flags the corresponding check as `INCONCLUSIVE` rather than falsely marking the target as clean.
- **Timeout Isolation:** Every plugin runs with an independent timeout (e.g., 5–10s) wrapped in `Promise.race`. If a target domain has a slow or dropped connection on one port, other plugins continue running uninterrupted.

---

## 2. Quick Access & Credentials

| Environment | URL | Credentials |
|---|---|---|
| **Local Web App** | **[http://localhost:3000](http://localhost:3000)** | **Email:** `demo@pliora.io`<br>**Password:** `demo12345!` |
| **Live Vercel Production** | **[https://pliora-threat-monitor.vercel.app](https://pliora-threat-monitor.vercel.app)** | Use `demo@pliora.io` / `demo12345!` or register a new organization |
| **New Org Registration** | [http://localhost:3000/register](http://localhost:3000/register) | Create any custom account & company |
| **Free Public Assessment** | [http://localhost:3000/free-assessment](http://localhost:3000/free-assessment) | No login required — instant live probe |

---

## 3. Navigation Directory: Where to Go

```
┌────────────────────────────────────────────────────────────────────────┐
│                        PLIŌRA Screen Map                               │
├───────────────────┬───────────────────┬────────────────────────────────┤
│ Public / Guest    │ Core Security     │ Governance & Reseller          │
├───────────────────┼───────────────────┼────────────────────────────────┤
│ • / (Home/Hero)   │ • /dashboard      │ • /agency/clients (MSP Hub)    │
│ • /free-assessment│ • /assets         │ • /settings/agency (Governance)│
│ • /pricing        │ • /findings       │ • /settings (Team/Keys/Alerts) │
│ • /login          │ • /threats        │ • /trust (Security Posture)    │
│ • /register       │ • /scans          │ • /terms (Acceptable Use)      │
│ • /onboarding     │ • /alerts         │ • /faq (Documentation)         │
└───────────────────┴───────────────────┴────────────────────────────────┘
```

### Detailed Screen Inventory
1. **Home / Landing Page (`/`):** Cinematic brand introduction, overview of features, trust badges, and CTA buttons to login or scan a free domain.
2. **Free Assessment (`/free-assessment`):** Instant, unauthenticated public security assessment. Enter any public domain name (e.g. `company.com`) to receive an immediate security posture grade, TLS audit, and risk summary.
3. **Login (`/login`):** Secure access using Scrypt password hashing and stateless JWT session cookies.
4. **Register (`/register`):** Multi-tenant sign-up page. Automatically creates your Organization tenant, provisions default scan quotas, and assigns you as the `OWNER`.
5. **Onboarding Wizard (`/onboarding`):** Guides new users through registering their first apex domain, setting importance levels, and initiating their first discovery sweep.
6. **Executive Dashboard (`/dashboard`):** Central command center showing overall Organization Posture Score (0–100), Letter Grade (`A`, `B`, `C`, `D`, `F`), active finding counts by severity, historical risk trend chart, what-if risk simulation widget, and one-click PDF export.
7. **Monitored Assets (`/assets`):** Complete inventory of root domains, subdomains, and cloud resources. Displays verification status (`VERIFIED`, `PENDING`, `FAILED`, `INHERITED`), discovery source badges, IP addresses, importance tags, and actions to trigger scans or sub-domain discovery.
8. **Findings & Vulnerabilities (`/findings`):** Live database of all detected security vulnerabilities, exposures, and misconfigurations. Filterable by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`), status (`OPEN`, `RESOLVED`, `ACCEPTED_RISK`), and domain. Includes one-click access to the AI Security Analyst drawer.
9. **Threat & Brand Monitoring (`/threats`):** Phishing and typosquatting defense console. Lists detected look-alike domain candidates, homoglyphs, corroboration scores (DNS resolution, active MX records, RDAP registration, ASN reputation), and structural content similarity scores.
10. **Scan History & Activity (`/scans`):** Real-time monitoring of scan jobs, progress meters, completed checks counter, findings counter, and historical logs.
11. **Alerts & Notification Rules (`/alerts`):** Notification logs and alert rule configurations for Email, Slack, and signed Webhooks.
12. **Settings & API Keys (`/settings`):** Manage organization profile, invite team members, generate customer REST API keys (`plk_live_...`), and configure alert routing.
13. **MSP / Agency Client Console (`/agency/clients`):** For organizations with `accountType: AGENCY`. View a unified multi-client portfolio, inspect client security grades, open criticals, delegate branding, or drill down into client findings.
14. **Partner Governance & Links (`/settings/agency`):** For client organizations. Review pending agency link requests, approve or decline partner access, toggle white-label branding delegation, view real-time agency access audit logs, or immediately revoke partner access.
15. **Pricing & Plans (`/pricing`):** Tier comparison (`FREE`, `STARTER`, `BUSINESS`, `PRO`) with monitored domain quotas and scan worker concurrency.

---

## 4. Step-by-Step Live Domain Lifecycle

Follow this operational flow to monitor and secure any live domain.

### Phase 1: Free Assessment (No-Login Lead Magnet)
**Where to go:** `http://localhost:3000/free-assessment` (or live at `https://pliora-threat-monitor.vercel.app/free-assessment`)
1. Enter any target domain name (e.g. `github.com` or `dns.google`).
2. Click **Run Free Security Assessment**.
3. **What happens on the live domain:**
   - Resolves IPv4 and IPv6 addresses.
   - Performs a TLS handshake to check expiration, issuer, and protocol cipher suites.
   - Evaluates HTTP security headers (HSTS, CSP).
   - Identifies web server banners.
   - Calculates a preliminary security grade (`A`–`F`) and provides a teaser breakdown with a link to register and monitor the full attack surface.

---

### Phase 2: Asset Inventory & Domain Registration
**Where to go:** `http://localhost:3000/assets`
1. Log in to your dashboard (`demo@pliora.io` / `demo12345!`).
2. Click **Add Domain** or **Add Asset**.
3. Input your live root domain (e.g. `acme-corp.com` or `mycompany.io`).
4. Select **Asset Importance** (`CRITICAL`, `HIGH`, `NORMAL`, `LOW`). This importance weight directly influences the downstream mathematical risk score.
5. Click **Add Asset**. The domain is registered with status `PENDING_VERIFICATION`.

---

### Phase 3: Domain Verification & Authorization Model
**Where to go:** `http://localhost:3000/assets` $\rightarrow$ Click **Verify** on the asset card.

PLIŌRA enforces a strict legal boundary: **Full vulnerability scans are only permitted on customer-authorized assets.**

#### How Verification Works:
1. When you add `example.com`, PLIŌRA generates a cryptographically unique token:  
   `pliora-site-verification=a1b2c3d4e5f6...`
2. **Production DNS Verification:**
   - Add a DNS `TXT` record at the root:
     - **Host:** `@` (or `_pliora-challenge.example.com`)
     - **Value:** `pliora-site-verification=a1b2c3d4e5f6...`
   - Click **Check Verification**. PLIŌRA's DNS resolver queries the live DNS records. When matched, the asset status transitions to `VERIFIED`.
3. **Development / Test Override:**
   - In local development or staging environments, you can verify instantly by selecting **Test Override / Demo Bypass**, transitioning status to `VERIFIED` immediately.
4. **Subdomain Verification Inheritance:**
   - Any subdomains subsequently discovered under `example.com` (e.g. `api.example.com`, `auth.example.com`) **automatically inherit verification** (`INHERITED_VERIFIED`), enabling recursive scanning without needing individual DNS records for every host.

---

### Phase 4: Passive Asset Discovery (CT Logs & DNS)
**Where to go:** `http://localhost:3000/assets` $\rightarrow$ Click **Discover Subdomains** on any verified root domain.

#### What Happens Under the Hood:
1. **Certificate Transparency Mining:** PLIŌRA streams certificate issuance logs from public CT registries (`crt.sh`) for `*.yourdomain.com`. This uncovers subdomains that have ever had an SSL certificate issued (including forgotten staging, VPN, or legacy portals) **without sending a single packet to your servers**.
2. **DNS Permutation Engine:** Generates active permutations using cloud and enterprise prefixes (`dev-`, `staging-`, `api-`, `test-`, `vpn-`).
3. **Multi-Provenance Merging:** Discovered subdomains are deduplicated and tagged with their source (`[CT_LOG, DNS_PERMUTATION]`).
4. **Automatic Inventory Population:** All discovered hosts appear immediately in your Monitored Assets list, ready for scanning.

---

### Phase 5: Attack Surface Scan (All 17 Plugins Explained)
**Where to go:** `http://localhost:3000/scans` $\rightarrow$ Click **New Scan**, select your asset, and click **Start Full Sweep**.

The scan processor executes the **17 detection plugins** in parallel with timeout isolation:

```
─────────────────────────────────────────────────────────────────────────────
Plugin                     What it checks on the live website
─────────────────────────────────────────────────────────────────────────────
1. tlsCert                 Certificate expiration (<30d, expired), self-signed
                           certs, weak protocols (TLS 1.0/1.1), weak ciphers.
2. httpHeaders             Missing HSTS (Strict-Transport-Security), missing CSP,
                           clickjacking (X-Frame-Options), MIME-sniffing headers.
3. techFingerprint         Identifies web server, proxy, and framework banners
                           (e.g., Nginx, Apache, Cloudflare). Capped at MEDIUM.
4. openPorts               Socket banner grab on sensitive ports (21 FTP, 22 SSH,
                           23 Telnet, 25 SMTP, 80, 443, 8080, 8443). Capped at MEDIUM.
5. cveCorrelation          Correlates detected software versions against NVD/CVE
                           databases. Strictly capped at MEDIUM confidence.
6. emailSecurity           Evaluates all 5 email defense standards on live DNS:
                           • SPF record presence and -all/~all enforcement
                           • DKIM DNS selector validation
                           • DMARC policy (reject, quarantine, or none)
                           • BIMI SVG certificate record presence
                           • MTA-STS & TLS-RPT strict transport policies.
7. dnsHealth               DNSSEC cryptographic chain, RFC CAA record presence,
                           dangling NS records, and zone transfer (AXFR) blocks.
8. subdomainTakeover       Checks if CNAME points to unclaimed cloud resources
                           (GitHub Pages, AWS S3, Heroku, Azure, Surge). Only
                           flags CONFIRMED/HIGH if provider error signature matches.
9. sensitiveFiles          Inspects HTTP responses for exposed sensitive paths:
                           /.git/HEAD, /.env, /backup.sql, /phpinfo.php. Validates
                           actual content signatures, not just 200 status codes.
10. storageBucket          Probes for publicly readable AWS S3, GCP, and Azure
                           storage buckets associated with the domain name.
11. webHygiene             Checks for dangerous CORS (credentialed wildcard *),
                           active/passive mixed HTTP/HTTPS content, cookies lacking
                           HttpOnly/Secure/SameSite flags, and missing SRI on CDNs.
12. cmsWordPress           WordPress/Drupal version disclosure, exposed /wp-admin/,
                           and reachable xmlrpc.php brute-force endpoints.
13. databaseExposure       Executes safe protocol handshakes via safeTcpConnect on
                           Redis (PING), MongoDB (isMaster), Elasticsearch.
14. smtpRelay              Tests for open mail relays using RFC EHLO/RCPT TO dialogue;
                           strictly aborts with QUIT before DATA (Option 2A).
15. githubSecrets          Monitors public GitHub repositories for leaked credentials,
                           tokens, and private keys referencing the organization.
16. pastebin               Monitors public paste sites for dumped company credentials.
17. breachLookup           Cross-references company domain against verified breach data,
                           recording exposure metadata with zeroized passwords.
─────────────────────────────────────────────────────────────────────────────
```

---

### Phase 6: Risk Scoring, Grades & Findings Triage
**Where to go:** `http://localhost:3000/findings` and `http://localhost:3000/dashboard`

#### Mathematical Risk Score:
Every detected finding is assigned a deterministic score from 0 to 100:
$$\text{RiskScore} = \text{Severity} \times \text{Exposure} \times \text{Confidence} \times \text{Importance}$$

- **Severity:** `CRITICAL` (1.0), `HIGH` (0.75), `MEDIUM` (0.5), `LOW` (0.25), `INFO` (0.05).
- **Exposure:** Public internet facing vs internal/limited reachability.
- **Confidence:** `CONFIRMED` (1.0), `HIGH` (0.8), `MEDIUM` (0.5), `LOW` (0.2).
- **Importance:** Assigned asset weight (`CRITICAL` 1.2, `HIGH` 1.0, `NORMAL` 0.8, `LOW` 0.5).

#### Organization Security Grade:
Your organization's overall grade is **dominated by the highest-severity open finding**, preventing critical vulnerabilities from being hidden behind a simple average:
- **Grade A (85–100):** Clean perimeter, no Critical/High findings.
- **Grade B (70–84):** Minor configuration weaknesses (e.g. missing security headers).
- **Grade C (55–69):** Medium severity findings present.
- **Grade D (40–54):** Unresolved High severity findings.
- **Grade F (0–39):** One or more active `CRITICAL` vulnerabilities detected.

#### Triaging Findings:
Click any finding in `/findings` to open the detail panel:
- **Mark as In Review:** Moves finding to `IN_REVIEW`.
- **Mark as Resolved:** Once you fix the issue on your live server, click **Resolve**.
  > ⚠️ **Auto-Reopen Invariant:** If a subsequent automated scan detects that the vulnerability is still present on the live domain, PLIŌRA automatically flips the finding back to `OPEN` and logs an audit record.
- **Accept Risk:** If the configuration is intentional, click **Accept Risk**. Findings in `ACCEPTED_RISK` do not affect your organization letter grade and will not auto-reopen on future scans.

---

### Phase 7: Grounded AI Security Analyst
**Where to go:** Click on any finding $\rightarrow$ Click **Analyze with AI Analyst**.

#### What the AI Analyst Provides:
1. **Plain-English Impact Analysis:** Explains what the finding means in business terms.
2. **Strict Evidence Grounding:** Directly cites the raw technical evidence collected during the scan (e.g. cipher suites, DNS records, exact expired timestamps).
3. **Mandatory Confidence Caveat:** Prepends a code-enforced confidence disclaimer:
   > *"This finding was verified directly by active handshake and has a high probability of accuracy."*
4. **Copy-Paste Remediation Guidance:** Step-by-step code and configuration snippets (e.g. Nginx config, DNS record syntax) sanitized against an approved remediation library to block malicious script injections.

---

### Phase 8: What-If Risk Simulation
**Where to go:** `http://localhost:3000/dashboard` $\rightarrow$ **What-If Risk Simulation** card.

Before spending engineering time fixing vulnerabilities, use the simulator to project the exact impact of your remediations:
1. Select one or more active open findings from the list.
2. The simulator calculates the projected Posture Score and Letter Grade in real-time (e.g. *"Resolving this TLS finding will improve posture from 35 (Grade F) to 85 (Grade A)"*).
3. **Zero Side-Effects:** The calculation is purely mathematical and makes zero database changes until the fix is deployed.

---

### Phase 9: Brand Protection & Typosquat Monitoring
**Where to go:** `http://localhost:3000/threats`

PLIŌRA protects your brand reputation by actively searching for malicious look-alike domains registered by cybercriminals.

#### The 7-Class Permutation Generator:
For your registered domain (e.g. `acme.com`), PLIŌRA generates permutations:
1. **Homoglyphs / IDN Punycode:** Visually identical characters (e.g. `аcme.com` using Cyrillic 'а').
2. **Omissions:** Missing letters (e.g. `ame.com`).
3. **Insertions:** Extra letters (e.g. `accme.com`).
4. **Transpositions:** Swapped letters (e.g. `amce.com`).
5. **Bitsquatting:** 1-bit memory flip variations.
6. **TLD Variations:** `.co`, `.net`, `.org`, `.xyz`, `.biz`.
7. **Keyword Combos:** `acme-login.com`, `acme-support.com`, `acme-portal.com`.

#### Threat Corroboration Engine:
Each candidate domain is inspected live:
- Does it have active DNS `A` records?
- Does it have active `MX` mail records (configured to send phishing emails)?
- What is its RDAP creation date (recently registered domains have higher risk)?
- **DOM Content Similarity:** Inspects the live candidate website. If it renders forms, logos, or titles resembling your real site, its Corroboration Score increases to `HIGH`/`CRITICAL`.
- **False-Positive Guard:** Unregistered or non-resolving domains are capped at `INFORMATIONAL` and never trigger false alerts.

---

### Phase 10: Multi-Channel Alerting & Webhooks
**Where to go:** `http://localhost:3000/alerts` and `http://localhost:3000/settings`

Configure notifications so your security team is alerted the moment a new threat or regression appears:
1. **Email Alerts:** Enter email recipients. Receives responsive security alert cards with direct remediation links.
2. **Slack Integration:** Provide your Slack Incoming Webhook URL. Alerts are dispatched as structured Slack Block Kit interactive messages with severity color strips.
3. **Generic Webhooks:** Provide any HTTPS endpoint URL. Payloads are delivered with an `x-pliora-signature` HMAC SHA-256 header and timestamp replay protection.
4. **Alert Storm Suppression:** PLIŌRA automatically collapses rapid bursts of duplicate alerts into a single summary notification.

---

### Phase 11: Executive PDF Reports & White-Labeling
**Where to go:** `http://localhost:3000/dashboard` $\rightarrow$ Click **Export PDF Report**.

#### What the PDF Contains:
- Executive Risk Posture overview with prominent Letter Grade ($A$–$F$).
- Score trend charts and factor breakdown.
- Complete inventory of verified monitored assets.
- Detailed findings breakdown categorized by severity with remediation instructions.
- Confidentiality markings and page count footers ("Page X of Y").

#### White-Label Branding Precedence:
On `BUSINESS` and `PRO` plans, you can override report branding in `/settings`:
- **Custom Logo & Name:** Brand reports with your company name (e.g., *"Acme Cybersecurity Assessment"*).
- **Agency Delegation (Rule A):** If an authorized MSP generates reports on behalf of a client, the PDF displays: *"Report prepared for [Client Name] by [Agency Name]"*.
- **Tier Gate:** Free/Starter tiers automatically receive clean default PLIŌRA Threat Monitor branding.

---

### Phase 12: MSP & Agency Multi-Client Resale
**Where to go:** `http://localhost:3000/agency/clients` (Agency) & `http://localhost:3000/settings/agency` (Client)

Designed for Managed Service Providers (MSPs), MSSPs, and cybersecurity agencies managing security for multiple businesses.

#### How Agency Delegation Works:
1. **Agency Issues Invite (`/agency/clients`):**
   - An agency owner enters the client organization slug or ID.
   - The link is created in status `PENDING`.
   - **Zero Access Invariant:** While `PENDING`, the agency has zero access to the client's data.
2. **Client Approves Access (`/settings/agency`):**
   - The client organization owner receives the link request and clicks **Approve Access**.
   - Link status becomes `ACTIVE`.
3. **Virtual Delegated Session Scoping:**
   - The agency user switches to the client context via the client selector or `x-client-org-id`.
   - The server dynamically scopes the agency user to role `VIEWER` (`isAgencyDelegate: true`).
   - **Read-Only Enforcement:** The agency can view client assets, findings, and export reports, but **cannot mutate assets, change settings, or resolve findings** (write attempts return HTTP `403 Forbidden`).
4. **Dual Audit Trails:**
   - Every delegated view is logged to the client audit log (`AGENCY_DATA_ACCESSED`) and agency audit log (`AGENCY_CLIENT_ACCESSED`).
5. **Immediate Unilateral Revocation:**
   - Either the client or the agency can revoke access at any time with one click. Access is terminated instantly.

---

## 5. Summary Operations Cheat Sheet

| Task | Where to Go | Action |
|---|---|---|
| **Run instant check on any domain** | `/free-assessment` | Type domain $\rightarrow$ Run Free Assessment |
| **Add a domain to monitor** | `/assets` | Click "Add Domain" $\rightarrow$ Enter domain name |
| **Verify domain ownership** | `/assets` $\rightarrow$ "Verify" | Add DNS TXT record $\rightarrow$ Click Check Verification |
| **Discover hidden subdomains** | `/assets` $\rightarrow$ "Discover" | Click "Discover Subdomains" (CT log query runs) |
| **Scan live domain for vulnerabilities**| `/scans` | Click "New Scan" $\rightarrow$ Select asset $\rightarrow$ Start |
| **View vulnerabilities & CVEs** | `/findings` | Filter by severity $\rightarrow$ Click finding to inspect |
| **Get AI analysis & fix code** | `/findings` $\rightarrow$ Select item | Click "Analyze with AI Analyst" |
| **Simulate score improvement** | `/dashboard` | Check findings in "What-If Simulation" widget |
| **Check look-alike phishing domains** | `/threats` | View typosquat candidates & similarity scores |
| **Export executive PDF report** | `/dashboard` | Click "Export PDF Report" button at top right |
| **Configure Slack/Email alerts** | `/alerts` & `/settings` | Enter webhook URL / email $\rightarrow$ Save rules |
| **Manage multiple client accounts** | `/agency/clients` | Invite clients $\rightarrow$ Switch context in console |
| **Manage agency access to your data** | `/settings/agency` | Approve, monitor access logs, or revoke partner |

---

*© 2026 PLIŌRA Threat Monitor. Built for enterprise attack surface defense.*
