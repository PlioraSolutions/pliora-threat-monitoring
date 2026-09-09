# PLIŌRA Threat Monitor — Secrets Management Audit & Rotation Runbook

**Document Version:** 1.0.0  
**Status:** 🟢 AUDITED & VERIFIED  
**Scope:** Production Hardening (Roadmap §C.2 + §C.3)

---

## 1. System Credential Inventory

All credentials across the PLIŌRA Threat Monitor platform are loaded exclusively via environment variables (`process.env` validated through `src/lib/env.ts`). None are hardcoded, committed to version control, or exposed to the client.

| Credential Identifier | Purpose | Loading Mechanism | Production Source | Redaction Rule |
| :--- | :--- | :--- | :--- | :--- |
| `STRIPE_SECRET_KEY` | Subscription & Checkout API (`sk_live_...`) | `env.STRIPE_SECRET_KEY` | Secrets Manager / Vault | `sk_live_[REDACTED]` |
| `STRIPE_WEBHOOK_SECRET` | Inbound Webhook HMAC Verification (`whsec_...`) | `env.STRIPE_WEBHOOK_SECRET` | Secrets Manager / Vault | `whsec_[REDACTED]` |
| `MONGODB_URI` | Primary Database Connection String | `env.MONGODB_URI` | Secrets Manager / Vault | `mongodb://user:[REDACTED]@host` |
| `REDIS_URL` | Distributed Scan Queue Broker | `env.REDIS_URL` | Secrets Manager / Vault | `redis://user:[REDACTED]@host` |
| `JWT_SECRET` | Multi-Tenant Session Cryptographic Signing | `env.JWT_SECRET` | Secrets Manager / Vault | `[JWT_REDACTED]` |
| `NEXTAUTH_SECRET` | Fallback Auth Secret Token | `env.NEXTAUTH_SECRET` | Secrets Manager / Vault | `[REDACTED]` |
| `GEMINI_API_KEY` | Grounded AI Security Analyst Provider | `env.GEMINI_API_KEY` | Secrets Manager / Vault | Masked in logs |
| `OPENAI_API_KEY` | Alternative LLM Provider | `env.OPENAI_API_KEY` | Secrets Manager / Vault | Masked in logs |
| `HIBP_API_KEY` | HaveIBeenPwned Domain Breach Lookup | `env.HIBP_API_KEY` | Secrets Manager / Vault | Masked in logs |
| `VIRUSTOTAL_API_KEY` | Domain Reputation Lookup | `env.VIRUSTOTAL_API_KEY` | Secrets Manager / Vault | Masked in logs |
| `GITHUB_TOKEN` | Public Code Leak Search | `env.GITHUB_TOKEN` | Secrets Manager / Vault | Masked in logs |

---

## 2. Redaction & Zero-Leak Verification

### Automated Log & Trace Redaction
- **File**: `src/lib/observability/logger.ts` and `src/lib/observability/errorTracker.ts`
- **Regex Patterns**:
  - Automatically matches and replaces Stripe live keys (`sk_live_*`), webhook secrets (`whsec_*`), customer API keys (`plk_live_*`), Bearer tokens, JWT tokens, and connection URIs containing user credentials.
  - Recursively scrubs nested objects, request payloads, and error stack traces before console logging or dispatching to error transports.
- **Verification Audit**:
  - Unit tests in `tests/production_hardening.test.ts` verify that passing live-pattern secrets into loggers, error events, or webhook processing routines results in sanitized output.
  - Zero plaintext secrets appear in repository files or git history.

---

## 3. Manual Key Rotation Procedures

In the event of key rotation, credential refresh, or security incident:

### A. Stripe API Keys (`STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`)
1. Log into the Stripe Dashboard -> **Developers** -> **API keys**.
2. Click **Roll key** for the secret key, selecting an expiration window for the old key (e.g., 2 hours).
3. Update `STRIPE_SECRET_KEY` in production environment variables (e.g. AWS Secrets Manager, Vercel Env, or Kubernetes Secret).
4. For Webhooks: Navigate to **Developers** -> **Webhooks**, select the production endpoint, and click **Roll secret**.
5. Update `STRIPE_WEBHOOK_SECRET` in production.
6. Trigger zero-downtime redeploy/restart.
7. Verify `/api/health` returns `billing.configured: true`.

### B. Session & JWT Secret (`JWT_SECRET`, `NEXTAUTH_SECRET`)
1. Generate a new 64-character high-entropy secret:
   ```bash
   node -e "console.log(crypto.randomBytes(32).toString('hex'))"
   ```
2. Update `JWT_SECRET` in environment variables.
3. Restart application instances.
4. *Impact*: Active browser sessions will be invalidated, requiring users to log in again. API keys (`plk_live_...`) remain unaffected as they use SHA-256 database hashes.

### C. Database & Redis Credentials
1. Create new database user with least privilege credentials in MongoDB Atlas / Redis Cloud.
2. Update `MONGODB_URI` and `REDIS_URL` in environment variables.
3. Restart application instances and scan workers.
4. Check `/api/health` to confirm `storage.backend: 'mongodb'` and `subsystems.database.connected: true`.
5. Revoke old database credentials after verifying zero errors.

### D. LLM & External API Keys (`GEMINI_API_KEY`, etc.)
1. Generate replacement API key in provider console.
2. Update environment variable.
3. Zero downtime; worker and AI analyst immediately pick up the new key on the next process instantiation or request.
